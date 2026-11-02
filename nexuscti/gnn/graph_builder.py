"""
Graph Builder: Constructs NetworkX and PyTorch Heterogeneous Knowledge Graphs
for Cyber Threat Intelligence.
"""

from typing import Dict, List, Tuple, Any, Optional
from contextlib import contextmanager
import networkx as nx
import torch
import numpy as np

from ..data.ontology import Node, Edge, NodeType, EdgeType
from ..config import GNN_EMBEDDING_DIM


class ThreatKnowledgeGraph:
    """
    Manages the heterogeneous threat intelligence graph, node index mappings,
    and PyTorch tensor representations for relational message passing.
    """

    def __init__(self, nodes: List[Node], edges: List[Edge]):
        self.raw_nodes = nodes
        self.raw_edges = edges

        # NetworkX multi-directed graph for path reasoning and topological operations
        self.nx_graph = nx.MultiDiGraph()

        # Node index mappings
        self.node_id_to_idx: Dict[str, int] = {}
        self.idx_to_node_id: Dict[int, str] = {}
        self.node_dict: Dict[str, Node] = {}

        # Relation mappings
        self.relation_to_idx: Dict[str, int] = {}
        self.idx_to_relation: Dict[int, str] = {}

        # Threat actor indices
        self.actor_indices: List[int] = []
        self.actor_idx_to_name: Dict[int, str] = {}

        self._build_graph()
        self._build_tensors()

    def _build_graph(self):
        # Index all nodes
        for idx, node in enumerate(self.raw_nodes):
            self.node_id_to_idx[node.id] = idx
            self.idx_to_node_id[idx] = node.id
            self.node_dict[node.id] = node

            self.nx_graph.add_node(
                node.id,
                name=node.name,
                type=node.type.value,
                description=node.description,
                metadata=node.metadata,
                idx=idx
            )

            if node.type == NodeType.THREAT_ACTOR:
                self.actor_indices.append(idx)
                self.actor_idx_to_name[idx] = node.name

        # Collect and index relation types (both forward and inverse)
        rel_set = set()
        for edge in self.raw_edges:
            rel_set.add(edge.type.value)
            rel_set.add(f"rev_{edge.type.value}")

        for r_idx, r_name in enumerate(sorted(list(rel_set))):
            self.relation_to_idx[r_name] = r_idx
            self.idx_to_relation[r_idx] = r_name

        # Add edges to NetworkX (bidirectional for relational message passing)
        for edge in self.raw_edges:
            # Forward edge
            self.nx_graph.add_edge(
                edge.source,
                edge.target,
                key=edge.type.value,
                rel_type=edge.type.value,
                confidence=edge.confidence,
                citation=edge.source_citation
            )
            # Reverse edge for message passing back to source
            rev_rel = f"rev_{edge.type.value}"
            self.nx_graph.add_edge(
                edge.target,
                edge.source,
                key=rev_rel,
                rel_type=rev_rel,
                confidence=edge.confidence,
                citation=edge.source_citation
            )

    def _build_tensors(self):
        """
        Builds initial node feature vectors and relational edge tensors.
        """
        num_nodes = len(self.raw_nodes)
        node_types = list(NodeType)
        num_types = len(node_types)

        # Initial features: concatenation of one-hot node type + structural features + normalized degree
        features = np.zeros((num_nodes, GNN_EMBEDDING_DIM), dtype=np.float32)

        for node_id, idx in self.node_id_to_idx.items():
            node = self.node_dict[node_id]
            # One-hot type
            type_idx = node_types.index(node.type)
            features[idx, :num_types] = 0.0
            features[idx, type_idx] = 1.0

            # Degree centrality feature
            degree = self.nx_graph.degree(node_id)
            features[idx, num_types] = min(degree / 20.0, 1.0)

            # Node name hash embedding for semantic initialization
            name_hash = hash(node.name) % 10000 / 10000.0
            features[idx, num_types + 1] = name_hash

            # Fill remaining dimensions with deterministic pseudo-spectral positional features
            for d in range(num_types + 2, GNN_EMBEDDING_DIM):
                features[idx, d] = np.sin((idx + 1) * (d + 1) * 0.1)

        self.x = torch.tensor(features, dtype=torch.float32)

        # Build edge indices per relation
        # Map: rel_idx -> (edge_index: Tensor of shape [2, E_r])
        self.rel_edge_indices: Dict[int, torch.Tensor] = {}
        for r_name, r_idx in self.relation_to_idx.items():
            sources, targets = [], []
            for u, v, data in self.nx_graph.edges(data=True):
                if data.get("rel_type") == r_name:
                    u_idx = self.node_id_to_idx[u]
                    v_idx = self.node_id_to_idx[v]
                    sources.append(u_idx)
                    targets.append(v_idx)

            if sources:
                edge_tensor = torch.tensor([sources, targets], dtype=torch.long)
            else:
                edge_tensor = torch.empty((2, 0), dtype=torch.long)
            self.rel_edge_indices[r_idx] = edge_tensor

    def find_node_by_indicator(self, indicator_str: str) -> Optional[Node]:
        """
        Searches for an existing node matching an IOC (IP, domain, hash, or CVE).
        Strict exact-match indicator lookup: eliminates substring containment
        matching to prevent false-positive leakage (e.g. '185.141.63.12' falsely matching '185.141.63.120').
        """
        if not indicator_str:
            return None

        indicator_str_clean = indicator_str.strip().lower().replace("[.]", ".").replace("[:]", ":")

        # Pass 1: Exact match on normalized name or ID
        for node in self.raw_nodes:
            node_clean = node.name.strip().lower().replace("[.]", ".").replace("[:]", ":")
            if indicator_str_clean == node_clean or indicator_str_clean == node.id.lower():
                return node

        # Pass 2: Exact match on aliases or known indicators
        for node in self.raw_nodes:
            aliases = node.metadata.get("aliases", [])
            for alias in aliases:
                alias_clean = alias.strip().lower().replace("[.]", ".").replace("[:]", ":")
                if indicator_str_clean == alias_clean:
                    return node

        # Pass 3: Exact match on sanitized IOC node ID convention (e.g. ioc_ip_185_141_63_12)
        sanitized = indicator_str_clean.replace(".", "_").replace(":", "_").replace("-", "_")
        for node in self.raw_nodes:
            if node.id.lower() == f"ioc_{sanitized}" or node.id.lower().endswith(f"_{sanitized}"):
                return node

        return None

    def add_temporary_ioc_node(self, ioc_val: str, ioc_type: NodeType = NodeType.INDICATOR) -> str:
        """
        Dynamically registers a novel IOC into the graph for real-time investigation.
        """
        existing = self.find_node_by_indicator(ioc_val)
        if existing:
            return existing.id

        new_id = f"novel_{hash(ioc_val) & 0xffffffff}"
        new_node = Node(
            id=new_id,
            name=ioc_val,
            type=ioc_type,
            description="Dynamically ingested indicator of compromise from incoming SOC telemetry.",
            metadata={"novel": True}
        )
        self.raw_nodes.append(new_node)
        self.node_id_to_idx[new_id] = len(self.raw_nodes) - 1
        self.idx_to_node_id[len(self.raw_nodes) - 1] = new_id
        self.node_dict[new_id] = new_node
        self.nx_graph.add_node(
            new_id,
            name=new_node.name,
            type=new_node.type.value,
            description=new_node.description,
            metadata=new_node.metadata,
            idx=self.node_id_to_idx[new_id]
        )
        self._build_tensors()
        return new_id

    def remove_temporary_ioc_node(self, node_id: str) -> bool:
        """
        Removes a dynamically added temporary IOC node and restores graph tensors.
        Base graph nodes (novel != True) cannot be removed.
        """
        if node_id not in self.node_dict:
            return False
        node = self.node_dict[node_id]
        if not node.metadata.get("novel", False):
            return False

        self.raw_nodes = [n for n in self.raw_nodes if n.id != node_id]
        self.node_id_to_idx = {n.id: i for i, n in enumerate(self.raw_nodes)}
        self.idx_to_node_id = {i: n.id for i, n in enumerate(self.raw_nodes)}
        del self.node_dict[node_id]
        if self.nx_graph.has_node(node_id):
            self.nx_graph.remove_node(node_id)
        self._build_tensors()
        return True

    @contextmanager
    def isolated_graph_context(self):
        """
        Context manager ensuring the graph state (raw_nodes, nx_graph, node_dict, tensors)
        is strictly restored to its initial state upon exiting, preventing cross-test pollution.
        """
        initial_node_count = len(self.raw_nodes)
        initial_edge_count = self.nx_graph.number_of_edges()
        initial_raw = list(self.raw_nodes)
        initial_nx = self.nx_graph.copy()
        initial_dict = dict(self.node_dict)
        initial_id_to_idx = dict(self.node_id_to_idx)
        initial_idx_to_id = dict(self.idx_to_node_id)
        try:
            yield self
        finally:
            if len(self.raw_nodes) != initial_node_count or self.nx_graph.number_of_edges() != initial_edge_count:
                self.raw_nodes = list(initial_raw)
                self.nx_graph = initial_nx
                self.node_dict = initial_dict
                self.node_id_to_idx = initial_id_to_idx
                self.idx_to_node_id = initial_idx_to_id
                self._build_tensors()
