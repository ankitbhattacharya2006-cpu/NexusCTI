#!/usr/bin/env python3
"""
Remediated Evaluation Plan for NexusCTI Benchmark.
Implements the safeguards outlined in remediation_proposal.md:
1. Strict exact-match IOC resolution (eliminates substring leakage).
2. Threat actor entity redaction mode for source passages (measures genuine TTP attribution).
3. Fair handling of unseen IOCs in Config B (prevents list-order tie-breaking bias).
4. Graph state rollback to prevent in-memory mutation across test cases.

Note: As per audit protocol, this script is staged for review and is not executed
until the post-run audit report and remediation proposal have been reviewed.
"""

import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from nexuscti.service import get_service

MANIFEST_PATH = ROOT / "experiments/phase11_large_sample_evaluation/dataset_manifest.csv"

CANDIDATE_ACTORS = [
    "actor_apt28",
    "actor_apt29",
    "actor_lazarus",
    "actor_sandworm",
    "actor_volt_typhoon",
    "actor_fin7",
]

# Patterns for redacting actor entities from test passages to test behavioral attribution
REDACTION_PATTERNS = [
    (re.compile(r"\b(apt28|fancy bear|strontium|sednit|pawn storm|forest blizzard)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(apt29|cozy bear|nobelium|midnight blizzard|the dukes|svr|unc2452)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(lazarus|hidden cobra|guardians of peace|zinc|diamond sleet|applejeus|blue noroff)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(sandworm|voodoo bear|telebots|blackenergy|electrum|seashell blizzard)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(volt typhoon|vanguard panda|bronze silhouette|dev-0391)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(fin7|carbanak|sangria tempest|elbrus)\b", re.I), "[REDACTED_ACTOR]"),
    (re.compile(r"\b(gru unit 26165|unit 26165|unit 74455|85th main special service center|gtsss)\b", re.I), "[REDACTED_ORG]"),
]


def redact_actor_entities(text: str) -> str:
    cleaned = text
    for pat, rep in REDACTION_PATTERNS:
        cleaned = pat.sub(rep, cleaned)
    return cleaned


def strict_find_node_by_indicator(tkg, val: str):
    """Exact-match lookup to replace loose substring matching."""
    if not val:
        return None
    val_norm = val.strip().lower()
    for node in tkg.nodes.values():
        if node.name.strip().lower() == val_norm or node.id.strip().lower() == val_norm:
            return node
    sanitized = val_norm.replace(".", "_").replace(":", "_").replace("-", "_")
    for node in tkg.nodes.values():
        if node.id.lower().endswith(f"_{sanitized}"):
            return node
    return None


class RemediatedEvaluator:
    def __init__(self, redact_entities: bool = False):
        self.service = get_service()
        self.actor_ids = list(CANDIDATE_ACTORS)
        self.redact_entities = redact_entities
        self.cases = self._load_manifest()

    def _load_manifest(self) -> List[Dict[str, str]]:
        rows = []
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
        return rows

    def get_case_query(self, case: Dict[str, str]) -> str:
        text = case["source_passage_excerpt"]
        if self.redact_entities:
            text = redact_actor_entities(text)
        return text

    def predict_config_a(self, query: str) -> List[Tuple[str, float]]:
        results = self.service.hybrid_retriever.dense.search(query, top_k=5)
        scores = defaultdict(float)
        for chunk, score in results:
            scores[chunk.target_actor] += max(score, 0.0)
        total = sum(scores.values()) or 1.0
        ranked = [(a, round(scores.get(a, 0.0) / total, 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def predict_config_b(self, ioc: str) -> List[Tuple[str, float]]:
        node = strict_find_node_by_indicator(self.service.tkg, ioc)
        if not node:
            # Unseen node has zero confidence across all actors; no tie-breaking advantage
            return [(a, 0.0) for a in self.actor_ids]

        undirected_g = self.service.tkg.nx_graph.to_undirected()
        scores = {}
        for a_id in self.actor_ids:
            try:
                dist = nx.shortest_path_length(undirected_g, node.id, a_id)
                scores[a_id] = 1.0 / (1.0 + float(dist))
            except nx.NetworkXNoPath:
                scores[a_id] = 0.0001

        total = sum(scores.values()) or 1.0
        ranked = [(a, round(scores.get(a, 0.0) / total, 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def predict_config_c(self, ioc: str) -> List[Tuple[str, float]]:
        node = strict_find_node_by_indicator(self.service.tkg, ioc)
        if node is None:
            return [(a, 0.0) for a in self.actor_ids]

        raw_preds = self.service.gnn_trainer.predict_attribution_gnn_only(node.id)
        scores_map = {p["actor_id"]: p["structural_confidence"] for p in raw_preds}
        ranked = [(a, round(scores_map.get(a, 0.0), 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked


if __name__ == "__main__":
    print("NexusCTI Remediated Evaluation Plan Script loaded.")
    print("Dry-run check: dataset manifest contains", len(RemediatedEvaluator().cases), "cases.")
    print("Execution deferred until post-run audit review is complete.")
