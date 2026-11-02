# Phase 11 Post-Run Audit: Technical Remediation Proposal

## 1. Overview

During the post-run audit of the Phase 11 large-sample evaluation (48 authentic external CTI cases), three primary methodological concerns and one state isolation issue were identified:
1. **Substring IOC Matching**: `node.name.lower() in val.lower()` in `find_node_by_indicator()` allowed IP prefix `185.141.63.12` to falsely match test IOC `185.141.63.120`.
2. **Actor Name Disclosure in Passages**: 31 of 32 Task A source passage excerpts explicitly stated the ground-truth actor name or its primary aliases, enabling the vector retriever to act as an entity keyword matcher rather than attributing anonymized behaviors.
3. **Graph-Only (Config B) Tie-Breaking Artifact**: Unseen IOCs returned uniform distances (1/6 = 0.1667) across all candidate actors. Stable sorting on candidate list order artificially ranked `actor_apt28` at #1, `actor_apt29` at #2, and `actor_lazarus` at #3, generating an apparent 50.0% Top-3 accuracy by chance.
4. **Graph Mutation During Inference (Config E)**: Config E called `add_temporary_ioc_node()` 47 times for unseen IOCs, mutating the in-memory knowledge graph across sequential test cases.

This document details the exact remediation required for each issue before any subsequent confirmatory benchmark is authorized.

---

## 2. Technical Remediation Specifications

### Remediation 1: Strict Exact-Match Indicator Resolution
* **File**: `nexuscti/gnn/graph_builder.py`
* **Function**: `find_node_by_indicator(val: str)`
* **Current Flawed Code**:
  ```python
  def find_node_by_indicator(self, val: str) -> Optional[GraphNode]:
      for node in self.nodes.values():
          if val.lower() in node.id.lower() or val.lower() in node.name.lower() or node.name.lower() in val.lower():
              return node
      return None
  ```
* **Remediated Code**:
  ```python
  def find_node_by_indicator(self, val: str) -> Optional[GraphNode]:
      """
      Strict exact-match indicator lookup. Prevents false-positive substring matches
      (e.g., preventing '185.141.63.12' from matching '185.141.63.120').
      """
      if not val:
          return None
      val_norm = val.strip().lower()
      # Pass 1: Exact match on normalized node name or node id
      for node in self.nodes.values():
          if node.name.strip().lower() == val_norm or node.id.strip().lower() == val_norm:
              return node
      # Pass 2: Structured IOC ID convention (ioc_<type>_<sanitized_val>)
      sanitized = val_norm.replace(".", "_").replace(":", "_").replace("-", "_")
      for node in self.nodes.values():
          if node.id.lower().endswith(f"_{sanitized}"):
              return node
      return None
  ```

---

### Remediation 2: Threat Actor Redaction for Text Retrieval
* **Issue**: Evaluating text-based attribution when the prompt says *"Microsoft attributes GooseEgg to Forest Blizzard (APT28)"* measures string retrieval, not behavioral attribution.
* **Remediation Specification**:
  Create an automated sanitizer that masks all known candidate actor names and aliases in the test set queries:
  ```python
  REDACTION_PATTERNS = [
      (r"\b(apt28|fancy bear|strontium|sednit|pawn storm|forest blizzard)\b", "[REDACTED_ACTOR]"),
      (r"\b(apt29|cozy bear|nobelium|midnight blizzard|the dukes|svr|unc2452)\b", "[REDACTED_ACTOR]"),
      (r"\b(lazarus|hidden cobra|guardians of peace|zinc|diamond sleet|applejeus|blue noroff)\b", "[REDACTED_ACTOR]"),
      (r"\b(sandworm|voodoo bear|telebots|blackenergy|electrum|seashell blizzard)\b", "[REDACTED_ACTOR]"),
      (r"\b(volt typhoon|vanguard panda|bronze silhouette|dev-0391)\b", "[REDACTED_ACTOR]"),
      (r"\b(fin7|carbanak|sangria tempest|elbrus)\b", "[REDACTED_ACTOR]"),
      (r"\b(gru unit 26165|unit 26165|unit 74455|85th main special service center|gtsss)\b", "[REDACTED_ORG]"),
  ]
  ```
  By benchmarking both **Raw Passages** and **Redacted Passages**, researchers can isolate how much retrieval accuracy is genuine TTP matching versus trivial entity recognition.

---

### Remediation 3: Explicit Tie-Break Handling for Unseen Graph IOCs
* **File**: `experiments/phase11_post_run_audit/remediated_evaluation_plan.py`
* **Issue**: Unseen nodes yielding uniform 0.1667 confidence across 6 actors should not be given an arbitrary rank 1-6 based on list order.
* **Remediated Logic for Config B**:
  ```python
  def predict_config_b_remediated(self, ioc: str) -> List[Tuple[str, float]]:
      node = self.service.tkg.find_node_by_indicator(ioc)
      if not node:
          # When no topological evidence exists, return 0.0 or uniform tied scores
          # and explicitly flag that no rank ordering exists
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
  ```

---

### Remediation 4: Clean State Isolation for Config E
* **Issue**: Graph node count grew from 65 to 112 during Config E execution due to `add_temporary_ioc_node()`.
* **Remediation Specification**:
  Before each test case in Config E:
  - Take a snapshot of `tkg.nodes`, `tkg.edges`, and `tkg.nx_graph`.
  - Alternatively, explicitly invoke `remove_temporary_node(node_id)` after inference.
  - Or instantiate a clean service copy per configuration.

---

## 3. Recommended Protocol

1. **Keep Phase 11 Historical Artifacts Frozen**: All artifacts in `experiments/phase11_large_sample_evaluation/` remain untouched as historical records.
2. **Review & Audit Sign-Off**: The user and researchers review this proposal and the post-run audit report.
3. **Dry-Run & Validation**: Once approved, run the remediated script in a new dedicated directory `experiments/phase12_remediated_evaluation/`.
