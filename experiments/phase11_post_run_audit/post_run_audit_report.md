 Next Step: Turn the Validated Backend into a Usable CTI Attribution API

The remediation and benchmark are complete. Do not run more audits, create more reports, or rerun the benchmark.

Now move the project toward a usable backend that exposes the existing CTI attribution capabilities through a clean, testable API.

Objectives

1. Inspect the existing backend architecture and identify the current entry points, service layer, data models, and dependencies.
2. Determine whether an API already exists. If it does, improve and extend it rather than creating a duplicate.
3. Implement or complete the following core capabilities:
    * Submit an IOC for analysis.
    * Retrieve relevant CTI context and graph evidence.
    * Return ranked threat-actor attribution candidates with scores.
    * Explain the evidence supporting each candidate.
    * Return an explicit unknown/insufficient-evidence result when appropriate.
4. Keep model inference separate from ground-truth evaluation data.
5. Preserve the existing remediation safeguards, graph isolation, and exact IOC matching.
6. Add API input validation, structured error handling, and clear response schemas.
7. Add automated tests for normal requests, invalid IOCs, unknown indicators, empty evidence, and service failures.
8. Add concise API documentation and example requests/responses.

Constraints

* Do not claim behavioral reasoning superiority.
* Do not fabricate confidence or evidence.
* Do not introduce unrelated features or rewrite working components unnecessarily.
* Do not modify historical benchmark or audit artifacts.
* Do not run another benchmark unless explicitly requested.

Execution

Implement the smallest production-oriented increment that fits the existing architecture. Run focused tests and the full existing test suite.

Final response

Report:

* What API/backend capabilities existed already.
* What you implemented or changed.
* Files changed.
* Exact test commands and results.
* How to start the backend and call the API.
* Any remaining blockers to frontend integration.

Proceed directly with implementation. Do not stop after producing another plan or report.# Phase 11 Post-Run Audit Report: Substring IOC Leak & Evaluation Integrity

**Date**: 2026-11-01  
**Audit Target**: Phase 11 Large-Sample Evaluation (`experiments/phase11_large_sample_evaluation/`)  
**Scope**: 48 authentic external CTI campaigns (Task A: 32 closed-set, Task B: 16 open-set)  
**Status**: Comprehensive Independent Audit Complete  

---

## 1. Executive Summary

Following the completion of the Phase 11 large-sample evaluation, an exhaustive post-run audit was conducted to investigate the disclosed substring IOC match, audit for any additional data leakage paths, verify the mathematical validity of reported metrics, and assess the integrity of all empirical claims.

### Key Audit Findings
1. **Root Cause of Substring Leak**: Confirmed in [`nexuscti/gnn/graph_builder.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/nexuscti/gnn/graph_builder.py). The bidirectional substring search `node.name.lower() in val.lower()` caused IP prefix `185.141.63.12` to match test indicator `185.141.63.120`.
2. **Scope of Substring Leak**: Exactly **1 case out of 48** (`cisa_aa23_347a_apt28_roundcube`) was affected across the entire benchmark. The remaining 47 test IOCs had zero exact or substring matches against the 65-node baseline graph.
3. **Metric Impact of Substring Leak**: Negligible. Because both Config A (vector) and Config E (hybrid) independently predicted the correct actor at Rank 1, this case was a **concordant pair**. Excluding or correcting this case changes Config E's Top-3 accuracy by only -0.20% (93.75% to 93.55%) and leaves the exact McNemar test result unchanged at **p = 0.375** (not statistically significant).
4. **Critical Methodological Finding — Actor Names in Passages**: 31 out of 32 (96.9%) Task A evaluation passages explicitly contained the ground-truth threat actor's name or primary aliases (e.g., *"attributed to Forest Blizzard (STRONTIUM/APT28)"*). Dense retrieval primarily functioned as an entity keyword and character-trigram matcher rather than evaluating behavioral or TTP attribution. In the single Task A case where the actor name was absent (`cisa_aa20_225a_drovorub`), both Config A and Config E failed Top-1.
5. **Config B Tie-Breaking Artifact**: Config B's apparent 50.0% Top-3 accuracy on unseen IOCs is a mathematical artifact of list ordering. Unseen IOCs return uniform distance (1/6 = 0.1667) to all actors, and Python's stable sort ranked `actor_apt28` #1, `actor_apt29` #2, and `actor_lazarus` #3 on every unseen case.
6. **Verdict**: **USABLE WITH SEVERE CAVEATS** as a diagnostic study of transductive GNN limitations (Config C: 0.0%), but **INVALIDATED** for claims of hybrid behavioral reasoning superiority over text retrieval.
7. **Recommendation**: **NO-GO** on claiming attribution superiority; **GO** on executing a remediated protocol with entity-redacted passages and exact IOC matching.

---

## 2. Root Cause Analysis: Substring IOC Leak

### The Mechanism
In [`nexuscti/gnn/graph_builder.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/nexuscti/gnn/graph_builder.py), lines 150–155:
```python
def find_node_by_indicator(self, val: str) -> Optional[GraphNode]:
    for node in self.nodes.values():
        if val.lower() in node.id.lower() or val.lower() in node.name.lower() or node.name.lower() in val.lower():
            return node
    return None
```
The clause `node.name.lower() in val.lower()` checks if an existing graph node's string representation is contained anywhere within the query indicator. 

When evaluating case `cisa_aa23_347a_apt28_roundcube` with test IOC `185.141.63.120`:
* Existing graph node: `ioc_ip_185_141_63_12` with `node.name = "185.141.63.12"`.
* String evaluation: `"185.141.63.12" in "185.141.63.120"` evaluated to **`True`**.
* The evaluator resolved test IOC `185.141.63.120` to the unrelated IP node `185.141.63.12` in the APT28 training cluster.

### Exhaustive Benchmark Scan
An exhaustive automated scan of all 48 test indicators against the 65 graph nodes confirmed:
* **Total test cases audited**: 48
* **Total IOC matches**: 1 (`cisa_aa23_347a_apt28_roundcube`)
* **Total clean unseen IOCs**: 47 (97.9%)
No other test cases experienced any IOC match (exact or substring).

---

## 3. Per-Configuration Impact on the Leaked Case

For case `cisa_aa23_347a_apt28_roundcube` (Ground Truth: `actor_apt28`):

| Configuration | Prediction With Leak | Confidence | Prediction Without Leak | Rank Impact | Metric Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Config A (Vector-only)** | `actor_apt28` | 0.4325 | `actor_apt28` | Rank 1 -> Rank 1 | **None** (Config A does not use IOCs) |
| **Config B (Graph-only)** | `actor_apt28` | 0.2854 | `actor_apt28` | Rank 1 -> Rank 1 | **None on rank** (due to tie-breaking artifact); confidence drops to 0.1667 |
| **Config C (GNN-only)** | `actor_lazarus` | 0.3617 | None (Empty) | Rank 6 -> Rank 6 | **None** (incorrect either way; GNN hallucinated Lazarus) |
| **Config D (Graph + RAG)** | `actor_apt28` | 0.3589 | `actor_apt28` | Rank 1 -> Rank 1 | **None** (RAG dominates) |
| **Config E (Full Hybrid)** | `actor_apt28` | 0.5201 | `actor_apt28` | Rank 1 -> Rank 1 | **None** (text retriever ranks APT28 #1; dominates combined score) |

### Counterfactual Metric Recalculation (Excluding Leaked Case)

| Configuration | Metric | With Leaked Case (N=32) | Without Leaked Case (N=31) | Delta |
| :--- | :--- | :---: | :---: | :---: |
| **Config A (Vector-only)** | Top-1 Accuracy | 50.00% (16/32) | 48.39% (15/31) | -1.61 pp |
| | Top-3 Accuracy | 84.38% (27/32) | 83.87% (26/31) | -0.50 pp |
| | MRR | 0.6510 | 0.6398 | -0.0112 |
| **Config B (Graph-only)** | Top-1 Accuracy | 15.62% (5/32) | 12.90% (4/31) | -2.72 pp |
| | Top-3 Accuracy | 50.00% (16/32) | 48.39% (15/31) | -1.61 pp |
| | MRR | 0.3995 | 0.3801 | -0.0194 |
| **Config C (GNN-only)** | Top-1 Accuracy | 0.00% (0/32) | 0.00% (0/31) | 0.00 pp |
| | Top-3 Accuracy | 0.00% (0/32) | 0.00% (0/31) | 0.00 pp |
| | MRR | 0.0052 | 0.0000 | -0.0052 |
| **Config D (Graph + RAG)** | Top-1 Accuracy | 50.00% (16/32) | 48.39% (15/31) | -1.61 pp |
| | Top-3 Accuracy | 87.50% (28/32) | 87.10% (27/31) | -0.40 pp |
| | MRR | 0.6896 | 0.6796 | -0.0100 |
| **Config E (Full Hybrid)** | Top-1 Accuracy | 50.00% (16/32) | 48.39% (15/31) | -1.61 pp |
| | Top-3 Accuracy | 93.75% (30/32) | 93.55% (29/31) | -0.20 pp |
| | MRR | 0.7083 | 0.6989 | -0.0094 |

### Impact on Statistical Significance (Config E vs Config A)
* **Full Benchmark (N=32)**: Config E (30/32) vs Config A (27/32). Discordant pairs: $b=3$, $c=0$. Exact McNemar **$p = 0.375$**. 95% Agresti-Min CI: `[-0.038, 0.214]`.
* **Excluding Leaked Case (N=31)**: Config E (29/31) vs Config A (26/31). Discordant pairs: $b=3$, $c=0$. Exact McNemar **$p = 0.375$**. 95% Agresti-Min CI: `[-0.039, 0.221]`.
* **Conclusion**: The substring leak has **zero effect** on the statistical comparison. The difference between Config E and Config A remains statistically non-significant at $\alpha = 0.05$.

---

## 4. Additional Leakage & Methodological Audits

### 4.1 Ground-Truth Actor Names in Source Passages (Substantial Bias)
An audit was conducted on the 32 Task A source passages in `dataset_manifest.csv`:
* **31 of 32 passages (96.9%)** explicitly name the ground-truth threat actor or its prominent public aliases in the text.
  * Example: *"Microsoft Threat Intelligence has attributed the novel GooseEgg tool exclusively to Forest Blizzard (STRONTIUM/APT28)..."*
  * Example: *"CISA, NSA, and FBI attribute these intrusions... to Russian military intelligence GRU Unit 26165 (APT28)."*
* **Only 1 passage** did not explicitly mention an actor alias: `cisa_aa20_225a_drovorub` (*"The FBI and NSA attribute Drovorub to the 85th Main Special Service Center (GTsSS) military unit 26165..."*).
* **Performance on Unnamed vs. Named Passages**:
  * Passages with explicit actor names: Config A Top-1 = 16/31 (51.6%), Config E Top-1 = 16/31 (51.6%).
  * Passages without explicit actor names: Config A Top-1 = 0/1 (0.0%), Config E Top-1 = 0/1 (0.0%).
* **Impact**: Dense text retrieval (`SemanticTextEncoder`) uses character n-gram hashing. It successfully retrieves training reports primarily by matching the literal string tokens `"APT28"`, `"APT29"`, `"Lazarus"`, etc. This demonstrates that Phase 11 Task A measured entity keyword retrieval rather than behavioral TTP-to-actor attribution.

### 4.2 Config B Tie-Breaking Artifact
When an IOC is unseen, `predict_config_b` assigns a uniform prior score of $1/6 \approx 0.1667$ across all 6 candidate actors:
```python
if not node:
    return [(a, round(1.0 / len(self.actor_ids), 4)) for a in self.actor_ids]
```
Because Python's `sort()` is stable, tied scores preserve the initial list order in `CANDIDATE_ACTORS`:
1. `actor_apt28` (always ranked #1)
2. `actor_apt29` (always ranked #2)
3. `actor_lazarus` (always ranked #3)

Because 16 of the 32 Task A cases belong to APT28, APT29, or Lazarus, Config B achieved **50.0% Top-3 accuracy (16/32)** purely by list-order artifact on unseen IOCs, with zero graph distance traversal.

### 4.3 In-Memory Graph Mutation in Config E
In `predict_config_e`, `service.analyze()` invokes `add_temporary_ioc_node()` for unseen IOCs. 
* Across the 48 cases, **47 isolated nodes** were progressively added to the knowledge graph, growing node count from 65 to 112.
* Because `run_all()` evaluated Configs A, B, C, D prior to Config E, earlier configurations were not contaminated.
* While isolated nodes do not alter shortest paths or GNN message passing, mutating the shared graph during evaluation violates test isolation and state reproducibility.

---

## 5. Scientific Validity Assessment

| Component | Audit Verdict | Rationale |
| :--- | :--- | :--- |
| **Config C (GNN-only: 0.0%)** | **VALID (Diagnostic)** | Correctly and cleanly proves that a transductive R-GCN has an absolute blindspot for novel infrastructure absent from its training graph. |
| **Config B (Graph-only: 50.0% Top-3)** | **INVALIDATED (Artifact)** | Apparent accuracy is an artifact of list-order tie-breaking on tied 0.1667 scores, not topological path discovery. |
| **Config A (Vector-only: 84.4% Top-3)** | **USABLE WITH CAVEATS** | Valid as a measure of text entity retrieval, but overstates attribution capability due to actor names present in source passages. |
| **Config E (Hybrid: 93.8% Top-3)** | **USABLE WITH CAVEATS** | Inherits text retriever entity matching; improvement over Vector-only (+9.4pp) is not statistically significant ($p = 0.375$). |
| **Task B (Abstention: 100%)** | **VALID** | Both Config E and Config B demonstrated 100% proper abstention on novel actors; zero hallucination. |

---

## 6. Recommendations & Next Steps

### Recommendation: NO-GO on External Generalization Claims
* Do **NOT** claim that NexusCTI or its hybrid architecture demonstrates statistically significant attribution superiority over vector retrieval on authentic external CTI ($p = 0.375$, CI crosses zero).
* Do **NOT** present Config B's 50% Top-3 accuracy as evidence of graph reasoning on unseen IOCs.
* Disclose that Task A text performance is substantially driven by threat actor entity mentions in source reporting.

### Recommendation: GO on Remediated Evaluation Protocol
1. **Preserve Phase 11 Historical Artifacts**: Keep all files in `experiments/phase11_large_sample_evaluation/` frozen as historical records.
2. **Review Proposed Remediation**: Review [`remediation_proposal.md`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_post_run_audit/remediation_proposal.md) and [`remediated_evaluation_plan.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_post_run_audit/remediated_evaluation_plan.py).
3. **Execute Remediated Benchmark (Phase 12)**:
   - Apply strict exact IOC matching.
   - Run parallel evaluations on (a) **Raw Passages** and (b) **Entity-Redacted Passages** to measure true behavioral attribution.
   - Handle unseen graph nodes with explicit zero confidence or randomized tie-breaking.
   - Implement strict state rollback to prevent graph mutation across cases.
