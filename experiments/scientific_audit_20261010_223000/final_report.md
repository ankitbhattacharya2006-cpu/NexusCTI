# Scientific Benchmark Audit & Controlled Ablation Technical Report

**Experiment ID:** `scientific_audit_20261010_223000`  
**Date:** October 10, 2026  
**Auditor:** Principal AI Systems & Scientific Verification Auditor  
**Repository:** `c:\Users\Arjaa Chatterjee\OneDrive\Desktop\NexusCTI`

---

## 1. Executive Summary

This study conducted an independent scientific audit of **NexusCTI (Cyber-Threat Attribution Engine)**, covering:
1. **Repository Reconnaissance & Baseline Reproduction:** Verification of 12 benchmark cases, GNN representations, ChromaDB vector stores, and baseline evaluation scripts.
2. **Case-Level Data Leakage Audit:** Systematic inspection of 6 leakage vectors across split contamination, graph shortcuts, retrieval contamination, near-duplicate documents, temporal provenance, and hyperparameter tuning.
3. **Controlled 5-Configuration Ablation Experiments:** Rigorous evaluation isolating Vector-only RAG, Graph-only (non-neural topological), GNN-only (neural relational message passing), Graph + RAG (non-neural fusion), and the Full Hybrid NexusCTI engine.

---

## 2. Benchmark Reproduction & Discrepancy Analysis

The documented benchmark was reproduced using the official environment:
```powershell
.\.venv\Scripts\python.exe -u run_benchmark.py
```

### Comparative Findings vs. Previous Literature Claims:

| Model Architecture | Literature / Report Claim | Newly Reproduced Reality | Discrepancy Note |
| :--- | :---: | :---: | :--- |
| **Naive Vector-only RAG** | Top-1: 25.0% \| MRR: 0.4514 | **Top-1: 41.67% (5/12) \| MRR: 0.5972** | Vector RAG performs higher than claimed due to partial indicator string matches in report passages. |
| **Standalone GNN Classifier** | Top-1: 41.7% \| MRR: 0.6806 | **Top-1: 75.00% (9/12) \| MRR: 0.8472** | GNN baseline is significantly stronger on 2-hop stager nodes than previously documented. |
| **NexusCTI Hybrid** | Top-1: 91.7% \| MRR: 0.9583 | **Top-1: 91.67% (11/12) \| MRR: 0.9444** | Faithfully reproduced (11/12 passed on raw evaluation; 12/12 on dynamic anchor resolution). |

---

## 3. Comprehensive Data Leakage Audit Findings

Every benchmark case was audited across 6 leakage dimensions (see `case_level_audit.csv`):

1. **Split Contamination (REVIEW — Transductive Setup):**
   - In `nexuscti/gnn/trainer.py`, training supervision labels are generated using `nx.single_source_shortest_path_length` with a 3-hop radius from actor nodes.
   - Tiers 1 and 2 indicators (`test_case_01`–`06`) fall within 2–3 hops of threat actors, meaning their embeddings were explicitly supervised during GNN training.
   - Tiers 3 and 4 indicators (`test_case_07`, `09`, `10`) reside 4 hops away, requiring true relational message passing across intermediate nodes.
   - **Academic Verdict:** Must be accurately designated in papers as a **Transductive Graph Verification Benchmark** rather than an out-of-sample inductive split.

2. **Graph Shortcut Leakage (PASS):**
   - Zero direct shortcuts exist from telemetry indicators (`185.225.17.42`, `freescanonline.com`, `a3d9e84b...`) directly to `ThreatActor` nodes.
   - Multi-hop traversal paths strictly adhere to STIX 2.1 schemas (`IP -> Domain -> Malware -> Actor`).

3. **Retrieval Leakage (REVIEW):**
   - 8 of 12 test indicators appear verbatim inside vendor threat reports. Exact keyword matching allows BM25 to score high term-frequency matches.
   - When indicators do NOT appear in report texts (e.g., dark subnets or fast-flux IPs), Vector-only RAG degrades to 36.36% multi-hop accuracy.

4. **Closed-World Campaign Overlap (REVIEW):**
   - All 12 cases test pivots into 6 known threat campaigns. There are no open-world, uncharacterized adversary clusters.

5. **Temporal Provenance (PASS — Documented):**
   - Reports represent post-incident forensic advisories. The system is designed for forensic incident response verification rather than real-time prediction.

6. **Tuning Leakage (REVIEW):**
   - Fusion weights ($\alpha=0.45, \beta=0.35, \gamma=0.20$) were calibrated against these 12 cases.

---

## 4. Controlled 5-Configuration Ablation Results

The 5 configurations were evaluated using identical candidate actor sets, metric formulas, and test cases:

```
[Config A: Vector-only]     ==> Dense Semantic Similarity Only (No Graph)
[Config B: Graph-only]      ==> NetworkX Unweighted Shortest-Path Proximity on an Undirected View (Non-Neural, No Text)
[Config C: GNN-only]         ==> HeteroThreatGNN Neural Representations Only (No Text)
[Config D: Graph + RAG]     ==> 0.5 * Graph Distance + 0.5 * Text Similarity (No GNN)
[Config E: Full Hybrid]     ==> 0.45 * GNN + 0.35 * RAG + 0.20 * Cross-Validation
```

The runner calls `get_service()` once and reuses its singleton across all five
predictors. Service construction builds the graph, trains the GNN, loads the
corpus, and initializes retrieval before scoring. The configuration labels
therefore describe prediction-time paths over shared initialized state, not
process-level isolation or independently initialized systems.

The original Config C called `predict_attribution()`, which blended 45% GNN
affinity with 55% NetworkX path proximity. Its earlier results were not
GNN-only. The corrective rerun below uses neural affinity alone, rejects
unknown anchors without mutating the shared graph, and records the
unseeded run in the current reproducibility manifest.

### Empirical Performance Comparison Table:

Corrective rerun on 2026-10-31; the runner uses an unseeded GNN, so the neural
and hybrid scores are one stochastic run, not a reproducibility estimate.

| Configuration | Top-1 Accuracy | Top-3 Accuracy | Top-5 Accuracy | Multi-Hop Attribution Accuracy ($\ge 2$ hops) | Hallucination Rate | MRR | Total Runtime | Avg Case Runtime |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config A: Vector-only RAG** | 41.67% (5/12) | 83.33% (10/12) | 91.67% (11/12) | 45.45% (5/11) | 58.33% (7/12) | 0.6042 | 0.003s | 0.2 ms |
| **Config B: Graph-only (Topological)** | **100.00%** (12/12) | **100.00%** (12/12) | **100.00%** (12/12) | **100.00%** (11/11) | **0.00%** (0/12) | **1.0000** | 0.007s | 0.6 ms |
| **Config C: GNN-only (Neural)** | 16.67% (2/12) | 41.67% (5/12) | 50.00% (6/12) | 9.09% (1/11) | 83.33% (10/12) | 0.3681 | 0.001s | 0.1 ms |
| **Config D: Graph + RAG (Non-Neural)** | 66.67% (8/12) | 91.67% (11/12) | **100.00%** (12/12) | 63.64% (7/11) | 33.33% (4/12) | 0.7847 | 0.008s | 0.7 ms |
| **Config E: Full Hybrid (NexusCTI)** | **100.00%** (12/12) | **100.00%** (12/12) | **100.00%** (12/12) | **100.00%** (11/11) | **0.00%** (0/12) | **1.0000** | 0.012s | 1.0 ms |

### Metric reconciliation with the Phase 2 audit summary

The companion [`audit_summary.md`](./audit_summary.md) reports 90.91%
multi-hop accuracy for the hybrid, while this detailed benchmark report
records 100.00% (11/11) for Config E. Both artifacts refer broadly to the same
12-case, closed-world, transductive benchmark, but the summary does not give a
distinct run configuration, numerator, or case-level results explaining the
difference. The 100.00% figure here is explicitly the result for all 11
cases with `expected_hops >= 2`; the 90.91% figure remains the separate value
stated by the summary. Until run-level evidence resolves the discrepancy,
report both with their sources and conditions rather than treating them as
one result. The corrective 2026-10-31 run also scored 11/11, but does not
explain the historical summary's 90.91% result.

---

## 5. Scientific Interpretation of Ablation Findings

1. **Vector Retrieval Result (Config A: 41.67% Top-1):**
   - In the corrective run, dense vector retrieval reached 41.67% Top-1 and 45.45% multi-hop attribution accuracy. This is a single benchmark run and does not establish generalization.

2. **The Graph Topology Factor (Config B: 100%):**
   - On a closed, curated knowledge graph, every verified indicator has a finite path to its parent actor. Symbolic path traversal achieves perfect Top-1 accuracy.
   - **However:** Graph-only attribution produces **zero qualitative explanations**, cannot assess attacker intent, cannot verify campaign timelines, and provides no textual citations for human SOC defenders.

3. **Corrected GNN-only Result (Config C: 16.67% in this run):**
   - Neural-only actor affinity performed substantially below the graph-distance and hybrid predictors in this single unseeded run. This result is stochastic and should not be generalized from one run.
   - The previous 58.33% / 75.00% Config C figures used predictors that blended GNN affinity with NetworkX topology; they are not valid neural-only comparisons.

4. **Hybrid and Graph-only Comparison:**
   - Both Config B and Config E reached 100.0% Top-1 accuracy and 1.0000 MRR in this transductive run, so no ranking advantage from fusion is measurable on this benchmark.
   - Config E additionally returns a graph trail and retrieved narrative context. Its graph and citation checks validate connectivity, relationships, and citation-field matching, not source entailment.

---

## 6. Generated Experiment Artifacts

All newly generated experiment artifacts are saved in:
`experiments/scientific_audit_20261010_223000/`

- `manifest.txt`: Execution manifest and timestamps.
- `repository_inventory.md`: Complete codebase architecture mapping.
- `baseline_reproduction.json`: Raw reproduced baseline metrics and discrepancy analysis.
- `case_level_audit.csv`: Comprehensive 20-column case-by-case audit matrix.
- `graph_edge_audit.json`: Hop distances and path traces for all 12 cases.
- `retrieval_trace.json`: Retrieved document chunks and indicator citation flags.
- `duplicate_overlap_report.json`: Overlap analysis between corpus and test cases.
- `leakage_findings.md`: Detailed audit across all 6 leakage classes.
- `audit_summary.md`: Summary status matrix (15 PASS, 5 REVIEW, 0 FAIL).
- `experiment_protocol.md`: Ablation experiment protocol and mathematical formulations.
- `ablation_configurations.json`: Formal specification of the 5 evaluated configurations.
- `ablation_results.json`: Full raw predictions and metrics for all configurations.
- `per_case_predictions.csv`: 60 evaluated case predictions with ranks and latencies.
- `metrics_summary.csv`: Summary metrics comparison table.
- `runtime_summary.json`: Detailed execution latencies per configuration.
- `reproducibility_manifest.json`: Exact reproducibility environment metadata.
- `historical_run_artifacts/`: Preserved pre-rerun historical artifacts directory.
- `final_report.md`: This comprehensive technical audit report.
