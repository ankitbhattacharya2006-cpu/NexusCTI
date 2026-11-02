# NexusCTI Phase 11: 48-Case Authentic External CTI Evaluation Report

**Experiment ID:** `phase11_large_sample_evaluation_20261031`
**Date:** 2026-10-31
**Environment:** Darwin 27.0.0, Python 3.12.2
**Execution Command:**
```bash
./.venv/bin/python experiments/phase11_large_sample_evaluation/run_phase11_evaluation.py
```
**Total Runtime:** 0.118 seconds (entire 5-configuration × 48-case suite)

---

## 1. Executive Summary

This evaluation tests NexusCTI's five ablation configurations against **48 authentic, publicly documented threat-intelligence campaigns** sourced from CISA, Microsoft MSRC, UK NCSC, ESET, Mandiant, and US Treasury (2020–2024). It is the first evaluation of NexusCTI on external data not present in the system's training graph or retrieval corpus.

**Key Results:**

| Metric | Config A (Vector-only) | Config B (Graph-only) | Config C (GNN-only) | Config D (Graph+RAG) | Config E (Full Hybrid) |
|---|---|---|---|---|---|
| **Task A Top-1** | 16/32 (50.0%) | 5/32 (15.6%) | 0/32 (0.0%) | 16/32 (50.0%) | 16/32 (50.0%) |
| **Task A Top-3** | 27/32 (84.4%) | 16/32 (50.0%) | 0/32 (0.0%) | 28/32 (87.5%) | **30/32 (93.8%)** |
| **Task A Top-5** | 27/32 (84.4%) | 27/32 (84.4%) | 0/32 (0.0%) | 32/32 (100.0%) | 32/32 (100.0%) |
| **Task A MRR** | 0.651 | 0.400 | 0.005 | 0.690 | **0.708** |
| **Task B Abstention** | 12/16 (75.0%) | 16/16 (100.0%) | 16/16 (100.0%) | 16/16 (100.0%) | **16/16 (100.0%)** |
| **Task B False Attr.** | 4/16 (25.0%) | 0/16 (0.0%) | 0/16 (0.0%) | 0/16 (0.0%) | **0/16 (0.0%)** |

**The Full Hybrid (Config E) achieves the highest Top-3 accuracy (93.8%) and MRR (0.708) among all configurations, with zero false attributions on novel actors. However, these improvements over Config A are not statistically significant at α = 0.05 given the sample size.**

---

## 2. Dataset Description and Provenance

### 2.1 Source

All 48 campaigns were curated from the Phase 8 expanded evaluation manifest. Each case is traceable to a specific public advisory with:
- Publisher name and publication date
- Original URL
- SHA-256 hash of the source passage excerpt
- Anchor IOC (IP, domain, hash, or CVE)

### 2.2 Task Assignments

| Task | N | Description | Ground-Truth Actors |
|---|---|---|---|
| **Task A: Closed-Set** | 32 | Known actors, unseen campaigns | APT28 (5), APT29 (5), Sandworm (5), Lazarus (6), FIN7 (5†), Volt Typhoon (6†) |
| **Task B: Open-Set** | 16 | Novel/unseen actors or ambiguous multi-actor campaigns | Kimsuky (2), LockBit (2), APT41 (2), Charming Kitten (2), Gamaredon (2), BlackCat (2), Scattered Spider (1), Clop (1), Ambiguous (2) |

† FIN7 and Volt Typhoon have 5 and 6 cases respectively due to one additional case each relative to the nominal 5-per-actor target.

### 2.3 Manifest Integrity

- All 48 rows contain non-empty values for: `report_id`, `publisher`, `original_url`, `attributed_actor`, `task_assignment`, `anchor_ioc`, `sha256_hash`, `source_passage_excerpt`.
- All fields verified programmatically; zero missing values.

---

## 3. Data Quarantine Verification

### 3.1 Graph Quarantine

| Check | Result |
|---|---|
| Exact IOC matches in baseline graph | **0** |
| Campaign ID matches in graph node names/IDs | **0** |
| Report title matches in graph | **0** |

### 3.2 Corpus Quarantine

| Check | Result |
|---|---|
| Source passage exact match in training corpus | **0** |
| Report title exact match in corpus document titles | **0** |

### 3.3 Substring IOC Leakage (Disclosed)

> [!WARNING]
> **One substring match was detected.** The test IOC `185.141.63.120` (case `cisa_aa23_347a_apt28_roundcube`, ground truth: `actor_apt28`) matched the existing graph node `ioc_ip_185_141_63_12` (name: `185.141.63.12`) via the `find_node_by_indicator()` substring matching logic (Pass 3, ≥4 chars).
>
> This means Config B, Config C, and Config E had access to the pre-existing graph neighbourhood of `185.141.63.12` for this single case. The graph path from that node to `actor_apt28` has distance 3 (via `mal_zebrocy`).
>
> **Impact:** This affected exactly 1/32 Task A cases. Config B scored this case correctly with confidence 0.2854 (vs. uniform 0.1667 for all other unseen IOCs). The ground truth actor was APT28, which is also the default tie-break winner for unseen IOCs, so Config B's Top-1 count would decrease from 5 to 4 if this case were excluded — all other 4 "correct" Config B predictions are coincidental tie-break wins on APT28 cases.

---

## 4. Per-Configuration Analysis

### 4.1 Config A — Vector-only RAG

**Mechanism:** Dense semantic retrieval (`DenseRetriever.search`) over the training corpus. Scores aggregated by `target_actor` field on retrieved chunks.

**Task A:** 50.0% Top-1, 84.4% Top-3, MRR = 0.651.
This is the strongest individual baseline for Top-1 accuracy. The retrieval corpus contains thematic descriptions of each actor's TTPs, and the source passage excerpts in the test cases name techniques and patterns that overlap semantically with those descriptions.

**Task B:** 75.0% proper abstention (12/16). Four false attributions occurred when the dense retriever returned high-confidence matches (>0.70) to corpus chunks describing known actors whose TTPs overlap with the novel actor's description (e.g., LockBit → Volt Typhoon, Charming Kitten → APT29, BlackCat → Volt Typhoon, Scattered Spider → APT29).

**Per-Actor Breakdown (Task A):**

| Actor | N | Top-1 | Top-3 |
|---|---|---|---|
| APT28 | 5 | 1/5 | 4/5 |
| APT29 | 5 | 2/5 | 4/5 |
| Sandworm | 5 | 2/5 | 4/5 |
| Lazarus | 6 | 3/6 | 5/6 |
| FIN7 | 5 | 3/5 | 5/5 |
| Volt Typhoon | 6 | 5/6 | 5/6 |

### 4.2 Config B — Graph-only Topological (Shortest Path)

**Mechanism:** `nx.shortest_path_length` on the undirected baseline graph from the IOC node to each candidate actor. Unseen IOCs get uniform prior `1/N_actors`.

**Task A:** 15.6% Top-1 (5/32). **All 5 correct predictions are APT28 cases.** 4 of these are coincidental tie-break wins (APT28 is first in the `CANDIDATE_ACTORS` list, and Python's stable sort places it first when all 6 actors have identical uniform scores). 1 case (`cisa_aa23_347a_apt28_roundcube`) is a genuine graph-distance win due to the substring IOC leak disclosed in §3.3.

**Task A Top-3 = 50.0% (16/32):** With 6 actors and uniform scores, the top-3 always contains `actor_apt28`, `actor_apt29`, `actor_lazarus` (the first 3 in the list). This means any case with those ground truths gets a Top-3 hit. This is a list-order artifact, not meaningful signal.

**Task B:** 100.0% abstention. All unseen IOCs yield uniform scores below the 0.70 threshold.

> [!IMPORTANT]
> Config B's performance on external data is effectively random for unseen IOCs. The 15.6% Top-1 and 50.0% Top-3 are artifacts of tie-breaking order, not genuine graph reasoning.

### 4.3 Config C — GNN-only (Isolated Neural Message Passing)

**Mechanism:** `predict_attribution_gnn_only()` — pure R-GCN message-passing without NetworkX shortest path or text retrieval. Unseen IOCs return all-zero scores.

**Task A:** 0.0% across all metrics. MRR = 0.005. **Total failure on external data.**

47 of 48 IOCs are unseen in the graph, so the GNN returns all-zero vectors. The one IOC that matches (`185.141.63.120` → `ioc_ip_185_141_63_12`) still fails to produce a correct Top-1 prediction because the GNN's learned embeddings do not rank `actor_apt28` first for that node.

**Task B:** 100.0% abstention. All scores are zero or near-zero.

> [!CAUTION]
> The isolated GNN has zero predictive power on novel indicators absent from its training graph. This is an expected limitation of transductive GNN architectures — they cannot generate embeddings for nodes not seen during training. **The Phase 3 benchmark (N=12), where Config C achieved non-zero accuracy, evaluated indicators already present in the graph.** The Phase 11 result demonstrates that this transductive accuracy does not transfer to novel infrastructure.

### 4.4 Config D — Graph + RAG (Non-Neural Hybrid)

**Mechanism:** Equal-weight average of Config A (vector retrieval) and Config B (shortest path) scores.

**Task A:** 50.0% Top-1, 87.5% Top-3, 100.0% Top-5, MRR = 0.690.

The graph component contributes uniform noise for 31/32 unseen-IOC cases, while the RAG component provides the actual signal. Top-3 improves slightly over Config A alone (87.5% vs. 84.4%) because the equal blending occasionally pushes borderline candidates into the top 3. Top-5 reaches 100.0% because the combination of uniform graph scores and non-zero RAG scores ensures the correct actor appears somewhere in the top 5.

**Task B:** 100.0% abstention. The graph's uniform low scores dilute Config A's occasional high-confidence false attributions below the 0.70 threshold.

### 4.5 Config E — Full Hybrid (NexusCTI Unified Engine)

**Mechanism:** Dynamic IOC ingestion via `add_temporary_ioc_node()`, R-GCN inference, hybrid RAG retrieval, and `SynergisticFusionEngine` multi-modal score fusion with cross-validation.

**Task A:** 50.0% Top-1, **93.8% Top-3**, 100.0% Top-5, **MRR = 0.708**.

Config E matches Config A on Top-1 but surpasses it on Top-3 by +9.4 percentage points (30/32 vs. 27/32). The fusion engine's cross-validation and multi-modal scoring rescues 4 cases that Config A misses entirely:
- `cisa_aa22_054a_cyclops_blink` (Sandworm) — Config A rank: >5, Config E rank: 1
- `cisa_volt_typhoon_maritime` (Volt Typhoon) — Config A rank: >5, Config E rank: 2
- `talos_lazarus_magicrat` (Lazarus) — Config A rank: >5, Config E rank: 1
- `welivesecurity_apt28_lojax` (APT28) — Config A rank: >5, Config E rank: 3

Config E loses 1 case that Config A gets right:
- `cisa_aa24_057a_svr_cloud` (APT29) — Config A rank: 2, Config E rank: 4

**Task B:** 100.0% abstention (16/16). All predictions return `INCONCLUSIVE` verdict with fused confidence consistently below 0.40. The fusion engine's cross-validation mechanism correctly detects that novel actors produce inconsistent signals across modalities.

**Per-Actor Breakdown (Task A):**

| Actor | N | Top-1 | Top-3 |
|---|---|---|---|
| APT28 | 5 | 1/5 | **5/5** |
| APT29 | 5 | 0/5 | 3/5 |
| Sandworm | 5 | 2/5 | **5/5** |
| Lazarus | 6 | **6/6** | **6/6** |
| FIN7 | 5 | 2/5 | **5/5** |
| Volt Typhoon | 6 | 5/6 | **6/6** |

> [!NOTE]
> Config E achieves perfect Top-3 recall for 4 of 6 actors (APT28, Sandworm, Lazarus, Volt Typhoon). The weakest actor is APT29, where the fusion engine misranks 2 of 5 cases outside the top 3 (and all 5 outside the top 1). This may reflect overlap between APT29's cloud-focused TTPs and other actors in the retrieval corpus.

---

## 5. Statistical Comparison: Config E vs. Config A

### 5.1 Exact McNemar Test (Paired Top-3 Correctness, N = 32)

| Cell | Count | Description |
|---|---|---|
| **a** (both correct) | 26 | Both configs rank ground truth in top 3 |
| **b** (Hybrid only) | 4 | Config E correct, Config A incorrect |
| **c** (Vector only) | 1 | Config A correct, Config E incorrect |
| **d** (both wrong) | 1 | Neither ranks ground truth in top 3 |

| Statistic | Value |
|---|---|
| Discordant pairs | 5 |
| Paired risk difference | +9.38% (favoring Config E) |
| Odds ratio (b/c) | 4.0 |
| Exact McNemar p-value | **0.375** |
| Significant at α = 0.05? | **No** |
| Agresti-Min 95% CI | [−6.14%, +23.78%] |

### 5.2 Interpretation

The Full Hybrid outperforms Vector-only RAG by +9.4 percentage points on Top-3 accuracy, but with only 5 discordant pairs out of 32 cases, the exact McNemar test yields p = 0.375 — **far from statistical significance**. The 95% confidence interval spans from −6.1% to +23.8%, meaning the true difference could plausibly be zero or even slightly favour Vector-only.

> [!IMPORTANT]
> **We cannot claim that the Full Hybrid is statistically superior to Vector-only RAG on this sample.** The observed +9.4% advantage is directionally positive but insufficiently powered. A formal power analysis suggests approximately N ≥ 100 closed-set cases would be needed to detect a 10% difference at 80% power with α = 0.05.

---

## 6. Config E — Qualitative Analysis of Rescued Cases

The 4 cases where Config E succeeds but Config A fails deserve scrutiny:

1. **Cyclops Blink (Sandworm):** The query describes VPNFilter-successor IoT malware. Config A misses because the training corpus may lack dense Sandworm/VPNFilter material. Config E's dynamic IOC ingestion and graph trail via malware families likely provides the rescue.

2. **Volt Typhoon Maritime:** Living-off-the-land techniques against maritime infrastructure. Config E likely benefits from graph-encoded TTPs (T1078, T1046) that connect to `actor_volt_typhoon` via shared technique nodes.

3. **Lazarus MagicRAT:** Talos-disclosed RAT with unique C2. Config E's fusion may leverage malware-family graph edges connecting RAT indicators to the Lazarus cluster.

4. **APT28 LoJax (ESET):** UEFI rootkit campaign. Config E's cross-validation between GNN structural affinity and RAG narrative produces a consistent (though low-ranked) signal for APT28.

**The 1 case Config E loses:** `cisa_aa24_057a_svr_cloud` (APT29 cloud exploitation). Config E ranks APT29 4th instead of 2nd. The fusion engine's dynamic IOC ingestion may dilute the RAG signal by introducing graph-based noise from shared cloud technique nodes.

---

## 7. Threat to Validity: Config B's Artificial Top-3 and Top-5

Config B's 50.0% Top-3 and 84.4% Top-5 are **entirely artifacts of list-order tie-breaking**, not graph reasoning:

- 31/32 test IOCs are unseen in the graph → uniform scores for all 6 actors.
- Python's stable sort preserves the original `CANDIDATE_ACTORS` ordering when scores tie.
- `CANDIDATE_ACTORS = [apt28, apt29, lazarus, sandworm, volt_typhoon, fin7]`
- Therefore: Top-3 always contains APT28, APT29, Lazarus. Any case with those ground truths gets a "hit."
- Top-5 always contains the first 5 actors. Only FIN7 (position 6) would be excluded.

This is **not meaningful performance** and must not be compared to other configurations' Top-3/Top-5 scores.

---

## 8. Limitations

> [!CAUTION]
> The following limitations apply to all results in this report.

1. **Sample Size (N = 48):** This evaluation has limited statistical power. The McNemar test on 32 Task A cases cannot detect differences smaller than ~15% at conventional significance levels.

2. **Closed Candidate Set (6 actors):** Task A evaluates attribution among only 6 known actors. Real-world attribution involves hundreds of tracked groups. Random baseline performance is 16.7% Top-1, substantially higher than in operational settings.

3. **Transductive Graph Architecture:** The R-GCN is transductive — it cannot generate embeddings for nodes absent from the training graph. Since 47/48 test IOCs are unseen, Config C (GNN-only) has effectively zero signal. This is a fundamental architectural limitation, not a bug.

4. **Substring IOC Leakage:** One test IOC (`185.141.63.120`) matched a training graph node (`185.141.63.12`) via substring matching. This contaminated 1/32 Task A cases for graph-dependent configurations (B, C, E).

5. **RAG Corpus Proximity:** Config A's 50% Top-1 suggests substantial semantic overlap between the test passages and the training corpus descriptions. The test passages are excerpts from government advisories that describe actor TTPs in similar language to the corpus entries. This is not memorization, but it is domain-specific vocabulary overlap that would be weaker on novel, undocumented threats.

6. **No Distractor Noise:** The test cases contain clean, professionally written advisory passages. Operational SOC telemetry is noisier, more fragmentary, and may contain misleading indicators. Performance would likely degrade on raw alert data.

7. **Sequential Evaluation Order:** Config E runs `analyze()` which calls `add_temporary_ioc_node()`, mutating the graph mid-evaluation. Since all 48 cases are evaluated in sequence, later cases may have a slightly different graph topology. However, the added nodes are isolated (no edges to actors), so the impact is negligible.

8. **Task B Threshold Dependency:** The 0.70 confidence threshold for abstention is a design parameter, not a learned decision boundary. Different thresholds would yield different abstention rates, particularly for Config A which has 4 false attributions just above 0.70.

---

## 9. Supported Claims vs. Unproven Claims

### ✅ Supported by Evidence

| Claim | Evidence |
|---|---|
| Config E achieves the highest Top-3 accuracy (93.8%) among all 5 configurations on this 48-case benchmark | per_case_predictions.csv, independently verified |
| Config E achieves 100% proper abstention on all 16 Task B cases | per_case_predictions.csv: all Task B verdicts = INCONCLUSIVE |
| Config C (isolated GNN) has zero predictive power on novel external indicators | 0/32 Top-1, 0/32 Top-3, MRR = 0.005 |
| Config B's Top-1 accuracy on external data is inflated by tie-breaking artifacts | 4/5 correct predictions are tie-break wins on APT28 cases with uniform scores |
| Config A (Vector-only) produces false attributions on 25% of novel-actor cases | 4/16 Task B cases with confidence > 0.70 |
| Config E's fusion engine suppresses false attributions that Config A makes | Config E: 0/16 false attributions vs. Config A: 4/16 |
| The hybrid architecture provides incremental Top-3 gains over vector-only retrieval | +9.4 percentage points, 4 rescued cases documented |

### ❌ Not Supported / Unproven

| Claim | Why Not Supported |
|---|---|
| Config E is statistically superior to Config A | McNemar p = 0.375, 95% CI includes zero |
| The hybrid system generalizes to open-world attribution | Only 6 candidate actors; real-world has hundreds |
| GNN structural reasoning contributes meaningfully to external predictions | Config C = 0% on all metrics; the GNN is transductive and blind to novel IOCs |
| Results would hold on operational SOC telemetry | Test uses clean advisory excerpts, not noisy alert data |
| The +9.4% Top-3 improvement is a reliable estimate of the true hybrid advantage | 95% CI = [−6.1%, +23.8%]; the estimate is very noisy |

---

## 10. Artifact Inventory

All artifacts are stored under `experiments/phase11_large_sample_evaluation/`:

| File | Description | Rows/Size |
|---|---|---|
| [`dataset_manifest.csv`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/dataset_manifest.csv) | 48-case input manifest with provenance | 48 rows |
| [`run_phase11_evaluation.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/run_phase11_evaluation.py) | Evaluation runner script | 445 lines |
| [`per_case_predictions.csv`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/per_case_predictions.csv) | Per-case predictions for all 5 configs × 48 cases | 240 rows |
| [`metrics_summary.csv`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/metrics_summary.csv) | Aggregated metrics per configuration | 5 rows |
| [`benchmark_metrics.json`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/benchmark_metrics.json) | Full metrics + McNemar test results | JSON |
| [`runtime_summary.json`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/runtime_summary.json) | Per-config and total runtime | JSON |
| [`reproducibility_manifest.json`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/reproducibility_manifest.json) | Environment, command, and provenance | JSON |
| [`phase11_evaluation_report.md`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_large_sample_evaluation/phase11_evaluation_report.md) | This report | — |

### Phase 3 Preservation Verified

- Directory `experiments/scientific_audit_20261010_223000/` contains no Phase 11 files.
- Historical backup at `experiments/scientific_audit_20261010_223000/historical_run_artifacts/` intact (6 files).

---

## 11. Conclusions

1. **The Full Hybrid (Config E) is the best-performing configuration** on this benchmark, achieving 93.8% Top-3, 100% Top-5, 0.708 MRR, and zero false attributions. However, the advantage over Config A (Vector-only) is not statistically significant (p = 0.375).

2. **The GNN component has no value on novel external indicators.** Config C achieves 0% on every metric. The transductive R-GCN architecture fundamentally cannot generalize to IOCs absent from its training graph.

3. **The fusion engine's primary contribution is abstention quality, not accuracy.** Config E achieves 100% proper abstention vs. Config A's 75% — a clear and operationally important difference. The fusion engine's cross-validation mechanism correctly detects inconsistent signals from novel actors.

4. **Config B's apparent performance is a tie-breaking artifact.** Graph-only topological reasoning has no signal for unseen IOCs. Its Top-1 accuracy of 15.6% is entirely due to the default sort order placing APT28 first.

5. **Scaling the evaluation to N ≥ 100 closed-set cases is needed** to obtain statistically powered comparisons between configurations.
