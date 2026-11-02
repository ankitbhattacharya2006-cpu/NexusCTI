# Pre-Run Verification Checklist: Phase 11 Remediated Benchmark

This checklist must be systematically verified prior to executing any benchmark run under the remediated protocol.

---

## Pre-Execution Verification Table

| Item # | Verification Check | Expected State | Validation Method | Verified Status |
| :---: | :--- | :--- | :--- | :---: |
| **1** | Historical Artifact Preservation | Phase 3 and Phase 11 directories unmodified | `git status` check | **CONFIRMED** |
| **2** | Strict Exact IOC Matching | Substring search eliminated; `185.141.63.120` resolves to `None` | `test_strict_exact_ioc_matching_leak_case` | **CONFIRMED** |
| **3** | Predictor Input Sanitization | All 48 passages have actor names/aliases redacted; 0 candidate tokens | `test_predictor_inputs_zero_unredacted_candidate_tokens` | **CONFIRMED** |
| **4** | Architectural Separation | `predictor_inputs.csv` contains 0 ground truth fields; labels held separately | `test_ground_truth_isolation` | **CONFIRMED** |
| **5** | Order-Invariant Tie Handling | Tied candidates yield identical expected metrics under forward, reverse, and shuffled candidate lists | `test_tie_handling_permutation_invariance` | **CONFIRMED** |
| **6** | Baseline Graph Immutability | Graph node count = 65, edge count = 130 before and after Config A–E inference | `test_runner_graph_invariance_across_predictions` | **CONFIRMED** |
| **7** | Diagnostic Baseline Labeling | Config C explicitly documented as a diagnostic baseline for transductive limits | Code review of runner and protocol | **CONFIRMED** |
| **8** | Statistical Rigor Guardrails | Exact McNemar test and Agresti-Min 95% paired CI implemented; claims constrained to data | Code review of `remediated_evaluator.py` | **CONFIRMED** |
| **9** | Focused Test Suite | All 8 regression tests pass cleanly | `pytest experiments/phase11_remediation/test_remediation_regressions.py` | **PASS (8/8)** |
| **10** | Dry-Run Pipeline Validation | Evaluator dry-run completes with status `READY_FOR_EXECUTION` | `python experiments/phase11_remediation/remediated_evaluator.py --dry-run` | **PASS** |

---

## Execution Guardrail

> **CRITICAL REQUIREMENT**: Do **NOT** execute the benchmark until explicit human review and authorization have been granted. Benchmark execution is deferred.
