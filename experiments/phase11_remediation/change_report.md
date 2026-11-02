# Phase 11 Audit Remediation: Concise Change Report

**Date**: 2026-11-02  
**Target**: NexusCTI Cyber Attribution Benchmark Suite  
**Remediation Directory**: [`experiments/phase11_remediation/`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation)  
**Status**: Remediation Implemented & Tested; Benchmark Execution Deferred Pending Review  

---

## 1. Files Changed & Added

### Core Codebase
* [`nexuscti/gnn/graph_builder.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/nexuscti/gnn/graph_builder.py)
  * Removed Pass 3 substring matching (`node.name.lower() in val.lower()`) from `find_node_by_indicator()`.
  * Implemented strict exact matching on normalized values, defanged tokens, and structured IOC IDs.
  * Added `remove_temporary_ioc_node()` for explicit temporary node deletion.
  * Added `isolated_graph_context()` context manager for automatic node/edge rollback.
  * *Backup preserved*: `nexuscti/gnn/graph_builder.py.bak`.

### Remediation Suite (`experiments/phase11_remediation/`)
* [`sanitization.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/sanitization.py): Comprehensive regex entity redaction engine for scrubbing actor names, aliases, and affiliations from CTI narratives.
* [`tie_handling.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/tie_handling.py): Permutation-invariant fractional ranking and expected Top-K evaluator.
* [`predictor_inputs.csv`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/predictor_inputs.csv): Isolated model input dataset (sanitized narratives + anchor IOCs, zero ground-truth labels).
* [`ground_truth_labels.csv`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/ground_truth_labels.csv): Isolated evaluation ground-truth dataset.
* [`remediated_evaluator.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/remediated_evaluator.py): Remediated benchmark runner with exact matching, graph invariance assertions, and paired statistical testing.
* [`test_remediation_regressions.py`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/test_remediation_regressions.py): 8 focused regression tests for leakage elimination, redaction, tie invariance, and graph isolation.
* [`revised_benchmark_protocol.md`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/revised_benchmark_protocol.md): Formal protocol specification.
* [`pre_run_checklist.md`](file:///Users/ankitbhattacharya/Documents/project/NexusCTI-main/experiments/phase11_remediation/pre_run_checklist.md): Pre-execution verification checklist.

---

## 2. Audit Findings Addressed

1. **Substring IOC Match Eliminated**: Test IOC `185.141.63.120` no longer matches graph node `185.141.63.12`. It correctly returns `None`.
2. **Actor Name Disclosure in Passages Removed**: All 48 passages in `predictor_inputs.csv` have been scrubbed of candidate actor names, aliases, and affiliations. The models now evaluate behavioral TTPs and telemetry.
3. **Config B Tie-Breaking Bias Eliminated**: Uniform tied scores (0.1667) on unseen IOCs are evaluated using fractional ranks (3.5) and expected Top-K probabilities ($1/6$ for Top-1, $3/6$ for Top-3, $5/6$ for Top-5). Candidate list order has zero effect.
4. **Graph State Mutation Prevented**: Config E and Config D execute within strict graph invariance guards; baseline node count ($65$) and edge count ($130$) remain immutable.
5. **Architectural Separation Enforced**: Ground truth labels are completely separated into `ground_truth_labels.csv` and never enter predictor inputs.
6. **Diagnostic Baseline Clarity**: Config C is explicitly designated as a diagnostic baseline testing transductive GNN limits on out-of-distribution infrastructure.

---

## 3. Tests Run & Results

* **Regression Test Suite**:
  ```bash
  PYTHONPATH=. ./.venv/bin/pytest experiments/phase11_remediation/test_remediation_regressions.py
  ```
  **Result**: **8 passed in 2.20s** (100% pass rate).
  * `test_strict_exact_ioc_matching_leak_case`: PASS
  * `test_strict_exact_ioc_matching_prefixes_and_suffixes`: PASS
  * `test_actor_name_redaction_comprehensive`: PASS
  * `test_predictor_inputs_zero_unredacted_candidate_tokens`: PASS
  * `test_tie_handling_permutation_invariance`: PASS
  * `test_graph_state_isolation_context`: PASS
  * `test_runner_graph_invariance_across_predictions`: PASS
  * `test_ground_truth_isolation`: PASS

* **Full Existing Test Suite**:
  ```bash
  PYTHONPATH=. ./.venv/bin/pytest tests/
  ```
  **Result**: **43 passed in 2.39s** (100% pass rate; zero regressions across existing codebase).

* **Dry-Run Evaluator Audit**:
  ```bash
  PYTHONPATH=. ./.venv/bin/python experiments/phase11_remediation/remediated_evaluator.py --dry-run
  ```
  **Result**: **PASSED** (`READY_FOR_EXECUTION`; 65 nodes, 130 edges invariant).

---

## 4. Remaining Risks

1. **Dense Retrieval Accuracy Drop Under Redacted Narratives**: Scrubbing explicit actor names like *"APT28"* or *"Lazarus"* will likely reduce Config A's Top-3 accuracy compared to the unredacted Phase 11 baseline (84.4%). This is expected and desirable: it measures true behavioral attribution rather than string matching.
2. **Small Candidate Actor Set**: With 6 closed-set candidate actors, random guessing yields $16.7\%$ Top-1 and $50.0\%$ Top-3. Statistical power on $N=32$ closed-set cases requires noticeable effect sizes to reach significance.
3. **Transductive GNN Generalization**: Config C will continue to score near 0% on unseen indicators by design; inductive graph extension or node feature mapping is required for GNN reasoning on novel IOCs.

---

## 5. Exact Command to Run the Benchmark Later

When authorized to execute the remediated benchmark:
```bash
PYTHONPATH=. ./.venv/bin/python experiments/phase11_remediation/remediated_evaluator.py --run-full
```
*(Currently blocked by evaluation guardrails until human confirmation is received).*

---

## 6. Explicit GO/NO-GO Recommendation

* **Benchmark Execution**: **HOLD / REQUEST REVIEW**. The remediation implementation is complete, verified, and passing all regression tests. Per user instruction, execution must stop here for user inspection.
* **Architecture & Safeguards**: **GO**. The safeguards completely eliminate substring leakage, entity prompt leakage, tie-breaking artifacts, and graph state mutation.
