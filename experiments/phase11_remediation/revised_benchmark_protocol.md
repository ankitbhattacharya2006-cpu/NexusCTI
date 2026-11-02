# Revised Benchmark Protocol: Sanitized & Isolated Attribution Evaluation

**Protocol Version**: 2.0 (Post-Audit Remediated)  
**Target Suite**: NexusCTI Cyber Attribution Engine  
**Dataset**: 48 Authentic External Threat Intelligence Campaigns  
**Task Split**: 32 Closed-Set Attribution Cases (Task A), 16 Open-Set Abstention Cases (Task B)  

---

## 1. Objectives & Methodological Principles

This revised protocol supersedes the Phase 11 experimental setup. It establishes strict experimental isolation, mathematical rigor, and objective attribution evaluation by addressing every methodological vulnerability uncovered during the Phase 11 post-run audit:

1. **Strict Exact-Match Indicator Resolution**: Complete elimination of substring searches (`node.name in val` or `val in node.name`). Indicators must match either exact node names, normalized defanged values, or structured IOC IDs.
2. **Architectural Separation of Predictor Inputs and Ground Truth**: Models and retrieval pipelines receive *only* feature inputs (`sanitized_passage_excerpt`, `anchor_ioc`). Ground truth labels (`attributed_actor`, `task_type`, `expected_verdict`) are held in a separate evaluator store and are inaccessible during inference.
3. **Actor Name Entity Redaction**: All threat actor names, public aliases, sponsoring military units, and state intelligence agencies are masked with standardized redaction tokens (`[REDACTED_ACTOR]`, `[REDACTED_AFFILIATION]`). This ensures text retrieval evaluates behavioral TTPs and telemetry rather than trivial keyword lookup.
4. **Order-Invariant Tie Handling**: Candidate ties (such as uniform distances on unseen IOCs) are evaluated using fractional ranking and expected Top-K hit probabilities under random tie-breaking. Arbitrary candidate-list order cannot award artificial hits.
5. **Strict Graph State Invariance**: The 65-node, 130-edge baseline knowledge graph is verified to be immutable across all test cases and configurations. Temporary nodes created during hybrid analysis must be strictly rolled back.
6. **Explicit Baseline Labeling**: Config C is designated as a **diagnostic baseline** testing transductive GNN limits on out-of-distribution indicators, not an indicator of generalization.
7. **Statistically Grounded Claims**: Hybrid superiority claims require a statistically significant paired test ($\alpha = 0.05$) and a 95% paired confidence interval bounded away from zero.

---

## 2. Experimental Configurations

| Config ID | Designation | Input Modality | Mechanism | Isolation & Role |
| :--- | :--- | :--- | :--- | :--- |
| **Config A** | Vector-Only (RAG) | Sanitized Narrative | Character n-gram & word-hash dense retrieval over 6 corpus reports | Textual baseline; evaluates behavioral semantic matching |
| **Config B** | Graph-Only (Topological) | Anchor IOC | NetworkX shortest path distance to candidate actor nodes | Non-neural graph baseline; evaluates topological proximity |
| **Config C** | GNN-Only (Neural) | Anchor IOC | Isolated R-GCN relational embedding affinity | **Diagnostic baseline**; evaluates transductive GNN behavior on novel IOCs |
| **Config D** | Graph + RAG (Non-Neural) | Narrative + IOC | Equal-weighted blend ($0.5 \times \text{Config A} + 0.5 \times \text{Config B}$) | Non-neural multi-modal baseline; no graph mutation permitted |
| **Config E** | Full Hybrid (NexusCTI) | Narrative + IOC | Unified GNN + RAG + Multi-Hop Trail + Cross-Validation | Full hybrid system evaluated under `isolated_graph_context` |

---

## 3. Data Provenance & Architectural Separation

### 3.1 Predictor Inputs (`predictor_inputs.csv`)
Provided to the model during inference. Contains strictly no labels:
* `case_id`: Unique identifier (e.g., `cisa_aa23_347a_apt28_roundcube`).
* `task_type`: Task designation (`Task A (Closed-Set)` vs. `Task B (Open-Set)`).
* `anchor_ioc`: Real-world IOC (IPv4, domain, hash, or CVE).
* `sanitized_passage_excerpt`: CTI narrative with all actor names and aliases redacted.

### 3.2 Ground Truth Labels (`ground_truth_labels.csv`)
Retained exclusively by the evaluator:
* `case_id`: Joins with predictor inputs.
* `task_type`: Evaluation cohort.
* `ground_truth_actor`: True attributing entity (`actor_apt28`, `actor_apt29`, etc., or `novel_actor` for Task B).
* `expected_verdict`: `ATTRIBUTION` for Task A, `ABSTAIN` for Task B.

---

## 4. Evaluation Metrics & Mathematical Definitions

### 4.1 Closed-Set Attribution (Task A, $N=32$)
* **Top-1 Accuracy**: Fraction of cases where the ground-truth actor is ranked #1.
  * *Strict*: Only if strictly #1 without ties ($\text{score} > \text{next}$).
  * *Expected*: Probability under uniform random tie breaking ($1/m$ if tied across $m$ candidates).
* **Top-3 Accuracy**: Fraction of cases where the ground-truth actor is in Top-3.
  * *Strict*: Only if the entire tied group lies within Top-3 ($r_{\text{end}} \le 3$).
  * *Expected*: Overlap fraction $\frac{\min(3, r_{\text{end}}) - r_{\text{start}} + 1}{m}$.
* **Top-5 Accuracy**: Fraction of cases where ground truth is in Top-5 (strict and expected).
* **Mean Reciprocal Rank (MRR)**: Average of $1 / \text{rank}_{\text{fractional}}$.
* **Hallucination Rate**: Fraction of cases where a wrong actor is predicted at Top-1.

### 4.2 Open-Set Abstention (Task B, $N=16$)
* **Proper Abstention Rate**: Fraction of novel-actor cases where the system outputs `ABSTAIN` or confidence $< 0.40$ (denominator: 16).
* **False Attribution Rate**: Fraction of novel-actor cases where the system falsely attributes to a closed-set candidate (denominator: 16).

### 4.3 Paired Statistical Inference
For pairwise comparison between Config E and Config A on Task A:
* **Discordant Counts**: $b = \text{Count}(E=1, A=0)$, $c = \text{Count}(E=0, A=1)$.
* **Exact McNemar $p$-value**:
  $$p = \min\left(1.0, 2 \sum_{i=\max(b, c)}^{b+c} \binom{b+c}{i} 0.5^{b+c}\right)$$
* **Agresti-Min 95% Paired Confidence Interval**:
  $$\tilde{p}_{12} = \frac{b + 1}{n + 2}, \quad \tilde{p}_{21} = \frac{c + 1}{n + 2}, \quad \hat{\delta} = \tilde{p}_{12} - \tilde{p}_{21}$$
  $$\text{CI}_{95\%} = \hat{\delta} \pm 1.96 \sqrt{\frac{\tilde{p}_{12} + \tilde{p}_{21} - \hat{\delta}^2}{n + 2}}$$

---

## 5. Execution Invariants & Acceptance Criteria

1. **Graph Invariance**: Graph node count ($65$) and edge count ($130$) must be identical before and after each configuration run.
2. **Leakage Regression**: Test IOC `185.141.63.120` must resolve to `None`.
3. **Redaction Check**: Zero candidate actor names in input passages.
4. **Tie Invariance**: Reversing or shuffling candidate list order produces identical metric outputs.
