#!/usr/bin/env python3
"""
Remediated Evaluation Suite for NexusCTI Benchmark.

Implements all methodological safeguards defined in the Phase 11 post-run audit:
1. Strict exact-match IOC resolution (eliminates substring matches).
2. Separation of predictor inputs from ground truth labels (evaluator-only ground truth).
3. Fair threat actor entity redaction from input narratives.
4. Permutation-invariant tie handling for Config B (eliminates list-order bias).
5. Strict graph state isolation for Config D and Config E (prevents baseline graph mutation).
6. Diagnostic labeling of Config C (GNN-only transductive baseline).
7. Valid paired statistical inference (Exact McNemar p-value and Agresti-Min 95% CI).
"""

import argparse
import csv
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import networkx as nx

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from nexuscti.service import get_service
from experiments.phase11_remediation.tie_handling import evaluate_ranked_prediction
from experiments.phase11_remediation.sanitization import redact_actor_entities

REMEDIATION_DIR = Path(__file__).resolve().parent
INPUTS_PATH = REMEDIATION_DIR / "predictor_inputs.csv"
LABELS_PATH = REMEDIATION_DIR / "ground_truth_labels.csv"

CANDIDATE_ACTORS = [
    "actor_apt28",
    "actor_apt29",
    "actor_lazarus",
    "actor_sandworm",
    "actor_volt_typhoon",
    "actor_fin7",
]


def exact_mcnemar_p_value(b: int, c: int) -> float:
    """Exact two-sided binomial McNemar test."""
    n_d = b + c
    if n_d == 0:
        return 1.0
    k = max(b, c)
    tail = sum(math.comb(n_d, i) * (0.5 ** n_d) for i in range(k, n_d + 1))
    return min(1.0, 2.0 * tail)


def agresti_min_interval(b: int, c: int, n: int) -> Tuple[float, float]:
    """
    95% Agresti-Min (2005) pseudo-observation paired confidence interval.
    Reference: Agresti, A. & Min, Y. (2005). Statistics in Medicine, 24(5), 729-740.
    """
    z = 1.959963984540054
    n_tilde = n + 2.0
    p12_tilde = (b + 1.0) / n_tilde
    p21_tilde = (c + 1.0) / n_tilde
    diff_tilde = p12_tilde - p21_tilde
    var_tilde = (p12_tilde + p21_tilde - (diff_tilde ** 2)) / n_tilde
    se_tilde = math.sqrt(max(0.0, var_tilde))
    low = max(-1.0, diff_tilde - z * se_tilde)
    high = min(1.0, diff_tilde + z * se_tilde)
    return low, high


class RemediatedBenchmarkRunner:
    def __init__(self, inputs_path: Path = INPUTS_PATH, labels_path: Path = LABELS_PATH):
        self.service = get_service()
        self.actor_ids = list(CANDIDATE_ACTORS)
        self.inputs_path = inputs_path
        self.labels_path = labels_path

        self.inputs = self._load_csv(self.inputs_path)
        self.labels = {r["case_id"]: r for r in self._load_csv(self.labels_path)}

        # Record initial baseline graph state
        self.baseline_node_count = len(self.service.tkg.raw_nodes)
        self.baseline_edge_count = self.service.tkg.nx_graph.number_of_edges()

    def _load_csv(self, path: Path) -> List[Dict[str, str]]:
        rows = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
        return rows

    def verify_graph_invariance(self, context_name: str):
        """Verifies that the shared knowledge graph has not been mutated."""
        current_nodes = len(self.service.tkg.raw_nodes)
        current_edges = self.service.tkg.nx_graph.number_of_edges()
        if current_nodes != self.baseline_node_count or current_edges != self.baseline_edge_count:
            raise RuntimeError(
                f"[LEAKAGE/MUTATION DETECTED in {context_name}] Graph state changed! "
                f"Expected {self.baseline_node_count} nodes, {self.baseline_edge_count} edges; "
                f"found {current_nodes} nodes, {current_edges} edges."
            )

    # --- CONFIGURATION A: VECTOR-ONLY RAG ---
    def predict_config_a(self, query: str) -> List[Tuple[str, float]]:
        # Predictor sees ONLY sanitized passage
        results = self.service.hybrid_retriever.dense.search(query, top_k=5)
        scores = defaultdict(float)
        for chunk, score in results:
            scores[chunk.target_actor] += max(score, 0.0)
        total = sum(scores.values()) or 1.0
        ranked = [(a, round(scores.get(a, 0.0) / total, 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIGURATION B: GRAPH-ONLY TOPOLOGICAL ---
    def predict_config_b(self, ioc: str) -> List[Tuple[str, float]]:
        # Uses strict exact-match lookup; returns 0.0 for all actors if unseen
        node = self.service.tkg.find_node_by_indicator(ioc)
        if not node:
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

    # --- CONFIGURATION C: GNN-ONLY NEURAL (DIAGNOSTIC BASELINE) ---
    def predict_config_c(self, ioc: str) -> List[Tuple[str, float]]:
        # Strictly isolated GNN inference; returns 0.0 if IOC is not in training graph
        node = self.service.tkg.find_node_by_indicator(ioc)
        if node is None:
            return [(a, 0.0) for a in self.actor_ids]

        raw_preds = self.service.gnn_trainer.predict_attribution_gnn_only(node.id)
        scores_map = {p["actor_id"]: p["structural_confidence"] for p in raw_preds}
        ranked = [(a, round(scores_map.get(a, 0.0), 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIGURATION D: GRAPH + RAG (NON-NEURAL) ---
    def predict_config_d(self, query: str, ioc: str) -> List[Tuple[str, float]]:
        # Combines Config A and Config B; guaranteed not to mutate graph
        preds_a = dict(self.predict_config_a(query))
        preds_b = dict(self.predict_config_b(ioc))
        combined = {a: round(0.5 * preds_a.get(a, 0.0) + 0.5 * preds_b.get(a, 0.0), 4) for a in self.actor_ids}
        ranked = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIGURATION E: FULL HYBRID (NEXUSCTI UNIFIED) ---
    def predict_config_e(self, query: str, ioc: str) -> Tuple[List[Tuple[str, float]], str, int, bool]:
        # Evaluated inside isolated_graph_context to prevent state accumulation
        with self.service.tkg.isolated_graph_context():
            res = self.service.analyze(query, ioc_override=ioc)
            scores_map = {c.actor_id: round(c.fused_confidence, 4) for c in res.all_candidates}
            ranked = [(a, scores_map.get(a, 0.0)) for a in self.actor_ids]
            ranked.sort(key=lambda x: x[1], reverse=True)
            verdict = res.top_actor.verdict if res.top_actor else "INCONCLUSIVE"
            depth = res.multi_hop_depth
            has_trail = bool(res.graph_trail and len(res.graph_trail.hops) > 0)
            return ranked, verdict, depth, has_trail

    def execute_dry_run_audit(self) -> Dict[str, any]:
        """
        Validates pipeline integrity, IOC exact matching, and state isolation
        without running the full benchmark.
        """
        print("[*] Performing Dry-Run Remediation Audit...")
        # 1. Verify exact indicator lookup behavior
        leak_ioc = "185.141.63.120"
        leaked_match = self.service.tkg.find_node_by_indicator(leak_ioc)
        assert leaked_match is None, f"Substring match regression! {leak_ioc} matched {leaked_match}"

        # 2. Verify legitimate IOC matches
        valid_ioc = "185.225.17.42"
        valid_match = self.service.tkg.find_node_by_indicator(valid_ioc)
        assert valid_match is not None, f"Valid IOC lookup failed for {valid_ioc}"

        # 3. Verify graph invariance before and after test inference
        self.verify_graph_invariance("pre-inference")

        # 4. Run test prediction with Config E and verify rollback
        test_case = self.inputs[0]
        preds_e, _, _, _ = self.predict_config_e(
            test_case["sanitized_passage_excerpt"], test_case["anchor_ioc"]
        )
        self.verify_graph_invariance("post-Config E test inference")

        print("[+] Dry-Run Audit Passed: Exact matching verified, graph invariance confirmed.")
        return {
            "status": "READY_FOR_EXECUTION",
            "baseline_nodes": self.baseline_node_count,
            "baseline_edges": self.baseline_edge_count,
            "total_test_cases": len(self.inputs),
            "graph_isolation_verified": True,
        }

    def run_full(self) -> Dict[str, any]:
        """
        Executes the full remediated evaluation across all 5 configurations.
        Guarantees strict graph invariance and exact tie handling throughout.
        """
        print("=" * 70)
        print("EXECUTING REMEDIATED NEXUS-CTI ATTRIBUTION BENCHMARK")
        print("=" * 70)

        configs = [
            ("Config A (Vector-only)", "vector_only"),
            ("Config B (Graph-only)", "graph_only"),
            ("Config C (Diagnostic GNN-only)", "gnn_only"),
            ("Config D (Graph + RAG)", "graph_plus_rag"),
            ("Config E (Full Hybrid)", "full_hybrid"),
        ]

        per_case_rows = []
        metrics_rows = []
        task_a_hits_top3 = {}
        full_results = {}

        total_bench_t0 = time.time()

        for cfg_name, cfg_key in configs:
            print(f"\n[*] Evaluating {cfg_name}...")
            cfg_t0 = time.time()

            top1_sum = 0.0
            top3_sum = 0.0
            top5_sum = 0.0
            mrr_sum = 0.0
            task_a_count = 0
            hallucinations = 0
            task_b_count = 0
            task_b_abstentions = 0
            task_b_false_attr = 0

            cfg_top3_binary = []

            for row in self.inputs:
                cid = row["case_id"]
                label_info = self.labels[cid]
                task_type = label_info["task_type"]
                is_task_a = "Task A" in task_type
                gt_actor = label_info["ground_truth_actor"]
                passage = row["sanitized_passage_excerpt"]
                ioc = row["anchor_ioc"]

                t0 = time.time()
                verdict = "INCONCLUSIVE"
                depth = 0
                has_trail = False

                if cfg_key == "vector_only":
                    ranked = self.predict_config_a(passage)
                elif cfg_key == "graph_only":
                    ranked = self.predict_config_b(ioc)
                elif cfg_key == "gnn_only":
                    ranked = self.predict_config_c(ioc)
                elif cfg_key == "graph_plus_rag":
                    ranked = self.predict_config_d(passage, ioc)
                elif cfg_key == "full_hybrid":
                    ranked, verdict, depth, has_trail = self.predict_config_e(passage, ioc)

                elapsed = round(time.time() - t0, 5)

                # Strict graph invariance check after every single prediction
                self.verify_graph_invariance(f"{cfg_name} case {cid}")

                top_actor = ranked[0][0] if ranked and ranked[0][1] > 0 else "NONE"
                top_conf = ranked[0][1] if ranked else 0.0

                eval_stats = evaluate_ranked_prediction(ranked, gt_actor, self.actor_ids)

                if is_task_a:
                    task_a_count += 1
                    top1_sum += eval_stats["top1_expected"]
                    top3_sum += eval_stats["top3_expected"]
                    top5_sum += eval_stats["top5_expected"]
                    mrr_sum += eval_stats["mrr_fractional"]

                    # Binary classification for McNemar test: whether GT is in top 3
                    cfg_top3_binary.append(1 if eval_stats["top3_expected"] >= 0.5 else 0)

                    if eval_stats["top1_expected"] < 0.5:
                        hallucinations += 1
                else:
                    task_b_count += 1
                    # In Task B, proper abstention occurs when confidence < 0.40 or verdict != PROBABLE
                    is_abstained = (verdict != "PROBABLE" and top_conf < 0.40) or (top_actor == "NONE")
                    if is_abstained:
                        task_b_abstentions += 1
                    else:
                        task_b_false_attr += 1

                per_case_rows.append({
                    "config": cfg_name,
                    "case_id": cid,
                    "task_type": task_type,
                    "anchor_ioc": ioc,
                    "ground_truth": gt_actor,
                    "predicted_top1": top_actor,
                    "confidence": top_conf,
                    "verdict": verdict,
                    "fractional_rank": round(eval_stats["rank_fractional"], 2),
                    "top1_hit": round(eval_stats["top1_expected"], 4),
                    "top3_hit": round(eval_stats["top3_expected"], 4),
                    "top5_hit": round(eval_stats["top5_expected"], 4),
                    "is_tied": bool(eval_stats["is_tied"]),
                    "runtime_sec": elapsed,
                })

            task_a_hits_top3[cfg_key] = cfg_top3_binary
            cfg_total_time = round(time.time() - cfg_t0, 4)

            top1_pct = round((top1_sum / max(1, task_a_count)) * 100, 2)
            top3_pct = round((top3_sum / max(1, task_a_count)) * 100, 2)
            top5_pct = round((top5_sum / max(1, task_a_count)) * 100, 2)
            mrr_avg = round(mrr_sum / max(1, task_a_count), 4)
            abstention_pct = round((task_b_abstentions / max(1, task_b_count)) * 100, 2)

            print(f"    Task A Top-1: {top1_pct:.1f}% | Top-3: {top3_pct:.1f}% | Top-5: {top5_pct:.1f}% | MRR: {mrr_avg:.4f}")
            print(f"    Task B Abstention: {abstention_pct:.1f}% ({task_b_abstentions}/{task_b_count}) | False Attr: {task_b_false_attr}")
            print(f"    Runtime: {cfg_total_time:.3f}s")

            metrics_rows.append({
                "configuration": cfg_name,
                "task_a_top1_expected_pct": top1_pct,
                "task_a_top3_expected_pct": top3_pct,
                "task_a_top5_expected_pct": top5_pct,
                "task_a_mrr": mrr_avg,
                "task_a_hallucinations": hallucinations,
                "task_b_abstention_pct": abstention_pct,
                "task_b_false_attributions": task_b_false_attr,
                "runtime_sec": cfg_total_time,
            })

            full_results[cfg_key] = {
                "name": cfg_name,
                "task_a": {
                    "top1_pct": top1_pct,
                    "top3_pct": top3_pct,
                    "top5_pct": top5_pct,
                    "mrr": mrr_avg,
                    "hallucinations": hallucinations,
                    "denominator": task_a_count,
                },
                "task_b": {
                    "abstention_pct": abstention_pct,
                    "abstentions": task_b_abstentions,
                    "false_attributions": task_b_false_attr,
                    "denominator": task_b_count,
                },
                "runtime_sec": cfg_total_time,
            }

        # Paired Statistical Inference: Config E vs Config A on Task A Top-3
        e_bin = task_a_hits_top3["full_hybrid"]
        a_bin = task_a_hits_top3["vector_only"]
        b = sum(1 for e, a in zip(e_bin, a_bin) if e == 1 and a == 0)
        c = sum(1 for e, a in zip(e_bin, a_bin) if e == 0 and a == 1)
        p_val = exact_mcnemar_p_value(b, c)
        ci_low, ci_high = agresti_min_interval(b, c, len(e_bin))

        stats_summary = {
            "comparison": "Config E vs Config A (Task A Top-3)",
            "n_pairs": len(e_bin),
            "discordant_b_e_better": b,
            "discordant_c_a_better": c,
            "exact_mcnemar_p_value": round(p_val, 4),
            "agresti_min_95ci": [round(ci_low, 4), round(ci_high, 4)],
            "statistically_significant": bool(p_val < 0.05 and (ci_low > 0 or ci_high < 0)),
        }
        full_results["statistical_test"] = stats_summary

        # Write CSVs and JSON
        preds_out = REMEDIATION_DIR / "per_case_predictions.csv"
        with open(preds_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(per_case_rows[0].keys()))
            writer.writeheader()
            writer.writerows(per_case_rows)

        summary_out = REMEDIATION_DIR / "metrics_summary.csv"
        with open(summary_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(metrics_rows[0].keys()))
            writer.writeheader()
            writer.writerows(metrics_rows)

        json_out = REMEDIATION_DIR / "benchmark_metrics.json"
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(full_results, f, indent=2)

        print("\n" + "=" * 70)
        print("BENCHMARK EXECUTION COMPLETE")
        print(f"Total Elapsed Time: {time.time() - total_bench_t0:.3f}s")
        print(f"Artifacts saved to: {REMEDIATION_DIR}")
        print(f"McNemar p-value: {p_val:.4f} | 95% CI: [{ci_low:.4f}, {ci_high:.4f}]")
        print("=" * 70)

        return full_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remediated Benchmark Runner")
    parser.add_argument("--dry-run", action="store_true", help="Run dry-run integrity audit only")
    parser.add_argument("--run-full", action="store_true", help="Execute the full remediated benchmark")
    args = parser.parse_args()

    runner = RemediatedBenchmarkRunner()
    if args.dry_run:
        audit_res = runner.execute_dry_run_audit()
        print(json.dumps(audit_res, indent=2))
    elif args.run_full:
        runner.run_full()
    else:
        print("[!] Specify --dry-run or --run-full.")

