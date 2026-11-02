"""
NexusCTI Phase 11: 48-Case Authentic External CTI Benchmark Evaluation Runner
=============================================================================
Evaluates all five configurations under strictly blinded, campaign-disjoint conditions:
  - Task A (Closed-Set Generalization): N = 32 authentic threat campaigns across 6 known actors
  - Task B (Open-Set Abstention Fidelity): N = 16 authentic novel adversary / ambiguous campaigns
Evaluates:
  - Config A: Vector-only RAG
  - Config B: Graph-only (Topological shortest path)
  - Config C: GNN-only (Isolated neural message passing)
  - Config D: Graph + RAG (Non-neural graph + text)
  - Config E: Full Hybrid (NexusCTI Unified Engine)
Generates:
  - per_case_predictions.csv
  - metrics_summary.csv
  - benchmark_metrics.json
  - runtime_summary.json
  - reproducibility_manifest.json
  - phase11_master_report.md
"""

import sys
import time
import json
import csv
import math
import hashlib
import platform
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Tuple
import networkx as nx

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from nexuscti.service import get_service

PHASE11_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = PHASE11_DIR / "dataset_manifest.csv"

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


class Phase11EvaluationSuite:
    def __init__(self):
        print("[*] Initializing Phase 11 Evaluation Suite...")
        self.service = get_service()
        self.actor_ids = list(CANDIDATE_ACTORS)
        self.cases = self._load_manifest()
        print(f"    -> Loaded {len(self.cases)} authentic external campaigns.")
        self.task_a_cases = [c for c in self.cases if "Task A" in c["task_assignment"]]
        self.task_b_cases = [c for c in self.cases if "Task B" in c["task_assignment"]]
        print(f"    -> Task A (Closed-Set): {len(self.task_a_cases)} cases")
        print(f"    -> Task B (Open-Set):   {len(self.task_b_cases)} cases")

    def _load_manifest(self) -> List[Dict[str, str]]:
        rows = []
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
        return rows

    # --- CONFIG A: Vector-only RAG ---
    def predict_config_a(self, query: str) -> List[Tuple[str, float]]:
        results = self.service.hybrid_retriever.dense.search(query, top_k=5)
        scores = defaultdict(float)
        for chunk, score in results:
            scores[chunk.target_actor] += max(score, 0.0)
        total = sum(scores.values()) or 1.0
        ranked = [(a, round(scores.get(a, 0.0) / total, 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIG B: Graph-only Topological ---
    def predict_config_b(self, ioc: str) -> List[Tuple[str, float]]:
        node = self.service.tkg.find_node_by_indicator(ioc)
        if not node:
            # Unseen node has uniform prior distance
            return [(a, round(1.0 / len(self.actor_ids), 4)) for a in self.actor_ids]

        undirected_g = self.service.tkg.nx_graph.to_undirected()
        scores = {}
        for a_id in self.actor_ids:
            try:
                dist = nx.shortest_path_length(undirected_g, node.id, a_id)
                scores[a_id] = 1.0 / (1.0 + float(dist))
            except nx.NetworkXNoPath:
                scores[a_id] = 0.001

        total = sum(scores.values()) or 1.0
        ranked = [(a, round(scores.get(a, 0.0) / total, 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIG C: GNN-only Neural ---
    def predict_config_c(self, ioc: str) -> List[Tuple[str, float]]:
        node = self.service.tkg.find_node_by_indicator(ioc)
        if node is None:
            # Strictly isolated: returns empty prediction without graph mutation
            return [(a, 0.0) for a in self.actor_ids]

        raw_preds = self.service.gnn_trainer.predict_attribution_gnn_only(node.id)
        scores_map = {p["actor_id"]: p["structural_confidence"] for p in raw_preds}
        ranked = [(a, round(scores_map.get(a, 0.0), 4)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIG D: Graph + RAG Non-Neural ---
    def predict_config_d(self, query: str, ioc: str) -> List[Tuple[str, float]]:
        preds_a = dict(self.predict_config_a(query))
        preds_b = dict(self.predict_config_b(ioc))
        combined = {a: round(0.5 * preds_a.get(a, 0.0) + 0.5 * preds_b.get(a, 0.0), 4) for a in self.actor_ids}
        ranked = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        return ranked

    # --- CONFIG E: Full Hybrid NexusCTI ---
    def predict_config_e(self, query: str, ioc: str) -> Tuple[List[Tuple[str, float]], str, int, bool]:
        res = self.service.analyze(query, ioc_override=ioc)
        scores_map = {c.actor_id: round(c.fused_confidence, 4) for c in res.all_candidates}
        ranked = [(a, scores_map.get(a, 0.0)) for a in self.actor_ids]
        ranked.sort(key=lambda x: x[1], reverse=True)
        verdict = res.top_actor.verdict if res.top_actor else "INCONCLUSIVE"
        depth = res.multi_hop_depth
        has_trail = bool(res.graph_trail and len(res.graph_trail.hops) > 0)
        return ranked, verdict, depth, has_trail

    def run_all(self):
        configs = [
            ("Config A (Vector-only)", "vector_only"),
            ("Config B (Graph-only)", "graph_only"),
            ("Config C (GNN-only)", "gnn_only"),
            ("Config D (Graph + RAG)", "graph_plus_rag"),
            ("Config E (Full Hybrid)", "full_hybrid"),
        ]

        per_case_rows = []
        runtime_summary = {}
        all_metrics = {}
        total_suite_start = time.time()

        print("\n[*] Starting Blind Evaluation across 48 cases...")

        # Store predictions per config for Task A paired comparisons
        task_a_preds = {cfg_key: [] for _, cfg_key in configs}

        for cfg_name, cfg_key in configs:
            print(f"[*] Running {cfg_name}...")
            cfg_start = time.time()

            top1_c = 0
            top3_c = 0
            top5_c = 0
            reciprocal_ranks = []
            hallucinations = 0
            task_b_abstentions = 0
            task_b_false_attributions = 0

            for case in self.cases:
                cid = case["report_id"]
                cname = case["campaign_name"]
                task = case["task_assignment"]
                is_task_a = "Task A" in task
                gt_actor = case["attributed_actor"]
                passage = case["source_passage_excerpt"]
                ioc = case["anchor_ioc"]

                t0 = time.time()
                depth = 0
                has_trail = False
                verdict = "INCONCLUSIVE"

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

                top_actor = ranked[0][0] if ranked and ranked[0][1] > 0 else "NONE"
                top_conf = ranked[0][1] if ranked else 0.0

                # Compute rank of ground truth in candidate list
                actor_rank = 999
                for r_idx, (a_id, score) in enumerate(ranked, 1):
                    if a_id == gt_actor and score > 0:
                        actor_rank = r_idx
                        break

                if is_task_a:
                    is_correct_top1 = (top_actor == gt_actor)
                    is_correct_top3 = any(a == gt_actor for a, s in ranked[:3] if s > 0)
                    is_correct_top5 = any(a == gt_actor for a, s in ranked[:5] if s > 0)

                    if is_correct_top1:
                        top1_c += 1
                    else:
                        hallucinations += 1

                    if is_correct_top3:
                        top3_c += 1

                    if is_correct_top5:
                        top5_c += 1

                    rr = (1.0 / actor_rank) if actor_rank <= len(self.actor_ids) else 0.0
                    reciprocal_ranks.append(rr)

                    task_a_preds[cfg_key].append({
                        "case_id": cid,
                        "gt_actor": gt_actor,
                        "top1": top_actor,
                        "top1_correct": is_correct_top1,
                        "top3_correct": is_correct_top3,
                        "top_conf": top_conf,
                        "rank": actor_rank,
                    })
                else:
                    # Task B (Open-Set Abstention)
                    # For hybrid: verdict == INCONCLUSIVE indicates proper abstention
                    # For baselines: top_conf < 0.70 threshold indicates proper abstention
                    if cfg_key == "full_hybrid":
                        proper_abstain = (verdict == "INCONCLUSIVE" or top_conf < 0.70)
                    else:
                        proper_abstain = (top_conf < 0.70 or top_actor == "NONE")

                    if proper_abstain:
                        task_b_abstentions += 1
                    else:
                        task_b_false_attributions += 1

                    is_correct_top1 = proper_abstain
                    is_correct_top3 = proper_abstain
                    is_correct_top5 = proper_abstain

                per_case_rows.append({
                    "config": cfg_name,
                    "case_id": cid,
                    "campaign_name": cname,
                    "task": task,
                    "anchor_ioc": ioc,
                    "ground_truth": gt_actor,
                    "predicted_top1": top_actor,
                    "is_correct": is_correct_top1,
                    "rank": actor_rank if is_task_a else "N/A (Task B)",
                    "confidence": top_conf,
                    "verdict": verdict if cfg_key == "full_hybrid" else ("ABSTAIN" if top_conf < 0.70 else "CONFIDENT"),
                    "multi_hop_depth": depth,
                    "has_verified_trail": has_trail,
                    "runtime_sec": elapsed,
                })

            cfg_elapsed = round(time.time() - cfg_start, 4)
            runtime_summary[cfg_name] = {
                "total_sec": cfg_elapsed,
                "avg_per_case_sec": round(cfg_elapsed / len(self.cases), 5),
            }

            n_a = len(self.task_a_cases)
            n_b = len(self.task_b_cases)

            all_metrics[cfg_name] = {
                "task_a_n": n_a,
                "top1_accuracy_pct": round((top1_c / n_a) * 100.0, 2),
                "top1_count": f"{top1_c}/{n_a}",
                "top3_accuracy_pct": round((top3_c / n_a) * 100.0, 2),
                "top3_count": f"{top3_c}/{n_a}",
                "top5_accuracy_pct": round((top5_c / n_a) * 100.0, 2),
                "top5_count": f"{top5_c}/{n_a}",
                "mrr": round(sum(reciprocal_ranks) / n_a, 4),
                "hallucination_rate_pct": round((hallucinations / n_a) * 100.0, 2),
                "task_b_n": n_b,
                "task_b_proper_abstention_pct": round((task_b_abstentions / n_b) * 100.0, 2),
                "task_b_abstention_count": f"{task_b_abstentions}/{n_b}",
                "task_b_false_attribution_pct": round((task_b_false_attributions / n_b) * 100.0, 2),
                "task_b_false_attribution_count": f"{task_b_false_attributions}/{n_b}",
                "total_runtime_sec": cfg_elapsed,
                "avg_case_runtime_sec": round(cfg_elapsed / len(self.cases), 5),
            }

            print(f"    -> Top-1: {all_metrics[cfg_name]['top1_count']} ({all_metrics[cfg_name]['top1_accuracy_pct']}%) | "
                  f"Top-3: {all_metrics[cfg_name]['top3_count']} ({all_metrics[cfg_name]['top3_accuracy_pct']}%) | "
                  f"MRR: {all_metrics[cfg_name]['mrr']} | "
                  f"Task B Abstention: {all_metrics[cfg_name]['task_b_abstention_count']} ({all_metrics[cfg_name]['task_b_proper_abstention_pct']}%)")

        total_suite_elapsed = round(time.time() - total_suite_start, 3)
        runtime_summary["overall_suite_runtime_sec"] = total_suite_elapsed

        # --- STATISTICAL COMPARISON: Config E (Full Hybrid) vs Config A (Vector-only) ---
        print("\n[*] Computing statistical comparison between Full Hybrid and Vector-only RAG on Task A (N=32)...")
        hybrid_a = task_a_preds["full_hybrid"]
        vector_a = task_a_preds["vector_only"]

        # Top-3 paired table
        a_cell = 0  # Both correct
        b_cell = 0  # Hybrid correct, Vector incorrect
        c_cell = 0  # Hybrid incorrect, Vector correct
        d_cell = 0  # Both incorrect

        for eh, ev in zip(hybrid_a, vector_a):
            h_corr = eh["top3_correct"]
            v_corr = ev["top3_correct"]
            if h_corr and v_corr:
                a_cell += 1
            elif h_corr and not v_corr:
                b_cell += 1
            elif not h_corr and v_corr:
                c_cell += 1
            else:
                d_cell += 1

        mcnemar_p = exact_mcnemar_p_value(b_cell, c_cell)
        ci_low, ci_high = agresti_min_interval(b_cell, c_cell, len(self.task_a_cases))
        delta = round(((b_cell - c_cell) / len(self.task_a_cases)) * 100.0, 2)
        odds_ratio = round(b_cell / max(c_cell, 1), 2) if c_cell > 0 else (float("inf") if b_cell > 0 else 1.0)

        statistical_report = {
            "test_name": "Exact Two-Sided McNemar Test (Paired Top-3 Correctness)",
            "sample_size": len(self.task_a_cases),
            "contingency_table": {
                "both_correct_a": a_cell,
                "hybrid_only_correct_b": b_cell,
                "vector_only_correct_c": c_cell,
                "both_incorrect_d": d_cell,
            },
            "discordant_pairs": b_cell + c_cell,
            "paired_risk_difference_pct": delta,
            "agresti_min_95_ci_pct": [round(ci_low * 100.0, 2), round(ci_high * 100.0, 2)],
            "odds_ratio": odds_ratio if odds_ratio != float("inf") else "Infinity (b > 0, c = 0)",
            "exact_mcnemar_p_value": round(mcnemar_p, 5),
            "significance_at_alpha_0_05": (mcnemar_p < 0.05),
        }

        # --- WRITE OUTPUT ARTIFACTS ---
        print("\n[*] Writing Phase 11 artifacts...")

        # 1. per_case_predictions.csv
        with open(PHASE11_DIR / "per_case_predictions.csv", "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "config", "case_id", "campaign_name", "task", "anchor_ioc",
                "ground_truth", "predicted_top1", "is_correct", "rank",
                "confidence", "verdict", "multi_hop_depth", "has_verified_trail",
                "runtime_sec"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(per_case_rows)

        # 2. metrics_summary.csv
        with open(PHASE11_DIR / "metrics_summary.csv", "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "configuration", "task_a_n", "top1_accuracy_pct", "top1_count",
                "top3_accuracy_pct", "top3_count", "top5_accuracy_pct", "top5_count",
                "mrr", "hallucination_rate_pct", "task_b_n",
                "task_b_proper_abstention_pct", "task_b_abstention_count",
                "task_b_false_attribution_pct", "task_b_false_attribution_count",
                "total_runtime_sec", "avg_case_runtime_sec"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for cfg_name, m in all_metrics.items():
                writer.writerow({"configuration": cfg_name, **m})

        # 3. runtime_summary.json
        with open(PHASE11_DIR / "runtime_summary.json", "w", encoding="utf-8") as f:
            json.dump(runtime_summary, f, indent=2)

        # 4. benchmark_metrics.json
        with open(PHASE11_DIR / "benchmark_metrics.json", "w", encoding="utf-8") as f:
            json.dump({
                "phase": "phase11_large_sample_evaluation",
                "dataset_manifest": "dataset_manifest.csv",
                "total_cases": len(self.cases),
                "task_a_closed_set_n": len(self.task_a_cases),
                "task_b_open_set_n": len(self.task_b_cases),
                "metrics_per_configuration": all_metrics,
                "statistical_significance_test": statistical_report,
            }, f, indent=2)

        # 5. reproducibility_manifest.json
        with open(PHASE11_DIR / "reproducibility_manifest.json", "w", encoding="utf-8") as f:
            json.dump({
                "manifest_version": "1.0",
                "experiment_id": "phase11_large_sample_evaluation_20261031",
                "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "environment": {
                    "os": f"{platform.system()} {platform.release()}",
                    "python_executable": sys.executable,
                    "python_version": sys.version,
                },
                "execution_command": f"{sys.executable} experiments/phase11_large_sample_evaluation/run_phase11_evaluation.py",
                "total_cases_evaluated": len(self.cases),
                "dataset_provenance": "Authentic external CTI advisories (CISA, Microsoft MSRC, UK NCSC, ESET, Mandiant, US Treasury) 2020-2024",
                "status": "COMPLETED_REPRODUCIBLE",
            }, f, indent=2)

        print("[+] Phase 11 evaluation and artifact generation complete!")


if __name__ == "__main__":
    suite = Phase11EvaluationSuite()
    suite.run_all()
