"""
Mathematically Principled Tie Handling for Attribution Benchmarks.

Provides permutation-invariant ranking and metric computation. When multiple
candidates have identical or near-identical confidence scores, this module
computes fractional ranks and expected Top-K hit probabilities under uniform
random tie breaking. This eliminates arbitrary list-order artifacts.
"""

from typing import Dict, List, Sequence, Tuple
import math


def evaluate_ranked_prediction(
    ranked_candidates: Sequence[Tuple[str, float]],
    ground_truth: str,
    all_candidate_ids: Sequence[str],
    tolerance: float = 1e-5,
) -> Dict[str, float]:
    """
    Evaluates a single case prediction with strict tie handling.

    Parameters:
        ranked_candidates: List of (actor_id, score) pairs.
        ground_truth: The true actor ID.
        all_candidate_ids: Full list of all candidate actor IDs.
        tolerance: Float threshold to consider two scores tied.

    Returns:
        Dictionary containing:
        - 'rank_fractional': Average rank across tied positions.
        - 'mrr_fractional': 1.0 / rank_fractional (0.0 if not in list or score <= 0).
        - 'top1_expected': Probability of inclusion in Top-1 under random tie break.
        - 'top3_expected': Probability of inclusion in Top-3 under random tie break.
        - 'top5_expected': Probability of inclusion in Top-5 under random tie break.
        - 'top1_strict': 1.0 if strictly #1 without ties, else 0.0.
        - 'top3_strict': 1.0 if strictly <= rank 3 without ties crossing cutoff, else 0.0.
        - 'top5_strict': 1.0 if strictly <= rank 5 without ties crossing cutoff, else 0.0.
        - 'is_tied': True if ground truth is in a tied group.
        - 'tied_group_size': Number of candidates tied with ground truth.
    """
    # Build complete mapping of scores for all candidates
    score_map: Dict[str, float] = {a: 0.0 for a in all_candidate_ids}
    for a_id, score in ranked_candidates:
        score_map[a_id] = float(score)

    # Sort candidates by score descending; stable sort tie-break is neutralized by grouping
    sorted_items = sorted(score_map.items(), key=lambda x: x[1], reverse=True)

    # Identify contiguous blocks of tied scores
    groups: List[List[Tuple[str, float]]] = []
    current_group: List[Tuple[str, float]] = []

    for item in sorted_items:
        if not current_group:
            current_group.append(item)
        else:
            prev_score = current_group[-1][1]
            if abs(item[1] - prev_score) <= tolerance:
                current_group.append(item)
            else:
                groups.append(current_group)
                current_group = [item]
    if current_group:
        groups.append(current_group)

    # Compute ranks and expectations
    current_pos = 1
    gt_stats: Dict[str, float] = {
        "rank_fractional": float(len(all_candidate_ids) + 1),
        "mrr_fractional": 0.0,
        "top1_expected": 0.0,
        "top3_expected": 0.0,
        "top5_expected": 0.0,
        "top1_strict": 0.0,
        "top3_strict": 0.0,
        "top5_strict": 0.0,
        "is_tied": 0.0,
        "tied_group_size": 1.0,
    }

    found = False
    for group in groups:
        group_size = len(group)
        r_start = current_pos
        r_end = current_pos + group_size - 1
        fractional_rank = (r_start + r_end) / 2.0

        group_actors = [actor for actor, _ in group]
        group_score = group[0][1]

        if ground_truth in group_actors:
            found = True
            # If the group score is 0.0 or negative, it indicates no evidence / unranked
            if group_score <= 0.0 and len(group) == len(all_candidate_ids):
                # Completely uninformative prediction (all 0.0)
                gt_stats["rank_fractional"] = float(fractional_rank)
                gt_stats["mrr_fractional"] = 1.0 / fractional_rank
                gt_stats["top1_expected"] = 1.0 / len(all_candidate_ids)
                gt_stats["top3_expected"] = min(3.0, len(all_candidate_ids)) / len(all_candidate_ids)
                gt_stats["top5_expected"] = min(5.0, len(all_candidate_ids)) / len(all_candidate_ids)
                gt_stats["top1_strict"] = 0.0
                gt_stats["top3_strict"] = 0.0
                gt_stats["top5_strict"] = 0.0
                gt_stats["is_tied"] = 1.0
                gt_stats["tied_group_size"] = float(group_size)
            else:
                gt_stats["rank_fractional"] = float(fractional_rank)
                gt_stats["mrr_fractional"] = 1.0 / fractional_rank if fractional_rank > 0 else 0.0

                # Expected Top-K probabilities: fraction of tied slots that lie <= K
                for k in (1, 3, 5):
                    overlap = max(0, min(k, r_end) - r_start + 1)
                    prob = overlap / float(group_size)
                    gt_stats[f"top{k}_expected"] = float(prob)
                    # Strict Top-K: entire group must be <= K
                    gt_stats[f"top{k}_strict"] = 1.0 if r_end <= k else 0.0

                gt_stats["is_tied"] = 1.0 if group_size > 1 else 0.0
                gt_stats["tied_group_size"] = float(group_size)
            break

        current_pos += group_size

    return gt_stats
