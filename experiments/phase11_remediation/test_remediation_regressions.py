"""
Regression Tests for Phase 11 Audit Remediation.

Validates that:
1. Substring matching is eliminated (strict exact IOC lookup).
2. Actor entity redaction blinds all candidate names in test inputs.
3. Tie-breaking metrics are mathematically invariant under candidate list order permutations.
4. Graph state remains strictly invariant (no mutation across predictions).
5. Ground truth labels are strictly isolated from predictor inputs.
"""

import csv
from pathlib import Path
import random
import pytest

from nexuscti.service import get_service
from experiments.phase11_remediation.sanitization import redact_actor_entities
from experiments.phase11_remediation.tie_handling import evaluate_ranked_prediction
from experiments.phase11_remediation.remediated_evaluator import (
    RemediatedBenchmarkRunner,
    CANDIDATE_ACTORS,
    INPUTS_PATH,
    LABELS_PATH,
)


@pytest.fixture(scope="module")
def service():
    return get_service()


@pytest.fixture(scope="module")
def runner():
    return RemediatedBenchmarkRunner()


def test_strict_exact_ioc_matching_leak_case(service):
    """Verifies that the disclosed substring leak IOC 185.141.63.120 does NOT match 185.141.63.12."""
    tkg = service.tkg
    # The disclosed leak case
    leak_ioc = "185.141.63.120"
    match = tkg.find_node_by_indicator(leak_ioc)
    assert match is None, f"Leak regression: {leak_ioc} falsely matched node {match.id} ({match.name})"


def test_strict_exact_ioc_matching_prefixes_and_suffixes(service):
    """Verifies that arbitrary substrings/prefixes/suffixes do not match."""
    tkg = service.tkg
    # Target node: 185.225.17.42
    assert tkg.find_node_by_indicator("185.225.17.4") is None
    assert tkg.find_node_by_indicator("185.225.17.420") is None
    assert tkg.find_node_by_indicator("85.225.17.42") is None

    # Legitimate exact match
    exact = tkg.find_node_by_indicator("185.225.17.42")
    assert exact is not None
    assert exact.name == "185.225.17.42"

    # Defanged exact match
    defanged = tkg.find_node_by_indicator("185.225.17[.]42")
    assert defanged is not None
    assert defanged.name == "185.225.17.42"


def test_actor_name_redaction_comprehensive():
    """Verifies that known actor names and aliases are scrubbed from narratives."""
    sample = (
        "Microsoft attributed the attack to Forest Blizzard (STRONTIUM/APT28), "
        "while CISA linked the campaign to Cozy Bear (APT29/NOBELIUM) and Lazarus Group (Hidden Cobra). "
        "GRU Unit 26165 was also cited."
    )
    redacted = redact_actor_entities(sample)
    for forbidden in ["apt28", "forest blizzard", "strontium", "cozy bear", "apt29", "nobelium", "lazarus", "hidden cobra", "unit 26165"]:
        assert forbidden not in redacted.lower(), f"Failed to redact {forbidden}: {redacted}"
    assert "[REDACTED_ACTOR]" in redacted
    assert "[REDACTED_AFFILIATION]" in redacted


def test_predictor_inputs_zero_unredacted_candidate_tokens():
    """Verifies that all 48 cases in predictor_inputs.csv contain zero unredacted candidate names."""
    with open(INPUTS_PATH, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 48
    candidate_tokens = ["apt28", "apt29", "lazarus", "sandworm", "volt typhoon", "fin7"]
    for row in rows:
        passage = row["sanitized_passage_excerpt"].lower()
        for tok in candidate_tokens:
            assert tok not in passage, f"Case {row['case_id']} contains unredacted candidate token '{tok}': {passage}"


def test_tie_handling_permutation_invariance():
    """Verifies that tie-handling metrics are mathematically invariant under any candidate ordering."""
    gt = "actor_apt28"
    all_actors = list(CANDIDATE_ACTORS)

    # All candidates tied with 0.1667 score (as in unseen IOC graph prediction)
    tied_candidates_forward = [(a, 0.1667) for a in all_actors]
    res_forward = evaluate_ranked_prediction(tied_candidates_forward, gt, all_actors)

    # Reverse order
    tied_candidates_reverse = [(a, 0.1667) for a in reversed(all_actors)]
    res_reverse = evaluate_ranked_prediction(tied_candidates_reverse, gt, all_actors)

    # Shuffled order
    rng = random.Random(42)
    shuffled_actors = list(all_actors)
    rng.shuffle(shuffled_actors)
    tied_candidates_shuffled = [(a, 0.1667) for a in shuffled_actors]
    res_shuffled = evaluate_ranked_prediction(tied_candidates_shuffled, gt, all_actors)

    # All three must yield identical metrics
    for key in ["rank_fractional", "mrr_fractional", "top1_expected", "top3_expected", "top5_expected", "top1_strict"]:
        assert res_forward[key] == res_reverse[key] == res_shuffled[key], f"Permutation variance on {key}"

    # Expected values for 6 tied candidates:
    assert res_forward["top1_expected"] == pytest.approx(1.0 / 6.0)
    assert res_forward["top3_expected"] == pytest.approx(3.0 / 6.0)
    assert res_forward["top5_expected"] == pytest.approx(5.0 / 6.0)
    assert res_forward["rank_fractional"] == pytest.approx(3.5)
    assert res_forward["top1_strict"] == 0.0
    assert res_forward["top3_strict"] == 0.0


def test_graph_state_isolation_context(service):
    """Verifies that isolated_graph_context restores the exact node and edge counts."""
    tkg = service.tkg
    initial_nodes = len(tkg.raw_nodes)
    initial_edges = tkg.nx_graph.number_of_edges()

    with tkg.isolated_graph_context():
        temp_id = tkg.add_temporary_ioc_node("999.999.999.999")
        assert len(tkg.raw_nodes) == initial_nodes + 1
        assert tkg.find_node_by_indicator("999.999.999.999") is not None

    # After exiting context, node must be removed and counts restored
    assert len(tkg.raw_nodes) == initial_nodes
    assert tkg.nx_graph.number_of_edges() == initial_edges
    assert tkg.find_node_by_indicator("999.999.999.999") is None


def test_runner_graph_invariance_across_predictions(runner):
    """Verifies that running Config A, B, C, D, and E predictions leaves graph state untouched."""
    initial_nodes = runner.baseline_node_count
    initial_edges = runner.baseline_edge_count

    test_case = runner.inputs[0]
    passage = test_case["sanitized_passage_excerpt"]
    ioc = test_case["anchor_ioc"]

    # Execute all 5 prediction methods
    runner.predict_config_a(passage)
    runner.verify_graph_invariance("Config A")

    runner.predict_config_b(ioc)
    runner.verify_graph_invariance("Config B")

    runner.predict_config_c(ioc)
    runner.verify_graph_invariance("Config C")

    runner.predict_config_d(passage, ioc)
    runner.verify_graph_invariance("Config D")

    runner.predict_config_e(passage, ioc)
    runner.verify_graph_invariance("Config E")

    assert len(runner.service.tkg.raw_nodes) == initial_nodes
    assert runner.service.tkg.nx_graph.number_of_edges() == initial_edges


def test_ground_truth_isolation():
    """Verifies strict separation of predictor inputs and ground truth labels."""
    with open(INPUTS_PATH, "r", encoding="utf-8") as f:
        inputs_header = next(csv.reader(f))
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        labels_header = next(csv.reader(f))

    # Predictor inputs must not contain ground truth columns
    for forbidden in ["ground_truth", "attributed_actor", "actor_aliases", "target_actor"]:
        assert forbidden not in inputs_header

    # Labels must contain ground_truth_actor
    assert "ground_truth_actor" in labels_header
    assert "case_id" in inputs_header and "case_id" in labels_header
