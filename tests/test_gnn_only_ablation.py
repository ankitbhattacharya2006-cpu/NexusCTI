import networkx as nx
from types import SimpleNamespace

import pytest
import torch

from nexuscti.gnn.trainer import GNNAttributionTrainer
from nexuscti.eval.baselines import StandaloneGNNBaseline
from nexuscti.service import get_service
from experiments.scientific_audit_20261010_223000.run_ablations import (
    AblationExperimentSuite,
)


def _trained_trainer():
    tkg = SimpleNamespace(
        x=torch.zeros((3, 8)),
        relation_to_idx={"relation": 0},
        actor_indices=[1, 2],
        node_id_to_idx={"ioc": 0},
        idx_to_node_id={1: "actor-a", 2: "actor-b"},
        actor_idx_to_name={1: "Actor A", 2: "Actor B"},
    )
    trainer = GNNAttributionTrainer(tkg)
    trainer.cached_embeddings = torch.randn((3, 64))
    trainer._is_trained = True
    return trainer


def test_neural_affinity_does_not_calculate_networkx_distances(monkeypatch):
    trainer = _trained_trainer()

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Neural affinity must not calculate graph distances.")

    monkeypatch.setattr("nexuscti.gnn.trainer.nx.shortest_path_length", fail_if_called)

    predictions = trainer.predict_attribution_gnn_only("ioc")

    assert {prediction["actor_id"] for prediction in predictions} == {
        "actor-a",
        "actor-b",
    }
    assert sum(
        prediction["structural_confidence"] for prediction in predictions
    ) == pytest.approx(1.0, abs=0.001)


def test_neural_affinity_rejects_nodes_without_cached_embeddings():
    trainer = _trained_trainer()
    trainer.tkg.node_id_to_idx["uncached"] = 3

    with pytest.raises(RuntimeError, match="no cached GNN embedding"):
        trainer.predict_neural_affinity("uncached")


def test_config_c_returns_empty_for_unknown_anchor_without_mutating_graph():
    tkg = SimpleNamespace(find_node_by_indicator=lambda indicator: None)
    suite = AblationExperimentSuite.__new__(AblationExperimentSuite)
    suite.service = SimpleNamespace(tkg=tkg)
    suite.actor_ids = ["actor-a"]

    assert suite.predict_config_c("new-indicator") == []


def test_config_c_uses_neural_affinity_not_mixed_predictor():
    gnn = SimpleNamespace(
        predict_attribution_gnn_only=lambda node_id: [
            {"actor_id": "actor-a", "structural_confidence": 1.0}
        ],
        predict_attribution=lambda node_id: (_ for _ in ()).throw(
            AssertionError("Config C must not use the mixed predictor.")
        ),
    )
    suite = AblationExperimentSuite.__new__(AblationExperimentSuite)
    suite.service = SimpleNamespace(
        tkg=SimpleNamespace(
            find_node_by_indicator=lambda indicator: SimpleNamespace(id="ioc")
        ),
        gnn_trainer=gnn,
    )
    suite.actor_ids = ["actor-a"]

    assert suite.predict_config_c("ioc") == [("actor-a", 1.0)]


def test_gnn_only_attribution_refreshes_cached_embeddings_when_graph_changes():
    trainer = _trained_trainer()
    trainer.tkg.x = torch.zeros((4, 8))
    trainer.tkg.rel_edge_indices = {}
    trainer.tkg.node_id_to_idx["new-ioc"] = 3
    trainer.tkg.idx_to_node_id[3] = "new-ioc"

    predictions = trainer.predict_attribution_gnn_only("new-ioc")

    assert {prediction["actor_id"] for prediction in predictions} == {
        "actor-a",
        "actor-b",
    }
    assert trainer.cached_embeddings.size(0) == 4


def test_standalone_gnn_baseline_uses_neural_affinity_only():
    gnn = SimpleNamespace(
        tkg=SimpleNamespace(
            find_node_by_indicator=lambda indicator: SimpleNamespace(id="ioc")
        ),
        predict_neural_affinity=lambda node_id: [
            {"actor_id": "actor-a", "structural_confidence": 0.8}
        ],
        predict_attribution=lambda node_id: (_ for _ in ()).throw(
            AssertionError("The mixed GNN/topology predictor must not be used.")
        ),
    )

    assert StandaloneGNNBaseline(gnn).predict("ioc") == [("actor-a", 0.8)]


def test_config_c_end_to_end_zero_networkx_calls(monkeypatch):
    suite = AblationExperimentSuite()

    def fail_nx(*args, **kwargs):
        raise AssertionError("NetworkX path method was invoked during Config C execution.")

    monkeypatch.setattr(nx, "shortest_path_length", fail_nx)
    monkeypatch.setattr(nx, "shortest_path", fail_nx)
    monkeypatch.setattr(nx, "all_simple_paths", fail_nx)

    # Known IOC
    preds_known = suite.predict_config_c("185.225.17.42")
    assert len(preds_known) == len(suite.actor_ids)
    assert sum(score for _, score in preds_known) == pytest.approx(1.0, abs=0.005)

    # Unknown IOC
    preds_unknown = suite.predict_config_c("nonexistent_ioc_0.0.0.0")
    assert preds_unknown == []


def test_config_c_end_to_end_zero_text_retrieval_calls(monkeypatch):
    suite = AblationExperimentSuite()

    def fail_rag(*args, **kwargs):
        raise AssertionError("Text retrieval method was invoked during Config C execution.")

    monkeypatch.setattr(suite.service.hybrid_retriever, "retrieve", fail_rag)
    monkeypatch.setattr(suite.service.hybrid_retriever, "predict_attribution", fail_rag)
    monkeypatch.setattr(suite.service.hybrid_retriever.dense, "search", fail_rag)
    monkeypatch.setattr(suite.service.hybrid_retriever.dense.encoder, "encode", fail_rag)
    monkeypatch.setattr(suite.service.hybrid_retriever.bm25, "search", fail_rag)

    # Known IOC
    preds_known = suite.predict_config_c("185.225.17.42")
    assert len(preds_known) == len(suite.actor_ids)

    # Unknown IOC
    preds_unknown = suite.predict_config_c("unknown.domain.threat.xyz")
    assert preds_unknown == []


def test_config_c_uses_only_gnn_derived_neural_affinity_scores():
    suite = AblationExperimentSuite()
    node = suite.service.tkg.find_node_by_indicator("185.225.17.42")
    assert node is not None

    config_c_preds = dict(suite.predict_config_c("185.225.17.42"))
    pure_gnn_preds = {
        item["actor_id"]: item["structural_confidence"]
        for item in suite.service.gnn_trainer.predict_attribution_gnn_only(node.id)
    }

    # Verify Config C matches pure GNN neural affinity exactly
    for actor_id, score in pure_gnn_preds.items():
        assert config_c_preds[actor_id] == pytest.approx(score, abs=0.0001)

    # Verify it does NOT match mixed predictor (which blends graph distance)
    mixed_preds = {
        item["actor_id"]: item["structural_confidence"]
        for item in suite.service.gnn_trainer.predict_attribution(node.id)
    }
    assert config_c_preds != mixed_preds


def test_config_c_does_not_mutate_graph_nodes_on_unknown_ioc():
    suite = AblationExperimentSuite()
    initial_node_count = suite.service.tkg.nx_graph.number_of_nodes()
    initial_edge_count = suite.service.tkg.nx_graph.number_of_edges()
    initial_raw_count = len(suite.service.tkg.raw_nodes)
    initial_node_dict_keys = set(suite.service.tkg.node_dict.keys())
    initial_id_to_idx = dict(suite.service.tkg.node_id_to_idx)

    result = suite.predict_config_c("completely_novel_ioc_never_seen_before_99.88.77.66")
    assert result == []

    assert suite.service.tkg.nx_graph.number_of_nodes() == initial_node_count
    assert suite.service.tkg.nx_graph.number_of_edges() == initial_edge_count
    assert len(suite.service.tkg.raw_nodes) == initial_raw_count
    assert set(suite.service.tkg.node_dict.keys()) == initial_node_dict_keys
    assert suite.service.tkg.node_id_to_idx == initial_id_to_idx


def test_config_c_does_not_leak_state_between_configurations():
    suite = AblationExperimentSuite()

    # Baseline runs for all configs
    baseline_c = suite.predict_config_c("185.225.17.42")
    baseline_a = suite.predict_config_a("SolarWinds build beaconing to avsvmcloud")
    baseline_b = suite.predict_config_b("185.225.17.42")
    baseline_d = suite.predict_config_d("SolarWinds build beaconing", "185.225.17.42")
    baseline_e, depth_e = suite.predict_config_e("SolarWinds build beaconing", "185.225.17.42")

    # Interleave unknown and known IOC queries across configs
    _ = suite.predict_config_c("unknown_telemetry_probe")
    _ = suite.predict_config_a("some unrelated threat advisory")
    _ = suite.predict_config_c("185.225.17.42")
    _ = suite.predict_config_b("185.225.17.42")

    # Re-evaluate all configs and confirm zero state leakage / exact reproducibility
    re_c = suite.predict_config_c("185.225.17.42")
    re_a = suite.predict_config_a("SolarWinds build beaconing to avsvmcloud")
    re_b = suite.predict_config_b("185.225.17.42")
    re_d = suite.predict_config_d("SolarWinds build beaconing", "185.225.17.42")
    re_e, re_depth_e = suite.predict_config_e("SolarWinds build beaconing", "185.225.17.42")

    assert re_c == baseline_c
    assert re_a == baseline_a
    assert re_b == baseline_b
    assert re_d == baseline_d
    assert re_e == baseline_e
    assert re_depth_e == depth_e


def test_original_hybrid_attribution_method_integrity():
    service = get_service()
    node = service.tkg.find_node_by_indicator("185.225.17.42")
    assert node is not None

    # Test GNN hybrid predictor
    hybrid_preds = service.gnn_trainer.predict_attribution(node.id)
    assert len(hybrid_preds) == len(service.tkg.actor_indices)
    assert all("actor_id" in p and "structural_confidence" in p for p in hybrid_preds)

    # Test full end-to-end multi-modal analysis
    analysis = service.analyze(
        "Infected SolarWinds Orion build beaconing to primary C2 domain avsvmcloud[.]com",
        ioc_override="185.225.17.42"
    )
    assert analysis.top_actor is not None
    assert analysis.top_actor.actor_id == "actor_apt29"
    assert analysis.top_actor.fused_confidence > 0.0
    assert analysis.graph_trail is not None and len(analysis.graph_trail.hops) > 0
    assert len(analysis.narrative_proofs) > 0
    assert analysis.multi_hop_depth >= 1

