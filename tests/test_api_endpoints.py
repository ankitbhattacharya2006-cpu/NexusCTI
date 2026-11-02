"""
Automated Integration and Unit Tests for NexusCTI REST API.

Tests:
1. Engine health check endpoint (GET /api/health).
2. Normal attribution analysis with known IOC (POST /api/analyze).
3. Dual-input attribution (IOC + Narrative).
4. Candidate evidence rationale & structure verification.
5. Unknown indicator handling and proper abstention / insufficient evidence.
6. Input validation:
   - Empty payload
   - Whitespace-only payload
   - Invalid top_k parameter
   - Malformed IOCs (invalid IP octets, forbidden characters, spaces)
7. Indicator direct lookup endpoint (GET /api/ioc/{indicator}):
   - Known indicator
   - Defanged indicator
   - Unknown indicator
   - Invalid indicator format
8. Direct GET IOC attribution endpoint (GET /api/ioc/{indicator}/attribution).
9. Empty/unrelated evidence handling (abstention without hallucination).
10. Unhandled service failure handling (HTTP 500 structured error response).
11. Threat actor directory endpoint (GET /api/actors).
12. Full graph topology endpoint (GET /api/graph).
13. Graph state immutability & isolation under repeated heterogeneous stress queries.
"""

import asyncio
import json
import pytest
from unittest.mock import patch

from nexuscti.api.server import app
from nexuscti.service import get_service


async def call_api(method: str, path: str, json_body: dict = None, query_string: str = ""):
    """Invokes FastAPI application directly via ASGI interface without external network dependencies."""
    body_bytes = json.dumps(json_body).encode("utf-8") if json_body is not None else b""
    headers = [
        (b"host", b"testserver"),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body_bytes)).encode("utf-8")),
    ]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query_string.encode("utf-8"),
        "headers": headers,
    }

    response_status = None
    response_headers = []
    response_body = []

    async def receive():
        return {
            "type": "http.request",
            "body": body_bytes,
            "more_body": False,
        }

    async def send(message):
        nonlocal response_status, response_headers, response_body
        if message["type"] == "http.response.start":
            response_status = message["status"]
            response_headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            response_body.append(message.get("body", b""))

    await app(scope, receive, send)

    raw_resp = b"".join(response_body).decode("utf-8")
    try:
        parsed_json = json.loads(raw_resp) if raw_resp else None
    except Exception:
        parsed_json = raw_resp

    return response_status, parsed_json


# --- TEST CASES ---
def test_scenarios_endpoint():
    status, body = asyncio.run(call_api("GET", "/api/scenarios"))
    assert status == 200
    assert isinstance(body, list)
    assert len(body) >= 12
    # Verify no ground truth leakage
    for s in body:
        assert "ground_truth_actor" not in s
        assert "name" in s
        assert "anchor_ioc" in s
        assert "query" in s

def test_health_check_endpoint():
    status, body = asyncio.run(call_api("GET", "/api/health"))
    assert status == 200
    assert body["status"] == "online"
    assert body["engine"].startswith("NexusCTI")
    assert body["graph"]["nodes"] == 65
    assert body["graph"]["edges"] == 130
    assert body["graph"]["threat_actors_tracked"] == 6


def test_normal_attribution_request():
    service = get_service()
    initial_nodes = len(service.tkg.raw_nodes)

    # Known IOC associated with APT29
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "185.225.17.42"}
    ))

    assert status == 200
    assert body["status"] in ("SUCCESS", "ATTRIBUTED")
    assert body["query_ioc"] == "185.225.17.42"
    assert body["graph_evidence"]["is_known_in_graph"] is True
    assert body["top_candidate"] is not None
    assert body["top_candidate"]["actor_id"] == "actor_apt29"
    assert len(body["candidates"]) >= 1

    # Verify graph trail hops are returned
    assert body["graph_evidence"]["hop_count"] >= 1
    assert len(body["graph_evidence"]["chain"]) >= 1

    # Verify text evidence is returned
    assert len(body["text_evidence"]) >= 1

    # Verify graph state was NOT mutated
    assert len(service.tkg.raw_nodes) == initial_nodes


def test_dual_input_attribution():
    service = get_service()
    initial_nodes = len(service.tkg.raw_nodes)

    payload = {
        "ioc": "185.225.17.42",
        "narrative": "Incident response team observed C2 beaconing via avsvmcloud[.]com domain."
    }
    status, body = asyncio.run(call_api("POST", "/api/analyze", json_body=payload))

    assert status == 200
    assert body["status"] == "SUCCESS"
    assert body["top_candidate"] is not None
    assert body["top_candidate"]["actor_id"] == "actor_apt29"
    assert "avsvmcloud.com" in [h["target"] for h in body["graph_evidence"]["chain"]] or body["top_candidate"]["textual_confidence"] > 0
    assert len(service.tkg.raw_nodes) == initial_nodes


def test_candidate_evidence_explanation():
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "185.225.17.42"}
    ))
    assert status == 200
    top = body["top_candidate"]
    assert top is not None

    # Check candidate evidence fields
    assert "evidence_summary" in top
    assert len(top["evidence_summary"]) > 20
    assert "Scores: Fused" in top["evidence_summary"]
    assert top["structural_hops"] >= 1
    assert isinstance(top["corroborating_sources"], list)
    assert len(top["corroborating_sources"]) >= 1


def test_unknown_indicator_explicit_abstention():
    service = get_service()
    initial_nodes = len(service.tkg.raw_nodes)

    # Completely unknown, out-of-distribution indicator (RFC 5737 valid syntax)
    payload = {"ioc": "198.51.100.77"}
    status, body = asyncio.run(call_api("POST", "/api/analyze", json_body=payload))

    assert status == 200
    assert body["status"] in ("UNKNOWN_INDICATOR", "INSUFFICIENT_EVIDENCE")
    assert body["attribution_status"] in ("UNKNOWN", "INCONCLUSIVE")
    assert body["top_candidate"] is None
    assert body["graph_evidence"]["is_known_in_graph"] is False
    assert len(body["graph_evidence"]["chain"]) == 0
    assert "not resolved in the threat knowledge graph" in body["synergistic_rationale"].lower() or "insufficient" in body["synergistic_rationale"].lower()

    # Crucial: verify that the unknown indicator did NOT leave residual nodes in the graph
    assert len(service.tkg.raw_nodes) == initial_nodes
    assert service.tkg.find_node_by_indicator("198.51.100.77") is None


def test_validation_error_empty_request():
    status, body = asyncio.run(call_api("POST", "/api/analyze", json_body={}))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"
    assert "At least one of 'ioc', 'narrative', or 'query'" in body["detail"]


def test_validation_error_whitespace_only():
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"query": "    ", "ioc": "   "}
    ))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"


def test_validation_error_invalid_top_k():
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "185.225.17.42", "top_k": 99}
    ))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"


def test_validation_error_invalid_ioc_octets():
    # Invalid IP octet > 255
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "999.999.999.999"}
    ))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"
    assert "Invalid indicator format" in body["detail"]


def test_validation_error_invalid_ioc_characters():
    # Disallowed script/injection characters
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "bad<script>"}
    ))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"
    assert "invalid characters" in body["detail"]


def test_validation_error_ioc_with_whitespace():
    # Multi-token string passed to indicator field
    status, body = asyncio.run(call_api(
        "POST",
        "/api/analyze",
        json_body={"ioc": "malicious domain with space.com"}
    ))
    assert status == 422
    assert body["error"] == "VALIDATION_ERROR"
    assert "whitespace" in body["detail"]


def test_indicator_lookup_known_and_defanged():
    # Exact lookup
    status, body = asyncio.run(call_api("GET", "/api/ioc/185.225.17.42"))
    assert status == 200
    assert body["is_known"] is True
    assert body["node_name"] == "185.225.17.42"
    assert len(body["connected_edges"]) > 0

    # Defanged lookup: 185.225.17[.]42
    status_defanged, body_defanged = asyncio.run(call_api("GET", "/api/ioc/185.225.17[.]42"))
    assert status_defanged == 200
    assert body_defanged["is_known"] is True
    assert body_defanged["node_name"] == "185.225.17.42"


def test_indicator_lookup_unknown():
    status, body = asyncio.run(call_api("GET", "/api/ioc/192.0.2.123"))
    assert status == 200
    assert body["is_known"] is False
    assert "not currently present" in body["detail"]


def test_indicator_lookup_invalid_syntax():
    # Invalid syntax rejected at lookup
    status, body = asyncio.run(call_api("GET", "/api/ioc/999.999.999.999"))
    assert status == 400
    assert body["error"] == "HTTP_ERROR"
    assert "Invalid indicator format" in body["detail"]


def test_direct_get_ioc_attribution():
    # GET /api/ioc/{indicator}/attribution
    status, body = asyncio.run(call_api("GET", "/api/ioc/185.225.17.42/attribution"))
    assert status == 200
    assert body["status"] in ("SUCCESS", "ATTRIBUTED")
    assert body["query_ioc"] == "185.225.17.42"
    assert body["top_candidate"]["actor_id"] == "actor_apt29"

    # Invalid IOC format via GET endpoint
    status_inv, body_inv = asyncio.run(call_api("GET", "/api/ioc/invalid@@ioc/attribution"))
    assert status_inv == 400
    assert body_inv["error"] == "HTTP_ERROR"


def test_empty_evidence_abstention():
    # Telemetry with zero CTI relevance or indicator matches
    payload = {
        "narrative": "General corporate announcement: team lunch scheduled on the cafeteria terrace this afternoon."
    }
    status, body = asyncio.run(call_api("POST", "/api/analyze", json_body=payload))
    assert status == 200
    assert body["status"] in ("INSUFFICIENT_EVIDENCE", "UNKNOWN_INDICATOR")
    assert body["attribution_status"] in ("INCONCLUSIVE", "UNKNOWN")
    assert body["top_candidate"] is None
    assert body["graph_evidence"]["chain"] == []
    assert "insufficient" in body["synergistic_rationale"].lower() or "telemetry" in body["synergistic_rationale"].lower()


def test_service_internal_failure_handling():
    # Verify unhandled internal service failures return HTTP 500 conforming to ErrorResponse
    service = get_service()
    with patch.object(service, "analyze", side_effect=RuntimeError("Simulated neural inference engine memory fault")):
        status, body = asyncio.run(call_api(
            "POST",
            "/api/analyze",
            json_body={"ioc": "185.225.17.42"}
        ))
        assert status == 500
        assert body["error"] == "INTERNAL_SERVER_ERROR"
        assert "unexpected error occurred" in body["detail"]
        assert "timestamp" in body


def test_list_threat_actors():
    status, body = asyncio.run(call_api("GET", "/api/actors"))
    assert status == 200
    assert body["total"] == 6
    actor_ids = {a["actor_id"] for a in body["actors"]}
    assert "actor_apt28" in actor_ids
    assert "actor_apt29" in actor_ids
    assert "actor_lazarus" in actor_ids
    assert "actor_sandworm" in actor_ids
    assert "actor_volt_typhoon" in actor_ids
    assert "actor_fin7" in actor_ids


def test_graph_data_endpoint():
    status, body = asyncio.run(call_api("GET", "/api/graph"))
    assert status == 200
    assert len(body["nodes"]) == 65
    assert len(body["edges"]) > 0


def test_graph_state_immutability_under_stress():
    service = get_service()
    initial_nodes = len(service.tkg.raw_nodes)
    initial_edges = service.tkg.nx_graph.number_of_edges()

    # Sequence of heterogeneous stress calls:
    # 1. Normal valid IOC
    asyncio.run(call_api("POST", "/api/analyze", json_body={"ioc": "185.225.17.42"}))
    # 2. Unknown indicator
    asyncio.run(call_api("POST", "/api/analyze", json_body={"ioc": "198.51.100.99"}))
    # 3. Invalid IOC validation failure
    asyncio.run(call_api("POST", "/api/analyze", json_body={"ioc": "999.999.999.999"}))
    # 4. Empty evidence narrative
    asyncio.run(call_api("POST", "/api/analyze", json_body={"narrative": "Routine hardware inventory check."}))
    # 5. Direct GET lookup
    asyncio.run(call_api("GET", "/api/ioc/185.225.17.42"))
    # 6. Direct GET attribution
    asyncio.run(call_api("GET", "/api/ioc/185.225.17.42/attribution"))

    # Assert 100% graph invariance
    assert len(service.tkg.raw_nodes) == initial_nodes
    assert service.tkg.nx_graph.number_of_edges() == initial_edges
