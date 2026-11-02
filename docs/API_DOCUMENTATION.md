# NexusCTI Cyber Threat Attribution REST API Documentation

**Version**: 1.1.0  
**Base URL**: `http://localhost:8000`  
**Interactive Swagger UI**: `http://localhost:8000/docs`  
**OpenAPI ReDoc**: `http://localhost:8000/redoc`  

---

## 1. Overview & Capabilities

The NexusCTI REST API exposes the attribution backend for Security Operations Center (SOC) incident response, threat hunting, and automated CTI ingestion pipelines.

### Core Capabilities
* **IOC & Incident Attribution**: Submit an indicator of compromise (IPv4, IPv6, domain, hash, CVE) and/or narrative telemetry to obtain ranked threat actor candidates.
* **Dual-Layer Verifiable Evidence**:
  * **Graph Evidence**: Multi-hop structural pivots connecting the indicator to adversary infrastructure and tool clusters with hop counts, relations, and topology citations.
  * **Text Evidence**: Passages retrieved from authoritative advisories (CISA, Mandiant, Microsoft, Dragos) with relevance scores and matched indicators.
* **Candidate-Specific Evidence Explanation**: Every ranked candidate returns an evidence breakdown including topological reasoning chain, hop distance, corroborating sources, and confidence signals.
* **Explicit Unknown Indicator & Insufficient Evidence Abstention**: Indicators absent from the knowledge graph and unsupported by authoritative text return an explicit `UNKNOWN_INDICATOR` or `INSUFFICIENT_EVIDENCE` status, avoiding forced false attributions.
* **Graph State Immutability**: All queries execute under strict state isolation; inference cannot mutate, pollute, or leak data into the baseline graph topology.
* **Evaluation Data Separation**: Production inference is strictly decoupled from benchmark labels, test harnesses, and ground-truth evaluation sets.

---

## 2. Server Startup

### Using Python
```bash
PYTHONPATH=. ./.venv/bin/python start_server.py
```
Or directly via `uvicorn`:
```bash
PYTHONPATH=. ./.venv/bin/uvicorn nexuscti.api.server:app --host 0.0.0.0 --port 8000
```

The server binds to `0.0.0.0:8000` by default. Swagger documentation is available at `http://localhost:8000/docs`.

---

## 3. Endpoints Reference

### 3.1 Health Check
`GET /api/health`

Returns engine status, version, knowledge graph metrics, and active model components.

#### Example Request
```bash
curl -s http://localhost:8000/api/health
```

#### Example Response (200 OK)
```json
{
  "status": "online",
  "engine": "NexusCTI v1.1",
  "timestamp": "2026-11-02T00:15:00.000000+00:00",
  "graph": {
    "nodes": 65,
    "edges": 130,
    "threat_actors_tracked": 6
  },
  "retrieval": {
    "corpus_reports": 6,
    "retriever": "Hybrid Dense-Sparse RRF"
  },
  "gnn": "Heterogeneous Relational GNN"
}
```

---

### 3.2 Attribution Analysis (POST)
`POST /api/analyze`

Submits an IOC, threat narrative, or combined telemetry for multi-modal attribution.

#### Request Headers
`Content-Type: application/json`

#### Request Schema (`AttributionRequest`)
| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `ioc` | `string` | Optional* | Target IOC (IPv4, IPv6, domain, MD5/SHA1/SHA256, CVE, URL). Defanged formats like `[.]` are auto-normalized. |
| `narrative` | `string` | Optional* | Free-form incident report, alert narrative, or log excerpt. |
| `query` | `string` | Optional* | Legacy field: free-form query or indicator (backward compatible). |
| `ioc_override` | `string` | Optional | Legacy field: explicit indicator override. |
| `top_k` | `integer` | Optional | Number of candidate actors to return (default: `5`, range: `1`–`10`). |

*\*At least one of `ioc`, `narrative`, or `query` must be provided.*

#### Example 1: Known Indicator Query
```bash
curl -X POST http://localhost:8000/api/analyze   -H "Content-Type: application/json"   -d '{"ioc": "185.225.17.42"}'
```

#### Example Response (200 OK — Attributed)
```json
{
  "status": "SUCCESS",
  "query_ioc": "185.225.17.42",
  "attribution_status": "ATTRIBUTED",
  "top_candidate": {
    "rank": 1,
    "actor_id": "actor_apt29",
    "actor_name": "APT29 (Cozy Bear / NOBELIUM)",
    "fused_confidence": 0.56,
    "structural_confidence": 0.2287,
    "textual_confidence": 0.7344,
    "cross_validation_score": 1.0,
    "verdict": "PROBABLE",
    "evidence_summary": "Structural path (4 hops): [Indicator] 185.225.17.42 --(rev_resolves_to)--> [Indicator] freescanonline[.]com --(rev_shares_infra)--> [Indicator] avsvmcloud[.]com --(rev_communicates_with)--> [Malware] SUNBURST --(rev_uses)--> [ThreatActor] APT29 (Cozy Bear / NOBELIUM). Corroborated by reporting from Cybersecurity and Infrastructure Security Agency (CISA). Scores: Fused 56.0%, GNN 22.9%, RAG 73.4%, Cross-Val 100.0%.",
    "structural_hops": 4,
    "corroborating_sources": [
      "Cybersecurity and Infrastructure Security Agency (CISA)"
    ]
  },
  "candidates": [
    {
      "rank": 1,
      "actor_id": "actor_apt29",
      "actor_name": "APT29 (Cozy Bear / NOBELIUM)",
      "fused_confidence": 0.56,
      "structural_confidence": 0.2287,
      "textual_confidence": 0.7344,
      "cross_validation_score": 1.0,
      "verdict": "PROBABLE",
      "evidence_summary": "Structural path (4 hops): [Indicator] 185.225.17.42 --(rev_resolves_to)--> [Indicator] freescanonline[.]com --(rev_shares_infra)--> [Indicator] avsvmcloud[.]com --(rev_communicates_with)--> [Malware] SUNBURST --(rev_uses)--> [ThreatActor] APT29 (Cozy Bear / NOBELIUM). Corroborated by reporting from Cybersecurity and Infrastructure Security Agency (CISA). Scores: Fused 56.0%, GNN 22.9%, RAG 73.4%, Cross-Val 100.0%.",
      "structural_hops": 4,
      "corroborating_sources": [
        "Cybersecurity and Infrastructure Security Agency (CISA)"
      ]
    }
  ],
  "graph_evidence": {
    "indicator": "185.225.17.42",
    "is_known_in_graph": true,
    "resolved_node_id": "ioc_ip_185_225_17_42",
    "hop_count": 4,
    "chain": [
      {
        "step": 1,
        "source": "185.225.17.42",
        "source_type": "Indicator",
        "relation": "resolves_to",
        "target": "freescanonline[.]com",
        "target_type": "Indicator",
        "rationale": "C2 network resolution pivot",
        "citation": "CISA AA20-352A"
      }
    ]
  },
  "text_evidence": [
    {
      "doc_id": "rpt_cisa_apt29_solarwinds_c0",
      "source": "Cybersecurity and Infrastructure Security Agency (CISA)",
      "date": "2020-12-17",
      "relevant_text": "CISA has determined that APT29 utilized primary C2 staging IP 185.225.17.42...",
      "matched_iocs": ["185.225.17.42", "avsvmcloud.com"],
      "retrieval_score": 0.8421
    }
  ],
  "synergistic_rationale": "Adversary attribution confirmed for APT29 (Cozy Bear / NOBELIUM)...",
  "hallucination_risk": "MINIMAL (Dual Grounded)",
  "disclaimer": "Attribution scores reflect graph topology and corpus retrieval signals. Human analyst corroboration is required before operational defense actions."
}
```

#### Example 2: Unknown Indicator Query (Explicit Abstention)
```bash
curl -X POST http://localhost:8000/api/analyze   -H "Content-Type: application/json"   -d '{"ioc": "198.51.100.77"}'
```

#### Example Response (200 OK — Unknown Indicator)
```json
{
  "status": "UNKNOWN_INDICATOR",
  "query_ioc": "198.51.100.77",
  "attribution_status": "UNKNOWN",
  "top_candidate": null,
  "candidates": [
    {
      "rank": 1,
      "actor_id": "actor_apt29",
      "actor_name": "APT29 (Cozy Bear / NOBELIUM)",
      "fused_confidence": 0.12,
      "structural_confidence": 0.05,
      "textual_confidence": 0.05,
      "cross_validation_score": 0.1,
      "verdict": "INCONCLUSIVE",
      "evidence_summary": "Indicator was not resolved in graph topology and no narrative evidence links this actor.",
      "structural_hops": 0,
      "corroborating_sources": []
    }
  ],
  "graph_evidence": {
    "indicator": "198.51.100.77",
    "is_known_in_graph": false,
    "resolved_node_id": null,
    "hop_count": 0,
    "chain": []
  },
  "text_evidence": [],
  "synergistic_rationale": "Indicator '198.51.100.77' was not resolved in the threat knowledge graph and no corroborating narrative evidence was retrieved in authoritative reporting. Attribution is inconclusive.",
  "hallucination_risk": "HIGH (Ungrounded)",
  "disclaimer": "Attribution scores reflect graph topology and corpus retrieval signals. Human analyst corroboration is required before operational defense actions."
}
```

---

### 3.3 Direct IOC Attribution (GET)
`GET /api/ioc/{indicator}/attribution?top_k=5`

Convenience GET endpoint for rapid indicator attribution from browser or curl without formatting a JSON payload.

#### Example Request
```bash
curl -s "http://localhost:8000/api/ioc/185.225.17.42/attribution?top_k=3"
```

Response matches the `AttributionResponse` schema documented above.

---

### 3.4 Indicator Direct Lookup
`GET /api/ioc/{indicator}`

Directly queries the threat knowledge graph topology and authoritative text corpus for an indicator.

#### Example Request
```bash
curl -s http://localhost:8000/api/ioc/185.225.17.42
```

#### Example Response (200 OK)
```json
{
  "indicator": "185.225.17.42",
  "is_known": true,
  "node_id": "ioc_ip_185_225_17_42",
  "node_type": "Indicator",
  "node_name": "185.225.17.42",
  "description": "Primary SolarWinds C2 IP address",
  "degree": 3,
  "connected_edges": [
    {
      "target_id": "ioc_domain_avsvmcloud_com",
      "target_name": "avsvmcloud.com",
      "relation": "resolves_to",
      "citation": "CISA AA20-352A"
    }
  ],
  "matching_reports": [
    {
      "doc_id": "rpt_cisa_apt29_solarwinds_c0",
      "source": "CISA Advisory AA20-352A",
      "date": "2020-12-17",
      "relevance_score": 0.8421,
      "excerpt": "CISA has determined that APT29 utilized primary C2 staging IP 185.225.17.42..."
    }
  ]
}
```

---

### 3.5 Threat Actor Directory
`GET /api/actors`

Lists tracked threat actors, public aliases, descriptions, and topological connectivity.

#### Example Request
```bash
curl -s http://localhost:8000/api/actors
```

#### Example Response (200 OK)
```json
{
  "total": 6,
  "actors": [
    {
      "actor_id": "actor_apt28",
      "name": "APT28 (Fancy Bear / STRONTIUM)",
      "aliases": ["Forest Blizzard", "Sednit", "Pawn Storm", "Sofacy", "GRU 26165"],
      "description": "Russian GRU Unit 26165 military intelligence cyber espionage group.",
      "connected_entities": 14
    },
    {
      "actor_id": "actor_apt29",
      "name": "APT29 (Cozy Bear / NOBELIUM)",
      "aliases": ["Midnight Blizzard", "The Dukes", "SVR", "UNC2452"],
      "description": "Russian Foreign Intelligence Service (SVR) cyber espionage operations.",
      "connected_entities": 16
    }
  ]
}
```

---

### 3.6 Knowledge Graph Topology
`GET /api/graph`

Exports full node and edge collections in D3/Cytoscape format for web visualizer rendering.

---

## 4. Input Validation & Error Handling

### 4.1 Supported Indicator Formats
When providing an indicator (`ioc` field or route parameter), the input is sanitized and validated against standard CTI formats:
* **IPv4 Address**: Dotted-quad (e.g. `185.225.17.42`, `185.225.17[.]42`). Octets > 255 are rejected.
* **IPv6 Address**: Standard colon-hex notation.
* **Domain / Hostname**: FQDN syntax (e.g. `avsvmcloud.com`, `avsvmcloud[.]com`).
* **Cryptographic Hash**: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex).
* **CVE Identifier**: Common Vulnerabilities and Exposures format (e.g. `CVE-2020-0601`).
* **URL**: Web URI (e.g. `hxxps://malicious[.]site/path`).

Any indicator containing whitespace, injection tokens (`;`, `'`, `"`, `<`, `>`, `{`, `}`), or invalid syntax is rejected with HTTP 422 (`VALIDATION_ERROR`) or HTTP 400.

### 4.2 Standard Error Response Schema
All API errors return a structured JSON response conforming to `ErrorResponse`:

```json
{
  "error": "VALIDATION_ERROR",
  "detail": "ioc: Value error, Invalid indicator format: '999.999.999.999'. Must be a valid IPv4/IPv6 address, domain name, hash (MD5/SHA1/SHA256), CVE identifier, or URL.",
  "timestamp": "2026-11-02T00:35:00.000000+00:00"
}
```

| HTTP Status | Error Code | Trigger Condition |
| :---: | :--- | :--- |
| **400** | `HTTP_ERROR` | Malformed route parameters or invalid indicator syntax on direct GET lookup. |
| **422** | `VALIDATION_ERROR` | Empty request payload, invalid IOC format, or out-of-range parameters (`top_k < 1` or `> 10`). |
| **500** | `INTERNAL_SERVER_ERROR` | Unhandled engine or inference failure (caught with structured diagnostics). |

---

## 5. Python Client Example

```python
import requests

BASE_URL = "http://localhost:8000"

# 1. Check Service Health
health = requests.get(f"{BASE_URL}/api/health").json()
print("Service status:", health["status"])

# 2. Analyze Indicator
payload = {
    "ioc": "185.225.17.42",
    "narrative": "Observed beaconing to avsvmcloud[.]com from staging infrastructure.",
    "top_k": 3
}
response = requests.post(f"{BASE_URL}/api/analyze", json=payload)
data = response.json()

print(f"Outcome: {data['status']} -> {data['attribution_status']}")
if data["top_candidate"]:
    top = data["top_candidate"]
    print(f"Top Actor: {top['actor_name']} ({top['fused_confidence'] * 100:.1f}%)")
    print(f"Evidence: {top['evidence_summary']}")
    print(f"Graph Hops: {top['structural_hops']}, Sources: {top['corroborating_sources']}")
```

---

## 6. Frontend Integration Status & Guidelines

| Component | Status | Route / API Mapping | Notes |
| :--- | :---: | :--- | :--- |
| **Attribution Workbench** | **Ready** | `POST /api/analyze` | Accepts queries and anchors, returns dual-layer brief and Mermaid trail. |
| **Knowledge Graph View** | **Ready** | `GET /api/graph` | Exports nodes and edges formatted for Canvas/D3 force layout. |
| **Indicator Search** | **Ready** | `GET /api/ioc/{indicator}` | Returns node degree, neighbors, and corpus report citations. |
| **Actor Directory** | **Ready** | `GET /api/actors` | Returns tracked adversaries and connected entity counts. |
| **Benchmark Dashboard** | **Decoupled** | — | Legacy evaluation harness (`/api/cases` and `/api/benchmark`) is intentionally decoupled from production serving to preserve evaluation data hygiene. Pre-computed audit metrics should be displayed via static report or dedicated evaluation dashboards. |
