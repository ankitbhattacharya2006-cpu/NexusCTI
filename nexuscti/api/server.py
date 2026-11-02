"""
FastAPI Server for NexusCTI.
Exposes REST endpoints for SOC incident attribution, graph visualization,
indicator evidence retrieval, and candidate actor intelligence.
"""

from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError

from ..service import get_service
from ..fusion.report_generator import AttributionReportGenerator
from ..config import WEB_DIR
from .schemas import (
    AttributionRequest,
    AttributionResponse,
    CandidateAttribution,
    GraphEvidence,
    GraphEvidenceHop,
    TextEvidenceProof,
    IndicatorLookupResponse,
    ActorDetail,
    ActorListResponse,
    ErrorResponse,
    validate_and_normalize_ioc,
    InvestigationScenario,
)

logger = logging.getLogger("NexusCTI.API")

app = FastAPI(
    title="NexusCTI: Cyber Threat Attribution Engine API",
    description=(
        "Production-ready REST API for cyber threat attribution. "
        "Provides multi-modal relational reasoning over structural knowledge graph topology "
        "and contextual narrative retrieval over authoritative threat reporting."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- EXCEPTION HANDLERS ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    detail_msg = "; ".join(f"{err['loc'][-1]}: {err['msg']}" for err in exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "detail": detail_msg or "Invalid request parameters.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
        err_code = "VALIDATION_ERROR"
    elif exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        err_code = "INTERNAL_SERVER_ERROR"
    else:
        err_code = "HTTP_ERROR"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": err_code,
            "detail": exc.detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled server error during {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "detail": "An unexpected error occurred during processing. Please verify server telemetry.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def _build_candidate_evidence(
    candidate: Any,
    is_unknown: bool = False,
) -> Tuple[str, int, List[str]]:
    """Generates structured, objective evidence rationale for an attribution candidate."""
    if is_unknown:
        return (
            "Indicator was not resolved in graph topology and no narrative evidence links this actor.",
            0,
            [],
        )

    hops = candidate.graph_trail.hop_count if candidate.graph_trail else 0
    sources = list(dict.fromkeys(p.source for p in candidate.narrative_proofs if p.source))
    clauses: List[str] = []

    if candidate.graph_trail and candidate.graph_trail.hops:
        chain_text = candidate.graph_trail.to_readable_chain()
        clauses.append(f"Structural path ({hops} hops): {chain_text}")
    else:
        clauses.append("No resolved multi-hop structural path in knowledge graph")

    if sources:
        clauses.append(f"Corroborated by reporting from {', '.join(sources[:2])}")
    else:
        clauses.append("No direct narrative citations in retrieved intelligence")

    clauses.append(
        f"Scores: Fused {candidate.fused_confidence * 100:.1f}%, "
        f"GNN {candidate.structural_confidence * 100:.1f}%, "
        f"RAG {candidate.textual_confidence * 100:.1f}%, "
        f"Cross-Val {candidate.cross_validation_score * 100:.1f}%"
    )

    return ". ".join(clauses) + ".", hops, sources


# --- CORE API ENDPOINTS ---
@app.get("/api/health")
def health_check():
    """Returns engine health, version, knowledge graph metrics, and active retrievers."""
    service = get_service()
    node_count = len(service.tkg.raw_nodes)
    edge_count = service.tkg.nx_graph.number_of_edges()
    corpus_count = len(service.corpus)
    actors = [n.id for n in service.tkg.raw_nodes if n.type.value in ("ThreatActor", "actor")]

    return {
        "status": "online",
        "engine": "NexusCTI v1.1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "graph": {
            "nodes": node_count,
            "edges": edge_count,
            "threat_actors_tracked": len(actors),
        },
        "retrieval": {
            "corpus_reports": corpus_count,
            "retriever": "Hybrid Dense-Sparse RRF",
        },
        "gnn": "Heterogeneous Relational GNN",
    }


@app.post(
    "/api/analyze",
    response_model=AttributionResponse,
    responses={
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
def analyze_incident(req: AttributionRequest):
    """
    Submits an indicator of compromise (IOC) or threat narrative for attribution analysis.
    Returns ranked threat actor candidates, multi-hop graph trails, and narrative evidence proofs.
    """
    effective_ioc = req.get_effective_ioc()
    effective_narrative = req.get_effective_narrative()

    if not effective_ioc and not effective_narrative:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one of 'ioc', 'narrative', or 'query' must be provided.",
        )

    service = get_service()

    # Step 1: Check indicator presence in knowledge graph
    is_known_in_graph = False
    resolved_node = None
    if effective_ioc:
        resolved_node = service.tkg.find_node_by_indicator(effective_ioc)
        is_known_in_graph = resolved_node is not None

    # Step 2: Execute fused attribution inference under isolation
    query_text = effective_narrative or f"Investigate IOC {effective_ioc}"
    try:
        result = service.analyze(query_text, ioc_override=effective_ioc)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unhandled engine error during incident analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during processing. Please verify server telemetry.",
        )
    top_candidate_raw = result.top_actor

    # Check if indicator is corroborated in retrieved narrative passages
    has_matching_iocs_in_text = (
        effective_ioc is not None
        and any(
            any(effective_ioc.lower() == str(ioc_m).lower() for ioc_m in p.matched_iocs)
            for p in result.narrative_proofs
        )
    )

    is_unknown_indicator = (effective_ioc is not None) and (not is_known_in_graph) and (not has_matching_iocs_in_text)
    is_insufficient = (not top_candidate_raw) or (top_candidate_raw.fused_confidence < 0.40 and not is_known_in_graph)

    if is_unknown_indicator:
        api_status = "UNKNOWN_INDICATOR"
        attribution_status = "UNKNOWN"
        rationale = (
            f"Indicator '{effective_ioc}' was not resolved in the threat knowledge graph "
            f"and no corroborating narrative evidence was retrieved in authoritative reporting. "
            f"Attribution is inconclusive."
        )
    elif is_insufficient:
        api_status = "INSUFFICIENT_EVIDENCE"
        attribution_status = "INCONCLUSIVE"
        rationale = (
            f"Telemetry signals for indicator '{result.query_ioc}' are insufficient to establish a definitive attribution. "
            f"Candidate confidences remain below operational thresholds."
        )
    else:
        api_status = "SUCCESS"
        attribution_status = (
            "ATTRIBUTED" if top_candidate_raw and top_candidate_raw.verdict in ("HIGH_CONFIDENCE", "PROBABLE")
            else "INCONCLUSIVE"
        )
        rationale = result.synergistic_rationale

    # Step 3: Construct structured candidate list with candidate evidence explanation
    candidates: List[CandidateAttribution] = []
    top_candidate_formatted: Optional[CandidateAttribution] = None

    for rank_idx, c in enumerate(result.all_candidates[:req.top_k], 1):
        summary, hops, sources = _build_candidate_evidence(c, is_unknown=is_unknown_indicator)
        cand_model = CandidateAttribution(
            rank=rank_idx,
            actor_id=c.actor_id,
            actor_name=c.actor_name,
            fused_confidence=c.fused_confidence,
            structural_confidence=c.structural_confidence,
            textual_confidence=c.textual_confidence,
            cross_validation_score=c.cross_validation_score,
            verdict=c.verdict if not is_unknown_indicator else "INCONCLUSIVE",
            evidence_summary=summary,
            structural_hops=hops,
            corroborating_sources=sources,
        )
        candidates.append(cand_model)

    if candidates and not is_unknown_indicator and not is_insufficient:
        top_candidate_formatted = candidates[0]

    # Step 4: Construct graph evidence
    hops_list: List[GraphEvidenceHop] = []
    if result.graph_trail and result.graph_trail.hops and not is_unknown_indicator:
        for hop in result.graph_trail.hops:
            hops_list.append(
                GraphEvidenceHop(
                    step=hop.step,
                    source=hop.source_name,
                    source_type=hop.source_type,
                    relation=hop.relation,
                    target=hop.target_name,
                    target_type=hop.target_type,
                    rationale=hop.rationale,
                    citation=hop.citation,
                )
            )

    graph_evidence = GraphEvidence(
        indicator=result.query_ioc,
        is_known_in_graph=is_known_in_graph,
        resolved_node_id=resolved_node.id if resolved_node else None,
        hop_count=len(hops_list),
        chain=hops_list,
    )

    # Step 5: Construct text evidence
    text_proofs: List[TextEvidenceProof] = []
    if result.narrative_proofs and not is_unknown_indicator:
        for p in result.narrative_proofs:
            text_proofs.append(
                TextEvidenceProof(
                    doc_id=p.doc_id,
                    source=p.source,
                    date=p.date or "",
                    relevant_text=p.relevant_text,
                    matched_iocs=p.matched_iocs,
                    retrieval_score=round(float(p.retrieval_score), 4),
                )
            )

    # Backward-compatible reports for web visualizer
    json_report = AttributionReportGenerator.generate_json_report(result)
    md_report = AttributionReportGenerator.generate_markdown_report(result)

    response_payload = {
        "status": api_status,
        "query_ioc": result.query_ioc,
        "attribution_status": attribution_status,
        "top_candidate": top_candidate_formatted.model_dump() if top_candidate_formatted else None,
        "candidates": [c.model_dump() for c in candidates],
        "graph_evidence": graph_evidence.model_dump(),
        "text_evidence": [p.model_dump() for p in text_proofs],
        "synergistic_rationale": rationale,
        "hallucination_risk": result.hallucination_risk if not is_unknown_indicator else "HIGH (Ungrounded)",
        "disclaimer": (
            "Attribution scores reflect graph topology and corpus retrieval signals. "
            "Human analyst corroboration is required before operational defense actions."
        ),
        # Legacy compatibility keys for Web UI
        "analysis": json_report,
        "markdown_report": md_report,
    }

    return response_payload


@app.get(
    "/api/ioc/{indicator}/attribution",
    response_model=AttributionResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
def attribute_indicator_get(indicator: str, top_k: int = 5):
    """
    Direct GET convenience endpoint for indicator attribution analysis.
    Accepts an IOC in the path and optional top_k query parameter (1 to 10).
    """
    try:
        valid_ioc = validate_and_normalize_ioc(indicator)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if top_k < 1 or top_k > 10:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="top_k must be an integer between 1 and 10.",
        )

    req = AttributionRequest(ioc=valid_ioc, top_k=top_k)
    return analyze_incident(req)


@app.get(
    "/api/ioc/{indicator}",
    response_model=IndicatorLookupResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
def lookup_indicator(indicator: str):
    """
    Directly retrieves graph topology neighborhood and relevant corpus documents for an indicator.
    """
    try:
        clean_ioc = validate_and_normalize_ioc(indicator)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    service = get_service()
    node = service.tkg.find_node_by_indicator(clean_ioc)

    if not node:
        return {
            "indicator": clean_ioc,
            "is_known": False,
            "detail": f"Indicator '{clean_ioc}' is not currently present in the threat knowledge graph.",
        }

    # Extract connected edges
    connected = []
    for u, v, data in service.tkg.nx_graph.edges(node.id, data=True):
        connected.append({
            "target_id": v,
            "target_name": service.tkg.nx_graph.nodes[v].get("name", v),
            "relation": data.get("rel_type", "associated_with"),
            "citation": data.get("citation", ""),
        })

    # Search corpus for references
    retrieved = service.hybrid_retriever.retrieve(clean_ioc, top_k=3)
    matching_reports = []
    for r in retrieved:
        matching_reports.append({
            "doc_id": r.doc_id,
            "source": r.source,
            "date": r.date,
            "relevance_score": round(float(r.retrieval_score), 4),
            "excerpt": r.relevant_text[:200] + "..." if len(r.relevant_text) > 200 else r.relevant_text,
        })

    return {
        "indicator": clean_ioc,
        "is_known": True,
        "node_id": node.id,
        "node_type": node.type.value,
        "node_name": node.name,
        "description": node.description,
        "degree": service.tkg.nx_graph.degree(node.id),
        "connected_edges": connected,
        "matching_reports": matching_reports,
    }


@app.get(
    "/api/actors",
    response_model=ActorListResponse,
    responses={500: {"model": ErrorResponse}},
)
def list_actors():
    """Lists tracked threat actors with descriptions, aliases, and known indicator counts."""
    service = get_service()
    actors: List[Dict[str, Any]] = []

    for n in service.tkg.raw_nodes:
        if n.type.value in ("ThreatActor", "actor"):
            degree = service.tkg.nx_graph.degree(n.id)
            aliases = n.metadata.get("aliases", [])
            actors.append({
                "actor_id": n.id,
                "name": n.name,
                "aliases": aliases,
                "description": n.description,
                "connected_entities": degree,
            })

    actors.sort(key=lambda x: x["name"])
    return {"total": len(actors), "actors": actors}


@app.get(
    "/api/scenarios",
    response_model=List[InvestigationScenario],
    responses={500: {"model": ErrorResponse}},
)
@app.get(
    "/api/cases",
    response_model=List[InvestigationScenario],
    include_in_schema=False,
)
def get_investigation_scenarios():
    """
    Returns standardized investigation telemetry scenarios for analyst workbench testing.
    Evaluation ground truth labels are strictly omitted to maintain evaluation hygiene.
    """
    from ..eval.benchmark_cases import get_benchmark_dataset
    raw_cases = get_benchmark_dataset()
    scenarios: List[InvestigationScenario] = []
    for c in raw_cases:
        scenarios.append(InvestigationScenario(
            id=c.id,
            name=c.name,
            query=c.query,
            anchor_ioc=c.anchor_ioc,
            expected_hops=c.expected_hops,
            category=c.category,
            description=c.description,
        ))
    return scenarios


@app.get("/api/graph")
def get_knowledge_graph():
    """Exports full graph topology for the interactive Web visualizer."""
    service = get_service()
    return service.get_graph_data()


# Mount Web UI static directory
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            with open(index_file, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>NexusCTI Web UI Loading...</h1>"
