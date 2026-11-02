"""
API Schemas for NexusCTI Threat Attribution Service.
Defines structured request and response models with strict input validation.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$"
)
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
CVE_REGEX = re.compile(r"^cve-\d{4}-\d{4,}$", re.IGNORECASE)
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def validate_and_normalize_ioc(indicator: Optional[str]) -> Optional[str]:
    """
    Normalizes defanged indicators and validates indicator syntax.
    Permits valid IPv4, IPv6, Domain/FQDN, MD5/SHA1/SHA256, CVE, or URL.
    Raises ValueError for malformed or invalid indicator strings.
    """
    if indicator is None:
        return None
    if not isinstance(indicator, str):
        raise ValueError("Indicator must be a string")

    cleaned = indicator.strip().replace("[.]", ".").replace("[:]", ":")
    if not cleaned:
        raise ValueError("Indicator cannot be empty or blank")

    # Must not contain spaces or control characters
    if any(c in cleaned for c in {" ", chr(9), chr(10), chr(13)}):
        raise ValueError("Indicator cannot contain whitespace characters")

    # Check for forbidden punctuation/command characters
    forbidden_chars = set(";'\"`<>{}\\^|")
    if any(c in cleaned for c in forbidden_chars):
        raise ValueError(f"Indicator contains invalid characters: '{cleaned}'")

    # 1. Try IP address (IPv4 / IPv6)
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    # 2. Try CVE identifier
    if CVE_REGEX.match(cleaned):
        return cleaned.upper()

    # 3. Try Hash (MD5, SHA1, SHA256)
    if HASH_REGEX.match(cleaned):
        return cleaned.lower()

    # 4. Try Domain / FQDN
    if DOMAIN_REGEX.match(cleaned):
        return cleaned.lower()

    # 5. Try URL
    if URL_REGEX.match(cleaned):
        return cleaned

    raise ValueError(
        f"Invalid indicator format: '{cleaned}'. "
        "Must be a valid IPv4/IPv6 address, domain name, hash (MD5/SHA1/SHA256), CVE identifier, or URL."
    )


class AttributionRequest(BaseModel):
    """
    Request payload for incident and indicator attribution analysis.
    """
    ioc: Optional[str] = Field(
        None,
        description="Indicator of Compromise (IPv4, domain, hash, or CVE)",
        json_schema_extra={"example": "185.225.17.42"}
    )
    narrative: Optional[str] = Field(
        None,
        description="Free-form incident telemetry or threat reporting text",
        json_schema_extra={"example": "Observed C2 beaconing using SUNBURST backdoor via avsvmcloud[.]com."}
    )
    query: Optional[str] = Field(
        None,
        description="Legacy field: free-form query or indicator (backward compatibility)",
    )
    ioc_override: Optional[str] = Field(
        None,
        description="Legacy field: explicit IOC override (backward compatibility)",
    )
    top_k: int = Field(
        5,
        ge=1,
        le=10,
        description="Number of ranked candidate actors to return"
    )

    @field_validator("ioc", "ioc_override", mode="before")
    @classmethod
    def clean_indicator(cls, v):
        if v is None:
            return None
        return validate_and_normalize_ioc(v)

    @field_validator("narrative", "query", mode="before")
    @classmethod
    def clean_text(cls, v):
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("Text query must be a string")
        cleaned = v.strip()
        if not cleaned:
            return None
        return cleaned

    def get_effective_ioc(self) -> Optional[str]:
        if self.ioc:
            return self.ioc
        if self.ioc_override:
            return self.ioc_override
        if self.query and self._looks_like_ioc(self.query):
            try:
                return validate_and_normalize_ioc(self.query)
            except ValueError:
                return None
        return None

    def get_effective_narrative(self) -> str:
        if self.narrative:
            return self.narrative
        if self.query and not self._looks_like_ioc(self.query):
            return self.query
        effective_ioc = self.get_effective_ioc()
        if effective_ioc:
            return f"Telemetry investigation regarding indicator {effective_ioc}."
        if self.query:
            return f"Telemetry investigation regarding indicator {self.query}."
        return ""

    @staticmethod
    def _looks_like_ioc(val: Optional[str]) -> bool:
        if not val:
            return False
        val = val.strip().replace("[.]", ".").replace("[:]", ":")
        if any(c in val for c in {" ", chr(9), chr(10), chr(13)}):
            return False
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            pass
        return bool(
            CVE_REGEX.match(val)
            or HASH_REGEX.match(val)
            or DOMAIN_REGEX.match(val)
            or URL_REGEX.match(val)
        )


class GraphEvidenceHop(BaseModel):
    step: int = Field(..., description="Step sequence index in the multi-hop path")
    source: str = Field(..., description="Source entity label")
    source_type: str = Field(..., description="Ontological type of source entity")
    relation: str = Field(..., description="Relational predicate connecting source to target")
    target: str = Field(..., description="Target entity label")
    target_type: str = Field(..., description="Ontological type of target entity")
    rationale: str = Field("", description="Technical explanation for this pivot")
    citation: str = Field("", description="Authoritative CTI source citation")


class GraphEvidence(BaseModel):
    indicator: str = Field(..., description="Query indicator string")
    is_known_in_graph: bool = Field(..., description="Whether indicator is present in baseline graph")
    resolved_node_id: Optional[str] = Field(None, description="Graph node ID if resolved")
    hop_count: int = Field(0, description="Total reasoning hops to the attributed actor")
    chain: List[GraphEvidenceHop] = Field(default_factory=list, description="Ordered multi-hop reasoning trail")


class TextEvidenceProof(BaseModel):
    doc_id: str = Field(..., description="Identifier of the retrieved CTI corpus report")
    source: str = Field(..., description="Publisher or threat advisory source")
    date: str = Field("", description="Publication or reporting date")
    relevant_text: str = Field(..., description="Extracted relevant narrative excerpt")
    matched_iocs: List[str] = Field(default_factory=list, description="Corroborated IOCs in passage")
    retrieval_score: float = Field(..., description="RAG hybrid retrieval relevance score")


class CandidateAttribution(BaseModel):
    rank: int = Field(..., description="Rank in the attribution candidate list (1-indexed)")
    actor_id: str = Field(..., description="Standardized actor identifier (e.g. actor_apt28)")
    actor_name: str = Field(..., description="Human-readable actor name")
    fused_confidence: float = Field(..., description="Multi-modal fused score (0.0 to 1.0)")
    structural_confidence: float = Field(..., description="GNN relational score (0.0 to 1.0)")
    textual_confidence: float = Field(..., description="RAG textual retrieval score (0.0 to 1.0)")
    cross_validation_score: float = Field(..., description="Graph-text corroboration consistency (0.0 to 1.0)")
    verdict: str = Field(..., description="Confidence verdict: HIGH_CONFIDENCE, PROBABLE, or INCONCLUSIVE")
    evidence_summary: str = Field("", description="Evidence rationale connecting indicator to actor")
    structural_hops: int = Field(0, description="Number of graph hops connecting IOC to this actor (0 if no path)")
    corroborating_sources: List[str] = Field(default_factory=list, description="Authoritative CTI reporting sources citing this actor")


class AttributionResponse(BaseModel):
    status: str = Field(..., description="Execution status: SUCCESS, INSUFFICIENT_EVIDENCE, or UNKNOWN_INDICATOR")
    query_ioc: str = Field(..., description="Investigated indicator")
    attribution_status: str = Field(..., description="High-level attribution outcome: ATTRIBUTED, INCONCLUSIVE, or UNKNOWN")
    top_candidate: Optional[CandidateAttribution] = Field(None, description="Leading attributed threat actor candidate")
    candidates: List[CandidateAttribution] = Field(default_factory=list, description="Ranked list of attribution candidates")
    graph_evidence: GraphEvidence = Field(..., description="Topological knowledge graph reasoning evidence")
    text_evidence: List[TextEvidenceProof] = Field(default_factory=list, description="Textual narrative proofs from authoritative corpus")
    synergistic_rationale: str = Field("", description="Synthesized multi-modal explanation")
    hallucination_risk: str = Field(..., description="Assessed hallucination risk level")
    disclaimer: str = Field(
        "Attribution scores reflect graph topology and corpus retrieval signals. Human analyst corroboration is required before operational defense actions.",
        description="Scientific and operational disclaimer"
    )


class IndicatorLookupResponse(BaseModel):
    indicator: str
    is_known: bool
    node_id: Optional[str] = None
    node_type: Optional[str] = None
    node_name: Optional[str] = None
    description: Optional[str] = None
    degree: int = 0
    connected_edges: List[Dict[str, Any]] = Field(default_factory=list)
    matching_reports: List[Dict[str, Any]] = Field(default_factory=list)
    detail: Optional[str] = None


class ActorDetail(BaseModel):
    actor_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: str = ""
    connected_entities: int = 0


class ActorListResponse(BaseModel):
    total: int
    actors: List[ActorDetail]


class ErrorResponse(BaseModel):
    error: str = Field(..., description="Standardized error code")
    detail: str = Field(..., description="Human-readable explanation of the error")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the error")


class InvestigationScenario(BaseModel):
    id: str = Field(..., description="Scenario unique identifier")
    name: str = Field(..., description="Descriptive scenario title")
    query: str = Field(..., description="Telemetry narrative or alert excerpt")
    anchor_ioc: str = Field(..., description="Primary anchor indicator")
    expected_hops: int = Field(..., description="Anticipated topological path depth")
    category: str = Field(..., description="Investigation scenario archetype")
    description: str = Field(..., description="Technical summary")
