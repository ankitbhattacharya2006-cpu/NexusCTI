/**
 * NexusCTI Production Web Dashboard Application
 * Connects the SOC frontend directly to the NexusCTI REST API:
 * - GET  /api/scenarios (Standardized investigation scenarios without ground-truth labels)
 * - POST /api/analyze (Incident & indicator multi-modal attribution)
 * - GET  /api/ioc/{indicator} (Graph topology & corpus neighborhood inspection)
 * - GET  /api/ioc/{indicator}/attribution (Direct indicator attribution)
 * - GET  /api/actors (Tracked threat actor intelligence directory)
 * - GET  /api/graph (Full knowledge graph topology)
 * - GET  /api/health (System status & engine component telemetry)
 */

let currentGraphData = { nodes: [], edges: [] };
let activeTrailHops = [];
let currentAnalysisResult = null;
let currentMarkdownReport = "";
let trackedActors = [];

// Canvas Rendering State
let canvas, ctx;
let graphState = {
    zoom: 1.0,
    panX: 0,
    panY: 0,
    isDragging: false,
    dragStartX: 0,
    dragStartY: 0,
    hoveredNode: null,
    onlyTrail: false,
    selectedNodeId: null,
};

const TYPE_COLORS = {
    ThreatActor: "#ef4444",
    Malware: "#f59e0b",
    Indicator: "#00f0ff",
    TTP: "#10b981",
    Vulnerability: "#a855f7",
};

// ==========================================
// INITIALIZATION
// ==========================================
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initCanvas();
    loadSystemStatus();
    loadScenarios();
    loadKnowledgeGraph();
    loadActors();
    loadBenchmarkData();
    setupEventListeners();
});

// ==========================================
// 1. TAB NAVIGATION
// ==========================================
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const viewPanels = document.querySelectorAll(".view-panel");

    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");

            tabBtns.forEach(b => b.classList.remove("active"));
            viewPanels.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const activePanel = document.getElementById(`view-${targetTab}`);
            if (activePanel) {
                activePanel.classList.add("active");
            }

            if (targetTab === "graph-view") {
                resizeCanvas();
                drawGraph();
            } else if (targetTab === "actors-view") {
                if (trackedActors.length === 0) {
                    loadActors();
                }
            }
        });
    });
}

// ==========================================
// 2. SYSTEM STATUS TELEMETRY (GET /api/health)
// ==========================================
async function loadSystemStatus() {
    const pill = document.getElementById("graph-stat-pill");
    try {
        const resp = await fetch("/api/health");
        if (resp.ok) {
            const data = await resp.json();
            if (pill && data.graph) {
                pill.innerText = `${data.graph.nodes} Nodes • ${data.graph.edges} Edges • ${data.graph.threat_actors_tracked} Actors`;
            }
        }
    } catch (err) {
        console.warn("Unable to fetch /api/health:", err);
    }
}

// ==========================================
// 3. INVESTIGATION SCENARIO LOADER (GET /api/scenarios)
// ==========================================
async function loadScenarios() {
    const container = document.getElementById("scenario-list");
    if (!container) return;

    try {
        const resp = await fetch("/api/scenarios");
        if (!resp.ok) {
            throw new Error(`Failed to fetch scenarios from /api/scenarios (HTTP ${resp.status})`);
        }
        const cases = await resp.json();

        container.innerHTML = "";
        cases.forEach((c, idx) => {
            const item = document.createElement("div");
            item.className = "scenario-item";
            if (idx === 0) item.classList.add("active");
            const catLabel = (c.category || "Investigation").replace(/_/g, " ");
            item.innerHTML = `
                <div>
                    <strong>${c.name}</strong>
                    <div class="scenario-category">${catLabel}</div>
                </div>
                <span class="hop-tag">${c.expected_hops > 0 ? c.expected_hops + " Hops" : "Direct"}</span>
            `;
            item.addEventListener("click", () => {
                document.querySelectorAll(".scenario-item").forEach(el => el.classList.remove("active"));
                item.classList.add("active");
                const queryEl = document.getElementById("incident-query");
                const anchorEl = document.getElementById("anchor-ioc");
                if (queryEl) queryEl.value = c.query;
                if (anchorEl) anchorEl.value = c.anchor_ioc;
                runAttribution(c.query, c.anchor_ioc);
            });
            container.appendChild(item);
        });

        // Auto-trigger first scenario on initial load
        if (cases.length > 0) {
            const first = cases[0];
            const queryEl = document.getElementById("incident-query");
            const anchorEl = document.getElementById("anchor-ioc");
            if (queryEl) queryEl.value = first.query;
            if (anchorEl) anchorEl.value = first.anchor_ioc;
            runAttribution(first.query, first.anchor_ioc);
        }
    } catch (err) {
        console.error("Failed to load scenarios:", err);
        container.innerHTML = `<div class="empty-state" style="color:var(--neon-red);">Failed to load scenarios: ${err.message}</div>`;
    }
}

// ==========================================
// 4. WORKBENCH ATTRIBUTION (POST /api/analyze)
// ==========================================
function showAlert(message, type = "error") {
    const banner = document.getElementById("attribution-alert-banner");
    if (!banner) return;
    banner.className = `alert-banner ${type}`;
    banner.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <span>${message}</span>
    `;
    banner.style.display = "flex";
}

function hideAlert() {
    const banner = document.getElementById("attribution-alert-banner");
    if (banner) {
        banner.style.display = "none";
    }
}

async function runAttribution(query, anchor) {
    const runBtn = document.getElementById("btn-run-attribution");
    const lookupBtn = document.getElementById("btn-lookup-ioc");

    if (runBtn) {
        runBtn.disabled = true;
        runBtn.innerHTML = `
            <span class="loading-spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite;"></span>
            Analyzing Telemetry...
        `;
    }
    if (lookupBtn) lookupBtn.disabled = true;

    hideAlert();
    setWorkbenchLoadingState();

    const payload = {};
    if (anchor && anchor.trim()) {
        payload.ioc = anchor.trim();
    }
    if (query && query.trim()) {
        payload.narrative = query.trim();
    }
    payload.top_k = 5;

    try {
        const resp = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await resp.json();

        if (resp.status === 422) {
            showAlert(`Validation Error: ${data.detail || "Invalid input parameters."}`, "error");
            renderInvalidIocState(data.detail || "Submitted indicator format was rejected by server validation.");
            return;
        }

        if (resp.status === 400) {
            showAlert(`Request Error: ${data.detail || "Bad request syntax."}`, "warning");
            renderInvalidIocState(data.detail);
            return;
        }

        if (!resp.ok || resp.status === 500) {
            showAlert(`Server Error (HTTP ${resp.status}): ${data.detail || "Inference engine encountered an unexpected error."}`, "error");
            renderServerErrorState(data.detail);
            return;
        }

        currentAnalysisResult = data;
        currentMarkdownReport = data.markdown_report || "";

        if (data.status === "UNKNOWN_INDICATOR" || data.attribution_status === "UNKNOWN") {
            renderUnknownIndicatorState(data);
        } else if (data.status === "INSUFFICIENT_EVIDENCE") {
            renderInsufficientEvidenceState(data);
        } else {
            renderSuccessfulAttribution(data);
        }

        renderReportView(currentMarkdownReport);

        if (data.graph_evidence && data.graph_evidence.chain && data.graph_evidence.chain.length > 0) {
            activeTrailHops = data.graph_evidence.chain.map(h => ({
                source_id: h.source,
                target_id: h.target,
                relation: h.relation
            }));
        } else {
            activeTrailHops = [];
        }

    } catch (err) {
        console.error("Attribution fetch error:", err);
        showAlert(`Network or server connection failure: ${err.message}`, "error");
        renderServerErrorState(err.message);
    } finally {
        if (runBtn) {
            runBtn.disabled = false;
            runBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                Execute Attribution
            `;
        }
        if (lookupBtn) lookupBtn.disabled = false;
    }
}

function setWorkbenchLoadingState() {
    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = "verdict-tag";
    verdictEl.innerText = "ANALYZING...";
    document.getElementById("actor-name").innerText = "Executing Dual-Layer Reasoning Engine...";
    document.getElementById("actor-rationale").innerText = "Traversing structural knowledge graph topology and performing dense-sparse RRF text retrieval...";
    document.getElementById("fused-conf-val").innerText = "...";
}

function renderSuccessfulAttribution(data) {
    const top = data.top_candidate;
    if (!top) {
        renderInsufficientEvidenceState(data);
        return;
    }

    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = `verdict-tag ${top.verdict}`;
    verdictEl.innerText = `${top.verdict.replace(/_/g, " ")} ATTRIBUTION`;

    document.getElementById("actor-name").innerText = top.actor_name;
    document.getElementById("actor-rationale").innerText = data.synergistic_rationale || top.evidence_summary;

    const fusedPct = Math.round(top.fused_confidence * 100);
    document.getElementById("fused-conf-val").innerText = `${fusedPct}%`;

    const gnnPct = Math.round(top.structural_confidence * 100);
    const ragPct = Math.round(top.textual_confidence * 100);
    const cvPct = Math.round(top.cross_validation_score * 100);

    document.getElementById("val-gnn").innerText = `${gnnPct}%`;
    document.getElementById("bar-gnn").style.width = `${gnnPct}%`;

    document.getElementById("val-rag").innerText = `${ragPct}%`;
    document.getElementById("bar-rag").style.width = `${ragPct}%`;

    document.getElementById("val-cv").innerText = `${cvPct}%`;
    document.getElementById("bar-cv").style.width = `${cvPct}%`;

    const hopCount = data.graph_evidence ? data.graph_evidence.hop_count : top.structural_hops;
    document.getElementById("val-hops").innerText = `${hopCount} Hops`;
    document.getElementById("val-hallucination").innerText = `Risk: ${data.hallucination_risk || "MINIMAL"}`;

    renderGraphTrail(data.graph_evidence ? data.graph_evidence.chain : []);
    renderNarrativeProofs(data.text_evidence || []);
    renderCandidatesTable(data.candidates || []);
}

function renderUnknownIndicatorState(data) {
    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = "verdict-tag INCONCLUSIVE";
    verdictEl.innerText = "UNKNOWN INDICATOR";

    document.getElementById("actor-name").innerText = `Unknown Indicator: ${data.query_ioc || "OOD"}`;
    document.getElementById("actor-rationale").innerText = data.synergistic_rationale ||
        `Indicator '${data.query_ioc}' was not resolved in the threat knowledge graph and no corroborating narrative evidence was retrieved in authoritative reporting. System abstains from false attribution.`;

    document.getElementById("fused-conf-val").innerText = "0%";
    document.getElementById("val-gnn").innerText = "0%";
    document.getElementById("bar-gnn").style.width = "0%";
    document.getElementById("val-rag").innerText = "0%";
    document.getElementById("bar-rag").style.width = "0%";
    document.getElementById("val-cv").innerText = "0%";
    document.getElementById("bar-cv").style.width = "0%";
    document.getElementById("val-hops").innerText = "0 Hops";
    document.getElementById("val-hallucination").innerText = "Risk: Ungrounded (Abstained)";

    renderGraphTrail([]);
    renderNarrativeProofs([]);
    renderCandidatesTable(data.candidates || []);
}

function renderInsufficientEvidenceState(data) {
    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = "verdict-tag INCONCLUSIVE";
    verdictEl.innerText = "INSUFFICIENT EVIDENCE";

    document.getElementById("actor-name").innerText = "Inconclusive Attribution";
    document.getElementById("actor-rationale").innerText = data.synergistic_rationale ||
        "Telemetry signals for this indicator are insufficient to establish a definitive attribution. Candidate confidences remain below operational threshold.";

    document.getElementById("fused-conf-val").innerText = "--%";
    document.getElementById("val-gnn").innerText = "--%";
    document.getElementById("bar-gnn").style.width = "0%";
    document.getElementById("val-rag").innerText = "--%";
    document.getElementById("bar-rag").style.width = "0%";
    document.getElementById("val-cv").innerText = "--%";
    document.getElementById("bar-cv").style.width = "0%";
    document.getElementById("val-hops").innerText = "0 Hops";
    document.getElementById("val-hallucination").innerText = "Risk: Unverified";

    renderGraphTrail([]);
    renderNarrativeProofs(data.text_evidence || []);
    renderCandidatesTable(data.candidates || []);
}

function renderInvalidIocState(detail) {
    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = "verdict-tag";
    verdictEl.style.background = "rgba(239, 68, 68, 0.2)";
    verdictEl.style.color = "#ef4444";
    verdictEl.innerText = "VALIDATION REJECTED";

    document.getElementById("actor-name").innerText = "Invalid Indicator Format";
    document.getElementById("actor-rationale").innerText = detail || "The indicator syntax did not match recognized CTI formats (IPv4/IPv6, domain, hash, CVE, URL).";

    document.getElementById("fused-conf-val").innerText = "N/A";
    document.getElementById("val-gnn").innerText = "N/A";
    document.getElementById("bar-gnn").style.width = "0%";
    document.getElementById("val-rag").innerText = "N/A";
    document.getElementById("bar-rag").style.width = "0%";
    document.getElementById("val-cv").innerText = "N/A";
    document.getElementById("bar-cv").style.width = "0%";
    document.getElementById("val-hops").innerText = "0 Hops";
    document.getElementById("val-hallucination").innerText = "Validation Fault";

    renderGraphTrail([]);
    renderNarrativeProofs([]);
    renderCandidatesTable([]);
}

function renderServerErrorState(detail) {
    const verdictEl = document.getElementById("actor-verdict");
    verdictEl.className = "verdict-tag";
    verdictEl.style.background = "rgba(239, 68, 68, 0.2)";
    verdictEl.style.color = "#ef4444";
    verdictEl.innerText = "SERVER ERROR";

    document.getElementById("actor-name").innerText = "Attribution Service Unavailable";
    document.getElementById("actor-rationale").innerText = detail || "An unexpected error occurred during backend inference. Please inspect server telemetry.";

    document.getElementById("fused-conf-val").innerText = "ERR";
    renderGraphTrail([]);
    renderNarrativeProofs([]);
    renderCandidatesTable([]);
}

function renderGraphTrail(hops) {
    const container = document.getElementById("trail-flow-container");
    const countEl = document.getElementById("trail-step-count");
    if (!container) return;

    if (!hops || hops.length === 0) {
        container.innerHTML = "<div class='empty-state'>No multi-hop structural path resolved for this indicator.</div>";
        if (countEl) countEl.innerText = "0 Steps";
        return;
    }

    if (countEl) countEl.innerText = `${hops.length} Steps`;
    container.innerHTML = "";

    hops.forEach(hop => {
        const card = document.createElement("div");
        card.className = "trail-step-card";
        card.innerHTML = `
            <div class="step-header">
                <span class="step-number">Step ${hop.step} — Relational Pivot</span>
                <span class="step-citation">${hop.citation || "Knowledge Graph Topology"}</span>
            </div>
            <div class="step-chain">
                <span class="node-chip ${hop.source_type}">${hop.source}</span>
                <span class="rel-chip">--[ ${hop.relation} ]--></span>
                <span class="node-chip ${hop.target_type}">${hop.target}</span>
            </div>
            <div class="step-rationale">${hop.rationale || "Structural link prediction"}</div>
        `;
        container.appendChild(card);
    });
}

function renderNarrativeProofs(proofs) {
    const container = document.getElementById("narrative-cards-container");
    const countEl = document.getElementById("proof-citation-count");
    if (!container) return;

    if (!proofs || proofs.length === 0) {
        container.innerHTML = "<div class='empty-state'>No corroborating narrative passages retrieved in authoritative reporting.</div>";
        if (countEl) countEl.innerText = "0 Citations";
        return;
    }

    if (countEl) countEl.innerText = `${proofs.length} Citations`;
    container.innerHTML = "";

    proofs.forEach(p => {
        const card = document.createElement("div");
        card.className = "narrative-card";
        const iocBadges = (p.matched_iocs || []).map(ioc => `<span class="ioc-badge">${ioc}</span>`).join(" ");

        card.innerHTML = `
            <div class="narrative-header">
                <span class="source-tag">${p.source} ${p.date ? `(${p.date})` : ""}</span>
                <span class="score-tag">RRF Score: ${p.retrieval_score ? p.retrieval_score.toFixed(3) : "0.00"}</span>
            </div>
            <div class="narrative-quote">"${(p.relevant_text || "").trim()}"</div>
            ${iocBadges ? `
                <div class="matched-iocs-row" style="margin-top:0.5rem; font-size:0.75rem;">
                    <span style="color:var(--text-muted); margin-right:0.4rem;">Corroborated:</span>
                    ${iocBadges}
                </div>
            ` : ""}
        `;
        container.appendChild(card);
    });
}

function renderCandidatesTable(candidates) {
    const tbody = document.getElementById("candidates-table-body");
    if (!tbody) return;

    if (!candidates || candidates.length === 0) {
        tbody.innerHTML = "<tr><td colspan='7' class='text-center'>No candidate actors to display.</td></tr>";
        return;
    }

    tbody.innerHTML = "";
    candidates.forEach((c, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>#${c.rank || idx + 1}</td>
            <td><strong>${c.actor_name}</strong><br><small style="color:var(--text-muted); font-family:var(--font-mono);">${c.actor_id}</small></td>
            <td><strong style="color:var(--neon-cyan)">${(c.fused_confidence * 100).toFixed(1)}%</strong></td>
            <td>${(c.structural_confidence * 100).toFixed(1)}%</td>
            <td>${(c.textual_confidence * 100).toFixed(1)}%</td>
            <td>${(c.cross_validation_score * 100).toFixed(1)}%</td>
            <td><span class="verdict-tag ${c.verdict}" style="font-size:0.65rem; padding:0.15rem 0.5rem">${c.verdict}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderReportView(markdown) {
    const el = document.getElementById("report-rendered-content");
    if (!el) return;
    if (!markdown) {
        el.innerHTML = "<p class='text-muted'>No report generated yet. Run an incident investigation from the workbench.</p>";
        return;
    }
    el.innerText = markdown;
}

// ==========================================
// 5. DIRECT INDICATOR LOOKUP (GET /api/ioc/{indicator})
// ==========================================
async function lookupIndicatorDirect(indicator) {
    if (!indicator || !indicator.trim()) {
        showAlert("Please enter an indicator to inspect.", "warning");
        return;
    }

    hideAlert();
    const clean = indicator.trim();
    try {
        const resp = await fetch(`/api/ioc/${encodeURIComponent(clean)}`);
        const data = await resp.json();

        if (resp.status === 400 || resp.status === 422) {
            showAlert(`Indicator Validation Rejection: ${data.detail}`, "error");
            renderInvalidIocState(data.detail);
            return;
        }

        if (!data.is_known) {
            showAlert(`Indicator '${clean}' is not resolved in the threat knowledge graph. Direct lookup returned 0 graph edges.`, "warning");
            return;
        }

        showAlert(
            `Found in Knowledge Graph: ${data.node_name} (${data.node_type}) • Degree: ${data.degree} • Connected Edges: ${data.connected_edges.length} • Matching Corpus Reports: ${data.matching_reports.length}`,
            "info"
        );

        graphState.selectedNodeId = data.node_id;

    } catch (err) {
        console.error("Lookup error:", err);
        showAlert(`Failed to query /api/ioc: ${err.message}`, "error");
    }
}

// ==========================================
// 6. THREAT ACTOR DIRECTORY (GET /api/actors)
// ==========================================
async function loadActors() {
    const container = document.getElementById("actors-directory-container");
    const countBadge = document.getElementById("actors-count-badge");
    if (!container) return;

    try {
        const resp = await fetch("/api/actors");
        if (!resp.ok) {
            container.innerHTML = `<div class='empty-state'>Failed to load threat actors: HTTP ${resp.status}</div>`;
            return;
        }

        const data = await resp.json();
        trackedActors = data.actors || [];

        if (countBadge) {
            countBadge.innerText = `${data.total || trackedActors.length} Tracked Adversaries`;
        }

        container.innerHTML = "";
        trackedActors.forEach(actor => {
            const card = document.createElement("div");
            card.className = "actor-card";

            const aliasText = (actor.aliases && actor.aliases.length > 0)
                ? actor.aliases.join(" • ")
                : "No aliases catalogued";

            card.innerHTML = `
                <div>
                    <div class="actor-card-header">
                        <span class="actor-card-title">${actor.name}</span>
                        <span class="badge info-badge">${actor.actor_id}</span>
                    </div>
                    <div class="actor-card-aliases">Aliases: ${aliasText}</div>
                    <div class="actor-card-desc">${actor.description || "Active advanced persistent threat group tracked in graph topology."}</div>
                </div>
                <div class="actor-card-meta">
                    <span>Connected Nodes: <strong>${actor.connected_entities}</strong></span>
                    <button class="btn btn-secondary btn-sm" onclick="pivotToActorWorkbench('${actor.name}', '${actor.actor_id}')">
                        Investigate in Workbench
                    </button>
                </div>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        console.error("Failed to load actors:", err);
        container.innerHTML = `<div class='empty-state'>Failed to load actors: ${err.message}</div>`;
    }
}

window.pivotToActorWorkbench = function(name, actorId) {
    const queryEl = document.getElementById("incident-query");
    const anchorEl = document.getElementById("anchor-ioc");
    if (queryEl) queryEl.value = `Investigating observed adversary behavior attributed to ${name}.`;
    if (anchorEl) anchorEl.value = "";

    const wbTab = document.getElementById("tab-btn-workbench");
    if (wbTab) wbTab.click();

    runAttribution(`Investigating observed adversary behavior attributed to ${name}.`, null);
};

// ==========================================
// 7. KNOWLEDGE GRAPH EXPLORER (GET /api/graph)
// ==========================================
function initCanvas() {
    canvas = document.getElementById("kg-canvas");
    if (!canvas) return;
    ctx = canvas.getContext("2d");

    window.addEventListener("resize", () => {
        resizeCanvas();
        drawGraph();
    });

    canvas.addEventListener("mousedown", (e) => {
        graphState.isDragging = true;
        graphState.dragStartX = e.clientX - graphState.panX;
        graphState.dragStartY = e.clientY - graphState.panY;
    });

    canvas.addEventListener("mousemove", (e) => {
        if (graphState.isDragging) {
            graphState.panX = e.clientX - graphState.dragStartX;
            graphState.panY = e.clientY - graphState.dragStartY;
            drawGraph();
        } else {
            handleCanvasHover(e);
        }
    });

    canvas.addEventListener("mouseup", () => { graphState.isDragging = false; });
    canvas.addEventListener("mouseleave", () => {
        graphState.isDragging = false;
        const tooltip = document.getElementById("node-tooltip");
        if (tooltip) tooltip.style.display = "none";
    });

    canvas.addEventListener("wheel", (e) => {
        e.preventDefault();
        const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
        graphState.zoom = Math.min(Math.max(graphState.zoom * zoomFactor, 0.3), 3.0);
        drawGraph();
    });
}

function resizeCanvas() {
    if (!canvas) return;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
}

async function loadKnowledgeGraph() {
    try {
        const resp = await fetch("/api/graph");
        if (!resp.ok) return;
        const data = await resp.json();
        currentGraphData = data;
        layoutGraphNodes(currentGraphData.nodes);
        drawGraph();
    } catch (err) {
        console.warn("Failed to load knowledge graph topology:", err);
    }
}

function layoutGraphNodes(nodes) {
    if (!nodes || nodes.length === 0) return;
    const width = (canvas && canvas.width) ? canvas.width : 1000;
    const height = (canvas && canvas.height) ? canvas.height : 650;
    const cx = width / 2;
    const cy = height / 2;

    const actors = nodes.filter(n => n.type === "ThreatActor");
    const others = nodes.filter(n => n.type !== "ThreatActor");

    const innerRadius = Math.min(width, height) * 0.22;
    actors.forEach((n, idx) => {
        const angle = (idx / actors.length) * 2 * Math.PI;
        n.x = cx + Math.cos(angle) * innerRadius;
        n.y = cy + Math.sin(angle) * innerRadius;
    });

    const outerRadius = Math.min(width, height) * 0.42;
    others.forEach((n, idx) => {
        const angle = (idx / others.length) * 2 * Math.PI + (idx % 2 * 0.1);
        const r = outerRadius + (idx % 4) * 22;
        n.x = cx + Math.cos(angle) * r;
        n.y = cy + Math.sin(angle) * r;
    });
}

function handleCanvasHover(e) {
    if (!canvas || !currentGraphData.nodes) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - graphState.panX) / graphState.zoom;
    const mouseY = (e.clientY - rect.top - graphState.panY) / graphState.zoom;

    let found = null;
    for (const node of currentGraphData.nodes) {
        const dx = node.x - mouseX;
        const dy = node.y - mouseY;
        const radius = node.type === "ThreatActor" ? 20 : 12;
        if (Math.sqrt(dx * dx + dy * dy) < radius) {
            found = node;
            break;
        }
    }

    const tooltip = document.getElementById("node-tooltip");
    if (found && tooltip) {
        graphState.hoveredNode = found;
        tooltip.style.display = "block";
        tooltip.style.left = `${e.clientX - rect.left + 15}px`;
        tooltip.style.top = `${e.clientY - rect.top + 15}px`;
        tooltip.innerHTML = `
            <div style="font-weight:700; color:${TYPE_COLORS[found.type] || '#fff'}; font-size:0.85rem;">${found.label}</div>
            <div style="font-size:0.7rem; color:#94a3b8; text-transform:uppercase;">${found.type} • Degree: ${found.degree || 0}</div>
            <div style="font-size:0.72rem; margin-top:0.3rem;">${found.description || "Active Knowledge Graph Entity"}</div>
        `;
    } else {
        graphState.hoveredNode = null;
        if (tooltip) tooltip.style.display = "none";
    }
    drawGraph();
}

function drawGraph() {
    if (!ctx || !canvas) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(graphState.panX, graphState.panY);
    ctx.scale(graphState.zoom, graphState.zoom);

    const trailNodeIds = new Set();
    const trailEdgeKeys = new Set();

    activeTrailHops.forEach(h => {
        trailNodeIds.add(h.source_id);
        trailNodeIds.add(h.target_id);
        trailEdgeKeys.add(`${h.source_id}->${h.target_id}`);
        trailEdgeKeys.add(`${h.target_id}->${h.source_id}`);
    });

    const nodeMap = new Map();
    (currentGraphData.nodes || []).forEach(n => nodeMap.set(n.id, n));

    (currentGraphData.edges || []).forEach(e => {
        const src = nodeMap.get(e.source);
        const tgt = nodeMap.get(e.target);
        if (!src || !tgt) return;

        const isTrailEdge = trailEdgeKeys.has(`${e.source}->${e.target}`);
        if (graphState.onlyTrail && !isTrailEdge) return;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);

        if (isTrailEdge) {
            ctx.strokeStyle = "#00f0ff";
            ctx.lineWidth = 3.5;
            ctx.shadowColor = "#00f0ff";
            ctx.shadowBlur = 12;
        } else {
            ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
            ctx.lineWidth = 1;
            ctx.shadowBlur = 0;
        }
        ctx.stroke();
    });

    ctx.shadowBlur = 0;

    (currentGraphData.nodes || []).forEach(n => {
        const isTrailNode = trailNodeIds.has(n.id) || trailNodeIds.has(n.label);
        const isSelected = graphState.selectedNodeId === n.id;
        if (graphState.onlyTrail && !isTrailNode) return;

        const radius = n.type === "ThreatActor" ? 18 : 10;
        const color = TYPE_COLORS[n.type] || "#ffffff";

        ctx.beginPath();
        ctx.arc(n.x, n.y, radius, 0, 2 * Math.PI);
        ctx.fillStyle = color;

        if (isTrailNode || isSelected) {
            ctx.shadowColor = isSelected ? "#f59e0b" : color;
            ctx.shadowBlur = 20;
            ctx.fill();
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 2.5;
            ctx.stroke();
        } else {
            ctx.shadowBlur = 0;
            ctx.fill();
        }

        ctx.shadowBlur = 0;
        ctx.fillStyle = (isTrailNode || isSelected) ? "#ffffff" : "#94a3b8";
        ctx.font = (isTrailNode || isSelected) ? "bold 11px Inter" : "9px Inter";
        ctx.textAlign = "center";
        ctx.fillText(n.label, n.x, n.y + radius + 12);
    });

    ctx.restore();
}

function resetGraphZoom() {
    graphState.zoom = 1.0;
    graphState.panX = 0;
    graphState.panY = 0;
    graphState.selectedNodeId = null;
    drawGraph();
}

// ==========================================
// 8. EMPIRICAL BENCHMARKS (Pre-computed Audit Results)
// ==========================================
function loadBenchmarkData() {
    const auditedSummary = {
        "Naive Vector-only RAG": {
            top1_accuracy: 58.33,
            multihop_reasoning_success: 44.44,
            hallucination_rate: 41.67,
            mrr: 0.6806
        },
        "Standalone GNN Classifier": {
            top1_accuracy: 66.67,
            multihop_reasoning_success: 66.67,
            hallucination_rate: 33.33,
            mrr: 0.7500
        },
        "NexusCTI Hybrid (GNN + RAG)": {
            top1_accuracy: 91.67,
            multihop_reasoning_success: 88.89,
            hallucination_rate: 8.33,
            mrr: 0.9583
        }
    };

    updateBenchmarkUI({ summary: auditedSummary });
}

function updateBenchmarkUI(data) {
    const summary = data.summary;
    if (!summary) return;

    const v = summary["Naive Vector-only RAG"];
    const g = summary["Standalone GNN Classifier"];
    const h = summary["NexusCTI Hybrid (GNN + RAG)"];

    if (document.getElementById("bm-top1-hybrid")) {
        document.getElementById("bm-top1-hybrid").innerText = `${h.top1_accuracy}%`;
        document.getElementById("bm-multihop-hybrid").innerText = `${h.multihop_reasoning_success}%`;
        document.getElementById("bm-halluc-hybrid").innerText = `${h.hallucination_rate}%`;
        document.getElementById("bm-mrr-hybrid").innerText = h.mrr.toFixed(4);
    }
}

// ==========================================
// 9. EVENT LISTENERS
// ==========================================
function setupEventListeners() {
    const runBtn = document.getElementById("btn-run-attribution");
    if (runBtn) {
        runBtn.addEventListener("click", () => {
            const query = document.getElementById("incident-query").value.trim();
            const anchor = document.getElementById("anchor-ioc").value.trim();
            if (query || anchor) {
                runAttribution(query, anchor);
            } else {
                showAlert("Please enter an indicator of compromise or incident narrative.", "warning");
            }
        });
    }

    const lookupBtn = document.getElementById("btn-lookup-ioc");
    if (lookupBtn) {
        lookupBtn.addEventListener("click", () => {
            const anchor = document.getElementById("anchor-ioc").value.trim();
            const query = document.getElementById("incident-query").value.trim();
            const target = anchor || query;
            lookupIndicatorDirect(target);
        });
    }

    const liveBmBtn = document.getElementById("btn-run-live-benchmark");
    if (liveBmBtn) {
        liveBmBtn.addEventListener("click", () => {
            alert(
                "Operational Architecture Note:\n\n" +
                "Production inference is strictly isolated from evaluation datasets to prevent label leakage.\n" +
                "The metrics displayed reflect the remediated 12-scenario empirical audit.\n" +
                "To run another full evaluation run, execute 'run_benchmark.py' in the audit environment."
            );
        });
    }

    const copyReportBtn = document.getElementById("btn-copy-report");
    if (copyReportBtn) {
        copyReportBtn.addEventListener("click", () => {
            if (currentMarkdownReport) {
                navigator.clipboard.writeText(currentMarkdownReport);
                copyReportBtn.innerText = "Copied to Clipboard!";
                setTimeout(() => { copyReportBtn.innerText = "Copy Markdown"; }, 2000);
            }
        });
    }

    const downloadReportBtn = document.getElementById("btn-download-report");
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener("click", () => {
            if (currentMarkdownReport) {
                const blob = new Blob([currentMarkdownReport], { type: "text/markdown" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `nexuscti_attribution_brief_${Date.now()}.md`;
                a.click();
            }
        });
    }

    const resetGraphBtn = document.getElementById("btn-reset-graph");
    if (resetGraphBtn) {
        resetGraphBtn.addEventListener("click", () => resetGraphZoom());
    }

    const highlightTrailBtn = document.getElementById("btn-highlight-trail");
    if (highlightTrailBtn) {
        highlightTrailBtn.addEventListener("click", () => {
            graphState.onlyTrail = !graphState.onlyTrail;
            highlightTrailBtn.innerText = graphState.onlyTrail ? "Show All Nodes" : "Highlight Current Trail";
            drawGraph();
        });
    }
}
