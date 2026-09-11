/* ================================================================
   Dashboard del Agente de Análisis de Seguridad — lógica de lectura.
   Solo lectura: hace fetch de alerts.jsonl y renderiza las alertas.
   No modifica al agente. Foco: exponer las alertas identificadas.
   ================================================================ */

"use strict";

// Ruta ABSOLUTA al archivo de alertas. Funciona con el server embebido del
// agente (que mapea esta URL a alerts.jsonl) y también con un http.server
// servido desde la raíz del agente (donde /data/alerts/ existe).
const ALERTS_URL = "/data/alerts/alerts.jsonl";
const REPORT_URL = "/data/validation/latest.json";       // último reporte de validación
const COMPARISON_URL = "/data/validation/comparison.json"; // comparativa (opcional)
const DIAGNOSTICS_URL = "/data/diagnostics.json";        // mensajes del agente
const REFRESH_MS = 10000; // auto-refresco cada 10 s
let currentView = "alerts";
let currentAlerts = [];    // últimas alertas leídas (para los parámetros en vivo)

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

// ------------------------------------------------------------------ tema
function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.getElementById("themeToggle").textContent = theme === "light" ? "☀️" : "🌙";
    localStorage.setItem("dash-theme", theme);
}
function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    applyTheme(current === "light" ? "dark" : "light");
}
applyTheme(localStorage.getItem("dash-theme") || "dark");
document.getElementById("themeToggle").addEventListener("click", toggleTheme);

// --------------------------------------------------------------- ingreso
// Gate cosmético: al enviar el formulario se oculta y se recuerda en la
// sesión para no repetirlo en cada refresco. NO es seguridad real.
const gate = document.getElementById("gate");
const app = document.getElementById("app");

function enterDashboard() {
    gate.classList.add("hidden");
    app.classList.remove("hidden");
    sessionStorage.setItem("dash-entered", "1");
    startPolling();
}

document.getElementById("gateForm").addEventListener("submit", (e) => {
    e.preventDefault();
    enterDashboard();
});

if (sessionStorage.getItem("dash-entered") === "1") {
    enterDashboard();
}

// -------------------------------------------------- tiempo de respuesta
// AUTOMÁTICO: lo mide el AGENTE (desde que la huella dispara hasta emitir la
// alerta) y viene estampado en cada alerta (alert.metrics.response_time_s). El
// dashboard solo lo muestra: por alerta y su promedio. Sin intervención manual.
function responseTime(alert) {
    const m = alert && alert.metrics;
    return m && typeof m.response_time_s === "number" ? m.response_time_s : null;
}

// --------------------------------------------------------------- fetch
/**
 * Parsea texto JSONL en una lista de objetos, ignorando líneas inválidas.
 * @param {string} text contenido del archivo .jsonl
 * @returns {Array<Object>} alertas parseadas
 */
function parseJsonl(text) {
    const alerts = [];
    for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
            alerts.push(JSON.parse(trimmed));
        } catch (_) {
            // Línea corrupta: se ignora, no rompe el render.
        }
    }
    return alerts;
}

async function loadAlerts() {
    const banner = document.getElementById("banner");
    const liveDot = document.getElementById("liveDot");
    try {
        // cache: no-store para ver siempre lo último que escribió el agente.
        const resp = await fetch(ALERTS_URL + "?t=" + Date.now(), { cache: "no-store" });

        // 404 = alerts.jsonl aún no existe: el agente no emitió ninguna alerta
        // todavía. Es un estado NORMAL (vigilando), no un error.
        if (resp.status === 404) {
            banner.classList.add("hidden");
            liveDot.className = "live-dot ok";
            render([]);
            document.getElementById("lastUpdated").textContent =
                "Actualizado " + new Date().toLocaleTimeString() + " · sin alertas aún";
            return;
        }

        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const text = await resp.text();
        const alerts = parseJsonl(text);

        banner.classList.add("hidden");
        liveDot.className = "live-dot ok";
        render(alerts);
    } catch (err) {
        // Los errores de lectura se exponen en el banner (parte "errores").
        liveDot.className = "live-dot err";
        banner.classList.remove("hidden");
        banner.textContent =
            "No se pudo leer las alertas (" + err.message + "). " +
            "Verificá que el dashboard se sirva desde la raíz del agente y que exista " +
            "data/alerts/alerts.jsonl.";
    }
    document.getElementById("lastUpdated").textContent =
        "Actualizado " + new Date().toLocaleTimeString();
}

// --------------------------------------------------------------- render
function render(alerts) {
    // Más recientes primero.
    alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    currentAlerts = alerts;  // disponible para los parámetros en vivo (Resultados)

    renderStats(alerts);
    // Si estamos en Resultados, refrescar los parámetros en vivo con cada alerta.
    if (currentView === "results") loadResults();

    const list = document.getElementById("alertsList");
    const empty = document.getElementById("emptyState");
    list.innerHTML = "";

    if (alerts.length === 0) {
        empty.classList.remove("hidden");
        return;
    }
    empty.classList.add("hidden");

    for (const alert of alerts) {
        list.appendChild(buildCard(alert));
    }
}

function renderStats(alerts) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let cveCount = 0;
    for (const a of alerts) {
        const sev = (a.severity || "info").toLowerCase();
        if (sev in counts) counts[sev]++;
        cveCount += (a.detected_cves || []).length;
    }
    document.getElementById("statTotal").textContent = alerts.length;
    document.getElementById("statCritical").textContent = counts.critical;
    document.getElementById("statHigh").textContent = counts.high;
    document.getElementById("statMedium").textContent = counts.medium;
    document.getElementById("statCves").textContent = cveCount;

    // Tiempo de respuesta PROMEDIO de las alertas posteriores al t0 marcado.
    const rts = alerts.map(responseTime).filter((v) => v !== null);
    const statRt = document.getElementById("statRt");
    if (rts.length) {
        statRt.textContent = fmtSeconds(rts.reduce((a, b) => a + b, 0) / rts.length);
    } else {
        statRt.textContent = "—";
    }
}

/**
 * Construye la tarjeta DOM de una alerta.
 * @param {Object} alert alerta según el esquema del agente
 * @returns {HTMLElement}
 */
function buildCard(alert) {
    const sev = (alert.severity || "info").toLowerCase();
    const card = el("div", "alert-card " + sev);

    // Cabecera: severidad, encadenado, id y timestamp.
    const top = el("div", "alert-top");
    const badges = el("div", "alert-badges");
    badges.appendChild(el("span", "sev-pill " + sev, sev));
    if (alert.chained) badges.appendChild(el("span", "chained-pill", "chained"));
    badges.appendChild(el("span", "alert-id", alert.alert_id || ""));
    // Tiempo de respuesta de ESTA alerta (desde el t0 del ataque marcado).
    const rt = responseTime(alert);
    if (rt !== null) {
        badges.appendChild(el("span", "alert-rt", "⏱ " + fmtSeconds(rt)));
    }
    top.appendChild(badges);
    top.appendChild(el("span", "alert-time", fmtTime(alert.timestamp)));
    card.appendChild(top);

    // Resumen (narrativa global del LLM).
    if (alert.summary) card.appendChild(el("p", "alert-summary", alert.summary));

    // CVEs detectadas.
    const cves = alert.detected_cves || [];
    if (cves.length) {
        const cveList = el("div", "cve-list");
        for (const cve of cves) cveList.appendChild(buildCve(cve));
        card.appendChild(cveList);
    }
    return card;
}

function buildCve(cve) {
    const item = el("div", "cve-item");

    const head = el("div", "cve-head");
    head.appendChild(el("span", "cve-id", cve.cve_id || "CVE"));
    const layer = (cve.affected_component && cve.affected_component.layer) || "";
    if (layer) head.appendChild(el("span", "layer-tag", layer));

    const conf = typeof cve.confidence === "number" ? cve.confidence : 0;
    const confWrap = el("span", "confidence");
    confWrap.appendChild(document.createTextNode("conf " + conf.toFixed(2)));
    const bar = el("span", "conf-bar");
    const fill = el("span", "conf-fill");
    fill.style.width = Math.round(conf * 100) + "%";
    bar.appendChild(fill);
    confWrap.appendChild(bar);
    head.appendChild(confWrap);
    item.appendChild(head);

    const mod = cve.affected_component && cve.affected_component.specific_module;
    if (mod) item.appendChild(el("p", "cve-module", "Módulo: " + mod));
    if (cve.narrative) item.appendChild(el("p", "cve-narrative", cve.narrative));

    return item;
}

// --------------------------------------------------------------- utils
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
}

/**
 * Formatea segundos de forma compacta: "12.3 s" o "1m 05s".
 * @param {number} s segundos
 * @returns {string}
 */
function fmtSeconds(s) {
    if (s < 60) return s.toFixed(1) + " s";
    const m = Math.floor(s / 60);
    const rem = Math.round(s % 60);
    return m + "m " + String(rem).padStart(2, "0") + "s";
}

// ------------------------------------------------- vista de RESULTADOS
// Sub-dashboard que LEE el reporte de validación (no recalcula) y lo expone.
// Se puebla a medida que se corren campañas mientras el agente acumula alertas.
function showView(view) {
    currentView = view;
    const isResults = view === "results";
    document.getElementById("stats").classList.toggle("hidden", isResults);
    document.getElementById("alertsView").classList.toggle("hidden", isResults);
    document.getElementById("resultsView").classList.toggle("hidden", !isResults);
    document.getElementById("viewAlertsBtn").classList.toggle("active", !isResults);
    document.getElementById("viewResultsBtn").classList.toggle("active", isResults);
    if (isResults) loadResults();
}

async function loadResults() {
    const banner = document.getElementById("resultsBanner");
    const meta = document.getElementById("resultsMeta");

    // Reporte de campaña (OPCIONAL: puede no existir hasta correr una validación).
    let report = null;
    try {
        const resp = await fetch(REPORT_URL + "?t=" + Date.now(), { cache: "no-store" });
        if (resp.ok) report = await resp.json();
        else if (resp.status !== 404) throw new Error("HTTP " + resp.status);
        banner.classList.add("hidden");
    } catch (err) {
        banner.classList.remove("hidden");
        banner.textContent = "No se pudo leer el reporte de validación (" + err.message + ").";
    }
    // Comparativa (opcional).
    let comparison = null;
    try {
        const cResp = await fetch(COMPARISON_URL + "?t=" + Date.now(), { cache: "no-store" });
        if (cResp.ok) comparison = await cResp.json();
    } catch (_) { /* opcional */ }

    const diagnostics = await loadDiagnostics();
    meta.textContent = report
        ? (report.campaign_id || "") + " · " + fmtTime(report.timestamp)
        : "parámetros en vivo · sin campaña aún";
    renderResults(report, comparison, diagnostics);
}

function renderResults(report, comparison, diagnostics) {
    const body = document.getElementById("resultsBody");
    body.innerHTML = "";

    // 1) Diagnóstico primero: lo más accionable (por qué algo no anda).
    if (diagnostics) body.appendChild(diagnosticsCard(diagnostics));

    // 2) Parámetros EN VIVO derivados de las alertas (se actualizan por alerta).
    body.appendChild(liveParamsCard(currentAlerts));

    // 3) Métricas rigurosas del reporte de validación (si ya se corrió una campaña).
    if (!report) {
        body.appendChild(_emptyResults());
        return;
    }
    const c = report.control || {}, a = report.autonomy || {}, k = report.knowledge || {}, lat = report.latency || {};

    body.appendChild(metricCard("Eficacia (autonomía)", [
        ["precision", a.precision], ["recall", a.recall], ["f1", a.f1],
        ["identificación", a.identification_accuracy],
        ["vínculo componente", a.component_linking_accuracy],
        ["coherencia razonamiento", a.reasoning_coherence_score],
    ]));
    body.appendChild(metricCard("Predecibilidad (control)", [
        ["terminación", c.termination_rate], ["crash rate", c.crash_rate],
        ["timeout rate", c.timeout_rate], ["fallo controlado", c.graceful_failure_rate],
        ["adherencia presupuesto", c.budget_adherence],
    ]));
    body.appendChild(metricCard("Conocimiento", [
        ["cobertura", k.coverage], ["rechazo desconocido", k.rejection_rate_on_unknown],
        ["falso reconocimiento", k.false_recognition_rate],
        ["consistencia", k.knowledge_consistency_score],
    ]));
    const q = report.quality || {};
    body.appendChild(metricCard(
        "Calidad (rúbrica manual 0-5)",
        Object.keys(q).length
            ? Object.keys(q).map((key) => [key, q[key]])
            : [["estado", "pendiente — evaluate-quality"]]
    ));
    body.appendChild(metricCard("Eficiencia (tokens · costo · tiempo)", [
        ["tokens totales", c.total_tokens],
        ["costo estimado", _usd(c.estimated_cost_usd)],
        ["resp. media", _sec(lat.mean_s)],
        ["resp. p50", _sec(lat.p50_s)],
        ["resp. máx", _sec(lat.max_s)],
    ]));
    const scn = report.scenarios || [];
    body.appendChild(metricCard("Escenarios", [
        ["total", scn.length],
        ["pass", scn.filter((s) => s.result === "pass").length],
        ["partial", scn.filter((s) => s.result === "partial").length],
        ["fail", scn.filter((s) => s.result === "fail").length],
    ]));
    if (comparison) body.appendChild(comparisonCard(comparison));
}

function liveParamsCard(alerts) {
    let tokens = 0, cost = 0;
    const rts = [], cves = {};
    for (const a of alerts) {
        const m = a.metrics || {};
        if (typeof m.tokens === "number") tokens += m.tokens;
        if (typeof m.cost_usd === "number") cost += m.cost_usd;
        if (typeof m.response_time_s === "number") rts.push(m.response_time_s);
        for (const cve of (a.detected_cves || [])) {
            const id = cve.cve_id || "?";
            cves[id] = (cves[id] || 0) + 1;
        }
    }
    const rows = [
        ["alertas", alerts.length],
        ["tokens (acum.)", tokens],
        ["costo (acum.)", _usd(cost)],
        ["resp. media", rts.length ? fmtSeconds(rts.reduce((x, y) => x + y, 0) / rts.length) : "—"],
        ["resp. máx", rts.length ? fmtSeconds(Math.max.apply(null, rts)) : "—"],
    ];
    for (const id of Object.keys(cves)) rows.push([id, cves[id]]);
    return metricCard("Parámetros en vivo (por alerta)", rows);
}

function diagnosticsCard(diag) {
    const card = el("div", "result-card result-card-wide");
    card.appendChild(el("h3", "result-title", "Diagnóstico del agente"));
    const items = (diag && diag.items) || [];
    if (!items.length) {
        card.appendChild(el("p", "result-note", "Sin mensajes de diagnóstico."));
        return card;
    }
    const list = el("div", "diag-list");
    for (const it of items) {
        const row = el("div", "diag-item diag-" + (it.level || "ok"));
        row.appendChild(el("span", "diag-dot", ""));
        const txt = el("div", "diag-text");
        txt.appendChild(el("div", "diag-msg", it.message || it.code));
        if (it.hint) txt.appendChild(el("div", "diag-hint", it.hint));
        row.appendChild(txt);
        list.appendChild(row);
    }
    card.appendChild(list);
    return card;
}

async function loadDiagnostics() {
    let diag = null;
    try {
        const d = await fetch(DIAGNOSTICS_URL + "?t=" + Date.now(), { cache: "no-store" });
        if (d.ok) diag = await d.json();
    } catch (_) { /* opcional */ }
    updateDiagBadge(diag);
    return diag;
}

function updateDiagBadge(diag) {
    const items = (diag && diag.items) || [];
    const problems = items.filter((i) => i.level === "error" || i.level === "warn").length;
    const btn = document.getElementById("viewResultsBtn");
    let badge = document.getElementById("diagBadge");
    if (problems > 0) {
        if (!badge) {
            badge = el("span", "diag-badge");
            badge.id = "diagBadge";
            btn.appendChild(badge);
        }
        badge.textContent = String(problems);
        badge.classList.remove("hidden");
    } else if (badge) {
        badge.classList.add("hidden");
    }
}

function metricCard(title, rows) {
    const card = el("div", "result-card");
    card.appendChild(el("h3", "result-title", title));
    const list = el("div", "result-rows");
    for (const [label, value] of rows) {
        const row = el("div", "result-row");
        row.appendChild(el("span", "result-label", label));
        row.appendChild(el("span", "result-value", _metric(value)));
        list.appendChild(row);
    }
    card.appendChild(list);
    return card;
}

function comparisonCard(cmp) {
    const card = el("div", "result-card result-card-wide");
    card.appendChild(el("h3", "result-title", "Comparativa determinista vs. LLM (aporte del modelo)"));
    const list = el("div", "result-rows");
    for (const m of (cmp.metrics || [])) {
        const row = el("div", "result-row");
        row.appendChild(el("span", "result-label", m.name));
        const delta = m.delta >= 0 ? "+" + m.delta : String(m.delta);
        row.appendChild(el("span", "result-value",
            _metric(m.nollm) + " → " + _metric(m.llm) + "  (" + delta + ")"));
        list.appendChild(row);
    }
    card.appendChild(list);
    card.appendChild(el("p", "result-note",
        "Costo: " + _usd(cmp.cost_llm_usd) + " (LLM) vs " + _usd(cmp.cost_nollm_usd) + " (sin LLM)."));
    return card;
}

function _emptyResults() {
    const d = el("div", "results-empty");
    d.appendChild(el("p", null,
        "Sin resultados aún — el agente los genera solo con su primera alerta. "
        + "Ejecutá una prueba (OIDC o DoS) y este panel se llena automáticamente."));
    return d;
}

function _metric(v) {
    if (v === null || v === undefined || v === "") return "—";
    if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(3);
    return String(v);
}
function _usd(v) { return (typeof v === "number") ? "$" + v.toFixed(6) : "—"; }
function _sec(v) { return (typeof v === "number") ? fmtSeconds(v) : "—"; }

document.getElementById("viewAlertsBtn").addEventListener("click", () => showView("alerts"));
document.getElementById("viewResultsBtn").addEventListener("click", () => showView("results"));

// --------------------------------------------------------------- polling
let pollTimer = null;
function startPolling() {
    if (pollTimer) return;
    loadAlerts();       // render() dispara loadResults() si estamos en Resultados
    loadDiagnostics();  // badge de diagnóstico desde el arranque
    pollTimer = setInterval(() => {
        loadAlerts();
        if (currentView !== "results") loadDiagnostics();  // mantener el badge al día
    }, REFRESH_MS);
}

document.getElementById("refreshBtn").addEventListener("click", () => {
    loadAlerts();
    loadDiagnostics();
});
