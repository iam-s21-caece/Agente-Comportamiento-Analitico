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
const REFRESH_MS = 10000; // auto-refresco cada 10 s

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

    renderStats(alerts);

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

// --------------------------------------------------------------- polling
let pollTimer = null;
function startPolling() {
    if (pollTimer) return;
    loadAlerts();
    pollTimer = setInterval(loadAlerts, REFRESH_MS);
}

document.getElementById("refreshBtn").addEventListener("click", loadAlerts);
