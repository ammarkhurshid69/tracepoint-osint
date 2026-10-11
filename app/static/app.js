"use strict";
/* Tracepoint frontend: plain JavaScript, no framework, no inline handlers (CSP-safe). */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : "never");
const SEVRANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/* Turns ANY error payload into readable text. This is the fix for "[object Object]":
   FastAPI used to send validation errors as an array of objects; String(array) gives "[object Object]". */
function formatError(data, fallback = "Request failed") {
  if (data == null) return fallback;
  if (typeof data === "string") return data || fallback;
  if (data instanceof Error) return data.message || fallback;
  const d = data.detail ?? data.message ?? data.error ?? data;
  if (typeof d === "string") return d || fallback;
  if (Array.isArray(d)) {
    const parts = d.map((e) => (typeof e === "string" ? e : e && e.msg ? `${(e.loc || []).slice(1).join(".") || "input"}: ${e.msg}` : JSON.stringify(e)));
    return parts.join("; ") || fallback;
  }
  try { return JSON.stringify(d); } catch { return fallback; }
}

async function request(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const k = sessionStorage.getItem("tp_key");
  if (k) headers["X-API-Key"] = k;
  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  let res;
  try { res = await fetch(path, Object.assign({}, opts, { headers })); }
  catch (e) { throw new Error("Cannot reach the server. Make sure the terminal running Tracepoint is still open."); }
  return res;
}
async function api(path, opts = {}) {
  const res = await request(path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON body */ }
  if (res.status === 401) { $("#keyDlg").showModal(); throw new Error("This server needs an API key. Enter it in the box that just opened."); }
  if (!res.ok) throw new Error(formatError(data, `Server returned HTTP ${res.status}`));
  return data;
}
async function download(path, name) {
  const res = await request(path);
  if (!res.ok) { let d = null; try { d = await res.json(); } catch (e) {} throw new Error(formatError(d, `Download failed (HTTP ${res.status})`)); }
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

let current = null, pollTimer = null;

function msg(text, ok = false) {
  const m = $("#formMsg");
  m.hidden = !text; m.textContent = text || ""; m.className = "msg" + (ok ? " ok" : "");
}

/* ---------- list + stats ---------- */
async function refreshStats() {
  const s = await api("/api/stats");
  const cell = (n, l) => `<div class="stat"><b>${esc(n)}</b><span>${esc(l)}</span></div>`;
  $("#stats").innerHTML = cell(s.total, "Cases") + cell(s.running, "Running") + cell(s.by_risk.High || 0, "High risk") +
    cell(s.by_risk.Critical || 0, "Critical") + cell(s.findings, "Findings") + cell(s.monitored, "Monitored");
  const b = $("#alertBadge"); b.hidden = !s.unread_alerts; b.textContent = s.unread_alerts;
}
async function refreshList() {
  const q = $("#filter").value.trim();
  const rows = await api("/api/investigations?q=" + encodeURIComponent(q));
  $("#list").innerHTML = rows.length ? rows.map((r) => `
    <li data-id="${r.id}" class="${r.id === current ? "sel" : ""}">
      <span class="score l-${esc(r.risk_label)}">${r.status === "completed" ? r.risk_score : "..."}</span>
      <div class="grow"><div class="t">${esc(r.target)}</div>
      <div class="m">${esc(r.target_type)} · ${esc(r.status)}${r.monitoring ? " · monitored" : ""}</div></div></li>`).join("")
    : `<li class="empty" style="cursor:default">Nothing yet. Search something above.</li>`;
}

/* ---------- case detail ---------- */
function renderEmpty() {
  $("#detail").innerHTML = `<div class="empty"><h3>Start with a search</h3>
    <p>Paste a domain, IP address, URL, e-mail, username or file hash. Tracepoint works out what it is, asks the public sources that apply, and shows what each one said.</p>
    <p>Try one:</p><div class="chips">${["example.com", "8.8.8.8", "octocat", "d41d8cd98f00b204e9800998ecf8427e", "https://example.com"].map((x) => `<button class="chip" data-fill="${esc(x)}">${esc(x)}</button>`).join("")}</div></div>`;
}
function renderCase(d) {
  const busy = d.status === "queued" || d.status === "running";
  const groups = {};
  (d.findings || []).forEach((f) => (groups[f.source] = groups[f.source] || []).push(f));
  const order = Object.keys(groups).sort((a, b) => {
    const w = (g) => Math.min(...groups[g].map((f) => SEVRANK[f.severity]));
    return w(a) - w(b) || a.localeCompare(b);
  });
  const fhtml = order.map((src) => `<section class="group"><h4>${esc(src)}<small>${groups[src].length} item${groups[src].length > 1 ? "s" : ""}</small></h4>` +
    groups[src].sort((a, b) => SEVRANK[a.severity] - SEVRANK[b.severity]).map((f) => `
      <div class="f"><div class="sev s-${esc(f.severity)}">${esc(f.severity)}</div>
      <div><span class="ti">${esc(f.title)}</span><span class="prov ${esc(f.provenance)}">${esc(f.provenance)}</span>
      ${f.detail ? `<pre>${esc(f.detail)}</pre>` : ""}</div></div>`).join("") + `</section>`).join("");
  const how = d.summary_source.startsWith("ai:") ? `AI-written summary (${esc(d.summary_source.slice(3))}). Check it against the evidence below.` : "Automatic rule-based summary (no AI used).";
  $("#detail").innerHTML = `
    <div class="dh"><div><div class="kind">${esc(d.target_type)}</div><h3>${esc(d.target)}</h3></div>
      <div class="big l-${esc(d.risk_label)}"><b>${busy ? "..." : d.risk_score}</b><span>${busy ? esc(d.status) : esc(d.risk_label) + " · heuristic"}</span></div></div>
    ${busy ? `<progress max="100" value="${d.progress}"></progress><p class="hint">Querying sources... ${d.progress}%</p>` : ""}
    ${d.status === "failed" ? `<p class="msg">Run failed: ${esc(d.error || "unknown error")}</p>` : ""}
    <div class="actions">
      <button data-act="rerun" ${busy ? "disabled" : ""}>Re-run</button>
      <button class="ghost" data-act="monitor">${d.monitoring ? "Stop monitoring" : "Monitor every 15 min"}</button>
      <button class="ghost" data-act="csv" ${d.finding_count ? "" : "disabled"}>CSV</button>
      <button class="ghost" data-act="pdf">PDF report</button>
      <button class="ghost danger" data-act="delete">Delete</button></div>
    ${d.summary && !busy ? `<div class="summary">${esc(d.summary)}<small>${how}</small></div>` : ""}
    <div class="meta"><span>Last run: ${esc(fmt(d.last_run_at))}</span><span>Runs: ${d.run_count}</span><span>Monitoring: ${d.monitoring ? "on" : "off"}</span>
      <span>Keyed sources: ${d.use_keyed ? "allowed" : "off"}</span></div>
    ${fhtml || (busy ? "" : `<p class="empty">No findings stored.</p>`)}`;
}
async function openCase(id) {
  current = id;
  clearTimeout(pollTimer);
  try {
    const d = await api("/api/investigations/" + id);
    renderCase(d);
    await Promise.all([refreshList(), refreshStats()]);
    if (d.status === "queued" || d.status === "running") pollTimer = setTimeout(() => openCase(id), 1200);
  } catch (e) { $("#detail").innerHTML = `<p class="msg">${esc(formatError(e))}</p>`; }
}

/* ---------- events ---------- */
$("#searchForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#goBtn"); msg("");
  const target = $("#target").value.trim();
  if (!target) return msg("Type something to investigate.");
  btn.disabled = true; btn.textContent = "Starting...";
  try {
    const d = await api("/api/investigations", { method: "POST", body: JSON.stringify({
      target, target_type: $("#type").value, monitoring: $("#optMon").checked, use_keyed: $("#optKeyed").checked }) });
    msg(`Investigating ${d.target_type} ${d.target}...`, true);
    await openCase(d.id);
  } catch (e) { msg(formatError(e)); }
  finally { btn.disabled = false; btn.textContent = "Investigate"; }
});
let detTimer;
$("#target").addEventListener("input", () => {
  clearTimeout(detTimer);
  detTimer = setTimeout(async () => {
    const v = $("#target").value.trim(), h = $("#detected");
    if (!v) { h.textContent = "Type or paste something. The kind is detected automatically."; return; }
    try {
      const r = await api("/api/detect?q=" + encodeURIComponent(v));
      h.textContent = r.ok ? `Detected: ${r.label}` : r.message;
    } catch (e) { h.textContent = formatError(e); }
  }, 250);
});
$("#filter").addEventListener("input", () => refreshList().catch(() => {}));
$("#list").addEventListener("click", (e) => { const li = e.target.closest("li[data-id]"); if (li) openCase(+li.dataset.id); });
$("#detail").addEventListener("click", async (e) => {
  const chip = e.target.closest("[data-fill]");
  if (chip) { $("#target").value = chip.dataset.fill; $("#target").dispatchEvent(new Event("input")); $("#target").focus(); return; }
  const b = e.target.closest("[data-act]"); if (!b || current == null) return;
  const id = current;
  try {
    if (b.dataset.act === "rerun") { await api(`/api/investigations/${id}/rerun`, { method: "POST" }); await openCase(id); }
    else if (b.dataset.act === "monitor") {
      const d = await api("/api/investigations/" + id);
      await api(`/api/investigations/${id}/monitoring`, { method: "PATCH", body: JSON.stringify({ enabled: !d.monitoring }) }); await openCase(id);
    }
    else if (b.dataset.act === "csv") await download(`/api/investigations/${id}/export.csv`, `investigation_${id}.csv`);
    else if (b.dataset.act === "pdf") await download(`/api/investigations/${id}/export.pdf`, `investigation_${id}.pdf`);
    else if (b.dataset.act === "delete" && confirm("Delete this case and all its findings?")) {
      await api("/api/investigations/" + id, { method: "DELETE" }); current = null; renderEmpty(); await Promise.all([refreshList(), refreshStats()]);
    }
  } catch (err) { msg(formatError(err)); }
});

/* tabs */
async function showTab(name) {
  ["cases", "alerts", "sources"].forEach((t) => ($("#view-" + t).hidden = t !== name));
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === name));
  try {
    if (name === "alerts") await loadAlerts();
    if (name === "sources") await loadSources();
  } catch (e) { msg(formatError(e)); }
}
$("#tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (b) showTab(b.dataset.tab); });
async function loadAlerts() {
  const rows = await api("/api/alerts");
  $("#alertList").innerHTML = rows.length ? rows.map((a) => `<li class="${a.is_read ? "" : "unread"}">
    <div><div class="s-${esc(a.severity)} sev">${esc(a.severity)}</div><div class="hint">${esc(fmt(a.created_at))}</div></div>
    <div><a data-case="${a.investigation_id}">${esc(a.target)}</a><div>${esc(a.message)}</div></div></li>`).join("")
    : `<li class="empty" style="display:block">No alerts yet. Turn on monitoring for a case; alerts appear when a re-check finds a change.</li>`;
}
$("#alertList").addEventListener("click", (e) => { const a = e.target.closest("a[data-case]"); if (a) { showTab("cases"); openCase(+a.dataset.case); } });
$("#readAll").addEventListener("click", async () => { try { await api("/api/alerts/read", { method: "POST" }); await loadAlerts(); await refreshStats(); } catch (e) { msg(formatError(e)); } });
async function loadSources() {
  const p = await api("/api/providers");
  const row = (n, kind, ok, env, desc) => `<tr><td>${esc(n)}</td><td>${esc(desc)}</td><td class="${ok ? "st-ready" : "st-off"}">${ok ? (kind === "free" ? "ready" : "key present") : "needs key"}${!ok && env ? `<br><code>${esc(env)}</code>` : ""}</td></tr>`;
  $("#srcTable").innerHTML = `<tr><th>Source</th><th>What it provides</th><th>Status</th></tr>` +
    p.providers.map((x) => row(x.name, x.kind, x.configured, x.env_var, x.description + " · for " + x.types.join(", "))).join("") +
    row("OpenAI summary", "key", p.ai.configured, p.ai.env_var, "Optional written summary based only on collected evidence");
  const m = await api("/api/monitoring");
  $("#monInfo").innerHTML = `Interval: every ${Math.round(m.interval_seconds / 60)} minutes. Active jobs: ${m.jobs.length}.` +
    (m.jobs.length ? "<br>" + m.jobs.map((j) => `${esc(j.id)}, next run ${esc(fmt(j.next_run))}`).join("<br>") : "") +
    "<br>Monitoring only runs while the server window stays open.";
}

/* API key dialog */
$("#keyBtn").addEventListener("click", () => $("#keyDlg").showModal());
$("#keyForm").addEventListener("close", () => {});
$("#keySave").addEventListener("click", () => { sessionStorage.setItem("tp_key", $("#keyInput").value.trim()); setTimeout(() => init(), 50); });
$("#keyDlg").addEventListener("click", (e) => { if (e.target.value === "cancel") $("#keyDlg").close(); });

async function init() {
  renderEmpty();
  try { await Promise.all([refreshList(), refreshStats()]); } catch (e) { msg(formatError(e)); }
  setInterval(() => { if (!document.hidden) refreshStats().catch(() => {}); }, 20000);
}
if (typeof module !== "undefined") module.exports = { formatError, esc };
else init();
