/* TinyBrother dashboard. No framework, no external dependency.
 * Every value coming from events is inserted with textContent or esc():
 * event fields are attacker-controlled (command lines, file names...). */
"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Info" };
// shape per severity so identity never relies on colour alone
const SEV_SHAPE = {
  critical: '<path d="M5 0 10 5 5 10 0 5z"/>',
  high: '<path d="M5 0 10 10 0 10z"/>',
  medium: '<circle cx="5" cy="5" r="5"/>',
  low: '<path d="M0 0h10L5 10z"/>',
  informational: '<rect x="1" y="1" width="8" height="8" rx="2"/>',
};
const TACTIC_LABEL = {
  "reconnaissance": "Reconnaissance", "resource-development": "Resource Dev.",
  "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
  "privilege-escalation": "Privilege Esc.", "stealth": "Stealth",
  "defense-impairment": "Defense Impairment", "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access", "discovery": "Discovery",
  "lateral-movement": "Lateral Movement", "collection": "Collection",
  "command-and-control": "Command & Control", "exfiltration": "Exfiltration",
  "impact": "Impact", "unknown": "Unmapped",
};
const STATUS_LABEL = { new: "New", acknowledged: "Acknowledged", closed: "Closed", false_positive: "False positive" };

const state = {
  range: localGet("tb.range") || "24h",
  severities: new Set(),
  status: "",
  q: "",
  technique: null,
  offset: 0,
  pageSize: 25,
  autoFallback: true,
};

// ---------------------------------------------------------------- helpers
function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } }
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => Number(n).toLocaleString();
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const sevColor = (s) => `var(--sev-${s})`;
const sevIcon = (s) => `<svg class="sev-icon" viewBox="0 0 10 10" fill="${sevColor(s)}" aria-hidden="true">${SEV_SHAPE[s] || ""}</svg>`;
const sevBadge = (s) => `<span class="sev-badge">${sevIcon(s)}${esc(SEV_LABEL[s] || s)}</span>`;

function fmtTime(iso, withDate = true) {
  const d = new Date(iso);
  if (isNaN(d)) return esc(iso);
  const opts = withDate
    ? { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }
    : { hour: "2-digit", minute: "2-digit" };
  return d.toLocaleString(undefined, opts);
}
function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

// ---------------------------------------------------------------- tooltip
const tip = $("tooltip");
function showTip(html, ev) {
  tip.innerHTML = html;
  tip.classList.add("show");
  moveTip(ev);
}
function moveTip(ev) {
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > innerHeight - 8) y = ev.clientY - h - pad;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hideTip() { tip.classList.remove("show"); }

// ---------------------------------------------------------------- KPIs
function renderKpis(s) {
  const ch = s.by_severity.critical + s.by_severity.high;
  const items = [
    { label: "Alerts", value: fmtN(s.total), sub: s.last_alert ? `last ${ago(s.last_alert)}` : "no alert in range" },
    { label: "Critical + High", value: fmtN(ch), sub: `${fmtN(s.by_severity.critical)} critical`, icon: ch ? "critical" : null },
    { label: "To triage", value: fmtN(s.open), sub: "status: new" },
    { label: "ATT&CK techniques", value: fmtN(s.distinct_techniques), sub: "observed in range" },
  ];
  $("kpis").innerHTML = items.map((k) =>
    `<div class="kpi"><div class="label">${k.icon ? sevIcon(k.icon) + " " : ""}${esc(k.label)}</div><div class="value">${k.value}</div><div class="sub">${esc(k.sub)}</div></div>`
  ).join("");
}

// ---------------------------------------------------------------- timeline (stacked bars)
function bucketLabel(seconds) {
  if (seconds < 3600) return `${seconds / 60}-minute buckets`;
  if (seconds < 86400) return `${seconds / 3600}-hour buckets`;
  if (seconds < 7 * 86400) return "daily buckets";
  if (seconds < 30 * 86400) return "weekly buckets";
  return "30-day buckets";
}
function renderTimeline(tl) {
  const el = $("timeline");
  $("bucket-hint").textContent = tl.buckets.length ? bucketLabel(tl.bucket_seconds) : "";
  const buckets = tl.buckets;
  const total = buckets.reduce((a, b) => a + SEVERITIES.reduce((x, s) => x + b[s], 0), 0);
  if (!total) { el.innerHTML = `<div class="empty">No alert in this range.</div>`; return; }

  const W = Math.max(el.clientWidth, 320), H = 220, m = { t: 8, r: 8, b: 24, l: 36 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const max = Math.max(...buckets.map((b) => SEVERITIES.reduce((x, s) => x + b[s], 0)));
  const nice = niceMax(max);
  const step = iw / buckets.length;
  const bw = Math.max(Math.min(step - 2, 28), 1.5);
  const y = (v) => m.t + ih - (v / nice) * ih;
  const stackOrder = ["informational", "low", "medium", "high", "critical"];

  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Alerts over time, stacked by severity">`;
  for (const v of [0, nice / 2, nice]) {
    svg += `<line class="grid-line" x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/>`;
    svg += `<text x="${m.l - 6}" y="${y(v) + 4}" text-anchor="end">${fmtN(Math.round(v))}</text>`;
  }
  buckets.forEach((b, i) => {
    const x = m.l + i * step + (step - bw) / 2;
    let acc = 0;
    const segs = stackOrder.filter((s) => b[s] > 0);
    segs.forEach((s, j) => {
      const y0 = y(acc), y1 = y(acc + b[s]);
      const h = Math.max(y0 - y1 - (j < segs.length - 1 ? 1 : 0), 1);
      const top = j === segs.length - 1;
      svg += top
        ? `<path d="${roundTop(x, y1, bw, h, Math.min(3, bw / 2))}" fill="${sevColor(s)}"/>`
        : `<rect x="${x}" y="${y1}" width="${bw}" height="${h}" fill="${sevColor(s)}"/>`;
      acc += b[s];
    });
    svg += `<rect class="hit" data-i="${i}" x="${m.l + i * step}" y="${m.t}" width="${step}" height="${ih}"/>`;
  });
  svg += `<line class="axis-line" x1="${m.l}" x2="${W - m.r}" y1="${m.t + ih}" y2="${m.t + ih}"/>`;
  const ticks = Math.min(6, buckets.length);
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k * (buckets.length - 1)) / Math.max(ticks - 1, 1));
    const d = new Date(buckets[i].t);
    let label;
    if (tl.bucket_seconds < 86400) label = fmtTime(buckets[i].t, false);
    else if (tl.bucket_seconds < 30 * 86400) label = d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    else label = d.toLocaleDateString(undefined, { month: "short", year: "numeric" });
    const x = m.l + i * step + step / 2;
    const anchor = k === 0 && ticks > 1 ? "start" : k === ticks - 1 && ticks > 1 ? "end" : "middle";
    const xa = anchor === "start" ? m.l : anchor === "end" ? W - m.r : x;
    svg += `<text x="${xa}" y="${H - 6}" text-anchor="${anchor}">${esc(label)}</text>`;
  }
  svg += `</svg>`;
  el.innerHTML = svg;
  el.querySelectorAll(".hit").forEach((r) => {
    const b = buckets[+r.dataset.i];
    const html = `<div class="tt-title">${esc(fmtTime(b.t))}</div>` +
      SEVERITIES.filter((s) => b[s]).map((s) => `<div class="tt-row"><span>${sevIcon(s)} ${SEV_LABEL[s]}</span><b>${fmtN(b[s])}</b></div>`).join("") ||
      `<div class="tt-row"><span>No alert</span></div>`;
    r.addEventListener("mousemove", (e) => showTip(html, e));
    r.addEventListener("mouseleave", hideTip);
  });
}
function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const f of [1, 2, 2.5, 5, 10]) if (f * p >= v) return f * p;
  return 10 * p;
}
function roundTop(x, y, w, h, r) {
  r = Math.min(r, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

// ---------------------------------------------------------------- severity + top rules
function renderSeverity(s) {
  const max = Math.max(1, ...SEVERITIES.map((k) => s.by_severity[k]));
  $("severity").innerHTML = `<div class="bars">${SEVERITIES.map((k) => `
    <div class="bar-row clickable" data-sev="${k}" title="Filter alerts: ${SEV_LABEL[k]}">
      <span class="label">${sevBadge(k)}</span>
      <div class="track"><div class="fill" style="width:${(100 * s.by_severity[k]) / max}%;background:${sevColor(k)}"></div></div>
      <span class="n">${fmtN(s.by_severity[k])}</span>
    </div>`).join("")}</div>`;
  $("severity").querySelectorAll(".bar-row").forEach((row) =>
    row.addEventListener("click", () => { state.severities = new Set([row.dataset.sev]); refreshAlerts(true); renderSevFilter(); scrollToAlerts(); }));

  const rules = s.top_rules;
  $("top-rules").innerHTML = rules.length
    ? `<div class="rules-list">${rules.map((r, i) => `
        <div class="rule-row" data-i="${i}" title="Search alerts for this rule">${sevIcon(r.severity)}<span class="t">${esc(r.title)}</span><span class="n">${fmtN(r.count)}</span></div>`).join("")}</div>`
    : `<div class="empty">—</div>`;
  $("top-rules").querySelectorAll(".rule-row").forEach((row) =>
    row.addEventListener("click", () => { state.q = rules[+row.dataset.i].title; $("search").value = state.q; refreshAlerts(true); scrollToAlerts(); }));
}

// ---------------------------------------------------------------- ATT&CK heatmap
function renderAttack(data) {
  const el = $("attack");
  const tactics = data.tactics;
  const maxAlerts = Math.max(0, ...tactics.flatMap((t) => t.techniques.map((x) => x.alerts)));
  const level = (n) => (n <= 0 || !maxAlerts ? 0 : Math.min(5, 1 + Math.floor((Math.log(n) / Math.log(maxAlerts + 1)) * 5)));
  $("attack-legend").innerHTML = `<span>0</span><span class="ramp">${[0, 1, 2, 3, 4, 5].map((l) => `<i style="background:var(--heat-${l})"></i>`).join("")}</span><span>${fmtN(maxAlerts)} alerts</span>` +
    (data.coverage_ready ? "" : `<span>· loading rule coverage…</span>`);
  if (!tactics.length) { el.innerHTML = `<div class="empty">No ATT&CK data yet.</div>`; return; }
  el.innerHTML = tactics.map((t) => {
    const hit = t.techniques.filter((x) => x.alerts > 0).length;
    return `<div class="tactic"><h3>${esc(TACTIC_LABEL[t.id] || t.id)}</h3>
      <div class="count">${hit} / ${t.techniques.length} triggered</div>
      <div class="cells">${t.techniques.map((x) => `
        <button class="cell h${level(x.alerts)} ${state.technique === x.id ? "active" : ""}" data-t="${esc(x.id)}" data-a="${x.alerts}" data-r="${x.rules}" data-ta="${esc(t.id)}">
          <span>${esc(x.id)}</span>${x.alerts ? `<b>${fmtN(x.alerts)}</b>` : ""}</button>`).join("")}</div></div>`;
  }).join("");
  el.querySelectorAll(".cell").forEach((c) => {
    const html = `<div class="tt-title">${esc(c.dataset.t)} · ${esc(TACTIC_LABEL[c.dataset.ta] || c.dataset.ta)}</div>
      <div class="tt-row"><span>Alerts in range</span><b>${fmtN(c.dataset.a)}</b></div>
      <div class="tt-row"><span>Rules covering it</span><b>${fmtN(c.dataset.r)}</b></div>`;
    c.addEventListener("mousemove", (e) => showTip(html, e));
    c.addEventListener("mouseleave", hideTip);
    c.addEventListener("click", () => {
      state.technique = state.technique === c.dataset.t ? null : c.dataset.t;
      el.querySelectorAll(".cell").forEach((o) => o.classList.toggle("active", o.dataset.t === state.technique));
      refreshAlerts(true);
      if (state.technique) scrollToAlerts();
    });
  });
}

// ---------------------------------------------------------------- alerts table
function renderSevFilter() {
  $("sev-filter").innerHTML = SEVERITIES.map((s) =>
    `<button class="chip" data-sev="${s}" aria-pressed="${state.severities.has(s)}">${sevIcon(s)}${SEV_LABEL[s]}</button>`).join("");
  $("sev-filter").querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => {
    const s = b.dataset.sev;
    state.severities.has(s) ? state.severities.delete(s) : state.severities.add(s);
    renderSevFilter();
    refreshAlerts(true);
  }));
}
function alertsQuery() {
  const p = new URLSearchParams({ range: state.range, limit: state.pageSize, offset: state.offset });
  state.severities.forEach((s) => p.append("severity", s));
  if (state.status) p.set("status", state.status);
  if (state.q) p.set("q", state.q);
  if (state.technique) p.set("technique", state.technique);
  return p;
}
function shortChannel(ch) {
  return ({ "Microsoft-Windows-Sysmon/Operational": "Sysmon", "Microsoft-Windows-PowerShell/Operational": "PowerShell",
    "Microsoft-Windows-Windows Defender/Operational": "Defender" })[ch] || (ch || "").replace(/^Microsoft-Windows-/, "");
}
function rowHtml(a) {
  return `<tr data-id="${a.id}">
    <td class="time">${esc(fmtTime(a.created_at))}</td>
    <td>${sevBadge(a.severity)}</td>
    <td class="rule">${esc(a.rule_title)}</td>
    <td>${a.techniques.map((t) => `<span class="tech">${esc(t)}</span>`).join("")}</td>
    <td class="src">${esc(shortChannel(a.channel))} ${esc(a.event_id ?? "")}</td>
    <td class="details">${esc(a.summary)}</td>
    <td><span class="status ${esc(a.status)}">${esc(STATUS_LABEL[a.status] || a.status)}</span></td>
  </tr>`;
}
async function refreshAlerts(reset) {
  if (reset) state.offset = 0;
  const data = await api(`/api/alerts?${alertsQuery()}`);
  const body = $("alerts-body");
  const html = data.items.map(rowHtml).join("");
  if (state.offset === 0) body.innerHTML = html || `<tr><td colspan="7" class="empty">No alert matches.</td></tr>`;
  else body.insertAdjacentHTML("beforeend", html);
  const shown = Math.min(state.offset + data.items.length, data.total);
  const filters = [state.severities.size && "severity", state.status && "status", state.q && "search", state.technique && state.technique].filter(Boolean);
  $("alerts-count").textContent = `${fmtN(shown)} of ${fmtN(data.total)}` + (filters.length ? ` · filtered by ${filters.join(", ")}` : "");
  $("clear-filters").hidden = !filters.length;
  $("load-more").hidden = shown >= data.total;
  body.querySelectorAll("tr[data-id]").forEach((tr) => { tr.onclick = () => openAlert(+tr.dataset.id); });
}
function scrollToAlerts() { $("alerts-body").closest(".card").scrollIntoView({ behavior: "smooth", block: "start" }); }

// ---------------------------------------------------------------- drawer
async function openAlert(id) {
  const a = await api(`/api/alerts/${id}`);
  const ev = a.event || {};
  const fields = Object.entries(ev.fields || {}).filter(([, v]) => v !== null && v !== "");
  const techLinks = a.techniques.map((t) =>
    `<a href="https://attack.mitre.org/techniques/${esc(t.replace(".", "/"))}/" target="_blank" rel="noopener noreferrer" class="tech">${esc(t)}</a>`).join("");
  $("drawer-content").innerHTML = `
    <div class="meta">${sevBadge(a.severity)}<span>${esc(fmtTime(a.created_at))}</span><span class="status ${esc(a.status)}">${esc(STATUS_LABEL[a.status] || a.status)}</span></div>
    <h3 id="d-title">${esc(a.rule_title)}</h3>
    ${a.description ? `<p class="desc">${esc(a.description)}</p>` : ""}
    <div class="meta">${techLinks}${a.tactics.map((t) => `<span class="tech">${esc(TACTIC_LABEL[t] || t)}</span>`).join("")}</div>
    <div class="actions">${Object.entries(STATUS_LABEL).map(([k, v]) =>
      `<button class="ghost" data-status="${k}" aria-pressed="${a.status === k}">${esc(v)}</button>`).join("")}</div>
    <h4>Event</h4>
    <table class="kv"><tbody>
      <tr><td>Channel</td><td>${esc(ev.channel)}</td></tr>
      <tr><td>Event ID</td><td>${esc(ev.event_id)}</td></tr>
      <tr><td>Computer</td><td>${esc(ev.computer)}</td></tr>
      <tr><td>Record ID</td><td>${esc(ev.record_id)}</td></tr>
    </tbody></table>
    <h4>Fields</h4>
    <table class="kv"><tbody>${fields.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</tbody></table>
    <h4>Rule</h4>
    <table class="kv"><tbody>
      <tr><td>ID</td><td>${esc(a.rule_id)}</td></tr>
      ${a.rule_path ? `<tr><td>File</td><td>${esc(a.rule_path)}</td></tr>` : ""}
    </tbody></table>`;
  $("drawer-content").querySelectorAll("[data-status]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/alerts/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: b.dataset.status }) });
    openAlert(id);
    refreshAll(false);
  }));
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-close").focus();
}
function closeDrawer() { $("drawer").classList.remove("open"); $("drawer").setAttribute("aria-hidden", "true"); }

// ---------------------------------------------------------------- orchestration
let lastStats = null, lastAttack = null;
async function refreshAll(resetAlerts = true) {
  try {
    const [s, a] = await Promise.all([api(`/api/stats?range=${state.range}`), api(`/api/attack?range=${state.range}`)]);
    if (state.autoFallback && s.total === 0 && state.range !== "all") {
      state.autoFallback = false;
      const all = await api("/api/stats?range=all");
      if (all.total > 0) { setRange("all"); return; }
    }
    state.autoFallback = false;
    lastStats = s; lastAttack = a;
    renderKpis(s); renderTimeline(s.timeline); renderSeverity(s); renderAttack(a);
    if (resetAlerts) await refreshAlerts(true);
    $("live").classList.remove("off");
    $("live-text").textContent = `updated ${new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
  } catch (e) {
    $("live").classList.add("off");
    $("live-text").textContent = "backend unreachable";
    console.error(e);
  }
}
function setRange(r) {
  state.range = r;
  localSet("tb.range", r);
  document.querySelectorAll("#range button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.range === r));
  refreshAll(true);
}

function init() {
  $("sev-legend").innerHTML = SEVERITIES.map((s) => `<span>${sevIcon(s)}${SEV_LABEL[s]}</span>`).join("");
  document.querySelectorAll("#range button").forEach((b) => b.addEventListener("click", () => { state.autoFallback = false; setRange(b.dataset.range); }));
  renderSevFilter();
  $("status-filter").addEventListener("change", (e) => { state.status = e.target.value; refreshAlerts(true); });
  let t;
  $("search").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value.trim(); refreshAlerts(true); }, 250); });
  $("clear-filters").addEventListener("click", () => {
    state.severities.clear(); state.status = ""; state.q = ""; state.technique = null;
    $("search").value = ""; $("status-filter").value = "";
    renderSevFilter(); if (lastAttack) renderAttack(lastAttack); refreshAlerts(true);
  });
  $("load-more").addEventListener("click", () => { state.offset += state.pageSize; refreshAlerts(false); });
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer").addEventListener("click", (e) => { if (e.target === $("drawer")) closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  let rt;
  addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => lastStats && renderTimeline(lastStats.timeline), 150); });
  api("/api/health").then((h) => { $("subtitle").textContent = `personal SOC · v${h.version} · 127.0.0.1`; }).catch(() => {});
  setRange(state.range);
  setInterval(() => { if (!document.hidden && !$("drawer").classList.contains("open")) refreshAll(state.offset === 0 && !state.q); }, 15000);
}
init();
