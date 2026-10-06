/* TinyBrother dashboard. No framework, no external dependency.
 * Every value coming from events is escaped (esc) before insertion:
 * event fields are attacker-controlled (command lines, file names...). */
"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Info" };
// a distinct shape per severity, so identity never relies on colour alone
const SEV_SHAPE = {
  critical: '<path d="M5 0 10 5 5 10 0 5z"/>',
  high: '<path d="M5 .5 10 9.5H0z"/>',
  medium: '<circle cx="5" cy="5" r="4.5"/>',
  low: '<path d="M0 .5h10L5 9.5z"/>',
  informational: '<rect x="1" y="1" width="8" height="8" rx="2"/>',
};
const STATUS_LABEL = { new: "New", acknowledged: "Acknowledged", closed: "Closed", false_positive: "False positive" };
const ICONS = {
  alerts: '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
  inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  warn: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  radar: '<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  filter: '<path d="M10 20a1 1 0 0 0 .553.895l2 1A1 1 0 0 0 14 21v-7a2 2 0 0 1 .517-1.341L21.74 4.67A1 1 0 0 0 21 3H3a1 1 0 0 0-.742 1.67l7.225 7.989A2 2 0 0 1 10 14z"/>',
  ext: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
};
const icon = (name, cls = "icon") => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;

const state = {
  range: localGet("tb.range") || "24h",
  showCovered: localGet("tb.showCovered") === "1",
  severities: new Set(),
  status: "",
  q: "",
  technique: null,
  offset: 0,
  pageSize: 20,
  total: 0,
  autoFallback: true,
};
let ATTACK = { techniques: {}, tactics: {} };

// ---------------------------------------------------------------- helpers
function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } }
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => Number(n).toLocaleString();
const sevColor = (s) => `var(--sev-${s})`;
const sevIcon = (s) => `<svg class="sev-icon" viewBox="0 0 10 10" fill="${sevColor(s)}" aria-hidden="true">${SEV_SHAPE[s] || ""}</svg>`;
const sevLabel = (s) => `<span class="sev">${sevIcon(s)}${esc(SEV_LABEL[s] || s)}</span>`;
const tech = (id) => ATTACK.techniques[id] || null;
const techName = (id) => tech(id)?.name || id;
const tacticName = (id) => ATTACK.tactics[id] || (id === "unknown" ? "Unmapped" : id);
function techFullName(id) {
  const t = tech(id);
  if (!t) return id;
  return t.parent ? `${t.parent}: ${t.name}` : t.name;
}
function techUrl(id) { return tech(id)?.url || `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`; }

function fmtTime(iso, withDate = true) {
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  return withDate
    ? d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 60) return `${Math.floor(s / 86400)} days ago`;
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

// ---------------------------------------------------------------- tooltip
const tip = $("tooltip");
function bindTip(el, html) {
  el.addEventListener("mousemove", (e) => { tip.innerHTML = html(); tip.classList.add("show"); moveTip(e); });
  el.addEventListener("mouseleave", () => tip.classList.remove("show"));
}
function moveTip(ev) {
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > innerHeight - 8) y = ev.clientY - h - pad;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}

// ---------------------------------------------------------------- live sensor
const CHANNEL_LABEL = {
  "Security": "Security",
  "System": "System",
  "Microsoft-Windows-Sysmon/Operational": "Sysmon",
  "Microsoft-Windows-PowerShell/Operational": "PowerShell",
  "Microsoft-Windows-Windows Defender/Operational": "Microsoft Defender",
  "Windows PowerShell": "Windows PowerShell (classic)",
};
const CHANNEL_STATUS = {
  ok: ["ok", "Monitored"], not_found: ["warn", "Not installed"], access_denied: ["bad", "Access denied"],
  error: ["bad", "Error"], pending: ["ghost", "Starting…"],
};
// `code` spans in server messages -> <code>, after escaping
const richText = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

function renderSensor(st) {
  const live = $("live");
  live.classList.remove("off", "idle");
  const stateText = {
    running: "Monitoring this machine",
    stopped: "Monitoring stopped",
    stale: "Monitoring stopped unexpectedly",
    never: "Monitoring not started",
  }[st.state];
  if (st.state === "running") {
    $("live-text").textContent = `Live · last event ${ago(st.last_event_at)}`;
  } else {
    live.classList.add(st.state === "never" ? "idle" : "off");
    $("live-text").textContent = stateText;
  }

  $("warnings").innerHTML = (st.warnings || []).map((w) => {
    const danger = w.code === "not_running" || w.code === "never_started";
    const title = { not_running: "Live monitoring is off", never_started: "Live monitoring has never run",
      sysmon_missing: "Sysmon is not installed", not_admin: "Not running as administrator" }[w.code] || "Warning";
    return `<div class="callout ${danger ? "danger" : "warning"}" role="alert">${icon("warn")}<div class="title">${esc(title)}</div><div class="desc">${richText(w.message)}</div></div>`;
  }).join("");

  const el = $("sensor");
  if (st.state === "never") {
    el.innerHTML = `<div class="card-header"><div><h2 class="card-title">Live monitoring</h2>
      <p class="card-description">The dashboard only shows <b>alerts</b>: events that match one of your Sigma rules. Normal activity (logons, unlocks…) is analysed but not displayed.</p></div>${icon("radar")}</div>
      <div class="card-content" style="display:block"><div class="sensor-state"><span class="state-dot never"></span>${esc(stateText)}</div>
      <p class="muted" style="margin:8px 0 0">Run <code>tinybrother watch</code> in an administrator terminal; this panel will turn green within a few seconds.</p></div>`;
    return;
  }
  const facts = [
    ["Running since", st.state === "running" ? ago(st.started_at).replace(" ago", "") : "—"],
    ["Last event received", st.last_event_at ? ago(st.last_event_at) : "none yet"],
    ["Last heartbeat", ago(st.heartbeat_at)],
    ["Events analysed", fmtN(st.events_total)],
    ["Alerts raised", fmtN(st.alerts_total)],
    ["Rules loaded", fmtN(st.rules_loaded ?? 0)],
  ];
  el.innerHTML = `
    <div class="card-header"><div><h2 class="card-title">Live monitoring</h2>
      <p class="card-description">Every event is checked against your Sigma rules; only matches become alerts. Normal activity such as logging in or unlocking the screen is analysed but not shown.</p></div>${icon("radar")}</div>
    <div class="card-content">
      <div>
        <div class="sensor-state"><span class="state-dot ${esc(st.state)}"></span>${esc(stateText)}
          ${st.hostname ? `<span class="badge ghost">${esc(st.hostname)}</span>` : ""}
          ${st.is_admin === true ? '<span class="badge ok">Administrator</span>' : st.is_admin === false ? '<span class="badge bad">Not administrator</span>' : ""}</div>
        <div class="facts">${facts.map(([k, v]) => `<div class="fact"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("")}</div>
      </div>
      <div class="channels">${(st.channels || []).map((c) => {
        const [cls, label] = CHANNEL_STATUS[c.status] || ["ghost", c.status];
        const sub = c.status === "ok" ? `${fmtN(c.events)} events${c.last_event_at ? ` · ${ago(c.last_event_at)}` : ""}` : "";
        return `<div class="channel" title="${esc(c.name)}"><span class="name">${esc(CHANNEL_LABEL[c.name] || c.name)}</span><span class="sub">${esc(sub)}</span><span class="badge ${cls}">${esc(label)}</span></div>`;
      }).join("")}</div>
    </div>`;
}
let lastAlertsTotal = null;
async function refreshSensor() {
  try {
    const st = await api("/api/status");
    renderSensor(st);
    // a new alert arrived: refresh the charts and the table right away
    if (lastAlertsTotal !== null && st.alerts_total !== lastAlertsTotal) refreshAll(state.offset === 0 && !state.q);
    lastAlertsTotal = st.alerts_total ?? null;
  }
  catch { $("live").classList.add("off"); $("live-text").textContent = "Dashboard backend unreachable"; }
}

// ---------------------------------------------------------------- KPIs
function renderKpis(s) {
  const ch = s.by_severity.critical + s.by_severity.high;
  const items = [
    { title: "Alerts", icon: "alerts", value: fmtN(s.total), hint: s.last_alert ? `Last alert ${ago(s.last_alert)}` : "No alert in this range" },
    { title: "Critical & high", icon: "shield", value: fmtN(ch), hint: `${fmtN(s.by_severity.critical)} critical · ${fmtN(s.by_severity.high)} high` },
    { title: "To triage", icon: "inbox", value: fmtN(s.open), hint: "Alerts with status New" },
    { title: "ATT&CK techniques", icon: "target", value: fmtN(s.distinct_techniques), hint: "Distinct techniques observed" },
  ];
  $("kpis").innerHTML = items.map((k) => `
    <div class="card kpi">
      <div class="card-header"><h3>${esc(k.title)}</h3>${icon(k.icon)}</div>
      <div class="card-content"><div class="value">${k.value}</div><div class="hint">${esc(k.hint)}</div></div>
    </div>`).join("");
}

// ---------------------------------------------------------------- timeline
function bucketLabel(sec) {
  if (sec < 3600) return `${sec / 60}-minute intervals`;
  if (sec < 86400) return sec === 3600 ? "Hourly" : `${sec / 3600}-hour intervals`;
  if (sec < 7 * 86400) return "Daily";
  if (sec < 30 * 86400) return "Weekly";
  return "30-day intervals";
}
function renderTimeline(tl) {
  const el = $("timeline");
  const buckets = tl.buckets;
  const sum = (b) => SEVERITIES.reduce((x, s) => x + b[s], 0);
  const total = buckets.reduce((a, b) => a + sum(b), 0);
  $("bucket-hint").textContent = total ? `${bucketLabel(tl.bucket_seconds)} · stacked by severity` : "Stacked by severity";
  if (!total) { el.innerHTML = `<div class="empty">No alert in this range. Try “All time”.</div>`; return; }

  const W = Math.max(el.clientWidth, 300), H = 300, m = { t: 8, r: 4, b: 26, l: 34 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const nice = niceMax(Math.max(...buckets.map(sum)));
  const step = iw / buckets.length;
  const bw = Math.max(Math.min(step * 0.7, 32), 2);
  const y = (v) => m.t + ih - (v / nice) * ih;
  const order = ["informational", "low", "medium", "high", "critical"];

  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Alerts over time, stacked by severity">`;
  for (const v of [0, nice / 4, nice / 2, (3 * nice) / 4, nice]) {
    svg += `<line class="grid-line" x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/>`;
    svg += `<text x="${m.l - 8}" y="${y(v) + 4}" text-anchor="end">${fmtN(Math.round(v))}</text>`;
  }
  buckets.forEach((b, i) => {
    const x = m.l + i * step + (step - bw) / 2;
    const segs = order.filter((s) => b[s] > 0);
    let acc = 0;
    segs.forEach((s, j) => {
      const y0 = y(acc), y1 = y(acc + b[s]);
      const last = j === segs.length - 1;
      const h = Math.max(y0 - y1 - (last ? 0 : 1.5), 1);
      svg += last
        ? `<path d="${roundTop(x, y1, bw, h, Math.min(4, bw / 2))}" fill="${sevColor(s)}"/>`
        : `<rect x="${x}" y="${y1}" width="${bw}" height="${h}" fill="${sevColor(s)}"/>`;
      acc += b[s];
    });
  });
  const ticks = Math.min(6, buckets.length);
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k * (buckets.length - 1)) / Math.max(ticks - 1, 1));
    const d = new Date(buckets[i].t);
    let label;
    if (tl.bucket_seconds < 86400) label = fmtTime(buckets[i].t, false);
    else if (tl.bucket_seconds < 30 * 86400) label = d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    else label = d.toLocaleDateString(undefined, { month: "short", year: "numeric" });
    const anchor = ticks > 1 && k === 0 ? "start" : ticks > 1 && k === ticks - 1 ? "end" : "middle";
    const x = anchor === "start" ? m.l : anchor === "end" ? W - m.r : m.l + i * step + step / 2;
    svg += `<text x="${x}" y="${H - 6}" text-anchor="${anchor}">${esc(label)}</text>`;
  }
  buckets.forEach((b, i) => { svg += `<rect class="hit" data-i="${i}" x="${m.l + i * step}" y="${m.t}" width="${step}" height="${ih}"/>`; });
  el.innerHTML = svg + `</svg>`;
  el.querySelectorAll(".hit").forEach((r) => {
    const b = buckets[+r.dataset.i];
    bindTip(r, () => `<div class="tt-title">${esc(fmtTime(b.t))}</div>` +
      (SEVERITIES.filter((s) => b[s]).map((s) => `<div class="tt-row"><span class="sev">${sevIcon(s)}${SEV_LABEL[s]}</span><b>${fmtN(b[s])}</b></div>`).join("") ||
        `<div class="tt-row"><span>No alert</span></div>`));
  });
}
function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const f of [1, 2, 2.5, 4, 5, 10]) if (f * p >= v) return f * p;
  return 10 * p;
}
function roundTop(x, y, w, h, r) {
  r = Math.min(r, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

// ---------------------------------------------------------------- severity + top rules
function renderSeverity(s) {
  const max = Math.max(1, ...SEVERITIES.map((k) => s.by_severity[k]));
  $("severity").innerHTML = `<div class="sev-bars">${SEVERITIES.map((k) => `
    <div class="sev-bar" data-sev="${k}" role="button" tabindex="0" aria-label="Filter alerts: ${SEV_LABEL[k]}">
      ${sevLabel(k)}
      <div class="track"><div class="fill" style="width:${(100 * s.by_severity[k]) / max}%;background:${sevColor(k)}"></div></div>
      <span class="n">${fmtN(s.by_severity[k])}</span>
    </div>`).join("")}</div>`;
  $("severity").querySelectorAll(".sev-bar").forEach((row) => {
    const go = () => { state.severities = new Set([row.dataset.sev]); renderSevFilter(); refreshAlerts(true); scrollToAlerts(); };
    row.addEventListener("click", go);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  });
  const rules = s.top_rules.slice(0, 7);
  $("top-rules").innerHTML = rules.length
    ? `<div class="rule-list">${rules.map((r, i) => `
        <div class="rule-item" data-i="${i}" role="button" tabindex="0">${sevIcon(r.severity)}<span class="t">${esc(r.title)}</span><span class="n">${fmtN(r.count)}</span></div>`).join("")}</div>`
    : `<div class="empty">No rule triggered.</div>`;
  $("top-rules").querySelectorAll(".rule-item").forEach((row) => {
    const r = rules[+row.dataset.i];
    bindTip(row, () => `<div class="tt-title">${esc(r.title)}</div><div class="tt-row"><span class="sev">${sevIcon(r.severity)}${SEV_LABEL[r.severity]}</span><b>${fmtN(r.count)} alerts</b></div>`);
    row.addEventListener("click", () => { state.q = r.title; $("search").value = r.title; refreshAlerts(true); scrollToAlerts(); });
  });
}

// ---------------------------------------------------------------- ATT&CK matrix
let lastAttack = null;
function renderAttack(data) {
  lastAttack = data;
  const el = $("attack");
  const all = data.tactics.map((t) => ({ ...t, techniques: t.techniques.filter((x) => state.showCovered || x.alerts > 0) }))
    .filter((t) => t.techniques.length);
  const maxAlerts = Math.max(0, ...data.tactics.flatMap((t) => t.techniques.map((x) => x.alerts)));
  const level = (n) => (n <= 0 || !maxAlerts ? 0 : Math.min(5, 1 + Math.floor((Math.log(n) / Math.log(maxAlerts + 1)) * 5)));
  $("heat-legend").innerHTML = `<span>Fewer</span>${[1, 2, 3, 4, 5].map((l) => `<i style="background:var(--heat-${l})"></i>`).join("")}<span>More alerts</span>`;
  const coveredIds = new Set(data.tactics.flatMap((t) => t.techniques.map((x) => x.id)));
  const seenIds = new Set(data.tactics.flatMap((t) => t.techniques.filter((x) => x.alerts > 0).map((x) => x.id)));
  $("attack-desc").textContent = data.coverage_ready
    ? `${seenIds.size} technique${seenIds.size === 1 ? "" : "s"} detected in this period, out of ${fmtN(coveredIds.size)} your rules can detect. Click a technique to show only its alerts.`
    : "Techniques seen in your alerts, by tactic. Rule coverage is loading…";
  if (!all.length) {
    el.innerHTML = `<div class="empty">${state.showCovered ? "No ATT&CK data yet." : "No technique triggered in this range. Enable “Show covered techniques” to see your coverage."}</div>`;
    return;
  }
  el.innerHTML = all.map((t) => {
    const hit = t.techniques.filter((x) => x.alerts > 0).length;
    return `<div class="tactic">
      <div class="tactic-head"><h4>${esc(tacticName(t.id))}</h4><span>${hit} triggered${state.showCovered ? ` · ${t.techniques.length} covered` : ""}</span></div>
      <div class="tech-list">${t.techniques.map((x) => `
        <button class="tech h${level(x.alerts)} ${state.technique === x.id ? "active" : ""}" aria-pressed="${state.technique === x.id}" data-t="${esc(x.id)}" data-ta="${esc(t.id)}" data-a="${x.alerts}" data-r="${x.rules}">
          <span class="name">${state.technique === x.id ? icon("check", "icon check") : ""}${esc(techName(x.id))}</span>
          ${x.alerts ? `<span class="count">${fmtN(x.alerts)}</span>` : ""}
          <span class="id">${esc(x.id)}</span>
          ${x.triggered_by && x.triggered_by.length ? `<span class="via" title="${esc(x.triggered_by.map((r) => r.title).join("\n"))}">via ${esc(x.triggered_by[0].title)}${x.triggered_by.length > 1 ? ` +${x.triggered_by.length - 1}` : ""}</span>` : ""}
        </button>`).join("")}</div></div>`;
  }).join("");
  const byKey = {};
  data.tactics.forEach((t) => t.techniques.forEach((x) => { byKey[`${t.id}|${x.id}`] = x; }));
  el.querySelectorAll(".tech").forEach((c) => {
    const id = c.dataset.t, info = tech(id);
    const rules = byKey[`${c.dataset.ta}|${id}`]?.triggered_by || [];
    bindTip(c, () => `<div class="tt-title">${esc(techFullName(id))}</div>
      <div class="tt-sub">${esc(id)} · ${esc(tacticName(c.dataset.ta))}</div>
      <div class="tt-row"><span>Alerts in range</span><b>${fmtN(c.dataset.a)}</b></div>
      <div class="tt-row"><span>Rules covering it</span><b>${fmtN(c.dataset.r)}</b></div>
      ${rules.length ? `<div class="tt-label">Triggered by</div>${rules.map((r) => `<div class="tt-row"><span class="tt-rule">${esc(r.title)}</span><b>${fmtN(r.alerts)}</b></div>`).join("")}` : ""}
      ${info?.description ? `<p>${esc(info.description)}</p>` : ""}
      <p class="tt-hint">${state.technique === id ? "Click to remove the filter" : "Click to show only these alerts"}</p>`);
    c.addEventListener("click", () => {
      tip.classList.remove("show");
      setTechnique(state.technique === id ? null : id);
      if (state.technique) scrollToAlerts();
    });
  });
}

function setTechnique(id) {
  state.technique = id;
  if (lastAttack) renderAttack(lastAttack);
  refreshAlerts(true);
}

// ---------------------------------------------------------------- alerts table
function renderSevFilter() {
  $("sev-filter").innerHTML = SEVERITIES.map((s) =>
    `<button class="btn outline sm" data-sev="${s}" aria-pressed="${state.severities.has(s)}">${sevIcon(s)}${SEV_LABEL[s]}</button>`).join("");
  $("sev-filter").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
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
const techChip = (id) => `<span class="tech-chip" title="${esc(techFullName(id))}">${esc(techName(id))}<span class="id">${esc(id)}</span></span>`;
const statusBadge = (s) => `<span class="badge status-badge ${esc(s)}">${esc(STATUS_LABEL[s] || s)}</span>`;
function rowHtml(a) {
  // show the most specific techniques (sub-techniques hide their parent)
  const ids = a.techniques.filter((t) => !a.techniques.some((o) => o !== t && o.startsWith(t + ".")));
  return `<tr data-id="${a.id}">
    <td class="time">${esc(fmtTime(a.created_at))}</td>
    <td>${sevLabel(a.severity)}</td>
    <td class="rule">${esc(a.rule_title)}</td>
    <td><div class="tech-chips">${ids.map(techChip).join("") || '<span class="muted">—</span>'}</div></td>
    <td class="src">${esc(shortChannel(a.channel))} · ${esc(a.event_id ?? "")}</td>
    <td class="details">${esc(a.summary)}</td>
    <td>${statusBadge(a.status)}</td>
  </tr>`;
}
async function refreshAlerts(reset) {
  if (reset) state.offset = 0;
  const data = await api(`/api/alerts?${alertsQuery()}`);
  state.total = data.total;
  $("alerts-body").innerHTML = data.items.map(rowHtml).join("") ||
    `<tr><td colspan="7"><div class="empty">No alert matches these filters.</div></td></tr>`;
  $("alerts-body").querySelectorAll("tr[data-id]").forEach((tr) => { tr.onclick = () => openAlert(+tr.dataset.id); });
  const from = data.total ? state.offset + 1 : 0, to = Math.min(state.offset + data.items.length, data.total);
  const filters = [state.severities.size && "severity", state.status && "status", state.q && "search",
    state.technique && `${techName(state.technique)} (${state.technique})`].filter(Boolean);
  $("alerts-count").textContent = filters.length ? `Filtered by ${filters.join(", ")}` : "All alerts in the selected range, newest first.";
  $("page-info").textContent = `Showing ${fmtN(from)}–${fmtN(to)} of ${fmtN(data.total)}`;
  $("prev").disabled = state.offset === 0;
  $("next").disabled = to >= data.total;
  $("clear-filters").hidden = !filters.length;
  $("tech-filter").innerHTML = state.technique
    ? `<button class="btn outline sm filter-chip" id="tech-chip" title="Remove this filter">${icon("filter")}Technique: ${esc(techName(state.technique))} <span class="mono muted">${esc(state.technique)}</span>${icon("x")}</button>`
    : "";
  if (state.technique) $("tech-chip").addEventListener("click", () => setTechnique(null));
}
function scrollToAlerts() { $("alerts-card").scrollIntoView({ behavior: "smooth", block: "start" }); }

// ---------------------------------------------------------------- sheet (alert detail)
async function openAlert(id) {
  const a = await api(`/api/alerts/${id}`);
  const ev = a.event || {};
  const fields = Object.entries(ev.fields || {}).filter(([, v]) => v !== null && v !== "");
  const techs = a.techniques.map((tid) => {
    const t = tech(tid);
    return `<div class="tech-detail">
      <div class="row"><span class="title">${esc(t ? t.name : tid)}</span><span class="badge secondary mono">${esc(tid)}</span></div>
      ${t?.parent ? `<span class="parent">Sub-technique of ${esc(t.parent)}</span>` : ""}
      ${t?.description ? `<p>${esc(t.description)}</p>` : ""}
      <a href="${esc(techUrl(tid))}" target="_blank" rel="noopener noreferrer">View on attack.mitre.org ${icon("ext")}</a>
    </div>`;
  }).join("");
  $("sheet-panel").innerHTML = `
    <div class="sheet-header">
      <button class="btn ghost sm icon-only close" id="sheet-close" aria-label="Close">${icon("x")}</button>
      <div class="meta">${sevLabel(a.severity)}${statusBadge(a.status)}<span class="muted">${esc(fmtTime(a.created_at))}</span></div>
      <h2 id="sheet-title">${esc(a.rule_title)}</h2>
      ${a.description ? `<p>${esc(a.description)}</p>` : ""}
    </div>
    <div class="sheet-body">
      <div>
        <h3>Triage</h3>
        <div class="actions">${Object.entries(STATUS_LABEL).map(([k, v]) =>
          `<button class="btn outline sm" data-status="${k}" aria-pressed="${a.status === k}">${esc(v)}</button>`).join("")}</div>
      </div>
      <div>
        <h3>MITRE ATT&amp;CK${a.tactics.length ? ` · ${a.tactics.map((t) => esc(tacticName(t))).join(", ")}` : ""}</h3>
        <div style="display:grid;gap:8px">${techs || '<span class="muted">No technique tagged on this rule.</span>'}</div>
      </div>
      <div>
        <h3>Event</h3>
        <table class="kv"><tbody>
          <tr><td>Channel</td><td>${esc(ev.channel)}</td></tr>
          <tr><td>Event ID</td><td>${esc(ev.event_id)}</td></tr>
          <tr><td>Computer</td><td>${esc(ev.computer)}</td></tr>
          <tr><td>Record ID</td><td>${esc(ev.record_id)}</td></tr>
        </tbody></table>
      </div>
      <div>
        <h3>Fields</h3>
        <table class="kv"><tbody>${fields.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</tbody></table>
      </div>
      <div>
        <h3>Rule</h3>
        <table class="kv"><tbody>
          <tr><td>ID</td><td>${esc(a.rule_id)}</td></tr>
          ${a.rule_path ? `<tr><td>File</td><td>${esc(a.rule_path)}</td></tr>` : ""}
        </tbody></table>
      </div>
    </div>`;
  $("sheet-close").addEventListener("click", closeSheet);
  $("sheet-panel").querySelectorAll("[data-status]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/alerts/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: b.dataset.status }) });
    openAlert(id);
    refreshAll(false);
    refreshAlerts(false);
  }));
  $("sheet").classList.add("open");
  $("sheet").setAttribute("aria-hidden", "false");
  $("sheet-close").focus();
}
function closeSheet() { $("sheet").classList.remove("open"); $("sheet").setAttribute("aria-hidden", "true"); }

// ---------------------------------------------------------------- orchestration
let lastStats = null;
async function refreshAll(resetAlerts = true) {
  try {
    const [s, a] = await Promise.all([api(`/api/stats?range=${state.range}`), api(`/api/attack?range=${state.range}`)]);
    if (state.autoFallback && s.total === 0 && state.range !== "all") {
      state.autoFallback = false;
      const all = await api("/api/stats?range=all");
      if (all.total > 0) { setRange("all"); return; }
    }
    state.autoFallback = false;
    lastStats = s;
    renderKpis(s); renderTimeline(s.timeline); renderSeverity(s); renderAttack(a);
    if (resetAlerts) await refreshAlerts(true);
  } catch (e) {
    $("live").classList.add("off");
    $("live-text").textContent = "Dashboard backend unreachable";
    console.error(e);
  }
}
function setRange(r) {
  state.range = r;
  localSet("tb.range", r);
  document.querySelectorAll("#range button").forEach((b) => b.setAttribute("aria-selected", b.dataset.range === r));
  refreshAll(true);
}

async function init() {
  $("sev-legend").innerHTML = SEVERITIES.map((s) => sevLabel(s)).join("");
  document.querySelectorAll("#range button").forEach((b) => b.addEventListener("click", () => { state.autoFallback = false; setRange(b.dataset.range); }));
  renderSevFilter();
  $("show-covered").checked = state.showCovered;
  $("show-covered").addEventListener("change", (e) => { state.showCovered = e.target.checked; localSet("tb.showCovered", state.showCovered ? "1" : "0"); if (lastAttack) renderAttack(lastAttack); });
  $("status-filter").addEventListener("change", (e) => { state.status = e.target.value; refreshAlerts(true); });
  let t;
  $("search").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value.trim(); refreshAlerts(true); }, 250); });
  $("clear-filters").addEventListener("click", () => {
    state.severities.clear(); state.status = ""; state.q = ""; state.technique = null;
    $("search").value = ""; $("status-filter").value = "";
    renderSevFilter(); setTechnique(null);
  });
  $("prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.pageSize); refreshAlerts(false); });
  $("next").addEventListener("click", () => { state.offset += state.pageSize; refreshAlerts(false); });
  $("sheet-overlay").addEventListener("click", closeSheet);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });
  let rt;
  addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => lastStats && renderTimeline(lastStats.timeline), 150); });

  try { ATTACK = await api("/api/techniques"); } catch { /* names are optional */ }
  api("/api/health").then((h) => {
    $("header-meta").textContent = `personal SOC · v${h.version}` + (ATTACK.attack_version ? ` · ATT&CK v${ATTACK.attack_version}` : "");
  }).catch(() => {});
  refreshSensor();
  setInterval(() => { if (!document.hidden) refreshSensor(); }, 5000);
  setRange(state.range);
  setInterval(() => {
    if (!document.hidden && !$("sheet").classList.contains("open")) refreshAll(state.offset === 0 && !state.q);
  }, 15000);
}
init();
