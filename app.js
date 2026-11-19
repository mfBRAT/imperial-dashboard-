/* Imperial bot dashboard - "live terminal" (2026-11-19). Static page, client-side decrypted; no data lives in this file.
   data.enc.json = {v, kdf:"PBKDF2-SHA256", iter, salt, iv, ct} (base64), AES-256-GCM over
   {generatedAt: epoch ms, data: <dashboard_data.py snapshot>, info: {...}}.
   The key derived from the password is kept in memory and sessionStorage (this tab only). Never localStorage. */
"use strict";
const REFRESH_MS = 5 * 60 * 1000;        // <- how often the page re-fetches data.enc.json (change here)
const STALE_MS = 20 * 60 * 1000;          // snapshot older than this gets a STALE badge
const SS_KEY = "imperialDash.key.v2", OLD_LS_KEY = "imperialDash.key.v1";
const TZ = "America/Los_Angeles";
try { localStorage.removeItem(OLD_LS_KEY); } catch (_) {}   // older page version could remember the key on the device; drop it

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const ub64 = (u) => btoa(String.fromCharCode(...new Uint8Array(u)));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let KEY = null, KEY_SALT = null, PAYLOAD = null, LAST_FETCH = null, FETCH_ERR = null, NEXT_FETCH = 0, timer = null, busy = false;
const UI = { showChurn: false, range: "7d", openDetails: new Set() };

/* ---------- crypto / fetch ---------- */
async function fetchEnvelope() {
  const r = await fetch("data.enc.json?t=" + Date.now(), { cache: "no-store" });
  if (!r.ok) throw new Error("data.enc.json HTTP " + r.status);
  const e = await r.json();
  if (e.v !== 1 || e.kdf !== "PBKDF2-SHA256" || !e.iter || !e.salt || !e.iv || !e.ct) throw new Error("unrecognized data format");
  return e;
}
async function deriveKey(pw, env) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(env.salt), iterations: env.iter },
    base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
}
async function decrypt(key, env) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv) }, key, b64(env.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function saveSession(key, env) {
  try { sessionStorage.setItem(SS_KEY, JSON.stringify({ salt: env.salt, iter: env.iter, k: ub64(await crypto.subtle.exportKey("raw", key)) })); } catch (_) {}
}
async function loadSession(env) {
  try {
    const s = JSON.parse(sessionStorage.getItem(SS_KEY) || "null");
    if (!s || s.salt !== env.salt || s.iter !== env.iter) return null;
    return await crypto.subtle.importKey("raw", b64(s.k), { name: "AES-GCM" }, true, ["decrypt"]);
  } catch (_) { return null; }
}
function clearSession() { try { sessionStorage.removeItem(SS_KEY); } catch (_) {} }

function showLock(msg) {
  KEY = null; PAYLOAD = null; if (timer) clearInterval(timer); timer = null;
  $("app").hidden = true; $("app").innerHTML = ""; $("lock").hidden = false;
  $("lockerr").textContent = msg || ""; $("pw").value = ""; $("unlock").disabled = false; $("unlock").textContent = "UNLOCK";
}
async function unlockWith(key, env) {
  PAYLOAD = await decrypt(key, env);   // throws OperationError on wrong password / tamper
  KEY = key; KEY_SALT = env.salt; LAST_FETCH = Date.now(); FETCH_ERR = null; NEXT_FETCH = Date.now() + REFRESH_MS;
  await saveSession(key, env);
  $("lock").hidden = true; $("app").hidden = false; render();
  if (!timer) timer = setInterval(tick, 1000);
}
function tick() { if (Date.now() >= NEXT_FETCH) refresh(); else updateClocks(); }
async function refresh() {
  if (busy || !KEY) return; busy = true; NEXT_FETCH = Date.now() + REFRESH_MS;
  try {
    const env = await fetchEnvelope();
    if (env.salt !== KEY_SALT) { clearSession(); busy = false; return showLock("The dashboard password was changed. Enter the new password."); }
    PAYLOAD = await decrypt(KEY, env); LAST_FETCH = Date.now(); FETCH_ERR = null;
  } catch (e) {
    FETCH_ERR = (e && e.name === "OperationError") ? "could not decrypt the latest data (password changed?)" : String(e && e.message || e);
  }
  busy = false; render();
}
$("lockform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("pw").value;
  if (!window.crypto || !crypto.subtle) { $("lockerr").textContent = "This browser can't decrypt here (needs HTTPS and WebCrypto)."; return; }
  $("unlock").disabled = true; $("unlock").textContent = "DECRYPTING…"; $("lockerr").textContent = "";
  try { const env = await fetchEnvelope(); await unlockWith(await deriveKey(pw, env), env); }
  catch (e) {
    $("unlock").disabled = false; $("unlock").textContent = "UNLOCK";
    $("lockerr").textContent = e && e.name === "OperationError" ? "Wrong password." : "Couldn't load the data: " + (e && e.message || e);
  } finally { $("pw").value = ""; }
});
document.addEventListener("visibilitychange", () => { if (!document.hidden && KEY && Date.now() - (LAST_FETCH || 0) > 60000) refresh(); });

/* ---------- formatting ---------- */
const isN = (v) => typeof v === "number" && isFinite(v);
const toN = (v) => (v === "" || v == null ? null : isFinite(+v) ? +v : null);
const usd = (v, d = 2) => !isN(v) ? "–" : (v < 0 ? "−$" : "$") + Math.abs(v).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
const susd = (v, d = 2) => !isN(v) ? "–" : (v > 0 ? "+" : v < 0 ? "−" : "") + "$" + Math.abs(v).toFixed(d);
const px = (v) => !isN(v) ? "–" : Math.abs(v) >= 1000 ? v.toLocaleString("en-US", { maximumFractionDigits: 1 }) : String(+v.toPrecision(5));
const pct = (v, d = 2) => !isN(v) ? "–" : (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(d) + "%";
const tone = (v) => !isN(v) ? "" : v > 0 ? "pos" : v < 0 ? "neg" : "";
const dur = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return s < 90 ? s + "s" : s < 5400 ? Math.round(s / 60) + "m" : s < 172800 ? (s / 3600).toFixed(1) + "h" : Math.round(s / 86400) + "d"; };
const ago = (ms) => (ms < 60000 ? "just now" : dur(ms) + " ago");
const mmss = (ms) => { const s = Math.max(0, Math.ceil(ms / 1000)); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); };
const fmtT = (ms, o) => new Date(ms).toLocaleString("en-US", Object.assign({ timeZone: TZ }, o));
const hm = (ms) => fmtT(ms, { hour: "numeric", minute: "2-digit" });
const tsLa = (s) => { // "2026-11-19 05:07:28 PST" -> epoch ms
  const m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) (P[SD]T)/.exec(s || ""); if (!m) return null;
  return Date.UTC(+m[1], m[2] - 1, +m[3], +m[4] + (m[7] === "PDT" ? 7 : 8), +m[5], +m[6]);
};

/* ---------- equity chart (SVG) ---------- */
function equityChart(D) {
  const start = isN(D.start) ? D.start : null, now = Date.now();
  const span = { "24h": 864e5, "7d": 7 * 864e5, all: Infinity }[UI.range];
  const cut = now - span;
  let real = (D.pnlCurve || []).filter((p) => isN(p[0]) && isN(p[1])).map(([t, c]) => [t, (start ?? 0) + c]);
  let samp = (D.equityHistory || []).filter((p) => isN(p[0]) && isN(p[1]));
  if (isN(D.equity) && PAYLOAD?.generatedAt) samp = samp.length && samp[samp.length - 1][0] >= PAYLOAD.generatedAt - 60000 ? samp : [...samp, [PAYLOAD.generatedAt, D.equity]];
  // carry the realized line to "now" so it reads as a step to the present
  if (real.length) {
    const before = real.filter((p) => p[0] < cut); real = real.filter((p) => p[0] >= cut);
    if (before.length && isFinite(cut)) real.unshift([cut, before[before.length - 1][1]]);
    real.push([now, real.length ? real[real.length - 1][1] : before[before.length - 1][1]]);
  }
  samp = samp.filter((p) => p[0] >= cut);
  const all = [...real, ...samp];
  if (all.length < 2) return `<div class="empty">Not enough history yet for this range.</div>`;
  const W = 760, H = 240, L = 46, R = 10, T = 12, B = 22;
  const t0 = Math.min(...all.map((p) => p[0])), t1 = Math.max(...all.map((p) => p[0]));
  const vals = all.map((p) => p[1]); if (start !== null) vals.push(start);
  let lo = Math.min(...vals), hi = Math.max(...vals); const pad = (hi - lo) * 0.08 || 1; lo -= pad; hi += pad;
  const x = (t) => L + ((t - t0) / ((t1 - t0) || 1)) * (W - L - R), y = (v) => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
  const step = (pts) => pts.map((p, i) => (i ? `H${x(p[0]).toFixed(1)}V${y(p[1]).toFixed(1)}` : `M${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`)).join("");
  const line = (pts) => pts.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + "," + y(p[1]).toFixed(1)).join("");
  let g = "";
  for (let i = 0; i <= 4; i++) { const v = lo + ((hi - lo) * i) / 4, yy = y(v); g += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="#1c2530"/><text x="${L - 6}" y="${yy + 3}" text-anchor="end">$${v.toFixed(0)}</text>`; }
  for (let i = 0; i <= 4; i++) { const t = t0 + ((t1 - t0) * i) / 4; const lab = t1 - t0 > 2 * 864e5 ? fmtT(t, { month: "short", day: "numeric" }) : hm(t); g += `<text x="${x(t)}" y="${H - 6}" text-anchor="${i === 0 ? "start" : i === 4 ? "end" : "middle"}">${esc(lab)}</text>`; }
  if (start !== null) g += `<line x1="${L}" x2="${W - R}" y1="${y(start)}" y2="${y(start)}" stroke="#4a5868" stroke-dasharray="3 4"/><text x="${W - R}" y="${y(start) - 4}" text-anchor="end">start ${usd(start, 0)}</text>`;
  if (isN(D.killLine) && D.killLine > lo && D.killLine < hi) g += `<line x1="${L}" x2="${W - R}" y1="${y(D.killLine)}" y2="${y(D.killLine)}" stroke="#ff5c6c88" stroke-dasharray="2 3"/>`;
  let body = "";
  if (real.length > 1) {
    const p = step(real);
    body += `<path d="${p}V${H - B}H${x(real[0][0])}Z" fill="url(#gfill)" opacity=".55"/><path d="${p}" fill="none" stroke="#a78bfa" stroke-width="1.6"/>`;
  }
  if (samp.length > 1) body += `<path d="${line(samp)}" fill="none" stroke="#2ee59d" stroke-width="2"/>`;
  if (samp.length) { const l = samp[samp.length - 1]; body += `<circle cx="${x(l[0])}" cy="${y(l[1])}" r="3.5" fill="#2ee59d"><animate attributeName="r" values="3;6;3" dur="2s" repeatCount="indefinite"/></circle>`; }
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Equity chart"><defs><linearGradient id="gfill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#a78bfa" stop-opacity=".35"/><stop offset="1" stop-color="#a78bfa" stop-opacity="0"/></linearGradient></defs>${g}${body}</svg>
  <div class="legend"><span><i style="background:#2ee59d"></i>equity (sampled each publish${samp.length < 3 ? ", building up" : ""})</span><span><i style="background:#a78bfa"></i>start + realized P&amp;L (trades.csv)</span>${isN(D.killLine) ? `<span><i style="background:#ff5c6c"></i>kill line ${usd(D.killLine, 0)}</span>` : ""}</div>`;
}

/* ---------- sections ---------- */
function statusInfo(D) {
  const p = D.pill || "?";
  const cls = p === "Running" ? "ok" : p === "Halted" ? "bad" : p === "Stalled" ? "warn" : "mute";
  const label = p === "Running" ? "HEALTHY" : p.toUpperCase();
  return { cls, label };
}
function kpis(D) {
  const st = statusInfo(D), capUsed = isN(D.dayPnl) && isN(D.dayCap) && D.dayPnl < 0 ? Math.min(100, (D.dayPnl / D.dayCap) * 100) : 0;
  const ret = isN(D.equity) && isN(D.start) && D.start ? ((D.equity - D.start) / D.start) * 100 : null;
  const k = (label, v, s, cls = "", extra = "") => `<div class="kpi ${extra}"><div class="k">${label}</div><div class="v ${cls}">${v}</div><div class="s">${s}</div></div>`;
  return `<div class="kpis">
    ${k("Equity", usd(D.equity), `${pct(ret)} since start ${usd(D.start, 0)}`, "", "wide")}
    ${k("Day P&amp;L", susd(D.dayPnl), `cap ${usd(D.dayCap, 0)} · ${capUsed.toFixed(0)}% used`, tone(D.dayPnl))}
    ${k("Cum P&amp;L", susd(D.cumPnl), `${esc(D.dayTrades ?? 0)} trade${D.dayTrades === 1 ? "" : "s"} today`, tone(D.cumPnl))}
    ${k("Unrealized", susd(sumUpnl(D)), `${(D.positions || []).length}/${esc(D.limits?.maxPos ?? 3)} slots`, tone(sumUpnl(D)))}
    ${k("Bot", `<span class="tag ${st.cls}"><span class="d"></span>${st.label}</span>`,
      `killed: ${D.killed ? `<span class="neg">${esc(D.killed)}</span>` : "no"} · hb <span id="hbAge">–</span> · bar ${esc(D.lastBarLabel ?? "–")}`, "", "wide")}
  </div>`;
}
const sumUpnl = (D) => { const ps = D.positions || []; if (!ps.length) return isN(D.upnl) ? D.upnl : 0; return ps.reduce((a, p) => a + (isN(p.upnl) ? p.upnl : 0), 0); };
function positions(D) {
  const ps = D.positions || [];
  if (!ps.length) return `<div class="empty">No open positions.</div>`;
  const rows = ps.map((p) => {
    const short = String(p.side).toLowerCase() === "short";
    const ret = isN(p.upnl) && isN(p.size) && p.size ? (p.upnl / p.size) * 100 : null;
    // SL..TP gauge: left = stop, right = target, tick = mark
    let gauge = "–";
    if (isN(p.sl) && isN(p.tp) && isN(p.mark) && p.sl !== p.tp) {
      const f = Math.max(0, Math.min(1, (p.mark - p.sl) / (p.tp - p.sl)));
      gauge = `<div class="rng"><i style="left:calc(${(f * 100).toFixed(1)}% - 1px)"></i></div><div class="rlab"><span>SL ${px(p.sl)}</span><span>TP ${px(p.tp)}</span></div>`;
    }
    const age = isN(p.openedTs) ? dur(Date.now() - p.openedTs) : "–";
    return `<tr><td data-l="Market"><b>${esc(p.market)}</b> <span class="side ${short ? "short" : "long"}">${short ? "SHORT" : "LONG"}</span></td>
      <td class="r" data-l="Notional">${usd(p.size)}</td><td class="r" data-l="Entry">${px(p.entry)}</td><td class="r" data-l="Mark">${px(p.mark)}</td>
      <td class="r ${tone(p.upnl)}" data-l="uPnL"><b>${susd(p.upnl)}</b> <span class="small">${pct(ret)}</span></td>
      <td class="r" data-l="Age">${age}</td><td class="full" data-l="Stop ↔ Target">${gauge}</td></tr>`;
  }).join("");
  return `<div class="tw"><table class="pos"><thead><tr><th>Market</th><th class="r">Notional</th><th class="r">Entry</th><th class="r">Mark</th><th class="r">uPnL</th><th class="r">Age</th><th>Stop ↔ Target</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="dim small" style="margin-top:6px">Exchange holds SL/TP on every position. Mark and uPnL as of the snapshot · source: ${esc(D.balanceSource ?? "–")}</div>`;
}
function volume(D) {
  const s = D.streak || {}, c = D.churn || {};
  let h = "";
  if (!s.error && isN(s.volumeUsd)) {
    const g = s.goalUsd || 100, f = Math.min(100, (s.volumeUsd / g) * 100);
    h += `<div class="row"><span>Streak · day volume</span><span>${s.met ? '<span class="pos">MET ✓</span>' : `<span class="warn">${esc(s.status ?? "open")}</span>`}</span></div>
      <div class="prog"><i style="width:${f}%"></i></div>
      <div class="row dim"><span>${usd(s.volumeUsd, 0)} / ${usd(g, 0)} goal</span><span>deadline ${esc((s.deadline || "").replace(/^\d{4}-\d\d-\d\d /, ""))}</span></div>`;
  } else h += `<div class="dim small">Streak data unavailable${s.error ? " (" + esc(s.error) + ")" : ""}.</div>`;
  if (c && (isN(c.dayVolumeUsd) || isN(c.count))) {
    const t = c.targetUsd || 0, f = t ? Math.min(100, ((c.dayVolumeUsd || 0) / t) * 100) : 0;
    h += `<div style="height:14px"></div><div class="row"><span>Points · day volume</span><span class="cyan">${usd(c.dayVolumeUsd, 0)}</span></div>
      <div class="prog amber"><i style="width:${f}%"></i></div>
      <div class="row dim"><span>churn ${usd(c.volumeUsd, 0)} · target ${usd(t, 0)}</span><span>${f.toFixed(0)}%</span></div>
      <div style="height:10px"></div>
      <div class="row"><span class="dim">Rotations</span><span>${esc(c.count ?? 0)} / ${esc(c.maxPerDay ?? "–")}</span></div>
      <div class="row"><span class="dim">Churn cost (fees · P&amp;L)</span><span>${usd(c.feesUsd)} · <span class="${tone(c.realizedUsd)}">${susd(c.realizedUsd)}</span></span></div>
      <div class="row"><span class="dim">Last rotation</span><span>${esc(c.last ?? "–")}</span></div>
      ${c.status ? `<div class="dim small" style="margin-top:6px">${esc(c.status)}</div>` : ""}`;
  }
  return h;
}
function feed(D) {
  const items = (D.trades || []).map((r) => ({ ...r, churn: false }));
  if (UI.showChurn) for (const r of D.churnFeed || []) items.push({ ...r, churn: true });
  items.sort((a, b) => (tsLa(b.ts_la) || 0) - (tsLa(a.ts_la) || 0));
  if (!items.length) return `<div class="empty">No trades yet.</div>`;
  return `<ul class="feed">${items.slice(0, 40).map((r) => {
    const t = tsLa(r.ts_la), pnl = toN(r.pnl_usd), size = toN(r.size_usd), fill = toN(r.fill_px);
    const when = t ? (Date.now() - t < 864e5 ? hm(t) : fmtT(t, { month: "short", day: "numeric" }) + " " + hm(t).replace(/ [AP]M$/, (m) => m.trim()[0].toLowerCase())) : esc(r.ts_la);
    const what = r.event === "HALT" ? "" : `<b>${esc(r.symbol)}</b> <span class="side ${String(r.side).toLowerCase() === "short" ? "short" : "long"}">${esc(String(r.side || "").toUpperCase())}</span> <span class="dim">${size ? usd(size, 0) : ""}${fill ? " @ " + px(fill) : ""}</span>`;
    const why = r.event === "HALT" || (r.why && !r.churn && r.why !== "churn") ? `<span class="why">${esc(r.why)}</span>` : "";
    return `<li class="${r.churn ? "churn" : ""}"><span class="t">${when}</span><span class="ev ${esc(r.event)}">${r.churn ? "↻ " : ""}${esc(r.event)}</span><span>${what}</span><span class="${tone(pnl)}">${pnl !== null ? susd(pnl) : ""}</span>${why}</li>`;
  }).join("")}</ul>`;
}
function signals(D) {
  const by = new Map();   // decisions.csv can hold several passes of the same bar; keep the newest row per market
  for (const r of D.latest || []) if (isN(r.score) && (!by.has(r.market) || String(r.ts) >= String(by.get(r.market).ts))) by.set(r.market, r);
  const held = new Set((D.positions || []).map((p) => String(p.market).split(" ")[0]));
  const rows = [...by.values()].sort((a, b) => Math.abs(b.score) - Math.abs(a.score));
  if (!rows.length) return `<div class="empty">No signal rows.</div>`;
  const max = Math.max(D.theta || 0.2, ...rows.map((r) => Math.abs(r.score))) * 1.05;
  return `<div class="tw"><table><thead><tr><th>Market</th><th class="r">Score</th><th>Strength</th><th class="hide-m">Action</th></tr></thead><tbody>${rows.map((r) => {
    const w = (Math.abs(r.score) / max) * 50;
    return `<tr><td><b>${esc(r.market)}</b>${held.has(r.market) ? ' <span class="cyan">●</span>' : ""}</td><td class="r ${tone(r.score)}">${r.score >= 0 ? "+" : "−"}${Math.abs(r.score).toFixed(3)}</td>
      <td style="min-width:120px"><div style="position:relative;height:6px;background:#1c2530;border-radius:3px"><i style="position:absolute;top:0;height:6px;border-radius:3px;${r.score >= 0 ? `left:50%;width:${w}%;background:var(--green)` : `right:50%;width:${w}%;background:var(--red)`}"></i><i style="position:absolute;left:50%;top:-2px;width:1px;height:10px;background:#4a5868"></i></div></td>
      <td class="hide-m dim small" style="white-space:normal">${held.has(r.market) ? '<span class="cyan">held</span> · ' : ""}${esc(r.action)}${r.info && !String(r.info).startsWith("{") ? " · " + esc(String(r.info).slice(0, 60)) : ""}</td></tr>`;
  }).join("")}</tbody></table></div><div class="dim small" style="margin-top:6px">Entry threshold ±${esc(D.theta)} · bar ${esc(D.lastBarLabel ?? "–")}</div>`;
}
function details(id, title, body) { return `<section class="panel mb"><details data-id="${id}"${UI.openDetails.has(id) ? " open" : ""}><summary>${title}</summary><div>${body}</div></details></section>`; }
const props = (items) => `<dl class="props">${items.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;

/* ---------- render ---------- */
function render() {
  if (!PAYLOAD) return;
  const D = PAYLOAD.data || {}, st = statusInfo(D), lim = D.limits || {}, reg = D.regime || {};
  let h = `<header class="top"><div style="display:flex;align-items:center;gap:10px"><span class="brand"><span class="blink">▮</span> IMPERIAL<span class="dim">//</span>LIVE</span>
      <span class="tag ${st.cls}"><span class="d"></span>${st.label}</span><span id="staleTag"></span></div>
    <div class="meta"><span>updated <b id="updAgo">–</b></span><span>next refresh <b id="nextIn">–</b> <span class="bar"><i id="nextBar" style="width:0"></i></span></span>
      <span class="btns"><button class="ghost" id="btnRefresh">↻ refresh</button><button class="ghost" id="btnLock">lock</button></span></div></header>`;
  if (D.pill === "Halted") h += `<div class="banner bad"><b>HALTED.</b> Kill flag: ${esc(D.killed || "set")}. The bot heartbeats but will not trade until reset.</div>`;
  else if (D.pill === "Stopped") h += `<div class="banner bad"><b>STOPPED.</b> Supervisor or trader not running${D.stop ? ", STOP file present" : ""}.</div>`;
  else if (D.pill === "Stalled") h += `<div class="banner warn"><b>STALLED.</b> Heartbeat over 5 minutes old at snapshot time; the watchdog restarts a hung trader.</div>`;
  if (D.lastError) h += `<div class="banner warn">Last error: ${esc(D.lastError)}</div>`;
  if (FETCH_ERR) h += `<div class="banner warn">Latest refresh failed: ${esc(FETCH_ERR)}. Showing the previous snapshot.</div>`;
  h += kpis(D);
  h += `<div class="grid2"><section class="panel"><h2><span class="h">Equity</span><span class="btns">${["24h", "7d", "all"].map((r) => `<button class="ghost ${UI.range === r ? "on" : ""}" data-range="${r}">${r}</button>`).join("")}</span></h2>${equityChart(D)}</section>
    <section class="panel"><h2><span class="h">Volume &amp; points</span><span>${esc(D.streak?.day ?? "")}</span></h2>${volume(D)}</section></div>`;
  h += `<section class="panel mb"><h2><span class="h">Open positions</span><span>uPnL ${`<span class="${tone(sumUpnl(D))}">${susd(sumUpnl(D))}</span>`}</span></h2>${positions(D)}</section>`;
  h += `<div class="grid2b"><section class="panel"><h2><span class="h">Trade feed</span><button class="ghost ${UI.showChurn ? "on" : ""}" id="btnChurn">${UI.showChurn ? "hide" : "show"} churn ↻</button></h2>${feed(D)}
      <div class="dim small" style="margin-top:6px">Strategy opens and closes${UI.showChurn ? "; churn rotations faded" : ". Churn rotations are hidden"}.</div></section>
    <section class="panel"><h2><span class="h">Signals</span><span>last bar ${esc(D.lastBarLabel ?? "–")}</span></h2>${signals(D)}</section></div>`;
  h += details("sys", "System &amp; limits", props([
    ["Mode", esc(D.mode ?? "–")], ["Heartbeat", esc(D.heartbeat ?? "–") + ` <span class="dim">(${isN(D.heartbeatAgeS) ? D.heartbeatAgeS + "s old at snapshot" : "–"})</span>`],
    ["Processes", `supervisor ${D.supervisorPid ? "✓" : "✗"} · trader ${D.traderPid ? "✓" : "✗"} · watchdog ${D.watchdogPid ? "✓" : "✗"}${D.stop ? ' · <span class="neg">STOP file</span>' : ""}`],
    ["Kill flag", D.killed ? `<span class="neg">${esc(D.killed)}</span>` : "clear"], ["Halted today", D.haltedToday ? '<span class="neg">yes</span>' : "no"],
    ["Balance (free)", usd(D.balance)], ["Risk per trade", usd(lim.risk)], ["Points slot", usd(lim.slotUsd, 0)], ["Total notional cap", usd(lim.totalCap, 0)],
    ["Daily loss cap", usd(D.dayCap, 0)], ["Kill switch", `equity ≤ ${usd(D.killLine, 0)} or ${esc(D.killConsec ?? "–")} straight losses (now ${esc(D.consecLosses ?? 0)})`],
    ["Max trades/day", esc(D.maxTrades ?? "–")], ["Protections", esc((lim.protections || []).join(", ") || "–") + " + exchange SL/TP"],
    ...(Object.keys(reg).length ? [["Regime", `${esc(reg.label ?? "–")} <span class="dim">(info only; as of ${esc(D.regimeAsOf ?? "–")})</span>`]] : []),
    ["Snapshot", esc(D.asOf ?? "–")],
  ]));
  if (Array.isArray(D.log) && D.log.length) h += details("log", `Recent log (${D.log.length} lines)`, `<pre class="log">${esc([...D.log].reverse().join("\n"))}</pre>`);
  h += `<div class="foot"><span>auto-refresh every ${Math.round(REFRESH_MS / 60000)} min · data republishes about every 10 min · times PT</span><span>read-only view · no trading controls</span></div>`;
  $("app").innerHTML = h;
  document.querySelectorAll("details[data-id]").forEach((d) => d.addEventListener("toggle", () => { d.open ? UI.openDetails.add(d.dataset.id) : UI.openDetails.delete(d.dataset.id); }));
  document.querySelectorAll("[data-range]").forEach((b) => (b.onclick = () => { UI.range = b.dataset.range; render(); }));
  $("btnChurn").onclick = () => { UI.showChurn = !UI.showChurn; render(); };
  $("btnRefresh").onclick = () => refresh();
  $("btnLock").onclick = () => { clearSession(); showLock(""); };
  updateClocks();
}
function updateClocks() {
  if (!PAYLOAD) return;
  const now = Date.now(), gen = PAYLOAD.generatedAt, D = PAYLOAD.data || {}, age = gen ? now - gen : null;
  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  set("updAgo", age === null ? "–" : ago(age));
  set("nextIn", busy ? "…" : mmss(NEXT_FETCH - now));
  const nb = $("nextBar"); if (nb) nb.style.width = (100 * (1 - Math.max(0, NEXT_FETCH - now) / REFRESH_MS)).toFixed(1) + "%";
  const hb = isN(D.heartbeatAgeS) && gen ? D.heartbeatAgeS * 1000 + (now - gen) : null;
  set("hbAge", hb === null ? "–" : dur(hb));
  const stale = age !== null && age > STALE_MS, tag = $("staleTag");
  if (tag) tag.innerHTML = stale ? `<span class="tag warn"><span class="d"></span>STALE ${dur(age)}</span>` : "";
  document.title = (stale ? "STALE · " : "") + (D.pill ?? "") + " · " + usd(D.equity) + " · Imperial";
}

// re-open from this tab's session (survives reloads, cleared when the tab closes)
(async () => {
  try {
    if (!sessionStorage.getItem(SS_KEY) || !window.crypto || !crypto.subtle) return;
    const env = await fetchEnvelope(), k = await loadSession(env);
    if (!k) { clearSession(); return; }
    await unlockWith(k, env);
  } catch (e) { clearSession(); if (e && e.name === "OperationError") showLock("Session expired. Enter the password again."); }
})();
