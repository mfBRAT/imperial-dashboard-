/* Imperial bot dashboard: static, client-side decrypted. No data lives in this file.
   data.enc.json = {v, kdf:"PBKDF2-SHA256", iter, salt, iv, ct} (base64), AES-256-GCM over a JSON payload
   {generatedAt: epoch ms, data: <dashboard_data.py snapshot>, info: {...}}. */
"use strict";
const STALE_MS = 20 * 60 * 1000, REFRESH_MS = 60 * 1000, LS_KEY = "imperialDash.key.v1";
const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const ub64 = (u) => btoa(String.fromCharCode(...new Uint8Array(u)));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let KEY = null, KEY_SALT = null, PAYLOAD = null, LAST_FETCH = null, FETCH_ERR = null, SORT = "strength", timer = null;

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
async function saveKey(key, env) {
  const raw = await crypto.subtle.exportKey("raw", key);
  localStorage.setItem(LS_KEY, JSON.stringify({ salt: env.salt, iter: env.iter, k: ub64(raw) }));
}
async function loadKey(env) {
  try {
    const s = JSON.parse(localStorage.getItem(LS_KEY) || "null");
    if (!s || s.salt !== env.salt || s.iter !== env.iter) return null;
    return await crypto.subtle.importKey("raw", b64(s.k), { name: "AES-GCM" }, false, ["decrypt"]);
  } catch (_) { return null; }
}
function forget() { localStorage.removeItem(LS_KEY); }

function showLock(msg) {
  KEY = null; PAYLOAD = null; if (timer) clearInterval(timer); timer = null;
  $("app").hidden = true; $("app").innerHTML = ""; $("lock").hidden = false;
  $("lockerr").textContent = msg || ""; $("pw").value = ""; $("unlock").disabled = false; $("unlock").textContent = "Unlock";
}
async function unlockWith(key, env, remember) {
  PAYLOAD = await decrypt(key, env);   // throws OperationError on wrong password / tamper
  KEY = key; KEY_SALT = env.salt; LAST_FETCH = Date.now(); FETCH_ERR = null;
  if (remember) await saveKey(key, env);
  $("lock").hidden = true; $("app").hidden = false; render();
  if (!timer) timer = setInterval(tick, 15000);
}
let nextFetch = 0;
async function tick() {
  if (Date.now() >= nextFetch) { nextFetch = Date.now() + REFRESH_MS; await refresh(); } else render();
}
async function refresh() {
  try {
    const env = await fetchEnvelope();
    if (env.salt !== KEY_SALT) {   // password/salt rotated on the publisher side
      const k = await loadKey(env);
      if (!k) return showLock("The dashboard password was changed. Enter the new password.");
      KEY = k; KEY_SALT = env.salt;
    }
    PAYLOAD = await decrypt(KEY, env); LAST_FETCH = Date.now(); FETCH_ERR = null;
  } catch (e) {
    FETCH_ERR = (e && e.name === "OperationError") ? "could not decrypt the latest data (password changed?)" : String(e && e.message || e);
  }
  render();
}

$("lockform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("pw").value, remember = $("remember").checked;
  if (!window.crypto || !crypto.subtle) { $("lockerr").textContent = "This browser can't decrypt here (needs HTTPS and WebCrypto)."; return; }
  $("unlock").disabled = true; $("unlock").textContent = "Unlocking…"; $("lockerr").textContent = "";
  try {
    const env = await fetchEnvelope();
    const key = await deriveKey(pw, env);
    await unlockWith(key, env, remember);
    nextFetch = Date.now() + REFRESH_MS;
  } catch (e) {
    $("unlock").disabled = false; $("unlock").textContent = "Unlock";
    $("lockerr").textContent = e && e.name === "OperationError" ? "Wrong password." : "Couldn't load the data: " + (e && e.message || e);
  }
});

/* ---------- formatting ---------- */
const isN = (v) => typeof v === "number" && isFinite(v);
const sgn = (v, d = 3) => !isN(v) ? "–" : (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(d);
const usd = (v, d = 2) => !isN(v) ? "–" : (v < 0 ? "−$" : "$") + Math.abs(v).toFixed(d);
const num = (v) => !isN(v) ? "–" : Math.abs(v) >= 1000 ? v.toLocaleString("en-US", { maximumFractionDigits: 2 }) : String(+v.toPrecision(6));
const dur = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return s < 90 ? s + " s" : s < 5400 ? Math.round(s / 60) + " min" : s < 172800 ? (s / 3600).toFixed(1) + " h" : Math.round(s / 86400) + " d"; };
const tone = (v) => !isN(v) ? "" : v > 0 ? "pos" : v < 0 ? "neg" : "";
const pill = (t, label) => `<span class="pill ${t}"><span class="dot"></span>${esc(label)}</span>`;
const props = (items) => `<dl class="props">${items.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const table = (cols, rows) => `<div class="tw"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => typeof c === "object" && c !== null ? `<td class="${c.cls || ""}">${c.html ?? esc(c.text)}</td>` : `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
const card = (h, cap, body) => `<section class="card"><h2>${esc(h)}</h2>${cap ? `<p class="cap">${esc(cap)}</p>` : ""}${body}</section>`;
const PILL_TONE = { Running: "success", Stalled: "warning", Halted: "danger", Stopped: "neutral" };
const PILL_NOTE = {
  Running: "Supervisor and trader processes alive; heartbeat under 5 minutes old.",
  Stalled: "Processes exist but the heartbeat is over 5 minutes old; the watchdog restarts a hung trader.",
  Halted: "A kill switch or failsafe fired; the bot only heartbeats and will not trade until reset.",
  Stopped: "Supervisor or trader not running, or the STOP file is present.",
};
const KNOWN = new Set("asOf pill supervisorPid traderPid watchdogPid stop heartbeat heartbeatAgeS mode profile lastError killed haltedToday balanceSource balance equity start killLine dayPnl dayCap dayTrades maxTrades cumPnl consecLosses killConsec theta lastBarUtc lastBarLabel positions latest history trades regime regimeAsOf log streak limits".split(" "));

/* ---------- charts (SVG) ---------- */
function scoreBars(rows, theta) {
  const W = 640, L = 54, R = 54, rowH = 24, top = 26, H = top + rows.length * rowH + 6;
  const max = Math.max(theta * 1.25, ...rows.map((r) => Math.abs(r.score ?? 0))) * 1.05;
  const half = (W - L - R) / 2, cx = L + half, x = (v) => cx + (v / max) * half;
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Latest score per market">`;
  for (const th of [-theta, theta]) s += `<line x1="${x(th)}" x2="${x(th)}" y1="${top - 6}" y2="${H - 2}" stroke="#8b949e" stroke-dasharray="5 4"/><text x="${x(th)}" y="${top - 10}" text-anchor="middle" fill="#8b949e" font-size="11">${th > 0 ? "+" : "−"}${theta.toFixed(2)} ${th > 0 ? "long" : "short"}</text>`;
  s += `<line x1="${cx}" x2="${cx}" y1="${top - 6}" y2="${H - 2}" stroke="#30363d"/>`;
  rows.forEach((r, i) => {
    const v = r.score ?? 0, y = top + i * rowH, x1 = x(v);
    s += `<text x="${L - 8}" y="${y + rowH / 2 + 4}" text-anchor="end" fill="#c9d1d9" font-size="12">${esc(r.market)}</text>`;
    s += `<rect x="${Math.min(cx, x1)}" y="${y + 5}" width="${Math.max(1, Math.abs(x1 - cx))}" height="${rowH - 10}" rx="3" fill="${v >= 0 ? "#3fb950" : "#f85149"}" opacity="${Math.abs(v) >= theta ? 1 : 0.6}"/>`;
    s += `<text x="${v >= 0 ? x1 + 6 : x1 - 6}" y="${y + rowH / 2 + 4}" text-anchor="${v >= 0 ? "start" : "end"}" fill="#e6edf3" font-size="11">${sgn(r.score)}</text>`;
  });
  return s + "</svg>";
}
function lineChart(labels, series, theta) {
  const W = 640, H = 220, L = 36, R = 10, T = 10, B = 26, colors = ["#58a6ff", "#3fb950", "#d29922", "#bc8cff"];
  const all = series.flatMap((s) => s.values).concat([theta]);
  const ymax = Math.ceil(Math.max(...all) * 1.15 * 100) / 100 || 1, n = labels.length;
  const X = (i) => L + (n <= 1 ? 0 : (i / (n - 1)) * (W - L - R)), Y = (v) => T + (1 - v / ymax) * (H - T - B);
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Signal strength over recent bars">`;
  for (let k = 0; k <= 4; k++) { const v = (ymax * k) / 4; s += `<line x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}" stroke="#21262d"/><text x="${L - 4}" y="${Y(v) + 4}" text-anchor="end" fill="#8b949e" font-size="10">${v.toFixed(2)}</text>`; }
  s += `<line x1="${L}" x2="${W - R}" y1="${Y(theta)}" y2="${Y(theta)}" stroke="#8b949e" stroke-dasharray="5 4"/>`;
  const step = Math.max(1, Math.ceil(n / 8));
  labels.forEach((lb, i) => { if (i % step === 0 || i === n - 1) s += `<text x="${X(i)}" y="${H - 8}" text-anchor="middle" fill="#8b949e" font-size="10">${esc(lb)}</text>`; });
  series.forEach((sr, j) => { s += `<polyline fill="none" stroke="${colors[j % 4]}" stroke-width="2" points="${sr.values.map((v, i) => X(i) + "," + Y(v)).join(" ")}"/>`; });
  s += "</svg>";
  const leg = `<div class="legend">${series.map((sr, j) => `<span><i style="background:${colors[j % 4]}"></i>${esc(sr.label)}</span>`).join("")}<span><i style="background:#8b949e"></i>entry threshold</span></div>`;
  return s + leg;
}

/* ---------- render ---------- */
function render() {
  if (!PAYLOAD) return;
  const D = PAYLOAD.data || {}, info = PAYLOAD.info || {}, now = Date.now();
  const snapAge = now - PAYLOAD.generatedAt, stale = snapAge > STALE_MS;
  const th = isN(D.theta) ? D.theta : 0.2;
  const hbNow = isN(D.heartbeatAgeS) ? D.heartbeatAgeS * 1000 + snapAge : null;
  const latest = Array.isArray(D.latest) ? D.latest : [], hist = Array.isArray(D.history) ? D.history : [];
  const positions = Array.isArray(D.positions) ? D.positions : [], trades = Array.isArray(D.trades) ? D.trades : [];
  const reg = D.regime || {}, lim = D.limits || {};
  let h = "";

  // header
  h += `<section class="card"><div class="top"><div><h1>Imperial bot dashboard</h1><div class="muted small">Profile ${esc(D.profile ?? "–")} · ${esc(D.mode ?? "–")} · snapshot ${esc(D.asOf ?? "–")}</div></div>
    <div class="pills">${stale ? pill("danger", "STALE") : ""}${pill(stale ? "neutral" : (PILL_TONE[D.pill] || "neutral"), (stale ? "Last known: " : "") + (D.pill ?? "Unknown"))}</div></div>
    <div style="margin-top:10px">Snapshot age <span class="age ${stale ? "stale" : "ok"}">${dur(snapAge)}</span>${stale ? ` <span class="muted">— updates have stopped (expected every 10 min); the status above may be out of date.</span>` : ""}</div>
    <div class="muted small">Heartbeat ${esc(D.heartbeat ?? "none")} (${isN(D.heartbeatAgeS) ? dur(D.heartbeatAgeS * 1000) + " old at snapshot, ~" + dur(hbNow) + " now" : "unknown"})</div></section>`;
  if (FETCH_ERR) h += `<div class="banner warning">Last refresh failed: ${esc(FETCH_ERR)}. Showing the previous data.</div>`;
  if (D.killed) h += `<div class="banner danger">Halted: ${esc(String(D.killed))}</div>`;
  else if (D.haltedToday) h += `<div class="banner warning">Daily loss cap reached; no new entries today.</div>`;

  // KPIs
  const chg = isN(D.equity) && isN(D.start) && D.start ? (D.equity / D.start - 1) * 100 : null;
  const toKill = isN(D.equity) && isN(D.killLine) ? D.equity - D.killLine : null;
  h += `<div class="kpis">
    <div class="kpi"><div class="l">Equity</div><div class="v">${usd(D.equity)}</div></div>
    <div class="kpi"><div class="l">vs start ${usd(D.start)}</div><div class="v ${tone(chg)}">${chg === null ? "–" : (chg >= 0 ? "+" : "−") + Math.abs(chg).toFixed(2) + "%"}</div></div>
    <div class="kpi"><div class="l">Today's P&amp;L</div><div class="v ${tone(D.dayPnl)}">${usd(D.dayPnl)}</div></div>
    <div class="kpi"><div class="l">Above kill line ${usd(D.killLine)}</div><div class="v ${toKill !== null && toKill < 5 ? "neg" : ""}">${usd(toKill)}</div></div>
    <div class="kpi"><div class="l">Open positions</div><div class="v">${positions.length}${isN(lim.maxPos) ? " / " + lim.maxPos : ""}</div></div>
    ${D.streak && isN(D.streak.volumeUsd) ? `<div class="kpi"><div class="l">Volume today / goal</div><div class="v ${D.streak.met ? "pos" : ""}">${usd(D.streak.volumeUsd, 0)} / ${usd(D.streak.goalUsd, 0)}</div></div>` : ""}
  </div>`;

  // status + account
  h += `<div class="grid">` + card("Bot status", null, props([
    ["Status", pill(PILL_TONE[D.pill] || "neutral", D.pill ?? "Unknown")],
    ["Note", esc(PILL_NOTE[D.pill] || "")],
    ["Mode", esc(D.mode ?? "–")],
    ["Last error", esc(D.lastError ?? "None")],
    ["Halt", D.killed ? `<span class="neg">${esc(String(D.killed))}</span>` : D.haltedToday ? "Daily loss cap reached" : "None"],
    ["Processes", `supervisor ${esc(D.supervisorPid ?? "down")} · trader ${esc(D.traderPid ?? "down")} · watchdog ${esc(D.watchdogPid ?? "down")}`],
    ["STOP file", D.stop ? "Present" : "Absent"],
  ])) + card("Account", D.balanceSource ? "Balance from " + D.balanceSource : null, props([
    ["Balance", usd(D.balance, 4) + " USDC"],
    ["Equity vs start", `${usd(D.equity, 4)} vs ${usd(D.start)}`],
    ["Kill line (−" + (isN(lim.killDd) ? (lim.killDd * 100).toFixed(0) : "–") + "%)", usd(D.killLine)],
    ["Today's P&L", `<span class="${tone(D.dayPnl)}">${usd(D.dayPnl, 4)}</span> of ${usd(D.dayCap)} cap`],
    ["Trades today", `${esc(D.dayTrades ?? "–")} of ${esc(D.maxTrades ?? "–")}`],
    ["Consecutive losses", `${esc(D.consecLosses ?? "–")} of ${esc(D.killConsec ?? "–")}`],
    ["Cumulative P&L", `<span class="${tone(D.cumPnl)}">${usd(D.cumPnl, 4)}</span>`],
  ])) + `</div><div style="height:12px"></div>`;

  // streak
  const S = D.streak;
  if (S && typeof S === "object") {
    if (S.error) h += card("Daily volume streak", null, `<p class="muted">Streak data unavailable (${esc(S.error)}).</p>`);
    else {
      const pct = isN(S.volumeUsd) && isN(S.goalUsd) && S.goalUsd > 0 ? Math.min(100, (S.volumeUsd / S.goalUsd) * 100) : 0;
      h += card("Daily volume streak", `${S.day ?? ""} · window ${S.windowStart ?? "–"} → ${S.windowEnd ?? "–"}`,
        `<div><b class="${S.met ? "pos" : ""}">${usd(S.volumeUsd)}</b> of ${usd(S.goalUsd)} goal${isN(S.targetUsd) ? ` (top-up target ${usd(S.targetUsd)})` : ""} · <b>${esc(S.met ? "met" : S.status ?? "")}</b></div>
         <div class="bar ${S.met ? "met" : ""}"><span style="width:${pct.toFixed(1)}%"></span></div>` +
        props([["Top-up window", `${esc(S.deadline ?? "–")} → ${esc(S.cutoff ?? "–")}`], ["Top-ups / attempts", `${esc(S.topups ?? 0)} / ${esc(S.attempts ?? 0)}`],
               ["Last note", esc(S.lastNote ?? "–")], ["Source", esc(S.source ?? "–")]]));
    }
  }

  // positions
  if (positions.length) h += card("Open positions", null, table(["Market", "Side", "Size", "Entry", "Mark", "SL", "TP", "uPnL", "Lev"],
    positions.map((p) => [p.market, p.side, usd(p.size), num(p.entry), num(p.mark), num(p.sl), num(p.tp), { text: usd(p.upnl, 4), cls: tone(p.upnl) }, isN(p.lev) ? p.lev.toFixed(1) + "×" : "–"])));
  else h += card("Open positions", null, `<p class="muted">None.</p>`);

  // decisions
  if (latest.length) {
    const byStr = [...latest].sort((a, b) => Math.abs(b.score ?? 0) - Math.abs(a.score ?? 0));
    const rows = SORT === "strength" ? byStr : [...latest].sort((a, b) => a.market.localeCompare(b.market));
    const signed = [...latest].sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    const c = byStr[0], gap = th - Math.abs(c.score ?? 0);
    h += card(`Latest hourly decisions (bar closing ${D.lastBarLabel ?? "–"} PT)`, `Entry needs |score| ≥ ${th.toFixed(2)}; evaluated ${latest[0].ts ?? "–"}`,
      scoreBars(signed, th) +
      `<div class="seg"><button data-sort="strength" class="${SORT === "strength" ? "on" : ""}">By strength</button><button data-sort="market" class="${SORT === "market" ? "on" : ""}">By market</button></div>` +
      table(["Market", "Score", "Trend", "Momentum", "Flow", "Positioning", "Cross", "Action", "To entry", "Close"], rows.map((d) => {
        const s = Math.abs(d.score ?? 0);
        return [d.market, { text: sgn(d.score), cls: tone(d.score) }, sgn(d.trend), sgn(d.momentum), sgn(d.flow), sgn(d.positioning), sgn(d.cross),
          d.info && d.info !== "{}" ? `${d.action} · ${d.info}` : d.action, s >= th ? { text: "at threshold", cls: "pos" } : (th - s).toFixed(3), num(d.close)];
      })) +
      `<p class="muted small">${gap > 0 ? `Closest to a new trade: ${esc(c.market)} at ${sgn(c.score)}, ${gap.toFixed(3)} short of the threshold.` : `${esc(c.market)} is at or past the threshold (${sgn(c.score)}).`}</p>`);
  }

  // history chart
  if (hist.length > 1 && latest.length) {
    const top3 = [...latest].sort((a, b) => Math.abs(b.score ?? 0) - Math.abs(a.score ?? 0)).slice(0, 3).map((d) => d.market);
    const series = top3.map((m) => ({ label: m, values: hist.map((x) => Math.abs((x.scores || {})[m] ?? 0)) }));
    h += card("Signal strength over recent bars", "|score| for the three strongest markets; dashed line = entry threshold (either direction)", lineChart(hist.map((x) => x.label), series, th));
  }

  // trades
  if (trades.length) h += card("Recent trades", null, table(["Time (PT)", "Event", "Market", "Side", "Size", "Fill", "SL", "TP", "P&L", "Why"],
    [...trades].reverse().map((r) => [r.ts_la ?? "", r.event ?? "", r.symbol ?? "", r.side ?? "", r.size_usd ?? "", r.fill_px ?? "", r.sl ?? "", r.tp ?? "",
      { text: r.pnl_usd ?? "", cls: tone(parseFloat(r.pnl_usd)) }, { text: r.why ?? "", cls: "wrap" }])));

  // regime + limits
  const rn = (k) => (isN(reg[k]) ? reg[k] : null);
  h += `<div class="grid">`;
  if (Object.keys(reg).length) h += card("Regime and sentiment", D.regimeAsOf ? `As of ${D.regimeAsOf}; informational, the regime gate is off` : null, props([
    ["Regime", esc(reg.label ?? "–")], ["Partial R", sgn(rn("R_partial"))], ["Breadth", sgn(rn("breadth"))], ["BTC trend", sgn(rn("btc_trend"))],
    ["Fear & Greed", rn("fng") === null ? "–" : String(rn("fng"))], ...(reg.note ? [["Note", `<span class="muted small">${esc(reg.note)}</span>`]] : [])]));
  h += card("Safety limits", null, props([
    ["Risk per trade", usd(lim.risk)], ["Daily loss cap", usd(D.dayCap)],
    ["Kill switch", `−${isN(lim.killDd) ? (lim.killDd * 100).toFixed(0) : "–"}% equity (${usd(D.killLine)}) or ${esc(D.killConsec ?? "–")} straight losses`],
    ["Max open positions", esc(lim.maxPos ?? "–")], ["Max trades per day", esc(D.maxTrades ?? "–")],
    ...(info.sizing ? [["Notional and leverage", esc(info.sizing)]] : []),
    ["Protections", esc((Array.isArray(lim.protections) && lim.protections.length ? lim.protections.join(", ") + "; " : "") + "exchange SL/TP on every position")],
  ]));
  h += `</div><div style="height:12px"></div>`;

  // any extra fields another publisher version adds
  const extra = Object.keys(D).filter((k) => !KNOWN.has(k));
  if (extra.length) h += card("Other fields", "Extra snapshot fields", props(extra.map((k) => [k, `<span class="small">${esc(typeof D[k] === "object" ? JSON.stringify(D[k]) : D[k])}</span>`])));

  // log
  if (Array.isArray(D.log) && D.log.length) h += `<section class="card"><details><summary>Recent log (${D.log.length} lines)</summary><pre class="log">${esc([...D.log].reverse().join("\n"))}</pre></details></section>`;

  h += `<div class="foot"><span>Fetched ${LAST_FETCH ? dur(now - LAST_FETCH) + " ago" : "–"} · auto-refresh every minute · times in PT</span>
    <span><button class="sec" id="btnRefresh">Refresh now</button> <button class="sec" id="btnLock">Lock</button> <button class="sec" id="btnForget">Forget this device</button></span></div>`;

  const openLog = document.querySelector("details")?.open;
  $("app").innerHTML = h;
  if (openLog) document.querySelector("details").open = true;
  document.querySelectorAll("[data-sort]").forEach((b) => b.addEventListener("click", () => { SORT = b.dataset.sort; render(); }));
  $("btnRefresh").onclick = () => { nextFetch = Date.now() + REFRESH_MS; refresh(); };
  $("btnLock").onclick = () => showLock("");
  $("btnForget").onclick = () => { forget(); showLock("This device no longer remembers the password."); };
  document.title = (stale ? "STALE · " : "") + (D.pill ?? "") + " · Imperial bot";
}

document.addEventListener("visibilitychange", () => { if (!document.hidden && KEY) { nextFetch = Date.now() + REFRESH_MS; refresh(); } });

// auto-unlock if this device remembers the key
(async () => {
  try {
    if (!localStorage.getItem(LS_KEY) || !window.crypto || !crypto.subtle) return;
    const env = await fetchEnvelope(), k = await loadKey(env);
    if (!k) { forget(); return; }
    $("remember").checked = true;
    await unlockWith(k, env, false); nextFetch = Date.now() + REFRESH_MS;
  } catch (e) { if (e && e.name === "OperationError") { forget(); showLock("Saved password no longer works. Enter it again."); } }
})();
