"use strict";
// VELA — GUI. Sin dependencias ni recursos externos.
// Todo el DOM se construye con textContent (nunca innerHTML con datos): los nombres de relays,
// SSID u otros datos observados no pueden inyectar código.

const SVGNS = "http://www.w3.org/2000/svg";
const LAYER_COLOR = { public_ip: "--c-public", wan_ip: "--c-wan", vpn_server: "--c-vpn", proxy: "--c-proxy",
  tor_exit: "--c-tor", tor_guard: "--c-guard", device: "--c-home", router: "--c-wan", vpn: "--c-vpn",
  internet: "--c-public", "tor-guard": "--c-guard", "tor-middle": "--c-tor", "tor-exit": "--c-tor" };
let TOKEN = null;
let WORLD = null;
const S = { status: null, statusAt: 0, map: null, tab: "dash", play: null, selected: null };

// ── utilidades ─────────────────────────────────────────────────────────────
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}
function s(tag, attrs) { const el = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v); return el; }
const $ = (id) => document.getElementById(id);
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const pad = (n) => String(n).padStart(2, "0");
function dur(sec) { sec = Math.max(0, Math.floor(sec || 0)); const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return `${pad(d)}d ${pad(hh)}h ${pad(m)}m ${pad(sec % 60)}s`; }
function ts(t) { if (!t) return "—"; const d = new Date(t * 1000); return d.toLocaleString("es-ES", { hour12: false }); }
function setKids(el, ...kids) { el.replaceChildren(...kids.flat().filter((k) => k != null)); }
function kv(el, pairs) { setKids(el, pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")])); }
function toast(msg, bad) { const t = $("toast"); t.textContent = msg; t.className = "toast" + (bad ? " bad" : ""); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), 6000); }
function confirmBox(text) { return new Promise((res) => { const d = $("confirmDlg"); $("confirmText").textContent = text; d.onclose = () => res(d.returnValue === "yes"); d.showModal(); }); }
function download(name, text, type) { const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name }); document.body.append(a); a.click(); a.remove(); }

async function api(method, params) {
  const r = await fetch(`/api/${method}`, { method: "POST", headers: { "Content-Type": "application/json", "X-VELA-Token": TOKEN }, body: JSON.stringify(params || {}) });
  const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
  return j.result;
}

// ── arranque ───────────────────────────────────────────────────────────────
function initToken() {
  const m = location.hash.match(/t=([\w-]+)/);
  if (m) { TOKEN = m[1]; try { sessionStorage.setItem("vela_t", TOKEN); } catch (e) { /* sin storage */ } history.replaceState(null, "", "/"); }
  else { try { TOKEN = sessionStorage.getItem("vela_t"); } catch (e) { TOKEN = null; } }
  if (!TOKEN) document.body.prepend(h("div", { class: "emergency" }, "Falta el token de acceso: abre la URL completa que mostró `vela gui`."));
}

function initTheme() {
  let t = "dark"; try { t = localStorage.getItem("vela_theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"); } catch (e) { /* */ }
  document.documentElement.dataset.theme = t;
  $("themeBtn").onclick = () => { const n = document.documentElement.dataset.theme === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = n; try { localStorage.setItem("vela_theme", n); } catch (e) { /* */ } renderAll(); };
}

function initTabs() {
  for (const b of document.querySelectorAll("#tabs button")) b.onclick = () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.id === `tab-${b.dataset.tab}`));
    S.tab = b.dataset.tab; loadTab();
  };
}

// ── estado general ─────────────────────────────────────────────────────────
async function refreshStatus() {
  try { S.status = await api("status"); S.statusAt = Date.now() / 1000; renderStatus(); }
  catch (e) { $("modeBadge").textContent = "sin conexión"; $("modeBadge").className = "badge bad"; }
}

function renderStatus() {
  const st = S.status; if (!st) return;
  const ex = st.exposure;
  $("scoreBadge").textContent = `exposición ${ex.score}/100 · ${ex.level}`;
  $("scoreBadge").className = "badge " + ({ baja: "ok", media: "warn", alta: "bad" })[ex.level];
  $("modeBadge").textContent = st.emergency ? "EMERGENCIA" : "monitorizando";
  $("modeBadge").className = "badge " + (st.emergency ? "bad" : "ok");
  $("emergencyBar").classList.toggle("hidden", !st.emergency);
  const obs = st.obs || {};
  renderChain($("chain"), obs.chain || []);
  renderChain($("torChain"), obs.tor_chain || [], "Tor: ");
  // score
  setKids($("score"), h("div", { class: `scorebig level-${ex.level}` }, `${ex.score}`, h("span", { class: "muted small" }, " /100")),
    ex.indicators.map((i) => h("div", { class: "ind" }, h("span", { class: i.present ? "on" : "off" }, i.present ? "●" : (i.present === false ? "○" : "?")), `${i.label} (${i.weight})`)),
    h("p", { class: "muted small" }, ex.disclaimer));
  const net = st.net, e4 = net.egress.ipv4 || {}, wan = st.wan || {}, pub = st.public || {};
  kv($("ids"), [["IP local", `${net.local_ip || "—"} (${e4.dev || "?"})`], ["Gateway", net.gateway],
    ["IP WAN router", wan.ok ? `${wan.ip}${wan.cgnat ? " · CGNAT" : ""}${wan.double_nat ? " · doble NAT" : ""}` : (wan.error || "no comprobada")],
    ...Object.entries(pub).map(([r, x]) => [`IP pública [${r}]`, x.ok ? `${x.ip} · ${(x.geo || {}).country_name || "?"} · ${ts(x.ts)}` : x.error]),
    ["IPv6", net.egress.ipv6 ? `sale por ${net.egress.ipv6.dev}` : "sin ruta a Internet"]]);
  const sess = st.session;
  kv($("session"), sess ? [["ID", sess.id], ["Duración", h("span", { id: "sessDur", class: "mono" }, dur(sess.duration))], ["Inicio", ts(sess.started)], ["Huella", sess.fingerprint], ["Perfil", sess.profile]]
    : [["Estado", st.emergency ? "emergencia" : "sin sesión registrada (arranca el daemon para registrar historial)"]]);
  const vpnRot = st.rotation.vpn, fw = st.forwarder;
  kv($("vpnproxy"), [["Túneles", net.tunnels.join(", ") || "ninguno"], ["Tráfico por túnel", net.via_tunnel.ipv4 ? "sí" : "no"],
    ["VPN", obs.vpn ? obs.vpn.label : "—"], ["Rotación VPN", vpnRot ? `${vpnRot.adapter}${vpnRot.available ? "" : " · " + vpnRot.reason}` : "sin adaptador en este sistema"],
    ["Proxy activo", obs.proxy ? obs.proxy.label : "—"], ["Forwarder", fw ? `${fw.listen} → ${fw.upstream}` : "no iniciado"],
    ...ksRows(st.killswitch)]);
  const t = st.tor || {};
  kv($("tor"), t.available ? [["Instancia", `${t.version} · ${t.target}`], ["Bootstrap", `${t.bootstrap}%`], ["Circuitos / streams", `${t.circuit_count} / ${t.stream_count}`],
    ["Guard", t.guard ? `${t.guard.nick} ${t.guard.ip} (${t.guard.country || "?"})` : "—"], ["Exit", t.exit ? `${t.exit.nick} ${t.exit.ip} (${t.exit.country || "?"})` : "—"],
    ["Modo", t.observe_only ? "Tor Browser: solo observación" : "gestionable (NEWNYM)"]] : [["Estado", t.error || "no disponible"]]);
  const d = st.dns || {}, enc = d.encryption || {};
  kv($("dns"), [["Origen", d.effective_source], ...(enc.resolvers || []).map((r) => [r.addr, `${r.provider || "desconocido"} · ${r.transport}${r.upstream ? " → " + r.upstream : ""}`]),
    ["Cifrado", h("span", { class: d.encrypted ? "status-ok" : d.encrypted === false ? "status-fail" : "status-unknown" }, d.encrypted ? "sí" : d.encrypted === false ? "NO" : "no verificable")],
    ["Conexión DoH", enc.upstream_route ? `${enc.upstream_route.ip} por ${enc.upstream_route.dev}` : "—"],
    ...(enc.browsers || []).map((b) => [b.browser, `DoH propio: ${b.mode}`]), ["Split DNS", (d.split_dns || []).join(", ") || "no"]]);
  setKids($("rotSummary"), Object.entries(st.rotation).map(([layer, r]) => h("div", { class: "alert info" },
    h("div", { class: "title" }, `${layer} · ${r.adapter}`),
    h("div", {}, r.enabled ? h("span", { class: "countdown", "data-deadline": String(r.deadline || "") }, r.remaining != null ? dur(r.remaining) : "—") : h("span", { class: "muted" }, "rotación automática desactivada")),
    h("div", { class: "meta" }, `${r.rotations_last_hour}/${r.max_per_hour} en la última hora${r.available ? "" : " · " + r.reason}`))));
  if (!Object.keys(st.rotation).length) setKids($("rotSummary"), h("p", { class: "muted" }, "Ningún adaptador de rotación disponible."));
  setKids($("alerts"), st.findings.length ? st.findings.map(alertEl) : [h("p", { class: "muted" }, "Sin alertas activas.")]);
  if (S.map) drawMap($("miniMap"), S.map, { mini: true });
}

function ksRows(ks) {
  const x = (ks || {}).external || {}, rp = x.route_protection || {};
  const st = (f) => rp[f] ? h("span", { class: rp[f].state === "bloqueado" ? "status-ok" : "status-fail" }, `${rp[f].state} · ${rp[f].detail}`) : "—";
  const rows = [["Kill-switch", (x.declared_by || []).join(", ") || (ks && ks.active ? "propio (nftables)" : "ningún cliente")], ["Si cae el túnel IPv4", st("ipv4")], ["Si cae el túnel IPv6", st("ipv6")]];
  for (const c of x.clients || []) if (c.declared) rows.push([`${c.client} (config)`, `kill-switch ${c.declared.killswitch_mode || c.declared.killswitch}`]);
  return rows;
}

function renderChain(el, chain, prefix) {
  const kids = [];
  chain.forEach((c, i) => {
    if (i) kids.push(h("span", { class: "arrow" }, "→"));
    kids.push(h("div", { class: `hop ${c.type}` }, h("div", { class: "t" }, (prefix && i === 0 ? prefix : "") + c.type), h("div", { class: "v" }, c.ip || c.label || "?"),
      h("div", { class: "muted small" }, [c.country, c.iface, c.note, c.geo_source].filter(Boolean).join(" · "))));
  });
  setKids(el, kids);
}

function alertEl(f) {
  return h("div", { class: `alert ${f.severity}` }, h("div", { class: "title" }, h("span", { class: `sev sev-${f.severity}` }, f.severity), " ", f.title, " ", h("span", { class: `status-${f.status} small` }, `[${f.status}]`)),
    h("div", {}, f.observed), h("div", { class: "meta" }, `${f.mode} · ${f.method} · confianza ${f.confidence}`),
    h("div", { class: "meta" }, `Limitaciones: ${f.limitations}`), h("div", { class: "meta" }, `Recomendación: ${f.recommendation}`));
}

function tickClock() {
  $("clock").textContent = new Date().toLocaleTimeString("es-ES", { hour12: false });
  if (!S.status) return;
  const el = $("sessDur");
  if (el && S.status.session) el.textContent = dur(S.status.session.duration + (Date.now() / 1000 - S.statusAt));
  for (const c of document.querySelectorAll(".countdown[data-deadline]")) {
    const dl = parseFloat(c.dataset.deadline); if (dl) c.textContent = dur(dl - Date.now() / 1000);
  }
}

// ── eventos en directo ─────────────────────────────────────────────────────
async function stream() {
  while (true) {
    try {
      const r = await fetch("/api/stream", { method: "POST", headers: { "X-VELA-Token": TOKEN, "Content-Type": "application/json" }, body: "{}" });
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
      while (true) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true }); let i;
        while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); if (line.trim()) onEvent(JSON.parse(line)); }
      }
    } catch (e) { /* reconectar */ }
    await new Promise((r) => setTimeout(r, 5000));
  }
}
function evLi(e) { return h("li", {}, h("span", { class: "mono muted" }, ts(e.ts)), h("span", { class: `sev sev-${e.severity}` }, e.severity), h("span", {}, e.kind), h("span", { class: "muted" }, JSON.stringify(e.data).slice(0, 220))); }
function onEvent(e) {
  const ul = $("live"); ul.prepend(evLi(e)); while (ul.children.length > 100) ul.lastChild.remove();
  if (["high", "critical"].includes(e.severity)) toast(`${e.kind}: ${JSON.stringify(e.data).slice(0, 160)}`, true);
  clearTimeout(onEvent.t); onEvent.t = setTimeout(refreshStatus, 800);
}

// ── mapa ───────────────────────────────────────────────────────────────────
function proj(lon, lat) {
  const top = WORLD.lat_top, bot = WORLD.lat_bottom;
  return [(lon + 180) / 360 * 1000, (top - Math.max(bot, Math.min(top, lat))) / (top - bot) * 500];
}
function arc(a, b) {
  const [x1, y1] = a, [x2, y2] = b, mx = (x1 + x2) / 2, my = (y1 + y2) / 2, d = Math.hypot(x2 - x1, y2 - y1);
  return `M${x1},${y1} Q${mx},${my - Math.min(120, d * 0.3)} ${x2},${y2}`;
}
function drawBase(svg) {
  svg.replaceChildren();
  const g = s("g");
  for (let lon = -150; lon <= 150; lon += 30) { const [x] = proj(lon, 0); g.append(s("line", { x1: x, y1: 0, x2: x, y2: 500, class: "gridline" })); }
  for (let lat = -30; lat <= 60; lat += 30) { const [, y] = proj(0, lat); g.append(s("line", { x1: 0, y1: y, x2: 1000, y2: y, class: "gridline" })); }
  const ring = (poly) => "M" + poly.map(([lo, la]) => proj(lo, la).map((v) => v.toFixed(1)).join(",")).join("L") + "Z";
  if (WORLD.rings) {  // costas de OpenStreetMap incorporadas: un solo trazado par-impar (lagos y mares interiores)
    g.append(s("path", { class: "land", "fill-rule": "evenodd", d: WORLD.rings.map(ring).join("") }));
    const t = s("text", { x: 6, y: 494, class: "attribution" });
    t.textContent = WORLD.attribution;
    g.append(t);
  } else {
    for (const poly of Object.values(WORLD.land)) g.append(s("path", { class: "land", d: ring(poly) }));
  }
  svg.append(g);
}
function nodeEl(p, color, r, info, cls) {
  const c = s("circle", { cx: p[0], cy: p[1], r, fill: color, class: cls || "node" });
  c.addEventListener("mousemove", (ev) => showTip(ev, info));
  c.addEventListener("mouseleave", hideTip);
  c.addEventListener("click", () => selectNode(info, c));
  return c;
}
function showTip(ev, info) {
  const t = $("tooltip"); if (!t) return;
  const wrap = t.parentElement.getBoundingClientRect();
  t.replaceChildren(...Object.entries(info).filter(([, v]) => v != null && v !== "").map(([k, v]) => h("div", {}, h("b", {}, k + ": "), String(v))));
  t.classList.remove("hidden");
  t.style.left = Math.min(ev.clientX - wrap.left + 12, wrap.width - 290) + "px"; t.style.top = (ev.clientY - wrap.top + 12) + "px";
}
function hideTip() { const t = $("tooltip"); if (t) t.classList.add("hidden"); }
function selectNode(info, el) {
  document.querySelectorAll(".node.sel").forEach((x) => x.classList.remove("sel")); el.classList.add("sel");
  const box = $("mapSelection"); if (!box) return;
  setKids(box, h("h2", {}, "Selección"), h("dl", { class: "kv" }, Object.entries(info).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")])),
    h("p", { class: "muted small" }, "Ubicación estimada por GeoIP local: no es la ubicación física real del servidor."));
}
function chainPoints(chain) { return chain.filter((c) => c.lat != null && c.lon != null).map((c) => ({ ...c, p: proj(c.lon, c.lat) })); }

function drawMap(svg, m, opts) {
  if (!WORLD) return;
  opts = opts || {};
  drawBase(svg);
  const layersOn = new Set([...document.querySelectorAll("#tab-map input[data-layer]")].filter((x) => x.checked).map((x) => x.dataset.layer));
  const tsel = opts.time || null;
  // heatmap
  if (!opts.mini && $("heatToggle").checked) {
    const max = Math.max(1, ...m.heat.map((x) => x.seconds));
    for (const x of m.heat) if (x.lat != null) { const p = proj(x.lon, x.lat); svg.append(nodeEl(p, css("--accent"), 6 + 34 * Math.sqrt(x.seconds / max), { país: `${x.name} (${x.country})`, tiempo: dur(x.seconds) }, "heat")); }
  }
  // historial
  if (!opts.mini) {
    for (const x of m.history) {
      if (!layersOn.has(x.layer)) continue;
      const active = tsel ? (x.started <= tsel && (x.ended || Date.now() / 1000) >= tsel) : !x.ended;
      if (tsel && !active) continue;
      const p = proj(x.lon, x.lat); const jitter = (x.key.charCodeAt(0) % 7) - 3;
      svg.append(nodeEl([p[0] + jitter, p[1] - jitter], css(LAYER_COLOR[x.layer] || "--accent"), active ? 5 : 3.5,
        { capa: x.layer, elemento: x.label, país: x.country, ASN: x.asn, desde: ts(x.started), hasta: x.ended ? ts(x.ended) : "activo", duración: dur((x.ended || Date.now() / 1000) - x.started) }, "node hist" + (active ? " on" : "")));
    }
  }
  // cadena actual
  if (!tsel) {
    const home = m.home && m.home.lat != null ? proj(m.home.lon, m.home.lat) : null;
    for (const [chain, start] of [[m.chain, home], [m.tor_chain, home]]) {
      const pts = chainPoints(chain || []); let prev = start;
      for (const c of pts) {
        if (prev && (prev[0] !== c.p[0] || prev[1] !== c.p[1])) svg.append(s("path", { d: arc(prev, c.p), class: "link", stroke: css(LAYER_COLOR[c.type] || "--accent") }));
        prev = c.p;
      }
      for (const c of pts) svg.append(nodeEl(c.p, css(LAYER_COLOR[c.type] || "--accent"), 6.5, { salto: c.type, nodo: c.label, IP: c.ip, país: c.country, ASN: c.asn, origen: c.geo_source }));
    }
    if (home) svg.append(nodeEl(home, css("--c-home"), 6, { salto: "casa (estimada)", país: m.home.country, origen: m.home.geo_source }));
  }
}

async function loadMap() {
  const since = Date.now() / 1000 - parseFloat($("mapRange").value);
  S.map = await api("map", { since });
  S.mapSince = since;
  drawMap($("bigMap"), S.map);
  $("mapNote").textContent = S.map.note;
  setKids($("circuits"), S.map.tor_circuits.length ? S.map.tor_circuits.map((c) => h("div", { class: "alert info" }, h("div", { class: "title" }, `Circuito ${c.id} · ${c.streams} streams`),
    h("div", {}, c.path.map((p) => `${p.role}: ${p.nick} (${p.country || "?"})`).join(" → ")))) : [h("p", { class: "muted" }, "Sin circuitos observables.")]);
}
function initMap() {
  for (const el of document.querySelectorAll("#tab-map input")) el.addEventListener("change", () => S.map && drawMap($("bigMap"), S.map, { time: sliderTime() }));
  $("mapRange").onchange = loadMap;
  $("timeSlider").oninput = () => { const t = sliderTime(); $("timeLabel").textContent = t ? ts(t) : "ahora"; drawMap($("bigMap"), S.map, { time: t }); };
  $("playBtn").onclick = () => {
    if (S.play) { clearInterval(S.play); S.play = null; $("playBtn").textContent = "▶ Reproducir"; return; }
    $("playBtn").textContent = "⏸ Pausa"; const sl = $("timeSlider"); if (+sl.value >= 1000) sl.value = 0;
    S.play = setInterval(() => { sl.value = Math.min(1000, +sl.value + 5); sl.oninput(); if (+sl.value >= 1000) $("playBtn").click(); }, 80);
  };
}
function sliderTime() { const v = +$("timeSlider").value; if (v >= 1000 || !S.mapSince) return null; const now = Date.now() / 1000; return S.mapSince + (now - S.mapSince) * v / 1000; }

// ── pestañas de datos ──────────────────────────────────────────────────────
function tableEl(cols, rows, rowCls) {
  return h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c[1])))),
    h("tbody", {}, rows.map((r) => h("tr", { class: rowCls ? rowCls(r) : null }, cols.map((c) => h("td", {}, c[2] ? c[2](r) : (r[c[0]] ?? "—")))))));
}
const matches = (obj, q) => !q || JSON.stringify(obj).toLowerCase().includes(q.toLowerCase());

async function loadSessions() {
  const rng = $("sessRange").value; const rows = await api("sessions", { limit: 500, since: rng ? Date.now() / 1000 - rng : null });
  const q = $("sessFilter").value;
  setKids($("sessionsTable"), tableEl([["started", "Inicio", (r) => ts(r.started)], ["ended", "Fin", (r) => r.ended ? ts(r.ended) : "activa"], ["duration", "Duración", (r) => dur(r.duration)],
    ["profile", "Perfil"], ["egress_iface", "Interfaz"], ["local_ip", "IP local"], ["wan_ip", "IP WAN"], ["public_ip", "IP pública"], ["vpn", "VPN"], ["proxy", "Proxy"],
    ["tor_exit", "Exit Tor", (r) => (r.tor_exit || "—").slice(0, 10)], ["country", "País"], ["fingerprint", "Huella"], ["end_reason", "Cierre"]],
  rows.filter((r) => matches(r, q)), (r) => r.ended ? "" : "active"));
}
async function loadCounters() {
  const rows = await api("counters", { layer: $("cntLayer").value || null }); const q = $("cntFilter").value;
  const sel = $("cntLayer"); if (sel.options.length <= 1) [...new Set(rows.map((r) => r.layer))].sort().forEach((l) => sel.append(h("option", { value: l }, l)));
  setKids($("countersTable"), tableEl([["layer", "Capa"], ["label", "Elemento"], ["country", "País"], ["asn", "ASN"], ["uses", "Usos"], ["total", "Tiempo total", (r) => dur(r.total)],
    ["current", "En curso", (r) => r.current ? dur(r.current) : "—"], ["first_seen", "Primer uso", (r) => ts(r.first_seen)], ["last_seen", "Último uso", (r) => ts(r.last_seen)]],
  rows.filter((r) => matches(r, q)), (r) => r.active ? "active" : ""));
}
async function loadTimeline() {
  const rows = await api("timeline", { limit: 1000 }); const q = $("tlFilter").value, sev = $("tlSev").value;
  const order = ["info", "low", "warning", "medium", "high", "critical"];
  setKids($("timelineList"), rows.filter((r) => matches(r, q) && (!sev || order.indexOf(r.severity) >= order.indexOf(sev))).map((r) => evLi({ ...r, kind: `${r.type}:${r.kind}` })));
}
async function loadRotation() {
  const r = await api("rotation_status");
  setKids($("rotationCards"), Object.entries(r.status).map(([layer, st]) => h("article", { class: "card" }, h("h2", {}, `${layer} · ${st.adapter}`),
    h("dl", { class: "kv" }, ...[["Automática", st.enabled ? "activada" : "desactivada"], ["Disponible", st.available ? "sí" : st.reason], ["Próxima", st.remaining != null ? dur(st.remaining) : "—"], ["Última hora", `${st.rotations_last_hour}/${st.max_per_hour}`],
      ...Object.entries(r.policies[layer] || {}).map(([k, v]) => [k, JSON.stringify(v)])].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
    h("div", { class: "toolbar" }, h("button", { onclick: () => doRotate(layer, true) }, "Simular (dry-run)"), h("button", { class: "danger", onclick: () => doRotate(layer, false) }, "Rotar ahora")))));
  if (!Object.keys(r.status).length) setKids($("rotationCards"), h("p", { class: "muted" }, "No hay adaptadores de rotación disponibles en este sistema."));
  setKids($("rotHistory"), tableEl([["ts", "Fecha", (x) => ts(x.ts)], ["layer", "Capa"], ["adapter", "Adaptador"], ["dry_run", "Dry-run", (x) => x.dry_run ? "sí" : "no"], ["from_target", "Desde"], ["to_target", "Hacia"],
    ["result", "Resultado"], ["detail", "Pasos", (x) => ((x.detail || {}).steps || []).map((p) => `${p.ok ? "✔" : "✘"}${p.name}${p.detail ? " (" + p.detail + ")" : ""}`).join(" · ")]], r.history));
}
async function doRotate(layer, dry) {
  if (!dry && !(await confirmBox(`¿Rotar ${layer} ahora? Se seguirá el ciclo seguro (verificación y rollback).`))) return;
  try { const r = await api("rotate", { layer, dry_run: dry, force: true }); toast(`Rotación ${layer}: ${r.result} — ${r.steps.map((p) => (p.ok ? "✔" : "✘") + p.name + (p.ok ? "" : ` (${p.detail})`)).join(" · ")}`, !["ok", "dry_run_ok"].includes(r.result)); }
  catch (e) { toast(e.message, true); }
  loadRotation(); refreshStatus();
}
async function loadProfiles() {
  const r = await api("profiles");
  const sel = $("profileSel"); sel.replaceChildren(...Object.keys(r.profiles).map((n) => h("option", { value: n, selected: n === r.active }, n)));
  setKids($("profilesList"), Object.entries(r.profiles).map(([n, p]) => h("article", { class: "card" }, h("h2", {}, n + (n === r.active ? " · activo" : "")),
    h("dl", { class: "kv" }, Object.entries(p).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, JSON.stringify(v))])),
    n === r.active ? null : h("button", { onclick: () => activate(n) }, "Activar"))));
  const c = await api("correlation");
  setKids($("correlation"), c.pairs.length ? c.pairs.map((p) => h("div", { class: `alert ${p.level === "high" ? "high" : p.level === "none" ? "info" : "medium"}` }, h("div", { class: "title" }, `${p.profiles.join(" ↔ ")} · riesgo ${p.level}`),
    p.risks.map((x) => h("div", { class: "meta" }, `${x.severity}: ${x.detail}`)))) : [h("p", { class: "muted" }, "No hay dos perfiles con historial para comparar.")], h("p", { class: "muted small" }, c.note));
}
async function genProfiles(write) {
  if (write && !(await confirmBox("¿Añadir los perfiles propuestos a tu config.toml? Los que ya existan no se tocan."))) return;
  try {
    const r = await api("profiles_generate", { write });
    setKids($("profileGen"), h("h2", {}, write ? "Perfiles añadidos" : "Perfiles propuestos para este sistema"),
      Object.entries(r.profiles).map(([n, p]) => h("div", { class: "alert info" }, h("div", { class: "title" }, n + (r.existing.includes(n) ? " (ya existe)" : "")),
        h("div", {}, p.description), h("div", { class: "meta" }, `Tor ${p.use_tor ? "sí" : "no"} · VPN ${p.require_vpn ? "obligatoria" : "opcional"} · kill-switch ${p.require_killswitch ? "obligatorio" : "opcional"} · DNS ${p.dns_policy} · prohibidos: ${p.forbidden_countries.join(", ") || "—"} · retención ${p.retention_days} d`),
        p._why.map((w) => h("div", { class: "meta" }, "· " + w)))),
      write ? h("p", {}, `Escritos en ${r.written.path}: ${r.written.written.join(", ") || "ninguno"}`) : h("pre", { class: "pre" }, r.toml));
    if (write) loadProfiles();
  } catch (e) { toast(e.message, true); }
}
async function activate(n) { try { await api("profile_activate", { name: n }); toast(`Perfil activo: ${n}`); loadProfiles(); refreshStatus(); } catch (e) { toast(e.message, true); } }

function bars(items, cls) {
  const max = Math.max(1, ...items.map((x) => x.seconds));
  return h("div", { class: "bars" }, items.map((x) => { const b = h("div", { class: "bar " + (cls || "") }); b.style.width = (100 * x.seconds / max) + "%"; return h("div", { class: "row" }, h("span", {}, x.label), h("div", {}, b), h("span", { class: "mono muted" }, dur(x.seconds))); }));
}
async function loadStats() {
  const r = await api("stats", { period: $("statsPeriod").value }); const an = await api("anomalies");
  const tech = Object.entries(r.time_by_technology).map(([k, v]) => ({ label: k, seconds: v }));
  setKids($("statsBody"),
    h("article", { class: "card" }, h("h2", {}, "Tiempo por tecnología"), bars(tech)),
    h("article", { class: "card" }, h("h2", {}, "País de salida"), r.time_by_country.length ? bars(r.time_by_country) : h("p", { class: "muted" }, "Sin IP pública comprobada en el periodo.")),
    h("article", { class: "card" }, h("h2", {}, "País del exit de Tor"), r.time_by_tor_country.length ? bars(r.time_by_tor_country, "tor") : h("p", { class: "muted" }, "Sin datos.")),
    h("article", { class: "card" }, h("h2", {}, "Rotaciones y fallos"), h("dl", { class: "kv" }, ...[["Total", r.rotations.total], ["Correctas", r.rotations.ok], ["Fallidas", r.rotations.failed], ["Por hora", r.rotations.per_hour], ["Fallos de conexión", r.connection_failures], ["Sesiones", r.sessions], ["Exposición directa", dur(r.direct_exposure_seconds)]].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))),
    h("article", { class: "card" }, h("h2", {}, "Reutilización"), Object.entries(r.reuse).flatMap(([l, items]) => items.length ? [h("div", {}, h("b", {}, l + ": "), items.map((i) => `${i.label}×${i.uses}`).join(", "))] : []).concat([h("p", { class: "muted small" }, "Elementos de identidad usados más de una vez en el periodo.")])),
    h("article", { class: "card" }, h("h2", {}, "Anomalías"), an.length ? an.map((a) => h("div", { class: `alert ${a.severity}` }, a.detail)) : h("p", { class: "muted" }, "Ninguna detectada.")));
}
async function loadAudit() {
  setKids($("auditBody"), h("p", { class: "muted" }, "Ejecutando auditoría…"));
  const a = await api("audit"); const caps = a.capabilities;
  setKids($("auditBody"),
    h("article", { class: "card" }, h("h2", {}, `Exposición ${a.summary.exposure.score}/100 (${a.summary.exposure.level})`), h("p", { class: "muted small" }, a.summary.exposure.disclaimer)),
    h("h2", {}, "Hallazgos"), a.findings.map(alertEl),
    h("h2", {}, "Matriz de capacidades"), tableEl([["area", "Área"], ["id", "Capacidad"], ["status", "Estado", (r) => h("span", { class: `status-${r.status}` }, r.status)], ["detail", "Detalle"]], caps),
    h("h2", {}, "Pruebas realizadas"), tableEl([["check", "Prueba"], ["mode", "Modo"], ["method", "Método"]], a.tests_performed),
    h("h2", {}, "Limitaciones de observabilidad"), h("ul", {}, a.limitations.map((l) => h("li", {}, l))),
    h("p", { class: "muted" }, a.storage.note));
}
async function exportData(fmt) {
  try {
    if (fmt === "html") { const r = await fetch("/api/export_html", { method: "POST", headers: { "X-VELA-Token": TOKEN, "Content-Type": "application/json" }, body: "{}" }); download("vela-informe.html", await r.text(), "text/html"); return; }
    const d = await api("export");
    if (fmt === "json") download("vela-export.json", JSON.stringify(d, null, 2), "application/json");
    else for (const k of ["sessions", "counters", "events", "rotations"]) {
      const rows = d[k]; if (!rows.length) continue; const keys = [...new Set(rows.flatMap(Object.keys))];
      const esc = (v) => { const t = typeof v === "object" && v !== null ? JSON.stringify(v) : (v ?? ""); return `"${String(t).replace(/"/g, '""')}"`; };
      download(`vela-${k}.csv`, [keys.join(","), ...rows.map((r) => keys.map((x) => esc(r[x])).join(","))].join("\n"), "text/csv");
    }
  } catch (e) { toast(e.message, true); }
}
async function runWebRTC() {
  const useStun = $("useStun").checked; const out = $("webrtcOut");
  if (!window.RTCPeerConnection) { setKids(out, h("p", {}, "Este navegador no expone RTCPeerConnection: WebRTC desactivado (no hay fuga por esta vía).")); return; }
  setKids(out, h("p", { class: "muted" }, "Recogiendo candidatos…"));
  const pc = new RTCPeerConnection({ iceServers: useStun ? [{ urls: $("stunUrl").value }] : [] }); const cands = [];
  pc.createDataChannel("x"); pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate); };
  await pc.setLocalDescription(await pc.createOffer());
  await new Promise((r) => setTimeout(r, useStun ? 5000 : 2500)); pc.close();
  try { const f = await api("webrtc_report", { candidates: cands, used_stun: useStun }); setKids(out, alertEl(f), h("pre", { class: "pre" }, cands.join("\n") || "sin candidatos")); }
  catch (e) { toast(e.message, true); }
}
async function loadConfig() {
  const c = await api("config_get"); $("cfgPath").textContent = c.path; $("cfgText").value = c.text || "# Sin config.toml: se aplican los valores por defecto.\n";
  $("cfgEffective").textContent = JSON.stringify(c.effective, null, 2);
}
async function saveConfig() {
  try { const r = await api("config_set", { text: $("cfgText").value }); $("cfgMsg").textContent = `Guardado. Cambios: ${r.changed.join(", ") || "ninguno"}`; loadConfig(); refreshStatus(); }
  catch (e) { $("cfgMsg").textContent = "Error: " + e.message; }
}

async function loadTab() {
  try {
    if (S.tab === "map") await loadMap();
    else if (S.tab === "sessions") await loadSessions();
    else if (S.tab === "counters") await loadCounters();
    else if (S.tab === "timeline") await loadTimeline();
    else if (S.tab === "rotation") await loadRotation();
    else if (S.tab === "profiles") await loadProfiles();
    else if (S.tab === "stats") await loadStats();
    else if (S.tab === "audit") await loadAudit();
    else if (S.tab === "config") await loadConfig();
    else if (S.tab === "dash") { S.map = await api("map"); renderStatus(); }
  } catch (e) { toast(e.message, true); }
}
function renderAll() { renderStatus(); if (S.tab === "map" && S.map) drawMap($("bigMap"), S.map, { time: sliderTime() }); }

async function main() {
  initToken(); initTheme(); initTabs(); initMap();
  $("panicBtn").onclick = async () => { if (await confirmBox("¿Activar el MODO EMERGENCIA? Detiene rotaciones y, si está permitido, bloquea conexiones no verificadas. No borra datos.")) { const r = await api("panic"); toast("Emergencia activada · kill-switch " + (r.killswitch.ok ? "aplicado" : "NO aplicado: " + r.killswitch.error), true); refreshStatus(); } };
  $("resumeBtn").onclick = async () => { await api("resume"); toast("Emergencia desactivada"); refreshStatus(); };
  $("profileSel").onchange = (e) => activate(e.target.value);
  for (const [id, fn] of [["sessFilter", loadSessions], ["sessRange", loadSessions], ["cntLayer", loadCounters], ["cntFilter", loadCounters], ["tlFilter", loadTimeline], ["tlSev", loadTimeline], ["statsPeriod", loadStats]]) $(id).addEventListener(id.endsWith("Filter") ? "input" : "change", fn);
  $("auditRun").onclick = loadAudit;
  $("leaksRun").onclick = async () => { const r = await api("leaks"); toast(`${r.filter((f) => f.status === "fail").length} fallos, ${r.filter((f) => f.status === "warn").length} avisos`); refreshStatus(); };
  $("exportJson").onclick = () => exportData("json"); $("exportCsv").onclick = () => exportData("csv"); $("exportHtml").onclick = () => exportData("html");
  $("genPreview").onclick = () => genProfiles(false); $("genWrite").onclick = () => genProfiles(true);
  $("webrtcRun").onclick = runWebRTC; $("cfgSave").onclick = saveConfig;
  if (!TOKEN) return;
  WORLD = await api("worldmap");
  await refreshStatus(); loadProfiles(); loadTab();
  setInterval(refreshStatus, 4000); setInterval(tickClock, 1000);
  setInterval(() => { if (["map", "counters", "sessions"].includes(S.tab) && !S.play) loadTab(); }, 20000);
  stream();
}
main();
