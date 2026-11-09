/* 공수 공진화 관제 대시보드 — 바닐라 SPA. 손으로 그린 SVG 차트(오프라인, 라이브러리 없음).
   라우팅=해시, 데이터=기존 로그 JSON API. 로그가 비면 예시 데이터로 렌더(배너 표시). */
(function () {
  "use strict";

  // ───────── 내비 구성(좌측 세로 탭, 5그룹) ─────────
  var NAV = [
    { group: "관제", items: [
      { id: "control", label: "실험 제어" },
      { id: "live", label: "실시간 관측" } ] },
    { group: "분석", items: [
      { id: "posture", label: "보안 태세 개요" },
      { id: "stats", label: "공수 통계" } ] },
    { group: "공격 관점", items: [
      { id: "attack-graph", label: "공격 추적 그래프", soon: true } ] },
    { group: "방어 관점", items: [
      { id: "defender-arch", label: "타깃 아키텍처", soon: true },
      { id: "defender-graph", label: "탐지·패치", soon: true } ] },
    { group: "기록", items: [
      { id: "events", label: "이벤트 로그" },
      { id: "report", label: "에피소드 보고서", soon: true } ] }
  ];
  var TITLES = { posture: "보안 태세 개요", stats: "공수 통계", control: "실험 제어",
    live: "실시간 관측", events: "이벤트 로그", "attack-graph": "공격 추적 그래프",
    "defender-arch": "타깃 아키텍처 (방어 관점)", "defender-graph": "탐지·패치 그래프",
    report: "에피소드 보고서" };
  var DEFAULT_ROUTE = "posture";
  var REAL = { posture: 1, stats: 1, control: 1, live: 1, events: 1 };  // 실데이터 렌더 라우트

  // ───────── 색 상수(의미색 — CSS 변수와 1:1) ─────────
  var C = { atk: "#e5484d", def: "#3b82f6", sys: "#64748b", crown: "#e5920b",
    ok: "#0ea371", teal: "#0d9488", grid: "#e3e8ee", muted: "#8a97ab" };
  var VERDICT = {
    blocked: { label: "진짜 차단", color: C.ok, cls: "b-ok" },
    fake_patch: { label: "가짜 패치", color: C.atk, cls: "b-atk" },
    not_blocked: { label: "여전히 취약", color: C.atk, cls: "b-atk" },
    inconclusive: { label: "검증 불능", color: C.sys, cls: "b-sys" }
  };

  // ───────── 상태 ─────────
  var S = { rounds: [], episodes: [], runs: [], events: [], status: {}, demo: false };
  var route = DEFAULT_ROUTE, evTab = "all";

  // ───────── 유틸 ─────────
  function $(sel, el) { return (el || document).querySelector(sel); }
  function h(html) { var t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function pct(x) { return (x == null || isNaN(x)) ? "—" : Math.round(x * 100) + "%"; }
  function num(x) { return (x == null || isNaN(x)) ? "—" : String(x); }
  function clamp(x, a, b) { return Math.max(a, Math.min(b, x)); }
  function hhmmss(ts) { if (!ts) return "—"; var d = new Date(ts * 1000);
    return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2) + ":" + ("0" + d.getSeconds()).slice(-2); }

  async function jget(path) {
    try { var r = await fetch(path, { cache: "no-store" }); if (!r.ok) return null; return await r.json(); }
    catch (e) { return null; }
  }

  // ───────── 예시 데이터(로그 비었을 때) ─────────
  function demoRounds() {
    var spec = [
      ["fake_patch", ["crown-secrets"], [1, 2, 3], [1, 0, 2], ["T1552.001", "T1078"]],
      ["fake_patch", ["crown-secrets"], [1, 2, 3], [2, 1, 1], ["T1078"]],
      ["blocked", [], [1, 2], [2, 1, 1], ["T1210"]],
      ["fake_patch", ["crown-secrets", "crown-pii"], [1, 2, 3], [3, 1, 1], ["T1210", "T1213"]],
      ["blocked", [], [1, 2, 3], [3, 1, 0], ["T1213"]],
      ["blocked", [], [1, 2], [3, 1, 0], []],
      ["inconclusive", [], [1], [3, 1, 0], []],
      ["blocked", [], [1, 2], [3, 1, 0], ["T1078"]]
    ];
    return spec.map(function (s, i) {
      return { episode: 1, round: i + 1, verdict: s[0], crowns_reached_cum: s[1],
        stages_reached: s[2], detection_cum: { tp: s[3][0], fp: s[3][1], fn: s[3][2] },
        reported_techniques: s[4], patch_applied: s[0] !== "inconclusive",
        healthcheck_passed: i !== 3, attack_end_reason: s[0] === "inconclusive" ? "deadend" : "flag",
        defense_end_reason: s[0] === "inconclusive" ? "skipped" : "patched",
        elapsed_attack_sec: 120 + i * 9, elapsed_defense_sec: 40 + i * 4,
        flags_reached_cum: s[2].map(String).concat(s[1]) };
    });
  }
  function demoEpisodes() {
    return [{ episode: 1, rounds: 8, end_reason: "consecutive_defense", max_flag_depth: 3,
      detection: { tp: 3, fp: 1, fn: 0, precision: 0.75, recall: 1.0 },
      mttd: { mean_rounds: 1.5, detected: 3, total_true: 3, detection_rate: 1.0 },
      verdict_counts: { blocked: 4, fake_patch: 3, inconclusive: 1 }, availability: 0.83,
      patches: 7, crowns_reached: ["crown-secrets", "crown-pii"], goals_reached: ["db_exfil"] }];
  }
  function demoEvents() {
    var out = [], base = Date.now() / 1000 - 400, A = "attacker", D = "defender", J = "judge";
    function e(t, actor, type, p) { out.push({ ts: base + t, episode: 1, round: 1 + Math.floor(t / 60), actor: actor, type: type, payload: p }); }
    e(2, A, "attack_step", { tool: "kubectl", args: ["get", "secrets", "-A"], success: true });
    e(9, A, "attack_step", { tool: "curl", args: ["http://internal-wiki/runbook"], success: true });
    e(14, A, "attack_step", { tool: "psql", args: ["-c", "select * from internal_secrets"], success: true, flag: true });
    e(16, A, "attack_turn", { end_reason: "flag", flags: 1, steps: 7 });
    e(70, D, "detection", { technique: "T1078", evidence: "admin-sa secret get", confidence: 0.7 });
    e(74, D, "patch", { detail: "delete rbac → internal [applied] admin-tools-binding 삭제", applied: true });
    e(78, D, "defense_turn", { patch_applied: true, detected: 1, patches: 1, healthcheck_passed: true });
    e(96, J, "verdict", { verdict: "fake_patch", method: "replay-crown", detail: "재생 후 크라운 재도달" });
    return out;
  }

  // ───────── 로드 ─────────
  async function loadCore() {
    var r = await Promise.all([jget("/api/rounds"), jget("/api/episodes"), jget("/api/runs")]);
    S.rounds = r[0] || []; S.episodes = r[1] || []; S.runs = r[2] || [];
    S.demo = (S.rounds.length === 0 && S.episodes.length === 0);
    if (S.demo) { S.rounds = demoRounds(); S.episodes = demoEpisodes(); }
  }

  // ───────── 집계(태세·통계) ─────────
  function agg() {
    var rs = S.rounds, decided = 0, blocked = 0, fake = 0, crownRounds = 0;
    rs.forEach(function (r) {
      var v = r.verdict;
      if (v === "blocked") { blocked++; decided++; }
      else if (v === "fake_patch" || v === "not_blocked") { fake++; decided++; }
      if ((r.crowns_reached_cum || []).length) crownRounds++;
    });
    var lastDet = null; for (var i = rs.length - 1; i >= 0; i--) { if (rs[i].detection_cum) { lastDet = rs[i].detection_cum; break; } }
    var recall = lastDet ? (lastDet.tp + lastDet.fn ? lastDet.tp / (lastDet.tp + lastDet.fn) : null) : null;
    var depth = 0; rs.forEach(function (r) { (r.stages_reached || []).forEach(function (s) { if (s > depth) depth = s; }); });
    S.episodes.forEach(function (e) { if (e.max_flag_depth > depth) depth = e.max_flag_depth; });
    var avail = null, ac = 0, an = 0; S.episodes.forEach(function (e) { if (e.availability != null) { ac += e.availability; an++; } });
    if (an) avail = ac / an;
    return { decided: decided, blocked: blocked, fake: fake, crownRounds: crownRounds, nrounds: rs.length,
      blockRate: decided ? blocked / decided : null, fakeRate: decided ? fake / decided : null,
      crownRate: rs.length ? crownRounds / rs.length : null, recall: recall, depth: depth,
      avail: avail, det: lastDet || { tp: 0, fp: 0, fn: 0 } };
  }
  // 공수 진화곡선: 라운드별 누적 차단율 / 가짜패치율
  function evolution() {
    var out = [], b = 0, f = 0, d = 0;
    S.rounds.forEach(function (r) {
      if (r.verdict === "blocked") { b++; d++; }
      else if (r.verdict === "fake_patch" || r.verdict === "not_blocked") { f++; d++; }
      out.push({ round: r.round, def: d ? b / d : 0, atk: d ? f / d : 0 });
    });
    return out;
  }

  // ───────── SVG 차트 ─────────
  function svg(w, hh, body) {
    return '<svg class="chart" viewBox="0 0 ' + w + ' ' + hh + '" preserveAspectRatio="xMidYMid meet" role="img">' + body + "</svg>";
  }
  function lineChart(series, xmax, opts) {
    opts = opts || {}; var w = 620, hh = 200, pad = { l: 34, r: 14, t: 14, b: 26 };
    var iw = w - pad.l - pad.r, ih = hh - pad.t - pad.b, ymax = opts.ymax || 1;
    var body = "";
    for (var g = 0; g <= 4; g++) { var gy = pad.t + ih * (g / 4), lv = ymax * (1 - g / 4);
      body += '<line x1="' + pad.l + '" y1="' + gy + '" x2="' + (w - pad.r) + '" y2="' + gy + '" stroke="' + C.grid + '" stroke-width="1"/>';
      body += '<text x="' + (pad.l - 6) + '" y="' + (gy + 3) + '" text-anchor="end" font-size="9">' + (opts.pct ? Math.round(lv * 100) : Math.round(lv * 10) / 10) + "</text>"; }
    function X(i) { return pad.l + (xmax <= 1 ? iw / 2 : iw * (i / (xmax - 1))); }
    function Y(v) { return pad.t + ih * (1 - clamp(v / ymax, 0, 1)); }
    series.forEach(function (s) {
      var pts = s.points.map(function (v, i) { return X(i) + "," + Y(v); }).join(" ");
      body += '<polyline points="' + pts + '" fill="none" stroke="' + s.color + '" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>';
      s.points.forEach(function (v, i) { body += '<circle cx="' + X(i) + '" cy="' + Y(v) + '" r="2.6" fill="' + s.color + '"/>'; });
      var li = s.points.length - 1; if (li >= 0) body += '<circle cx="' + X(li) + '" cy="' + Y(s.points[li]) + '" r="4" fill="' + s.color + '" stroke="#fff" stroke-width="1.5"/>';
    });
    for (var i2 = 0; i2 < xmax; i2++) if (xmax <= 12 || i2 % 2 === 0)
      body += '<text x="' + X(i2) + '" y="' + (hh - 8) + '" text-anchor="middle" font-size="9">' + (i2 + 1) + "</text>";
    return svg(w, hh, body);
  }
  function barChart(items, opts) {
    opts = opts || {}; var w = 300, hh = 180, pad = { l: 10, r: 10, t: 12, b: 34 };
    var iw = w - pad.l - pad.r, ih = hh - pad.t - pad.b;
    var mx = Math.max.apply(null, items.map(function (d) { return d.value; }).concat([1]));
    var bw = iw / items.length, body = "";
    items.forEach(function (d, i) {
      var bh = ih * (d.value / mx), x = pad.l + bw * i + bw * 0.16, y = pad.t + ih - bh, ww = bw * 0.68;
      body += '<rect x="' + x + '" y="' + y + '" width="' + ww + '" height="' + Math.max(bh, 1) + '" rx="4" fill="' + d.color + '"/>';
      body += '<text x="' + (x + ww / 2) + '" y="' + (y - 5) + '" text-anchor="middle" font-size="11" font-weight="700" fill="' + d.color + '">' + d.value + "</text>";
      body += '<text x="' + (x + ww / 2) + '" y="' + (hh - 18) + '" text-anchor="middle" font-size="9.5">' + esc(d.label) + "</text>";
      if (d.sub) body += '<text x="' + (x + ww / 2) + '" y="' + (hh - 6) + '" text-anchor="middle" font-size="8.5" fill="' + C.muted + '">' + esc(d.sub) + "</text>";
    });
    return svg(w, hh, body);
  }
  function gauge(v, color, label) {
    var w = 150, hh = 92, cx = 75, cy = 80, r = 60;
    function pt(a) { return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; }
    var a0 = Math.PI, a1 = Math.PI + Math.PI * clamp(v, 0, 1);
    function arc(end, col, wd) { var p0 = pt(a0), p1 = pt(end), large = (end - a0) > Math.PI ? 1 : 0;
      return '<path d="M' + p0[0] + ' ' + p0[1] + ' A' + r + ' ' + r + ' 0 ' + large + ' 1 ' + p1[0] + ' ' + p1[1] + '" fill="none" stroke="' + col + '" stroke-width="' + wd + '" stroke-linecap="round"/>'; }
    var body = arc(2 * Math.PI, C.grid, 9) + arc(a1, color, 9);
    body += '<text x="' + cx + '" y="' + (cy - 8) + '" text-anchor="middle" font-size="22" font-weight="700" fill="' + color + '">' + pct(v) + "</text>";
    if (label) body += '<text x="' + cx + '" y="' + (cy + 8) + '" text-anchor="middle" font-size="9.5">' + esc(label) + "</text>";
    return svg(w, hh, body);
  }
  function miniSpark(points, color) {
    if (!points.length) return "";
    var w = 120, hh = 30, mx = Math.max.apply(null, points.concat([1])), mn = Math.min.apply(null, points.concat([0]));
    var rng = (mx - mn) || 1;
    var pts = points.map(function (v, i) { return (points.length <= 1 ? w / 2 : w * i / (points.length - 1)) + "," + (hh - 3 - (hh - 6) * (v - mn) / rng); }).join(" ");
    return svg(w, hh, '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>');
  }

  // ───────── 페이지: 보안 태세 개요 ─────────
  function pagePosture() {
    var a = agg(), ev = evolution();
    var tiles = [
      { k: "크라운 반출", v: a.crownRounds + "회", sub: "전체 " + a.nrounds + "R 중 " + pct(a.crownRate), cls: a.crownRounds ? "accent-atk" : "accent-ok", dot: a.crownRounds ? C.atk : C.ok },
      { k: "진짜 차단율", v: pct(a.blockRate), sub: "BLOCKED / 판정 " + a.decided, cls: "accent-ok", dot: C.ok },
      { k: "가짜 패치율", v: pct(a.fakeRate), sub: "막은 척(보안 연극) " + a.fake + "건", cls: a.fake ? "accent-atk" : "accent-ok", dot: C.atk },
      { k: "가용성", v: pct(a.avail), sub: "패치 후 서비스 생존", cls: "accent-def", dot: C.def },
      { k: "탐지 재현율", v: pct(a.recall), sub: "놓친 공격(FN) " + a.det.fn + "건", cls: "accent-teal", dot: C.teal },
      { k: "최고 침투 깊이", v: a.depth ? "①→" + "①②③④"[a.depth - 1] : "—", sub: "킬체인 도달 단계", cls: "accent-crown", dot: C.crown }
    ];
    var tileHtml = tiles.map(function (t) {
      return '<div class="tile ' + t.cls + '"><div class="tile-k"><span class="tag-dot" style="background:' + t.dot + '"></span>' + t.k + '</div>' +
        '<div class="tile-v">' + t.v + '</div><div class="tile-sub">' + t.sub + "</div></div>";
    }).join("");

    var evoCard = '<div class="card"><div class="card-h">공수 진화곡선</div><div class="card-sub">라운드가 갈수록 공격·방어 성공률이 어떻게 갈리나 (누적)</div>' +
      lineChart([{ name: "방어", color: C.def, points: ev.map(function (e) { return e.def; }) },
        { name: "공격", color: C.atk, points: ev.map(function (e) { return e.atk; }) }], Math.max(ev.length, 1), { pct: true }) +
      '<div class="legend"><span><span class="tag-dot" style="background:' + C.def + '"></span>방어 성공률(진짜 차단)</span>' +
      '<span><span class="tag-dot" style="background:' + C.atk + '"></span>공격 성공률(가짜 패치)</span></div></div>';

    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, inconclusive: 0 };
    S.rounds.forEach(function (r) { if (vc[r.verdict] != null) vc[r.verdict]++; });
    var vcard = '<div class="card"><div class="card-h">판정 분포</div><div class="card-sub">리플레이 검증 결과 — 패치가 실제로 막았나</div>' +
      barChart([{ label: "차단", value: vc.blocked, color: C.ok }, { label: "가짜", value: vc.fake_patch, color: C.atk },
        { label: "불능", value: vc.inconclusive, color: C.sys }]) + "</div>";

    var hl = highlights();
    var hcard = '<div class="card"><div class="card-h">하이라이트</div><div class="card-sub">보안담당자가 먼저 봐야 할 사건</div>' +
      (hl.length ? hl.map(function (x) { return '<div class="hl-row"><span class="hl-ic" style="background:' + x.color + '"></span><div><div>' + x.text + '</div><div class="mono">' + x.meta + "</div></div></div>"; }).join("")
        : '<div class="tile-sub">특이 사건 없음</div>') + "</div>";

    var html = (S.demo ? demoBanner() : "") +
      '<p class="page-intro">실험이 지금 어떤 보안 태세를 만들고 있는지 한눈에. 크라운이 뚫렸나, 패치가 진짜 막았나, 우리가 공격을 놓쳤나.</p>' +
      '<div class="grid cols-6">' + tileHtml + "</div>" +
      '<div class="section-label">공수 추세</div>' + evoCard +
      '<div class="section-label">판정·사건</div><div class="grid cols-2">' + vcard + hcard + "</div>";
    return html;
  }
  function highlights() {
    var out = [];
    S.rounds.forEach(function (r) {
      if ((r.crowns_reached_cum || []).length && r.verdict === "fake_patch")
        out.push({ color: C.atk, text: "R" + r.round + ": 크라운 반출 후 패치가 막지 못함 (가짜 패치)", meta: "crown " + (r.crowns_reached_cum.join(", ")) + " · " + (r.reported_techniques || []).join(" ") });
      else if (r.verdict === "blocked" && (r.stages_reached || []).length >= 2)
        out.push({ color: C.ok, text: "R" + r.round + ": 공격을 실제로 차단", meta: "깊이 " + Math.max.apply(null, r.stages_reached) + " · 재현율 개선" });
    });
    return out.slice(0, 5);
  }

  // ───────── 페이지: 공수 통계 ─────────
  function pageStats() {
    var a = agg(), ev = evolution();
    var evoCard = '<div class="card"><div class="card-h">공수 진화곡선</div><div class="card-sub">누적 성공률 — 연구 핵심 그래프</div>' +
      lineChart([{ color: C.def, points: ev.map(function (e) { return e.def; }) }, { color: C.atk, points: ev.map(function (e) { return e.atk; }) }], Math.max(ev.length, 1), { pct: true }) +
      '<div class="legend"><span><span class="tag-dot" style="background:' + C.def + '"></span>방어</span><span><span class="tag-dot" style="background:' + C.atk + '"></span>공격</span></div></div>';

    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, inconclusive: 0 };
    S.rounds.forEach(function (r) { if (vc[r.verdict] != null) vc[r.verdict]++; });
    var vcard = '<div class="card"><div class="card-h">판정 분포</div><div class="card-sub">BLOCKED / FAKE_PATCH / 불능</div>' +
      barChart([{ label: "차단", value: vc.blocked, color: C.ok }, { label: "가짜", value: vc.fake_patch, color: C.atk }, { label: "불능", value: vc.inconclusive, color: C.sys }]) + "</div>";

    var dcard = '<div class="card"><div class="card-h">탐지 정확도</div><div class="card-sub">누적 TP / FP / FN (방어자 보고 vs god-view)</div>' +
      barChart([{ label: "정탐", value: a.det.tp, color: C.ok, sub: "TP" }, { label: "오탐", value: a.det.fp, color: C.crown, sub: "FP" }, { label: "미탐", value: a.det.fn, color: C.atk, sub: "FN" }]) +
      '<div class="tile-sub" style="margin-top:8px">재현율 ' + pct(a.recall) + ' · 미탐지 사각 ' + a.det.fn + "건 (방어 blind spot)</div></div>";

    var depth = S.rounds.map(function (r) { return (r.stages_reached || []).length ? Math.max.apply(null, r.stages_reached) : 0; });
    var fcard = '<div class="card"><div class="card-h">플래그 도달 깊이 추이</div><div class="card-sub">라운드별 공격자가 킬체인 어디까지</div>' +
      lineChart([{ color: C.crown, points: depth }], Math.max(depth.length, 1), { ymax: 4 }) + "</div>";

    return (S.demo ? demoBanner() : "") +
      '<p class="page-intro">공수 진화·판정·탐지 정확도·침투 깊이. 논문 그래프와 보안팀 관점을 같은 자리에.</p>' +
      evoCard + '<div class="section-label">판정 · 탐지 · 깊이</div><div class="grid cols-3">' + vcard + dcard + fcard + "</div>";
  }

  // ───────── 페이지: 실험 제어 ─────────
  function pageControl() {
    var running = !!(S.status && S.status.running);
    var runsRows = S.runs.length ? S.runs.map(function (r) {
      var p = r.params || {};
      return "<tr><td class='mono'>" + esc(r.id) + "</td><td>" + (r.status === "running" ? '<span class="badge b-ok">진행 중</span>' : '<span class="chip">완료</span>') +
        "</td><td class='mono'>" + (p.episodes || "?") + "ep · " + (p.max_rounds || "?") + "R · " + (p.time_limit || "?") + "s</td><td class='mono'>" + esc(r.mode || "") + "</td></tr>";
    }).join("") : "<tr><td colspan='4' class='tile-sub'>아직 실행한 런이 없습니다.</td></tr>";

    return '<p class="page-intro">실험 파라미터를 정해 오케스트레이터(VM C)를 시작·중지합니다. 진행 로그는 아래에 라이브로.</p>' +
      '<div class="card"><div class="card-h">새 실험 시작</div><div class="card-sub">시작 = 경기 시작. 이미 떠 있는 하네스를 호출합니다.</div>' +
      '<div class="form-row" style="margin-bottom:14px">' +
      field("에피소드", "f-eps", "number", 1) + field("최대 라운드", "f-mr", "number", 10) +
      field("시간 제한(초)", "f-tl", "number", 180) + field("max_tokens", "f-mt", "number", 1024) +
      '<div class="field"><label>모드</label><select id="f-mode"><option value="demo">데모</option><option value="stat">통계</option></select></div></div>' +
      '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">' +
      '<label class="toggle"><input type="checkbox" id="f-fresh"> 로그 초기화(fresh)</label>' +
      '<button class="btn btn-primary" id="btn-start"' + (running ? " disabled" : "") + '>▶ 시작</button>' +
      '<button class="btn btn-danger" id="btn-stop"' + (running ? "" : " disabled") + '>■ 중지</button>' +
      '<span class="tile-sub" id="ctl-msg"></span></div></div>' +
      '<div class="section-label">실행 로그 (run.out)</div>' +
      '<div class="card"><pre class="mono" id="run-log" style="margin:0;max-height:260px;overflow:auto;font-size:11.5px;color:var(--text-2);white-space:pre-wrap">로그 없음</pre></div>' +
      '<div class="section-label">런 레지스트리</div>' +
      '<div class="card" style="padding:0;overflow:hidden"><table class="tbl"><thead><tr><th>런 ID</th><th>상태</th><th>파라미터</th><th>모드</th></tr></thead><tbody>' + runsRows + "</tbody></table></div>";
  }
  function field(label, id, type, val) {
    return '<div class="field"><label for="' + id + '">' + label + '</label><input id="' + id + '" type="' + type + '" value="' + val + '"></div>';
  }
  function bindControl() {
    var start = $("#btn-start"), stop = $("#btn-stop"), msg = $("#ctl-msg");
    if (start) start.onclick = async function () {
      msg.textContent = "시작 요청…";
      var body = { episodes: +$("#f-eps").value, max_rounds: +$("#f-mr").value, time_limit: +$("#f-tl").value,
        max_tokens: +$("#f-mt").value, mode: $("#f-mode").value, fresh: $("#f-fresh").checked };
      var r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then(function (x) { return x.json(); }).catch(function () { return { ok: false, error: "서버 연결 실패(데모 모드)" }; });
      msg.textContent = r.ok ? "시작됨: " + r.id : "실패: " + (r.error || "");
      refreshRunStatus();
    };
    if (stop) stop.onclick = async function () {
      msg.textContent = "중지 요청…";
      await fetch("/api/run/stop", { method: "POST" }).catch(function () {});
      msg.textContent = "중지 요청 보냄"; refreshRunStatus();
    };
    refreshRunStatus();
  }
  async function refreshRunStatus() {
    var st = await jget("/api/run/status");
    var log = $("#run-log"); if (log && st && st.log) log.textContent = st.log.join("\n") || "로그 없음";
    var start = $("#btn-start"), stop = $("#btn-stop");
    if (start && st) start.disabled = !!st.running;
    if (stop && st) stop.disabled = !st.running;
  }

  // ───────── 페이지: 실시간 관측 ─────────
  var PHASES = ["초기화", "공격 턴", "방어 턴", "검증", "채점", "종료"];
  function pageLive() {
    var st = S.status || {}, running = !!st.running;
    if (!running && !S.demo && (!st.status || st.status === "idle"))
      return '<p class="page-intro">실시간으로 공격·방어·턴이 어떻게 오가는지 봅니다. 폴링 2.5초.</p>' +
        emptyState("⏸", "지금 도는 실험이 없습니다", "실험 제어에서 시작하면 여기서 단계·턴 예산·플래그 진행이 실시간으로 뜹니다.", [["events.jsonl", C.teal], ["progress.json", C.teal]]);

    var demo = S.demo ? { phase: 2, episode: 1, round: 4, active: "defender", turn_started: Date.now() / 1000 - 48, time_limit_sec: 180, last_verdict: "fake_patch", flags_reached: ["1", "2", "3"], crowns_reached: ["crown-secrets"] } : st;
    var ph = demo.phase || 0;
    var steps = PHASES.map(function (p, i) {
      var cls = i < ph ? "done" : (i === ph ? "active" : "");
      return '<div class="phase-step ' + cls + '"><span class="phase-n">' + i + '</span>' + p + "</div>";
    }).join("");
    var elapsed = demo.turn_started ? Math.round(Date.now() / 1000 - demo.turn_started) : 0;
    var budget = demo.time_limit_sec || 180, bp = clamp(elapsed / budget, 0, 1);
    var actor = demo.active === "attacker" ? '<span class="badge b-atk">공격자</span>' : demo.active === "defender" ? '<span class="badge b-def">방어자</span>' : '<span class="badge b-sys">심판</span>';
    var lv = demo.last_verdict ? VERDICT[demo.last_verdict] : null;

    return (S.demo ? demoBanner() : "") +
      '<p class="page-intro">지금 무엇이 오가는지. 2.5초마다 자동 갱신.</p>' +
      '<div class="card"><div class="card-h">루프 단계</div><div class="phases">' + steps + "</div></div>" +
      '<div class="grid cols-4" style="margin-top:14px">' +
      '<div class="tile accent-teal"><div class="tile-k">에피소드 · 라운드</div><div class="tile-v">' + (demo.episode || 0) + " · " + (demo.round || 0) + '</div></div>' +
      '<div class="tile"><div class="tile-k">활성 에이전트</div><div class="tile-v" style="font-size:18px;margin-top:12px">' + actor + '</div></div>' +
      '<div class="tile"><div class="tile-k">턴 경과 / 예산</div><div class="tile-v" style="font-size:20px">' + elapsed + "s<span style='font-size:12px;color:var(--text-3)'> / " + budget + 's</span></div><div class="progressbar"><span style="width:' + (bp * 100) + '%"></span></div></div>' +
      '<div class="tile"><div class="tile-k">직전 판정</div><div class="tile-v" style="font-size:16px;margin-top:12px">' + (lv ? '<span class="badge ' + lv.cls + '">' + lv.label + "</span>" : "—") + "</div></div></div>" +
      '<div class="section-label">진행도</div>' +
      '<div class="card"><div class="card-sub">god-view 누적 — 어느 플래그·크라운이 열렸나</div>' +
      '<div style="display:flex;gap:7px;flex-wrap:wrap">' +
      (["1", "2", "3", "4"].map(function (s) { var on = (demo.flags_reached || []).indexOf(s) >= 0; return '<span class="chip" style="' + (on ? "background:var(--crown-soft);color:#9a6a0c;border-color:#f3dca6" : "") + '">단계 ' + s + (on ? " ✓" : "") + "</span>"; }).join("")) +
      ((demo.crowns_reached || []).map(function (c) { return '<span class="badge b-atk">크라운 ' + esc(c) + "</span>"; }).join("")) +
      "</div></div>";
  }

  // ───────── 페이지: 이벤트 로그 ─────────
  async function loadEvents() { S.events = (await jget("/api/events")) || []; if (!S.events.length) S.events = demoEvents(); }
  function pageEvents() {
    var tabs = [["all", "전체"], ["attacker", "공격"], ["defender", "방어"], ["judge", "심판"]];
    var tabHtml = tabs.map(function (t) { return '<button class="tab ' + (evTab === t[0] ? "active" : "") + '" data-tab="' + t[0] + '">' + t[1] + "</button>"; }).join("");
    var evs = S.events.filter(function (e) { return evTab === "all" || e.actor === evTab; }).slice().reverse();
    var rows = evs.length ? evs.map(evRow).join("") : '<div class="tile-sub" style="padding:14px">이벤트 없음</div>';
    return (S.demo ? demoBanner() : "") +
      '<p class="page-intro">하네스별 행위를 한 줄씩 — 공격 명령·방어 탐지/패치·심판 판정이 시간순으로. 사건 재구성.</p>' +
      '<div class="tabs">' + tabHtml + "</div>" +
      '<div class="card" style="padding:6px 8px">' + rows + "</div>";
  }
  function evRow(e) {
    var map = { attack_step: ["b-atk", "명령"], attack_turn: ["b-atk", "공격턴"], detection: ["b-def", "탐지"],
      patch: ["b-def", "패치"], defense_turn: ["b-def", "방어턴"], verdict: ["b-sys", "판정"], planner_wave: ["b-atk", "플랜"] };
    var m = map[e.type] || ["b-sys", e.type]; var p = e.payload || {}, body = "";
    if (e.type === "attack_step") body = '<span class="mono">' + esc(p.tool) + " " + esc((p.args || []).join(" ")).slice(0, 90) + "</span>" + (p.flag ? ' <span class="badge b-crown">FLAG</span>' : p.success ? "" : ' <span class="badge b-sys">실패</span>');
    else if (e.type === "attack_turn") body = "공격 턴 종료 · " + esc(p.end_reason) + " · 플래그 " + num(p.flags) + " · 스텝 " + num(p.steps);
    else if (e.type === "detection") body = '추정 <b>' + esc(p.technique) + '</b> <span class="mono">' + esc((p.evidence || "")).slice(0, 70) + "</span>";
    else if (e.type === "patch") body = '<span class="mono">' + esc((p.detail || (p.kind + " → " + p.target))).slice(0, 90) + "</span>" + (p.applied ? ' <span class="badge b-ok">적용</span>' : ' <span class="badge b-sys">스킵</span>');
    else if (e.type === "defense_turn") body = "방어 턴 · 패치 " + (p.patch_applied ? "O" : "X") + " · 탐지 " + num(p.detected) + " · health " + (p.healthcheck_passed ? "O" : "X");
    else if (e.type === "verdict") { var v = VERDICT[p.verdict]; body = (v ? '<span class="badge ' + v.cls + '">' + v.label + "</span>" : esc(p.verdict)) + ' <span class="mono">' + esc((p.detail || "")).slice(0, 60) + "</span>"; }
    else body = '<span class="mono">' + esc(JSON.stringify(p)).slice(0, 90) + "</span>";
    return '<div class="ev-row"><span class="ev-ts">' + hhmmss(e.ts) + '</span><span class="ev-type ' + m[0] + '">' + m[1] + '</span><span class="ev-body">R' + (e.round || "?") + " · " + body + "</span></div>";
  }

  // ───────── 스텁(다음 단계) ─────────
  function pageStub(id) {
    var info = {
      "attack-graph": ["🕸", "공격 추적 그래프", "플래너·워커의 의도·사실·발견을 노드 그래프로. 노드 클릭 → 지식 그래프에서 기법 설명·문서 링크. 탐색 그래프를 VM A에서 당겨와 Cytoscape 로 그립니다.", [["graph bridge", C.atk], ["Cytoscape.js", C.teal]]],
      "defender-arch": ["🗺", "타깃 아키텍처 (방어 관점)", "방어 하네스가 대상을 훑어 재구성한 아키텍처 구성도를 자동 렌더. god-view 실제 도면이 아닌 '방어자가 본 지도' — 가시성 사각이 드러납니다. defense_topology 계측은 이미 심어뒀습니다.", [["defense_topology", C.def], ["자동 생성", C.teal]]],
      "defender-graph": ["🛡", "탐지·패치 그래프", "관측→탐지→패치 합성 그래프 + 순수 패치세트 큐레이션(패치마다 의도·연관). round_detail 의 detected/patch_set 을 읽습니다.", [["round_detail", C.def], ["합성 그래프", C.teal]]],
      "report": ["📄", "에피소드 보고서", "2계층 리포트 — 위=스토리(비전문가) / 아래=전문가 접힘. god-view↔방어추측 대조·리플레이 판정 분해. 에피소드 집계.", [["집계", C.crown], ["2계층", C.teal]]]
    }[id] || ["•", TITLES[id] || id, "준비 중입니다.", []];
    return '<p class="page-intro">다음 단계에서 제공됩니다. 데이터 계측(이벤트·라운드 상세·방어 토폴로지)은 백엔드에 이미 들어가 있어, 화면만 붙이면 됩니다.</p>' +
      emptyState(info[0], info[1], info[2], info[3]);
  }
  function emptyState(mark, title, desc, feeds) {
    return '<div class="empty"><div class="e-mark">' + mark + '</div><h3>' + esc(title) + "</h3><p>" + esc(desc) + "</p>" +
      (feeds && feeds.length ? '<div class="e-feeds">' + feeds.map(function (f) { return '<span class="chip"><span class="tag-dot" style="background:' + f[1] + '"></span>' + esc(f[0]) + "</span>"; }).join("") + "</div>" : "") + "</div>";
  }
  function demoBanner() { return '<div class="demo-banner"><b>예시 데이터</b> — 아직 실험 로그가 없어 샘플을 보여줍니다. 실험을 돌리면 실제 값으로 바뀝니다.</div>'; }

  // ───────── 렌더 ─────────
  async function render() {
    var view = $("#view"); $("#page-title").textContent = TITLES[route] || route;
    setActiveNav();
    if (route === "events") { await loadEvents(); view.innerHTML = pageEvents(); bindEventTabs(); return; }
    if (!REAL[route]) { view.innerHTML = pageStub(route); return; }
    if (route === "posture") view.innerHTML = pagePosture();
    else if (route === "stats") view.innerHTML = pageStats();
    else if (route === "control") { view.innerHTML = pageControl(); bindControl(); }
    else if (route === "live") view.innerHTML = pageLive();
  }
  function bindEventTabs() {
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (b) {
      b.onclick = function () { evTab = b.getAttribute("data-tab"); $("#view").innerHTML = pageEvents(); bindEventTabs(); };
    });
  }
  function setActiveNav() {
    Array.prototype.forEach.call(document.querySelectorAll(".nav-item"), function (a) {
      a.classList.toggle("active", a.getAttribute("data-route") === route);
    });
  }

  // ───────── 내비 빌드 ─────────
  function buildNav() {
    var nav = $("#nav"), html = "";
    NAV.forEach(function (g) {
      html += '<div class="nav-group-label">' + esc(g.group) + "</div>";
      g.items.forEach(function (it) {
        html += '<a class="nav-item" href="#' + it.id + '" data-route="' + it.id + '"><span class="ni-dot"></span><span class="ni-label">' + esc(it.label) + "</span>" + (it.soon ? '<span class="ni-soon">다음</span>' : "") + "</a>";
      });
    });
    nav.innerHTML = html;
  }

  // ───────── 라이브 상태 폴링(상단 pill + 연결 + live 페이지) ─────────
  async function poll() {
    var st = await jget("/api/status");
    var dot = $("#conn-dot"), ct = $("#conn-text");
    if (st === null) { dot.className = S.demo ? "" : "off"; ct.textContent = S.demo ? "데모 모드" : "서버 연결 끊김"; }
    else { S.status = st; dot.className = st.running ? "live" : ""; ct.textContent = st.running ? "실험 진행 중" : "대기"; }
    var pill = $("#run-pill"), pt = $("#run-pill-text");
    if (st && st.running) { pill.className = "run-pill running"; pt.textContent = "R" + (st.round || 0) + " · " + (PHASES[st.phase || 0] || ""); }
    else { pill.className = "run-pill"; pt.textContent = S.demo ? "데모" : "대기"; }
    if (route === "live") $("#view").innerHTML = pageLive();
    if (route === "control") refreshRunStatus();
  }

  // ───────── 라우팅·부팅 ─────────
  function onHash() {
    var r = (location.hash || "").replace(/^#/, "") || DEFAULT_ROUTE;
    if (!TITLES[r]) r = DEFAULT_ROUTE;
    route = r; closeSidebar(); render();
  }
  function closeSidebar() { $("#sidebar").classList.remove("open"); $("#nav-toggle").setAttribute("aria-expanded", "false"); }

  async function boot() {
    buildNav();
    $("#nav-toggle").onclick = function () {
      var sb = $("#sidebar"), open = sb.classList.toggle("open");
      this.setAttribute("aria-expanded", open ? "true" : "false");
    };
    window.addEventListener("hashchange", onHash);
    await loadCore();
    onHash();
    poll(); setInterval(poll, 2500);
  }
  boot();
})();
