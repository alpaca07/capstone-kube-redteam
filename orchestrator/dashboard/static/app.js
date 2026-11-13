/* 공격·방어 관제 대시보드 — 바닐라 SPA. 손으로 그린 SVG 차트(오프라인, 라이브러리 없음).
   라우팅=해시, 데이터=기존 로그 JSON API. 로그가 비면 예시 데이터로 렌더(배너 표시). */
(function () {
  "use strict";

  // ───────── 내비 구성(좌측 세로 탭, 5그룹) ─────────
  var NAV = [
    { group: "관제", items: [
      { id: "control", label: "실행 제어" },
      { id: "live", label: "실시간 현황" } ] },
    { group: "분석", items: [
      { id: "posture", label: "보안 현황" },
      { id: "stats", label: "공격·방어 통계" } ] },
    { group: "공격", items: [
      { id: "attack-graph", label: "공격 추적 그래프" },
      { id: "attack-log", label: "공격 저널" } ] },
    { group: "방어", items: [
      { id: "defender-arch", label: "타깃 구성도" },
      { id: "defender-graph", label: "탐지·패치 흐름" } ] },
    { group: "기록", items: [
      { id: "events", label: "이벤트 로그" },
      { id: "report", label: "회차 보고서" } ] }
  ];
  var TITLES = { posture: "보안 현황", stats: "공격·방어 통계", control: "실행 제어",
    live: "실시간 현황", events: "이벤트 로그", "attack-graph": "공격 추적 그래프", "attack-log": "공격 저널",
    "defender-arch": "타깃 구성도", "defender-graph": "탐지·패치 흐름",
    report: "회차 보고서" };
  var DEFAULT_ROUTE = "posture";
  var REAL = { posture: 1, stats: 1, control: 1, live: 1, events: 1, "defender-arch": 1, "defender-graph": 1, "attack-graph": 1, "attack-log": 1, report: 1 };

  // ───────── 색 상수(의미색 — CSS 변수와 1:1) ─────────
  var C = { atk: "#e5484d", def: "#3b82f6", sys: "#64748b", crown: "#e5920b",
    ok: "#0ea371", teal: "#0d9488", grid: "#e3e8ee", muted: "#8a97ab" };
  var VERDICT = {
    blocked: { label: "차단", color: C.ok, cls: "b-ok" },
    fake_patch: { label: "무효 패치", color: C.atk, cls: "b-atk" },
    not_blocked: { label: "미차단", color: C.atk, cls: "b-atk" },
    inconclusive: { label: "판정 불가", color: C.sys, cls: "b-sys" }
  };
  // 핵심 자산 식별자 → 쉬운 말
  // 크라운 라벨 — 알려진 2종만 친화명, 그 외는 실제 크라운 id(대상)를 그대로 노출(목표는 설정 주도).
  function crownLabel(c) {
    return ({ "crown-secrets": "내부 비밀 유출", "crown-pii": "고객정보 유출", "crown-ops": "운영 비밀 유출" })[c] ||
      (c ? String(c).replace(/^crown[-_]?/i, "") + " 유출" : "핵심정보 유출");
  }
  // 턴 종료 사유(enum) → 쉬운 말
  function reasonLabel(r) { return ({ flag: "목표 도달", deadend: "막다른 길", timeout: "시간 초과",
    budget: "예산 소진", max_steps: "명령 한도", error: "오류", patched: "패치 완료", skipped: "건너뜀" })[r] || r || "—"; }

  // ───────── 상태 ─────────
  var S = { rounds: [], episodes: [], runs: [], events: [], journal: [], status: {}, demo: false, runCount: 0, detItems: null };
  var route = DEFAULT_ROUTE, evTab = "all", defSel = null, repEp = null, agRkey = null, agSel = null, agTab = "overview", agLogView = "intent", evRun = null, jRun = null, agView = null, agLogOpen = null, _wasRunning = false;

  // ───────── 유틸 ─────────
  function $(sel, el) { return (el || document).querySelector(sel); }
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

  // ───────── 속성 블록 용어 설명(호버 툴팁) ─────────
  var TIP = {
    badge: {
      "차단": "검증 재생에서 공격이 핵심자산에 다시 도달하지 못함 — 패치가 실제로 막음",
      "무효 패치": "패치를 적용했으나 검증 재생에서 공격이 우회 — 실질적 차단 실패",
      "미차단": "패치 적용에도 공격이 그대로 도달함",
      "판정 불가": "재생 불가·근거 부족으로 차단 여부 미확정",
      "목표 획득": "이 명령으로 핵심자산(크라운)에 도달",
      "서비스 정상": "패치 후에도 서비스 헬스체크 통과", "서비스 중단": "패치로 서비스가 죽거나 헬스체크 실패",
      "정상": "서비스 헬스체크 통과", "중단": "서비스 헬스체크 실패",
      "적용": "방어자가 패치를 실제 적용함", "미적용": "패치를 적용하지 않음",
      "패치 적용": "방어자가 패치를 실제 적용함", "패치 미적용": "패치를 적용하지 않음",
      "공격": "공격자 턴 — 새 수 생성", "방어": "방어자 턴 — 관측·추론·패치", "심판": "검증·채점 주체",
      "진행 중": "이 실행이 현재 돌고 있음"
    },
    journal: {
      "성공": "명령이 정상 실행됨(종료코드 0)",
      "실패": "명령이 거부·차단·오류로 실패",
      "비결정": "재실행 시 결과가 달라질 수 있는 명령(시간·순서·외부 상태 의존)"
    },
    det: {
      "정탐": "실제 공격을 올바르게 탐지 (TP)",
      "오탐": "공격이 아닌데 공격으로 오인 (FP·오경보)",
      "미탐": "실제 공격을 탐지하지 못함 (FN·방어 공백)"
    },
    state: {
      "실행 중": "워커가 이 의도를 지금 수행 중", "차단": "이 의도가 경로 차단으로 중단됨",
      "완료": "이 의도를 끝까지 수행함",
      "대기": "아직 착수 전(프런티어 대기)", "중단": "외부 중지로 멈춤",
      "확인됨": "관측으로 확인된 사실", "포착": "침해 신호를 포착한 발견"
    }
  };
  var _TIP_SEL = ".badge, .chip, .jr-ok, .jr-fail, .jr-nd, .det-coll";
  function lookupTip(el) {
    var t = (el.textContent || "").trim();
    if (el.classList.contains("jr-ok") || el.classList.contains("jr-fail") || el.classList.contains("jr-nd")) return TIP.journal[t];
    if (el.classList.contains("det-coll")) return TIP.det[t] || TIP.badge[t];
    if (el.classList.contains("ag-state")) return TIP.state[t];
    if (el.classList.contains("badge")) return TIP.badge[t];
    if (el.classList.contains("chip")) return TIP.state[t] || TIP.badge[t];
    return null;
  }
  var _tipEl = null;
  function _tipNode() { if (!_tipEl) { _tipEl = document.createElement("div"); _tipEl.className = "uitip"; _tipEl.hidden = true; document.body.appendChild(_tipEl); } return _tipEl; }
  function showTip(el, text) {
    var tp = _tipNode(); tp.textContent = text; tp.hidden = false;
    var r = el.getBoundingClientRect(), tr = tp.getBoundingClientRect();
    var left = Math.max(8, Math.min(r.left + r.width / 2 - tr.width / 2, window.innerWidth - tr.width - 8));
    var top = r.top - tr.height - 8; if (top < 8) top = r.bottom + 8;
    tp.style.left = left + "px"; tp.style.top = top + "px";
  }
  function hideTip() { if (_tipEl) _tipEl.hidden = true; }

  // ───────── 예시 데이터(로그 비었을 때) ─────────
  function demoRounds() {
    function mk(ep, spec) {
      return spec.map(function (s, i) {
        return { episode: ep, round: i + 1, verdict: s[0], crowns_reached_cum: s[1],
          stages_reached: s[2], detection_cum: { tp: s[3][0], fp: s[3][1], fn: s[3][2] },
          reported_techniques: s[4], patch_applied: s[0] !== "inconclusive",
          healthcheck_passed: !(ep === 1 && i === 3), attack_end_reason: s[0] === "inconclusive" ? "deadend" : "flag",
          defense_end_reason: s[0] === "inconclusive" ? "skipped" : "patched",
          elapsed_attack_sec: 120 + i * 9, elapsed_defense_sec: 40 + i * 4,
          flags_reached_cum: s[2].map(String).concat(s[1]) };
      });
    }
    var ep1 = [
      ["fake_patch", ["crown-secrets"], [1, 2, 3], [1, 0, 1], ["T1552.001", "T1078"]],
      ["fake_patch", ["crown-secrets"], [1, 2, 3], [2, 0, 1], ["T1078"]],
      ["blocked", [], [1, 2], [2, 1, 2], ["T1210"]],
      ["fake_patch", ["crown-secrets", "crown-pii"], [1, 2, 3], [3, 1, 2], ["T1210", "T1213"]],
      ["blocked", [], [1, 2, 3], [3, 1, 3], ["T1213"]],
      ["blocked", [], [1, 2], [4, 1, 3], []],
      ["inconclusive", [], [1], [4, 1, 3], []],
      ["blocked", [], [1, 2], [5, 1, 3], ["T1078"]]
    ];
    var ep2 = [
      ["fake_patch", ["crown-secrets"], [1, 2, 3], [1, 0, 1], ["T1078"]],
      ["blocked", [], [1, 2], [2, 0, 1], ["T1210"]],
      ["blocked", [], [1, 2, 3], [3, 1, 1], ["T1078", "T1213"]],
      ["blocked", [], [1, 2], [3, 1, 2], []]
    ];
    return mk(1, ep1).concat(mk(2, ep2));
  }
  function demoEpisodes() {
    return [
      { episode: 1, rounds: 8, end_reason: "consecutive_defense", max_flag_depth: 3,
        detection: { tp: 3, fp: 1, fn: 0, precision: 0.75, recall: 1.0 },
        mttd: { mean_rounds: 1.5, detected: 3, total_true: 3, detection_rate: 1.0 },
        verdict_counts: { blocked: 4, fake_patch: 3, inconclusive: 1 }, availability: 0.83,
        patches: 7, crowns_reached: ["crown-secrets", "crown-pii"], goals_reached: ["db_exfil"] },
      { episode: 2, rounds: 4, end_reason: "consecutive_defense", max_flag_depth: 3,
        detection: { tp: 6, fp: 1, fn: 1, precision: 0.86, recall: 0.86 },
        mttd: { mean_rounds: 1.0, detected: 6, total_true: 7, detection_rate: 0.86 },
        verdict_counts: { blocked: 3, fake_patch: 1, inconclusive: 0 }, availability: 1.0,
        patches: 4, crowns_reached: ["crown-secrets"], goals_reached: ["db_exfil"] }
    ];
  }
  function demoEvents() {
    var out = [], base = Date.now() / 1000 - 400, A = "attacker", D = "defender", J = "judge";
    function e(t, actor, type, p) { out.push({ ts: base + t, episode: 1, round: 1 + Math.floor(t / 60), actor: actor, type: type, payload: p }); }
    e(2, A, "attack_step", { tool: "kubectl", args: ["get", "secrets", "-A"], success: true, intent: "관리용 계정 권한 악용", determinism: "deterministic" });
    e(5, A, "attack_step", { tool: "kubectl", args: ["auth", "can-i", "--list"], success: true, intent: "관리용 계정 권한 악용" });
    e(9, A, "attack_step", { tool: "curl", args: ["http://internal-wiki/runbook"], success: true, intent: "내부 위키 문서 수집", determinism: "nondeterministic" });
    e(11, A, "attack_step", { tool: "nmap", args: ["-p-", "backend"], success: false, intent: "백엔드 API 원격 취약점 탐색" });
    e(14, A, "attack_step", { tool: "psql", args: ["-h", "database.svc", "-c", "select * from customers"], success: true, flag: true, intent: "유출 접속정보로 DB 직접 연결" });
    e(16, A, "attack_turn", { end_reason: "flag", flags: 1, steps: 7 });
    e(70, D, "detection", { technique: "T1078", evidence: "admin-sa secret get", confidence: 0.7 });
    e(74, D, "patch", { detail: "delete rbac → internal [applied] admin-tools-binding 삭제", applied: true });
    e(78, D, "defense_turn", { patch_applied: true, detected: 1, patches: 1, healthcheck_passed: true });
    e(96, J, "verdict", { verdict: "fake_patch", method: "replay-crown", detail: "재생 후 내부 비밀 재유출" });
    return out;
  }
  function demoTopology() {
    return { generated: true, demo: true, namespaces: [
      { name: "frontend", has_network_policy: false, services: [{ name: "web", type: "NodePort", ports: [30080] }], deployments: [{ name: "web" }] },
      { name: "backend", has_network_policy: false, services: [{ name: "catalog-api", ports: [8000] }, { name: "order-api", ports: [8000] }, { name: "auth-service", ports: [8000] }], deployments: [{ name: "catalog-api" }, { name: "order-api" }] },
      { name: "internal", has_network_policy: false, services: [{ name: "admin-dashboard", ports: [80] }, { name: "internal-wiki", ports: [80] }], deployments: [{ name: "admin-dashboard" }] },
      { name: "database", has_network_policy: true, services: [{ name: "postgres", ports: [5432] }], deployments: [{ name: "postgres" }] }
    ] };
  }

  // ───────── 로드 ─────────
  // rounds.jsonl / episodes.jsonl 은 실행을 여러 번 돌리면 누적된다(fresh 안 쓰면).
  // 각 실행은 1회차 1라운드로 다시 시작하므로, 마지막 "1회차 1라운드" 이후가 최신 실행.
  function latestRunRounds(rs) {
    var s = 0;
    for (var i = 0; i < rs.length; i++) if ((rs[i].episode || 1) === 1 && (rs[i].round || 1) === 1) s = i;
    return rs.slice(s);
  }
  function latestRunEpisodes(es) {
    var s = 0;
    for (var i = 0; i < es.length; i++) if ((es[i].episode || 1) === 1) s = i;
    return es.slice(s);
  }
  async function loadCore() {
    var r = await Promise.all([jget("/api/rounds"), jget("/api/episodes"), jget("/api/runs")]);
    S.rounds = latestRunRounds(r[0] || []); S.episodes = latestRunEpisodes(r[1] || []); S.runs = r[2] || [];
    S.runCount = countRuns(r[0] || []);
    // 실행 중이면 데이터가 아직 없어도 데모로 빠지지 않음(집계 대기 상태를 보여줌)
    S.demo = (S.rounds.length === 0 && S.episodes.length === 0) && !(S.status && S.status.running);
    if (S.demo) { S.rounds = demoRounds(); S.episodes = demoEpisodes(); }
  }
  function countRuns(rs) {
    var n = 0;
    for (var i = 0; i < rs.length; i++) if ((rs[i].episode || 1) === 1 && (rs[i].round || 1) === 1) n++;
    return n;
  }

  // ───────── 집계(현황·통계) ─────────
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
  // 성공률 추세: 라운드별 누적 방어 성공률 / 공격 성공률
  function evolution() {
    var out = [], b = 0, f = 0, d = 0;
    S.rounds.forEach(function (r) {
      if (r.verdict === "blocked") { b++; d++; }
      else if (r.verdict === "fake_patch" || r.verdict === "not_blocked") { f++; d++; }
      out.push({ round: r.round, def: d ? b / d : 0, atk: d ? f / d : 0 });
    });
    return out;
  }
  function verdictCounts() {
    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, inconclusive: 0 };
    S.rounds.forEach(function (r) { if (vc[r.verdict] != null) vc[r.verdict]++; });
    return vc;
  }
  // 라운드 선택 칩 — 회차(에피소드)별로 묶어 구분. 키=에피소드-라운드. attr=선택용 데이터속성.
  function roundChipsHtml(rounds, selKey, attr) {
    var byEp = {}, order = [];
    rounds.forEach(function (r) { var e = r.episode || 1; if (!byEp[e]) { byEp[e] = []; order.push(e); } byEp[e].push(r); });
    order.sort(function (a, b) { return a - b; });
    var groups = order.map(function (e) {
      byEp[e].sort(function (a, b) { return a.round - b.round; });
      var chips = byEp[e].map(function (r) {
        var key = (r.episode || 1) + "-" + r.round, on = key === selKey;
        if (r._live)   // 진행 중 라운드 — 맥동 점으로 구분
          return '<button class="rchip rchip-live' + (on ? " on" : "") + '" ' + attr + '="' + key + '">' +
            '<span class="tag-dot ag-live-dot"></span>R' + r.round + " 진행</button>";
        var rv = VERDICT[r.verdict], col = rv ? rv.color : C.muted;
        return '<button class="rchip' + (on ? " on" : "") + '" ' + attr + '="' + key + '"' +
          (on ? ' style="border-color:' + col + ";color:" + col + '"' : "") +
          '><span class="tag-dot" style="background:' + col + '"></span>R' + r.round + "</button>";
      }).join("");
      var aggKey = "E" + e, aggOn = aggKey === selKey;   // 회차 종합 보기 선택 키
      var aggChip = '<button class="rchip rchip-agg' + (aggOn ? " on" : "") + '" ' + attr + '="' + aggKey + '">종합</button>';
      return '<span class="rchip-grp"><span class="rchip-ep">' + e + "회차</span>" + chips + aggChip + "</span>";
    }).join("");
    var note = (S.runCount > 1) ? '<span class="rchip-note">최신 실행만 표시 · 누적 ' + S.runCount + "회</span>" : "";
    return '<div class="rchips">' + groups + note + "</div>";
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
  function barChart(items) {
    var w = 300, hh = 180, pad = { l: 10, r: 10, t: 12, b: 34 };
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

  // ───────── 페이지: 보안 현황 ─────────
  function pagePosture() {
    var a = agg(), ev = evolution();
    var tiles = [
      { k: "핵심정보 유출", v: a.crownRounds + "회", sub: "전체 " + a.nrounds + "라운드 중 " + pct(a.crownRate), cls: a.crownRounds ? "accent-atk" : "accent-ok", dot: a.crownRounds ? C.atk : C.ok },
      { k: "공격 차단율", v: pct(a.blockRate), sub: "검증상 차단된 비율 (검증 " + a.decided + "건)", cls: "accent-ok", dot: C.ok },
      { k: "무효 패치율", v: pct(a.fakeRate), sub: "패치 적용에도 미차단 " + a.fake + "건", cls: a.fake ? "accent-atk" : "accent-ok", dot: C.atk },
      { k: "서비스 정상", v: pct(a.avail), sub: "패치 후 서비스 정상 비율", cls: "accent-def", dot: C.def },
      { k: "공격 탐지율", v: pct(a.recall), sub: "미탐 " + a.det.fn + "건", cls: "accent-teal", dot: C.teal },
      { k: "최대 침투 단계", v: a.depth ? a.depth + "단계" : "—", sub: "공격자 최대 도달 단계 (최대 4)", cls: "accent-crown", dot: C.crown }
    ];
    var tileHtml = tiles.map(function (t) {
      return '<div class="tile ' + t.cls + '"><div class="tile-k"><span class="tag-dot" style="background:' + t.dot + '"></span>' + t.k + '</div>' +
        '<div class="tile-v">' + t.v + '</div><div class="tile-sub">' + t.sub + "</div></div>";
    }).join("");

    var evoCard = '<div class="card"><div class="card-h">공격 성공률 vs 방어 성공률</div>' +
      lineChart([{ color: C.def, points: ev.map(function (e) { return e.def; }) },
        { color: C.atk, points: ev.map(function (e) { return e.atk; }) }], Math.max(ev.length, 1), { pct: true }) +
      '<div class="legend"><span><span class="tag-dot" style="background:' + C.def + '"></span>방어 성공 (차단)</span>' +
      '<span><span class="tag-dot" style="background:' + C.atk + '"></span>공격 성공 (패치 우회)</span></div></div>';

    var vcard = verdictCard();

    var hl = highlights();
    var hcard = '<div class="card"><div class="card-h">주요 사건</div>' +
      (hl.length ? hl.map(function (x) { return '<div class="hl-row"><span class="hl-ic" style="background:' + x.color + '"></span><div><div>' + x.text + '</div><div class="mono">' + x.meta + "</div></div></div>"; }).join("")
        : '<div class="tile-sub">특이 사건 없음</div>') + "</div>";

    return (S.demo ? demoBanner() : "") +
      '<div class="grid cols-6">' + tileHtml + "</div>" +
      '<div class="section-label">성공률 추세</div>' + evoCard +
      '<div class="section-label">검증 결과 · 주요 사건</div><div class="grid cols-2">' + vcard + hcard + "</div>";
  }
  function highlights() {
    var out = [];
    S.rounds.forEach(function (r) {
      if ((r.crowns_reached_cum || []).length && r.verdict === "fake_patch")
        out.push({ color: C.atk, text: "R" + r.round + ": 패치 적용에도 핵심정보 유출 — 무효 패치",
          meta: (r.crowns_reached_cum.map(crownLabel).join(", ")) + " · " + (r.reported_techniques || []).join(" ") });
      else if (r.verdict === "blocked" && (r.stages_reached || []).length >= 2)
        out.push({ color: C.ok, text: "R" + r.round + ": 공격 차단 확인",
          meta: "침투 " + Math.max.apply(null, r.stages_reached) + "단계에서 차단" });
    });
    return out.slice(0, 5);
  }

  // ───────── 페이지: 공격·방어 통계 ─────────
  function pageStats() {
    var a = agg(), ev = evolution();
    var evoCard = '<div class="card"><div class="card-h">공격 성공률 vs 방어 성공률</div>' +
      lineChart([{ color: C.def, points: ev.map(function (e) { return e.def; }) }, { color: C.atk, points: ev.map(function (e) { return e.atk; }) }], Math.max(ev.length, 1), { pct: true }) +
      '<div class="legend"><span><span class="tag-dot" style="background:' + C.def + '"></span>방어</span><span><span class="tag-dot" style="background:' + C.atk + '"></span>공격</span></div></div>';

    var vcard = verdictCard();

    var dcard = detectionCard();

    var depth = S.rounds.map(function (r) { return (r.stages_reached || []).length ? Math.max.apply(null, r.stages_reached) : 0; });
    var fcard = '<div class="card"><div class="card-h">침투 단계 추이</div>' +
      lineChart([{ color: C.crown, points: depth }], Math.max(depth.length, 1), { ymax: 4 }) + "</div>";

    return (S.demo ? demoBanner() : "") +
      evoCard +
      '<div class="section-label">탐지 정확도 · 미탐 추적</div>' + dcard +
      '<div class="section-label">검증 · 침투 단계</div><div class="grid cols-2">' + vcard + fcard + "</div>";
  }
  // ── 드릴 차트(막대 호버 → 발생 라운드 팝업 → 상세보기 점프). 탐지·검증 공용, 카드별 스코프 ──
  function drillCard(opts) {
    var cats = opts.cats, counts = opts.counts;
    var mx = Math.max.apply(null, [1].concat(cats.map(function (c) { return counts[c[0]] || 0; })));
    var colsHtml = cats.map(function (c) {
      var v = counts[c[0]] || 0, h = Math.round((v / mx) * 96) + 6;
      return '<div class="det-col" data-drill="' + c[0] + '" tabindex="0">' +
        '<div class="det-colbar"><span style="height:' + h + 'px;background:' + c[2] + '"></span></div>' +
        '<div class="det-colv" style="color:' + c[2] + '">' + v + "</div>" +
        '<div class="det-coll">' + c[1] + '</div><div class="det-cols">' + c[3] + "</div></div>";
    }).join("");
    return '<div class="card det-card" data-drillcard="' + opts.id + '"><div class="card-h">' + opts.title + "</div>" +
      '<div class="det-wrap"><div class="det-colrow">' + colsHtml + "</div>" +
      '<div class="det-pop">' + opts.hint + "</div></div>" +
      (opts.footer ? '<div class="tile-sub" style="margin-top:10px">' + opts.footer + "</div>" : "") + "</div>";
  }
  function bindDrill() {
    S.drillSel = S.drillSel || {};
    Array.prototype.forEach.call(document.querySelectorAll("[data-drillcard]"), function (card) {
      var id = card.getAttribute("data-drillcard"), cfg = (S.drill || {})[id];
      if (!cfg) return;
      var pop = card.querySelector(".det-pop");
      function fill(cat) {                      // 클릭 시 열림 — 선택 유지(재렌더에도)
        S.drillSel[id] = cat;
        Array.prototype.forEach.call(card.querySelectorAll(".det-col"), function (c) { c.classList.toggle("on", c.getAttribute("data-drill") === cat); });
        var arr = (cfg.items || {})[cat] || [], tot = arr.reduce(function (s, x) { return s + (x.delta || 1); }, 0);
        pop.innerHTML = '<div class="det-pop-h">' + cfg.names[cat] + " · " + tot + "건</div>" +
          (arr.length ? arr.map(function (x) {
            return '<div class="det-pop-row"><span class="det-pop-r">' + (x.ep > 1 ? x.ep + "-" : "") + "R" + x.round + "</span>" +
              '<span class="det-pop-t">' + (x.delta ? "+" + x.delta + "건" : "") + "</span>" +
              '<button class="det-pop-btn" data-jump="' + x.ep + "-" + x.round + '" data-sec="' + cfg.section + '">상세보기</button></div>';
          }).join("") : '<div class="tile-sub">해당 라운드 없음</div>');
        Array.prototype.forEach.call(pop.querySelectorAll("[data-jump]"), function (b) {
          b.onclick = function () { defSel = b.getAttribute("data-jump"); S.defJumpSection = b.getAttribute("data-sec"); S.defSig = null; location.hash = "defender-graph"; };
        });
      }
      Array.prototype.forEach.call(card.querySelectorAll(".det-col"), function (col) {
        var cat = col.getAttribute("data-drill");
        col.onclick = function () { fill(cat); };
        col.onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fill(cat); } };
      });
      if (S.drillSel[id] != null) fill(S.drillSel[id]);   // 재렌더 후 선택 복원
    });
  }
  // 탐지 혼동행렬 — 범주별 '발생 라운드'를 누적값 증분으로(추가 조회 없이). 막대 합계=팝업 항목 합(공식 누적).
  function detectionItemsFromDeltas() {
    var out = { tp: [], fp: [], fn: [] }, prevEp = null, prev = { tp: 0, fp: 0, fn: 0 };
    S.rounds.forEach(function (r) {
      var ep = r.episode || 1;
      if (ep !== prevEp) { prev = { tp: 0, fp: 0, fn: 0 }; prevEp = ep; }    // 탐지 누적은 회차마다 리셋
      var c = r.detection_cum || {};
      ["tp", "fp", "fn"].forEach(function (k) { var d = (c[k] || 0) - (prev[k] || 0); if (d > 0) out[k].push({ ep: ep, round: r.round, delta: d }); });
      prev = { tp: c.tp || 0, fp: c.fp || 0, fn: c.fn || 0 };
    });
    return out;
  }
  function detectionTotals() {
    var byEp = {}, out = { tp: 0, fp: 0, fn: 0 };
    S.rounds.forEach(function (r) { byEp[r.episode || 1] = r.detection_cum || {}; });
    Object.keys(byEp).forEach(function (e) { var c = byEp[e]; out.tp += c.tp || 0; out.fp += c.fp || 0; out.fn += c.fn || 0; });
    return out;
  }
  function detectionCard() {
    var counts = detectionTotals(), recall = (counts.tp + counts.fn) ? counts.tp / (counts.tp + counts.fn) : null;
    var hint = '<div class="det-pop-hint">막대를 클릭하면 발생 라운드가 표시됩니다 · 상세보기 → 해당 라운드 탐지 근거</div>';
    S.drill = S.drill || {};
    S.drill.detection = { items: detectionItemsFromDeltas(), names: { tp: "정탐", fp: "오탐", fn: "미탐" }, section: "detect", hint: hint };
    return drillCard({ id: "detection", title: "공격 탐지 정확도", hint: hint,
      cats: [["tp", "정탐", C.ok, "실제 공격 식별"], ["fp", "오탐", C.crown, "오경보"], ["fn", "미탐", C.atk, "공격 미식별"]],
      counts: counts, footer: "탐지율 " + pct(recall) + " · 미탐 " + counts.fn + "건 (방어 공백)" });
  }
  // 검증 판정 — 라운드 단위라 범주별 발생 라운드가 바로 나온다(델타 불필요).
  function verdictItemsFromRounds() {
    var out = { blocked: [], fake: [], inconclusive: [] };
    S.rounds.forEach(function (r) {
      var k = r.verdict === "blocked" ? "blocked" : (r.verdict === "fake_patch" || r.verdict === "not_blocked") ? "fake" : r.verdict === "inconclusive" ? "inconclusive" : null;
      if (k) out[k].push({ ep: r.episode || 1, round: r.round });
    });
    return out;
  }
  function verdictCard() {
    var items = verdictItemsFromRounds();
    var counts = { blocked: items.blocked.length, fake: items.fake.length, inconclusive: items.inconclusive.length };
    var dec = counts.blocked + counts.fake;
    var hint = '<div class="det-pop-hint">막대를 클릭하면 해당 판정 라운드가 표시됩니다 · 상세보기 → 해당 라운드 검증 근거</div>';
    S.drill = S.drill || {};
    S.drill.verdict = { items: items, names: { blocked: "차단", fake: "무효 패치", inconclusive: "판정 불가" }, section: "verify", hint: hint };
    return drillCard({ id: "verdict", title: "검증 결과", hint: hint,
      cats: [["blocked", "차단", C.ok, "실질 차단"], ["fake", "무효 패치", C.atk, "패치 우회"], ["inconclusive", "판정 불가", C.sys, "미확정"]],
      counts: counts, footer: "차단율 " + pct(dec ? counts.blocked / dec : null) + " · 무효 패치 " + counts.fake + "건" });
  }

  // ───────── 페이지: 실행 제어 ─────────
  // 모드 = 파라미터 프리셋. 데모=짧은 1회차 시연, 통계=여러 회차 반복 수집.
  var MODES = { demo: { eps: 1, mr: 4, tl: 120, mt: 1024 }, stat: { eps: 10, mr: 10, tl: 180, mt: 1024 } };
  // 타깃 = 공격 목표(orchestrator --objective-mode/--target-assets). om/ta 가 null 이면 config 기본(ShopFlow).
  var TARGETS = {
    "default":  { label: "config 기본(ShopFlow)", om: null,    ta: null },
    "corp-pii": { label: "corp · 고객 PII",        om: "asset", ta: "crown-pii" },
    "corp-ops": { label: "corp · 운영 비밀",       om: "asset", ta: "crown-ops" },
    "corp-all": { label: "corp · 전체(PII+운영)",  om: "asset", ta: "crown-pii,crown-ops" }
  };
  function pageControl() {
    var running = !!(S.status && S.status.running);
    var runsRows = S.runs.length ? S.runs.map(function (r) {
      var p = r.params || {};
      return "<tr><td class='mono'>" + esc(r.id) + "</td><td>" + (r.status === "running" ? '<span class="badge b-ok">진행 중</span>' : '<span class="chip">완료</span>') +
        "</td><td class='mono'>" + (p.episodes || "?") + "회차 · " + (p.max_rounds || "?") + "라운드 · " + (p.time_limit || "?") + "s" + (p.target && p.target !== "(config)" ? " · " + esc(p.target) : "") + "</td><td class='mono'>" + esc(({ demo: "데모", stat: "통계" })[r.mode] || r.mode || "") + "</td></tr>";
    }).join("") : "<tr><td colspan='4' class='tile-sub'>아직 실행 기록이 없습니다.</td></tr>";

    return '<div class="card"><div class="card-h">새 실행 시작</div>' +
      '<div class="form-row" style="margin-bottom:14px">' +
      field("회차 수", "f-eps", "number", 1) + field("회차당 최대 라운드", "f-mr", "number", 4) +
      field("턴 제한시간(초)", "f-tl", "number", 120) +
      '<div class="field"><label for="f-mt">생성 토큰 상한</label><div class="mt-wrap"><input id="f-mt" type="number" value="1024"><label class="toggle mt-unl"><input type="checkbox" id="f-mt-unl"> 무제한</label></div></div>' +
      '<div class="field"><label>모드</label><select id="f-mode"><option value="demo">데모</option><option value="stat">통계</option></select></div>' +
      '<div class="field"><label>타깃</label><select id="f-target">' + Object.keys(TARGETS).map(function (k) { return '<option value="' + k + '">' + esc(TARGETS[k].label) + '</option>'; }).join("") + '</select></div></div>' +
      '<div class="tile-sub" style="margin:-4px 0 12px">모드 = 파라미터 프리셋(데모/통계) · 타깃 = 공격 목표(ShopFlow 기본 / corp 크라운) · 선택 후 값 직접 수정 가능</div>' +
      '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">' +
      '<label class="toggle"><input type="checkbox" id="f-fresh"> 이전 실행 보관 후 새로 시작</label>' +
      '<button class="btn btn-primary" id="btn-start"' + (running ? " disabled" : "") + '>▶ 시작</button>' +
      '<button class="btn btn-danger" id="btn-stop"' + (running ? "" : " disabled") + '>■ 중지</button>' +
      '<span class="tile-sub" id="ctl-msg"></span></div></div>' +
      '<div class="section-label">실행 로그</div>' +
      '<div class="card"><pre class="mono" id="run-log" style="margin:0;max-height:260px;overflow:auto;font-size:11.5px;color:var(--text-2);white-space:pre-wrap">로그 없음</pre></div>' +
      '<div class="section-label">실행 기록</div>' +
      '<div class="card" style="padding:0;overflow:hidden"><table class="tbl"><thead><tr><th>실행 ID</th><th>상태</th><th>조건</th><th>모드</th></tr></thead><tbody>' + runsRows + "</tbody></table></div>";
  }
  function field(label, id, type, val) {
    return '<div class="field"><label for="' + id + '">' + label + '</label><input id="' + id + '" type="' + type + '" value="' + val + '"></div>';
  }
  function bindControl() {
    var start = $("#btn-start"), stop = $("#btn-stop"), msg = $("#ctl-msg");
    var unl = $("#f-mt-unl");
    if (unl) unl.onchange = function () { var inp = $("#f-mt"); if (inp) { inp.disabled = unl.checked; inp.style.opacity = unl.checked ? 0.45 : 1; } };
    var mode = $("#f-mode");
    if (mode) mode.onchange = function () {       // 모드 선택 → 파라미터 프리셋 자동 세팅
      var m = MODES[mode.value]; if (!m) return;
      $("#f-eps").value = m.eps; $("#f-mr").value = m.mr; $("#f-tl").value = m.tl;
      if (unl) unl.checked = false;
      var mt = $("#f-mt"); if (mt) { mt.disabled = false; mt.style.opacity = 1; mt.value = m.mt; }
    };
    if (start) start.onclick = async function () {
      msg.textContent = "시작 요청…";
      var _tg = TARGETS[(($("#f-target") || {}).value)] || {};
      var body = { episodes: +$("#f-eps").value, max_rounds: +$("#f-mr").value, time_limit: +$("#f-tl").value,
        max_tokens: ($("#f-mt-unl") && $("#f-mt-unl").checked) ? null : +$("#f-mt").value, mode: $("#f-mode").value,
        objective_mode: _tg.om || null, target_assets: _tg.ta || null, fresh: $("#f-fresh").checked };
      var r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then(function (x) { return x.json(); }).catch(function () { return { ok: false, error: "서버 연결 실패(데모 모드)" }; });
      msg.textContent = r.ok ? ("시작됨: " + r.id + (r.archived ? " · 이전 실행 보관됨" : "")) : "실패: " + (r.error || "");
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
    var msg = $("#ctl-msg");    // 외부(CLI) 실행 감지 표기 — 사용자 동작 메시지가 없을 때만
    if (msg && st && st.external && !msg.textContent) msg.textContent = "외부(CLI) 실행 감지 — 여기서 중지 가능";
  }

  // ───────── 페이지: 실시간 현황 ─────────
  var PHASES = ["초기화", "공격 차례", "방어 차례", "검증", "채점", "종료"];
  function pageLive() {
    var st = S.status || {}, running = !!st.running;
    if (!running && !S.demo && (!st.status || st.status === "idle"))
      return emptyState("⏸", "진행 중인 실행이 없습니다", "실행 제어에서 시작하면 진행 단계·잔여 시간·공격 진행이 실시간으로 표시됩니다.", []);

    var useDemo = S.demo && !running;   // 실제 실행 중이면 데모 아닌 실시간 상태 사용
    var demo = useDemo ? { phase: 2, episode: 1, round: 4, active: "defender", turn_started: Date.now() / 1000 - 48, time_limit_sec: 180, last_verdict: "fake_patch", flags_reached: ["1", "2", "3"], crowns_reached: ["crown-secrets"] } : st;
    var ph = demo.phase || 0;
    var steps = PHASES.map(function (p, i) {
      var cls = i < ph ? "done" : (i === ph ? "active" : "");
      return '<div class="phase-step ' + cls + '"><span class="phase-n">' + i + '</span>' + p + "</div>";
    }).join("");
    var elapsed = demo.turn_started ? Math.round(Date.now() / 1000 - demo.turn_started) : 0;
    var budget = demo.time_limit_sec || 180, bp = clamp(elapsed / budget, 0, 1);
    var actor = demo.active === "attacker" ? '<span class="badge b-atk">공격</span>' : demo.active === "defender" ? '<span class="badge b-def">방어</span>' : '<span class="badge b-sys">심판</span>';
    var lv = demo.last_verdict ? VERDICT[demo.last_verdict] : null;

    return (useDemo ? demoBanner() : "") +
      '<div class="card"><div class="card-h">진행 단계</div><div class="phases">' + steps + "</div></div>" +
      '<div class="grid cols-4" style="margin-top:14px">' +
      '<div class="tile accent-teal"><div class="tile-k">회차 · 라운드</div><div class="tile-v">' + (demo.episode || 0) + " · " + (demo.round || 0) + '</div></div>' +
      '<div class="tile"><div class="tile-k">지금 차례</div><div class="tile-v" style="font-size:18px;margin-top:12px">' + actor + '</div></div>' +
      '<div class="tile"><div class="tile-k">턴 경과 / 제한</div><div class="tile-v" style="font-size:20px">' + elapsed + "s<span style='font-size:12px;color:var(--text-3)'> / " + budget + 's</span></div><div class="progressbar"><span style="width:' + (bp * 100) + '%"></span></div></div>' +
      '<div class="tile"><div class="tile-k">직전 결과</div><div class="tile-v" style="font-size:16px;margin-top:12px">' + (lv ? '<span class="badge ' + lv.cls + '">' + lv.label + "</span>" : "—") + "</div></div></div>" +
      '<div class="section-label">공격 진행</div>' +
      '<div class="card">' +
      '<div style="display:flex;gap:7px;flex-wrap:wrap">' +
      (["1", "2", "3", "4"].map(function (s) { var on = (demo.flags_reached || []).indexOf(s) >= 0; return '<span class="chip" style="' + (on ? "background:var(--crown-soft);color:#9a6a0c;border-color:#f3dca6" : "") + '">' + s + "단계" + (on ? " ✓" : "") + "</span>"; }).join("")) +
      ((demo.crowns_reached || []).map(function (c) { return '<span class="badge b-atk">' + esc(crownLabel(c)) + "</span>"; }).join("")) +
      "</div></div>";
  }

  // ───────── 페이지: 타깃 구성도 (방어 시점) ─────────
  async function loadTopology() {
    var topo = null;
    if (!S.demo && S.rounds.length) {
      var last = S.rounds[S.rounds.length - 1];
      var r = await jget("/api/topology/" + (last.episode || 1) + "/" + (last.round || 1));
      if (r && r.topology) topo = r.topology;
    }
    return (topo && topo.namespaces && topo.namespaces.length) ? topo : demoTopology();
  }
  function pageArch(topo) {
    var crownNs = { database: 1, internal: 1, "corp-crown": 1 };
    var nss = topo.namespaces || [];
    var zones = nss.map(function (ns) {
      var exposed = !ns.has_network_policy, crown = crownNs[ns.name];
      var chips = (ns.services || []).map(function (s) {
        var ext = (s.type === "NodePort" || s.type === "LoadBalancer");
        return '<span class="svc-chip' + (ext ? " ext" : "") + '">' + esc(s.name) +
          (s.ports && s.ports.length ? '<span class="svc-port">:' + esc(s.ports.join(",")) + "</span>" : "") +
          (ext ? ' <span class="svc-tag">외부 노출</span>' : "") + "</span>";
      }).join("");
      return '<div class="zone' + (crown ? " crown" : "") + '">' +
        '<div class="zone-h"><span class="zone-name">' + esc(ns.name) + "</span>" +
        '<span class="zone-bd ' + (exposed ? "open" : "closed") + '">' + (exposed ? "경계 없음" : "경계 있음") + "</span></div>" +
        '<div class="zone-body">' + (chips || '<span class="tile-sub">보이는 서비스 없음</span>') + "</div>" +
        (crown ? '<div class="zone-crown">★ 핵심 자산 영역</div>' : "") + "</div>";
    }).join("");
    var openCount = nss.filter(function (n) { return !n.has_network_policy; }).length;
    var crownCount = nss.filter(function (n) { return crownNs[n.name]; }).length;
    return (topo.demo ? demoBanner() : "") +
      '<div class="grid cols-4" style="margin-bottom:6px">' +
      '<div class="tile"><div class="tile-k">영역 수</div><div class="tile-v">' + nss.length + '개</div><div class="tile-sub">네임스페이스</div></div>' +
      '<div class="tile accent-atk"><div class="tile-k">경계 없는 영역</div><div class="tile-v">' + openCount + '개</div><div class="tile-sub">가로막는 규칙 없음 = 열림</div></div>' +
      '<div class="tile accent-crown"><div class="tile-k">핵심 자산 영역</div><div class="tile-v">' + crownCount + '개</div><div class="tile-sub">최종 탈취 목표</div></div>' +
      '<div class="tile accent-def"><div class="tile-k">총 서비스</div><div class="tile-v">' + nss.reduce(function (a, n) { return a + (n.services || []).length; }, 0) + '개</div></div>' +
      "</div>" +
      '<div class="section-label">영역 구성 (네임스페이스별)</div>' +
      '<div class="arch">' + zones + "</div>" +
      '<div class="legend"><span><span class="tag-dot" style="background:' + C.def + '"></span>서비스</span><span><span class="tag-dot" style="background:' + C.atk + '"></span>외부 노출 / 경계 없음</span><span><span class="tag-dot" style="background:' + C.ok + '"></span>경계 있음</span><span><span class="tag-dot" style="background:' + C.crown + '"></span>핵심 자산 영역</span></div>';
  }

  // ───────── 페이지: 탐지·패치 흐름 (방어 시점) ─────────
  var DEMO_TECH = {
    "T1078": { ev: "admin-sa 서비스어카운트로 secrets get 다수 호출", pk: "rbac", pt: "internal/admin-tools-binding", ps: "과다 권한 롤바인딩 삭제" },
    "T1552.001": { ev: "파드에 마운트된 시크릿 파일 직접 접근", pk: "secret", pt: "default/db-cred", ps: "노출된 시크릿 회전" },
    "T1210": { ev: "backend 서비스 포트 스캔 후 원격 악용 시도", pk: "networkpolicy", pt: "backend", ps: "동서 트래픽 차단(수신 제한)" },
    "T1213": { ev: "internal-wiki 런북 페이지 열람", pk: "networkpolicy", pt: "internal", ps: "wiki 접근 출처 제한" }
  };
  function patchKindLabel(k) { return ({ networkpolicy: "네트워크 차단", rbac: "권한(RBAC)", secret: "비밀/크리덴셜", config: "설정", image: "이미지", resource: "리소스 제한" })[k] || k || "패치"; }
  // 패치 조치 효과(전 → 후) — 종류별 보안 태세 변화. 실제 리소스 YAML 전/후 스냅샷은 하네스가 남기지
  // 않으므로(패치는 manifest_ref 식별자만 전달), 종류·대상 기반의 의미적 전/후를 제시한다.
  function patchBeforeAfter(p) {
    var k = String(p.kind || "").toLowerCase(), s = String(p.summary || ""), tgt = p.target || "대상";
    if (/pod.?security|psa|baseline/.test(k + " " + s)) return ["PodSecurity 승인 제어 없음 — privileged·hostPath 파드 허용", "enforce=baseline — 특권·hostPath 파드 생성 차단"];
    if (/파드.*삭제|delete\s+pod|pod\b.*delete/.test(s)) return ["침해·탈출 파드 상주 — 공격 발판 유지", "파드 삭제 — 공격 발판 제거"];
    var map = {
      networkpolicy: ["인그레스 제약 없음 — 모든 네임스페이스·티어에서 접근 가능", "NetworkPolicy 적용 — 허용 티어(backend·internal)만 인그레스, 그 외 차단"],
      rbac: ["과도권한 바인딩 유효 — " + tgt + "가 광범위 권한 보유", "바인딩 제거 — 과도권한 회수"],
      secret: ["유출된 비밀이 그대로 유효", "비밀 회전·폐기 — 탈취 자격증명 무력화"],
      config: ["취약 설정값 운영 중", "하드닝 설정(ConfigMap) 적용·재기동"],
      image: ["취약 이미지 태그 구동 중", "패치 이미지로 교체"],
      resource: ["리소스 제한 없음 — 남용 가능", "리소스 제한(limit/quota) 적용"]
    };
    return map[k] || ["조치 전 — " + tgt + " 취약 상태", s || "방어 조치 적용"];
  }
  function stillLabel(f) { return ("" + f).indexOf("crown") === 0 ? crownLabel(f) : "flag " + f; }

  function demoDetail(rec) {
    var techs = rec.reported_techniques || [];
    var detected = techs.map(function (t) { var m = DEMO_TECH[t] || {}; return { technique: t, evidence: m.ev || "의심 행위 관측", confidence: 0.55 + (t.length % 3) * 0.12 }; });
    var patch_set = techs.map(function (t) { var m = DEMO_TECH[t] || {}; return { kind: m.pk || "config", target: m.pt || "-", summary: m.ps || "설정 보강", manifest_ref: "patches/" + (m.pk || "config") + "-r" + rec.round + ".yaml" }; });
    if (!patch_set.length && rec.verdict !== "inconclusive") patch_set = [{ kind: "networkpolicy", target: "internal", summary: "기본 격리 정책 보강", manifest_ref: "patches/netpol-r" + rec.round + ".yaml" }];
    var attempts = patch_set.map(function (p) { return p.kind + " → " + p.target + " [applied] " + p.summary; });
    var still = (rec.verdict === "fake_patch" || rec.verdict === "not_blocked") ? (rec.crowns_reached_cum || []).slice() : [];
    var detail = rec.verdict === "blocked" ? "재생 시 핵심자산 재도달 실패 — 차단 확인"
      : (rec.verdict === "fake_patch" || rec.verdict === "not_blocked") ? "재생 시 패치 우회로 핵심자산 재유출 — 무효 패치"
      : "재생 불가·근거 부족으로 판정 보류";
    var summary = "웨이브 2 · 탐지 " + detected.length + "건 · 침해 보고 " + (rec.crowns_reached_cum || []).length + "건";
    return {
      episode: rec.episode, round: rec.round,
      attack: { end_reason: rec.attack_end_reason, attack_summary: summary, flags_obtained: (rec.flags_reached_cum || []).map(function (f) { return { flag_id: f }; }) },
      defense: (rec.verdict === "inconclusive" && !patch_set.length) ? null : {
        patch_applied: rec.patch_applied, end_reason: rec.defense_end_reason,
        detected: detected, patch_set: patch_set, healthcheck_passed: rec.healthcheck_passed, patch_attempts: attempts, patch_note: ""
      },
      verification: { verdict: rec.verdict, method: "replay-crown(재생 검증)", detail: detail, flags_still_reachable: still, post: { flags_reached: still } }
    };
  }

  async function pageDefGraphRender() {
    var view = $("#view"), rounds = S.rounds;
    if (!rounds.length) {
      view.innerHTML = '<p class="page-intro">방어자가 라운드마다 무엇을 탐지하고 패치했는지, 검증에서 실제 차단되었는지 확인합니다.</p>' +
        emptyState("🛡", "아직 방어 기록이 없습니다", "실행하면 라운드별 탐지 → 패치 → 검증 흐름이 여기 나타납니다.", []);
      return;
    }
    if (defSel != null && /^E\d+$/.test(defSel)) {        // 회차 종합 — 라운드 요약표
      var aep = parseInt(defSel.slice(1), 10);
      var ars = rounds.filter(function (r) { return (r.episode || 1) === aep; });
      var asig = "AGG" + aep + "|" + ars.map(function (r) { return r.round + ":" + r.verdict + ":" + (r.patch_applied ? 1 : 0) + ":" + (r.healthcheck_passed ? 1 : 0); }).join(",");
      if (route !== "defender-graph") return;
      if (asig === S.defSig && document.querySelector(".def-ep-tbl")) return;
      S.defSig = asig;
      view.innerHTML = pageDefEpisode(aep, rounds);
      bindDefChips();
      return;
    }
    var idx = defSel != null ? rounds.map(function (r) { return (r.episode || 1) + "-" + r.round; }).indexOf(defSel) : rounds.length - 1;
    if (idx < 0) idx = rounds.length - 1;
    var rec = rounds[idx], detail;
    if (S.demo) detail = demoDetail(rec);
    else { var d = await jget("/api/round/" + (rec.episode || 1) + "/" + rec.round); detail = (d && (d.defense || d.verification)) ? d : demoDetail(rec); }
    if (route !== "defender-graph") return;
    S.defDetail = detail; S.defRec = rec;
    var dd = detail.defense || {}, dv = detail.verification || {};
    var sig = rounds.length + "|" + (rec.episode || 1) + "-" + rec.round + "|" + (dd.detected || []).length + "|" + (dd.patch_set || []).length + "|" + (dv.verdict || "");
    if (sig === S.defSig && document.querySelector(".flow")) return;   // 변화 없으면 재렌더 생략(폴링 깜빡임 방지)
    S.defSig = sig;
    view.innerHTML = pageDefGraph(detail, rec, rounds, idx);
    bindDefChips();
    if (S.defJumpSection) { var js = S.defJumpSection; S.defJumpSection = null; defOpenModal(js); }   // 통계에서 점프 시 해당 섹션 상세 자동 오픈
  }
  function bindDefChips() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-rkey]"), function (b) {
      b.onclick = function () { defSel = b.getAttribute("data-rkey"); pageDefGraphRender(); };
    });
    var more = document.querySelector("[data-defmore]");
    if (more) more.onclick = function () { defOpenModal("all"); };
    Array.prototype.forEach.call(document.querySelectorAll("[data-defsec]"), function (b) {
      b.onclick = function () { defOpenModal(b.getAttribute("data-defsec")); };
    });
  }
  function defEsc(e) { if (e.key === "Escape") closeDefModal(); }
  function closeDefModal() { var m = document.querySelector(".modal-ov"); if (m) m.remove(); document.removeEventListener("keydown", defEsc); }
  function bindDefModal() {
    var ov = document.querySelector(".modal-ov");
    if (!ov) return;
    ov.onclick = function (e) { if (e.target === ov) closeDefModal(); };
    Array.prototype.forEach.call(ov.querySelectorAll(".modal-x"), function (b) { b.onclick = closeDefModal; });
    document.addEventListener("keydown", defEsc);
  }
  function defModalHtml(detail, rec, section) {
    detail = detail || {}; section = section || "all";
    var d = detail.defense || {}, v = detail.verification || {}, a = detail.attack || {};
    var det = d.detected || [], ps = d.patch_set || [], atts = d.patch_attempts || [];
    var vv = v.verdict ? VERDICT[v.verdict] : null, still = v.flags_still_reachable || [], post = v.post || {};
    function sec(t, b) { return '<div class="md-sec"><div class="md-st">' + t + "</div>" + b + "</div>"; }

    var atkBody = (a.attack_summary ? '<pre class="md-pre">' + esc(a.attack_summary) + "</pre>" : '<div class="tile-sub">공격 요약 없음</div>') +
      (a.end_reason ? '<div class="rep-line"><span class="rep-k">공격 종료</span><span>' + esc(reasonLabel(a.end_reason)) + "</span></div>" : "");

    var detBody = det.length ? det.map(function (x) {
      var conf = x.confidence != null ? Math.round(x.confidence * 100) + "%" : "—";
      return '<div class="md-item"><div class="fi-head">' + (x.technique ? '<span class="badge b-def">' + esc(x.technique) + "</span>" : '<span class="chip">기법 미상</span>') + '<span class="fi-conf">확신도 ' + conf + "</span></div>" +
        '<div class="md-ev mono">' + esc(x.evidence || "—") + "</div></div>";
    }).join("") : '<div class="tile-sub">미탐 — 공격 미식별</div>';

    var psBody = (ps.length ? ps.map(function (p) {
      var ba = patchBeforeAfter(p);
      return '<div class="md-item"><div class="fi-head"><span class="badge b-def">' + esc(patchKindLabel(p.kind)) + '</span><span class="fi-tgt mono">' + esc(p.target || "") + "</span></div>" +
        '<div class="md-ev">' + esc(p.summary || "—") + "</div>" +
        '<div class="pba"><div class="pba-c pba-before"><span class="pba-k">패치 전</span><span class="pba-v">' + esc(ba[0]) + "</span></div>" +
        '<div class="pba-arrow">→</div>' +
        '<div class="pba-c pba-after"><span class="pba-k">패치 후</span><span class="pba-v">' + esc(ba[1]) + "</span></div></div>" +
        (p.manifest_ref ? '<div class="fi-tgt mono">매니페스트: ' + esc(p.manifest_ref) + "</div>" : "") + "</div>";
    }).join("") : '<div class="tile-sub">적용한 패치 없음</div>') +
      (atts.length ? '<div class="md-st2">패치 시도 로그</div>' + atts.map(function (s) { return '<div class="md-ev mono">· ' + esc(s) + "</div>"; }).join("") : "") +
      (d.patch_note ? '<div class="md-ev mono" style="color:var(--text-3)">메모: ' + esc(d.patch_note) + "</div>" : "") +
      '<div class="flow-foot" style="border:none;padding-top:10px">' +
      (d.patch_applied ? '<span class="badge b-ok">패치 적용</span>' : '<span class="badge b-sys">패치 미적용</span>') +
      (d.healthcheck_passed ? '<span class="badge b-ok">서비스 정상</span>' : '<span class="badge b-atk">서비스 중단</span>') +
      (d.end_reason ? '<span class="chip">' + esc(reasonLabel(d.end_reason)) + "</span>" : "") + "</div>" +
      (d.error ? '<div class="md-ev mono" style="color:var(--atk)">오류: ' + esc(d.error) + "</div>" : "");

    var vBody = (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : "") +
      '<div class="md-ev">' + esc(v.detail || "—") + "</div>" +
      (v.method ? '<div class="rep-line"><span class="rep-k">검증 방식</span><span class="mono">' + esc(v.method) + "</span></div>" : "") +
      (still.length ? '<div class="rep-line"><span class="rep-k">재유출 가능</span><span style="color:var(--atk)">' + still.map(stillLabel).join(", ") + "</span></div>" : "") +
      ((post.flags_reached || []).length ? '<div class="rep-line"><span class="rep-k">재생 재도달</span><span class="mono">' + post.flags_reached.map(stillLabel).join(", ") + "</span></div>" : "");

    var title = ({ all: "상세 · 판단 근거", detect: "탐지 상세", patch: "패치 상세", verify: "검증 상세" })[section] || "상세";
    var secs;
    if (section === "detect") secs = sec("탐지 (" + det.length + "건)", detBody);
    else if (section === "patch") secs = sec("패치", psBody);
    else if (section === "verify") secs = sec("검증 결과", vBody);
    else secs = sec("① 공격 요약", atkBody) + sec("② 탐지 (" + det.length + "건)", detBody) + sec("③ 패치", psBody) + sec("④ 검증 결과", vBody);
    return '<div class="modal-ov" role="dialog" aria-modal="true"><div class="modal">' +
      '<div class="modal-h"><span>' + (rec ? (rec.episode || 1) + "회차 R" + rec.round : "") + " · " + title + '</span><button class="modal-x" aria-label="닫기">✕</button></div>' +
      '<div class="modal-body">' + secs + "</div></div></div>";
  }
  // 섹션별/전체 상세 모달 열기(중복 방지)
  function defOpenModal(section) {
    if (document.querySelector(".modal-ov")) return;
    var wrap = document.createElement("div");
    wrap.innerHTML = defModalHtml(S.defDetail, S.defRec, section);
    if (wrap.firstElementChild) { document.body.appendChild(wrap.firstElementChild); bindDefModal(); }
  }
  // 회차 종합 — 라운드별 탐지·패치·검증 요약표 + 회차 집계(추가 조회 없이 rounds.jsonl 만으로).
  function pageDefEpisode(ep, rounds) {
    var rs = rounds.filter(function (r) { return (r.episode || 1) === ep; });
    var chips = roundChipsHtml(rounds, "E" + ep, "data-rkey");
    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, inconclusive: 0 }, patched = 0, maxDepth = 0;
    rs.forEach(function (r) { if (vc[r.verdict] != null) vc[r.verdict]++; if (r.patch_applied) patched++; (r.stages_reached || []).forEach(function (s) { if (s > maxDepth) maxDepth = s; }); });
    var last = rs[rs.length - 1] || {}, det = last.detection_cum || { tp: 0, fp: 0, fn: 0 }, fake = vc.fake_patch + vc.not_blocked;
    var tiles = [
      ["라운드", rs.length + "회", "", C.teal, "accent-teal"],
      ["차단", vc.blocked + "회", "무효 패치 " + fake + "회", C.ok, "accent-ok"],
      ["미탐", det.fn + "건", "정탐 " + det.tp + " · 오탐 " + det.fp, det.fn ? C.atk : C.ok, det.fn ? "accent-atk" : "accent-ok"],
      ["패치 적용", patched + "/" + rs.length, "라운드", C.def, "accent-def"],
      ["최고 침투", maxDepth + "단계", "최대 4", C.crown, "accent-crown"]
    ].map(function (t) { return '<div class="tile ' + t[4] + '"><div class="tile-k"><span class="tag-dot" style="background:' + t[3] + '"></span>' + t[0] + '</div><div class="tile-v">' + t[1] + "</div>" + (t[2] ? '<div class="tile-sub">' + t[2] + "</div>" : "") + "</div>"; }).join("");
    var rows = rs.map(function (r) {
      var vv = VERDICT[r.verdict], depth = (r.stages_reached || []).length ? Math.max.apply(null, r.stages_reached) : 0, ndet = (r.reported_techniques || []).length;
      return '<tr class="clickable" data-rkey="' + (r.episode || 1) + "-" + r.round + '"><td class="mono">R' + r.round + "</td>" +
        "<td>" + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : esc(r.verdict)) + "</td>" +
        '<td class="mono">' + ndet + "건</td>" +
        "<td>" + (r.patch_applied ? '<span class="badge b-ok">적용</span>' : '<span class="badge b-sys">미적용</span>') + "</td>" +
        '<td class="mono">' + depth + "단계</td>" +
        "<td>" + (r.healthcheck_passed ? '<span class="badge b-ok">정상</span>' : '<span class="badge b-atk">중단</span>') + "</td></tr>";
    }).join("");
    return (S.demo ? demoBanner() : "") + chips +
      '<div class="section-label">' + ep + "회차 종합 · 집계</div>" +
      '<div class="grid cols-5" style="margin-bottom:6px">' + tiles + "</div>" +
      '<div class="section-label">라운드별 탐지 · 패치 · 검증</div>' +
      '<div class="card" style="padding:0;overflow:hidden"><table class="tbl def-ep-tbl"><thead><tr><th>라운드</th><th>판정</th><th>탐지</th><th>패치</th><th>침투</th><th>서비스</th></tr></thead><tbody>' + rows + "</tbody></table></div>" +
      '<div class="tile-sub" style="margin-top:10px">라운드 행을 클릭하면 해당 라운드 상세 흐름으로 이동합니다.</div>';
  }
  function pageDefGraph(detail, rec, rounds, idx) {
    var d = detail.defense || {}, v = detail.verification || {};
    var det = d.detected || [], ps = d.patch_set || [];
    var vv = v.verdict ? VERDICT[v.verdict] : null;

    var chips = roundChipsHtml(rounds, (rec.episode || 1) + "-" + rec.round, "data-rkey");

    var detHtml = det.length ? det.map(function (x) {
      var conf = x.confidence != null ? Math.round(x.confidence * 100) : null;
      return '<div class="flow-item"><div class="fi-head">' + (x.technique ? '<span class="badge b-def">' + esc(x.technique) + "</span>" : '<span class="chip">기법 미상</span>') + (conf != null ? '<span class="fi-conf">확신도 ' + conf + "%</span>" : "") + "</div>" +
        '<div class="fi-ev mono">' + esc(x.evidence || "—") + "</div>" + (conf != null ? '<div class="conf-bar"><span style="width:' + conf + '%"></span></div>' : "") + "</div>";
    }).join("") : '<div class="flow-empty">미탐 — 이 라운드 공격 미식별</div>';

    var psHtml = ps.length ? ps.map(function (p) {
      return '<div class="flow-item"><div class="fi-head"><span class="badge b-def">' + esc(patchKindLabel(p.kind)) + '</span><span class="fi-tgt mono">' + esc(p.target || "") + "</span></div>" +
        '<div class="fi-ev">' + esc(p.summary || "—") + "</div></div>";
    }).join("") : '<div class="flow-empty">적용한 패치 없음</div>';
    var psFoot = detail.defense ? '<div class="flow-foot">' + (d.patch_applied ? '<span class="badge b-ok">패치 적용</span>' : '<span class="badge b-sys">패치 미적용</span>') +
      (d.healthcheck_passed ? '<span class="badge b-ok">서비스 정상</span>' : '<span class="badge b-atk">서비스 중단</span>') + "</div>" : "";

    var still = v.flags_still_reachable || [];
    var vHtml = detail.verification ? '<div class="flow-item"><div class="fi-head">' + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : '<span class="chip">—</span>') + "</div>" +
      '<div class="fi-ev">' + esc(v.detail || "") + "</div>" + (still.length ? '<div class="fi-ev" style="color:var(--atk)">재유출 가능 핵심자산: ' + still.map(stillLabel).join(", ") + "</div>" : "") +
      '<div class="fi-tgt mono">' + esc(v.method || "") + "</div></div>" : '<div class="flow-empty">검증 기록 없음</div>';

    var punchCls = v.verdict === "blocked" ? "ok" : (v.verdict === "fake_patch" || v.verdict === "not_blocked") ? "atk" : "sys";

    return (S.demo ? demoBanner() : "") +
      chips +
      '<div class="section-label">' + (rec.episode || 1) + "회차 R" + rec.round + " · 탐지 → 패치 → 검증</div>" +
      '<div class="grid cols-3 flow">' +
      '<div class="card flow-card c-def"><div class="card-h">① 탐지 <span class="flow-n">' + det.length + '건</span><button class="flow-more" data-defsec="detect">상세</button></div>' + detHtml + "</div>" +
      '<div class="card flow-card c-teal"><div class="card-h">② 패치 <span class="flow-n">' + ps.length + '건</span><button class="flow-more" data-defsec="patch">상세</button></div>' + psHtml + psFoot + "</div>" +
      '<div class="card flow-card c-' + punchCls + '"><div class="card-h">③ 검증<button class="flow-more" data-defsec="verify">상세</button></div>' + vHtml + "</div>" +
      "</div>" +
      '<div style="margin-top:14px"><button class="btn btn-ghost" data-defmore>전체 상세 · 판단 근거</button></div>';
  }

  // ───────── 페이지: 이벤트 로그 ─────────
  // ───────── 로그 회차(실행) 분리 ─────────
  // 이벤트·저널 로그는 실행을 여러 번 돌리면 한 파일에 누적된다. 레코드에 run_id 가 박혀 있으면
  // 그걸로, 없으면(구기록) 에피소드·라운드가 되돌아가는 지점으로 실행 경계를 잡아 회차별로 나눈다.
  function runSegments(records) {
    var segs = [], cur = null, prevK = -1;
    (records || []).forEach(function (e) {
      var k = (e.episode || 1) * 10000 + (e.round || 1);
      var rid = e.run_id || (e.payload && e.payload.run_id) || null, fresh;
      if (cur === null) fresh = true;
      else if (rid && cur.runId) fresh = (rid !== cur.runId);
      else if (rid && !cur.runId) fresh = true;        // 구기록 → 스탬프 전환 경계
      else fresh = (k < prevK);                         // 카운터 되돌아감 = 새 실행
      if (fresh) { cur = { runId: rid, records: [] }; segs.push(cur); }
      cur.records.push(e); prevK = k;
    });
    segs.forEach(function (s, i) {
      s.idx = i;
      var ts = []; s.records.forEach(function (r) { if (r.ts) ts.push(r.ts); });
      s.startTs = ts.length ? Math.min.apply(null, ts) : 0;
      s.endTs = ts.length ? Math.max.apply(null, ts) : 0;
      s.dur = (s.endTs && s.startTs) ? (s.endTs - s.startTs) : 0;
      var eps = {}, rnds = {};
      s.records.forEach(function (r) { eps[r.episode || 1] = 1; rnds[(r.episode || 1) + "-" + (r.round || 1)] = 1; });
      s.nEp = Object.keys(eps).length; s.nRnd = Object.keys(rnds).length;
      s.man = manifestFor(s.runId);
    });
    return segs;
  }
  function manifestFor(runId) {
    if (!runId) return null;
    var rs = S.runs || [];
    for (var i = 0; i < rs.length; i++) if (rs[i].id === runId) return rs[i];
    return null;
  }
  function segKey(s) { return s ? (s.runId || ("t" + s.startTs)) : ""; }
  function pickSeg(segs, sel) {
    if (!segs.length) return null;
    if (sel) for (var i = 0; i < segs.length; i++) if (segKey(segs[i]) === sel) return segs[i];
    return segs[segs.length - 1];                        // 기본 = 최신 실행
  }
  function durLabel(sec) {
    sec = Math.round(sec || 0);
    if (sec < 60) return sec + "초";
    var m = Math.floor(sec / 60), s = sec % 60;
    return s ? (m + "분 " + s + "초") : (m + "분");
  }
  function whenLabel(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000), now = new Date();
    var hm = ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
    return d.toDateString() === now.toDateString() ? hm : ((d.getMonth() + 1) + "/" + d.getDate() + " " + hm);
  }
  function runConfigLine(s) {
    if (!s) return "";
    var man = s.man, p = man && man.params;
    if (p) {
      var tok = (p.max_tokens == null || p.max_tokens === 0) ? "무제한" : num(p.max_tokens);
      var tgt = (man.target_assets && man.target_assets.length) ? man.target_assets.join(", ") : "전체";
      return "회차 " + num(p.episodes) + " · 라운드 " + num(p.max_rounds) +
        " · 제한 " + num(p.time_limit) + "s · 토큰 " + tok + " · 대상 " + esc(tgt);
    }
    return "에피소드 " + s.nEp + " · 라운드 " + s.nRnd + " · 설정 미상";
  }
  // 회차 피커 — 최신 먼저. 실행이 하나뿐이면 숨김. attr=선택용 데이터 속성.
  function runPickerHtml(segs, selKey, attr) {
    if (segs.length <= 1) return "";
    var selK = segKey(pickSeg(segs, selKey));
    var chips = segs.map(function (s) {
      var on = segKey(s) === selK, latest = (s.idx === segs.length - 1);
      return '<button class="runchip' + (on ? " on" : "") + '" ' + attr + '="' + segKey(s) + '">' +
        '<span class="runchip-n">실행 ' + (s.idx + 1) + (latest ? ' <span class="runchip-new">최신</span>' : "") + "</span>" +
        '<span class="runchip-meta">' + whenLabel(s.startTs) + " · " + durLabel(s.dur) + "</span></button>";
    });
    chips.reverse();
    return '<div class="runpick">' + chips.join("") + "</div>";
  }
  function runCfgHtml(seg) {
    if (!seg) return "";
    return '<div class="runcfg"><span class="runcfg-when">' + whenLabel(seg.startTs) + " · " + durLabel(seg.dur) +
      '</span><span class="runcfg-set">' + runConfigLine(seg) + "</span></div>";
  }

  async function loadEvents() {
    var r = await Promise.all([jget("/api/events"), jget("/api/runs")]);
    S.events = r[0] || []; S.runs = r[1] || S.runs || [];
    if (!S.events.length) S.events = demoEvents();
  }
  function pageEvents() {
    var segs = runSegments(S.events), seg = pickSeg(segs, evRun);
    var recs = seg ? seg.records : S.events;
    var tabs = [["all", "전체"], ["attacker", "공격"], ["defender", "방어"], ["judge", "심판"]];
    var tabHtml = tabs.map(function (t) { return '<button class="tab ' + (evTab === t[0] ? "active" : "") + '" data-tab="' + t[0] + '">' + t[1] + "</button>"; }).join("");
    var evs = recs.filter(function (e) { return evTab === "all" || e.actor === evTab; }).slice().reverse();
    var rows = evs.length ? evs.map(evRow).join("") : '<div class="tile-sub" style="padding:14px">이벤트 없음</div>';
    return (S.demo ? demoBanner() : "") +
      runPickerHtml(segs, evRun, "data-evrun") + runCfgHtml(seg) +
      '<div class="tabs">' + tabHtml + "</div>" +
      '<div class="card" style="padding:6px 8px">' + rows + "</div>";
  }
  function evRow(e) {
    var map = { attack_step: ["b-atk", "명령"], attack_turn: ["b-atk", "공격 차례"], detection: ["b-def", "탐지"],
      patch: ["b-def", "패치"], defense_turn: ["b-def", "방어 차례"], verdict: ["b-sys", "판정"], planner_wave: ["b-atk", "계획"] };
    var m = map[e.type] || ["b-sys", e.type]; var p = e.payload || {}, body = "", status = "";
    // 본문(가변 길이)과 결과 배지(실패·적용·판정 등)를 분리 — 배지는 오른쪽 고정 열로 정렬.
    if (e.type === "attack_step") {
      body = '<span class="mono">' + esc(p.tool) + " " + esc((p.args || []).join(" ")).slice(0, 110) + "</span>";
      status = p.flag ? '<span class="badge b-crown">목표 획득</span>' : p.success ? "" : '<span class="badge b-sys">실패</span>';
    } else if (e.type === "attack_turn") {
      body = "공격 차례 종료 · " + esc(reasonLabel(p.end_reason)) + " · 획득 " + num(p.flags) + " · 명령 " + num(p.steps) + "개";
    } else if (e.type === "detection") {
      body = '추정 <b>' + esc(p.technique) + '</b> <span class="mono">' + esc((p.evidence || "")).slice(0, 80) + "</span>";
    } else if (e.type === "patch") {
      body = '<span class="mono">' + esc((p.detail || (p.kind + " → " + p.target))).slice(0, 110) + "</span>";
      status = p.applied ? '<span class="badge b-ok">적용</span>' : '<span class="badge b-sys">건너뜀</span>';
    } else if (e.type === "defense_turn") {
      body = "방어 차례 · 패치 " + (p.patch_applied ? "적용" : "미적용") + " · 탐지 " + num(p.detected) + "건 · 서비스 " + (p.healthcheck_passed ? "정상" : "중단");
    } else if (e.type === "verdict") {
      var v = VERDICT[p.verdict];
      status = v ? '<span class="badge ' + v.cls + '">' + v.label + "</span>" : '<span class="badge b-sys">' + esc(p.verdict) + "</span>";
      body = '<span class="mono">' + esc((p.detail || "")).slice(0, 80) + "</span>";
    } else body = '<span class="mono">' + esc(JSON.stringify(p)).slice(0, 110) + "</span>";
    return '<div class="ev-row"><span class="ev-ts">' + hhmmss(e.ts) + '</span>' +
      '<span class="ev-type ' + m[0] + '">' + m[1] + '</span>' +
      '<span class="ev-rr">R' + (e.round || "?") + '</span>' +
      '<span class="ev-body">' + body + '</span>' +
      '<span class="ev-status">' + status + '</span></div>';
  }

  // ───────── 페이지: 공격 저널(실시간 명령 로그) ─────────
  // 공격자 이벤트만 추려 콘솔처럼. 이벤트는 라운드 종료 시 기록되므로 라운드 단위로 흘러든다.
  function journalRow(e) {
    var p = e.payload || {}, t = hhmmss(e.ts), r = "R" + (e.round || "?");
    if (e.type === "attack_turn") {
      return '<div class="jr jr-turn"><span class="jr-ts">' + t + '</span><span class="jr-r">' + r + '</span>' +
        '<span class="jr-body">공격 턴 종료 · ' + esc(reasonLabel(p.end_reason)) + " · 명령 " + num(p.steps) + "개" +
        (p.elapsed_sec ? " · " + Math.round(p.elapsed_sec) + "s" : "") + "</span></div>";
    }
    if (e.type === "planner_wave")
      return '<div class="jr jr-plan"><span class="jr-ts">' + t + '</span><span class="jr-r">' + r + '</span><span class="jr-body">계획 수립(웨이브)</span></div>';
    var cmd = (String(p.tool || "") + " " + (p.args || []).join(" ")).trim();
    var badge = p.flag ? '<span class="badge b-crown">목표 획득</span>'
      : p.success ? '<span class="jr-ok">성공</span>' : '<span class="jr-fail">실패</span>';
    var nd = (p.determinism && p.determinism !== "deterministic") ? ' <span class="jr-nd">비결정</span>' : "";
    return '<div class="jr' + (p.flag ? " jr-flag" : "") + '"><span class="jr-ts">' + t + '</span><span class="jr-r">' + r + '</span>' +
      '<span class="jr-cmd mono">' + (cmd ? esc(cmd) : '<span class="jr-dim">(명령 없음)</span>') + '</span><span class="jr-meta">' + badge + nd + "</span></div>";
  }
  // 실시간 저널 우선(attack_journal.jsonl, 턴 중 스트리밍) → 없으면 이벤트 로그의 공격자 항목으로 폴백
  async function loadJournal() {
    var r = await Promise.all([jget("/api/attack_journal"), jget("/api/runs")]);
    var j = r[0] || []; S.runs = r[1] || S.runs || [];
    S.journalLive = j.length > 0;      // 실시간 스트림 소스 여부(없으면 라운드 종료 집계로 폴백 — 의도 정보 없음)
    if (!j.length) { await loadEvents(); j = S.events.filter(function (e) { return e.actor === "attacker"; }); }
    S.journal = j;
  }
  // 의도 라벨 — 요약(intent_label)이 있으면 그대로, 없으면 태그를 "의도 #N · w1"로, 둘 다 없으면 "의도 외".
  function intentLabelOf(p) {
    p = p || {};
    if (p.intent_label) return p.intent_label;
    var s = String(p.intent || "").replace(/^\[|\]$/g, "").trim();
    if (!s) return "의도 외";
    var m = s.match(/(w\d+)[·\s]*intent#(\d+)/);
    return m ? "의도 #" + m[2] + " · " + m[1] : s;
  }
  // 의도별 그룹 로그 — 의도는 라운드 단위라 그룹당 라운드 하나. 그룹 헤더=라운드·건수·성공·목표.
  function journalStepRow(e) {
    var p = e.payload || {}, t = hhmmss(e.ts);
    var cmd = (String(p.tool || "") + " " + (p.args || []).join(" ")).trim();
    var badge = p.flag ? '<span class="badge b-crown">목표 획득</span>' : p.success ? '<span class="jr-ok">성공</span>' : '<span class="jr-fail">실패</span>';
    var nd = (p.determinism && p.determinism !== "deterministic") ? ' <span class="jr-nd">비결정</span>' : "";
    return '<div class="jr jr-instep' + (p.flag ? " jr-flag" : "") + '"><span class="jr-ts">' + t + "</span>" +
      '<span class="jr-cmd mono">' + (cmd ? esc(cmd) : '<span class="jr-dim">(명령 없음)</span>') + '</span><span class="jr-meta">' + badge + nd + "</span></div>";
  }
  // 라운드 → (의도) → 스텝 아코디언 — 길게 쭉 흐르지 않게 라운드·의도 단위로 접고 펼친다.
  // agLogOpen: 펼친 키 집합. 새로 나타난 최신 라운드는 자동 펼침(한 번 접으면 그 상태 유지).
  function journalAccordion(evs, byIntent) {
    var rounds = {}, rorder = [];
    evs.forEach(function (e) {
      if (e.type !== "attack_step") return;
      var r = e.round || 0;
      if (!rounds[r]) { rounds[r] = []; rorder.push(r); }
      rounds[r].push(e);
    });
    if (!rorder.length) return '<div class="journal">' + evs.slice().reverse().map(journalRow).join("") + "</div>";
    rorder.sort(function (a, b) { return b - a; });                 // 최신 라운드 먼저
    if (agLogOpen == null) agLogOpen = {};
    var topKey = "r" + rorder[0];
    if (agLogOpen[topKey] === undefined) agLogOpen[topKey] = true;  // 최신 라운드 기본 펼침
    function sumMeta(steps) {
      var ok = steps.filter(function (s) { return (s.payload || {}).success; }).length;
      var flag = steps.some(function (s) { return (s.payload || {}).flag; });
      return { ok: ok, flag: flag };
    }
    function caret(open) { return '<span class="jacc-caret' + (open ? " open" : "") + '">▸</span>'; }
    return rorder.map(function (r) {
      var steps = rounds[r], rkey = "r" + r, ropen = !!agLogOpen[rkey], m = sumMeta(steps);
      var rhead = '<button class="jacc-h jacc-r' + (ropen ? " open" : "") + '" data-jtoggle="' + rkey + '">' +
        caret(ropen) + '<span class="jacc-t">R' + r + "</span>" +
        '<span class="jacc-meta">' + steps.length + "건 · 성공 " + m.ok + (m.flag ? ' <span class="badge b-crown">목표 획득</span>' : "") + "</span></button>";
      var inner = "";
      if (ropen && byIntent) {
        var ig = {}, iorder = [];
        steps.forEach(function (e) { var k = intentLabelOf(e.payload); if (!ig[k]) { ig[k] = []; iorder.push(k); } ig[k].push(e); });
        inner = iorder.map(function (k) {
          var ikey = rkey + "|" + k, iopen = !!agLogOpen[ikey], ist = ig[k], im = sumMeta(ist);
          var ihead = '<button class="jacc-h jacc-i' + (iopen ? " open" : "") + '" data-jtoggle="' + esc(ikey) + '">' +
            caret(iopen) + '<span class="jacc-t jacc-intent">' + esc(k) + "</span>" +
            '<span class="jacc-meta">' + ist.length + "건 · 성공 " + im.ok + (im.flag ? ' <span class="badge b-crown">목표</span>' : "") + "</span></button>";
          return '<div class="jacc-ig' + (im.flag ? " jg-flag" : "") + '">' + ihead +
            (iopen ? ist.slice().reverse().map(journalStepRow).join("") : "") + "</div>";
        }).join("");
      } else if (ropen) {
        inner = steps.slice().reverse().map(journalStepRow).join("");
      }
      return '<div class="jacc' + (m.flag ? " jg-flag" : "") + '">' + rhead + (ropen ? '<div class="jacc-body">' + inner + "</div>" : "") + "</div>";
    }).join("");
  }
  function pageAttackLog() {
    var all = S.journal || [];
    if (!all.length)
      return (S.demo ? demoBanner() : "") + emptyState("📓", "아직 공격 저널이 없습니다", "공격 턴이 시작되면 실행한 명령과 결과가 실시간으로 쌓입니다.", []);
    var segs = runSegments(all), seg = pickSeg(segs, jRun);
    var evs = seg ? seg.records : all;
    var nSteps = 0, nFlag = 0, intents = {};
    evs.forEach(function (e) { if (e.type === "attack_step") { nSteps++; if ((e.payload || {}).flag) nFlag++; var k = (e.payload || {}).intent; if (k) intents[k] = 1; } });
    var nIntents = Object.keys(intents).length;
    var tabs = '<div class="tabs"><button class="tab' + (agLogView === "intent" ? " active" : "") + '" data-logview="intent">의도별</button>' +
      '<button class="tab' + (agLogView === "time" ? " active" : "") + '" data-logview="time">시간순</button></div>';
    var body = journalAccordion(evs, agLogView === "intent");
    return (S.demo ? demoBanner() : "") +
      runPickerHtml(segs, jRun, "data-jrun") + runCfgHtml(seg) +
      '<div class="jhead"><span class="jhead-m"><span class="jhead-k">실행 명령</span><span class="jhead-v">' + nSteps + "건</span></span>" +
      (nIntents ? '<span class="jhead-m"><span class="jhead-k">의도</span><span class="jhead-v">' + nIntents + "개</span></span>" : "") +
      (nFlag ? '<span class="jhead-m"><span class="jhead-k">목표 획득</span><span class="jhead-v atk">' + nFlag + "건</span></span>" : "") +
      '<span class="jhead-note">실행 중 자동 갱신(라운드 종료 시 반영)</span></div>' +
      (!S.journalLive ? '<div class="jwarn">실시간 저널 미연결 — 라운드 종료 집계만 표시되어 의도 정보가 없습니다. 오케스트레이터(VM C)가 최신 코드로 실행 중인지 확인하세요.</div>' : "") +
      tabs + body;
  }
  function bindAttackLog() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-logview]"), function (b) {
      b.onclick = function () { agLogView = b.getAttribute("data-logview"); $("#view").innerHTML = pageAttackLog(); bindAttackLog(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-jrun]"), function (b) {
      b.onclick = function () { jRun = b.getAttribute("data-jrun"); agLogOpen = null; $("#view").innerHTML = pageAttackLog(); bindAttackLog(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-jtoggle]"), function (b) {
      b.onclick = function () { var k = b.getAttribute("data-jtoggle"); agLogOpen[k] = !agLogOpen[k]; $("#view").innerHTML = pageAttackLog(); bindAttackLog(); };
    });
  }

  // ───────── 페이지: 공격 추적 그래프 ─────────
  function kindLabel(k) { return ({ goal: "Goal", intent: "Intent", fact: "Fact", finding: "Finding", hint: "Hint" })[k] || k; }
  function kindLabelFull(k) { return ({ goal: "Goal · 목표", intent: "Intent · 의도", fact: "Fact · 사실", finding: "Finding · 발견", hint: "Hint · 힌트" })[k] || kindLabel(k); }
  function kindColor(k) {
    return ({ goal: { bg: "#fdf1dc", line: "#b8740a" }, intent: { bg: "#fdecec", line: "#d13b40" },
      fact: { bg: "#e8f0fe", line: "#2f6fe0" }, finding: { bg: "#fbdcde", line: "#b4303a" },
      hint: { bg: "#eef1f5", line: "#5b6676" } })[k] || { bg: "#eef1f5", line: "#5b6676" };
  }
  function relColor(r) { return ({ spawns: "#e5484d", yields: "#3b82f6", proves: "#b4303a", derived_from: "#94a3b8" })[r] || "#94a3b8"; }
  // 관계 — 사람이 읽는 우리말(엣지 의미가 더 직관적)
  function relLabel(r) { return ({ spawns: "파생", yields: "산출", proves: "입증", derived_from: "유도" })[r] || r; }
  function relDesc(r) { return ({ spawns: "목표·사실이 새 의도를 낳음", yields: "의도가 사실을 산출", proves: "사실이 발견을 입증", derived_from: "사실이 다른 사실에서 유도됨" })[r] || ""; }
  // 노드 상태 — 화면 표기는 쉬운 우리말(상태는 식별자 아닌 진행 상황이라 한글이 명확)
  function stateKo(s) { return ({ open: "대기", running: "실행 중", done: "완료", blocked: "차단", exhausted: "막다름", stopped: "중단", confirmed: "확인됨", claimed: "포착" })[s] || s; }
  function stateColor(s) { return ({ running: "#0d9488", done: "#0ea371", blocked: "#e5484d", exhausted: "#e5920b", stopped: "#64748b", confirmed: "#2f6fe0", claimed: "#b4303a" })[s] || "#8a97ab"; }
  function mitreUrl(t) { return "https://attack.mitre.org/techniques/" + String(t).replace(".", "/") + "/"; }
  function truncate(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function demoAttackGraph() {
    return { demo: true, nodes: [
      { id: 1, kind: "goal", summary: "내부 DB의 핵심 비밀 확보",
        desc: "이번 회차 공격의 최종 목표입니다. 내부망 깊숙한 데이터베이스에 보관된 핵심 자산(고객 개인정보·내부 크리덴셜)을 실제로 빼내는 것이 성공 조건이고, 아래의 모든 의도·사실은 이 목표에서 뻗어 나옵니다." },
      { id: 2, kind: "intent", state: "done", owner: "w1", technique: "T1078", target: "internal/admin-sa", summary: "관리용 계정 권한 악용",
        why: "권한이 과하게 열려 있을 것으로 추정", desc: "관리 작업용으로 만들어진 서비스 계정이 필요 이상으로 넓은 권한을 가졌을 거라 보고, 이 계정을 발판 삼아 비밀 저장소에 접근하려는 방향입니다." },
      { id: 3, kind: "intent", state: "running", owner: "w2", technique: "T1210", target: "backend/catalog-api", summary: "백엔드 API 원격 취약점 탐색",
        why: "외부에 노출된 포트가 많음", desc: "외부에서 닿는 백엔드 서비스들의 알려진 취약점을 훑어, 원격에서 코드 실행이 가능한 구멍이 있는지 지금 확인하는 중입니다." },
      { id: 4, kind: "intent", state: "blocked", owner: "w1", technique: "T1213", target: "internal/internal-wiki", summary: "내부 위키 문서 수집",
        why: "운영 문서에 접속정보가 섞여 있을 가능성", desc: "내부 위키의 운영 문서에 비밀번호·접속정보가 평문으로 적힌 경우가 많아 뒤졌지만, 이번 라운드엔 접근 경로가 막혀 중단됐습니다." },
      { id: 5, kind: "fact", confidence: 0.9, evidence: "권한 점검 결과 전 영역 비밀 읽기 허용", loot: { readable_secrets: ["db-postgres-admin", "jwt-signing-key", "smtp-credentials", "redis-auth"] }, summary: "관리 계정이 모든 영역의 비밀을 읽을 수 있음",
        desc: "관리용 서비스 계정 하나로 클러스터 전 영역의 비밀 저장소를 읽을 수 있음을 확인했습니다. 사실상 마스터키에 가까운 과도한 권한입니다." },
      { id: 6, kind: "fact", confidence: 0.6, evidence: "응답에 구버전 식별자 노출", summary: "주문 API가 오래된 취약 버전",
        desc: "주문 처리 API가 알려진 원격 취약점이 있는 구버전으로 운영 중임을 확인했습니다. 다만 실제 악용까지는 조건이 더 필요한 상태입니다." },
      { id: 7, kind: "fact", confidence: 0.75, evidence: "운영 런북 페이지에 접속 문자열 기재", loot: "postgresql://app_admin:P@ssw0rd!2024@database.svc:5432/appdb", summary: "위키 문서에 DB 접속정보가 평문 노출",
        desc: "내부 위키의 한 운영 문서에 데이터베이스 접속 주소와 계정·비밀번호가 그대로 적혀 있었습니다. 방어가 이 문서를 치우기 전까진 재사용 가능한 통로입니다." },
      { id: 8, kind: "finding", severity: "critical", technique: "T1078", occurrences: 2, loot: { secret: "db-postgres-admin", username: "app_admin", password: "P@ssw0rd!2024", host: "database.svc:5432", db: "appdb" }, summary: "관리 계정으로 DB 비밀 탈취",
        desc: "과도한 권한의 관리 계정을 발판으로 데이터베이스 접속 비밀(사용자명·비밀번호)을 읽어냈습니다. 이 자격증명이면 고객 개인정보가 담긴 테이블을 직접 조회할 수 있어, 사실상 핵심 자산이 뚫린 상태입니다. 두 라운드 연속 재현돼 일시적 우연이 아님이 확인됐습니다." },
      { id: 9, kind: "finding", severity: "high", technique: "T1213", occurrences: 1, loot: { table: "customers", total_rows: 18420, sample_row: { id: 24, email: "jmkim@corp.example", phone: "010-33xx-xx71", card_last4: "4417" } }, summary: "유출 접속정보로 DB 직접 연결",
        desc: "위키에서 주운 접속정보로 애플리케이션을 건너뛰고 데이터베이스에 바로 붙었습니다. 주문·결제 이력을 조회할 수 있는 수준까지 들어갔습니다." }
    ], edges: [
      { src: 1, rel: "spawns", dst: 2 }, { src: 1, rel: "spawns", dst: 3 }, { src: 1, rel: "spawns", dst: 4 },
      { src: 2, rel: "yields", dst: 5 }, { src: 3, rel: "yields", dst: 6 }, { src: 4, rel: "yields", dst: 7 },
      { src: 5, rel: "proves", dst: 8 }, { src: 7, rel: "proves", dst: 9 }, { src: 5, rel: "spawns", dst: 4 }
    ] };
  }

  // 라운드 선택 키 해석 — "E{ep}"=회차 종합(해당 회차 누적=마지막 라운드 스냅샷), "ep-rnd"=단일 라운드.
  function resolveRoundSel(rounds, sel) {
    if (sel != null && /^E\d+$/.test(sel)) {
      var ep = parseInt(sel.slice(1), 10), li = -1;
      rounds.forEach(function (r, i) { if ((r.episode || 1) === ep) li = i; });
      return { rec: li >= 0 ? rounds[li] : null, aggEp: li >= 0 ? ep : null };
    }
    var idx = sel != null ? rounds.map(function (r) { return (r.episode || 1) + "-" + r.round; }).indexOf(sel) : rounds.length - 1;
    if (idx < 0) idx = rounds.length - 1;
    return { rec: rounds[idx] || null, aggEp: null };
  }
  async function pageAttackGraphRender() {
    var view = $("#view"), g, st = S.status || {};
    var rounds = (S.rounds || []).slice();
    // 진행 중 라운드는 아직 rounds.jsonl 에 없다 — 실행 중이면 진행 상태(progress)로 라이브 라운드를
    // 만들어 목록에 넣고 기본 선택한다. 백엔드 스트리머가 그 라운드 그래프 파일을 턴 중 갱신하므로,
    // 2.5초 폴링마다 새 노드가 '뿅' 하고 추가되는 게 보인다.
    var live = null;
    if (st.running && st.episode) {
      var lk = st.episode + "-" + (st.round || 1);
      if (!rounds.some(function (r) { return (r.episode || 1) + "-" + r.round === lk; })) {
        live = { episode: st.episode, round: st.round || 1, _live: true };
        rounds.push(live);
      }
    }
    var defKey = (live && agRkey == null) ? (live.episode + "-" + live.round) : agRkey;
    var sel = resolveRoundSel(rounds, defKey), rec = sel.rec, aggEp = sel.aggEp;
    var selKey = defKey || (rec ? (rec.episode || 1) + "-" + rec.round : "");
    if ((S.demo || !S.rounds.length) && !live) {
      g = demoAttackGraph();
    } else if (rec) {
      var d = await jget("/api/attack_graph/" + (rec.episode || 1) + "/" + rec.round);
      g = (d && d.graph && (d.graph.nodes || []).length) ? d.graph : { nodes: [], edges: [] };
    } else {
      g = { nodes: [], edges: [] };
    }
    if (route !== "attack-graph") return;
    var nodes = g.nodes || [];
    if (agSel == null || !nodes.some(function (n) { return n.id === agSel; })) {
      var f = nodes.filter(function (n) { return n.kind === "finding"; });
      agSel = f.length ? f[0].id : (nodes[0] ? nodes[0].id : null);
    }
    // 변화 서명 — 같으면 재렌더 생략(폴링 중 깜빡임·재애니메이션 방지)
    var sig = nodes.map(function (n) { return n.id + ":" + (n.state || ""); }).join(",") + "|" +
      (g.edges || []).map(function (e) { return e.src + ">" + e.dst; }).join(",") + "|" + agSel + "|" + agTab + "|" + selKey;
    if (sig === S.agSig && document.querySelector(".ag-svg")) return;
    var seen = S.agSeen || {};
    nodes.forEach(function (n) { n._new = !seen[n.id]; });   // 새로 생긴 노드만 등장 애니메이션
    view.innerHTML = pageAttackGraph(g, rounds, rec, aggEp, selKey);
    nodes.forEach(function (n) { seen[n.id] = 1; });
    S.agSeen = seen; S.agSig = sig;
    bindAttackGraph();
  }
  function bindAttackGraph() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-agtab]"), function (b) {
      b.onclick = function () { agTab = b.getAttribute("data-agtab"); pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agrk]"), function (b) {
      b.onclick = function () { agRkey = b.getAttribute("data-agrk"); agSel = null; agView = null; S.agSeen = {}; S.agSig = null; pageAttackGraphRender(); };
    });
    var svg = document.querySelector(".ag-svg");
    if (!svg) return;
    var GW = parseFloat(svg.getAttribute("data-gw")) || 1, GH = parseFloat(svg.getAttribute("data-gh")) || 1;
    function view() { return agView || { x: 0, y: 0, w: GW, h: GH }; }
    function apply(v) { agView = v; svg.setAttribute("viewBox", v.x + " " + v.y + " " + v.w + " " + v.h); }
    function zoomAt(cx, cy, f) {                       // cx,cy = viewBox 좌표 기준 확대/축소
      var v = view(), nw = clamp(v.w * f, GW * 0.08, GW * 4), nh = v.h * (nw / v.w);
      apply({ x: cx - (cx - v.x) * (nw / v.w), y: cy - (cy - v.y) * (nh / v.h), w: nw, h: nh });
    }
    function toVB(ev) { var r = svg.getBoundingClientRect(), v = view(); return { x: v.x + (ev.clientX - r.left) / r.width * v.w, y: v.y + (ev.clientY - r.top) / r.height * v.h }; }
    // 노드 선택 — 드래그로 많이 움직였으면 선택 아님
    Array.prototype.forEach.call(svg.querySelectorAll(".ag-node"), function (el) {
      el.addEventListener("click", function () { if (!svg._dragged) { agSel = parseInt(el.getAttribute("data-nid"), 10); pageAttackGraphRender(); } });
    });
    svg.onwheel = function (e) { e.preventDefault(); var p = toVB(e); zoomAt(p.x, p.y, e.deltaY < 0 ? 0.88 : 1.14); };
    var drag = null;
    svg.onpointerdown = function (e) {
      svg._dragged = false;
      if (e.target.closest(".ag-node")) return;        // 노드 위 시작은 선택 우선
      drag = { x: e.clientX, y: e.clientY, v: view() }; svg.classList.add("grabbing");
    };
    svg.onpointermove = function (e) {
      if (!drag) return;
      var r = svg.getBoundingClientRect();
      if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > 6) svg._dragged = true;
      apply({ x: drag.v.x - (e.clientX - drag.x) / r.width * drag.v.w, y: drag.v.y - (e.clientY - drag.y) / r.height * drag.v.h, w: drag.v.w, h: drag.v.h });
    };
    svg.onpointerup = svg.onpointerleave = function () { drag = null; svg.classList.remove("grabbing"); };
    Array.prototype.forEach.call(document.querySelectorAll("[data-agzoom]"), function (b) {
      b.onclick = function () {
        var m = b.getAttribute("data-agzoom"), v = view(), cx = v.x + v.w / 2, cy = v.y + v.h / 2;
        if (m === "in") zoomAt(cx, cy, 0.8); else if (m === "out") zoomAt(cx, cy, 1.25); else { agView = null; apply(view()); }
      };
    });
    svg.onkeydown = function (e) {
      var v = view(), cx = v.x + v.w / 2, cy = v.y + v.h / 2, pan = v.w * 0.12;
      if (e.key === "+" || e.key === "=") zoomAt(cx, cy, 0.8);
      else if (e.key === "-" || e.key === "_") zoomAt(cx, cy, 1.25);
      else if (e.key === "ArrowLeft") apply({ x: v.x - pan, y: v.y, w: v.w, h: v.h });
      else if (e.key === "ArrowRight") apply({ x: v.x + pan, y: v.y, w: v.w, h: v.h });
      else if (e.key === "ArrowUp") apply({ x: v.x, y: v.y - pan, w: v.w, h: v.h });
      else if (e.key === "ArrowDown") apply({ x: v.x, y: v.y + pan, w: v.w, h: v.h });
      else if (e.key === "0") { agView = null; apply(view()); }
      else return;
      e.preventDefault();
    };
  }
  function agLine(k, v) { return '<div class="rep-line"><span class="rep-k">' + esc(k) + "</span><span>" + esc(v) + "</span></div>"; }
  // 개요 큐레이션 — 수동 서술(desc)이 있으면 그대로, 없으면 노드 필드(summary·detail·근거 등)를
  // 한국어 해설 프레임에 엮어 노드별 판단 근거를 생성한다. 워커 산출값(summary·detail)이 영어여도
  // 프레임은 우리말 — 값은 그대로 인용. 어떤 노드든 빈 큐레이션이 나오지 않게 한다.
  function _dot(x) { x = String(x || "").trim(); return !x || /[.!?。…]$/.test(x) ? x : x + "."; }
  function agCuration(n) {
    if (n.desc) return n.desc;
    var s = String(n.summary || "").trim(), d = String(n.detail || "").trim(), parts = [];
    if (n.kind === "goal") {
      parts.push("이번 회차 공격의 최종 목표입니다. 아래의 모든 의도·사실·발견이 이 목표에서 뻗어 나옵니다.");
      if (s) parts.push("목표 — " + _dot(s));
    } else if (n.kind === "intent") {
      parts.push((n.target ? "'" + n.target + "'을(를) 겨냥한 " : "") + "탐색 의도입니다.");
      if (s) parts.push("방향 — " + _dot(s));
      if (n.why) parts.push("판단 근거: " + _dot(n.why));
      if (n.state) parts.push("현재 " + stateKo(n.state) + " 상태입니다.");
    } else if (n.kind === "fact") {
      parts.push((n.target ? "'" + n.target + "' 관련 " : "") + "확인된 사실입니다.");
      if (s) parts.push("내용 — " + _dot(s));
      if (n.evidence) parts.push("관측 근거: " + _dot(n.evidence));
    } else if (n.kind === "finding") {
      parts.push((n.technique ? n.technique + " 기법으로 " : "") + (n.target ? "'" + n.target + "'에서 " : "") +
        (n.severity ? n.severity + " 등급 " : "") + "침해를 확인했습니다.");
      if (s) parts.push("내용 — " + _dot(s));
      if (n.occurrences > 1) parts.push(n.occurrences + "회 재현돼 일시적 우연이 아님이 확인됐습니다.");
      if (n.loot != null && String(n.loot) !== "") parts.push("아래 '확보한 데이터'에 실제 탈취 값이 담겨 있습니다.");
    } else if (s) {
      parts.push(_dot(s));
    }
    if (d && d !== s) parts.push("상세: " + _dot(d));
    return parts.join(" ");
  }
  function agPanel(nodes) {
    var n = nodes.filter(function (x) { return x.id === agSel; })[0];
    if (!n) return "";
    var col = kindColor(n.kind);
    var tabs = '<div class="tabs"><button class="tab' + (agTab === "overview" ? " active" : "") + '" data-agtab="overview">개요</button>' +
      '<button class="tab' + (agTab === "knowledge" ? " active" : "") + '" data-agtab="knowledge">지식</button></div>';
    var head = '<div class="ag-ph"><span class="badge" style="background:' + col.bg + ";color:" + col.line + '">' + kindLabelFull(n.kind) + "</span>" +
      (n.technique ? '<span class="badge b-atk">' + esc(n.technique) + "</span>" : "") +
      (n.state && n.state !== "exhausted" ? '<span class="chip ag-state" style="color:' + stateColor(n.state) + ';border-color:' + stateColor(n.state) + '33">' + esc(stateKo(n.state)) + "</span>" : "") +
      (n.severity ? '<span class="chip">심각도 ' + esc(n.severity) + "</span>" : "") + "</div>" +
      '<div class="ag-sum">' + esc(n.summary || "—") + "</div>" +
      (function () { var c = agCuration(n); return c ? '<div class="ag-desc">' + esc(c) + "</div>" : ""; })() +
      (n.loot != null && n.loot !== "" ? '<div class="ag-loot"><div class="ag-loot-h">확보한 데이터</div><pre class="ag-loot-v">' + esc(typeof n.loot === "object" ? JSON.stringify(n.loot, null, 2) : String(n.loot)) + "</pre></div>" : "");
    var body;
    if (agTab === "overview") {
      body = (n.target ? agLine("대상", n.target) : "") +
        (n.why ? agLine("판단 근거", n.why) : "") +
        (n.confidence != null && isFinite(n.confidence) ? agLine("확신도", Math.round(n.confidence * 100) + "%") : "") +
        (n.occurrences ? agLine("재현 횟수", n.occurrences + "회") : "") +
        (n.owner ? agLine("담당 워커", n.owner) : "") +
        (n.evidence ? '<div class="ag-ev-sm">관측: ' + esc(n.evidence) + "</div>" : "");
      if (!body) body = '<div class="tile-sub">추가 정보 없음</div>';
    } else {
      body = (n.technique ? agLine("MITRE 기법", n.technique) +
          '<div class="rep-line"><span class="rep-k">참고 문서</span><span><a href="' + mitreUrl(n.technique) + '" target="_blank" rel="noopener">MITRE ATT&CK에서 보기 ↗</a></span></div>'
        : '<div class="tile-sub">연결된 MITRE 기법 없음</div>') +
        '<div class="tile-sub" style="margin-top:10px">제품·CVE 심층 조회(지식그래프)는 다음 단계 브리지에서 연결됩니다.</div>';
    }
    return '<div class="section-label">노드 상세</div><div class="card ag-panel" style="border-top:3px solid ' + col.line + '">' + tabs + head + '<div class="ag-body">' + body + "</div></div>";
  }
  function pageAttackGraph(g, rounds, rec, aggEp, selKey) {
    var nodes = g.nodes || [], edges = g.edges || [];
    if (!nodes.length) {
      var chips0 = (rounds && rounds.length) ? roundChipsHtml(rounds, selKey || "", "data-agrk") : "";
      return chips0 + emptyState("🕸", "이 라운드는 공격 그래프 기록이 없습니다",
        "탐색 그래프는 병렬 모드(attack.mode: parallel)에서만 생성됩니다. 단일 모드(single)는 플래너·의도 그래프가 없어 비어 있습니다. 다른 회차·라운드를 선택하거나 병렬 모드로 실행하세요.", []);
    }
    // 수직 트리 레이아웃 — 목표(위)에서 깊이가 아래로 떨어진다. BFS 최단경로로 깊이(행)를 잡고,
    // 자식은 부모 아래에 모아 배치(종류별 가로 열이 아니라 계층 트리). 하위 의도는 사실보다 더 아래.
    var NW = 184, NH = 56, PADX = 28, TOP = 20;
    var byId = {}, childrenMap = {}, parentsMap = {};
    nodes.forEach(function (n) { byId[n.id] = n; childrenMap[n.id] = []; parentsMap[n.id] = []; });
    edges.forEach(function (e) { if (byId[e.src] && byId[e.dst]) { childrenMap[e.src].push(e.dst); parentsMap[e.dst].push(e.src); } });
    var roots = nodes.filter(function (n) { return n.kind === "goal"; });
    if (!roots.length) roots = nodes.filter(function (n) { return !parentsMap[n.id].length; });
    if (!roots.length) roots = [nodes[0]];
    var kd = { goal: 0, hint: 0, intent: 1, fact: 2, finding: 3 }, depth = {}, bfsParent = {}, q = [];
    roots.forEach(function (r) { depth[r.id] = 0; q.push(r.id); });
    for (var qi = 0; qi < q.length; qi++) {
      var u = q[qi];
      childrenMap[u].slice().sort(function (a, b) { return a - b; }).forEach(function (v) {
        if (depth[v] == null) { depth[v] = depth[u] + 1; bfsParent[v] = u; q.push(v); }
      });
    }
    nodes.forEach(function (n) { if (depth[n.id] == null) depth[n.id] = (kd[n.kind] != null ? kd[n.kind] : 1); });
    var treeChildren = {}; nodes.forEach(function (n) { treeChildren[n.id] = []; });
    nodes.forEach(function (n) { if (bfsParent[n.id] != null) treeChildren[bfsParent[n.id]].push(n.id); });
    Object.keys(treeChildren).forEach(function (k) { treeChildren[k].sort(function (a, b) { return a - b; }); });
    var slot = 0, xOf = {};
    function layX(id) {                    // 후위 순회 — 잎은 순차 슬롯, 내부 노드는 자식 가운데
      var ks = treeChildren[id];
      if (!ks.length) { xOf[id] = slot++; return xOf[id]; }
      var xs = ks.map(layX);
      xOf[id] = (xs[0] + xs[xs.length - 1]) / 2; return xOf[id];
    }
    roots.slice().sort(function (a, b) { return a.id - b.id; }).forEach(function (r) { layX(r.id); });
    nodes.forEach(function (n) { if (xOf[n.id] == null) xOf[n.id] = slot++; });   // 고립 노드
    var COLW = NW + 30, ROWH = NH + 46, pos = {}, maxSlot = 0, maxDep = 0;
    nodes.forEach(function (n) {
      pos[n.id] = { x: PADX + xOf[n.id] * COLW, y: TOP + depth[n.id] * ROWH };
      if (xOf[n.id] > maxSlot) maxSlot = xOf[n.id];
      if (depth[n.id] > maxDep) maxDep = depth[n.id];
    });
    var W = PADX * 2 + maxSlot * COLW + NW, H = TOP + maxDep * ROWH + NH + 20;
    var newSet = {}; nodes.forEach(function (n) { if (n._new) newSet[n.id] = 1; });
    var edgeSvg = edges.map(function (e) {
      var a = pos[e.src], b = pos[e.dst]; if (!a || !b) return "";
      var hot = (agSel === e.src || agSel === e.dst), isNew = newSet[e.dst] || newSet[e.src], d;
      if (b.y > a.y + 1) {                 // 아래로(부모→자식) — 수직 베지어로 떨어뜨림
        var ax = a.x + NW / 2, ay = a.y + NH, bx = b.x + NW / 2, by = b.y, my = (ay + by) / 2;
        d = "M" + ax + " " + ay + " C" + ax + " " + my + " " + bx + " " + my + " " + bx + " " + by;
      } else {                             // 같은/위 레벨(교차 링크) — 오른쪽으로 둘러
        var cx = a.x + NW, cy = a.y + NH / 2, dx = b.x + NW, dy = b.y + NH / 2, mx = Math.max(cx, dx) + 28;
        d = "M" + cx + " " + cy + " C" + mx + " " + cy + " " + mx + " " + dy + " " + dx + " " + dy;
      }
      return '<path class="ag-edge' + (isNew ? " ag-new" : "") + (hot ? " ag-hot" : "") + '" d="' + d +
        '" fill="none" stroke="' + relColor(e.rel) + '" stroke-width="' + (hot ? 2.2 : 1.3) + '" opacity="' + (hot ? 0.95 : 0.34) + '"' + (isNew ? ' style="animation-delay:200ms"' : "") + "/>";
    }).join("");
    var nIdx = 0;
    var nodeSvg = nodes.map(function (n) {
      var p = pos[n.id]; if (!p) return "";
      var col = kindColor(n.kind), sel = (agSel === n.id);
      // 막다름(exhausted=시간예산 소진)은 거의 모든 미결 의도에 붙는 흔한 상태라 태그에서 제외 —
      // 사점(점선·흐림) 표기는 실제 중단 사유인 차단·중단만.
      var dead = n.kind === "intent" && (n.state === "blocked" || n.state === "stopped");
      var cls = "ag-node" + (n._new ? " ag-new" : "") + (n.state === "running" ? " ag-run" : "") + (dead ? " ag-dead" : "") + (n.kind === "finding" ? " ag-find" : "");
      var delay = n._new ? (nIdx++ * 55) : 0;
      var l1 = kindLabel(n.kind) + (n.technique ? " · " + esc(n.technique) : "");
      var l2 = esc(truncate(n.summary || kindLabel(n.kind), 16));
      // 상태 뱃지 — 대기·완료·막다름 외 의미 있는 상태(실행 중·차단·중단·확인됨·포착)만.
      var showSt = n.kind === "intent" && n.state && n.state !== "open" && n.state !== "done" && n.state !== "exhausted";
      var stBadge = showSt ? '<text x="' + (p.x + NW - 11) + '" y="' + (p.y + 21) + '" text-anchor="end" font-size="8.5" font-weight="700" fill="' + stateColor(n.state) + '">' + esc(stateKo(n.state)) + "</text>" : "";
      return '<g class="' + cls + '" data-nid="' + n.id + '"' + (delay ? ' style="animation-delay:' + delay + 'ms"' : "") + ' opacity="' + (dead ? 0.9 : 1) + '">' +
        '<rect x="' + p.x + '" y="' + p.y + '" width="' + NW + '" height="' + NH + '" rx="10" fill="' + col.bg + '" stroke="' + col.line + '" stroke-width="' + (sel ? 2.6 : 1.2) + '"' + (dead ? ' stroke-dasharray="5 3"' : "") + "/>" +
        '<text class="agk" x="' + (p.x + 13) + '" y="' + (p.y + 21) + '" font-size="9.5" font-weight="700" fill="' + col.line + '">' + l1 + "</text>" + stBadge +
        '<text x="' + (p.x + 13) + '" y="' + (p.y + 39) + '" font-size="11.5" fill="#0f1b2d">' + l2 + "</text></g>";
    }).join("");
    var vb = agView || { x: 0, y: 0, w: W, h: H };     // agView=수동 조작(확대·이동) 지속, null=자동 맞춤(라이브 성장 추적)
    var tools = '<div class="ag-tools">' +
      '<button class="ag-tool" data-agzoom="in" aria-label="확대">+</button>' +
      '<button class="ag-tool" data-agzoom="out" aria-label="축소">−</button>' +
      '<button class="ag-tool" data-agzoom="fit" aria-label="맞춤">⤢</button></div>';
    var svg = '<div class="ag-wrap">' + tools +
      '<svg class="ag-svg" tabindex="0" viewBox="' + vb.x + " " + vb.y + " " + vb.w + " " + vb.h +
      '" preserveAspectRatio="xMidYMid meet" data-gw="' + W + '" data-gh="' + H + '">' + edgeSvg + nodeSvg + "</svg></div>";
    var legend = '<div class="ag-legend"><div class="legend">' +
      ["goal", "intent", "fact", "finding"].map(function (k) { return '<span><span class="tag-dot" style="background:' + kindColor(k).line + '"></span>' + kindLabel(k) + "</span>"; }).join("") +
      ["spawns", "yields", "proves", "derived_from"].map(function (r) { return '<span title="' + esc(relDesc(r)) + '"><span style="display:inline-block;width:15px;height:0;border-top:2px solid ' + relColor(r) + '"></span> ' + relLabel(r) + "</span>"; }).join("") + "</div>" +
      '<div class="legend ag-legend-st"><span class="agl-k">상태</span>' +
      '<span><span class="agls agls-run"></span>실행 중(맥동)</span>' +
      '<span><span class="agls agls-dead"></span>차단·중단(점선·흐림)</span>' +
      '<span><span class="agls agls-done"></span>완료</span></div></div>';
    var chips = (rounds && rounds.length) ? roundChipsHtml(rounds, selKey || "", "data-agrk") : "";
    var ctx = aggEp ? aggEp + "회차 종합 · 누적 그래프" : (rec ? (rec.episode || 1) + "회차 R" + rec.round : "예시");
    return (S.demo ? demoBanner() : "") + chips +
      '<div class="section-label">' + ctx + " · 공격 추론 그래프 (Goal → Intent → Fact → Finding)</div>" + svg + legend + agPanel(nodes);
  }

  // ───────── 페이지: 회차 보고서 ─────────
  function endReasonLabel(r) { return ({ consecutive_defense: "방어 연속 성공", max_rounds: "최대 라운드 도달", crown_exfil: "핵심정보 유출", attacker_deadend: "공격 막다름", error: "오류" })[r] || r || "—"; }
  function reportLine(k, v) { return '<div class="rep-line"><span class="rep-k">' + esc(k) + "</span><span>" + esc(v) + "</span></div>"; }
  function pageReport() {
    var eps = S.episodes;
    if (!eps.length) return emptyState("📄", "아직 끝난 회차가 없습니다", "회차(여러 라운드)가 종료되면 요약·상세 보고서가 여기 만들어집니다.", []);
    var idx = repEp != null ? eps.map(function (e) { return e.episode; }).indexOf(repEp) : eps.length - 1;
    if (idx < 0) idx = eps.length - 1;
    var e = eps[idx];
    var rs = S.rounds.filter(function (r) { return r.episode === e.episode; });
    if (!rs.length) rs = S.rounds;

    var vc = e.verdict_counts || {};
    var blocked = vc.blocked || 0, fake = (vc.fake_patch || 0) + (vc.not_blocked || 0);
    var det = e.detection || { tp: 0, fp: 0, fn: 0 };
    var recall = det.recall != null ? det.recall : (det.tp + det.fn ? det.tp / (det.tp + det.fn) : null);
    var crowns = e.crowns_reached || [], mttd = e.mttd || {};

    var chips = eps.length > 1 ? '<div class="rchips">' + eps.map(function (x, i) {
      var col = (x.crowns_reached && x.crowns_reached.length) ? C.atk : C.ok;
      return '<button class="rchip' + (i === idx ? " on" : "") + '" data-ep="' + x.episode + '"><span class="tag-dot" style="background:' + col + '"></span>' + x.episode + "회차</button>";
    }).join("") + "</div>" : "";

    var tiles = [
      ["라운드", e.rounds + "회", "", "accent-teal", C.teal],
      ["핵심정보 유출", crowns.length + "종", crowns.length ? crowns.map(crownLabel).join(", ") : "없음", crowns.length ? "accent-atk" : "accent-ok", crowns.length ? C.atk : C.ok],
      ["차단", blocked + "회", "무효 패치 " + fake + "회", "accent-ok", C.ok],
      ["서비스 정상", pct(e.availability), "패치 후 가용성", "accent-def", C.def],
      ["공격 탐지율", pct(recall), "미탐 " + det.fn + "건", "accent-teal", C.teal],
      ["최고 침투", (e.max_flag_depth || 0) + "단계", "최대 4", "accent-crown", C.crown]
    ].map(function (t) {
      return '<div class="tile ' + t[3] + '"><div class="tile-k"><span class="tag-dot" style="background:' + t[4] + '"></span>' + t[0] + '</div><div class="tile-v">' + t[1] + "</div>" + (t[2] ? '<div class="tile-sub">' + t[2] + "</div>" : "") + "</div>";
    }).join("");

    var narr = "총 " + e.rounds + "라운드를 진행했습니다. " +
      (crowns.length ? "공격자가 핵심정보 " + crowns.length + "종(" + crowns.map(crownLabel).join(", ") + ")을 유출했고, " : "공격자는 핵심정보를 유출하지 못했고, ") +
      "방어는 " + blocked + "회 차단에 성공했으나 " + fake + "회는 패치 적용에도 차단하지 못했습니다(무효 패치). " +
      "공격 탐지율은 " + pct(recall) + ", 패치 후 서비스 정상 유지 비율은 " + pct(e.availability) + "입니다. " +
      "공격자는 최대 " + (e.max_flag_depth || 0) + "단계까지 침투했습니다.";

    var reported = {}; rs.forEach(function (r) { (r.reported_techniques || []).forEach(function (t) { reported[t] = 1; }); });
    var repList = Object.keys(reported);
    var cmp = '<div class="grid cols-2">' +
      '<div class="card flow-card c-atk"><div class="card-h">실제로 일어난 일</div>' +
        reportLine("핵심정보 유출", crowns.length ? crowns.map(crownLabel).join(", ") : "없음") +
        reportLine("최고 침투 단계", (e.max_flag_depth || 0) + "단계") +
        reportLine("달성 목표", (e.goals_reached || []).length ? e.goals_reached.join(", ") : "없음") + "</div>" +
      '<div class="card flow-card c-def"><div class="card-h">방어자가 파악한 것</div>' +
        reportLine("탐지한 기법", repList.length ? repList.join(", ") : "없음") +
        reportLine("탐지 정확도", "정탐 " + det.tp + " · 오탐 " + det.fp + " · 미탐 " + det.fn) +
        reportLine("평균 탐지 소요", mttd.mean_rounds != null ? mttd.mean_rounds + "라운드" : "—") + "</div></div>";

    var vbars = barChart([{ label: "차단", value: vc.blocked || 0, color: C.ok }, { label: "무효 패치", value: fake, color: C.atk }, { label: "판정불가", value: vc.inconclusive || 0, color: C.sys }]);
    var rows = rs.map(function (r) {
      var vv = VERDICT[r.verdict], depth = (r.stages_reached || []).length ? Math.max.apply(null, r.stages_reached) : 0;
      return "<tr><td class='mono'>R" + r.round + "</td><td>" + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : esc(r.verdict)) + "</td><td class='mono'>" + ((r.reported_techniques || []).join(", ") || "—") + "</td><td class='mono'>" + depth + "단계</td><td>" + (r.healthcheck_passed ? '<span class="badge b-ok">정상</span>' : '<span class="badge b-atk">중단</span>') + "</td></tr>";
    }).join("");
    var detail = '<details class="rep-details"><summary>전문가용 상세 보기</summary>' +
      '<div class="section-label">판정 분포</div><div class="card">' + vbars + "</div>" +
      '<div class="section-label">라운드별 타임라인</div><div class="card" style="padding:0;overflow:hidden"><table class="tbl"><thead><tr><th>라운드</th><th>판정</th><th>탐지 기법</th><th>침투</th><th>서비스</th></tr></thead><tbody>' + rows + "</tbody></table></div></details>";

    return (S.demo ? demoBanner() : "") + chips +
      '<div class="rep-head">' + e.episode + "회차 · " + e.rounds + "라운드 · " + esc(endReasonLabel(e.end_reason)) + "</div>" +
      '<div class="grid cols-6" style="margin:10px 0 2px">' + tiles + "</div>" +
      '<div class="card rep-narr">' + esc(narr) + "</div>" +
      '<div class="section-label">실제 vs 방어자 추측</div>' + cmp + detail;
  }

  // ───────── 스텁(다음 단계) ─────────
  function pageStub(id) {
    var info = {}[id] || ["•", TITLES[id] || id, "준비 중입니다.", []];
    return emptyState(info[0], info[1], info[2], info[3]);
  }
  function emptyState(mark, title, desc, feeds) {
    return '<div class="empty"><div class="e-mark">' + mark + '</div><h3>' + esc(title) + "</h3><p>" + esc(desc) + "</p>" +
      (feeds && feeds.length ? '<div class="e-feeds">' + feeds.map(function (f) { return '<span class="chip"><span class="tag-dot" style="background:' + f[1] + '"></span>' + esc(f[0]) + "</span>"; }).join("") + "</div>" : "") + "</div>";
  }
  function demoBanner() { return '<div class="demo-banner"><b>예시 데이터</b> · 실행 로그가 없어 예시 값을 표시합니다. 실행 시 실제 값으로 대체됩니다.</div>'; }

  // ───────── 렌더 ─────────
  async function render() {
    var view = $("#view"); $("#page-title").textContent = TITLES[route] || route;
    setActiveNav();
    if (route === "events") { await loadEvents(); view.innerHTML = pageEvents(); bindEventTabs(); return; }
    if (route === "attack-log") { await loadJournal(); view.innerHTML = pageAttackLog(); bindAttackLog(); return; }
    if (route === "defender-arch") { view.innerHTML = '<p class="page-intro">구성도 불러오는 중…</p>'; var topo = await loadTopology(); if (route === "defender-arch") view.innerHTML = pageArch(topo); return; }
    if (route === "defender-graph") { await pageDefGraphRender(); return; }
    if (route === "attack-graph") { await pageAttackGraphRender(); return; }
    if (!REAL[route]) { view.innerHTML = pageStub(route); return; }
    if (route === "posture") { view.innerHTML = pagePosture(); bindDrill(); }
    else if (route === "stats") { view.innerHTML = pageStats(); bindDrill(); }
    else if (route === "control") { view.innerHTML = pageControl(); bindControl(); }
    else if (route === "live") view.innerHTML = pageLive();
    else if (route === "report") { view.innerHTML = pageReport(); bindRepChips(); }
  }
  function bindRepChips() {
    Array.prototype.forEach.call(document.querySelectorAll(".rchip[data-ep]"), function (b) {
      b.onclick = function () { repEp = parseInt(b.getAttribute("data-ep"), 10); $("#view").innerHTML = pageReport(); bindRepChips(); };
    });
  }
  function bindEventTabs() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-evrun]"), function (b) {
      b.onclick = function () { evRun = b.getAttribute("data-evrun"); $("#view").innerHTML = pageEvents(); bindEventTabs(); };
    });
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
    else { S.status = st; dot.className = st.running ? "live" : ""; ct.textContent = st.running ? "실행 진행 중" : "대기"; }
    renderStatusBar(st === null ? S.status : st);

    var running = !!(st && st.running);
    if (running && !_wasRunning) {   // 새 실험 시작 감지 — 지난 실험의 선택·캐시 비워 '현재 실행만' 표시
      agRkey = null; agSel = null; S.agSeen = {}; S.agSig = null;
      defSel = null; S.defSig = null; repEp = null; S.detItems = null;
    }
    // 실행 중(또는 방금 종료)이면 로그 데이터도 재적재하고 현재 보는 개요 페이지를 갱신 — 실시간 반영
    if (running || _wasRunning) {
      await loadCore();
      await refreshLivePage();
    }
    _wasRunning = running;

    if (route === "live") $("#view").innerHTML = pageLive();
    if (route === "control") refreshRunStatus();
  }
  // 상단 상태바 — 모든 화면 공통. 실행 중이면 회차·라운드·단계·차례·경과를 한 줄로.
  function actorKo(a) { return a === "attacker" ? "공격" : a === "defender" ? "방어" : a === "judge" ? "심판" : "—"; }
  function renderStatusBar(st) {
    var el = $("#run-status"); if (!el) return;
    if (!(st && st.running)) {
      el.innerHTML = '<div class="sbar"><span class="sbar-state"><span class="sbar-dot"></span>' + (S.demo ? "예시 데이터" : "대기") + "</span></div>";
      return;
    }
    var phase = PHASES[st.phase || 0] || "—", acls = st.active === "attacker" ? "a-atk" : st.active === "defender" ? "a-def" : "a-sys";
    // 단계명이 '공격/방어 차례'면 차례 중복 → 그 외(검증·채점 등)에서만 담당 표기
    var showActor = st.active && st.phase !== 1 && st.phase !== 2;
    var started = st.turn_started || 0, limit = st.time_limit_sec || 180;
    var elapsed = started ? Math.max(0, Math.round(Date.now() / 1000 - started)) : 0, bp = clamp(elapsed / limit, 0, 1) * 100;
    var lv = st.last_verdict ? VERDICT[st.last_verdict] : null;
    el.innerHTML = '<div class="sbar live">' +
      '<span class="sbar-state on"><span class="sbar-dot"></span>실행 중</span>' +
      '<span class="sbar-seg"><span class="sbar-k">회차·R</span><span class="sbar-v ' + acls + '">' + (st.episode || 0) + " · " + (st.round || 0) + "</span></span>" +
      '<span class="sbar-seg sb-hide-sm"><span class="sbar-k">단계</span><span class="sbar-v">' + esc(phase) + "</span></span>" +
      (showActor ? '<span class="sbar-seg sb-hide-sm"><span class="sbar-k">담당</span><span class="sbar-v ' + acls + '">' + actorKo(st.active) + "</span></span>" : "") +
      '<span class="sbar-seg sb-time sb-hide-sm"><span class="sbar-v">' + elapsed + "s<i>/" + limit + 's</i></span><span class="sbar-bar"><b style="width:' + bp + '%"></b></span></span>' +
      (lv ? '<span class="sbar-seg sb-hide-sm"><span class="sbar-k">직전</span><span class="badge ' + lv.cls + '">' + lv.label + "</span></span>" : "") +
      "</div>";
  }
  async function refreshLivePage() {
    // 선택 상태 없는 개요 페이지만 자동 갱신(그래프·보고서는 사용자 선택 보존 위해 제외 — 재방문 시 최신)
    if (route === "posture") { $("#view").innerHTML = pagePosture(); bindDrill(); }
    else if (route === "stats") { $("#view").innerHTML = pageStats(); bindDrill(); }
    else if (route === "events") { await loadEvents(); $("#view").innerHTML = pageEvents(); bindEventTabs(); }
    else if (route === "attack-log") { await loadJournal(); $("#view").innerHTML = pageAttackLog(); bindAttackLog(); }
    else if (route === "attack-graph") await pageAttackGraphRender();
    else if (route === "defender-graph") { if (!document.querySelector(".modal-ov")) await pageDefGraphRender(); }
    else if (route === "defender-arch") { var topo = await loadTopology(); if (route === "defender-arch") $("#view").innerHTML = pageArch(topo); }
    else if (route === "report") { $("#view").innerHTML = pageReport(); bindRepChips(); }
  }

  // ───────── 라우팅·부팅 ─────────
  function onHash() {
    var r = (location.hash || "").replace(/^#/, "") || DEFAULT_ROUTE;
    if (!TITLES[r]) r = DEFAULT_ROUTE;
    if (r === "attack-graph") { S.agSeen = {}; S.agSig = null; }   // 진입 시 등장 애니메이션 재생
    route = r; closeSidebar(); render();
  }
  function closeSidebar() { $("#sidebar").classList.remove("open"); var bd = $("#sidebar-backdrop"); if (bd) bd.classList.remove("on"); $("#nav-toggle").setAttribute("aria-expanded", "false"); }

  async function boot() {
    buildNav();
    $("#nav-toggle").onclick = function () {
      var sb = $("#sidebar"), open = sb.classList.toggle("open");
      var bd = $("#sidebar-backdrop"); if (bd) bd.classList.toggle("on", open);
      this.setAttribute("aria-expanded", open ? "true" : "false");
    };
    var _bd = $("#sidebar-backdrop"); if (_bd) _bd.onclick = closeSidebar;
    var _sc = $("#sidebar-close"); if (_sc) _sc.onclick = closeSidebar;
    window.addEventListener("hashchange", onHash);
    // 속성 블록 호버 설명 — 위임 방식(렌더마다 바인딩 불필요)
    document.addEventListener("mouseover", function (e) {
      var el = e.target && e.target.closest ? e.target.closest(_TIP_SEL) : null;
      var tip = el ? lookupTip(el) : null;
      if (tip) showTip(el, tip); else hideTip();
    });
    window.addEventListener("scroll", hideTip, true);
    await loadCore();
    onHash();
    poll(); setInterval(poll, 2500);
  }
  boot();
})();
