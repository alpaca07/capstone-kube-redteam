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
      { id: "attack-brief", label: "공격 브리핑" },
      { id: "attack-graph", label: "공격 추적 그래프" },
      { id: "attack-log", label: "공격 저널" } ] },
    { group: "방어", items: [
      { id: "defender-arch", label: "타깃 구성도" },
      { id: "defender-graph", label: "탐지·패치 흐름" },
      { id: "defense-log", label: "방어 저널" } ] },
    { group: "기록", items: [
      { id: "events", label: "이벤트 로그" },
      { id: "report", label: "회차 보고서" } ] }
  ];
  var TITLES = { posture: "보안 현황", stats: "공격·방어 통계", control: "실행 제어",
    live: "실시간 현황", events: "이벤트 로그", "attack-brief": "공격 브리핑", "attack-graph": "공격 추적 그래프", "attack-log": "공격 저널",
    "defender-arch": "타깃 구성도", "defender-graph": "탐지·패치 흐름", "defense-log": "방어 저널",
    report: "회차 보고서" };
  var DEFAULT_ROUTE = "posture";
  var REAL = { posture: 1, stats: 1, control: 1, live: 1, events: 1, "defender-arch": 1, "defender-graph": 1, "defense-log": 1, "attack-brief": 1, "attack-graph": 1, "attack-log": 1, report: 1 };

  // ⬆⬆ 빌드 버전 — 패치할 때마다 +1 (server.py 의 SERVER_BUILD 과 같은 값으로 함께 올린다).
  // 좌상단에 v<UI_BUILD> 를 표시하고, 서버가 보고한 server_build 와 다르면 '재시작 필요' 경고를 띄운다.
  var UI_BUILD = 22;
  function renderBuild(serverBuild) {
    var el = document.getElementById("build-tag");
    if (!el) return;
    var stale = (serverBuild != null && serverBuild !== UI_BUILD);
    el.textContent = "v" + UI_BUILD + (stale ? " ⚠" : "");
    el.className = "brand-tag" + (stale ? " stale" : "");
    el.title = stale ? ("서버는 v" + serverBuild + " — 대시보드 재시작 필요(최신 코드 미반영)")
                     : ("빌드 v" + UI_BUILD);
  }

  // ───────── 다크모드 ─────────
  var _dark = localStorage.getItem("helix-dark") === "1";
  function applyTheme() {
    document.documentElement.classList.toggle("dark", _dark);
    C_update();
    VERDICT = _verdict();
    var btn = document.getElementById("theme-btn");
    if (btn) btn.textContent = _dark ? "☀" : "☾";
  }
  function toggleTheme() { _dark = !_dark; localStorage.setItem("helix-dark", _dark ? "1" : "0"); applyTheme(); }

  // ───────── 색 상수(의미색 — CSS 변수와 1:1, 다크모드 연동) ─────────
  var C_LIGHT = { atk: "#e5484d", def: "#3b82f6", sys: "#64748b", crown: "#e5920b",
    ok: "#0ea371", teal: "#0d9488", grid: "#e3e8ee", muted: "#8a97ab", text: "#0f1b2d" };
  var C_DARK = { atk: "#f87171", def: "#60a5fa", sys: "#94a3b8", crown: "#fbbf24",
    ok: "#34d399", teal: "#2dd4bf", grid: "#293549", muted: "#64748b", text: "#e4e9f1" };
  var C = Object.assign({}, C_LIGHT);
  function C_update() { var src = _dark ? C_DARK : C_LIGHT; for (var k in src) C[k] = src[k]; }
  function _verdict() { return {
    blocked: { label: "차단", color: C.ok, cls: "b-ok" },
    fake_patch: { label: "무효 패치", color: C.atk, cls: "b-atk" },
    not_blocked: { label: "미차단", color: C.atk, cls: "b-atk" },
    service_broken: { label: "무효 패치·서비스 중단", color: C.atk, cls: "b-atk" },
    inconclusive: { label: "판정 불가", color: C.sys, cls: "b-sys" }
  }; }
  var VERDICT = _verdict();
  // 핵심 자산 식별자 → 쉬운 말
  // 크라운 라벨 — 알려진 2종만 친화명, 그 외는 실제 크라운 id(대상)를 그대로 노출(목표는 설정 주도).
  function crownLabel(c) {
    return ({ "crown-secrets": "내부 비밀 유출", "crown-pii": "고객정보 유출", "crown-ops": "운영 비밀 유출" })[c] ||
      (c ? String(c).replace(/^crown[-_]?/i, "") + " 유출" : "핵심정보 유출");
  }
  // 탐지 판정(god-view 대조) 배지·조회 — 정탐/오탐/미탐
  var DET_V = { tp: { ko: "정탐", cls: "b-ok" }, fp: { ko: "오탐", cls: "b-fp" },
    fn: { ko: "미탐", cls: "b-fn" }, unknown: { ko: "판정 보류", cls: "b-sys" } };
  function detBadge(v) { var m = DET_V[v]; return m ? '<span class="badge ' + m.cls + '">' + m.ko + "</span>" : ""; }
  function detEvalByTech(de, tech) {   // detection_eval.items 에서 기법 판정 조회(없으면 null)
    if (!de || !de.items) return null;
    for (var i = 0; i < de.items.length; i++) { if (de.items[i].technique === tech) return de.items[i]; }
    return null;
  }
  function detMissedHtml(de, item) {   // 미탐(실제 발생·방어 미보고) 항목들
    if (!de || !de.missed || !de.missed.length) return "";
    return de.missed.map(function (m) {
      return '<div class="' + item + ' det-missed"><div class="fi-head"><span class="badge b-fn">미탐</span>' +
        '<span class="badge b-atk">' + esc(m.technique) + "</span></div>" +
        '<div class="det-why det-fn">' + esc(m.reason) + "</div></div>";
    }).join("");
  }
  // 턴 종료 사유(enum) → 쉬운 말
  function reasonLabel(r) { return ({ flag: "목표 도달", deadend: "막다른 길", timeout: "시간 초과",
    budget: "예산 소진", max_steps: "명령 한도", error: "오류", patched: "패치 완료", skipped: "건너뜀" })[r] || r || "—"; }

  // 방어 턴이 '크라운 미반출'로 생략된 라운드인가 — end_reason/defense_end_reason 로 판별.
  //   생략 라운드는 방어가 서비스를 안 건드려 healthcheck_passed 가 기본 false 지만 '서비스 중단'이 아님 → 중립 표시.
  function _dSkipped(x) { return !!x && (x.end_reason === "skipped" || x.defense_end_reason === "skipped"); }

  // ───────── 상태 ─────────
  var S = { rounds: [], episodes: [], runs: [], events: [], journal: [], status: {}, demo: false, runCount: 0, detItems: null };
  var route = DEFAULT_ROUTE, evTab = "all", defSel = null, repEp = null, agRkey = null, agSel = null, agTab = "overview", agLogView = "intent", evRun = null, jRun = null, agView = null, agLogOpen = null, agHide = {}, agRaw = false, briefEp = null, _wasRunning = false, dlRun = null, dlOpen = null, agMode = "graph", agFull = false;

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
    if (window.__SNAPSHOT__) {                 // 스냅샷 모드 — 박제된 데이터만 읽고 네트워크 안 씀(공유용 단일 HTML)
      var k = (path || "").split("?")[0];
      return (k in window.__SNAPSHOT__) ? window.__SNAPSHOT__[k] : null;
    }
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
    var avail = null, ac = 0, an = 0; S.episodes.forEach(function (e) { if (e.availability != null) { ac += e.availability; an++; } });
    if (an) avail = ac / an;
    return { decided: decided, blocked: blocked, fake: fake, crownRounds: crownRounds, nrounds: rs.length,
      blockRate: decided ? blocked / decided : null, fakeRate: decided ? fake / decided : null,
      crownRate: rs.length ? crownRounds / rs.length : null, recall: recall,
      avail: avail, det: lastDet || { tp: 0, fp: 0, fn: 0 } };
  }
  // 목표(크라운) 축 집계 — 선형 침투 단계를 대체. 자산(objective) 단위라 타깃이 N개로 늘어도
  // '침해된 핵심 자산 종 수'로 그대로 확장된다(고정 4단계 킬체인 가정 없음).
  function goalAgg() {
    var seen = {}, goalsSet = {}, series = [], crownRounds = 0, firstCrownRound = null;
    S.rounds.forEach(function (r) {
      (r.crowns_reached_cum || []).forEach(function (c) { seen[c] = 1; });  // 전체 실행 누적(회차 경계 넘어 합집합)
      (r.goals_reached_cum || []).forEach(function (g) { goalsSet[g] = 1; });
      if ((r.crowns_reached_cum || []).length) { crownRounds++; if (firstCrownRound == null) firstCrownRound = (r.episode || 1) + "-" + r.round; }
      series.push(Object.keys(seen).length);   // 그 라운드 시점까지 침해된 고유 자산 종 수(단조 증가)
    });
    S.episodes.forEach(function (e) {           // 끝난 회차 요약도 합산
      (e.crowns_reached || []).forEach(function (c) { seen[c] = 1; });
      (e.goals_reached || []).forEach(function (g) { goalsSet[g] = 1; });
    });
    return { crowns: Object.keys(seen), goals: Object.keys(goalsSet), series: series,
      crownRounds: crownRounds, firstCrownRound: firstCrownRound, nrounds: S.rounds.length };
  }
  // 심판 god-view CVSS(공인 등급) — 크라운별 {score,severity,vector,basis}. 회차 확정값 우선, 없으면 라운드 최신.
  function crownCvss() {
    var out = {};
    S.rounds.forEach(function (r) { var bc = r.breach_cvss || {}; Object.keys(bc).forEach(function (c) { out[c] = bc[c]; }); });
    S.episodes.forEach(function (e) { var bc = e.breach_cvss || {}; Object.keys(bc).forEach(function (c) { out[c] = bc[c]; }); });
    return out;
  }
  function sevKo(s) { return ({ none: "없음", low: "낮음", medium: "중간", high: "높음", critical: "치명적" })[String(s).toLowerCase()] || s; }
  // 크라운 집합의 최고 CVSS(보안 현황 타일용)
  function maxCrownCvss(crowns) {
    var cc = crownCvss(), top = null;
    (crowns || []).forEach(function (c) { var v = cc[c]; if (v && (!top || v.score > top.score)) top = v; });
    return top;
  }
  // 핵심 자산 침해 공인 등급 카드(CVSS v3.1 심판 산정) — 브리핑·보고서 공용.
  function cvssCard(crowns) {
    var cc = crownCvss();
    var list = (crowns || []).filter(function (c) { return cc[c]; }).sort(function (a, b) { return cc[b].score - cc[a].score; });
    if (!list.length) return "";
    var rows = list.map(function (c) {
      var v = cc[c], sev = String(v.severity).toLowerCase();
      return '<div class="cvss-row sev-' + sev + '">' +
        '<div class="cvss-score sev-' + sev + '"><span class="cvss-num">' + v.score + '</span><span class="sev-badge sev-' + sev + '">' + sevKo(sev) + "</span></div>" +
        '<div class="cvss-main"><div class="cvss-asset">' + esc(crownLabel(c)) + "</div>" +
        '<div class="cvss-basis">' + esc(v.basis || "") + "</div>" +
        '<div class="cvss-vec mono">' + esc(v.vector || "") + "</div></div></div>";
    }).join("");
    return '<div class="section-label">핵심 자산 침해 · 공인 위험도(CVSS v3.1 · 심판 산정)</div>' +
      '<div class="card cvss-card">' + rows +
      '<div class="tile-sub" style="margin-top:4px">심판 god-view 로 확정된 핵심 자산 침해입니다. 개별 발견은 전술·확보 데이터로 추정하며 신뢰도를 함께 표기합니다.</div></div>';
  }
  // ── CVSS v3.1 Base 산식(프론트) — orchestrator/cvss.py 와 동일. 비크라운 발견을 공인 등급으로 매기기 위함 ──
  var _CVW = { AV: { N: .85, A: .62, L: .55, P: .2 }, AC: { L: .77, H: .44 },
    PRU: { N: .85, L: .62, H: .27 }, PRC: { N: .85, L: .68, H: .5 }, UI: { N: .85, R: .62 }, CIA: { N: 0, L: .22, H: .56 } };
  function _cvRound(x) { var i = Math.round(x * 100000); return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; }
  function _cvSev(s) { if (s <= 0) return "none"; if (s < 4) return "low"; if (s < 7) return "medium"; if (s < 9) return "high"; return "critical"; }
  function cvssJs(m) {
    var c = _CVW.CIA[m.c], i = _CVW.CIA[m.i], a = _CVW.CIA[m.a];
    var iss = 1 - (1 - c) * (1 - i) * (1 - a);
    var impact = (m.s === "C") ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    var prw = (m.s === "C" ? _CVW.PRC : _CVW.PRU)[m.pr];
    var expl = 8.22 * _CVW.AV[m.av] * _CVW.AC[m.ac] * prw * _CVW.UI[m.ui];
    var sc = impact <= 0 ? 0 : (m.s === "C" ? _cvRound(Math.min(1.08 * (impact + expl), 10)) : _cvRound(Math.min(impact + expl, 10)));
    return { score: sc, severity: _cvSev(sc),
      vector: "CVSS:3.1/AV:" + m.av + "/AC:" + m.ac + "/PR:" + m.pr + "/UI:" + m.ui + "/S:" + m.s + "/C:" + m.c + "/I:" + m.i + "/A:" + m.a };
  }
  // ATT&CK 전술 → 영향축(기밀 C·무결 I·가용 A·범위 S). 하위기법은 상위로 접어 매핑.
  var _TECH_IMPACT = {
    T1213: { c: "H" }, T1005: { c: "H" }, T1530: { c: "H" }, T1040: { c: "H" },     // 수집·탈취 → 기밀
    T1552: { c: "H", s: "C" }, T1555: { c: "H", s: "C" }, T1078: { c: "H", s: "C" }, // 자격증명·유효계정 → 기밀+범위
    T1496: { a: "H", s: "C" }, T1486: { a: "H" }, T1490: { a: "H" }, T1489: { a: "H" }, T1485: { i: "H" }, // 자원·파괴
    T1610: { i: "H", s: "C" }, T1609: { i: "H", s: "C" }, T1611: { i: "H", s: "C" }, // 컨테이너·실행 → 무결+범위
    T1059: { i: "H" }, T1053: { i: "H" }, T1068: { i: "H", s: "C" }, T1548: { s: "C" }, // 실행·권한상승
    T1046: { c: "L" }, T1018: { c: "L" }, T1083: { c: "L" }, T1087: { c: "L" }, T1082: { c: "L" }, // 정찰 → 정보 노출
  };
  var _CROWN_BY_MITRE = { T1213: ["crown-pii", "crown-secrets"], T1496: ["crown-resource-hijack"], T1610: ["crown-container-deploy"] };
  function _axisKo(vec) {
    var ax = [];
    if (vec.c === "H") ax.push("기밀성 High"); else if (vec.c === "L") ax.push("기밀성 Low");
    if (vec.i === "H") ax.push("무결성 High"); else if (vec.i === "L") ax.push("무결성 Low");
    if (vec.a === "H") ax.push("가용성 High"); else if (vec.a === "L") ax.push("가용성 Low");
    if (vec.s === "C") ax.push("권한 범위 확대");
    return ax.join(", ") || "영향 미상";
  }
  // 발견 노드 위험도 — 하이브리드: 크라운 확정(심판 god-view) > loot 입증 > 공격자 주장.
  function findingCvss(node) {
    var bt = _baseTech(node.technique), cc = crownCvss();
    if (node.crown_id) {                           // god-view 주입 발견 — 해당 크라운 등급 직접(확정)
      var cj = cc[node.crown_id] || (node.cvss && node.cvss.score ? node.cvss : null);
      if (cj) return { score: cj.score, severity: cj.severity, vector: cj.vector, confidence: "확정",
        basis: "심판 god-view 로 확정된 핵심 자산 침해 — " + (cj.basis || "") };
    }
    var crowns = (_CROWN_BY_MITRE[bt] || []).filter(function (c) { return cc[c]; });
    if (crowns.length) {                           // 크라운 확정 — 심판 god-view 등급 사용
      crowns.sort(function (a, b) { return cc[b].score - cc[a].score; });
      var jv = cc[crowns[0]];
      return { score: jv.score, severity: jv.severity, vector: jv.vector, confidence: "확정",
        basis: "심판 god-view 로 확정된 핵심 자산 침해 — " + (jv.basis || "") };
    }
    var imp = _TECH_IMPACT[bt];
    var hasLoot = (node.loot != null && String(node.loot) !== "");
    if (!imp) imp = hasLoot ? { c: "H" } : { c: "L" };    // 전술 미상 — loot 있으면 기밀, 없으면 정보 노출
    var vec = { s: imp.s || "U", c: imp.c || "N", i: imp.i || "N", a: imp.a || "N" };
    var conf;
    if (hasLoot) { conf = "입증"; }                 // 확보 데이터 — 관측 기반
    else { conf = "주장"; if (vec.c === "H") vec.c = "L"; }  // 공격자 보고만 — 기밀성축 하향
    var r = cvssJs({ av: "N", ac: "L", pr: "N", ui: "N", s: vec.s, c: vec.c, i: vec.i, a: vec.a });
    var src = hasLoot ? "확보 데이터로 입증" : "공격자 보고 기반(미입증)";
    return { score: r.score, severity: r.severity, vector: r.vector, confidence: conf,
      basis: (bt ? bt + " 전술 — " : "") + _axisKo(vec) + " · " + src };
  }
  function _confCls(c) { return c === "확정" ? "ok" : c === "입증" ? "def" : "sys"; }
  // 발견 노드 CVSS 공인 등급 블록(노드 상세 패널용)
  function agCvssBlock(fc, n) {
    var sev = String(fc.severity).toLowerCase();
    return '<div class="ag-cvss sev-' + sev + '">' +
      '<div class="ag-cvss-top"><span class="ag-cvss-score sev-' + sev + '">' + fc.score + "</span>" +
      '<span class="sev-badge sev-' + sev + '">CVSS ' + sevKo(fc.severity) + "</span>" +
      '<span class="ag-cvss-conf cf-' + _confCls(fc.confidence) + '">' + fc.confidence + "</span></div>" +
      '<div class="ag-cvss-basis">' + esc(fc.basis) + "</div>" +
      '<div class="ag-cvss-vec mono">' + esc(fc.vector) + "</div>" +
      ((n.severity && fc.confidence !== "확정") ? '<div class="ag-cvss-claim">공격자 주장 등급: ' + esc(n.severity) + "</div>" : "") + "</div>";
  }
  // 노드 그래프 기반 자산별 침해 단계 — target 으로 자산을 묶고 도달 깊이를 매긴다.
  // 단계는 타깃마다 독립(0 미접근·1 정찰접근·2 정보확보·3 침해확인·4 데이터반출) → 자산 수만큼 병렬.
  var BREACH_STAGE = { 0: "미접근", 1: "정찰·접근", 2: "정보 확보", 3: "침해 확인", 4: "데이터 반출" };
  var _SEVR = { critical: 4, high: 3, medium: 2, low: 1 };
  function assetBreach(nodes) {
    var by = {};
    function ens(t) { if (!by[t]) by[t] = { target: t, stage: 0, intents: [], facts: [], findings: [], tech: {}, loot: false, maxSev: null, rounds: {} }; return by[t]; }
    (nodes || []).forEach(function (n) {
      if (n.kind === "goal") return;
      var t = n.target || "미지정 대상";
      var a = ens(t);
      if (n.technique) a.tech[n.technique] = 1;
      if (n.round != null) a.rounds[n.round] = 1;
      if (n.kind === "intent") { a.intents.push(n); if (a.stage < 1) a.stage = 1; }
      else if (n.kind === "fact") { a.facts.push(n); if (a.stage < 2) a.stage = 2; }
      else if (n.kind === "finding") {
        a.findings.push(n);
        var hasLoot = (n.loot != null && String(n.loot) !== ""); if (hasLoot) a.loot = true;
        a.stage = Math.max(a.stage, hasLoot ? 4 : 3);
        if ((_SEVR[String(n.severity).toLowerCase()] || 0) > (_SEVR[String(a.maxSev).toLowerCase()] || 0)) a.maxSev = n.severity;
      }
    });
    var list = Object.keys(by).map(function (t) { var a = by[t]; a.stageLabel = BREACH_STAGE[a.stage]; a.tech = Object.keys(a.tech); a.rounds = Object.keys(a.rounds).map(Number).sort(function (x, y) { return x - y; }); return a; });
    list.sort(function (x, y) { return y.stage - x.stage || (_SEVR[String(y.maxSev).toLowerCase()] || 0) - (_SEVR[String(x.maxSev).toLowerCase()] || 0); });
    return list;
  }
  function verdictCounts() {
    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, service_broken: 0, inconclusive: 0 };
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
      var li = s.points.length - 1; if (li >= 0) body += '<circle cx="' + X(li) + '" cy="' + Y(s.points[li]) + '" r="4" fill="' + s.color + '" stroke="' + (_dark ? "#161d2b" : "#fff") + '" stroke-width="1.5"/>';
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

  // ───────── 타깃 인식 — 실행별 공격 목표(ShopFlow 선형 체인 vs corp 크라운) ─────────
  // 최신 실행 params.target(크라운 id CSV) → corp 자산 모드면 목표 크라운 배열, ShopFlow·config·데모면 null.
  function targetCrowns() {
    if (S.demo) return null;                           // 예시 데이터는 ShopFlow 색 → 선형 단계 뷰 유지
    var run = (S.runs && S.runs.length) ? S.runs[0] : null;
    var t = run && run.params ? run.params.target : null;
    if (!t || t === "(config)") return null;
    return String(t).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  }

  // ───────── 페이지: 보안 현황 ─────────
  function pagePosture() {
    var a = agg(), ga = goalAgg(), _topCv = maxCrownCvss(ga.crowns);
    var tiles = [
      { k: "핵심 자산 침해", v: ga.crowns.length + "종", sub: ga.crowns.length ? (ga.crowns.map(crownLabel).join(", ") + (_topCv ? " · CVSS " + _topCv.score + " " + sevKo(_topCv.severity) : "")) : "반출된 핵심 자산 없음", cls: ga.crowns.length ? "accent-atk" : "accent-ok", dot: ga.crowns.length ? C.atk : C.ok },
      { k: "공격 차단율", v: pct(a.blockRate), sub: "검증상 차단된 비율 (검증 " + a.decided + "건)", cls: "accent-ok", dot: C.ok },
      { k: "무효 패치율", v: pct(a.fakeRate), sub: "패치 적용에도 미차단 " + a.fake + "건", cls: a.fake ? "accent-atk" : "accent-ok", dot: C.atk },
      { k: "서비스 정상", v: pct(a.avail), sub: "패치 후 서비스 정상 비율", cls: "accent-def", dot: C.def },
      { k: "공격 탐지율", v: pct(a.recall), sub: "미탐 " + a.det.fn + "건", cls: "accent-teal", dot: C.teal },
      { k: "목표 도달", v: a.crownRounds + "회", sub: a.crownRounds ? "핵심 자산 반출 라운드 (전체 " + a.nrounds + ")" : "전체 " + a.nrounds + "라운드 방어 유지", cls: a.crownRounds ? "accent-crown" : "accent-ok", dot: C.crown }
    ];
    var tileHtml = tiles.map(function (t) {
      return '<div class="tile ' + t.cls + '"><div class="tile-k"><span class="tag-dot" style="background:' + t.dot + '"></span>' + t.k + '</div>' +
        '<div class="tile-v">' + t.v + '</div><div class="tile-sub">' + t.sub + "</div></div>";
    }).join("");

    var vcard = verdictCard();

    var hl = highlights();
    var hcard = '<div class="card"><div class="card-h">주요 사건</div>' +
      (hl.length ? hl.map(function (x) { return '<div class="hl-row"><span class="hl-ic" style="background:' + x.color + '"></span><div><div>' + x.text + '</div><div class="mono">' + x.meta + "</div></div></div>"; }).join("")
        : '<div class="tile-sub">특이 사건 없음</div>') + "</div>";

    return (S.demo ? demoBanner() : "") +
      '<div class="grid cols-6">' + tileHtml + "</div>" +
      '<div class="section-label">검증 결과 · 주요 사건</div><div class="grid cols-2">' + vcard + hcard + "</div>";
  }
  function highlights() {
    var out = [];
    S.rounds.forEach(function (r) {
      if ((r.crowns_reached_cum || []).length && r.verdict === "fake_patch")
        out.push({ color: C.atk, text: "R" + r.round + ": 패치 적용에도 핵심정보 유출 — 무효 패치",
          meta: (r.crowns_reached_cum.map(crownLabel).join(", ")) + " · " + (r.reported_techniques || []).join(" ") });
      else if (r.verdict === "blocked")
        out.push({ color: C.ok, text: "R" + r.round + ": 공격 차단 확인",
          meta: (r.reported_techniques || []).length ? "탐지 기법 " + r.reported_techniques.join(", ") : "검증상 차단" });
    });
    return out.slice(0, 5);
  }

  // ───────── 통계 공용 헬퍼 ─────────
  function baseTech(t) { return String(t || "").split(".")[0]; }   // 서브기법→부모(T1078.004→T1078)
  function chartCard(title, body, sub) {
    return '<div class="card"><div class="card-h">' + title + "</div>" + body +
      (sub ? '<div class="tile-sub" style="margin-top:8px">' + sub + "</div>" : "") + "</div>";
  }
  function chartLegend(items) {
    return '<div class="chart-leg">' + items.map(function (x) {
      return '<span class="chart-leg-i"><span class="chart-leg-dot" style="background:' + x.color + '"></span>' + esc(x.label) + "</span>";
    }).join("") + "</div>";
  }
  function noDataCard(title, msg) {
    return chartCard(title, '<div class="tile-sub" style="padding:24px 4px;text-align:center">' + msg + "</div>");
  }

  // ───────── 페이지: 공격·방어 통계 ─────────
  function pageStats() {
    var a = agg(), ga = goalAgg(), rs = S.rounds || [], eps = S.episodes || [];
    var xmax = Math.max(rs.length, 1);
    var hasTruth = rs.some(function (r) { return (r.truth_techniques_cum || []).length; });
    var TNOTE = "god-view 기법 데이터는 v9 이후 수집분부터 — 런 재실행 필요";

    // 회차별 최초 침해(돌파) 라운드 {ep: round|null}
    function episodeBreachRounds() {
      var first = {}, eset = {};
      rs.forEach(function (r) { var ep = r.episode || 1; eset[ep] = 1; if ((r.crowns_reached_cum || []).length && first[ep] == null) first[ep] = r.round; });
      eps.forEach(function (e) { if (eset[e.episode] == null) eset[e.episode] = 1; });
      var out = {}; Object.keys(eset).forEach(function (ep) { out[ep] = first[ep] != null ? first[ep] : null; });
      return out;
    }
    // base 기법 → 등장(지속) 라운드 수. cum 이라 최초 등장 이후 끝까지 지속 → 지속성 지표.
    function truthFreq() {
      var m = {}; rs.forEach(function (r) { var seen = {}; (r.truth_techniques_cum || []).forEach(function (t) { var b = baseTech(t); if (!seen[b]) { seen[b] = 1; m[b] = (m[b] || 0) + 1; } }); });
      return Object.keys(m).map(function (k) { return { k: k, v: m[k] }; }).sort(function (x, y) { return y.v - x.v; });
    }

    // ── 종합 지표(KPI) ──
    var CROWN_TOTAL = 4;                                  // 환경 정의 핵심 자산 4종(pii·secrets·resource-hijack·container-deploy)
    var crownsN = ga.crowns.length;
    var haveD = (a.recall != null) || (a.blockRate != null) || (a.avail != null);
    var defScore = haveD ? ((a.recall == null ? 0 : a.recall) * 0.4 + (a.blockRate == null ? 0 : a.blockRate) * 0.3 + (a.avail == null ? 0 : a.avail) * 0.3) : null;
    var mv = [], mdet = 0, mtot = 0; eps.forEach(function (e) { var m = e.mttd || {}; if (m.mean_rounds != null) mv.push(m.mean_rounds); mdet += m.detected || 0; mtot += m.total_true || 0; });
    var mttdAvg = mv.length ? mv.reduce(function (s, x) { return s + x; }, 0) / mv.length : null;
    var br = episodeBreachRounds();
    var brVals = Object.keys(br).map(function (k) { return br[k]; }).filter(function (v) { return v != null; });
    var brAvg = brVals.length ? brVals.reduce(function (s, x) { return s + x; }, 0) / brVals.length : null;
    var unbreached = Object.keys(br).filter(function (ep) { return br[ep] == null; }).length;
    var techN = truthFreq().length, ob = overBlockCount();
    var kpis = [
      { k: "공격 성공률", v: pct(crownsN / CROWN_TOTAL), sub: "핵심 자산 " + crownsN + "/" + CROWN_TOTAL + "종 반출", cls: crownsN ? "accent-atk" : "accent-ok", dot: crownsN ? C.atk : C.ok },
      { k: "방어 종합점수", v: pct(defScore), sub: "탐지·차단·가용성 가중", cls: "accent-def", dot: C.def },
      { k: "평균 탐지지연", v: mttdAvg != null ? mttdAvg.toFixed(1) + "R" : "—", sub: "탐지 기법 " + mdet + "/" + mtot, cls: "accent-teal", dot: C.teal },
      { k: "평균 돌파 라운드", v: brAvg != null ? brAvg.toFixed(1) + "R" : "—", sub: unbreached ? ("미돌파 " + unbreached + "회차") : "전 회차 돌파", cls: "accent-crown", dot: C.crown },
      { k: "공격 기법 수", v: hasTruth ? (techN + "종") : "—", sub: "god-view 누적 고유 기법", cls: "accent-atk", dot: C.atk },
      { k: "과잉차단", v: ob + "회", sub: "패치했으나 서비스 중단", cls: ob ? "accent-crown" : "accent-ok", dot: ob ? C.crown : C.ok }
    ];
    var kpiHtml = kpis.map(function (t) {
      return '<div class="tile ' + t.cls + '"><div class="tile-k"><span class="tag-dot" style="background:' + t.dot + '"></span>' + t.k + "</div>" +
        '<div class="tile-v">' + t.v + '</div><div class="tile-sub">' + t.sub + "</div></div>";
    }).join("");

    // ── 침해: (a)라운드별 신규 침해 막대, (b)회차별 돌파까지 라운드 ──
    var seenCr = {}, nbItems = rs.map(function (r) {
      var before = Object.keys(seenCr).length; (r.crowns_reached_cum || []).forEach(function (c) { seenCr[c] = 1; });
      return { value: Object.keys(seenCr).length - before, label: ((r.episode || 1) > 1 ? (r.episode) + "-" : "") + "R" + r.round, color: C.atk };
    });
    var newBreachCard = nbItems.length
      ? chartCard("라운드별 신규 침해", barChart(nbItems), "그 라운드에 새로 반출된 핵심 자산 종 수 (누적 아님 — 압박이 터진 지점)")
      : noDataCard("라운드별 신규 침해", "라운드 데이터 없음");
    var brKeys = Object.keys(br).sort(function (x, y) { return x - y; });
    var brItems = brKeys.map(function (ep) { return { value: br[ep] || 0, label: "E" + ep, color: br[ep] ? C.crown : C.ok, sub: br[ep] ? null : "미돌파" }; });
    var breachLatencyCard = brItems.length
      ? chartCard("회차별 돌파까지 라운드", barChart(brItems), "방어가 버틴 라운드 수 — 값이 클수록(늦을수록) 방어 우세")
      : noDataCard("회차별 돌파까지 라운드", "회차 데이터 없음");

    // ── 위험도·공격 전개 ──
    var cvSer = rs.map(function (r) { var b = r.breach_cvss || {}, s = 0; Object.keys(b).forEach(function (k) { s += (b[k] && b[k].score) || 0; }); return s; });
    var cvssCard = chartCard("CVSS 가중 침해 점수 추이",
      lineChart([{ color: C.crown, points: cvSer }], xmax, { ymax: Math.max.apply(null, [1].concat(cvSer)) }),
      "라운드별 침해 크라운 CVSS 합 — 개수 대신 심각도 가중");
    var kcSer = rs.map(function (r) { var s = r.stages_reached || []; return s.length ? Math.max.apply(null, s) : 0; });
    var kcMax = Math.max.apply(null, [1].concat(kcSer));
    var killchainCard = chartCard("킬체인 단계 추이",
      lineChart([{ color: C.atk, points: kcSer }], xmax, { ymax: kcMax }),
      "라운드별 god-view 최고 도달 단계 (최대 " + kcMax + "단계)");
    var distItems = []; for (var k = 1; k <= kcMax; k++) { (function (k) { var c = 0; kcSer.forEach(function (v) { if (v >= k) c++; }); distItems.push({ value: c, label: "①②③④⑤⑥".charAt(k - 1) || ("L" + k), color: C.atk }); })(k); }
    var chainDistCard = distItems.length
      ? chartCard("킬체인 단계별 도달 라운드", barChart(distItems), "각 단계 이상 도달한 라운드 수 — 어디서 막혔나")
      : noDataCard("킬체인 단계별 도달 라운드", "단계 데이터 없음");
    var tdSer = rs.map(function (r) { var s = {}; (r.truth_techniques_cum || []).forEach(function (t) { s[baseTech(t)] = 1; }); return Object.keys(s).length; });
    var techDivCard = hasTruth
      ? chartCard("공격 기법 다양성 추이", lineChart([{ color: C.atk, points: tdSer }], xmax, { ymax: Math.max.apply(null, [1].concat(tdSer)) }), "라운드별 god-view 누적 고유 기법 수")
      : noDataCard("공격 기법 다양성 추이", TNOTE);

    // ── 탐지·검증 추세 ── (드릴 카드는 와이드에서 2칸 차지)
    var dcard = detectionCard("span-2"), vcard = verdictCard("span-2");
    var pSer = [], rSer = [];
    rs.forEach(function (r) { var c = r.detection_cum || {}, tp = c.tp || 0, fp = c.fp || 0, fn = c.fn || 0; pSer.push(tp + fp ? tp / (tp + fp) : 0); rSer.push(tp + fn ? tp / (tp + fn) : 0); });
    var prCard = chartCard("정밀도 · 재현율 추이",
      chartLegend([{ color: C.teal, label: "정밀도" }, { color: C.def, label: "재현율" }]) +
      lineChart([{ color: C.teal, points: pSer }, { color: C.def, points: rSer }], xmax, { ymax: 1, pct: true }),
      "누적 혼동행렬 기준 — 탐지 품질이 라운드 진행에 따라 느는가");

    // ── 소요 시간 ──
    var aSec = rs.map(function (r) { return Math.round(r.elapsed_attack_sec || 0); }), dSec = rs.map(function (r) { return Math.round(r.elapsed_defense_sec || 0); });
    var secMax = Math.max.apply(null, [1].concat(aSec, dSec));
    var elapsedCard = chartCard("라운드 소요 시간(초) 추이",
      chartLegend([{ color: C.atk, label: "공격" }, { color: C.def, label: "방어" }]) +
      lineChart([{ color: C.atk, points: aSec }, { color: C.def, points: dSec }], xmax, { ymax: secMax }),
      "에이전트 턴 소요 — 병목·비용 추적");

    // ── 기법 분포 ──
    var tf = truthFreq();
    var techFreqCard = hasTruth
      ? chartCard("공격 기법별 지속 라운드", barChart(tf.slice(0, 8).map(function (x) { return { value: x.v, label: x.k, color: C.atk }; })), "god-view 기법이 활성이던 라운드 수(상위 8)")
      : noDataCard("공격 기법별 지속 라운드", TNOTE);
    var repBase = {}; rs.forEach(function (r) { (r.reported_techniques || []).forEach(function (t) { repBase[baseTech(t)] = 1; }); });
    var missed = tf.filter(function (x) { return !repBase[x.k]; });
    var missedCard = hasTruth
      ? (missed.length ? chartCard("미탐 기법 Top-8", barChart(missed.slice(0, 8).map(function (x) { return { value: x.v, label: x.k, color: C.crown }; })), "실제 발생했으나 한 번도 탐지 못한 기법 — 방어 공백")
        : noDataCard("미탐 기법 Top-8", "미탐 기법 없음 — 발생 기법 전부 탐지됨"))
      : noDataCard("미탐 기법 Top-8", TNOTE);
    var truthBase = {}; rs.forEach(function (r) { (r.truth_techniques_cum || []).forEach(function (t) { truthBase[baseTech(t)] = 1; }); });
    var fpm = {}; rs.forEach(function (r) { var seen = {}; (r.reported_techniques || []).forEach(function (t) { var b = baseTech(t); if (!truthBase[b] && !seen[b]) { seen[b] = 1; fpm[b] = (fpm[b] || 0) + 1; } }); });
    var fpArr = Object.keys(fpm).map(function (k) { return { k: k, v: fpm[k] }; }).sort(function (x, y) { return y.v - x.v; });
    var fpCard = hasTruth
      ? (fpArr.length ? chartCard("오탐 유발 기법 Top-8", barChart(fpArr.slice(0, 8).map(function (x) { return { value: x.v, label: x.k, color: C.crown }; })), "god-view 실제 기법에 없는데 보고된 기법(오경보) — 보고 라운드 수")
        : noDataCard("오탐 유발 기법 Top-8", "오탐 유발 기법 없음"))
      : noDataCard("오탐 유발 기법 Top-8", TNOTE);

    return (S.demo ? demoBanner() : "") +
      '<div class="grid cols-6">' + kpiHtml + "</div>" +
      '<div class="section-label">목표 자산 침해 · 공격 전개</div>' +
      '<div class="grid cols-3 dense">' + newBreachCard + breachLatencyCard + cvssCard + killchainCard + chainDistCard + techDivCard + "</div>" +
      '<div class="section-label">탐지 정확도 · 검증</div>' +
      '<div class="grid cols-3 dense">' + dcard + prCard + vcard + elapsedCard + "</div>" +
      '<div class="section-label">기법 분포</div>' +
      '<div class="grid cols-3 dense">' + techFreqCard + missedCard + fpCard + "</div>";
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
    return '<div class="card det-card' + (opts.cardClass ? " " + opts.cardClass : "") + '" data-drillcard="' + opts.id + '"><div class="card-h">' + opts.title + "</div>" +
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
  function overBlockCount() {   // 과잉차단 — 패치했으나 서비스 중단(health 실패)된 라운드 수
    var n = 0; S.rounds.forEach(function (r) { if (r.patch_applied && r.healthcheck_passed === false) n++; }); return n;
  }
  function detectionCard(cardClass) {
    var counts = detectionTotals(), recall = (counts.tp + counts.fn) ? counts.tp / (counts.tp + counts.fn) : null;
    var ob = overBlockCount();
    var hint = '<div class="det-pop-hint">막대를 클릭하면 발생 라운드가 표시됩니다 · 상세보기 → 해당 라운드 탐지 근거</div>';
    S.drill = S.drill || {};
    S.drill.detection = { items: detectionItemsFromDeltas(), names: { tp: "정탐", fp: "오탐", fn: "미탐" }, section: "detect", hint: hint };
    var foot = "탐지율 " + pct(recall) + " · 미탐 " + counts.fn + "건 (방어 공백)";
    if (counts.tp === 0 && (counts.fp + counts.fn) > 0)   // 정탐 0 — 왜인지 명시(착시 교정)
      foot += '<div class="det-note">정탐 0 — 보고한 탐지가 god-view 실제 공격 기법과 하나도 맞지 않음(전부 오경보). 탐지(기법 식별)와 패치·차단(검증)은 별개 축이라, 경로를 막아도 기법을 못 맞히면 정탐은 0입니다.</div>';
    if (ob > 0)   // 과잉차단 — '패치 잘한다' 착시 교정
      foot += '<div class="det-note det-warn">과잉차단 ' + ob + '회 — 서비스 중단(health 실패)을 감수하고 얻은 차단. 채점에선 방어 성공으로 치지 않습니다.</div>';
    return drillCard({ id: "detection", title: "공격 탐지 정확도", hint: hint, cardClass: cardClass,
      cats: [["tp", "정탐", C.ok, "실제 공격 식별"], ["fp", "오탐", C.crown, "오경보"], ["fn", "미탐", C.atk, "공격 미식별"]],
      counts: counts, footer: foot });
  }
  // 검증 판정 — 라운드 단위라 범주별 발생 라운드가 바로 나온다(델타 불필요).
  function verdictItemsFromRounds() {
    var out = { blocked: [], fake: [], inconclusive: [] };
    S.rounds.forEach(function (r) {
      var k = r.verdict === "blocked" ? "blocked" : (r.verdict === "fake_patch" || r.verdict === "not_blocked" || r.verdict === "service_broken") ? "fake" : r.verdict === "inconclusive" ? "inconclusive" : null;
      if (k) out[k].push({ ep: r.episode || 1, round: r.round });
    });
    return out;
  }
  function verdictCard(cardClass) {
    var items = verdictItemsFromRounds();
    var counts = { blocked: items.blocked.length, fake: items.fake.length, inconclusive: items.inconclusive.length };
    var dec = counts.blocked + counts.fake;
    var hint = '<div class="det-pop-hint">막대를 클릭하면 해당 판정 라운드가 표시됩니다 · 상세보기 → 해당 라운드 검증 근거</div>';
    S.drill = S.drill || {};
    S.drill.verdict = { items: items, names: { blocked: "차단", fake: "무효 패치", inconclusive: "판정 불가" }, section: "verify", hint: hint };
    return drillCard({ id: "verdict", title: "검증 결과", hint: hint, cardClass: cardClass,
      cats: [["blocked", "차단", C.ok, "실질 차단"], ["fake", "무효 패치", C.atk, "패치 우회"], ["inconclusive", "판정 불가", C.sys, "미확정"]],
      counts: counts, footer: "차단율 " + pct(dec ? counts.blocked / dec : null) + " · 무효 패치 " + counts.fake + "건" });
  }

  // ───────── 페이지: 실행 제어 ─────────
  // 모드 = 파라미터 프리셋. 데모=짧은 1회차 시연, 통계=여러 회차 반복 수집.
  var MODES = { demo: { eps: 1, mr: 4, tl: 120, mt: 1024 }, stat: { eps: 10, mr: 10, tl: 180, mt: 1024 } };
  // 타깃 = 공격 목표(orchestrator --objective-mode/--target-assets). om/ta 가 null 이면 config 기본(ShopFlow).
  // fn/fp = 발판(네임스페이스/파드) — 타깃 선택 시 발판까지 자동전환. ShopFlow=frontend, corp=corp-ext.
  // dr = DB 크라운 역할 스코핑(ShopFlow=앱·유출 role 분리 / corp=빈값→스코핑 없음), dlc = corp-crown 로그(-corp) 사용.
  var TARGETS = {
    "default":  { label: "ShopFlow",              om: null,    ta: null,                  fn: "frontend", fp: "deploy/attacker-foothold",      dr: "appuser,legacy_admin", dlc: false, so: true  },
    "corp":     { label: "corp",                   om: "asset", ta: "crown-pii,crown-ops", fn: "corp-ext", fp: "deploy/corp-attacker-foothold", dr: "",                     dlc: true,  so: false }
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
        objective_mode: _tg.om || null, target_assets: _tg.ta || null,
        exec_namespace: _tg.fn || null, exec_pod: _tg.fp || null,
        attacker_db_roles: (_tg.dr != null ? _tg.dr : null), db_log_corp: !!_tg.dlc, shopflow_only: !!_tg.so, fresh: $("#f-fresh").checked };
      var r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then(function (x) { return x.json(); }).catch(function () { return { ok: false, error: "서버 연결 실패(데모 모드)" }; });
      msg.textContent = r.ok ? ("시작됨: " + r.id + (r.archived ? " · 이전 실행 보관됨" : "")) : "실패: " + (r.error || "");
      refreshRunStatus();
    };
    if (stop) stop.onclick = async function () {   // 한 번 누르면 종료 — 서버가 SIGTERM→(유예)→SIGKILL 로 escalate
      stop.disabled = true;
      msg.textContent = "중지 중… (최대 몇 초)";
      var r = await fetch("/api/run/stop", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({}) })
        .then(function (x) { return x.json(); }).catch(function () { return { ok: false, error: "서버 연결 실패" }; });
      if (r && r.stopped) msg.textContent = "중지됨 — 실행 종료";
      else if (r && r.ok) msg.textContent = "중지 신호 전송됨 — 종료 확인 중";
      else msg.textContent = "중지 실패: " + ((r && r.error) || "경로 없음");
      refreshRunStatus();
    };
    refreshRunStatus();
  }
  async function refreshRunStatus() {
    var st = await jget("/api/run/status");
    var log = $("#run-log"); if (log && st && st.log) log.textContent = st.log.join("\n") || "로그 없음";
    var start = $("#btn-start"), stop = $("#btn-stop");
    if (start && st) start.disabled = !!st.running;
    if (stop && st) stop.disabled = !st.running;
    var msg = $("#ctl-msg");
    if (msg && st && st.stopping) msg.textContent = "중지 처리 중…";
    else if (msg && st && st.external && !msg.textContent) msg.textContent = "외부(CLI) 실행 감지 — 여기서 중지 가능";
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
      (function () {
        var tc = targetCrowns();
        var _crOn = "background:var(--crown-soft);color:var(--crown);border-color:" + (_dark ? "rgba(251,191,36,.2)" : "#f3dca6");
        if (!tc) return (["1", "2", "3", "4"].map(function (s) { var on = (demo.flags_reached || []).indexOf(s) >= 0; return '<span class="chip" style="' + (on ? _crOn : "") + '">' + s + "단계" + (on ? " ✓" : "") + "</span>"; }).join("")) +
          ((demo.crowns_reached || []).map(function (c) { return '<span class="badge b-atk">' + esc(crownLabel(c)) + "</span>"; }).join(""));
        var cr = demo.crowns_reached || [];
        return tc.map(function (c) { var on = cr.indexOf(c) >= 0; return '<span class="chip" style="' + (on ? _crOn : "") + '">' + esc(crownLabel(c)) + (on ? " ✓" : "") + "</span>"; }).join("");
      })() +
      "</div></div>";
  }

  // ───────── 페이지: 타깃 구성도 (방어 시점) ─────────
  async function loadTopology() {
    var topo = null, live = false;
    if (!S.demo && S.rounds.length) {
      // 최신 라운드부터 역순 — 진행 중(공격 턴) 라운드엔 방어 턴 전이라 토폴로지가 아직 없다.
      // 토폴로지가 있는 가장 최근 라운드로 폴백해, 공격 턴 중에도 직전 구성도를 유지한다
      // (예전엔 현재 라운드만 읽어 공격 턴마다 예시로 떨어졌다).
      for (var i = S.rounds.length - 1; i >= 0 && i >= S.rounds.length - 10; i--) {
        var rr = S.rounds[i];
        var r = await jget("/api/topology/" + (rr.episode || 1) + "/" + rr.round);
        if (r && r.topology && r.topology.namespaces && r.topology.namespaces.length) { topo = r.topology; live = !!r.live; break; }
      }
    }
    // 라운드 기록이 없으면(게이팅·미실행) 서버가 god-view 로 '현재 클러스터'를 직접 스캔해 준다.
    if (!(topo && topo.namespaces && topo.namespaces.length) && !S.demo) {
      var lv = await jget("/api/topology_live");
      if (lv && lv.topology && lv.topology.namespaces && lv.topology.namespaces.length) { topo = lv.topology; live = true; }
    }
    if (topo && topo.namespaces && topo.namespaces.length) { topo._live = live; return topo; }
    return demoTopology();
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
      '<div class="section-label">영역 구성 (네임스페이스별)' +
        (topo._live ? ' <span class="arch-live">god-view 실시간</span>' : "") + "</div>" +
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

    var de = detail.detection_eval || null;
    var detItems = det.length ? det.map(function (x) {
      var conf = x.confidence != null ? Math.round(x.confidence * 100) + "%" : "—";
      var ev = detEvalByTech(de, x.technique);
      return '<div class="md-item"><div class="fi-head">' + (x.technique ? '<span class="badge b-def">' + esc(x.technique) + "</span>" : '<span class="chip">기법 미상</span>') + (ev ? detBadge(ev.verdict) : "") + '<span class="fi-conf">확신도 ' + conf + "</span></div>" +
        '<div class="md-ev mono">' + esc(x.evidence || "—") + "</div>" +
        (ev ? '<div class="det-why det-' + ev.verdict + '">' + esc(ev.reason) + "</div>" : "") + "</div>";
    }).join("") : "";
    var detMiss = (de && de.missed && de.missed.length) ?
      '<div class="md-st2">미탐 — 실제 발생·방어 미보고 (' + de.missed.length + "건)</div>" + detMissedHtml(de, "md-item") : "";
    var detNote = (de && de.truth_techniques) ?
      '<div class="md-ev" style="color:var(--text-3)">god-view 실제 공격 기법: ' + (de.truth_techniques.length ? esc(de.truth_techniques.join(", ")) : "없음") + " · 정탐 " + de.summary.tp + " · 오탐 " + de.summary.fp + " · 미탐 " + de.summary.fn + "</div>" : "";
    var detBody = (detNote + detItems + detMiss) || '<div class="tile-sub">보고·미탐 없음</div>';

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
      (_dSkipped(d) ? '<span class="badge b-sys">해당 없음</span>' : d.healthcheck_passed ? '<span class="badge b-ok">서비스 정상</span>' : '<span class="badge b-atk">서비스 중단</span>') +
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
    var vc = { blocked: 0, fake_patch: 0, not_blocked: 0, service_broken: 0, inconclusive: 0 }, patched = 0;
    rs.forEach(function (r) { if (vc[r.verdict] != null) vc[r.verdict]++; if (r.patch_applied) patched++; });
    var last = rs[rs.length - 1] || {}, det = last.detection_cum || { tp: 0, fp: 0, fn: 0 }, fake = vc.fake_patch + vc.not_blocked + vc.service_broken, nAsset = (last.crowns_reached_cum || []).length;
    var tiles = [
      ["라운드", rs.length + "회", "", C.teal, "accent-teal"],
      ["차단", vc.blocked + "회", "무효 패치 " + fake + "회", C.ok, "accent-ok"],
      ["미탐", det.fn + "건", "정탐 " + det.tp + " · 오탐 " + det.fp, det.fn ? C.atk : C.ok, det.fn ? "accent-atk" : "accent-ok"],
      ["패치 적용", patched + "/" + rs.length, "라운드", C.def, "accent-def"],
      ["핵심 자산 침해", nAsset + "종", nAsset ? "회차 끝 누적 반출" : "방어 유지", nAsset ? C.atk : C.ok, nAsset ? "accent-atk" : "accent-ok"]
    ].map(function (t) { return '<div class="tile ' + t[4] + '"><div class="tile-k"><span class="tag-dot" style="background:' + t[3] + '"></span>' + t[0] + '</div><div class="tile-v">' + t[1] + "</div>" + (t[2] ? '<div class="tile-sub">' + t[2] + "</div>" : "") + "</div>"; }).join("");
    var rows = rs.map(function (r) {
      var vv = VERDICT[r.verdict], ndet = (r.reported_techniques || []).length, rAsset = (r.crowns_reached_cum || []).length;
      return '<tr class="clickable" data-rkey="' + (r.episode || 1) + "-" + r.round + '"><td class="mono">R' + r.round + "</td>" +
        "<td>" + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : esc(r.verdict)) + "</td>" +
        '<td class="mono">' + ndet + "건</td>" +
        "<td>" + (r.patch_applied ? '<span class="badge b-ok">적용</span>' : '<span class="badge b-sys">미적용</span>') + "</td>" +
        '<td class="mono">' + (rAsset ? rAsset + "종" : "—") + "</td>" +
        "<td>" + (_dSkipped(r) ? '<span class="badge b-sys">—</span>' : r.healthcheck_passed ? '<span class="badge b-ok">정상</span>' : '<span class="badge b-atk">중단</span>') + "</td></tr>";
    }).join("");
    return (S.demo ? demoBanner() : "") + chips +
      '<div class="section-label">' + ep + "회차 종합 · 집계</div>" +
      '<div class="grid cols-5" style="margin-bottom:6px">' + tiles + "</div>" +
      '<div class="section-label">라운드별 탐지 · 패치 · 검증</div>' +
      '<div class="card" style="padding:0;overflow:hidden"><table class="tbl def-ep-tbl"><thead><tr><th>라운드</th><th>판정</th><th>탐지</th><th>패치</th><th>침해 자산</th><th>서비스</th></tr></thead><tbody>' + rows + "</tbody></table></div>" +
      '<div class="tile-sub" style="margin-top:10px">라운드 행을 클릭하면 해당 라운드 상세 흐름으로 이동합니다.</div>';
  }
  function pageDefGraph(detail, rec, rounds, idx) {
    var d = detail.defense || {}, v = detail.verification || {};
    var det = d.detected || [], ps = d.patch_set || [];
    var vv = v.verdict ? VERDICT[v.verdict] : null;

    var chips = roundChipsHtml(rounds, (rec.episode || 1) + "-" + rec.round, "data-rkey");

    var de = detail.detection_eval || null;
    var detItems = det.length ? det.map(function (x) {
      var conf = x.confidence != null ? Math.round(x.confidence * 100) : null;
      var ev = detEvalByTech(de, x.technique);
      return '<div class="flow-item"><div class="fi-head">' + (x.technique ? '<span class="badge b-def">' + esc(x.technique) + "</span>" : '<span class="chip">기법 미상</span>') + (ev ? detBadge(ev.verdict) : "") + (conf != null ? '<span class="fi-conf">확신도 ' + conf + "%</span>" : "") + "</div>" +
        '<div class="fi-ev mono">' + esc(x.evidence || "—") + "</div>" + (conf != null ? '<div class="conf-bar"><span style="width:' + conf + '%"></span></div>' : "") +
        (ev ? '<div class="det-why det-' + ev.verdict + '">' + esc(ev.reason) + "</div>" : "") + "</div>";
    }).join("") : "";
    var detHtml = (detItems + detMissedHtml(de, "flow-item")) || '<div class="flow-empty">보고·미탐 없음</div>';

    var psHtml = ps.length ? ps.map(function (p) {
      return '<div class="flow-item"><div class="fi-head"><span class="badge b-def">' + esc(patchKindLabel(p.kind)) + '</span><span class="fi-tgt mono">' + esc(p.target || "") + "</span></div>" +
        '<div class="fi-ev">' + esc(p.summary || "—") + "</div></div>";
    }).join("") : '<div class="flow-empty">적용한 패치 없음</div>';
    var psFoot = detail.defense ? '<div class="flow-foot">' + (d.patch_applied ? '<span class="badge b-ok">패치 적용</span>' : '<span class="badge b-sys">패치 미적용</span>') +
      (_dSkipped(d) ? '<span class="badge b-sys">해당 없음</span>' : d.healthcheck_passed ? '<span class="badge b-ok">서비스 정상</span>' : '<span class="badge b-atk">서비스 중단</span>') + "</div>" : "";

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
      body = "방어 차례 · 패치 " + (p.patch_applied ? "적용" : "미적용") + " · 탐지 " + num(p.detected) + "건" + (_dSkipped(p) ? " · 검증 생략" : " · 서비스 " + (p.healthcheck_passed ? "정상" : "중단"));
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
    S.jlExport = evs;                               // 내보내기 대상(지금 보이는 실행의 레코드)
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
      exportBar("data-jexport") +
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
    Array.prototype.forEach.call(document.querySelectorAll("[data-jexport]"), function (b) {
      b.onclick = function () { exportAttackJournal(b.getAttribute("data-jexport")); };
    });
  }

  // ───────── 페이지: 방어 저널(방어자 행동 로그 — 탐지→패치→검증) ─────────
  // events.jsonl 의 방어자/판정 이벤트(detection·patch·defense_turn·verdict)를 라운드별로 모아 보여준다.
  // 공격 저널과 같은 틀(실행 선택·라운드 아코디언)·방어 색(파랑). 백엔드 추가 없음(이미 기록됨).
  function defLogRows(evs) {
    var det = [], pat = [], ver = [], turn = null;
    evs.forEach(function (e) {
      if (e.type === "detection") det.push(e);
      else if (e.type === "patch") pat.push(e);
      else if (e.type === "verdict") ver.push(e);
      else if (e.type === "defense_turn") turn = e;
    });
    var out = "";
    if (det.length) out += '<div class="dj-ph"><span class="dj-pt">① 탐지</span><span class="dj-n">' + det.length + "건</span></div>" +
      det.map(function (e) { var p = e.payload || {}, conf = p.confidence != null ? Math.round(p.confidence * 100) + "%" : "—";
        return '<div class="dj-row"><span class="jr-ts">' + hhmmss(e.ts) + "</span>" +
          (p.technique ? '<span class="badge b-def">' + esc(p.technique) + "</span>" : '<span class="chip">기법 미상</span>') +
          '<span class="dj-ev mono">' + esc(p.evidence || "—") + '</span><span class="jr-meta">확신도 ' + conf + "</span></div>"; }).join("");
    if (pat.length) out += '<div class="dj-ph"><span class="dj-pt">② 패치</span><span class="dj-n">' + pat.length + "건</span></div>" +
      pat.map(function (e) { var p = e.payload || {};
        var label = p.detail ? p.detail : (patchKindLabel(p.kind) + " → " + (p.target || "") + (p.summary ? " · " + p.summary : ""));
        return '<div class="dj-row"><span class="jr-ts">' + hhmmss(e.ts) + "</span>" +
          (p.applied ? '<span class="jr-ok">적용</span>' : '<span class="jr-fail">스킵</span>') +
          '<span class="dj-ev mono">' + esc(label) + "</span></div>"; }).join("");
    if (ver.length) out += '<div class="dj-ph"><span class="dj-pt">③ 검증</span></div>' +
      ver.map(function (e) { var p = e.payload || {}, vv = p.verdict ? VERDICT[p.verdict] : null;
        return '<div class="dj-row"><span class="jr-ts">' + hhmmss(e.ts) + "</span>" +
          (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : '<span class="chip">—</span>') +
          '<span class="dj-ev">' + esc(p.detail || "") + '</span><span class="jr-meta mono">' + esc(p.method || "") + "</span></div>"; }).join("");
    if (turn) { var tp = turn.payload || {};
      out += '<div class="dj-foot">' +
        (tp.patch_applied ? '<span class="badge b-ok">패치 적용</span>' : '<span class="badge b-sys">패치 미적용</span>') +
        (_dSkipped(tp) ? '<span class="badge b-sys">해당 없음</span>' : tp.healthcheck_passed ? '<span class="badge b-ok">서비스 정상</span>' : '<span class="badge b-atk">서비스 중단</span>') +
        (tp.elapsed_sec ? '<span class="chip">' + Math.round(tp.elapsed_sec) + "s</span>" : "") +
        (tp.note ? '<span class="dj-note">' + esc(tp.note) + "</span>" : "") +
        (tp.error ? '<span class="dj-note" style="color:var(--atk)">오류: ' + esc(tp.error) + "</span>" : "") + "</div>";
    }
    return out || '<div class="tile-sub">이 라운드 방어 행동 기록 없음</div>';
  }
  function defLogAccordion(evs) {
    var rounds = {}, rorder = [];
    evs.forEach(function (e) { var r = e.round || 0; if (!rounds[r]) { rounds[r] = []; rorder.push(r); } rounds[r].push(e); });
    if (!rorder.length) return '<div class="tile-sub">방어 행동 기록 없음</div>';
    rorder.sort(function (a, b) { return b - a; });          // 최신 라운드 먼저
    if (dlOpen == null) dlOpen = {};
    var topKey = "r" + rorder[0];
    if (dlOpen[topKey] === undefined) dlOpen[topKey] = true; // 최신 라운드 기본 펼침
    return rorder.map(function (r) {
      var evr = rounds[r], rkey = "r" + r, open = !!dlOpen[rkey];
      var nd = evr.filter(function (e) { return e.type === "detection"; }).length;
      var np = evr.filter(function (e) { return e.type === "patch" && (e.payload || {}).applied; }).length;
      var turn = evr.filter(function (e) { return e.type === "defense_turn"; })[0];
      var _tp = turn ? (turn.payload || {}) : {}, health = _tp.healthcheck_passed;
      var head = '<button class="jacc-h jacc-r dj-rh' + (open ? " open" : "") + '" data-dltoggle="' + rkey + '">' +
        '<span class="jacc-caret' + (open ? " open" : "") + '">▸</span><span class="jacc-t">R' + r + "</span>" +
        '<span class="jacc-meta">탐지 ' + nd + " · 적용 패치 " + np +
        (!_dSkipped(_tp) && health === false ? ' <span class="badge b-atk">서비스 중단</span>' : "") + "</span></button>";
      return '<div class="jacc dj-acc">' + head + (open ? '<div class="jacc-body">' + defLogRows(evr) + "</div>" : "") + "</div>";
    }).join("");
  }
  function pageDefenseLog() {
    var all = (S.events || []).filter(function (e) { return e.actor === "defender" || e.type === "verdict"; });
    if (!all.length)
      return (S.demo ? demoBanner() : "") + emptyState("🛡", "아직 방어 저널이 없습니다", "방어 턴이 끝나면 탐지·패치·검증 행동이 라운드별로 쌓입니다.", []);
    var segs = runSegments(all), seg = pickSeg(segs, dlRun);
    var evs = seg ? seg.records : all;
    S.dlExport = evs;                               // 내보내기 대상(지금 보이는 실행의 방어 레코드)
    var nDet = 0, nPat = 0, nBlock = 0;
    evs.forEach(function (e) {
      if (e.type === "detection") nDet++;
      else if (e.type === "patch" && (e.payload || {}).applied) nPat++;
      else if (e.type === "verdict" && (e.payload || {}).verdict === "blocked") nBlock++;
    });
    return (S.demo ? demoBanner() : "") +
      runPickerHtml(segs, dlRun, "data-dlrun") + runCfgHtml(seg) +
      '<div class="jhead"><span class="jhead-m"><span class="jhead-k">탐지</span><span class="jhead-v">' + nDet + "건</span></span>" +
      '<span class="jhead-m"><span class="jhead-k">적용 패치</span><span class="jhead-v">' + nPat + "건</span></span>" +
      '<span class="jhead-m"><span class="jhead-k">차단</span><span class="jhead-v def">' + nBlock + "건</span></span>" +
      exportBar("data-dexport") +
      '<span class="jhead-note">방어 턴 종료 시 반영 · 탐지→패치→검증</span></div>' +
      defLogAccordion(evs);
  }
  function bindDefenseLog() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-dlrun]"), function (b) {
      b.onclick = function () { dlRun = b.getAttribute("data-dlrun"); dlOpen = null; $("#view").innerHTML = pageDefenseLog(); bindDefenseLog(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-dltoggle]"), function (b) {
      b.onclick = function () { var k = b.getAttribute("data-dltoggle"); dlOpen[k] = !dlOpen[k]; $("#view").innerHTML = pageDefenseLog(); bindDefenseLog(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-dexport]"), function (b) {
      b.onclick = function () { exportDefenseJournal(b.getAttribute("data-dexport")); };
    });
  }

  // ───────── 저널 내보내기(파일 다운로드 — 공격·방어 공용) ─────────
  // 지금 화면에 보이는(선택 실행) 저널 레코드를 CSV·JSON·Markdown 파일로 내려받는다.
  // 자체 호스팅 대시보드라 브라우저 Blob 다운로드가 그대로 동작(아티팩트 CSP 아님).
  function exportBar(attr) {
    return '<span class="jhead-x"><span class="jx-lbl">내보내기</span>' +
      '<button class="jx-btn" ' + attr + '="csv">CSV</button>' +
      '<button class="jx-btn" ' + attr + '="json">JSON</button>' +
      '<button class="jx-btn" ' + attr + '="md">MD</button></span>';
  }
  function _dl(name, content, mime) {
    try {
      var blob = new Blob([content], { type: (mime || "text/plain") + ";charset=utf-8" });
      var url = URL.createObjectURL(blob), a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click();
      setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 120);
      return true;
    } catch (e) { return false; }
  }
  function _csvCell(v) { v = (v == null ? "" : String(v)); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function _csv(headers, rows) {
    return "﻿" + headers.map(_csvCell).join(",") + "\n" +   // BOM: 엑셀 한글 깨짐 방지
      rows.map(function (r) { return r.map(_csvCell).join(","); }).join("\n") + "\n";
  }
  function _stamp() { var d = new Date(); function z(n) { return (n < 10 ? "0" : "") + n; } return "" + z(d.getMonth() + 1) + z(d.getDate()) + "-" + z(d.getHours()) + z(d.getMinutes()); }

  function exportAttackJournal(fmt) {
    var all = S.jlExport || [], steps = all.filter(function (e) { return e.type === "attack_step"; });
    var base = "attack-journal-" + _stamp();
    if (fmt === "json") return _dl(base + ".json", JSON.stringify(all, null, 2), "application/json");
    if (fmt === "csv") {
      var rows = steps.map(function (e) { var p = e.payload || {};
        var cmd = (String(p.tool || "") + " " + (p.args || []).join(" ")).trim();
        var res = p.flag ? "목표획득" : p.success ? "성공" : "실패";
        return ["R" + (e.round || ""), hhmmss(e.ts), intentLabelOf(p), cmd, res, p.determinism || ""]; });
      return _dl(base + ".csv", _csv(["라운드", "시각", "의도", "명령", "결과", "결정성"], rows), "text/csv");
    }
    var md = "# 공격 저널\n\n", byR = {}, ord = [];
    steps.forEach(function (e) { var r = e.round || 0; if (!byR[r]) { byR[r] = []; ord.push(r); } byR[r].push(e); });
    ord.sort(function (a, b) { return a - b; }).forEach(function (r) {
      md += "## R" + r + "\n\n";
      byR[r].forEach(function (e) { var p = e.payload || {}, cmd = (String(p.tool || "") + " " + (p.args || []).join(" ")).trim();
        md += "- `" + hhmmss(e.ts) + "` [" + intentLabelOf(p) + "] `" + cmd + "` → " + (p.flag ? "목표획득" : p.success ? "성공" : "실패") + "\n"; });
      md += "\n";
    });
    return _dl(base + ".md", md, "text/markdown");
  }

  var _DJ_PHASE = { detection: "탐지", patch: "패치", verdict: "검증", defense_turn: "턴요약" };
  function _djContent(e) { var p = e.payload || {};
    if (e.type === "detection") return (p.technique || "기법미상") + " · " + (p.evidence || "");
    if (e.type === "patch") return p.detail || (patchKindLabel(p.kind) + " → " + (p.target || "") + (p.summary ? " " + p.summary : ""));
    if (e.type === "verdict") return (p.verdict || "") + (p.detail ? " · " + p.detail : "");
    if (e.type === "defense_turn") return "패치 " + (p.patch_applied ? "적용" : "미적용") + (_dSkipped(p) ? " · 검증 생략" : " · 서비스 " + (p.healthcheck_passed ? "정상" : "중단"));
    return ""; }
  function _djResult(e) { var p = e.payload || {};
    if (e.type === "detection") return p.confidence != null ? Math.round(p.confidence * 100) + "%" : "";
    if (e.type === "patch") return p.applied ? "적용" : "스킵";
    if (e.type === "verdict") return p.verdict || "";
    if (e.type === "defense_turn") return _dSkipped(p) ? "생략" : (p.healthcheck_passed ? "정상" : "중단");
    return ""; }
  function exportDefenseJournal(fmt) {
    var evs = S.dlExport || [], base = "defense-journal-" + _stamp();
    if (fmt === "json") return _dl(base + ".json", JSON.stringify(evs, null, 2), "application/json");
    if (fmt === "csv") {
      var rows = evs.map(function (e) { return ["R" + (e.round || ""), hhmmss(e.ts), _DJ_PHASE[e.type] || e.type, e.type, _djContent(e), _djResult(e)]; });
      return _dl(base + ".csv", _csv(["라운드", "시각", "단계", "유형", "내용", "결과"], rows), "text/csv");
    }
    var md = "# 방어 저널\n\n", byR = {}, ord = [];
    evs.forEach(function (e) { var r = e.round || 0; if (!byR[r]) { byR[r] = []; ord.push(r); } byR[r].push(e); });
    ord.sort(function (a, b) { return a - b; }).forEach(function (r) {
      md += "## R" + r + "\n\n";
      byR[r].forEach(function (e) { md += "- `" + hhmmss(e.ts) + "` [" + (_DJ_PHASE[e.type] || e.type) + "] " + _djContent(e) + " → " + _djResult(e) + "\n"; });
      md += "\n";
    });
    return _dl(base + ".md", md, "text/markdown");
  }

  // ───────── 페이지: 공격 추적 그래프 ─────────
  function kindLabel(k) { return ({ goal: "Goal", intent: "Intent", fact: "Fact", finding: "Finding", hint: "Hint" })[k] || k; }
  function kindLabelKo(k) { return ({ goal: "목표", intent: "의도", fact: "사실", finding: "발견", hint: "힌트" })[k] || k; }
  function kindLabelFull(k) { return ({ goal: "목표 · Goal", intent: "의도 · Intent", fact: "사실 · Fact", finding: "발견 · Finding", hint: "힌트 · Hint" })[k] || kindLabel(k); }
  var _KC_LIGHT = { goal: { bg: "#fdf1dc", line: "#b8740a" }, intent: { bg: "#fdecec", line: "#d13b40" },
    fact: { bg: "#e8f0fe", line: "#2f6fe0" },
    finding: { bg: "#b11722", line: "#8a0f18", solid: true, fg: "#ffffff", fg2: "#ffd7db" },
    hint: { bg: "#eef1f5", line: "#5b6676" }, _def: { bg: "#eef1f5", line: "#5b6676" } };
  var _KC_DARK = { goal: { bg: "#2a2010", line: "#d4950e" }, intent: { bg: "#2a1418", line: "#f87171" },
    fact: { bg: "#111c30", line: "#60a5fa" },
    finding: { bg: "#7f1d1d", line: "#ef4444", solid: true, fg: "#fef2f2", fg2: "#fca5a5" },
    hint: { bg: "#1c2536", line: "#94a3b8" }, _def: { bg: "#1c2536", line: "#94a3b8" } };
  function kindColor(k) {
    var map = _dark ? _KC_DARK : _KC_LIGHT;
    return map[k] || map._def;
  }
  var _RC_LIGHT = { spawns: "#e5484d", yields: "#3b82f6", proves: "#b4303a", derived_from: "#94a3b8", enables: "#f59e0b" };
  var _RC_DARK = { spawns: "#f87171", yields: "#60a5fa", proves: "#ef4444", derived_from: "#64748b", enables: "#fbbf24" };
  function relColor(r) { var m = _dark ? _RC_DARK : _RC_LIGHT; return m[r] || (_dark ? "#64748b" : "#94a3b8"); }
  // 관계 — 사람이 읽는 우리말(엣지 의미가 더 직관적)
  function relLabel(r) { return ({ spawns: "파생", yields: "산출", proves: "입증", derived_from: "유도", enables: "활용" })[r] || r; }
  function relDesc(r) { return ({ spawns: "목표·사실이 새 의도를 낳음", yields: "의도가 사실을 산출", proves: "사실이 발견을 입증", derived_from: "사실이 다른 사실에서 유도됨", enables: "발견(자격증명·접근)을 활용하는 후속 의도를 낳음" })[r] || ""; }
  // 노드 상태 — 화면 표기는 쉬운 우리말(상태는 식별자 아닌 진행 상황이라 한글이 명확)
  function stateKo(s) { return ({ open: "대기", running: "실행 중", done: "완료", blocked: "차단", exhausted: "막다름", stopped: "중단", confirmed: "확인됨", claimed: "포착" })[s] || s; }
  function stateColor(s) {
    var m = _dark
      ? { running: "#2dd4bf", done: "#34d399", blocked: "#f87171", exhausted: "#fbbf24", stopped: "#94a3b8", confirmed: "#60a5fa", claimed: "#ef4444" }
      : { running: "#0d9488", done: "#0ea371", blocked: "#e5484d", exhausted: "#e5920b", stopped: "#64748b", confirmed: "#2f6fe0", claimed: "#b4303a" };
    return m[s] || (_dark ? "#64748b" : "#8a97ab");
  }
  // WEB_* 자체 기법 → ATT&CK 부모 기법으로 매핑(링크용)
  var _WEB_MITRE = { WEB_SQLI:"T1190", WEB_SSRF:"T1190", WEB_BOLA:"T1190", WEB_CMDI:"T1059", WEB_CREDLEAK:"T1552" };
  function mitreUrl(t) { var m = _WEB_MITRE[t] || t; return "https://attack.mitre.org/techniques/" + String(m).replace(".", "/") + "/"; }
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
      var ep = parseInt(sel.slice(1), 10), li = -1, liDone = -1;
      rounds.forEach(function (r, i) {
        if ((r.episode || 1) !== ep) return;
        li = i;                     // 그 회차 마지막 라운드(진행 중 포함)
        if (!r._live) liDone = i;   // 그 회차 마지막 '완료' 라운드
      });
      // 종합은 god-view 발견 노드가 주입된 '완료 라운드' 스냅샷을 읽어야 한다.
      // 진행 중 라운드 파일은 아직 라이브 스트리머 사본(주입 전)이라 god-view 발견이 없다
      // — 돌파 라운드엔 보이는데 종합(=마지막=진행 중)엔 안 보이던 원인.
      var pick = liDone >= 0 ? liDone : li;
      return { rec: pick >= 0 ? rounds[pick] : null, aggEp: pick >= 0 ? ep : null };
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
    // 변화 서명 — 같으면 재렌더 생략(폴링 중 깜빡임·재애니메이션·스크롤 점프 방지).
    // agMode 포함 + 두 뷰 공유 컨테이너(.ag-layout)로 확인 — 리스트 뷰엔 .ag-svg 가 없어
    // 매 폴링마다 재렌더되며 스크롤이 맨 위로 튀던 문제 교정.
    var sig = nodes.map(function (n) { return n.id + ":" + (n.state || ""); }).join(",") + "|" +
      (g.edges || []).map(function (e) { return e.src + ">" + e.dst; }).join(",") + "|" + agSel + "|" + agTab + "|" + selKey + "|" + agMode + "|" + agFull;
    if (sig === S.agSig && document.querySelector(".ag-layout")) return;
    var seen = S.agSeen || {};
    nodes.forEach(function (n) { n._new = !seen[n.id]; });   // 새로 생긴 노드만 등장 애니메이션
    var _scroll = view.scrollTop;                            // 재렌더로 리셋되는 스크롤 보존(라이브 노드 추가 시)
    view.innerHTML = pageAttackGraph(g, rounds, rec, aggEp, selKey);
    nodes.forEach(function (n) { seen[n.id] = 1; });
    S.agSeen = seen; S.agSig = sig;
    bindAttackGraph();
    view.scrollTop = _scroll;                                // 복원
  }
  // 그래프 전체화면 — #view(폴링 재렌더에도 DOM 에 남는 안정 컨테이너)에 ag-full 클래스를 걸어
  // .ag-wrap 를 화면 전체로 띄우고 그래프(노드)만 보이게 한다. 가능하면 네이티브 전체화면도 함께
  // 요청(발표·판넬용 투사에 좋음) — 거부돼도 고정 오버레이로 화면 전체를 덮으므로 동작 보장.
  function _agFullApply() {   // agFull 상태를 DOM 클래스에 반영(재렌더는 호출부에서)
    var host = document.getElementById("view");
    if (host) host.classList.toggle("ag-full", agFull);
    document.body.classList.toggle("ag-full-lock", agFull);
  }
  function setAgFull(on) {
    agFull = !!on; _agFullApply();
    try {
      var host = document.getElementById("view");
      if (agFull && host && host.requestFullscreen && !document.fullscreenElement) host.requestFullscreen().catch(function () {});
      else if (!agFull && document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(function () {});
    } catch (e) {}
    if (route === "attack-graph") { S.agSig = null; pageAttackGraphRender(); }
  }
  function bindAttackGraph() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-agfull]"), function (b) {   // 그래프 전체화면 토글
      b.onclick = function () { setAgFull(!agFull); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agtab]"), function (b) {
      b.onclick = function () { agTab = b.getAttribute("data-agtab"); pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agrk]"), function (b) {
      b.onclick = function () { agRkey = b.getAttribute("data-agrk"); agSel = null; agView = null; S.agSeen = {}; S.agSig = null; pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agkind]"), function (b) {   // 카테고리 표시 토글
      b.onclick = function () { var k = b.getAttribute("data-agkind"); agHide[k] = !agHide[k]; S.agSig = null; pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agraw]"), function (b) {    // 원문 보기 토글
      b.onclick = function () { agRaw = !agRaw; S.agSig = null; pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-agmode]"), function (b) {   // 그래프↔리스트 전환
      b.onclick = function () { agMode = b.getAttribute("data-agmode"); S.agSig = null; pageAttackGraphRender(); };
    });
    Array.prototype.forEach.call(document.querySelectorAll(".anl-item"), function (b) {       // 리스트 항목 선택 → 우측 상세
      b.onclick = function () { var id = parseInt(b.getAttribute("data-nid"), 10); agSel = (agSel === id) ? null : id; S.agSig = null; pageAttackGraphRender(); };
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
      el.addEventListener("click", function () {
        if (svg._dragged) return;
        var id = parseInt(el.getAttribute("data-nid"), 10);
        agSel = (agSel === id) ? null : id;      // 같은 노드 다시 클릭 → 선택·계보 포커스 해제
        S.agSig = null; pageAttackGraphRender();
      });
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
  // 발견 노드 심각도 판단 근거 — 등급·확보 데이터로 왜 그 심각도인지 우리말로 해설.
  function _sevBasis(n) {
    var sev = String(n.severity || "").toLowerCase(), loot = (n.loot != null && String(n.loot) !== "");
    if (sev === "critical") return "핵심 자산을 실제로 반출·장악해 되돌릴 수 없는 침해" + (loot ? "(확보 데이터로 입증)" : "");
    if (sev === "high") return "재사용 가능한 자격증명·비밀 또는 핵심 경로 확보로 즉시 확대 가능" + (loot ? "(확보 데이터로 입증)" : "");
    if (sev === "medium") return "악용에 추가 조건이 필요하나 유효한 침해 경로를 확인";
    if (sev === "low") return "영향이 제한적이거나 정보 노출 수준";
    return loot ? "실제 데이터 확보로 침해가 입증됨" : "";
  }
  function agCuration(n) {
    // 노드 상세 핵심 한 줄 — god-view 설명(desc) 우선, 없으면 요약. 종류별 상투 문구와
    // 판단근거·관측·상태 반복은 뺀다(그 값들은 아래 '개요'에 구조화돼 한 번만 나온다).
    return String(n.desc || n.summary || n.detail || "").trim();
  }
  function agPanel(nodes) {
    var n = nodes.filter(function (x) { return x.id === agSel; })[0];
    if (!n) return '<div class="ag-side-empty">노드를 클릭하면 상세가 여기 표시됩니다.</div>';
    var col = kindColor(n.kind);
    var tabs = '<div class="tabs"><button class="tab' + (agTab === "overview" ? " active" : "") + '" data-agtab="overview">개요</button>' +
      '<button class="tab' + (agTab === "knowledge" ? " active" : "") + '" data-agtab="knowledge">지식</button></div>';
    var _fc = (n.kind === "finding") ? findingCvss(n) : null;
    var curation = agCuration(n);
    // 원문(원본 산출) — 큐레이션 한 줄과 겹치지 않는 부분만. god-view 주입 노드는 desc 가 완결이라 생략.
    var rawParts = n.godview ? "" : (
      (n.summary && n.summary !== curation ? '<div class="ag-raw-k">summary</div><div class="ag-sum">' + esc(n.summary) + "</div>" : "") +
      (n.detail && n.detail !== n.summary && n.detail !== curation ? '<div class="ag-raw-k">detail</div><div class="ag-sum">' + esc(n.detail) + "</div>" : ""));
    // 폐쇄(closure) 뱃지 — 승격되면 '데드엔드 확정'(빨강), 후보만 있으면 '데드엔드 후보'(앰버).
    // 대상 자산이 '목표 없음'으로 입증돼 플래너가 더 이상 거기 의도를 내지 않게 하는 신호.
    var clsBadge = "";
    if (n.kind === "fact" && n.promoted) {
      clsBadge = '<span class="badge" style="background:' + (_dark ? "#991b1b" : "#dc2626") + ";color:" + (_dark ? "#fecaca" : "#fff") + '" title="이 사실이 플래너 심사를 통과해 대상 자산을 R'
        + n.promoted + '에 폐쇄로 승격. 이후 라운드부터 그 자산엔 새 의도 금지.">데드엔드 R' + n.promoted + '</span>';
    } else if (n.kind === "fact" && n.closure_candidate) {
      clsBadge = '<span class="badge" style="background:' + (_dark ? "#92400e" : "#f59e0b") + ";color:" + (_dark ? "#fef3c7" : "#0b0f1a") + '" title="워커가 대상 자산을 데드엔드 후보로 표시. 다음 라운드 전에 플래너가 심사해 승격·거부를 결정.">데드엔드 후보</span>';
    }
    var head = '<div class="ag-ph"><span class="badge" style="background:' + col.bg + ";color:" + col.line + '">' + kindLabelFull(n.kind) + "</span>" +
      (n.godview ? '<span class="badge b-ok" title="심판 god-view 접근기록으로 확정된 침해">god-view 확정</span>' : "") +
      (n.technique ? '<span class="badge b-atk">' + esc(n.technique) + "</span>" : "") +
      clsBadge +
      (n.state && n.state !== "exhausted" ? '<span class="chip ag-state" style="color:' + stateColor(n.state) + ';border-color:' + stateColor(n.state) + '33">' + esc(stateKo(n.state)) + "</span>" : "") + "</div>" +
      (_fc ? agCvssBlock(_fc, n) : "") +
      (curation ? '<div class="ag-desc ag-desc-main">' + esc(curation) + "</div>" : "") +
      (rawParts ? '<button class="ag-raw-t" data-agraw>' + (agRaw ? "원문 접기 ▴" : "원문 보기 ▾") + "</button>" +
        (agRaw ? '<div class="ag-raw">' + rawParts + "</div>" : "") : "") +
      (n.loot != null && n.loot !== "" ? '<div class="ag-loot"><div class="ag-loot-h">확보한 데이터</div><pre class="ag-loot-v">' + esc(typeof n.loot === "object" ? JSON.stringify(n.loot, null, 2) : String(n.loot)) + "</pre></div>" : "");
    var body;
    if (agTab === "overview") {
      body = (n.target ? agLine("대상", n.target) : "") +
        (n.why ? agLine("판단 근거", n.why) : "") +
        (n.confidence != null && isFinite(n.confidence) ? agLine("확신도", Math.round(n.confidence * 100) + "%") : "") +
        (n.occurrences ? agLine("재현 횟수", n.occurrences + "회") : "") +
        (n.evidence ? '<div class="ag-ev-sm">관측: ' + esc(n.evidence) + "</div>" : "");
      if (!body) body = '<div class="tile-sub">핵심 요약 외 추가 정보 없음</div>';
    } else {
      body = (n.technique ? agLine("MITRE 기법", n.technique) +
          '<div class="rep-line"><span class="rep-k">참고 문서</span><span><a href="' + mitreUrl(n.technique) + '" target="_blank" rel="noopener">MITRE ATT&CK에서 보기 ↗</a></span></div>'
        : '<div class="tile-sub">연결된 MITRE 기법 없음</div>');
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
    // 카테고리 필터 — 숨긴 종류의 노드와 그 노드에 닿는 엣지를 뺀다(노드 많을 때 종류별 조회).
    var _hid = {}; nodes.forEach(function (n) { if (agHide[n.kind]) _hid[n.id] = 1; });
    nodes = nodes.filter(function (n) { return !_hid[n.id]; });
    edges = edges.filter(function (e) { return !_hid[e.src] && !_hid[e.dst]; });
    if (!nodes.length) {
      var chipsH = (rounds && rounds.length) ? roundChipsHtml(rounds, selKey || "", "data-agrk") : "";
      return chipsH + agKindFilter(g.nodes || []) + '<div class="tile-sub" style="padding:20px">선택한 종류가 모두 숨겨졌습니다 · 위 필터에서 다시 켜세요</div>';
    }
    // 라운드별 보기 — 종합(aggEp)이 아니라 '단일 라운드'를 고르면 그 라운드 노드만 보이고,
    // 그 노드들의 직속 부모(한 단계 위, 대개 직전 라운드)만 맥락으로 함께 둔다(점선·흐림 표기).
    var ctxIds = {}, _perRound = false;
    var _curR = (rec && rec.round != null) ? rec.round : null;
    if (!aggEp && _curR != null && nodes.some(function (n) { return n.round === _curR; })) {
      var inR = {}; nodes.forEach(function (n) { if (n.round === _curR) inR[n.id] = 1; });
      var par = {}; edges.forEach(function (e) { if (inR[e.dst] && !inR[e.src]) par[e.src] = 1; });  // 직속 부모만(1단계)
      nodes = nodes.filter(function (n) { return inR[n.id] || par[n.id]; });
      nodes.forEach(function (n) { if (par[n.id] && !inR[n.id]) ctxIds[n.id] = 1; });
      var _keepR = {}; nodes.forEach(function (n) { _keepR[n.id] = 1; });
      edges = edges.filter(function (e) { return _keepR[e.src] && _keepR[e.dst]; });
      _perRound = true;
    }
    // 리스트 보기 — 종류(목표·의도·사실·발견)별로 노드를 일괄 나열. 그래프 레이아웃 계산 없이 바로.
    if (agMode === "list") {
      var chipsL = (rounds && rounds.length) ? roundChipsHtml(rounds, selKey || "", "data-agrk") : "";
      var ctxL = aggEp ? aggEp + "회차 종합 · 누적" : (rec ? (rec.episode || 1) + "회차 R" + rec.round + (_perRound ? " · 이 라운드 노드만" : "") : "예시");
      return (S.demo ? demoBanner() : "") + chipsL +
        '<div class="section-label">' + ctxL + " · 공격 추론 그래프</div>" +
        agViewToggle() + agKindFilter(g.nodes || []) +
        '<div class="ag-layout"><div class="ag-main">' + agNodeList(nodes) + "</div>" +
        '<div class="ag-side">' + agPanel(g.nodes || []) + "</div></div>";
    }
    // 수직 트리 레이아웃 — 목표(위)에서 깊이가 아래로 떨어진다. BFS 최단경로로 깊이(행)를 잡고,
    // 자식은 부모 아래에 모아 배치(종류별 가로 열이 아니라 계층 트리). 하위 의도는 사실보다 더 아래.
    var NW = 184, NH = 56, PADX = 28, TOP = 20;
    var byId = {}, childrenMap = {}, parentsMap = {};
    nodes.forEach(function (n) { byId[n.id] = n; childrenMap[n.id] = []; parentsMap[n.id] = []; });
    edges.forEach(function (e) { if (byId[e.src] && byId[e.dst]) { childrenMap[e.src].push(e.dst); parentsMap[e.dst].push(e.src); } });
    // 선택 노드 계보(조상+자손) — 포커스 집합. 노드 많을 때 선택하면 계보만 선명, 나머지 흐림.
    var focus = null;
    if (agSel != null && byId[agSel]) {
      focus = {}; focus[agSel] = 1;
      var up = [agSel]; while (up.length) { var _u = up.pop(); (parentsMap[_u] || []).forEach(function (p) { if (!focus[p]) { focus[p] = 1; up.push(p); } }); }
      var dn = [agSel]; while (dn.length) { var _d = dn.pop(); (childrenMap[_d] || []).forEach(function (c) { if (!focus[c]) { focus[c] = 1; dn.push(c); } }); }
    }
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
    var edgeSvg = edges.map(function (e) {
      var a = pos[e.src], b = pos[e.dst]; if (!a || !b) return "";
      var hot = (agSel === e.src || agSel === e.dst);
      var dim = focus && !(focus[e.src] && focus[e.dst]), d;
      if (b.y > a.y + 1) {                 // 아래로(부모→자식) — 수직 베지어로 떨어뜨림
        var ax = a.x + NW / 2, ay = a.y + NH, bx = b.x + NW / 2, by = b.y, my = (ay + by) / 2;
        d = "M" + ax + " " + ay + " C" + ax + " " + my + " " + bx + " " + my + " " + bx + " " + by;
      } else {                             // 같은/위 레벨(교차 링크) — 오른쪽으로 둘러
        var cx = a.x + NW, cy = a.y + NH / 2, dx = b.x + NW, dy = b.y + NH / 2, mx = Math.max(cx, dx) + 28;
        d = "M" + cx + " " + cy + " C" + mx + " " + cy + " " + mx + " " + dy + " " + dx + " " + dy;
      }
      var op = dim ? 0.05 : (hot ? 0.95 : 0.26);
      // 엣지는 등장 애니메이션 없이 즉시 그린다 — dasharray 그리기 애니메이션은 긴 엣지(노드 많을 때)에서
      // 점선처럼 깨져 '릴레이션이 클릭 전까지 안 보이는' 버그를 일으켰다. 노드만 pop 애니메이션 유지.
      return '<path class="ag-edge' + (hot ? " ag-hot" : "") + '" d="' + d +
        '" fill="none" stroke="' + relColor(e.rel) + '" stroke-width="' + (hot ? 2.2 : 1.3) + '" opacity="' + op + '"/>';
    }).join("");
    var curRound = (rec && rec.round != null) ? rec.round : null;   // 지금 보는 라운드 — 이 라운드 추가 노드 강조
    var nIdx = 0;
    var nodeSvg = nodes.map(function (n) {
      var p = pos[n.id]; if (!p) return "";
      var col = kindColor(n.kind), sel = (agSel === n.id), dim = focus && !focus[n.id];
      // 막다름(exhausted=시간예산 소진)은 거의 모든 미결 의도에 붙는 흔한 상태라 태그에서 제외 —
      // 사점(점선·흐림) 표기는 실제 중단 사유인 차단·중단만.
      var dead = n.kind === "intent" && (n.state === "blocked" || n.state === "stopped");
      var isCtx = !!ctxIds[n.id];   // 라운드별 보기에서 맥락으로 끌어온 직전 부모
      var cls = "ag-node" + (n._new ? " ag-new" : "") + (n.state === "running" ? " ag-run" : "") + (dead ? " ag-dead" : "") + (n.kind === "finding" ? " ag-find" : "") + (isCtx ? " ag-ctx" : "");
      var delay = n._new ? (nIdx++ * 55) : 0;
      var l1col = col.solid ? col.fg2 : col.line, l2col = col.solid ? col.fg : C.text;
      var l1 = kindLabelKo(n.kind) + (n.technique ? " · " + esc(n.technique) : "");
      var l2 = esc(truncate(n.summary || kindLabelKo(n.kind), 16));
      // 상태 뱃지 — 대기·완료·막다름 외 의미 있는 상태(실행 중·차단·중단·확인됨·포착)만.
      var showSt = n.kind === "intent" && n.state && n.state !== "open" && n.state !== "done" && n.state !== "exhausted";
      var stBadge = showSt ? '<text x="' + (p.x + NW - 11) + '" y="' + (p.y + 21) + '" text-anchor="end" font-size="8.5" font-weight="700" fill="' + stateColor(n.state) + '">' + esc(stateKo(n.state)) + "</text>" : "";
      var op = isCtx ? (dim ? 0.18 : 0.5) : (dim ? 0.2 : (dead ? 0.9 : 1));
      // 라운드 태그 — 노드가 생성된 라운드. 지금 보는 라운드에 추가된 노드는 강조색(그 외 회색).
      var rnd = (n.round != null && isFinite(n.round) && n.round > 0) ? n.round : null;
      var rcur = (rnd != null && curRound != null && rnd === curRound);
      var rtw = (rnd != null && rnd >= 10) ? 25 : 21;
      var _rCur = _dark ? "#2dd4bf" : "#0d9488", _rOther = _dark ? "#64748b" : "#9aa6b6", _rFg = _dark ? "#0e1420" : "#fff";
      var rTag = rnd != null ? '<g class="ag-rtag' + (rcur ? " cur" : "") + '"><rect x="' + (p.x + 8) + '" y="' + (p.y - 8) +
        '" width="' + rtw + '" height="15" rx="7.5" fill="' + (rcur ? _rCur : _rOther) + '"/>' +
        '<text x="' + (p.x + 8 + rtw / 2) + '" y="' + (p.y + 3) + '" text-anchor="middle" font-size="9" font-weight="700" fill="' + _rFg + '">R' + rnd + "</text></g>" : "";
      // god-view 확정 발견(심판 주입) — 노드 우상단에 표식. 공격자 자기보고 발견과 구분.
      var _gvBg = _dark ? "#059669" : "#0ea371", _gvFg = _dark ? "#0e1420" : "#fff";
      var gvTag = n.godview ? '<g class="ag-gv"><rect x="' + (p.x + NW - 62) + '" y="' + (p.y - 8) +
        '" width="58" height="15" rx="7.5" fill="' + _gvBg + '"/><text x="' + (p.x + NW - 33) + '" y="' + (p.y + 3) +
        '" text-anchor="middle" font-size="8.5" font-weight="700" fill="' + _gvFg + '">god-view</text></g>' : "";
      // 폐쇄(closure) 표식 — fact 노드 전용. 승격(promoted>0) = 빨강 '데드엔드', 후보만 = 앰버 '후보'.
      // 'promoted' 는 승격 라운드(정수) — 플래너 1차가 근거 통과시킨 뒤 asset_graph 에 폐쇄 태그가 달린 것.
      var _deadBg = _dark ? "#991b1b" : "#dc2626", _candBg = _dark ? "#92400e" : "#f59e0b", _candFg = _dark ? "#fef3c7" : "#0b0f1a";
      var _ctxBg = _dark ? "#475569" : "#64748b", _badgeFg = _dark ? "#0e1420" : "#fff";
      var clsTag = "";
      if (n.kind === "fact") {
        if (n.promoted) {
          clsTag = '<g class="ag-clsd"><rect x="' + (p.x + NW - 62) + '" y="' + (p.y + NH - 7) +
            '" width="58" height="15" rx="7.5" fill="' + _deadBg + '"/><text x="' + (p.x + NW - 33) + '" y="' + (p.y + NH + 4) +
            '" text-anchor="middle" font-size="8.5" font-weight="700" fill="' + _badgeFg + '">데드엔드</text></g>';
        } else if (n.closure_candidate) {
          clsTag = '<g class="ag-clsc"><rect x="' + (p.x + NW - 50) + '" y="' + (p.y + NH - 7) +
            '" width="46" height="15" rx="7.5" fill="' + _candBg + '"/><text x="' + (p.x + NW - 27) + '" y="' + (p.y + NH + 4) +
            '" text-anchor="middle" font-size="8.5" font-weight="700" fill="' + _candFg + '">데드엔드?</text></g>';
        }
      }
      var ctxTag = isCtx ? '<g class="ag-ctxtag"><rect x="' + (p.x + 8 + rtw + 4) + '" y="' + (p.y - 8) +
        '" width="54" height="15" rx="7.5" fill="' + _ctxBg + '"/><text x="' + (p.x + 8 + rtw + 4 + 27) + '" y="' + (p.y + 3) +
        '" text-anchor="middle" font-size="8.5" font-weight="700" fill="' + _badgeFg + '">직전 노드</text></g>' : "";
      return '<g class="' + cls + (rcur ? " ag-rcur" : "") + '" data-nid="' + n.id + '"' + (delay ? ' style="animation-delay:' + delay + 'ms"' : "") + ' opacity="' + op + '">' +
        '<rect x="' + p.x + '" y="' + p.y + '" width="' + NW + '" height="' + NH + '" rx="10" fill="' + col.bg + '" stroke="' + col.line + '" stroke-width="' + (sel ? 2.8 : (col.solid ? 1.6 : 1.2)) + '"' + (dead || isCtx ? ' stroke-dasharray="5 3"' : "") + "/>" +
        '<text class="agk" x="' + (p.x + 13) + '" y="' + (p.y + 21) + '" font-size="9.5" font-weight="700" fill="' + l1col + '">' + l1 + "</text>" + stBadge +
        '<text x="' + (p.x + 13) + '" y="' + (p.y + 39) + '" font-size="11.5" fill="' + l2col + '">' + l2 + "</text>" + rTag + gvTag + ctxTag + clsTag + "</g>";
    }).join("");
    var vb = agView || { x: 0, y: 0, w: W, h: H };     // agView=수동 조작(확대·이동) 지속, null=자동 맞춤(라이브 성장 추적)
    var tools = '<div class="ag-tools">' +
      '<button class="ag-tool ag-tool-full" data-agfull aria-label="' + (agFull ? "전체화면 나가기" : "그래프 전체화면") + '" title="' + (agFull ? "전체화면 나가기 (Esc)" : "그래프만 전체화면으로") + '">' + (agFull ? "✕" : "⛶") + "</button>" +
      '<button class="ag-tool" data-agzoom="in" aria-label="확대">+</button>' +
      '<button class="ag-tool" data-agzoom="out" aria-label="축소">−</button>' +
      '<button class="ag-tool" data-agzoom="fit" aria-label="맞춤">⤢</button></div>';
    // 전체화면 안내 바 — 평소 숨김(CSS), #view.ag-full 일 때만 좌상단에 회차·라운드 + 나가기 안내.
    var _fctx = aggEp ? (aggEp + "회차 종합") : (rec ? ((rec.episode || 1) + "회차 R" + rec.round) : "예시");
    var fullBar = '<div class="ag-full-bar">' + esc(_fctx) + " · 공격 추론 그래프 <span>Esc · ✕ 나가기</span></div>";
    var svg = '<div class="ag-wrap">' + tools + fullBar +
      '<svg class="ag-svg" tabindex="0" viewBox="' + vb.x + " " + vb.y + " " + vb.w + " " + vb.h +
      '" preserveAspectRatio="xMidYMid meet" data-gw="' + W + '" data-gh="' + H + '">' + edgeSvg + nodeSvg + "</svg></div>";
    var legend = '<div class="ag-legend"><div class="legend">' +
      ["goal", "intent", "fact", "finding"].map(function (k) { return '<span><span class="tag-dot" style="background:' + kindColor(k).line + '"></span>' + kindLabelKo(k) + "</span>"; }).join("") +
      ["spawns", "yields", "proves", "derived_from", "enables"].map(function (r) { return '<span title="' + esc(relDesc(r)) + '"><span style="display:inline-block;width:15px;height:0;border-top:2px solid ' + relColor(r) + '"></span> ' + relLabel(r) + "</span>"; }).join("") + "</div>" +
      '<div class="legend ag-legend-st"><span class="agl-k">상태</span>' +
      '<span><span class="agls agls-run"></span>실행 중(맥동)</span>' +
      '<span><span class="agls agls-dead"></span>차단·중단(점선·흐림)</span>' +
      '<span><span class="agls" style="background:' + C.teal + ';border:none"></span>R# 생성 라운드(강조=현재 라운드 추가)</span>' +
      (_perRound ? '<span><span class="agls" style="background:' + C.sys + ';border:none;opacity:.55"></span>직전 노드(점선·흐림, 맥락용)</span>' : "") +
      (focus ? '<span class="agl-focus">· 선택 노드 계보만 선명 (노드 다시 클릭 → 해제)</span>' : "") + "</div></div>";
    var chips = (rounds && rounds.length) ? roundChipsHtml(rounds, selKey || "", "data-agrk") : "";
    var ctx = aggEp ? aggEp + "회차 종합 · 누적 그래프" : (rec ? (rec.episode || 1) + "회차 R" + rec.round + (_perRound ? " · 이 라운드 노드만(직전 노드는 점선)" : "") : "예시");
    return (S.demo ? demoBanner() : "") + chips +
      '<div class="section-label">' + ctx + " · 공격 추론 그래프 (목표 → 의도 → 사실 → 발견)</div>" +
      agViewToggle() + agKindFilter(g.nodes || []) +
      '<div class="ag-layout"><div class="ag-main">' + svg + legend + "</div>" +
      '<div class="ag-side">' + agPanel(g.nodes || []) + "</div></div>";
  }
  // 보기 전환 — 그래프(관계 트리) ↔ 리스트(종류별 일괄 나열)
  function agViewToggle() {
    return '<div class="tabs ag-vtoggle"><button class="tab' + (agMode !== "list" ? " active" : "") + '" data-agmode="graph">그래프</button>' +
      '<button class="tab' + (agMode === "list" ? " active" : "") + '" data-agmode="list">리스트</button></div>';
  }
  // 종류별 노드 리스트 — 목표·의도·사실·발견 순으로 섹션, 각 노드 한 줄 요약(클릭 시 우측 상세).
  function agNodeList(nodes) {
    var kinds = ["goal", "intent", "fact", "finding"];
    var byKind = {}; nodes.forEach(function (n) { (byKind[n.kind] = byKind[n.kind] || []).push(n); });
    var secs = kinds.filter(function (k) { return byKind[k] && byKind[k].length; });
    if (!secs.length) return '<div class="tile-sub" style="padding:18px">표시할 노드가 없습니다.</div>';
    return '<div class="anl">' + secs.map(function (k) {
      var col = kindColor(k), items = byKind[k].slice().sort(function (a, b) { return (a.id || 0) - (b.id || 0); });
      return '<div class="anl-sec"><div class="anl-h"><span class="tag-dot" style="background:' + col.line + '"></span>' +
        kindLabelKo(k) + ' <span class="anl-n">' + items.length + "건</span></div>" +
        items.map(function (n) {
          var fc = (k === "finding") ? findingCvss(n) : null, sev = fc ? String(fc.severity).toLowerCase() : "";
          var st = (n.state && n.state !== "open" && n.state !== "exhausted" && n.state !== "done");
          return '<button class="anl-item' + (agSel === n.id ? " sel" : "") + '" data-nid="' + n.id + '">' +
            '<div class="anl-top">' +
            (n.round ? '<span class="anl-r">R' + n.round + "</span>" : "") +
            (n.technique ? '<span class="badge b-atk">' + esc(n.technique) + "</span>" : "") +
            (n.godview ? '<span class="badge b-ok">god-view</span>' : "") +
            (st ? '<span class="anl-st" style="color:' + stateColor(n.state) + '">' + esc(stateKo(n.state)) + "</span>" : "") +
            (fc ? '<span class="sev-badge sev-' + sev + '">CVSS ' + fc.score + "</span>" : "") +
            '</div><div class="anl-sum">' + esc(n.summary || kindLabelKo(k)) + "</div>" +
            (n.target ? '<div class="anl-tgt mono">' + esc(n.target) + "</div>" : "") + "</button>";
        }).join("") + "</div>";
    }).join("") + "</div>";
  }
  // 카테고리(종류) 표시 토글 — 노드 많을 때 종류별로 조회. 켜진 종류만 그래프에 표시.
  function agKindFilter(allNodes) {
    var present = {}; (allNodes || []).forEach(function (n) { present[n.kind] = (present[n.kind] || 0) + 1; });
    var chips = ["goal", "intent", "fact", "finding"].filter(function (k) { return present[k]; }).map(function (k) {
      var on = !agHide[k], c = kindColor(k);
      return '<button class="agf' + (on ? " on" : "") + '" data-agkind="' + k + '"' + (on ? ' style="border-color:' + c.line + ";color:" + c.line + '"' : "") + '>' +
        '<span class="agf-dot" style="background:' + c.line + '"></span>' + kindLabelKo(k) + ' <span class="agf-n">' + present[k] + "</span></button>";
    }).join("");
    return chips ? '<div class="agfilter"><span class="agf-k">표시</span>' + chips + "</div>" : "";
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
    var firstCrown = null; rs.forEach(function (r) { if (firstCrown == null && (r.crowns_reached_cum || []).length) firstCrown = r.round; });

    var vc = e.verdict_counts || {};
    var blocked = vc.blocked || 0, fake = (vc.fake_patch || 0) + (vc.not_blocked || 0) + (vc.service_broken || 0);
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
      ["목표 도달", firstCrown ? "R" + firstCrown : "미도달", firstCrown ? "첫 핵심 자산 반출" : "방어 유지", firstCrown ? "accent-crown" : "accent-ok", firstCrown ? C.crown : C.ok]
    ].map(function (t) {
      return '<div class="tile ' + t[3] + '"><div class="tile-k"><span class="tag-dot" style="background:' + t[4] + '"></span>' + t[0] + '</div><div class="tile-v">' + t[1] + "</div>" + (t[2] ? '<div class="tile-sub">' + t[2] + "</div>" : "") + "</div>";
    }).join("");

    var narr = "총 " + e.rounds + "라운드를 진행했습니다. " +
      (crowns.length ? "공격자가 핵심정보 " + crowns.length + "종(" + crowns.map(crownLabel).join(", ") + ")을 유출했고, " : "공격자는 핵심정보를 유출하지 못했고, ") +
      "방어는 " + blocked + "회 차단에 성공했으나 " + fake + "회는 패치 적용에도 차단하지 못했습니다(무효 패치). " +
      "공격 탐지율은 " + pct(recall) + ", 패치 후 서비스 정상 유지 비율은 " + pct(e.availability) + "입니다. " +
      (firstCrown ? "최초 핵심 자산 반출은 R" + firstCrown + "에서 발생했습니다." : "핵심 자산 반출은 확인되지 않았습니다.");

    var reported = {}; rs.forEach(function (r) { (r.reported_techniques || []).forEach(function (t) { reported[t] = 1; }); });
    var repList = Object.keys(reported);
    var cmp = '<div class="grid cols-2">' +
      '<div class="card flow-card c-atk"><div class="card-h">실제로 일어난 일</div>' +
        reportLine("핵심정보 유출", crowns.length ? crowns.map(crownLabel).join(", ") : "없음") +
        reportLine("최초 침해 라운드", firstCrown ? "R" + firstCrown : "없음") +
        reportLine("달성 목표", (e.goals_reached || []).length ? e.goals_reached.join(", ") : "없음") + "</div>" +
      '<div class="card flow-card c-def"><div class="card-h">방어자가 파악한 것</div>' +
        reportLine("탐지한 기법", repList.length ? repList.join(", ") : "없음") +
        reportLine("탐지 정확도", "정탐 " + det.tp + " · 오탐 " + det.fp + " · 미탐 " + det.fn) +
        reportLine("평균 탐지 소요", mttd.mean_rounds != null ? mttd.mean_rounds + "라운드" : "—") + "</div></div>";

    var vbars = barChart([{ label: "차단", value: vc.blocked || 0, color: C.ok }, { label: "무효 패치", value: fake, color: C.atk }, { label: "판정불가", value: vc.inconclusive || 0, color: C.sys }]);
    var rows = rs.map(function (r) {
      var vv = VERDICT[r.verdict], nAsset = (r.crowns_reached_cum || []).length;
      var key = (r.episode || e.episode) + "-" + r.round;
      var jmp = '<div class="rep-jmps"><button class="rep-jmp" data-rjag="' + key + '">추적 그래프 ↗</button>' +
        '<button class="rep-jmp" data-rjdef="' + key + '">탐지·검증 ↗</button></div>';
      return "<tr><td class='mono'>R" + r.round + "</td><td>" + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : esc(r.verdict)) + "</td><td class='mono'>" + ((r.reported_techniques || []).join(", ") || "—") + "</td><td class='mono'>" + (nAsset ? nAsset + "종" : "—") + "</td><td>" + (_dSkipped(r) ? '<span class="badge b-sys">—</span>' : r.healthcheck_passed ? '<span class="badge b-ok">정상</span>' : '<span class="badge b-atk">중단</span>') + "</td><td>" + jmp + "</td></tr>";
    }).join("");
    var timeline = '<div class="section-label">라운드별 타임라인 · 근거</div>' +
      '<div class="card" style="padding:0;overflow:hidden"><table class="tbl"><thead><tr><th>라운드</th><th>판정</th><th>탐지 기법</th><th>침해 자산</th><th>서비스</th><th>근거</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
    var detail = '<details class="rep-details"><summary>전문가용 상세 보기</summary>' +
      '<div class="section-label">판정 분포</div><div class="card">' + vbars + "</div></details>";

    return (S.demo ? demoBanner() : "") + chips +
      '<div class="rep-head">' + e.episode + "회차 · " + e.rounds + "라운드 · " + esc(endReasonLabel(e.end_reason)) + "</div>" +
      '<div class="grid cols-6" style="margin:10px 0 2px">' + tiles + "</div>" +
      '<div class="card rep-narr">' + esc(narr) + "</div>" +
      cvssCard(crowns) +
      '<div class="section-label">실제 vs 방어자 추측</div>' + cmp + timeline + detail;
  }

  // ───────── 페이지: 공격 브리핑(큐레이션 — 전체 흐름 종합) ─────────
  // 노드 그래프 인덱스 — 부모·자식·목표 역추적 공용.
  function graphIndex(nodes, edges) {
    var byId = {}, parents = {}, children = {}, DO = { goal: 0, intent: 1, fact: 2, finding: 3 };
    (nodes || []).forEach(function (n) { byId[n.id] = n; parents[n.id] = []; children[n.id] = []; });
    (edges || []).forEach(function (e) { if (byId[e.src] && byId[e.dst]) { parents[e.dst].push(e.src); children[e.src].push(e.dst); } });
    function traceToGoal(id) {
      var chain = [], seen = {}, cur = id, g = 0;
      while (cur != null && !seen[cur] && g++ < 60) {
        seen[cur] = 1; chain.unshift(byId[cur]);
        var ps = (parents[cur] || []).filter(function (p) { return byId[p] && !seen[p]; });
        ps.sort(function (a, b) { return (DO[byId[a].kind] || 9) - (DO[byId[b].kind] || 9); });
        cur = ps.length ? ps[0] : null;
      }
      return chain;
    }
    return { byId: byId, parents: parents, children: children, traceToGoal: traceToGoal };
  }
  function _nlabel(n) { return kindLabelKo(n.kind) + (n.technique ? "·" + esc(n.technique) : "") + " " + esc(truncate(n.summary || "", 30)); }
  function _baseTech(t) { return String(t || "").split(".")[0]; }   // 하위기법→상위(T1552.001→T1552)

  async function pageAttackBriefRender() {
    var view = $("#view");
    if (S.demo || !S.rounds.length) {
      var dg = demoAttackGraph();
      if (route !== "attack-brief") return;
      view.innerHTML = pageAttackBrief(dg, S.rounds || [], (S.episodes || [])[(S.episodes || []).length - 1] || null, S.episodes || []);
      bindBrief(); return;
    }
    var eps = S.episodes || [], e = null, rs = S.rounds;
    if (eps.length) {
      var idx = briefEp != null ? eps.map(function (x) { return x.episode; }).indexOf(briefEp) : eps.length - 1;
      if (idx < 0) idx = eps.length - 1;
      e = eps[idx];
      rs = S.rounds.filter(function (r) { return (r.episode || 1) === e.episode; });
    }
    if (!rs.length) rs = S.rounds;
    var lastR = rs[rs.length - 1] || {};
    var ep = (e && e.episode) || (lastR.episode || 1), rnd = lastR.round;
    var g = { nodes: [], edges: [] };
    if (rnd != null) { var d = await jget("/api/attack_graph/" + ep + "/" + rnd); if (d && d.graph) g = d.graph; }
    if (route !== "attack-brief") return;
    view.innerHTML = pageAttackBrief(g, rs, e, eps);
    bindBrief();
  }
  function pageAttackBrief(g, rs, e, eps) {
    var nodes = g.nodes || [], edges = g.edges || [];
    var chips = (eps && eps.length > 1) ? '<div class="rchips">' + eps.map(function (x) {
      var on = e && x.episode === e.episode, col = (x.crowns_reached && x.crowns_reached.length) ? C.atk : C.ok;
      return '<button class="rchip' + (on ? " on" : "") + '" data-briefep="' + x.episode + '"><span class="tag-dot" style="background:' + col + '"></span>' + x.episode + "회차</button>";
    }).join("") + "</div>" : "";
    if (!nodes.length && !rs.length)
      return (S.demo ? demoBanner() : "") + emptyState("📄", "아직 공격 기록이 없습니다", "실행이 진행되면 자산별 침해·라운드별 공진화·기법별 전술이 여기 종합됩니다.", []);
    var crowns = (e && e.crowns_reached) ? e.crowns_reached : (function () { var s = {}; rs.forEach(function (r) { (r.crowns_reached_cum || []).forEach(function (c) { s[c] = 1; }); }); return Object.keys(s); })();
    return (S.demo ? demoBanner() : "") + chips +
      briefSummary(e, rs, nodes) + cvssCard(crowns) + briefAssets(nodes, edges) + briefTimeline(rs, nodes) + briefTechniques(nodes, rs);
  }
  // 1) 핵심 수치 요약 헤더
  function briefSummary(e, rs, nodes) {
    var vc = { blocked: 0, fake: 0 };
    rs.forEach(function (r) { if (r.verdict === "blocked") vc.blocked++; else if (r.verdict === "fake_patch" || r.verdict === "not_blocked" || r.verdict === "service_broken") vc.fake++; });
    var dec = vc.blocked + vc.fake;
    var lastDet = null; for (var i = rs.length - 1; i >= 0; i--) { if (rs[i].detection_cum) { lastDet = rs[i].detection_cum; break; } }
    var recall = lastDet && (lastDet.tp + lastDet.fn) ? lastDet.tp / (lastDet.tp + lastDet.fn) : null;
    var crowns = (e && e.crowns_reached) ? e.crowns_reached : (function () { var s = {}; rs.forEach(function (r) { (r.crowns_reached_cum || []).forEach(function (c) { s[c] = 1; }); }); return Object.keys(s); })();
    var assets = assetBreach(nodes);
    var breached = assets.filter(function (a) { return a.stage >= 3; }).length;
    var exfil = assets.filter(function (a) { return a.stage >= 4; }).length;
    var ctx = e ? e.episode + "회차 · " + (e.rounds || rs.length) + "라운드" : rs.length + "라운드";
    var tiles = [
      ["대상 자산", assets.length + "개", "탐색·접근된 자산", C.teal, "accent-teal"],
      ["침해 자산", breached + "개", exfil ? "데이터 반출 " + exfil + "개" : "반출 없음", breached ? C.atk : C.ok, breached ? "accent-atk" : "accent-ok"],
      ["핵심 자산 반출", crowns.length + "종", crowns.length ? crowns.map(crownLabel).join(", ") : "없음", crowns.length ? C.atk : C.ok, crowns.length ? "accent-atk" : "accent-ok"],
      ["공격 차단율", pct(dec ? vc.blocked / dec : null), "무효 패치 " + vc.fake + "회", C.ok, "accent-ok"],
      ["공격 탐지율", pct(recall), lastDet ? "미탐 " + lastDet.fn + "건" : "—", C.teal, "accent-teal"]
    ].map(function (t) { return '<div class="tile ' + t[4] + '"><div class="tile-k"><span class="tag-dot" style="background:' + t[3] + '"></span>' + t[0] + '</div><div class="tile-v">' + t[1] + "</div>" + (t[2] ? '<div class="tile-sub">' + t[2] + "</div>" : "") + "</div>"; }).join("");
    return '<div class="brief-head">' + esc(ctx) + " · 공격 흐름 종합</div><div class=\"grid cols-5\">" + tiles + "</div>";
  }
  // 2) 자산별 침해 서사 — target 으로 묶어 도달 단계·경로·발견·확보 데이터를 서술.
  function briefAssets(nodes, edges) {
    var assets = assetBreach(nodes);
    if (!assets.length) return "";
    var idx = graphIndex(nodes, edges);
    var cards = assets.map(function (a) {
      var topFind = a.findings.slice().sort(function (x, y) { return (_SEVR[String(y.severity).toLowerCase()] || 0) - (_SEVR[String(x.severity).toLowerCase()] || 0); })[0];
      var pathHtml = "";
      if (topFind) {
        var chain = idx.traceToGoal(topFind.id).filter(function (n) { return n.id !== topFind.id; });
        if (chain.length) pathHtml = '<div class="grpt-path"><span class="grpt-k">경로</span>' + chain.map(_nlabel).join(' <span class="grpt-arr">→</span> ') + ' <span class="grpt-arr">→</span> <b>' + kindLabelKo("finding") + "</b></div>";
      }
      var lootN = a.findings.filter(function (f) { return f.loot != null && String(f.loot) !== ""; });
      var lootHtml = lootN.length ? '<div class="grpt-loot">확보 데이터: <span class="mono">' + esc(truncate(lootN.map(function (f) { return typeof f.loot === "object" ? JSON.stringify(f.loot) : String(f.loot); }).join(" · "), 140)) + "</span></div>" : "";
      var narr = "'" + esc(a.target) + "' 자산에 " + (a.tech.length ? esc(a.tech.join(", ")) + " 기법으로 " : "") + BREACH_STAGE[a.stage] + " 단계까지 진행. " +
        (a.findings.length ? "침해 " + a.findings.length + "건" + (a.maxSev ? "(최고 " + esc(a.maxSev) + ")" : "") + " 확인" : "확정 침해 없음") +
        ", 사실 " + a.facts.length + "건 · 탐색 의도 " + a.intents.length + "건.";
      var sev = String(a.maxSev || "").toLowerCase();
      return '<div class="brief-asset stg-' + a.stage + '">' +
        '<div class="brief-ah"><span class="brief-stage s' + a.stage + '">' + BREACH_STAGE[a.stage] + "</span>" +
        '<span class="brief-at mono">' + esc(a.target) + "</span>" +
        (a.maxSev ? '<span class="sev-badge sev-' + sev + '">' + esc(a.maxSev) + "</span>" : "") +
        (a.rounds.length ? '<span class="grpt-rnd">R' + a.rounds[0] + (a.rounds.length > 1 ? "–" + a.rounds[a.rounds.length - 1] : "") + "</span>" : "") + "</div>" +
        '<div class="brief-anarr">' + narr + "</div>" + pathHtml + lootHtml + "</div>";
    }).join("");
    return '<div class="section-label">자산별 침해</div><div class="brief-assets">' + cards + "</div>";
  }
  // 3) 라운드별 공진화 타임라인 — 공격(신규 노드·기법) → 방어(탐지·패치) → 검증(판정).
  function briefTimeline(rs, nodes) {
    if (!rs.length) return "";
    var addByR = {};
    nodes.forEach(function (n) { if (n.round != null && n.kind !== "goal") { (addByR[n.round] = addByR[n.round] || []).push(n); } });
    var rows = rs.map(function (r) {
      var add = addByR[r.round] || [];
      var newFind = add.filter(function (n) { return n.kind === "finding"; });
      var atkTech = {}; add.forEach(function (n) { if (n.technique) atkTech[n.technique] = 1; });
      var atk = Object.keys(atkTech).length ? esc(Object.keys(atkTech).join(", ")) : (add.length ? add.length + "개 노드 추가" : "진전 없음");
      var det = r.reported_techniques || [];
      var vv = VERDICT[r.verdict], crownN = (r.crowns_reached_cum || []).length;
      return '<div class="brief-tl-row">' +
        '<div class="brief-tl-r mono">R' + r.round + "</div>" +
        '<div class="brief-tl-cols">' +
          '<div class="brief-tl-c c-atk"><span class="brief-tl-k">공격</span>' + atk + (newFind.length ? ' <span class="brief-tl-b b-atk">침해 +' + newFind.length + "</span>" : "") + (crownN ? ' <span class="brief-tl-b b-crown">핵심자산 ' + crownN + "종</span>" : "") + "</div>" +
          '<div class="brief-tl-c c-def"><span class="brief-tl-k">방어</span>' + (det.length ? "탐지 " + esc(det.join(", ")) : "미탐지") + (r.patch_applied ? ' <span class="brief-tl-b b-def">패치</span>' : "") + "</div>" +
          '<div class="brief-tl-c c-jdg"><span class="brief-tl-k">검증</span>' + (vv ? '<span class="badge ' + vv.cls + '">' + vv.label + "</span>" : esc(r.verdict || "—")) + (!_dSkipped(r) && r.healthcheck_passed === false ? ' <span class="brief-tl-b b-atk">서비스 중단</span>' : "") + "</div>" +
        "</div></div>";
    }).join("");
    return '<div class="section-label">라운드별 공진화</div><div class="card brief-tl">' + rows + "</div>";
  }
  // 4) 기법별 전술 · 탐지 연결 — 공격 사용 기법 ↔ 방어 탐지 매핑(미탐지 = 방어 공백).
  function briefTechniques(nodes, rs) {
    var tech = {};
    nodes.forEach(function (n) {
      if (!n.technique || n.kind === "goal") return;
      var t = tech[n.technique] = tech[n.technique] || { id: n.technique, targets: {}, findings: 0, maxSev: null };
      if (n.target) t.targets[n.target] = 1;
      if (n.kind === "finding") { t.findings++; if ((_SEVR[String(n.severity).toLowerCase()] || 0) > (_SEVR[String(t.maxSev).toLowerCase()] || 0)) t.maxSev = n.severity; }
    });
    var detected = {};
    rs.forEach(function (r) { (r.reported_techniques || []).forEach(function (x) { detected[_baseTech(x)] = 1; }); });
    var list = Object.keys(tech).map(function (k) { var t = tech[k]; t.targets = Object.keys(t.targets); t.detected = !!detected[_baseTech(k)]; return t; });
    if (!list.length) return "";
    list.sort(function (x, y) { return (_SEVR[String(y.maxSev).toLowerCase()] || 0) - (_SEVR[String(x.maxSev).toLowerCase()] || 0) || y.findings - x.findings; });
    var rows = list.map(function (t) {
      return '<div class="brief-tech">' +
        '<span class="badge b-atk">' + esc(t.id) + "</span>" +
        '<span class="brief-tc-tg mono">' + (t.targets.length ? esc(t.targets.join(", ")) : "—") + "</span>" +
        '<span class="brief-tc-f">' + (t.findings ? "침해 " + t.findings + "건" + (t.maxSev ? " · " + esc(t.maxSev) : "") : "탐색") + "</span>" +
        '<span class="brief-tc-d ' + (t.detected ? "on" : "off") + '">' + (t.detected ? "탐지됨" : "미탐지") + "</span></div>";
    }).join("");
    var miss = list.filter(function (t) { return !t.detected && t.findings; }).length;
    return '<div class="section-label">기법별 전술 · 탐지</div><div class="card brief-techs">' +
      '<div class="brief-tech brief-tech-h"><span>기법</span><span>대상 자산</span><span>결과</span><span>방어 탐지</span></div>' +
      rows + (miss ? '<div class="tile-sub" style="margin-top:8px">침해로 이어졌으나 미탐지된 기법 ' + miss + "건 — 방어 공백</div>" : "") + "</div>";
  }
  function bindBrief() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-briefep]"), function (b) {
      b.onclick = function () { briefEp = parseInt(b.getAttribute("data-briefep"), 10); pageAttackBriefRender(); };
    });
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
    if (route === "defense-log") { await loadEvents(); view.innerHTML = pageDefenseLog(); bindDefenseLog(); return; }
    if (route === "defender-arch") { view.innerHTML = '<p class="page-intro">구성도 불러오는 중…</p>'; var topo = await loadTopology(); if (route === "defender-arch") view.innerHTML = pageArch(topo); return; }
    if (route === "defender-graph") { await pageDefGraphRender(); return; }
    if (route === "attack-graph") { await pageAttackGraphRender(); return; }
    if (route === "attack-brief") { await pageAttackBriefRender(); return; }
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
    // 근거 연결 — 보고서 라운드 → 그 라운드의 공격 추적 그래프 / 탐지·검증 상세로 점프
    Array.prototype.forEach.call(document.querySelectorAll("[data-rjag]"), function (b) {
      b.onclick = function () { agRkey = b.getAttribute("data-rjag"); agSel = null; agView = null; S.agSeen = {}; S.agSig = null; location.hash = "attack-graph"; };
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-rjdef]"), function (b) {
      b.onclick = function () { defSel = b.getAttribute("data-rjdef"); S.defJumpSection = "all"; S.defSig = null; location.hash = "defender-graph"; };
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
    renderBuild(st && st.server_build != null ? st.server_build : null);   // 좌상단 버전 + 서버 불일치 경고

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
    else if (route === "attack-brief") await pageAttackBriefRender();
    else if (route === "defender-graph") { if (!document.querySelector(".modal-ov")) await pageDefGraphRender(); }
    else if (route === "defender-arch") { var topo = await loadTopology(); if (route === "defender-arch") $("#view").innerHTML = pageArch(topo); }
    else if (route === "report") { $("#view").innerHTML = pageReport(); bindRepChips(); }
  }

  // ───────── 라우팅·부팅 ─────────
  function onHash() {
    var r = (location.hash || "").replace(/^#/, "") || DEFAULT_ROUTE;
    if (!TITLES[r]) r = DEFAULT_ROUTE;
    if (agFull && r !== "attack-graph") {   // 다른 화면으로 나가면 전체화면 해제(재렌더 없이 정리)
      agFull = false; _agFullApply();
      try { if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(function () {}); } catch (e) {}
    }
    if (r === "attack-graph") { S.agSeen = {}; S.agSig = null; }   // 진입 시 등장 애니메이션 재생
    route = r; closeSidebar(); render();
  }
  function closeSidebar() { $("#sidebar").classList.remove("open"); var bd = $("#sidebar-backdrop"); if (bd) bd.classList.remove("on"); $("#nav-toggle").setAttribute("aria-expanded", "false"); }

  async function boot() {
    applyTheme();        // 다크모드 localStorage 복원(렌더 전 — 깜빡임 방지)
    renderBuild(null);   // 최초엔 프런트 버전만(서버 응답 오면 poll 이 불일치 경고 갱신)
    buildNav();
    $("#nav-toggle").onclick = function () {
      var sb = $("#sidebar"), open = sb.classList.toggle("open");
      var bd = $("#sidebar-backdrop"); if (bd) bd.classList.toggle("on", open);
      this.setAttribute("aria-expanded", open ? "true" : "false");
    };
    var _bd = $("#sidebar-backdrop"); if (_bd) _bd.onclick = closeSidebar;
    var _sc = $("#sidebar-close"); if (_sc) _sc.onclick = closeSidebar;
    var _tb = $("#theme-btn"); if (_tb) _tb.onclick = function () { toggleTheme(); render(); };
    window.addEventListener("hashchange", onHash);
    // 그래프 전체화면 종료 — Esc 키, 또는 브라우저가 네이티브 전체화면을 빠져나갈 때 오버레이도 해제
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && agFull) setAgFull(false); });
    document.addEventListener("fullscreenchange", function () { if (!document.fullscreenElement && agFull) setAgFull(false); });
    // 속성 블록 호버 설명 — 위임 방식(렌더마다 바인딩 불필요)
    document.addEventListener("mouseover", function (e) {
      var el = e.target && e.target.closest ? e.target.closest(_TIP_SEL) : null;
      var tip = el ? lookupTip(el) : null;
      if (tip) showTip(el, tip); else hideTip();
    });
    window.addEventListener("scroll", hideTip, true);
    await loadCore();
    onHash();
    poll(); if (!window.__SNAPSHOT__) setInterval(poll, 2500);   // 스냅샷은 정적 — 폴링 중단
  }
  boot();
})();
