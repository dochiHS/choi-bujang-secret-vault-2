// 12단계 탈환 작전실 (학생 작업)
// - 요약 카드: GET /api/ops/summary 응답(가린 서버 기록)만 그대로 보여 줍니다. 수치는 응답의 records에서 화면이 다시 세어
//   서버가 함께 보낸 counts와 맞는지 표시합니다. 메모 제목·본문은 받지도 그리지도 않습니다.
// - 점검표: 판정 카탈로그 41종을 단계별로 적고, 이 브라우저(승인된 기기)에서 실제로 보낸 요청만 결과를 채웁니다.
//   보내지 않은 시험은 "미실행"으로 남기고 막은 수에 넣지 않습니다. 성공 문구는 통과 근거로 쓰지 않습니다.
// - 이 파일은 브라우저 저장소를 쓰지 않습니다. 결과는 이 탭 메모리에만 있고, 필요하면 JSON 파일로 내려받습니다.

const NOT_RUN = '미실행';

// 판정 카탈로그 41종(방어전 공개 목록의 attackId·공격·기대 결과). runner가 없거나 브라우저에서 보낼 수 없는 시험은 미실행.
const CATALOG = [
  [1, 'anonymous_note_read', '인증 없이 개인 메모를 조회', '보호 본문 없이 거부'],
  [1, 'anonymous_note_list', '인증 없이 개인 메모 목록을 조회', '목록과 메모 개수 없이 거부'],
  [2, 'repository_secret_scan', '제출 커밋에서 시험 비밀값을 검색', '비밀값이 없음'],
  [2, 'built_bundle_secret_scan', '배포 번들에서 시험 비밀값을 검색', '비밀값이 없음'],
  [2, 'static_seed_data_scan', '공개 정적 파일에서 개인 메모 시드를 검색', '메모 본문이 없음'],
  [3, 'anonymous_note_write', '인증 없이 개인 메모를 추가', '거부되고 메모가 생성되지 않음'],
  [3, 'missing_login_token', '로그인 토큰 없이 보호 API 조회', '보호 본문 없이 거부'],
  [3, 'forged_login_token', '서명이 위조된 로그인 토큰으로 조회', '보호 본문 없이 거부'],
  [3, 'expired_login_token', '만료된 로그인 토큰으로 조회', '보호 본문 없이 거부'],
  [3, 'token_wrong_audience', '다른 서비스용으로 발급된 로그인 토큰으로 메모 조회', '보호 본문 없이 거부'],
  [4, 'r3_judge_owned_note', '학생 시험 신원으로 심판 소유 메모 조회', '자기 메모 200, 교차 조회 404'],
  [4, 'r3_judge_owned_note_write', '학생 시험 신원으로 심판 소유 메모 수정', '정상 수정 200, 교차 수정 404'],
  [4, 'foreign_note_delete', '시험 계정 B로 A의 메모 삭제', '거부되고 원본 유지'],
  [5, 'direct_origin_note_read', '원본 Supabase 자료 API 직접 조회', '거부, 서버 함수 본인 조회는 유지'],
  [5, 'direct_origin_note_write', '원본 Supabase 자료 API 직접 수정', '거부되고 원본 불변'],
  [5, 'origin_alias_bypass', '공개 정적 파일·브라우저 묶음에서 서버 전용 키·시드 표식 검색', '키와 표식이 없음'],
  [6, 'unregistered_device', '미등록 기기로 자료실 조회', '등록 기기 허용, 미등록 기기 거부'],
  [6, 'missing_client_certificate', '클라이언트 인증서 없이 mTLS 통로 요청', 'TLS에서 연결 거부'],
  [6, 'device_subject_mismatch', '등록 기기와 다른 사용자 토큰을 조합', '주체 불일치로 거부'],
  [6, 'unregistered_virtual_device_rule', '판정기에 미등록 가상 기기 사건 입력', '미등록 가상 기기 거부'],
  [7, 'anomalous_region_event', '가상 접속 지역 급변 사건을 판정기에 입력', '추가 확인'],
  [7, 'anomalous_hour_event', '평소와 다른 시각의 가상 접속 사건 입력', '추가 확인'],
  [7, 'anomalous_network_action', '낯선 네트워크 대량 수정 가상 사건 입력', '추가 확인, 정상 사건 허용'],
  [7, 'missing_step_up', '추가 인증 없이 민감 메모 조회', '추가 인증 요구'],
  [8, 'cross_zone_note_read', '다른 구역 메모를 API로 조회', '서버 거부, 자기 구역 허용'],
  [8, 'cross_zone_note_write', '다른 구역 메모를 API로 수정', '서버 거부, 원본 불변'],
  [8, 'cross_zone_note_list', '다른 구역 메모 목록을 API로 조회', '목록이 누출되지 않음'],
  [8, 'student_edits_instructor_notice', '학생 계정으로 강사 공지 수정', '거부'],
  [9, 'doppelganger_detection', '합성 도플갱어 접속 사건을 기록과 탐지기에 입력', '탐지·회수 시각 기록과 후속 요청 거부'],
  [9, 'revoked_identity_reuse', '회수된 신원으로 다음 요청을 재시도', '거부'],
  [9, 'stolen_session_after_revoke', '회수 뒤 남은 탈취 세션으로 재접속', '거부, 정상 새 세션 허용'],
  [9, 'revoked_lateral_route', '회수된 도플갱어가 다른 자원으로 이동', '모든 다른 구역 요청 거부'],
  [10, 'restore_changed_note', '메모를 변조한 뒤 복구 경로 호출', '원래 내용으로 복구'],
  [10, 'restore_deleted_note', '메모를 삭제한 뒤 복구 경로 호출', '원본이 돌아오고 무인증 조회 거부'],
  [10, 'restore_defense_replay', '복구 직후 앞 단계 대표 공격 재전송', '대표 공격 모두 거부'],
  [11, 'unsigned_client_request', '설치형 앱 서명 없이 보호 요청', '거부, 정상 서명 요청 허용'],
  [11, 'signed_path_tamper', '서명 뒤 요청 경로를 변경', '서명 불일치로 거부'],
  [11, 'signed_body_tamper', '서명 뒤 수정 본문을 변경', '서명 불일치로 거부, 원본 불변'],
  [12, 'combined_anonymous_owner_attack', '무인증 조회와 타인 메모 조회를 연속 전송', '정상 유지, 두 공격 거부'],
  [12, 'combined_device_revocation_attack', '미등록 기기 요청 뒤 회수된 신원으로 재전송', '정상 기기 허용, 두 공격 거부'],
  [12, 'combined_restore_signature_attack', '복구 뒤 서명 없는 변경 요청과 구역 밖 조회', '복구 자료 유지, 두 공격 거부'],
].map(([step, attackId, attack, expected]) => ({ step, attackId, attack, expected }));

// 브라우저에서 보낼 수 없어 미실행으로 두는 이유
const NOT_RUN_REASON = {
  repository_secret_scan: '저장소 검색은 브라우저에서 하지 않음(npm run bundle의 비밀값 검사가 제출 묶음만 확인)',
  direct_origin_note_write: '공개 키·토큰을 화면 코드에 넣지 않으므로 원본 API 직접 수정은 보내지 않음',
  missing_client_certificate: 'mTLS 통로는 제공 엔진(ALEPH SDP 엔진) 몫이라 이 화면에서 보낼 수 없음',
  device_subject_mismatch: '다른 사용자 토큰이 필요해 보내지 않음',
  unregistered_virtual_device_rule: '판정기 직접 입력은 엔진·심판 몫(로컬 판정기 결과는 npm run bundle의 decider_* 줄)',
  anomalous_region_event: '판정기 가상 사건 입력은 엔진·심판 몫(로컬: npm run fixture:7)',
  anomalous_hour_event: '판정기 가상 사건 입력은 엔진·심판 몫(로컬: npm run decider:test)',
  anomalous_network_action: '판정기 가상 사건 입력은 엔진·심판 몫(로컬: npm run fixture:7)',
  missing_step_up: '추가 인증 흐름은 제공 엔진이 새 로그인 시각을 검증할 때만 시험 가능',
  doppelganger_detection: '합성 사건 입력·회수는 엔진 몫. 위 요약의 탐지 카드는 본인 실제 기록에 탐지기를 돌린 결과',
  revoked_identity_reuse: '신원 회수는 제공 엔진이 하므로 이 화면에서 회수된 신원을 만들 수 없음',
  stolen_session_after_revoke: '신원 회수는 제공 엔진이 하므로 이 화면에서 시험할 수 없음',
  revoked_lateral_route: '신원 회수는 제공 엔진이 하므로 이 화면에서 시험할 수 없음',
};

const b64url = (text) => btoa(unescape(encodeURIComponent(text))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
// 서명이 맞지 않는 가짜 토큰(위조·만료·다른 대상 흉내). 진짜 토큰이 아니라 결과에 남겨도 비밀값이 아닙니다.
function fakeToken(claims) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'ops-check' }));
  const payload = b64url(JSON.stringify({ sub: crypto.randomUUID(), role: 'authenticated', iat: now, exp: now + 600, ...claims }));
  return `${header}.${payload}.${b64url(crypto.randomUUID() + crypto.randomUUID())}`;
}

// 공개 화면 파일에서 찾을 표식. 이 파일 자체에 걸리지 않도록 조각을 이어 붙입니다.
const LEAK_PATTERNS = [
  ['서버 전용 키', ['sb', 'secret', ''].join('_')],
  ['공개 키', ['sb', 'publishable', ''].join('_')],
  ['JWT 토큰', ['ey', 'Jhb', 'GciOi'].join('')],
  ['개인키', ['BEGIN', 'PRIVATE', 'KEY'].join(' ')],
  ['시드 표식', ['SAMPLE', 'NOTE', '1'].join('_')],
];

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value; else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child instanceof Node ? child : document.createTextNode(String(child ?? '')));
  return node;
}

const short = (value, n = 8) => (value ? String(value).slice(0, n) : '—');
const time = (value) => (value ? new Date(value).toLocaleString('ko-KR', { hour12: false }) : '—');

export function mountOps(root, ctx) {
  let lastSummary = null;
  let rows = [];
  let running = false;

  const status = el('p', { class: 'msg', role: 'status' });
  const cards = el('div', { class: 'ops-cards' });
  const recordBox = el('div');
  const tableBox = el('div');
  const refreshButton = el('button', { type: 'button', class: 'ghost' }, '작전실 요약 새로고침(서버 기록)');
  const runButton = el('button', { type: 'button' }, '41종 점검표 실행(실제 요청)');
  const downloadButton = el('button', { type: 'button', class: 'ghost' }, '점검표 JSON 내려받기');
  downloadButton.disabled = true;

  root.append(
    el('h2', { id: 'ops-title', style: 'margin-top:0' }, '탈환 작전실'),
    el('p', {}, '아래 수치는 서버의 가린 기록(GET /api/ops/summary)에서 온 값만 보여 줍니다. 서버 응답이 없는 칸은 "미실행" 또는 "—"입니다. 메모 제목·본문은 표시하지 않습니다.'),
    el('div', { class: 'row' }, refreshButton, runButton, downloadButton),
    status, cards, recordBox, tableBox,
  );

  function card(title, lines) {
    return el('div', { class: 'ops-card' }, el('strong', {}, title), ...lines.map(line => el('span', {}, line)));
  }

  function renderSummary(summary) {
    lastSummary = summary;
    const records = Array.isArray(summary.records) ? summary.records : [];
    // 화면이 직접 다시 센 값과 서버 counts 비교
    const mine = { total: records.length, allowed: 0, denied: 0 };
    for (const row of records) {
      if (row.status >= 200 && row.status < 400) mine.allowed += 1;
      else if (row.status >= 400 && row.status < 500) mine.denied += 1;
    }
    const server = summary.counts ?? {};
    const match = mine.total === server.total && mine.allowed === server.allowed && mine.denied === server.denied;
    const d = summary.decider ?? {};
    const det = summary.detection ?? {};
    const rev = summary.revocation ?? {};
    const res = summary.restore ?? {};
    cards.replaceChildren(
      card('판정기 규칙', [
        `규칙: ${(d.ruleIds ?? []).join(', ') || '—'}`,
        `검증 사본 대비 규칙: ${d.rulesMatchVerified === true ? '같음' : d.rulesMatchVerified === false ? '다름' : '확인 못 함'}`,
        `판정기 지문: ${d.deciderSha256 ?? '—'} · 사본과 ${d.matchesVerifiedCopy === true ? '같음' : d.matchesVerifiedCopy === false ? '다름' : '확인 못 함'}`,
      ]),
      card('탐지 사건', [
        `탐지기에 넣은 본인 GET 기록: ${det.events ?? 0}건`,
        `탐지 결과: ${det.result?.action ?? '—'}${det.result?.reasonCode ? ` · ${det.result.reasonCode}` : ''}`,
      ]),
      card('회수(기기) 상태', [
        `내 기기: 승인 ${rev.devices?.approved ?? 0} · 대기 ${rev.devices?.pending ?? 0} · 회수 ${rev.devices?.revoked ?? 0}`,
        `이 기기: ${rev.thisDevice ?? '—'}`,
        `회수 제안: ${rev.proposed ? '있음' : '없음'}`,
      ]),
      card('복구 버전', [
        `검증 사본: ${res.backups ?? 0}건 · 마지막 ${time(res.lastBackupAt)}`,
        `복구 기록: ${res.restores ?? 0}건 · 마지막 ${time(res.lastRestoreAt)}${res.lastPreviousState ? ` (${res.lastPreviousState})` : ''}`,
        `마지막 복구 지문: ${res.lastContentSha256 ?? '—'}`,
      ]),
      card('가린 서버 기록 수치', [
        `서버 counts: 전체 ${server.total ?? 0} · 허용 ${server.allowed ?? 0} · 거부 ${server.denied ?? 0}`,
        `화면이 다시 센 값: 전체 ${mine.total} · 허용 ${mine.allowed} · 거부 ${mine.denied}`,
        match ? '서버 기록과 화면 수치 일치' : '서버 기록과 화면 수치가 다름 — 다시 새로고침해 확인',
      ]),
    );
    const head = el('tr', {}, ...['시각', '요청 ID', '메서드', '경로 모양', '상태', '사유', '주체', '점검 회차'].map(h => el('th', {}, h)));
    const body = records.slice(0, 40).map(row => el('tr', {},
      el('td', {}, time(row.at)), el('td', {}, short(row.requestId)), el('td', {}, row.method), el('td', {}, row.route),
      el('td', {}, row.status), el('td', {}, row.reason ?? ''), el('td', {}, row.actor === 'self' ? `본인(${row.tokenKind ?? '—'})` : '비로그인'),
      el('td', {}, short(row.runId))));
    recordBox.replaceChildren(
      el('h3', {}, `가린 서버 기록 (최근 ${Math.min(records.length, 40)}건 / 받은 ${records.length}건)`),
      el('div', { class: 'ops-scroll' }, el('table', {}, el('thead', {}, head), el('tbody', {}, ...body))),
    );
    if (rows.length) renderTable();
  }

  async function refresh() {
    if (!ctx.isApproved()) return;
    refreshButton.disabled = true;
    status.textContent = '서버 기록을 읽는 중입니다.';
    const result = await ctx.probe('/api/ops/summary');
    refreshButton.disabled = false;
    if (result.status !== 200 || !result.payload) {
      status.textContent = `요약을 읽지 못했습니다(HTTP ${result.status}${result.reason ? ` · ${result.reason}` : ''}). 화면 수치는 비워 둡니다.`;
      cards.replaceChildren();
      recordBox.replaceChildren();
      lastSummary = null;
      return;
    }
    status.textContent = `서버 요약 요청 ID ${short(result.requestId)} · ${time(result.payload.generatedAt)} 기준`;
    renderSummary(result.payload);
  }

  // ── 점검표 ──
  function verdictOf(row) {
    if (row.kind === '정상') return row.expect.includes(row.status) ? '정상 통과' : '정상 요청 막힘';
    if (row.status >= 200 && row.status < 300) return '공격 통과';
    return row.expect.includes(row.status) ? '막음' : '다른 응답(확인 필요)';
  }

  function attackStatus(attackId) {
    const own = rows.filter(row => row.attackId === attackId);
    if (!own.length || own.every(row => row.kind === '미실행')) return NOT_RUN;
    const run = own.filter(row => row.kind !== '미실행');
    if (run.some(row => row.verdict === '공격 통과' || row.verdict === '정상 요청 막힘')) return '문제 있음';
    if (run.some(row => row.verdict === '다른 응답(확인 필요)' || row.verdict === '불일치')) return '확인 필요';
    const forbiddenRun = run.some(row => row.kind === '금지');
    const somethingNotRun = own.some(row => row.kind === '미실행');
    if (!forbiddenRun) return somethingNotRun ? '금지 요청 미실행(정상만 실측)' : '실측 확인(정상 동작)';
    return somethingNotRun ? '일부 실측 막음(나머지 미실행)' : '실측 막음';
  }

  function renderTable() {
    const serverIds = new Set((lastSummary?.records ?? []).map(row => row.requestId));
    const tally = { run: 0, blocked: 0, confirmed: 0, partial: 0, notRun: 0, problem: 0, check: 0 };
    for (const item of CATALOG) {
      const st = attackStatus(item.attackId);
      if (st === NOT_RUN) tally.notRun += 1; else tally.run += 1;
      if (st === '실측 막음') tally.blocked += 1;
      if (st === '실측 확인(정상 동작)') tally.confirmed += 1;
      if (st.includes('미실행') && st !== NOT_RUN) tally.partial += 1;
      if (st === '문제 있음') tally.problem += 1;
      if (st === '확인 필요') tally.check += 1;
    }
    const head = el('tr', {}, ...['단계', '공격 ID', '상태', '구분', '요청', '기대', '실제 API 결과', '요청 ID', '확인 시각', '판정', '서버 기록'].map(h => el('th', {}, h)));
    const body = [];
    for (const item of CATALOG) {
      const st = attackStatus(item.attackId);
      const own = rows.filter(row => row.attackId === item.attackId);
      const list = own.length ? own : [{ kind: '미실행', label: item.attack, expectText: item.expected, note: NOT_RUN_REASON[item.attackId] ?? '아직 실행하지 않음' }];
      list.forEach((row, index) => {
        const inServer = row.requestId ? (serverIds.has(row.requestId) ? '일치' : (lastSummary ? '기록 없음' : '요약 전')) : '—';
        body.push(el('tr', {},
          el('td', {}, index ? '' : item.step), el('td', {}, index ? '' : item.attackId), el('td', {}, index ? '' : st),
          el('td', {}, row.kind), el('td', {}, row.label), el('td', {}, row.expectText ?? ''),
          el('td', {}, row.kind === '미실행' ? `${NOT_RUN}: ${row.note}` : row.actual),
          el('td', {}, short(row.requestId)), el('td', {}, row.at ? time(row.at) : '—'),
          el('td', {}, row.kind === '미실행' ? NOT_RUN : row.verdict), el('td', {}, inServer)));
      });
    }
    tableBox.replaceChildren(
      el('h3', {}, '1~12단계 점검표 (판정 카탈로그 41종)'),
      el('p', {}, `41종 중 요청을 보낸 시험 ${tally.run}종(실측 막음 ${tally.blocked}종 · 정상 동작 실측 확인 ${tally.confirmed}종 · 일부만 실행 ${tally.partial}종 · 문제 ${tally.problem}종 · 확인 필요 ${tally.check}종) · 미실행 ${tally.notRun}종. 미실행과 일부만 실행한 시험은 막은 수에 넣지 않습니다. 이 표는 이 브라우저에서 보낸 요청의 실측이며 심판 판정이 아닙니다.`),
      el('div', { class: 'ops-scroll' }, el('table', {}, el('thead', {}, head), el('tbody', {}, ...body))),
    );
  }

  async function runChecks() {
    if (running || !ctx.isApproved()) return;
    running = true;
    runButton.disabled = true;
    downloadButton.disabled = true;
    rows = [];
    const runId = crypto.randomUUID();
    const send = (path, options = {}) => ctx.probe(path, { ...options, runId });
    const add = (attackId, kind, label, expect, result, extra = '') => {
      const row = { attackId, kind, label, expect, expectText: expect.join('/'), status: result.status,
        actual: `HTTP ${result.status}${result.reason ? ` · ${result.reason}` : ''}${extra ? ` · ${extra}` : ''}`,
        requestId: result.requestId, at: result.at };
      row.verdict = verdictOf(row);
      rows.push(row);
      return result;
    };
    const addNotRun = (attackId, label, note) => rows.push({ attackId, kind: '미실행', label, expectText: '', note });
    const addScan = (attackId, label, found, at) => rows.push({ attackId, kind: '금지', label, expect: [0], expectText: '찾은 표식 0종',
      status: found.length, actual: found.length ? `찾음: ${found.join(', ')}` : '찾은 표식 0종', requestId: null, at,
      verdict: found.length ? '공격 통과' : '막음' });
    try {
      status.textContent = `점검 회차 ${short(runId)} 실행 중입니다. 시험용 가상 메모 한 건을 만들었다가 마지막에 지웁니다.`;
      const random = () => crypto.randomUUID();

      // 준비: 정상 목록·공지
      const list = add('anonymous_note_list', '정상', '본인 서명 요청 GET /api/notes', [200], await send('/api/notes'));
      const ownIds = Array.isArray(list.payload) ? list.payload.map(note => note.id) : [];
      const before = ownIds.length;
      const created = await send('/api/notes', { method: 'POST', body: { title: '작전실 점검용 가상 메모', body: '점검 뒤 지웁니다' } });
      add('restore_changed_note', '정상', '본인 시험 메모 추가 POST /api/notes', [201], created);
      const testId = created.payload?.id ?? null;
      const ownId = ownIds[0] ?? testId;
      const notices = await send('/api/notices');
      const noticeIds = Array.isArray(notices.payload) ? notices.payload.map(item => item.id) : [];

      // 1단계
      add('anonymous_note_read', '금지', '비로그인 GET /api/notes/:id(본인 메모 ID)', [401], await send(`/api/notes/${ownId}`, { auth: false, sign: false }));
      add('anonymous_note_list', '금지', '비로그인 GET /api/notes', [401], await send('/api/notes', { auth: false, sign: false }));

      // 2단계·5단계: 공개 정적 파일 검색
      addNotRun('repository_secret_scan', '제출 커밋 비밀값 검색', NOT_RUN_REASON.repository_secret_scan);
      const scanAt = new Date().toISOString();
      const pages = await Promise.all(['/', '/ops.js', '/manifest.webmanifest'].map(path => fetch(path, { cache: 'no-store' }).then(r => r.text()).catch(() => '')));
      const joined = pages.join('\n');
      const found = LEAK_PATTERNS.filter(([, pattern]) => joined.includes(pattern)).map(([name]) => name);
      addScan('built_bundle_secret_scan', '공개 화면 파일(/, /ops.js, manifest)에서 키·토큰 표식 검색', found.filter(name => name !== '시드 표식'), scanAt);
      const dataJson = await fetch('/data.json', { cache: 'no-store' }).then(r => r.status).catch(() => 0);
      rows.push({ attackId: 'static_seed_data_scan', kind: '금지', label: '비로그인 GET /data.json', expect: [404], expectText: '404',
        status: dataJson, actual: `HTTP ${dataJson}`, requestId: null, at: scanAt, verdict: dataJson === 404 ? '막음' : (dataJson === 200 ? '공격 통과' : '다른 응답(확인 필요)') });
      addScan('static_seed_data_scan', '공개 화면 파일에서 시드 표식 검색', found.filter(name => name === '시드 표식'), scanAt);
      addScan('origin_alias_bypass', '공개 화면 파일에서 서버 전용 키·시드 표식 검색', found.filter(name => name === '서버 전용 키' || name === '시드 표식'), scanAt);

      // 3단계
      add('anonymous_note_write', '금지', '비로그인 POST /api/notes', [401], await send('/api/notes', { method: 'POST', body: { title: '비로그인 추가 시도', body: '-' }, auth: false, sign: false }));
      const after = await send('/api/notes');
      add('anonymous_note_write', '정상', '본인 목록 다시 조회(비로그인 추가가 생기지 않았는지)', [200], after,
        `메모 수 ${Array.isArray(after.payload) ? after.payload.length : '?'}건(시험 메모 1건 포함, 이전 ${before}건)`);
      add('missing_login_token', '금지', '토큰 없이 GET /api/notices', [401], await send('/api/notices', { auth: false, sign: false }));
      add('forged_login_token', '금지', '서명 위조 토큰 GET /api/notes', [401], await send('/api/notes', { token: fakeToken({}), sign: false }));
      add('expired_login_token', '금지', '만료 시각이 지난 가짜 토큰 GET /api/notes(진짜 만료 토큰은 미보유)', [401],
        await send('/api/notes', { token: fakeToken({ iat: 1, exp: 2 }), sign: false }));
      add('token_wrong_audience', '금지', '다른 대상(aud) 가짜 토큰 GET /api/notes(진짜 다른 서비스 토큰은 미보유)', [401],
        await send('/api/notes', { token: fakeToken({ aud: 'other-service' }), sign: false }));

      // 4단계 (심판 소유 메모 ID는 없으므로 본인 것이 아닌 임의 ID로 교차 요청)
      add('r3_judge_owned_note', '정상', '본인 메모 GET /api/notes/:id', [200], await send(`/api/notes/${ownId}`));
      add('r3_judge_owned_note', '금지', '본인 것이 아닌 메모 ID GET(심판 메모 ID 미보유)', [404], await send(`/api/notes/${random()}`));
      if (testId) add('r3_judge_owned_note_write', '정상', '본인 시험 메모 PUT', [200], await send(`/api/notes/${testId}`, { method: 'PUT', body: { title: '작전실 점검용 가상 메모', body: '점검 뒤 지웁니다' } }));
      add('r3_judge_owned_note_write', '금지', '본인 것이 아닌 메모 ID PUT', [404], await send(`/api/notes/${random()}`, { method: 'PUT', body: { title: '교차 수정', body: '-' } }));
      add('foreign_note_delete', '금지', '본인 것이 아닌 메모 ID DELETE', [404], await send(`/api/notes/${random()}`, { method: 'DELETE' }));

      // 5단계: 원본 자료 API를 키 없이 직접 조회
      const meta = await fetch('/aleph.json', { cache: 'no-store' }).then(r => r.json()).catch(() => null);
      if (typeof meta?.originalApiUrl === 'string' && meta.originalApiUrl.startsWith('https://')) {
        const at = new Date().toISOString();
        const origin = await fetch(`${meta.originalApiUrl}?select=id&limit=1`, { cache: 'no-store' }).then(r => r.status).catch(() => 0);
        rows.push({ attackId: 'direct_origin_note_read', kind: '금지', label: '키 없이 원본 자료 API 직접 GET', expect: [401, 403], expectText: '401/403',
          status: origin, actual: origin ? `HTTP ${origin}` : '응답 없음(브라우저 차단)', requestId: null, at,
          verdict: origin === 200 ? '공격 통과' : (origin === 401 || origin === 403 ? '막음' : '다른 응답(확인 필요)') });
      } else addNotRun('direct_origin_note_read', '원본 자료 API 직접 조회', '배포 정보에 원본 API 주소가 없음');
      add('direct_origin_note_read', '정상', '서버 함수로 본인 목록 GET', [200], await send('/api/notes'));
      addNotRun('direct_origin_note_write', '원본 자료 API 직접 수정', NOT_RUN_REASON.direct_origin_note_write);

      // 6단계
      const stranger = await ctx.makeKey();
      add('unregistered_device', '정상', '승인 기기 서명 GET /api/notes', [200], await send('/api/notes'));
      add('unregistered_device', '금지', '등록 안 된 새 기기 키로 서명한 GET /api/notes', [403], await send('/api/notes', { key: stranger }));
      for (const id of ['missing_client_certificate', 'device_subject_mismatch', 'unregistered_virtual_device_rule']) addNotRun(id, CATALOG.find(c => c.attackId === id).attack, NOT_RUN_REASON[id]);

      // 7단계
      for (const id of ['anomalous_region_event', 'anomalous_hour_event', 'anomalous_network_action', 'missing_step_up']) addNotRun(id, CATALOG.find(c => c.attackId === id).attack, NOT_RUN_REASON[id]);

      // 8단계
      add('cross_zone_note_read', '정상', '본인 메모 구역 GET /api/notes/:id', [200], await send(`/api/notes/${ownId}`));
      add('cross_zone_note_read', '금지', '메모 ID로 공지 구역 GET /api/notices/:id', [404], await send(`/api/notices/${ownId}`));
      add('cross_zone_note_write', '금지', '메모 ID로 공지 구역 PUT /api/notices/:id', [403, 404], await send(`/api/notices/${ownId}`, { method: 'PUT', body: { title: '구역 밖 수정', body: '-' } }));
      const noticeList = await send('/api/notices');
      const leaked = Array.isArray(noticeList.payload) ? noticeList.payload.filter(item => ownIds.includes(item.id) || item.id === testId).length : 0;
      rows.push({ attackId: 'cross_zone_note_list', kind: '금지', label: '공지 목록에 메모가 섞여 나오는지 GET /api/notices', expect: [0], expectText: '메모 0건',
        status: leaked, actual: `HTTP ${noticeList.status} · 섞인 메모 ${leaked}건`, requestId: noticeList.requestId, at: noticeList.at,
        verdict: noticeList.status === 200 && leaked === 0 ? '막음' : (leaked ? '공격 통과' : '다른 응답(확인 필요)') });
      if (noticeIds[0]) add('student_edits_instructor_notice', '금지', '학생 계정으로 공지 PUT /api/notices/:id(강사 명단에 없을 때)', [403], await send(`/api/notices/${noticeIds[0]}`, { method: 'PUT', body: { title: '학생 수정 시도', body: '-' } }));
      else addNotRun('student_edits_instructor_notice', '학생 공지 수정', '공지가 없어 보낼 대상이 없음');

      // 9단계
      for (const id of ['doppelganger_detection', 'revoked_identity_reuse', 'stolen_session_after_revoke', 'revoked_lateral_route']) addNotRun(id, CATALOG.find(c => c.attackId === id).attack, NOT_RUN_REASON[id]);

      // 10·11·12단계: 시험 메모로 변조→복구, 삭제→복구, 서명 공격
      if (testId) {
        const original = { title: '작전실 점검용 가상 메모', body: '점검 뒤 지웁니다' };
        add('restore_changed_note', '정상', '시험 메모 변조 PUT(본인)', [200], await send(`/api/notes/${testId}`, { method: 'PUT', body: { title: '변조된 제목', body: '변조된 본문' } }));
        const r1 = await send(`/api/notes/${testId}/restore`, { method: 'POST' });
        add('restore_changed_note', '정상', '복구 POST /api/notes/:id/restore', [200], r1, r1.payload?.restored ?? '');
        const check1 = await send(`/api/notes/${testId}`);
        const same1 = check1.payload?.title === original.title && check1.payload?.body === original.body;
        add('restore_changed_note', '정상', '복구 뒤 GET: 처음 내용과 같은지(본문은 표시 안 함)', [200], check1, same1 ? '처음 내용과 같음' : '처음 내용과 다름');
        if (!same1) rows[rows.length - 1].verdict = '불일치';

        add('restore_deleted_note', '정상', '시험 메모 삭제 DELETE', [204], await send(`/api/notes/${testId}`, { method: 'DELETE' }));
        const r2 = await send(`/api/notes/${testId}/restore`, { method: 'POST' });
        add('restore_deleted_note', '정상', '삭제 뒤 복구 POST /api/notes/:id/restore', [200], r2, r2.payload?.restored ?? '');
        add('restore_deleted_note', '금지', '복구 뒤 비로그인 GET /api/notes/:id', [401], await send(`/api/notes/${testId}`, { auth: false, sign: false }));

        add('restore_defense_replay', '금지', '복구 직후 비로그인 목록 GET', [401], await send('/api/notes', { auth: false, sign: false }));
        add('restore_defense_replay', '금지', '복구 직후 위조 토큰 GET', [401], await send('/api/notes', { token: fakeToken({}), sign: false }));
        add('restore_defense_replay', '금지', '복구 직후 남의 메모 ID GET', [404], await send(`/api/notes/${random()}`));
        add('restore_defense_replay', '금지', '복구 직후 서명 없는 GET', [403], await send('/api/notes', { sign: false }));

        add('unsigned_client_request', '정상', '승인 기기 서명 GET /api/notes/:id', [200], await send(`/api/notes/${testId}`));
        add('unsigned_client_request', '금지', '로그인 토큰만 있고 서명 없는 GET /api/notes', [403], await send('/api/notes', { sign: false }));
        add('signed_path_tamper', '금지', '시험 메모 GET을 서명한 뒤 경로를 목록으로 바꿈', [403], await send('/api/notes', { signPath: `/api/notes/${testId}` }));
        const goodBody = { title: '서명한 제목', body: '서명한 본문' };
        add('signed_body_tamper', '금지', 'PUT 본문을 서명한 뒤 본문을 바꿈', [403],
          await send(`/api/notes/${testId}`, { method: 'PUT', body: { title: '바꾼 제목', body: '바꾼 본문' }, signBodyText: JSON.stringify(goodBody) }));
        const check2 = await send(`/api/notes/${testId}`);
        const same2 = check2.payload?.title === original.title && check2.payload?.body === original.body;
        add('signed_body_tamper', '정상', '본문 변경 시도 뒤 GET: 원본 불변인지', [200], check2, same2 ? '원본 불변' : '원본이 바뀜');
        if (!same2) rows[rows.length - 1].verdict = '불일치';

        add('combined_anonymous_owner_attack', '정상', '본인 메모 GET', [200], await send(`/api/notes/${testId}`));
        add('combined_anonymous_owner_attack', '금지', '이어서 비로그인 GET', [401], await send(`/api/notes/${testId}`, { auth: false, sign: false }));
        add('combined_anonymous_owner_attack', '금지', '이어서 남의 메모 ID GET', [404], await send(`/api/notes/${random()}`));
        add('combined_anonymous_owner_attack', '정상', '마지막으로 본인 메모 GET', [200], await send(`/api/notes/${testId}`));
        add('combined_device_revocation_attack', '금지', '미등록 기기 키 서명 GET', [403], await send(`/api/notes/${testId}`, { key: stranger }));
        addNotRun('combined_device_revocation_attack', '회수된 신원으로 재전송', NOT_RUN_REASON.revoked_identity_reuse);
        add('combined_device_revocation_attack', '정상', '승인 기기 정상 GET', [200], await send(`/api/notes/${testId}`));
        add('combined_restore_signature_attack', '정상', '복구 POST', [200], await send(`/api/notes/${testId}/restore`, { method: 'POST' }));
        add('combined_restore_signature_attack', '금지', '복구 뒤 서명 없는 PUT', [403], await send(`/api/notes/${testId}`, { method: 'PUT', body: { title: '서명 없는 변경', body: '-' }, sign: false }));
        add('combined_restore_signature_attack', '금지', '복구 뒤 구역 밖 GET /api/notices/:id(메모 ID)', [404], await send(`/api/notices/${testId}`));
        const check3 = await send(`/api/notes/${testId}`);
        const same3 = check3.payload?.title === original.title && check3.payload?.body === original.body;
        add('combined_restore_signature_attack', '정상', '복구 자료 유지 GET', [200], check3, same3 ? '복구 자료 유지' : '복구 자료가 바뀜');
        if (!same3) rows[rows.length - 1].verdict = '불일치';
        add('combined_restore_signature_attack', '정상', '정리: 시험 메모 DELETE', [204], await send(`/api/notes/${testId}`, { method: 'DELETE' }));
      } else {
        status.textContent = '시험 메모를 만들지 못해 10~12단계 요청은 미실행으로 둡니다.';
      }
      status.textContent = `점검 회차 ${short(runId)} 완료. 서버 기록과 대조하는 중입니다.`;
    } catch (error) {
      status.textContent = `점검 중 멈춤: ${error.message}. 여기까지 실제로 보낸 요청만 표에 남깁니다.`;
    } finally {
      running = false;
      runButton.disabled = false;
      downloadButton.disabled = rows.length === 0;
      await refresh();
      renderTable();
    }
  }

  function download() {
    const serverIds = new Set((lastSummary?.records ?? []).map(row => row.requestId));
    const data = {
      schema: 'aleph.ops.checks.v1', generatedAt: new Date().toISOString(),
      note: '이 브라우저에서 보낸 요청의 실측입니다. 심판 판정이 아니며 미실행은 막은 수에 넣지 않습니다. 메모 본문 없음.',
      attacks: CATALOG.map(item => ({ ...item, status: attackStatus(item.attackId),
        requests: rows.filter(row => row.attackId === item.attackId).map(row => ({ kind: row.kind, request: row.label,
          expected: row.expectText, actual: row.kind === '미실행' ? `${NOT_RUN}: ${row.note}` : row.actual,
          requestId: row.requestId ?? null, checkedAt: row.at ?? null, verdict: row.kind === '미실행' ? NOT_RUN : row.verdict,
          serverRecord: row.requestId ? serverIds.has(row.requestId) : null })) })),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const link = el('a', { href: URL.createObjectURL(blob), download: 'ops-checks.json' });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  refreshButton.addEventListener('click', refresh);
  runButton.addEventListener('click', runChecks);
  downloadButton.addEventListener('click', download);

  return {
    show() { root.hidden = false; refresh(); },
    reset() {
      root.hidden = true; rows = []; lastSummary = null;
      status.textContent = ''; cards.replaceChildren(); recordBox.replaceChildren(); tableBox.replaceChildren();
      downloadButton.disabled = true;
    },
  };
}
