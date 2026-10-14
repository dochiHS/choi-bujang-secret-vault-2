// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { randomUUID } from 'node:crypto';

const SEED_PHRASE = '실습용 가상';

function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

// 12단계: 심판 격리 환경 규칙
// - 공개 HTTPS로 GET·HEAD만 보냅니다. 쓰기 요청이 필요한 점검은 보내지 않고 observed를 정확히 "not_run"으로 둡니다.
// - 실제로 보낸 요청에는 fetch 옵션 alephEvidence {caseId: attackId, requestKey: 'read'}를 붙여, 심판 실행기가 그 요청을
//   제출 점검 ID와 연결할 수 있게 합니다(HTTP 머리글·신원·권한 값이 아님). 점검 하나에 요청 하나만 보냅니다.
// - observed에는 실제 응답의 "HTTP <상태 코드>"만 적습니다. 설명·통과 문구는 넣지 않습니다.
async function send(app, path, attackId, { headers = {} } = {}) {
  const response = await fetch(new URL(path, app), {
    method: 'GET', headers, redirect: 'error', cache: 'no-store',
    signal: typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(10000) : undefined,
    alephEvidence: { caseId: attackId, requestKey: 'read' },
  });
  const text = await response.text();
  return { status: response.status, ok: response.ok, text };
}

// 12단계: 심판 격리 환경에는 Buffer 같은 Node 전용 전역이 없어서, 글자(ASCII JSON)를 직접 base64url로 바꿉니다.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
function b64url(value) {
  const bytes = [];
  for (const ch of String(value)) {
    let code = ch.codePointAt(0);
    if (code < 0x80) bytes.push(code);
    else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 63));
    else if (code < 0x10000) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
  }
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += B64[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += B64[n & 63];
  }
  return out;
}

// 서명이 맞지 않는 가짜 토큰(발급자는 실제 학생 Supabase로 흉내). 결과에는 토큰을 남기지 않습니다.
function forgedToken(config) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'forged' }));
  const payload = b64url(JSON.stringify({
    iss: config.identityProvider?.issuer, aud: config.identityProvider?.audience ?? 'authenticated',
    sub: randomUUID(), role: 'authenticated', iat: now, exp: now + 600,
  }));
  return `${header}.${payload}.${b64url(randomUUID() + randomUUID())}`;
}

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 3) {
    throw new Error('3단계 이후 공격 점검입니다. aleph.config.json의 step을 확인해 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const app = appUrl(config);
  const results = [];
  const run = async (attackId, expected, path, options) => {
    const result = await send(app, path, attackId, options);
    results.push({ attackId, expected, observed: `HTTP ${result.status}` });
    return result;
  };
  const notRun = (attackId, expected) => results.push({ attackId, expected, observed: 'not_run' });

  // 1~2단계: 공개 정적 파일
  await run('static_data_json_read', 'HTTP 404; /data.json에 가상 메모가 없음', '/data.json');
  await run('static_page_seed_search', 'HTTP 200; 첫 화면 HTML에 가상 메모 문장이 없음', '/');
  await run('static_page_key_search', 'HTTP 200; 첫 화면에 Supabase 공개 키·서버 키·시드 표식이 없음', '/');

  // 3~5단계: 로그인 없는 요청·위조 토큰
  await run('anonymous_api_notes_read', 'HTTP 401; 토큰 없는 목록 조회는 메모 없이 JSON 오류', '/api/notes');
  notRun('anonymous_api_notes_create', 'HTTP 401; 토큰 없는 메모 추가 거절(쓰기 요청이라 묶음 점검에서는 보내지 않음, 작전실 점검표에서 실측)');
  await run('anonymous_api_note_item_read', 'HTTP 401; 토큰 없는 한 건 조회 거절', `/api/notes/${randomUUID()}`);
  await run('forged_token_api_notes_read', 'HTTP 401; 서명이 맞지 않는 토큰은 거절', '/api/notes',
    { headers: { Authorization: `Bearer ${forgedToken(config)}` } });
  await run('anonymous_notices_read', 'HTTP 401; 토큰 없는 공지 목록 조회 거절', '/api/notices');
  notRun('anon_original_api_read', '원본 자료 API를 공개 키로 직접 읽으면 거절 또는 0건(공개 키를 묶음에 넣지 않아 보내지 않음)');
  notRun('cross_owner_note_access', 'B의 A 메모 읽기·수정·삭제 거절(두 계정의 실제 토큰이 필요해 보내지 않음, test/r5와 작전실 점검표)');
  if (config.step >= 10) notRun('anonymous_restore', 'HTTP 401; 토큰 없는 복구 요청 거절(POST라 보내지 않음)');

  // 11단계: 설치형 앱 설정과 기기 상태
  if (config.step >= 11) {
    await run('pwa_manifest_read', 'HTTP 200; 앱 이름·standalone manifest(설치 표시는 기기 확인이 아님)', '/manifest.webmanifest');
    await run('anonymous_device_status', 'HTTP 401; 로그인·기기 서명 없는 기기 상태 조회 거절', '/api/devices/status');
    notRun('device_approve_without_reauth', 'HTTP 403; 비밀번호 재확인·기기 서명 없는 승인 거절(POST라 보내지 않음, test/r11)');
  }
  // 12단계: 작전실 요약은 로그인한 본인 기록만
  if (config.step >= 12) {
    await run('anonymous_ops_summary', 'HTTP 401; 로그인 없는 작전실 요약 조회 거절', '/api/ops/summary');
  }
  return results;
}
