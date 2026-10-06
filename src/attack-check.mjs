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

async function send(app, path, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(new URL(path, app), {
    method, headers, body, redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
  });
  const text = await response.text();
  return { status: response.status, ok: response.ok,
    type: response.headers.get('content-type') ?? '', text };
}

const b64url = (value) => Buffer.from(value).toString('base64url');

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

// 거절이 "자료 없이 401/403 + JSON 오류"인지 한 줄로 적습니다.
function rejection(result) {
  let json = null;
  try { json = JSON.parse(result.text); } catch { json = null; }
  const leaked = Array.isArray(json) ? json.length > 0
    : Array.isArray(json?.notes) && json.notes.length > 0;
  const refused = (result.status === 401 || result.status === 403) && !leaked;
  const jsonError = json && typeof json.error === 'string';
  return refused
    ? `HTTP ${result.status}로 거절, ${jsonError ? 'JSON 오류 문구 있음' : 'JSON 오류 문구 없음'}, 메모 0건`
    : `거절되지 않음 (HTTP ${result.status}${leaked ? ', 메모가 응답에 보임' : ''})`;
}

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 3) {
    throw new Error('3단계 이후 공격 점검입니다. aleph.config.json의 step을 확인해 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const app = appUrl(config);
  const results = [];

  // 1) 옛 공개 정적 파일 /data.json에 메모가 남아 있는지
  const staticFile = await send(app, '/data.json');
  const staticLeak = staticFile.ok && (staticFile.text.includes(SEED_PHRASE)
    || staticFile.text.includes(config.sampleMarker));
  results.push({ attackId: 'static_data_json_read', expected: '/data.json에 가상 메모가 없어야 함',
    observed: staticLeak ? `/data.json에서 가상 메모가 보임 (HTTP ${staticFile.status})`
      : `/data.json에서 가상 메모가 보이지 않음 (HTTP ${staticFile.status})` });

  // 2) 첫 화면 정적 파일에 메모 문장이 박혀 있는지
  const page = await send(app, '/');
  results.push({ attackId: 'static_page_seed_search', expected: '첫 화면 HTML에 가상 메모 문장이 없어야 함',
    observed: page.text.includes(SEED_PHRASE)
      ? `첫 화면 HTML에서 가상 메모 문장이 보임 (HTTP ${page.status})`
      : `첫 화면 HTML에서 가상 메모 문장이 보이지 않음 (HTTP ${page.status})` });

  // 3) 로그인 토큰 없이 메모 목록 조회
  results.push({ attackId: 'anonymous_api_notes_read',
    expected: '토큰 없는 목록 조회는 자료 없이 401/403 JSON 오류',
    observed: rejection(await send(app, '/api/notes')) });

  // 4) 로그인 토큰 없이 메모 추가
  results.push({ attackId: 'anonymous_api_notes_create',
    expected: '토큰 없는 메모 추가는 401/403으로 거절',
    observed: rejection(await send(app, '/api/notes', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: '점검', body: '점검' }),
    })) });

  // 5) 로그인 토큰 없이 한 건 조회 (임의 UUID)
  results.push({ attackId: 'anonymous_api_note_item_read',
    expected: '토큰 없는 한 건 조회는 401/403으로 거절',
    observed: rejection(await send(app, `/api/notes/${randomUUID()}`)) });

  // 6) 서명이 위조된 토큰으로 목록 조회
  results.push({ attackId: 'forged_token_api_notes_read',
    expected: '서명이 맞지 않는 토큰은 401/403으로 거절',
    observed: rejection(await send(app, '/api/notes', {
      headers: { Authorization: `Bearer ${forgedToken(config)}` },
    })) });

  // 7) 원본 자료 API(originalApiUrl)를 공개(anon) 키로 직접 불러 메모가 나오는지
  const anonKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (typeof config.originalApiUrl === 'string' && anonKey) {
    const original = new URL(config.originalApiUrl);
    const direct = await send(new URL(`${original.origin}/`), `${original.pathname}?select=id,title&limit=5`, {
      headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
    });
    let rows = null;
    try { rows = JSON.parse(direct.text); } catch { rows = null; }
    const leaked = Array.isArray(rows) && rows.length > 0;
    results.push({ attackId: 'anon_original_api_read',
      expected: '원본 자료 API를 공개(anon) 키로 직접 읽으면 거절되거나 0건',
      observed: leaked ? `거절되지 않음 (HTTP ${direct.status}, ${rows.length}건 보임)`
        : `메모 0건 (HTTP ${direct.status})` });
  } else {
    results.push({ attackId: 'anon_original_api_read',
      expected: '원본 자료 API를 공개(anon) 키로 직접 읽으면 거절되거나 0건',
      observed: '미실행: SUPABASE_PUBLISHABLE_KEY 환경변수를 주지 않아 보내지 않음' });
  }

  // 8) 공개 첫 화면에 Supabase 키·서버 키·시드 표식이 있는지
  const exposed = [/sb_publishable_/u, /sb_secret_/u, /eyJhbGci/u, new RegExp(config.sampleMarker, 'u')]
    .filter((pattern) => pattern.test(page.text)).length;
  results.push({ attackId: 'static_page_key_search',
    expected: '첫 화면에 Supabase 공개 키·서버 키·시드 표식이 없어야 함',
    observed: exposed ? `첫 화면에서 키 또는 표식 ${exposed}종이 보임 (HTTP ${page.status})`
      : `첫 화면에서 키·표식이 보이지 않음 (HTTP ${page.status})` });

  // 9) A/B 교차 접근(B가 A 메모 읽기·수정·삭제, 소유자 변경)은 두 계정의 실제 토큰이 필요해 여기서 보내지 않습니다.
  results.push({ attackId: 'cross_owner_note_access',
    expected: 'B가 A 메모를 읽기·수정·삭제하거나 소유자를 바꾸면 거절, 각자 자기 메모는 허용',
    observed: '미실행: 두 계정의 실제 로그인 토큰이 필요해 자동 점검에서 보내지 않음. 배포 화면과 test/r5.test.mjs로 확인' });
  return results;
}
