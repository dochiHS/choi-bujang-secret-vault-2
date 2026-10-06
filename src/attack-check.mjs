// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
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

async function get(app, path) {
  const response = await fetch(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
  });
  const text = await response.text();
  return { status: response.status, ok: response.ok, text };
}

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 2) {
    throw new Error('2단계 공격 점검입니다. aleph.config.json의 step을 확인해 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const app = appUrl(config);
  const results = [];

  // 1) 옛 공개 정적 파일 /data.json에 메모가 남아 있는지
  const staticFile = await get(app, '/data.json');
  const staticLeak = staticFile.ok && (staticFile.text.includes(SEED_PHRASE)
    || staticFile.text.includes(config.sampleMarker));
  results.push({ attackId: 'static_data_json_read', expected: '/data.json에 가상 메모가 없어야 함',
    observed: staticLeak ? `/data.json에서 가상 메모가 보임 (HTTP ${staticFile.status})`
      : `/data.json에서 가상 메모가 보이지 않음 (HTTP ${staticFile.status})` });

  // 2) 첫 화면 정적 파일에 메모 문장이 박혀 있는지
  const page = await get(app, '/');
  results.push({ attackId: 'static_page_seed_search', expected: '첫 화면 HTML에 가상 메모 문장이 없어야 함',
    observed: page.text.includes(SEED_PHRASE)
      ? `첫 화면 HTML에서 가상 메모 문장이 보임 (HTTP ${page.status})`
      : `첫 화면 HTML에서 가상 메모 문장이 보이지 않음 (HTTP ${page.status})` });

  // 3) 남은 약점: 서버 함수를 로그인 없이 부를 수 있는지 (3단계에서 막을 예정)
  const api = await get(app, '/api/notes');
  let count = 0;
  try {
    const data = JSON.parse(api.text);
    count = Array.isArray(data?.notes) ? data.notes.length : 0;
  } catch {
    // 응답이 JSON이 아니면 0건으로 기록합니다.
  }
  results.push({ attackId: 'anonymous_api_notes_read',
    expected: '2단계에서는 아직 열려 있음(남은 약점), 3단계에서 거부되어야 함',
    observed: api.ok && count > 0
      ? `비로그인 요청으로 /api/notes에서 가상 메모 ${count}건을 읽음 (HTTP ${api.status})`
      : `비로그인 요청으로 /api/notes에서 메모를 읽지 못함 (HTTP ${api.status})` });
  return results;
}
