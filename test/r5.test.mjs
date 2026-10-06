import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { createCollectionHandler, createItemHandler, supabaseNotes } from '../api/_notes-lib.js';

const config = {
  step: 3,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app/',
  identityProvider: {
    issuer: 'https://example-project.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://example-project.supabase.co/auth/v1/.well-known/jwks.json',
  },
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('stage 3 checks: unauthenticated and forged requests are refused', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  try {
    globalThis.fetch = async (url, init) => {
      const path = new URL(String(url)).pathname;
      seen.push(`${init.method} ${path.replace(/[0-9a-f-]{36}$/u, ':id')}`);
      assert.equal(init.redirect, 'error');
      if (path === '/data.json') return new Response('Not Found', { status: 404 });
      if (path === '/') return new Response('<html>자료실</html>', { status: 200 });
      return new Response('{"error":"로그인이 필요합니다."}', { status: 401 });
    };
    const results = await runAttackChecks(config);
    assert.deepEqual(seen, ['GET /data.json', 'GET /', 'GET /api/notes', 'POST /api/notes',
      'GET /api/notes/:id', 'GET /api/notes']);
    assert.match(results[0].observed, /보이지 않음 \(HTTP 404\)/u);
    assert.match(results[1].observed, /보이지 않음/u);
    for (const item of results.slice(2, 6)) assert.match(item.observed, /HTTP 401로 거절, JSON 오류 문구 있음/u);
    assert.match(results[6].observed, /^미실행/u);
    assert.match(results[7].observed, /^미실행/u);
    for (const item of results) assert.doesNotMatch(item.observed, /eyJ|Bearer/u);

    globalThis.fetch = async () => new Response('[{"title":"a"}]', { status: 200 });
    const open = await runAttackChecks(config);
    assert.match(open[2].observed, /거절되지 않음 \(HTTP 200, 메모가 응답에 보임\)/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---- API: 가짜 토큰 검사기와 메모리 DB로 계약을 확인합니다 ----
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';

function fakeDeps() {
  const rows = new Map();
  let counter = 0;
  return {
    rows,
    verify: async (authorization) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B } })[authorization] ?? null,
    newId: () => `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`,
    notes: {
      async listByOwner(owner) {
        return [...rows.values()].filter(r => r.owner_id === owner)
          .map(({ id, title, body }) => ({ id, title, body }));
      },
      async insert({ id, ownerId, title, body }) {
        if (rows.has(id)) return 'duplicate';
        rows.set(id, { id, owner_id: ownerId, title, body });
        return 'created';
      },
      async getOwned(id, owner) {
        const r = rows.get(id);
        return r && r.owner_id === owner ? { id: r.id, title: r.title, body: r.body } : null;
      },
      async updateOwned(id, owner, { title, body }) {
        const r = rows.get(id); if (!r || r.owner_id !== owner) return null;
        Object.assign(r, { title, body }); return { id, title, body };
      },
      async removeOwned(id, owner) {
        const r = rows.get(id); if (!r || r.owner_id !== owner) return false;
        return rows.delete(id);
      },
    },
  };
}

async function call(handler, { method = 'GET', token, body, id } = {}) {
  const res = { statusCode: 0, headers: {}, payload: undefined,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.payload = value; return this; },
    end() { return this; } };
  const req = { method, headers: token ? { authorization: `Bearer ${token}` } : {},
    body, query: id ? { id } : {} };
  await handler(req, res);
  return res;
}

test('stage 3 API: login required, CRUD contract, owner_id from server', async () => {
  const deps = fakeDeps();
  const list = createCollectionHandler(() => deps);
  const item = createItemHandler(() => deps);

  // 토큰 없음·잘못된 토큰 → 자료 없이 401 JSON
  for (const res of [await call(list), await call(list, { method: 'POST', body: { title: 't', body: 'b' } }),
    await call(item, { id: USER_A }), await call(list, { token: 'x.y.z' })]) {
    assert.equal(res.statusCode, 401);
    assert.equal(typeof res.payload.error, 'string');
    assert.equal(res.headers['cache-control'], 'no-store');
  }
  assert.equal(deps.rows.size, 0);

  // POST: id 없으면 서버가 만들고, 브라우저가 보낸 userId·role·owner_id는 무시
  const created = await call(list, { method: 'POST', token: 'a.a.a',
    body: { title: ' 첫 메모 ', body: '본문', userId: USER_B, role: 'service_role', owner_id: USER_B } });
  assert.equal(created.statusCode, 201);
  assert.deepEqual(Object.keys(created.payload), ['id']);
  assert.equal(deps.rows.get(created.payload.id).owner_id, USER_A);

  // POST: id를 직접 주면 그 id로 저장, 같은 id는 409, UUID가 아니면 400
  const given = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  assert.deepEqual((await call(list, { method: 'POST', token: 'a.a.a', body: { id: given, title: 't', body: '' } })).payload, { id: given });
  assert.equal((await call(list, { method: 'POST', token: 'a.a.a', body: { id: given, title: 't', body: '' } })).statusCode, 409);
  assert.equal((await call(list, { method: 'POST', token: 'a.a.a', body: { id: '1', title: 't', body: '' } })).statusCode, 400);
  assert.equal((await call(list, { method: 'POST', token: 'a.a.a', body: { title: '', body: '' } })).statusCode, 400);

  // GET 목록: 로그인 사용자의 메모 배열
  const mine = await call(list, { token: 'a.a.a' });
  assert.equal(mine.statusCode, 200);
  assert.ok(Array.isArray(mine.payload));
  assert.equal(mine.payload.length, 2);
  assert.deepEqual((await call(list, { token: 'b.b.b' })).payload, []);

  // GET 한 건 / PUT / DELETE / 지운 뒤 404
  const one = await call(item, { token: 'a.a.a', id: given });
  assert.deepEqual(one.payload, { id: given, title: 't', body: '' });
  const put = await call(item, { method: 'PUT', token: 'a.a.a', id: given, body: { title: '고침', body: '새 본문' } });
  assert.deepEqual(put.payload, { id: given, title: '고침', body: '새 본문' });
  assert.equal((await call(item, { method: 'DELETE', token: 'a.a.a', id: given })).statusCode, 204);
  assert.equal((await call(item, { token: 'a.a.a', id: given })).statusCode, 404);
  assert.equal((await call(item, { method: 'DELETE', token: 'a.a.a', id: given })).statusCode, 404);
  assert.equal((await call(item, { token: 'a.a.a', id: 'not-a-uuid' })).statusCode, 404);
  assert.equal((await call(item, { method: 'PATCH', token: 'a.a.a', id: given })).statusCode, 405);

});

test('stage 4 API: owners only — B cannot read, change, or delete A notes', async () => {
  const deps = fakeDeps();
  const list = createCollectionHandler(() => deps);
  const item = createItemHandler(() => deps);
  const aNote = (await call(list, { method: 'POST', token: 'a.a.a', body: { title: 'A 메모', body: 'a' } })).payload.id;
  const bNote = (await call(list, { method: 'POST', token: 'b.b.b', body: { title: 'B 메모', body: 'b' } })).payload.id;

  // 목록은 각자 자기 것만
  assert.deepEqual((await call(list, { token: 'a.a.a' })).payload.map(n => n.id), [aNote]);
  assert.deepEqual((await call(list, { token: 'b.b.b' })).payload.map(n => n.id), [bNote]);

  // B → A 메모: 읽기·수정·삭제 모두 404, A 메모는 그대로
  assert.equal((await call(item, { token: 'b.b.b', id: aNote })).statusCode, 404);
  const hijack = await call(item, { method: 'PUT', token: 'b.b.b', id: aNote, body: { title: '빼앗음', body: 'x' } });
  assert.equal(hijack.statusCode, 404);
  assert.equal(typeof hijack.payload.error, 'string');
  assert.equal((await call(item, { method: 'DELETE', token: 'b.b.b', id: aNote })).statusCode, 404);
  assert.deepEqual(deps.rows.get(aNote), { id: aNote, owner_id: USER_A, title: 'A 메모', body: 'a' });

  // 소유자 변경 시도: 본인 메모라도 owner_id를 남으로 바꾸면 403, 행은 그대로
  for (const field of ['owner_id', 'ownerId', 'userId']) {
    const moved = await call(item, { method: 'PUT', token: 'a.a.a', id: aNote,
      body: { title: '넘김', body: 'x', [field]: USER_B } });
    assert.equal(moved.statusCode, 403);
  }
  assert.equal(deps.rows.get(aNote).owner_id, USER_A);
  assert.equal(deps.rows.get(aNote).title, 'A 메모');

  // 본인 ID를 같이 보내는 정상 수정은 허용
  const own = await call(item, { method: 'PUT', token: 'a.a.a', id: aNote, body: { title: '고침', body: 'b', owner_id: USER_A } });
  assert.deepEqual(own.payload, { id: aNote, title: '고침', body: 'b' });

  // 추가할 때 본문의 owner_id·userId는 무시하고 검증된 ID로 저장
  const forged = await call(list, { method: 'POST', token: 'b.b.b', body: { title: 't', body: '', owner_id: USER_A, userId: USER_A } });
  assert.equal(deps.rows.get(forged.payload.id).owner_id, USER_B);

  // 남의 메모 id로 POST를 해도 덮어쓰지 못함(409), 내용 그대로
  assert.equal((await call(list, { method: 'POST', token: 'b.b.b', body: { id: aNote, title: 'x', body: 'x' } })).statusCode, 409);
  assert.equal(deps.rows.get(aNote).owner_id, USER_A);

  // 각자 자기 메모 삭제는 가능
  assert.equal((await call(item, { method: 'DELETE', token: 'b.b.b', id: bNote })).statusCode, 204);
  assert.equal((await call(item, { method: 'DELETE', token: 'a.a.a', id: aNote })).statusCode, 204);
});

test('stage 3 API: server misconfiguration never returns notes', async () => {
  const list = createCollectionHandler(() => { throw new Error('server_env_missing'); });
  const res = await call(list, { token: 'a.a.a' });
  assert.equal(res.statusCode, 500);
  assert.equal(Array.isArray(res.payload), false);
});

test('stage 4 DB queries: every read/update/delete is filtered by owner_id', async () => {
  const calls = [];
  const builder = (op) => {
    const chain = { op, filters: [] };
    calls.push(chain);
    const api = {
      select: () => api, order: () => api, update: () => api, delete: () => api, insert: () => api,
      eq: (column, value) => { chain.filters.push([column, value]); return api; },
      maybeSingle: async () => ({ data: null, error: null }),
      then: (resolve) => resolve({ data: [], error: null }),
    };
    return api;
  };
  const db = { from: () => ({
    select: (...a) => builder('select').select(...a),
    update: (...a) => builder('update').update(...a),
    delete: (...a) => builder('delete').delete(...a),
    insert: async () => ({ error: null }),
  }) };
  const notes = supabaseNotes(db);
  await notes.listByOwner(USER_A);
  await notes.getOwned('n1', USER_A);
  await notes.updateOwned('n1', USER_A, { title: 't', body: 'b' });
  await notes.removeOwned('n1', USER_A);
  assert.equal(calls.length, 4);
  for (const c of calls) assert.ok(c.filters.some(([col, v]) => col === 'owner_id' && v === USER_A), c.op);
});
