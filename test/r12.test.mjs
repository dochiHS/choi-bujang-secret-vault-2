import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { actorHash, createCollectionHandler, createItemHandler, createOpsSummaryHandler, opsCounts } from '../api/_notes-lib.js';

// 12단계 로컬 연습: 가린 서버 기록과 작전실 요약이 서로 맞는지(가짜 토큰·메모리 자료, 실제 심판 판정 아님)
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const NOTE_A = '44444444-4444-4444-8444-444444444444';
const SECRET_TITLE = '절대 보이면 안 되는 제목';
const SECRET_BODY = '절대 보이면 안 되는 본문';

function world() {
  const log = [];
  const notes = new Map([[NOTE_A, { id: NOTE_A, owner_id: USER_A, title: SECRET_TITLE, body: SECRET_BODY }]]);
  const deps = {
    deviceGate: async () => ({ ok: true, via: 'approved_device_stub', deviceId: 'a'.repeat(16) }),
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B } })[h] ?? null,
    newId: randomUUID,
    now: () => '2026-10-14T00:00:00.000Z',
    requestLog: {
      record: async (entry) => { log.push(entry); },
      forActor: async (hash, n) => log.filter(e => e.actor_hash === hash).slice(-n).reverse(),
      anonymousForRuns: async (ids, n) => log.filter(e => !e.actor_hash && ids.includes(e.run_id)).slice(-n).reverse(),
    },
    devices: { listByOwner: async () => [{ device_id: 'a'.repeat(16), status: 'approved' }] },
    backups: { summary: async () => ({ count: 1, lastBackupAt: '2026-10-13T00:00:00.000Z' }),
      restoresBy: async () => [{ at: '2026-10-13T01:00:00.000Z', action: 'restore_note', previous_state: 'deleted', content_sha256: 'f'.repeat(64) }] },
    notes: {
      listByOwner: async (o) => [...notes.values()].filter(r => r.owner_id === o),
      getOwned: async (id, o) => (notes.get(id)?.owner_id === o ? { ...notes.get(id) } : null),
    },
  };
  return { deps, log };
}

async function call(handler, { method = 'GET', token, id, run } = {}) {
  const res = { statusCode: 0, headers: {}, payload: undefined,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, getHeader(k) { return this.headers[k.toLowerCase()]; },
    status(c) { this.statusCode = c; return this; }, json(v) { this.payload = v; return this; }, end() { return this; } };
  const headers = { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(run ? { 'x-aleph-check': run } : {}) };
  await handler({ method, headers, query: id ? { id } : {} }, res);
  return res;
}

test('stage 12: every API response has a request ID and a masked server record without note text', async () => {
  const w = world(); const d = () => w.deps;
  const list = createCollectionHandler(d), item = createItemHandler(d);
  const run = randomUUID();
  const ok = await call(item, { token: 'a.a.a', id: NOTE_A, run });
  const anon = await call(list, { run });
  const cross = await call(item, { token: 'b.b.b', id: NOTE_A });
  assert.equal(ok.statusCode, 200);
  assert.equal(anon.statusCode, 401);
  assert.equal(cross.statusCode, 404);
  for (const res of [ok, anon, cross]) assert.match(res.headers['x-request-id'], /^[0-9a-f-]{36}$/u);
  assert.deepEqual(w.log.map(e => e.request_id), [ok, anon, cross].map(r => r.headers['x-request-id']));
  assert.equal(w.log[0].actor_hash, actorHash(USER_A));
  assert.equal(w.log[1].actor_hash, null);
  assert.equal(w.log[1].run_id, run);
  const text = JSON.stringify(w.log);
  assert.ok(!text.includes(SECRET_TITLE) && !text.includes(SECRET_BODY) && !text.includes(USER_A) && !text.includes(NOTE_A));
});

test('stage 12: ops summary numbers come from the same masked records and never include note text', async () => {
  const w = world(); const d = () => w.deps;
  const list = createCollectionHandler(d), item = createItemHandler(d), ops = createOpsSummaryHandler(d);
  const run = randomUUID();
  await call(item, { token: 'a.a.a', id: NOTE_A, run });
  await call(list, { run });                                   // 본인 점검 회차의 비로그인 요청
  await call(list, { run: randomUUID() });                     // 다른 회차의 비로그인 요청 → 보이면 안 됨
  await call(item, { token: 'b.b.b', id: NOTE_A });            // B의 기록 → A 작전실에 보이면 안 됨
  const res = await call(ops, { token: 'a.a.a' });
  assert.equal(res.statusCode, 200);
  const s = res.payload;
  assert.equal(s.schema, 'aleph.ops.summary.v1');
  assert.deepEqual(s.counts, opsCounts(s.records));
  assert.equal(s.records.length, 2);
  assert.deepEqual(s.records.map(r => r.actor).sort(), ['anonymous', 'self']);
  assert.deepEqual(s.decider.ruleIds, ['device_registered', 'step_up_required', 'zone_access']);
  assert.equal(s.decider.rulesMatchVerified, true);
  assert.equal(s.detection.result.action, 'observe');
  assert.deepEqual(s.revocation.devices, { pending: 0, approved: 1, revoked: 0 });
  assert.equal(s.restore.backups, 1);
  assert.equal(s.restore.lastContentSha256.length, 12);
  const text = JSON.stringify(s);
  assert.ok(!text.includes(SECRET_TITLE) && !text.includes(SECRET_BODY) && !text.includes(USER_A) && !text.includes(NOTE_A));
  // 로그인 없이 작전실 요약은 401
  assert.equal((await call(ops, {})).statusCode, 401);
});
