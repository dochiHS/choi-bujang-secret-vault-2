import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCollectionHandler, createItemHandler, createNoticeCollectionHandler,
  createNoticeItemHandler, resourceId, supabaseNotes } from '../api/_notes-lib.js';

// 8단계 로컬 연습: 가짜 토큰·메모리 자료로 구역별 자원 ID를 확인합니다(실제 심판 판정 아님).
const USER_A = '11111111-1111-4111-8111-111111111111';
const NOTE = '22222222-2222-4222-8222-222222222222';
const NOTICE = '33333333-3333-4333-8333-333333333333';
const USER_B = '55555555-5555-4555-8555-555555555555';
const TEACHER = '66666666-6666-4666-8666-666666666666';

function deps() {
  const notes = new Map([[NOTE, { id: NOTE, owner_id: USER_A, title: 'A 메모', body: 'a' }]]);
  const notices = new Map([[NOTICE, { id: NOTICE, title: '공지', body: 'n', updatedAt: '2026-10-13T00:00:00Z' }]]);
  return {
    deviceGate: async () => ({ ok: true, via: "approved_device_stub", deviceId: null }), // 11단계: 앞 단계 시험은 승인된 기기에서 보낸 요청으로 가정
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B },
      'Bearer t.t.t': { kind: 'student', userId: TEACHER } })[h] ?? null,
    newId: () => '44444444-4444-4444-8444-444444444444',
    notes: {
      listByOwner: async (o) => [...notes.values()].filter(r => r.owner_id === o).map(({ id, title, body }) => ({ id, title, body })),
      getOwned: async (id, o) => { const r = notes.get(id); return r && r.owner_id === o ? { id, title: r.title, body: r.body } : null; },
    },
    notices: { list: async () => [...notices.values()], get: async (id) => notices.get(id) ?? null,
      isInstructor: async (userId) => userId === TEACHER,
      update: async (id, { title, body }) => { const n = notices.get(id); if (!n) return null;
        Object.assign(n, { title, body }); return n; } },
  };
}

async function call(handler, { method = 'GET', token = 'a.a.a', id, body } = {}) {
  const res = { statusCode: 0, headers: {}, payload: undefined,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; }, json(v) { this.payload = v; return this; }, end() { return this; } };
  await handler({ method, headers: token ? { authorization: `Bearer ${token}` } : {}, body, query: id ? { id } : {} }, res);
  return res;
}

test('stage 8 resource ids: notes and notices are different zones', async () => {
  const d = () => deps();
  assert.equal(resourceId('note', NOTE), `note:${NOTE}`);
  assert.equal(resourceId('notice', NOTICE), `notice:${NOTICE}`);
  assert.throws(() => resourceId('admin', NOTE));
  assert.equal((await call(createCollectionHandler(d))).headers['x-resource-id'], 'note:list');
  assert.equal((await call(createItemHandler(d), { id: NOTE })).headers['x-resource-id'], `note:${NOTE}`);
  assert.equal((await call(createNoticeCollectionHandler(d))).headers['x-resource-id'], 'notice:list');
  const one = await call(createNoticeItemHandler(d), { id: NOTICE });
  assert.equal(one.statusCode, 200);
  assert.equal(one.headers['x-resource-id'], `notice:${NOTICE}`);
  // 같은 UUID라도 메모 경로로는 공지가 나오지 않습니다(다른 구역).
  assert.equal((await call(createItemHandler(d), { id: NOTICE })).statusCode, 404);
  // 로그인 없이는 공지도 401, 공지 삭제는 받지 않음(405).
  assert.equal((await call(createNoticeCollectionHandler(d), { token: null })).statusCode, 401);
  assert.equal((await call(createNoticeItemHandler(d), { method: 'DELETE', id: NOTICE })).statusCode, 405);
});

test('stage 8 API re-check: owner and instructor come from the server, not the body', async () => {
  const d = () => deps();
  // B는 A 메모를 메뉴 없이 직접 불러도 404
  const bRead = await call(createItemHandler(d), { token: 'b.b.b', id: NOTE });
  assert.equal(bRead.statusCode, 404);
  assert.equal(bRead.payload.reason, 'not_owner_or_missing');
  assert.equal((await call(createItemHandler(d), { id: NOTE })).statusCode, 200);
  // 학생 A가 본문에 role: instructor를 넣어도 공지 수정 403
  const student = await call(createNoticeItemHandler(d), { method: 'PUT', id: NOTICE,
    body: { title: '고침', body: 'x', role: 'instructor', isInstructor: true } });
  assert.equal(student.statusCode, 403);
  assert.equal(student.payload.reason, 'not_instructor');
  // DB 강사 명단에 있는 사용자만 수정 가능
  const teacher = await call(createNoticeItemHandler(d), { method: 'PUT', token: 't.t.t', id: NOTICE,
    body: { title: '새 공지', body: 'y' } });
  assert.equal(teacher.statusCode, 200);
  assert.equal(teacher.payload.title, '새 공지');
});

test('stage 8 DB adapter drops rows whose stored owner differs', async () => {
  const rows = [{ id: NOTE, title: 'A', body: 'a', owner_id: USER_A },
    { id: NOTICE, title: 'X', body: 'x', owner_id: '99999999-9999-4999-8999-999999999999' }];
  const api = { select: () => api, eq: () => api, order: () => api,
    maybeSingle: async () => ({ data: rows[1], error: null }),
    then: (resolve) => resolve({ data: rows, error: null }) };
  const notes = supabaseNotes({ from: () => api });
  assert.deepEqual(await notes.listByOwner(USER_A), [{ id: NOTE, title: 'A', body: 'a' }]);
  assert.equal(await notes.getOwned(NOTICE, USER_A), null);
});

test('stage 8 handler re-check: a DB that hands back another owner\'s row still leaks nothing', async () => {
  const leaky = () => ({
    deviceGate: async () => ({ ok: true, via: "approved_device_stub", deviceId: null }), // 11단계: 앞 단계 시험은 승인된 기기에서 보낸 요청으로 가정
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B } })[h] ?? null,
    newId: () => NOTE,
    // 일부러 소유자 조건을 무시하고 A의 행을 그대로 돌려주는 DB
    notes: {
      listByOwner: async () => [{ id: NOTE, owner_id: USER_A, title: 'A 메모', body: 'a' }],
      getOwned: async () => ({ id: NOTE, owner_id: USER_A, title: 'A 메모', body: 'a' }),
      updateOwned: async () => ({ id: NOTE, owner_id: USER_A, title: 'x', body: 'x' }),
      removeOwned: async () => false,
    },
    notices: { list: async () => [], get: async () => null, isInstructor: async () => false, update: async () => null },
  });
  const bGet = await call(createItemHandler(leaky), { token: 'b.b.b', id: NOTE });
  assert.equal(bGet.statusCode, 404);
  assert.equal(bGet.payload.reason, 'not_owner_or_missing');
  assert.deepEqual((await call(createCollectionHandler(leaky), { token: 'b.b.b' })).payload, []);
  assert.equal((await call(createItemHandler(leaky), { method: 'PUT', token: 'b.b.b', id: NOTE,
    body: { title: 't', body: 'b' } })).statusCode, 404);
  // A 본인은 그대로 읽히고, 응답에 소유자 값은 없습니다.
  const aGet = await call(createItemHandler(leaky), { id: NOTE });
  assert.equal(aGet.statusCode, 200);
  assert.deepEqual(aGet.payload, { id: NOTE, title: 'A 메모', body: 'a' });
});

test('stage 8 zones in the API: a memo never comes out of the notice route, and vice versa', async () => {
  const mixed = () => ({
    deviceGate: async () => ({ ok: true, via: "approved_device_stub", deviceId: null }), // 11단계: 앞 단계 시험은 승인된 기기에서 보낸 요청으로 가정
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B } })[h] ?? null,
    newId: () => NOTE,
    notes: {
      listByOwner: async () => [{ id: NOTICE, kind: 'notice', title: '공지', body: 'n' }],
      // 메모 경로로 공지 행이나 다른 ID의 행을 돌려주는 DB
      getOwned: async (id) => (id === NOTICE ? { id: NOTICE, kind: 'notice', title: '공지', body: 'n' }
        : { id: '77777777-7777-4777-8777-777777777777', title: '다른 메모', body: 'x' }),
    },
    notices: {
      // 공지 경로로 A의 메모 행을 돌려주는 DB
      list: async () => [{ id: NOTE, owner_id: USER_A, title: 'A 메모', body: 'a' },
        { id: NOTICE, title: '공지', body: 'n', updatedAt: 't' }],
      get: async () => ({ id: NOTE, owner_id: USER_A, title: 'A 메모', body: 'a' }),
    },
  });
  // B가 공지 경로로 A의 메모 번호를 조회해도 404
  assert.equal((await call(createNoticeItemHandler(mixed), { token: 'b.b.b', id: NOTE })).statusCode, 404);
  // 공지 목록에 개인 메모가 섞여 오면 빼고 공지만
  assert.deepEqual((await call(createNoticeCollectionHandler(mixed), { token: 'b.b.b' })).payload.map(n => n.id), [NOTICE]);
  // 메모 경로로 공지 행이 오면 404, 요청과 다른 ID의 행이 오면 404
  assert.equal((await call(createItemHandler(mixed), { id: NOTICE })).statusCode, 404);
  assert.equal((await call(createItemHandler(mixed), { id: NOTE })).statusCode, 404);
  assert.deepEqual((await call(createCollectionHandler(mixed))).payload, []);
});
