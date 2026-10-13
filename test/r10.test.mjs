import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCollectionHandler, createItemHandler, createRestoreHandler, noteHash } from '../api/_notes-lib.js';

// 10단계 로컬 연습: 가짜 토큰·메모리 자료로 복구 경로를 확인합니다(실제 심판 판정 아님).
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const NOTE_B = '33333333-3333-4333-8333-333333333333';
const NOTE_A = '44444444-4444-4444-8444-444444444444';

function world() {
  const notes = new Map();
  const backups = new Map();
  const audit = [];
  let next = [NOTE_B, NOTE_A];
  const deps = {
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B } })[h] ?? null,
    newId: () => next.shift(),
    now: () => '2026-10-13T00:00:00.000Z',
    notes: {
      listByOwner: async (o) => [...notes.values()].filter(r => r.owner_id === o),
      insert: async ({ id, ownerId, title, body }) => { if (notes.has(id)) return 'duplicate';
        notes.set(id, { id, owner_id: ownerId, title, body }); return 'created'; },
      getOwned: async (id, o) => { const r = notes.get(id); return r && r.owner_id === o ? { ...r } : null; },
      updateOwned: async (id, o, { title, body }) => { const r = notes.get(id); if (!r || r.owner_id !== o) return null;
        Object.assign(r, { title, body }); return { ...r }; },
      removeOwned: async (id, o) => { const r = notes.get(id); if (!r || r.owner_id !== o) return false; return notes.delete(id); },
      ownerOf: async (id) => (notes.has(id) ? { exists: true, ownerId: notes.get(id).owner_id } : { exists: false, ownerId: null }),
      restoreOwned: async ({ id, ownerId, title, body, exists }) => {
        if (exists) { const r = notes.get(id); if (!r || r.owner_id !== ownerId) return null; Object.assign(r, { title, body }); return { ...r }; }
        notes.set(id, { id, owner_id: ownerId, title, body }); return { id, title, body }; },
    },
    backups: {
      saveVerified: async ({ id, ownerId, title, body }) => { if (backups.has(id)) return 'exists';
        backups.set(id, { note_id: id, owner_id: ownerId, title, body, content_sha256: noteHash(title, body) }); return 'saved'; },
      getOwned: async (id, o) => { const b = backups.get(id); return b && b.owner_id === o ? { ...b } : null; },
      audit: async (entry) => { audit.push(entry); },
    },
  };
  return { deps, notes, backups, audit };
}

async function call(handler, { method = 'GET', token, body, id } = {}) {
  const res = { statusCode: 0, headers: {}, payload: undefined,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; }, json(v) { this.payload = v; return this; }, end() { return this; } };
  await handler({ method, headers: token ? { authorization: `Bearer ${token}` } : {}, body, query: id ? { id } : {} }, res);
  return res;
}

test('stage 10 restore: tampered and deleted B notes come back from the verified copy only', async () => {
  const w = world(); const d = () => w.deps;
  const list = createCollectionHandler(d), item = createItemHandler(d), restore = createRestoreHandler(d);
  assert.equal((await call(list, { method: 'POST', token: 'b.b.b', body: { title: 'B 원본', body: '원래 내용' } })).statusCode, 201);
  assert.equal((await call(list, { method: 'POST', token: 'a.a.a', body: { title: 'A 원본', body: 'a' } })).statusCode, 201);
  const original = noteHash('B 원본', '원래 내용');
  // 변조 → 복구
  await call(item, { method: 'PUT', token: 'b.b.b', id: NOTE_B, body: { title: '변조', body: '나쁜 내용' } });
  const r1 = await call(restore, { method: 'POST', token: 'b.b.b', id: NOTE_B });
  assert.equal(r1.statusCode, 200);
  assert.equal(r1.payload.restored, 'reverted');
  assert.equal(r1.payload.contentSha256, original);
  assert.deepEqual((await call(item, { token: 'b.b.b', id: NOTE_B })).payload, { id: NOTE_B, title: 'B 원본', body: '원래 내용' });
  // 삭제 → 같은 번호·소유자로 다시 만들기
  await call(item, { method: 'DELETE', token: 'b.b.b', id: NOTE_B });
  const r2 = await call(restore, { method: 'POST', token: 'b.b.b', id: NOTE_B });
  assert.equal(r2.payload.restored, 'recreated');
  assert.equal(w.notes.get(NOTE_B).owner_id, USER_B);
  assert.equal(noteHash(w.notes.get(NOTE_B).title, w.notes.get(NOTE_B).body), original);
  // 다른 메모(A)와 감사 기록은 보존·추가만
  assert.deepEqual(w.notes.get(NOTE_A), { id: NOTE_A, owner_id: USER_A, title: 'A 원본', body: 'a' });
  assert.equal(w.audit.length, 2);
  // 복구 뒤 1~9단계 대표 금지 요청: B는 A 메모를 못 읽고, 토큰 없으면 401
  assert.equal((await call(item, { token: 'b.b.b', id: NOTE_A })).statusCode, 404);
  assert.equal((await call(restore, { method: 'POST', id: NOTE_B })).statusCode, 401);
  // B가 A 메모 복구 시도 → 사본 없음 404, 감사 기록 그대로
  assert.equal((await call(restore, { method: 'POST', token: 'b.b.b', id: NOTE_A })).statusCode, 404);
  assert.equal(w.audit.length, 2);
  // 사본 해시가 맞지 않으면 복구 중단
  w.backups.get(NOTE_B).body = '사본 변조';
  assert.equal((await call(restore, { method: 'POST', token: 'b.b.b', id: NOTE_B })).payload.reason, 'backup_unverified');
  assert.equal((await call(restore, { method: 'GET', token: 'b.b.b', id: NOTE_B })).statusCode, 405);
});
