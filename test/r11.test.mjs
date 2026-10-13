import assert from 'node:assert/strict';
import { randomUUID, webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { canonicalRequest, createDeviceGate, deviceIdOf, sha256Hex } from '../api/_device-lib.js';
import {
  createCollectionHandler, createDeviceApproveHandler, createDeviceRegisterHandler,
  createDeviceStatusHandler, createItemHandler, createRestoreHandler,
} from '../api/_notes-lib.js';

// 11단계 로컬 연습: 메모리 자료·가짜 토큰·실제 WebCrypto 키로 기기 승인과 요청 서명을 확인합니다(실제 심판 판정 아님).
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const JUDGE = '55555555-5555-4555-8555-555555555555';
const NOTE_A = '44444444-4444-4444-8444-444444444444';
const NOTE_A2 = '66666666-6666-4666-8666-666666666666';
const PASSWORD = 'virtual-password-for-local-test';

function world() {
  const notes = new Map([[NOTE_A, { id: NOTE_A, owner_id: USER_A, title: 'A 메모', body: 'a' }],
    [NOTE_A2, { id: NOTE_A2, owner_id: USER_A, title: 'A 두 번째', body: 'a2' }]]);
  const rows = new Map();
  const devices = {
    get: async (id) => (rows.has(id) ? { ...rows.get(id) } : null),
    register: async ({ deviceId, ownerId, jwk }) => {
      if (rows.has(deviceId)) return rows.get(deviceId).owner_id === ownerId ? rows.get(deviceId) : 'conflict';
      rows.set(deviceId, { device_id: deviceId, owner_id: ownerId, public_jwk: jwk, status: 'pending' });
      return rows.get(deviceId);
    },
    approve: async ({ deviceId, ownerId }) => {
      const row = rows.get(deviceId);
      if (!row || row.owner_id !== ownerId || row.status === 'revoked') return null;
      row.status = 'approved';
      return { ...row };
    },
  };
  const deps = {
    verify: async (h) => ({ 'Bearer a.a.a': { kind: 'student', userId: USER_A },
      'Bearer b.b.b': { kind: 'student', userId: USER_B },
      'Bearer j.j.j': { kind: 'judge', userId: JUDGE, identity: 'a' } })[h] ?? null,
    devices,
    deviceGate: createDeviceGate({ devices }),
    confirmPassword: async (userId, password) => userId === USER_A && password === PASSWORD,
    newId: randomUUID,
    now: () => '2026-10-13T00:00:00.000Z',
    notes: {
      listByOwner: async (o) => [...notes.values()].filter(r => r.owner_id === o),
      getOwned: async (id, o) => { const r = notes.get(id); return r && r.owner_id === o ? { ...r } : null; },
      updateOwned: async (id, o, { title, body }) => { const r = notes.get(id); if (!r || r.owner_id !== o) return null;
        Object.assign(r, { title, body }); return { ...r }; },
      removeOwned: async () => false,
      ownerOf: async (id) => ({ exists: notes.has(id), ownerId: notes.get(id)?.owner_id ?? null }),
    },
    backups: { getOwned: async () => null, audit: async () => {} },
  };
  return { deps, notes, rows };
}

// 브라우저(public/index.html)와 같은 방식: 메모리에서만 쓰는 내보낼 수 없는 개인키
async function newDevice() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty, crv, x, y };
  return { pair, jwk, id: deviceIdOf(jwk) };
}

async function sign(device, { method, path, bodyText = '', nonce = randomUUID(), timestamp = String(Date.now()) }) {
  const message = canonicalRequest({ method, path, timestamp, nonce, bodySha256: sha256Hex(bodyText) });
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    device.pair.privateKey, Buffer.from(message, 'utf8'))).toString('base64url');
  return { 'x-aleph-device': device.id, 'x-aleph-timestamp': timestamp, 'x-aleph-nonce': nonce, 'x-aleph-signature': signature };
}

async function call(handler, { method = 'GET', token, body, id, headers = {} } = {}) {
  const res = { statusCode: 0, headers: {}, payload: undefined,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; }, json(v) { this.payload = v; return this; }, end() { return this; } };
  await handler({ method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body, query: id ? { id } : {} }, res);
  return res;
}

test('stage 11: device must be registered and approved by the server before protected data opens', async () => {
  const w = world(); const d = () => w.deps;
  const register = createDeviceRegisterHandler(d), approve = createDeviceApproveHandler(d);
  const status = createDeviceStatusHandler(d), list = createCollectionHandler(d);
  const dev = await newDevice();
  const regBody = { publicKey: dev.jwk };

  // 서명 없는 등록, 개인키가 섞인 공개키는 거절
  assert.equal((await call(register, { method: 'POST', token: 'a.a.a', body: regBody })).statusCode, 403);
  assert.equal((await call(register, { method: 'POST', token: 'a.a.a', body: { publicKey: { ...dev.jwk, d: 'x' } } })).statusCode, 400);
  const reg = await call(register, { method: 'POST', token: 'a.a.a', body: regBody,
    headers: await sign(dev, { method: 'POST', path: '/api/devices', bodyText: JSON.stringify(regBody) }) });
  assert.equal(reg.statusCode, 200);
  assert.deepEqual(reg.payload, { deviceId: dev.id, status: 'pending', registered: false });

  // 승인 전: 상태는 pending, 자료 목록은 403(자료 없음)
  const st = await call(status, { token: 'a.a.a', headers: await sign(dev, { method: 'GET', path: '/api/devices/status' }) });
  assert.equal(st.payload.registered, false);
  const before = await call(list, { token: 'a.a.a', headers: await sign(dev, { method: 'GET', path: '/api/notes' }) });
  assert.equal(before.statusCode, 403);
  assert.equal(before.payload.reason, 'device_not_approved');
  assert.equal(Array.isArray(before.payload), false);

  // 승인 버튼만(비밀번호 없음)·틀린 비밀번호·남의 계정 토큰으로는 승인되지 않음
  const empty = {};
  assert.equal((await call(approve, { method: 'POST', token: 'a.a.a', body: empty,
    headers: await sign(dev, { method: 'POST', path: '/api/devices/approve', bodyText: '' }) })).statusCode, 400);
  const wrong = { password: 'wrong' };
  assert.equal((await call(approve, { method: 'POST', token: 'a.a.a', body: wrong,
    headers: await sign(dev, { method: 'POST', path: '/api/devices/approve', bodyText: JSON.stringify(wrong) }) })).statusCode, 403);
  const right = { password: PASSWORD };
  assert.equal((await call(approve, { method: 'POST', token: 'b.b.b', body: right,
    headers: await sign(dev, { method: 'POST', path: '/api/devices/approve', bodyText: JSON.stringify(right) }) })).statusCode, 403);
  assert.equal(w.rows.get(dev.id).status, 'pending');

  // 서버가 비밀번호를 확인하고 기기 서명이 맞으면 승인 → 기존 자료실이 열림
  const ok = await call(approve, { method: 'POST', token: 'a.a.a', body: right,
    headers: await sign(dev, { method: 'POST', path: '/api/devices/approve', bodyText: JSON.stringify(right) }) });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.payload.registered, true);
  const after = await call(list, { token: 'a.a.a', headers: await sign(dev, { method: 'GET', path: '/api/notes' }) });
  assert.equal(after.statusCode, 200);
  assert.equal(after.payload.length, 2);
});

test('stage 11: unsigned, path-tampered, body-tampered and replayed requests are refused', async () => {
  const w = world(); const d = () => w.deps;
  const item = createItemHandler(d), list = createCollectionHandler(d), restore = createRestoreHandler(d);
  const dev = await newDevice();
  w.rows.set(dev.id, { device_id: dev.id, owner_id: USER_A, public_jwk: dev.jwk, status: 'approved' });

  // 1) 서명 없는 보호 요청
  const unsigned = await call(list, { token: 'a.a.a' });
  assert.equal(unsigned.statusCode, 403);
  assert.equal(unsigned.payload.reason, 'device_signature_required');

  // 2) NOTE_A 수정을 서명한 뒤 경로만 NOTE_A2로 바꿈
  const edit = { title: '고친 제목', body: '고친 본문' };
  const signedForA = await sign(dev, { method: 'PUT', path: `/api/notes/${NOTE_A}`, bodyText: JSON.stringify(edit) });
  const pathTamper = await call(item, { method: 'PUT', token: 'a.a.a', id: NOTE_A2, body: edit, headers: signedForA });
  assert.equal(pathTamper.statusCode, 403);
  assert.equal(pathTamper.payload.reason, 'device_signature_invalid');
  assert.equal(w.notes.get(NOTE_A2).title, 'A 두 번째');

  // 3) 서명 뒤 본문만 바꿈
  const bodyTamper = await call(item, { method: 'PUT', token: 'a.a.a', id: NOTE_A,
    body: { ...edit, body: '몰래 바꾼 본문' }, headers: await sign(dev, { method: 'PUT', path: `/api/notes/${NOTE_A}`, bodyText: JSON.stringify(edit) }) });
  assert.equal(bodyTamper.statusCode, 403);
  assert.equal(bodyTamper.payload.reason, 'device_signature_invalid');
  assert.equal(w.notes.get(NOTE_A).body, 'a');

  // 정상: 서명한 그대로 보내면 수정됨, 같은 서명을 다시 보내면 거절
  const good = await sign(dev, { method: 'PUT', path: `/api/notes/${NOTE_A}`, bodyText: JSON.stringify(edit) });
  assert.equal((await call(item, { method: 'PUT', token: 'a.a.a', id: NOTE_A, body: edit, headers: good })).statusCode, 200);
  const replay = await call(item, { method: 'PUT', token: 'a.a.a', id: NOTE_A, body: edit, headers: good });
  assert.equal(replay.payload.reason, 'device_signature_replayed');

  // 오래된 서명, 다른 사용자 토큰으로 A의 기기 서명 사용
  const old = await sign(dev, { method: 'GET', path: '/api/notes', timestamp: String(Date.now() - 5 * 60 * 1000) });
  assert.equal((await call(list, { token: 'a.a.a', headers: old })).payload.reason, 'device_signature_expired');
  assert.equal((await call(list, { token: 'b.b.b', headers: await sign(dev, { method: 'GET', path: '/api/notes' }) })).payload.reason, 'device_not_registered');

  // 회수된 기기는 서명이 맞아도 거절
  w.rows.get(dev.id).status = 'revoked';
  assert.equal((await call(list, { token: 'a.a.a', headers: await sign(dev, { method: 'GET', path: '/api/notes' }) })).payload.reason, 'device_revoked');

  // 운영 심판 토큰: 서명 없는 읽기·복구만 받고, 서명 없는 수정은 거절
  assert.notEqual((await call(item, { token: 'j.j.j', id: NOTE_A })).statusCode, 403);
  assert.equal((await call(item, { method: 'PUT', token: 'j.j.j', id: NOTE_A, body: edit })).statusCode, 403);
  assert.equal((await call(list, { method: 'POST', token: 'j.j.j', body: edit })).statusCode, 403);
  assert.notEqual((await call(restore, { method: 'POST', token: 'j.j.j', id: NOTE_A })).statusCode, 403);
});
