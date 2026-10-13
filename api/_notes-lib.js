import { readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { defaultAuthClient } from './_auth-lib.js';
import { createDeviceGate, deviceIdOf, publicJwk, supabaseDevices } from './_device-lib.js';

// 공통: 로그인 토큰 검사 + 가상 메모 추가·읽기·수정·삭제.
// 파일 이름이 _로 시작하므로 Vercel은 이 파일을 공개 경로로 만들지 않습니다.
// 서버 전용 키는 Vercel 환경변수에서만 읽고, 응답·로그에 넣지 않습니다.
// 4단계: 모든 DB 질의에 owner_id = (서버가 검증한 사용자 ID) 조건을 함께 겁니다.
// 서버 전용 키는 RLS를 건너뛰므로, 이 조건이 빠진 질의를 새로 만들지 마세요.
// 8단계: 메모(note)와 강사 공지(notice)는 서로 다른 구역입니다. 요청마다 서버가 자원 ID를 정해
// 응답 머리글 X-Resource-Id로 알려 줍니다(예: note:<uuid>, notice:<uuid>, note:list, notice:list).
// 자원 ID는 서버가 경로에서 만들며, 브라우저가 보낸 값으로 정하지 않습니다.
// 8단계 제작 3: DB에서 꺼낸 행의 owner_id를 검증된 사용자 ID와 한 번 더 대조하고,
// 공지 수정은 DB의 강사 명단(vault_instructors)에 검증된 사용자 ID가 있을 때만 허용합니다.
// 화면 메뉴·요청 본문의 role·isInstructor 같은 값은 읽지 않습니다. 거부 응답에는 짧은 사유(reason)를 남깁니다.

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 200;
const BODY_MAX = 5000;
const COLUMNS = 'id, title, body';
const NOTICE_COLUMNS = 'id, title, body, updated_at';

// 8단계 자원 ID: 구역(note/notice) + 자료 ID(UUID) 또는 목록(list)
export const RESOURCE_KINDS = Object.freeze(['note', 'notice']);
export function resourceId(kind, id = 'list') {
  if (!RESOURCE_KINDS.includes(kind)) throw new Error('unknown_resource_kind');
  if (id !== 'list' && !UUID.test(id)) throw new Error('bad_resource_id');
  return `${kind}:${id.toLowerCase()}`;
}

let cached;

function loadConfig() {
  return JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
}

// 실제 배포에서 쓰는 도구 묶음. 처음 요청 때 한 번만 만듭니다.
export function defaultDeps() {
  if (cached) return cached;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('server_env_missing');
  const verify = createLoginVerifier({ config: loadConfig(), supabaseSecretKey: key });
  const db = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const devices = supabaseDevices(db);
  cached = { verify, notes: supabaseNotes(db), notices: supabaseNotices(db),
    backups: supabaseBackups(db), newId: randomUUID, now: () => new Date().toISOString(),
    // 11단계: 기기 명단·요청 서명 확인·비밀번호 재확인(승인용)
    devices, deviceGate: createDeviceGate({ devices }), confirmPassword: supabasePasswordCheck(db) };
  return cached;
}

// DB 접근을 한곳에 모읍니다. owner_id는 항상 서버가 확인한 사용자 ID만 씁니다.
export function supabaseNotes(db) {
  const table = () => db.from('vault_notes');
  return {
    async listByOwner(ownerId) {
      const { data, error } = await table().select(`${COLUMNS}, owner_id`)
        .eq('owner_id', ownerId).order('created_at', { ascending: true });
      if (error) throw error;
      // 제작 3: 질의 조건과 별개로 꺼낸 행의 소유자를 다시 대조합니다.
      return (data ?? []).filter(row => row.owner_id === ownerId)
        .map(({ id, title, body }) => ({ id, title, body }));
    },
    async insert({ id, ownerId, title, body }) {
      const { error } = await table().insert({ id, owner_id: ownerId, title, body });
      if (error?.code === '23505') return 'duplicate';
      if (error) throw error;
      return 'created';
    },
    // 본인 메모만 찾습니다. 남의 메모나 없는 메모는 똑같이 null(→ 404)이라 존재 여부도 새지 않습니다.
    async getOwned(id, ownerId) {
      const { data, error } = await table().select(`${COLUMNS}, owner_id`)
        .eq('id', id).eq('owner_id', ownerId).maybeSingle();
      if (error) throw error;
      if (!data || data.owner_id !== ownerId) return null;   // 제작 3: 소유자 재대조
      return { id: data.id, title: data.title, body: data.body };
    },
    // 기존 행이 본인 것일 때만 고치고, owner_id는 바꾸지 않으므로 새 행도 본인 소유로 남습니다.
    async updateOwned(id, ownerId, { title, body }) {
      const { data, error } = await table().update({ title, body })
        .eq('id', id).eq('owner_id', ownerId).select(`${COLUMNS}, owner_id`).maybeSingle();
      if (error) throw error;
      if (!data) return null;
      if (data.owner_id !== ownerId) throw new Error('owner_changed');
      return { id: data.id, title: data.title, body: data.body };
    },
    // 10단계 복구용: 이 번호의 메모가 있는지와 그 소유자만 확인합니다(내용은 꺼내지 않음).
    async ownerOf(id) {
      const { data, error } = await table().select('id, owner_id').eq('id', id).maybeSingle();
      if (error) throw error;
      return data ? { exists: true, ownerId: data.owner_id } : { exists: false, ownerId: null };
    },
    // 10단계 복구용: 본인 메모면 사본 내용으로 되돌리고, 지워졌으면 같은 번호·소유자로 다시 만듭니다.
    async restoreOwned({ id, ownerId, title, body, exists }) {
      if (exists) {
        const { data, error } = await table().update({ title, body })
          .eq('id', id).eq('owner_id', ownerId).select(`${COLUMNS}, owner_id`).maybeSingle();
        if (error) throw error;
        return data && data.owner_id === ownerId ? { id: data.id, title: data.title, body: data.body } : null;
      }
      const { error } = await table().insert({ id, owner_id: ownerId, title, body });
      if (error) throw error;
      return { id, title, body };
    },
    async removeOwned(id, ownerId) {
      const { data, error } = await table().delete()
        .eq('id', id).eq('owner_id', ownerId).select('id');
      if (error) throw error;
      return Array.isArray(data) && data.length > 0;
    },
  };
}

// 10단계: 메모 내용 지문(SHA-256). "제목 바이트 수:제목본문"을 UTF-8로 계산합니다(DB의 SQL과 같은 방식).
export function noteHash(title, body) {
  const t = String(title);
  return createHash('sha256').update(`${Buffer.byteLength(t, 'utf8')}:${t}${String(body)}`, 'utf8').digest('hex');
}

// 10단계: 침해 전에 검증한 메모 사본(vault_note_backups)과 감사 기록(vault_audit_log).
// 사본은 메모를 처음 만들 때 한 번 저장하며, 이후 수정(PUT)으로는 바뀌지 않습니다.
// 감사 기록은 추가만 하고 고치거나 지우지 않습니다.
export function supabaseBackups(db) {
  const backups = () => db.from('vault_note_backups');
  return {
    async saveVerified({ id, ownerId, title, body }) {
      const { error } = await backups().insert({ note_id: id, owner_id: ownerId, title, body,
        content_sha256: noteHash(title, body) });
      if (error?.code === '23505') return 'exists';
      if (error) throw error;
      return 'saved';
    },
    async getOwned(id, ownerId) {
      const { data, error } = await backups().select('note_id, owner_id, title, body, content_sha256')
        .eq('note_id', id).eq('owner_id', ownerId).maybeSingle();
      if (error) throw error;
      return data && data.owner_id === ownerId ? data : null;
    },
    async audit(entry) {
      const { error } = await db.from('vault_audit_log').insert(entry);
      if (error) throw error;
    },
  };
}

// 8단계: 강사 공지 표(vault_notices). 메모 표와 따로 있어 메모 질의가 공지를 건드리지 않습니다.
export function supabaseNotices(db) {
  const table = () => db.from('vault_notices');
  const shape = row => ({ id: row.id, title: row.title, body: row.body, updatedAt: row.updated_at });
  return {
    async list() {
      const { data, error } = await table().select(NOTICE_COLUMNS).order('created_at', { ascending: true });
      if (error) throw error;
      return (data ?? []).map(shape);
    },
    async get(id) {
      const { data, error } = await table().select(NOTICE_COLUMNS).eq('id', id).maybeSingle();
      if (error) throw error;
      return data ? shape(data) : null;
    },
    // 제작 3: 저장된 강사 명단에 검증된 사용자 ID가 있는지(브라우저가 보낸 role은 보지 않음)
    async isInstructor(userId) {
      const { data, error } = await db.from('vault_instructors').select('user_id')
        .eq('user_id', userId).maybeSingle();
      if (error) throw error;
      return Boolean(data && data.user_id === userId);
    },
    async update(id, { title, body }) {
      const { data, error } = await table().update({ title, body, updated_at: new Date().toISOString() })
        .eq('id', id).select(NOTICE_COLUMNS).maybeSingle();
      if (error) throw error;
      return data ? shape(data) : null;
    },
  };
}

function send(res, status, payload) {
  res.setHeader('Cache-Control', 'no-store');
  if (payload === undefined) return res.status(status).end();
  return res.status(status).json(payload);
}

function readBody(req) {
  let value = req.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// 브라우저가 보낸 userId·role·owner_id 같은 값은 읽지 않고 title·body(·id)만 꺼냅니다.
function noteInput(raw) {
  if (!raw) return { error: 'JSON 본문이 필요합니다.' };
  const { title, body } = raw;
  if (typeof title !== 'string' || !title.trim()) return { error: '제목(title)이 필요합니다.' };
  if (typeof body !== 'string') return { error: '본문(body)은 글자여야 합니다.' };
  if (title.trim().length > TITLE_MAX) return { error: `제목은 ${TITLE_MAX}자 이하입니다.` };
  if (body.length > BODY_MAX) return { error: `본문은 ${BODY_MAX}자 이하입니다.` };
  return { title: title.trim(), body };
}

// 수정 본문에 다른 사람을 가리키는 소유자 값이 있으면 소유자 변경 시도로 보고 거절합니다.
// (저장할 때는 어차피 이 값을 쓰지 않습니다. 본인 ID와 같으면 그냥 무시합니다.)
const OWNER_FIELDS = ['owner_id', 'ownerId', 'owner', 'user_id', 'userId'];
function changesOwner(raw, userId) {
  if (!raw) return false;
  return OWNER_FIELDS.some((key) => key in raw
    && String(raw[key]).toLowerCase() !== userId.toLowerCase());
}

// 8단계 제작 3(처리기 단계 재대조): DB 도구가 어떤 행을 돌려주든, 처리기가 응답 직전에
// 행에 저장된 소유자와 검증된 사용자 ID를 한 번 더 비교합니다. 소유자 값이 다른 행은 없는 메모처럼 다룹니다.
// 응답에는 id·title·body만 내보냅니다(소유자 값은 내보내지 않음).
const STORED_OWNER_FIELDS = ['owner_id', 'ownerId', 'owner', 'user_id', 'userId'];
function storedOwner(row) {
  for (const key of STORED_OWNER_FIELDS) {
    if (row && Object.hasOwn(row, key) && row[key] !== undefined && row[key] !== null) return String(row[key]);
  }
  return null;
}
// 행이 어느 구역 자료인지 표시한 값(kind·zone·type·resource·resourceId)이 있으면 그 구역과 맞아야 합니다.
const ZONE_MARK_FIELDS = ['kind', 'zone', 'type', 'resource', 'resourceType', 'resourceId'];
function zoneOf(row) {
  for (const key of ZONE_MARK_FIELDS) {
    if (row && typeof row[key] === 'string' && row[key]) {
      const value = row[key].toLowerCase();
      if (/^notices?(:|$)/u.test(value)) return 'notice';
      if (/^notes?(:|$)|^memos?(:|$)/u.test(value)) return 'note';
      return 'other';
    }
  }
  return null;
}
// 메모 구역의 내 행인지: 다른 구역 표시가 없고, 저장된 소유자가 검증된 사용자와 같고,
// (요청한 자료 ID가 있으면) DB가 돌려준 행의 ID도 요청한 ID와 같아야 합니다.
function ownRow(row, userId, requestedId) {
  if (!row || typeof row !== 'object') return false;
  const zone = zoneOf(row);
  if (zone !== null && zone !== 'note') return false;
  if (requestedId && String(row.id).toLowerCase() !== requestedId) return false;
  const owner = storedOwner(row);
  return owner === null || owner.toLowerCase() === userId.toLowerCase();
}
// 공지 구역의 행인지: 소유자가 붙은 개인 메모가 아니고, 다른 구역 표시가 없고, 요청한 ID와 같은 행이어야 합니다.
function noticeRow(row, requestedId) {
  if (!row || typeof row !== 'object') return false;
  if (storedOwner(row) !== null) return false;
  const zone = zoneOf(row);
  if (zone !== null && zone !== 'notice') return false;
  return !requestedId || String(row.id).toLowerCase() === requestedId;
}
const publicNotice = row => ({ id: row.id, title: row.title, body: row.body, updatedAt: row.updatedAt });
const publicNote = row => ({ id: row.id, title: row.title, body: row.body });

// 11단계: 승인 요청 때 서버가 비밀번호를 다시 확인합니다. 비밀번호는 Supabase로 넘기기만 하고 저장·기록하지 않습니다.
// 확인용으로 생긴 세션은 바로 끊습니다.
export function supabasePasswordCheck(db) {
  return async function confirmPassword(userId, password) {
    const { data: found, error } = await db.auth.admin.getUserById(userId);
    const email = found?.user?.email;
    if (error || typeof email !== 'string') return false;
    const auth = defaultAuthClient();
    const { data, error: signInError } = await auth.signInWithPassword({ email, password });
    if (signInError || data?.user?.id !== userId) return false;
    try { await auth.admin.signOut(data.session.access_token, 'local'); } catch { /* 확인용 세션 정리 실패는 무시 */ }
    return true;
  };
}

// 로그인 확인. 토큰이 없거나 검증에 실패하면 자료 없이 401을 돌려줍니다.
// 11단계: 로그인 다음에 기기 서명을 확인합니다(path는 서버가 처리할 경로를 서버가 직접 만든 값).
// 기기 확인 도구가 없으면 허용하지 않습니다(기본 거부).
async function authenticate(req, res, deps, path, device = {}) {
  let user = null;
  try {
    user = await deps.verify(req.headers?.authorization);
  } catch {
    user = null;
  }
  if (!user || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
    res.setHeader('WWW-Authenticate', 'Bearer');
    send(res, 401, { error: '로그인이 필요합니다.' });
    return null;
  }
  let proof;
  try {
    proof = typeof deps.deviceGate === 'function'
      ? await deps.deviceGate(req, user, path, device)
      : { ok: false, status: 403, reason: 'device_check_unavailable', message: '기기 확인을 할 수 없습니다.' };
  } catch {
    proof = { ok: false, status: 403, reason: 'device_check_failed', message: '기기 확인에 실패했습니다.' };
  }
  if (!proof?.ok) {
    send(res, proof?.status ?? 403, { error: proof?.message ?? '기기 확인에 실패했습니다.', reason: proof?.reason ?? 'device_check_failed' });
    return null;
  }
  return { ...user, deviceId: proof.deviceId ?? null };
}

const queryId = (req) => (Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id);
const pathPart = (value) => (typeof value === 'string' ? value : '');
// 심판 토큰의 서명 없는 요청은 읽기(GET)만 받습니다. 바꾸는 요청은 누구든 승인된 기기 서명이 필요합니다.
const readOnly = (req) => ({ judgeUnsigned: req.method === 'GET' });

function withDeps(handler, getDeps) {
  return async function notesHandler(req, res) {
    // 토큰 모양이 아예 없으면 서버 설정과 상관없이 바로 401(JSON)로 거절합니다.
    if (['GET', 'POST', 'PUT', 'DELETE'].includes(req.method)
        && !/^Bearer \S+$/u.test(req.headers?.authorization ?? '')) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return send(res, 401, { error: '로그인이 필요합니다.' });
    }
    let deps;
    try {
      deps = getDeps();
    } catch {
      console.error('notes: 서버 환경변수 또는 로그인 설정을 확인하세요.');
      return send(res, 500, { error: '서버 설정이 아직 끝나지 않았습니다.' });
    }
    try {
      return await handler(req, res, deps);
    } catch (error) {
      console.error('notes: 자료 처리 중 오류', error?.code ?? 'unknown');
      return send(res, 502, { error: '자료를 처리하지 못했습니다.' });
    }
  };
}

// /api/notes — GET 목록, POST 추가
export function createCollectionHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'GET' && req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return send(res, 405, { error: 'GET과 POST만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, '/api/notes', readOnly(req));
    if (!user) return undefined;
    res.setHeader('X-Resource-Id', resourceId('note'));

    if (req.method === 'GET') {
      const rows = await deps.notes.listByOwner(user.userId);
      return send(res, 200, (Array.isArray(rows) ? rows : [])
        .filter(row => ownRow(row, user.userId)).map(publicNote));
    }

    const raw = readBody(req);
    const input = noteInput(raw);
    if (input.error) return send(res, 400, { error: input.error });
    let id = raw.id;
    if (id === undefined || id === null) {
      id = deps.newId();
    } else if (typeof id !== 'string' || !UUID.test(id)) {
      return send(res, 400, { error: 'id는 UUID여야 합니다.' });
    }
    id = id.toLowerCase();
    const result = await deps.notes.insert({ id, ownerId: user.userId,
      title: input.title, body: input.body });
    if (result === 'duplicate') return send(res, 409, { error: '같은 id의 메모가 이미 있습니다.' });
    // 10단계: 처음 만든 내용을 검증된 사본으로 남깁니다(실패해도 메모 추가는 유지, 내용은 기록하지 않음).
    if (deps.backups) {
      try {
        await deps.backups.saveVerified({ id, ownerId: user.userId, title: input.title, body: input.body });
      } catch (error) {
        console.error('notes: 사본 저장 실패', error?.code ?? 'unknown');
      }
    }
    return send(res, 201, { id });
  }, getDeps);
}

// /api/notes/:id — GET 한 건, PUT 수정, DELETE 삭제
export function createItemHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (!['GET', 'PUT', 'DELETE'].includes(req.method)) {
      res.setHeader('Allow', 'GET, PUT, DELETE');
      return send(res, 405, { error: 'GET, PUT, DELETE만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, `/api/notes/${pathPart(queryId(req))}`, readOnly(req));
    if (!user) return undefined;

    const rawId = Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) {
      return send(res, 404, { error: '메모를 찾을 수 없습니다.', reason: 'not_found' });
    }
    const id = rawId.toLowerCase();
    res.setHeader('X-Resource-Id', resourceId('note', id));

    // 본인 메모가 아니면 없는 메모와 똑같이 404로 거절합니다(기본 거부).
    if (req.method === 'GET') {
      const note = await deps.notes.getOwned(id, user.userId);
      return ownRow(note, user.userId, id) ? send(res, 200, publicNote(note)) : send(res, 404, { error: '메모를 찾을 수 없습니다.', reason: 'not_owner_or_missing' });
    }
    if (req.method === 'PUT') {
      const raw = readBody(req);
      if (changesOwner(raw, user.userId)) {
        return send(res, 403, { error: '메모 소유자는 바꿀 수 없습니다.', reason: 'owner_change' });
      }
      const input = noteInput(raw);
      if (input.error) return send(res, 400, { error: input.error });
      const note = await deps.notes.updateOwned(id, user.userId,
        { title: input.title, body: input.body });
      return ownRow(note, user.userId, id) ? send(res, 200, publicNote(note)) : send(res, 404, { error: '메모를 찾을 수 없습니다.', reason: 'not_owner_or_missing' });
    }
    const removed = await deps.notes.removeOwned(id, user.userId);
    return removed ? send(res, 204) : send(res, 404, { error: '메모를 찾을 수 없습니다.', reason: 'not_owner_or_missing' });
  }, getDeps);
}

// 8단계 /api/notices — GET 공지 목록(로그인한 사용자 누구나 읽기)
export function createNoticeCollectionHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return send(res, 405, { error: 'GET만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, '/api/notices', readOnly(req));
    if (!user) return undefined;
    res.setHeader('X-Resource-Id', resourceId('notice'));
    const rows = await deps.notices.list();
    return send(res, 200, (Array.isArray(rows) ? rows : []).filter(row => noticeRow(row)).map(publicNotice));
  }, getDeps);
}

// 8단계 /api/notices/:id — GET 공지 한 건(로그인한 누구나), PUT 수정(DB 강사 명단에 있는 사용자만)
export function createNoticeItemHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'GET' && req.method !== 'PUT') {
      res.setHeader('Allow', 'GET, PUT');
      return send(res, 405, { error: 'GET과 PUT만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, `/api/notices/${pathPart(queryId(req))}`, readOnly(req));
    if (!user) return undefined;
    const rawId = Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) {
      return send(res, 404, { error: '공지를 찾을 수 없습니다.', reason: 'not_found' });
    }
    const id = rawId.toLowerCase();
    res.setHeader('X-Resource-Id', resourceId('notice', id));
    if (req.method === 'GET') {
      const notice = await deps.notices.get(id);
      // 공지 구역으로 다른 구역(개인 메모)의 행이 나오지 않게 합니다.
      return noticeRow(notice, id) ? send(res, 200, publicNotice(notice)) : send(res, 404, { error: '공지를 찾을 수 없습니다.', reason: 'not_found' });
    }
    // PUT: 본문의 role 같은 값은 보지 않고, 검증된 사용자 ID로 DB 강사 명단만 확인합니다.
    if (!(await deps.notices.isInstructor(user.userId))) {
      return send(res, 403, { error: '강사만 공지를 고칠 수 있습니다.', reason: 'not_instructor' });
    }
    const input = noteInput(readBody(req));
    if (input.error) return send(res, 400, { error: input.error, reason: 'bad_input' });
    const notice = await deps.notices.update(id, { title: input.title, body: input.body });
    return noticeRow(notice, id) ? send(res, 200, publicNotice(notice)) : send(res, 404, { error: '공지를 찾을 수 없습니다.', reason: 'not_found' });
  }, getDeps);
}

// 10단계 POST /api/notes/:id/restore — 검증된 사본에서 본인 메모 한 건만 되살립니다.
// 1) 로그인 확인 2) 본인 소유 사본 찾기 3) 사본 내용 해시 검증 4) 지금 메모가 다른 사람 것이면 건드리지 않음
// 5) 되돌리거나(변조) 다시 만들기(삭제) 6) 되살린 내용 해시를 사본과 다시 대조 7) 감사 기록 추가
// 요청 본문의 내용·소유자 값은 쓰지 않습니다. 다른 메모와 감사 기록은 바꾸지 않습니다.
export function createRestoreHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return send(res, 405, { error: 'POST만 받습니다.' });
    }
    // 복구는 요청 본문을 쓰지 않고 서버의 검증된 사본만 되살리므로, 운영 심판 토큰은 서명 없이도 받습니다(10단계 경로 유지).
    // 학생 로그인 토큰은 승인된 기기 서명이 필요합니다.
    const user = await authenticate(req, res, deps, `/api/notes/${pathPart(queryId(req))}/restore`, { judgeUnsigned: true });
    if (!user) return undefined;
    const rawId = Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) {
      return send(res, 404, { error: '복구할 사본이 없습니다.', reason: 'backup_not_found' });
    }
    const id = rawId.toLowerCase();
    res.setHeader('X-Resource-Id', resourceId('note', id));
    const backup = await deps.backups.getOwned(id, user.userId);
    if (!backup || String(backup.owner_id).toLowerCase() !== user.userId.toLowerCase()) {
      return send(res, 404, { error: '복구할 사본이 없습니다.', reason: 'backup_not_found' });
    }
    const expected = noteHash(backup.title, backup.body);
    if (expected !== backup.content_sha256) {
      return send(res, 409, { error: '사본 검증에 실패해 복구를 멈췄습니다.', reason: 'backup_unverified' });
    }
    const current = await deps.notes.ownerOf(id);
    if (current.exists && String(current.ownerId).toLowerCase() !== user.userId.toLowerCase()) {
      return send(res, 404, { error: '복구할 사본이 없습니다.', reason: 'backup_not_found' });
    }
    const restored = await deps.notes.restoreOwned({ id, ownerId: user.userId,
      title: backup.title, body: backup.body, exists: current.exists });
    if (!restored || noteHash(restored.title, restored.body) !== expected) {
      return send(res, 409, { error: '복구 뒤 내용이 사본과 다릅니다.', reason: 'restore_mismatch' });
    }
    await deps.backups.audit({ action: 'restore_note', note_id: id, actor_id: user.userId,
      previous_state: current.exists ? 'tampered_or_current' : 'deleted', content_sha256: expected,
      at: deps.now ? deps.now() : new Date().toISOString() });
    return send(res, 200, { id, owner: 'self', restored: current.exists ? 'reverted' : 'recreated',
      contentSha256: expected, note: publicNote(restored) });
  }, getDeps);
}

// ── 11단계: 기기 등록·승인·상태 ─────────────────────────────────────────────
// POST /api/devices { publicKey }            → 등록(승인 대기). 본문의 공개키로 서명돼 있어야 합니다.
// POST /api/devices/approve { password }     → 서버가 비밀번호를 다시 확인하고, 등록한 기기 키 서명이 맞을 때만 승인
// GET  /api/devices/status                   → 서버 DB 기준 이 기기의 상태(approved일 때만 registered: true)
// 학생 로그인 토큰만 받습니다. 기기 ID는 서버가 공개키 지문으로 계산합니다.
const deviceView = (row) => ({ deviceId: row.device_id, status: row.status, registered: row.status === 'approved' });

export function createDeviceRegisterHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return send(res, 405, { error: 'POST만 받습니다.' });
    }
    const jwk = publicJwk(readBody(req)?.publicKey);
    if (!jwk) return send(res, 400, { error: '기기 공개키(P-256)가 필요합니다.', reason: 'bad_public_key' });
    const user = await authenticate(req, res, deps, '/api/devices', { mode: 'register', jwk });
    if (!user) return undefined;
    if (user.kind !== 'student') return send(res, 403, { error: '학생 로그인으로만 기기를 등록합니다.', reason: 'student_only' });
    const row = await deps.devices.register({ deviceId: deviceIdOf(jwk), ownerId: user.userId, jwk,
      now: deps.now ? deps.now() : new Date().toISOString() });
    if (row === 'conflict' || !row) return send(res, 409, { error: '이 기기 키는 쓸 수 없습니다.', reason: 'device_conflict' });
    return send(res, 200, deviceView(row));
  }, getDeps);
}

export function createDeviceApproveHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return send(res, 405, { error: 'POST만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, '/api/devices/approve', { mode: 'pending' });
    if (!user) return undefined;
    if (user.kind !== 'student') return send(res, 403, { error: '학생 로그인으로만 기기를 승인합니다.', reason: 'student_only' });
    const password = readBody(req)?.password;
    if (typeof password !== 'string' || !password || password.length > 512) {
      return send(res, 400, { error: '비밀번호를 다시 입력해 주세요.', reason: 'password_required' });
    }
    // 승인 버튼을 눌렀다는 사실이 아니라, 서버가 비밀번호를 확인한 결과로만 승인합니다.
    if (!(await deps.confirmPassword(user.userId, password))) {
      return send(res, 403, { error: '비밀번호가 맞지 않아 기기를 승인하지 않았습니다.', reason: 'reauth_failed' });
    }
    const row = await deps.devices.approve({ deviceId: user.deviceId, ownerId: user.userId,
      now: deps.now ? deps.now() : new Date().toISOString() });
    if (!row) return send(res, 403, { error: '이 기기는 승인할 수 없습니다.', reason: 'device_not_approvable' });
    return send(res, 200, deviceView(row));
  }, getDeps);
}

export function createDeviceStatusHandler(getDeps = defaultDeps) {
  return withDeps(async (req, res, deps) => {
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return send(res, 405, { error: 'GET만 받습니다.' });
    }
    const user = await authenticate(req, res, deps, '/api/devices/status', { mode: 'pending' });
    if (!user) return undefined;
    const row = await deps.devices.get(user.deviceId);
    if (!row) return send(res, 403, { error: '등록되지 않은 기기입니다.', reason: 'device_not_registered' });
    return send(res, 200, deviceView(row));
  }, getDeps);
}
