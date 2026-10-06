import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

// 3단계 공통: 로그인 토큰 검사 + 가상 메모 추가·읽기·수정·삭제.
// 파일 이름이 _로 시작하므로 Vercel은 이 파일을 공개 경로로 만들지 않습니다.
// 서버 전용 키는 Vercel 환경변수에서만 읽고, 응답·로그에 넣지 않습니다.
// 남은 약점(4단계에서 막을 것): 한 건 읽기·수정·삭제에서 메모 주인을 아직 비교하지 않습니다.

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 200;
const BODY_MAX = 5000;
const COLUMNS = 'id, title, body';

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
  cached = { verify, notes: supabaseNotes(db), newId: randomUUID };
  return cached;
}

// DB 접근을 한곳에 모읍니다. owner_id는 항상 서버가 확인한 사용자 ID만 씁니다.
export function supabaseNotes(db) {
  const table = () => db.from('vault_notes');
  return {
    async listByOwner(ownerId) {
      const { data, error } = await table().select(COLUMNS)
        .eq('owner_id', ownerId).order('created_at', { ascending: true });
      if (error) throw error;
      return data ?? [];
    },
    async insert({ id, ownerId, title, body }) {
      const { error } = await table().insert({ id, owner_id: ownerId, title, body });
      if (error?.code === '23505') return 'duplicate';
      if (error) throw error;
      return 'created';
    },
    async get(id) {
      const { data, error } = await table().select(COLUMNS).eq('id', id).maybeSingle();
      if (error) throw error;
      return data ?? null;
    },
    async update(id, { title, body }) {
      const { data, error } = await table().update({ title, body })
        .eq('id', id).select(COLUMNS).maybeSingle();
      if (error) throw error;
      return data ?? null;
    },
    async remove(id) {
      const { data, error } = await table().delete().eq('id', id).select('id');
      if (error) throw error;
      return Array.isArray(data) && data.length > 0;
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

// 로그인 확인. 토큰이 없거나 검증에 실패하면 자료 없이 401을 돌려줍니다.
async function authenticate(req, res, deps) {
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
  return user;
}

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
    const user = await authenticate(req, res, deps);
    if (!user) return undefined;

    if (req.method === 'GET') {
      return send(res, 200, await deps.notes.listByOwner(user.userId));
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
    const user = await authenticate(req, res, deps);
    if (!user) return undefined;

    const rawId = Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) {
      return send(res, 404, { error: '메모를 찾을 수 없습니다.' });
    }
    const id = rawId.toLowerCase();

    if (req.method === 'GET') {
      const note = await deps.notes.get(id);
      return note ? send(res, 200, note) : send(res, 404, { error: '메모를 찾을 수 없습니다.' });
    }
    if (req.method === 'PUT') {
      const input = noteInput(readBody(req));
      if (input.error) return send(res, 400, { error: input.error });
      const note = await deps.notes.update(id, { title: input.title, body: input.body });
      return note ? send(res, 200, note) : send(res, 404, { error: '메모를 찾을 수 없습니다.' });
    }
    const removed = await deps.notes.remove(id);
    return removed ? send(res, 204) : send(res, 404, { error: '메모를 찾을 수 없습니다.' });
  }, getDeps);
}
