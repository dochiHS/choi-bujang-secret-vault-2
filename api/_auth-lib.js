import { createClient } from '@supabase/supabase-js';

// 5단계: 로그인·토큰 갱신·로그아웃을 서버 함수가 대신 Supabase Auth에 요청합니다.
// 그래서 브라우저 코드에는 Supabase 주소·공개 키·SDK가 없습니다.
// 비밀번호는 이 함수에서 Supabase로 넘기기만 하고 저장·기록하지 않습니다.
// 서버 전용 키는 Vercel 환경변수에서만 읽고 응답·로그에 넣지 않습니다.

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/u;
const MESSAGES = {
  invalid_credentials: '이메일 또는 비밀번호가 맞지 않습니다.',
  email_not_confirmed: '이메일 인증이 아직 끝나지 않은 계정입니다.',
  user_banned: '사용이 막힌 계정입니다.',
  over_request_rate_limit: '시도가 너무 많습니다. 잠시 뒤 다시 해 주세요.',
  refresh_token_not_found: '로그인이 만료되었습니다. 다시 로그인해 주세요.',
  refresh_token_already_used: '로그인이 만료되었습니다. 다시 로그인해 주세요.',
  session_not_found: '로그인이 만료되었습니다. 다시 로그인해 주세요.',
};

// 요청마다 새 클라이언트를 만듭니다. 한 사용자의 세션이 다른 요청에 섞이지 않게 합니다.
export function defaultAuthClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('server_env_missing');
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  }).auth;
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

// 브라우저에 돌려줄 세션: 토큰과 만료 시각, 화면 표시용 이메일만.
function publicSession(session) {
  return {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    user: { email: session.user?.email ?? null },
  };
}

function authError(res, error) {
  const code = typeof error?.code === 'string' ? error.code : 'auth_failed';
  const status = code.startsWith('over_') ? 429 : (error?.status >= 500 ? 502 : 401);
  return send(res, status, { error: MESSAGES[code] ?? '로그인 처리에 실패했습니다.', code });
}

function withAuth(handler, getAuth) {
  return async function authHandler(req, res) {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return send(res, 405, { error: 'POST만 받습니다.' });
    }
    let auth;
    try {
      auth = getAuth();
    } catch {
      console.error('auth: 서버 환경변수를 확인하세요.');
      return send(res, 500, { error: '서버 설정이 아직 끝나지 않았습니다.' });
    }
    try {
      return await handler(req, res, auth);
    } catch (error) {
      console.error('auth: 처리 중 오류', error?.code ?? 'unknown');
      return send(res, 502, { error: '로그인 서버에 연결하지 못했습니다.' });
    }
  };
}

// POST /api/auth/login { email, password } → { access_token, refresh_token, expires_at, user }
export function createLoginHandler(getAuth = defaultAuthClient) {
  return withAuth(async (req, res, auth) => {
    const body = readBody(req);
    const email = typeof body?.email === 'string' ? body.email.trim() : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    if (!EMAIL.test(email) || !password || password.length > 512) {
      return send(res, 400, { error: '이메일과 비밀번호 형식을 확인해 주세요.', code: 'validation_failed' });
    }
    const { data, error } = await auth.signInWithPassword({ email, password });
    if (error || !data?.session) return authError(res, error);
    return send(res, 200, publicSession(data.session));
  }, getAuth);
}

// POST /api/auth/refresh { refresh_token } → 새 세션
export function createRefreshHandler(getAuth = defaultAuthClient) {
  return withAuth(async (req, res, auth) => {
    const token = readBody(req)?.refresh_token;
    if (typeof token !== 'string' || !token || token.length > 2048) {
      return send(res, 400, { error: '갱신 토큰이 필요합니다.', code: 'validation_failed' });
    }
    const { data, error } = await auth.refreshSession({ refresh_token: token });
    if (error || !data?.session) return authError(res, error);
    return send(res, 200, publicSession(data.session));
  }, getAuth);
}

// POST /api/auth/logout (Authorization: Bearer <access_token>) → 204. 그 세션의 갱신 토큰을 끊습니다.
export function createLogoutHandler(getAuth = defaultAuthClient) {
  return withAuth(async (req, res, auth) => {
    const match = /^Bearer (\S+)$/u.exec(req.headers?.authorization ?? '');
    if (!match) return send(res, 401, { error: '로그인이 필요합니다.' });
    const { error } = await auth.admin.signOut(match[1], 'local');
    // 이미 만료된 세션이어도 브라우저 쪽 로그아웃은 진행되므로 204로 끝냅니다.
    if (error && !['session_not_found', 'bad_jwt'].includes(error.code)) {
      console.error('auth: 로그아웃 처리 중 오류', error.code ?? 'unknown');
    }
    return send(res, 204);
  }, getAuth);
}
