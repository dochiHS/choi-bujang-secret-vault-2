import { createLogoutHandler } from '../_auth-lib.js';

// 5단계: POST /api/auth/logout — 브라우저 대신 서버가 Supabase Auth에 요청합니다.
export default createLogoutHandler();
