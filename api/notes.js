import { createCollectionHandler } from './_notes-lib.js';

// 3단계 /api/notes
// GET: 로그인한 사용자의 가상 메모 배열 [{ id, title, body }]
// POST { id?, title, body }: 메모 추가. id(UUID)가 없으면 서버가 만들어 { id }로 돌려줍니다.
// owner_id는 브라우저 값이 아니라 서버가 확인한 로그인 사용자 ID로 저장합니다.
// 토큰이 없거나 검증에 실패하면 자료 없이 401입니다.
export default createCollectionHandler();
