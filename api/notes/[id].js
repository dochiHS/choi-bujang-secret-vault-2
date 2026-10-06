import { createItemHandler } from '../_notes-lib.js';

// 3단계 /api/notes/:id
// GET: { id, title, body } / PUT { title, body }: 수정 / DELETE: 삭제(204), 지운 뒤 GET은 404
// 토큰이 없거나 검증에 실패하면 자료 없이 401입니다.
// 남은 약점(4단계에서 막을 것): 로그인만 확인하고, 이 메모의 주인인지는 아직 비교하지 않습니다.
export default createItemHandler();
