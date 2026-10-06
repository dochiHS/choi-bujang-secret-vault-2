import { createItemHandler } from '../_notes-lib.js';

// /api/notes/:id
// GET: { id, title, body } / PUT { title, body }: 수정 / DELETE: 삭제(204), 지운 뒤 GET은 404
// 토큰이 없거나 검증에 실패하면 자료 없이 401입니다.
// 4단계: 서버가 검증한 사용자 ID와 메모의 owner_id가 같을 때만 읽기·수정·삭제합니다.
// 남의 메모는 없는 메모와 똑같이 404, 수정 본문으로 소유자를 바꾸려 하면 403입니다.
export default createItemHandler();
