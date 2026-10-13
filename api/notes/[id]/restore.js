import { createRestoreHandler } from '../../_notes-lib.js';

// 10단계 POST /api/notes/:id/restore — 침해 전에 검증한 사본에서 본인 메모 한 건만 되살립니다.
// 변조된 메모는 사본 내용으로 되돌리고, 삭제된 메모는 같은 번호·소유자로 다시 만듭니다.
// 다른 사람의 메모·다른 메모·감사 기록은 바꾸지 않습니다.
export default createRestoreHandler();
