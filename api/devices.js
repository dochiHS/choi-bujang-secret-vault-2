import { createDeviceRegisterHandler } from './_notes-lib.js';

// 11단계 POST /api/devices — 이 기기의 공개키 등록(승인 대기). 개인키는 받지 않습니다.
export default createDeviceRegisterHandler();
