import { createDeviceApproveHandler } from '../_notes-lib.js';

// 11단계 POST /api/devices/approve — 서버가 비밀번호를 다시 확인하고 기기 서명이 맞을 때만 승인합니다.
export default createDeviceApproveHandler();
