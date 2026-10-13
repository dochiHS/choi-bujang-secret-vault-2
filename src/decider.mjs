// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다(계약: docs/DECIDER_REQUEST.md, aleph.decision.v1).
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 않습니다.
// 다른 파일을 import하지 않습니다(심판이 이 파일만 따로 실행할 수 있음).
//
// 6단계 device_registered: 엔진이 확인한 기기 등록 여부(deviceRegistered)가 정확히 true이고
// deviceId가 계약 형식(16자리 소문자 16진수)일 때만 허용합니다.
// false·값 없음·문자열 "true"·형식이 다른 기기 ID는 모두 device_not_registered로 거부합니다(기본 거부).
export const RULE_IDS = Object.freeze(['device_registered']);

const DEVICE_ID = /^[0-9a-f]{16}$/u;

function respond(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request && typeof request === 'object' ? request.requestId : undefined,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  };
}

export async function decide(request) {
  const registered = request !== null && typeof request === 'object' && !Array.isArray(request)
    && request.schema === 'aleph.decision.v1'
    && request.deviceRegistered === true
    && typeof request.deviceId === 'string' && DEVICE_ID.test(request.deviceId);
  if (!registered) return respond(request, 'deny', 'device_not_registered', 'device_registered');
  return respond(request, 'allow', 'approved', 'device_registered');
}
