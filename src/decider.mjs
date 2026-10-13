// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다(계약: docs/DECIDER_REQUEST.md, aleph.decision.v1).
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 않습니다.
// 다른 파일을 import하지 않습니다(심판이 이 파일만 따로 실행할 수 있음).
//
// 6단계 device_registered: 엔진이 확인한 기기 등록 여부(deviceRegistered)가 정확히 true이고
// deviceId가 계약 형식(16자리 소문자 16진수)일 때만 다음 검사로 넘어갑니다.
// false·값 없음·문자열 "true"·형식이 다른 기기 ID는 모두 device_not_registered로 거부합니다(기본 거부).
//
// 7단계 step_up_required: 평소와 다른 접속(지역·시각·네트워크·최근 행동)이 보이면 거부 대신
// 추가 본인 확인(step_up)을 요구합니다. 지역 하나만으로 영구 차단(deny)하지 않습니다.
// 최근(STEP_UP_FRESH_SECONDS 이내)에 다시 확인을 마친 요청만 허용합니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

const DEVICE_ID = /^[0-9a-f]{16}$/u;

// 접속 정보 출처: 'none'은 "정보 없음"(현재 실제 경로), 'judge_fixture'는 심판·연습용 가상 사건.
// 그 밖의 출처(예: 브라우저·클라이언트 헤더)는 믿지 않으며, 그 값으로 정상 판정을 내리지 않습니다.
const NO_SIGNAL_SOURCE = 'none';
const FIXTURE_SOURCE = 'judge_fixture';
const USUAL_REGION = 'local';
const USUAL_NETWORK = 'usual';
const USUAL_HOURS = { from: 6, to: 22 };          // 06~22시는 평소 시각, 그 밖(23~05시)은 평소와 다른 시각
const BURST_WINDOW_SECONDS = 600;                 // 최근 10분 안의 사건만 셉니다
const BURST_COUNT = 10;                           // 10분 안에 10번 이상이면 갑작스러운 대량 행동
const RISK_KIND = /risk|bulk|mass|burst|anomal|unusual|fail/iu;
const STEP_UP_FRESH_SECONDS = 300;                // 다시 확인한 지 5분 이내만 인정

function respond(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request && typeof request === 'object' ? request.requestId : undefined,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  };
}

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// 제작 1: 접속 정보의 출처를 구분합니다. 없는 값을 정상값으로 채우지 않습니다.
// 반환값은 평소와 다른 점 목록입니다. 확인할 수 없는 정보도 "확인 불가"로 목록에 넣습니다.
function signalAnomalies(signals) {
  if (!isObject(signals)) return ['signals_missing'];
  if (signals.source === NO_SIGNAL_SOURCE) return [];     // 정보 없음: 정상이라고도 이상이라고도 하지 않음
  if (signals.source !== FIXTURE_SOURCE) return ['signals_untrusted_source'];
  const found = [];
  if (typeof signals.region !== 'string' || !signals.region) found.push('region_unverified');
  else if (signals.region !== USUAL_REGION) found.push('region_changed');
  if (typeof signals.network !== 'string' || !signals.network) found.push('network_unverified');
  else if (signals.network !== USUAL_NETWORK) found.push('network_unusual');
  if (!Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) found.push('hour_unverified');
  else if (signals.hour < USUAL_HOURS.from || signals.hour > USUAL_HOURS.to) found.push('hour_unusual');
  return found;
}

function eventAnomalies(recentEvents) {
  if (recentEvents === undefined) return [];
  if (!Array.isArray(recentEvents) || recentEvents.length > 12) return ['events_unverified'];
  let recentCount = 0;
  let risky = false;
  for (const event of recentEvents) {
    if (!isObject(event) || typeof event.kind !== 'string'
        || !Number.isFinite(event.ageSeconds) || !Number.isInteger(event.count) || event.count < 0) {
      return ['events_unverified'];
    }
    if (event.ageSeconds < 0 || event.ageSeconds > BURST_WINDOW_SECONDS) continue;
    recentCount += event.count;
    if (RISK_KIND.test(event.kind)) risky = true;
  }
  const found = [];
  if (risky) found.push('risk_event');
  if (recentCount >= BURST_COUNT) found.push('burst_activity');
  return found;
}

// 다시 확인을 "방금" 마쳤는지: verified가 정확히 true이고 나이가 0~300초 정수일 때만.
function freshStepUp(stepUp) {
  return isObject(stepUp) && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= STEP_UP_FRESH_SECONDS;
}

export async function decide(request) {
  // 6단계: 등록 기기만
  const registered = isObject(request)
    && request.schema === 'aleph.decision.v1'
    && request.deviceRegistered === true
    && typeof request.deviceId === 'string' && DEVICE_ID.test(request.deviceId);
  if (!registered) return respond(request, 'deny', 'device_not_registered', 'device_registered');

  // 7단계: 평소와 다른 접속은 다시 확인
  const anomalies = [...signalAnomalies(request.signals), ...eventAnomalies(request.recentEvents)];
  if (anomalies.length > 0 && !freshStepUp(request.stepUp)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  return respond(request, 'allow', 'approved', anomalies.length > 0 ? 'step_up_required' : 'device_registered');
}
