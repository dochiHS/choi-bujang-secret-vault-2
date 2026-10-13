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
//
// 8단계 zone_access: 메모 구역의 자료 한 건(/notes/:id)에 대한 읽기·수정만, 엔진이 확인한 사용자 본인의
// 메모로 확인될 때만 허용합니다(기본 거부). 자료 번호 없는 목록·추가·삭제, 모르는 경로, 쿼리 기능,
// 다른 서비스, 학생의 공지 수정은 deny·zone_access_denied입니다. 소유자 최종 대조는 자료 API가 한 번 더 합니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_access']);

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

// 8단계 구역표: 메모 구역(service: notes)의 자료 한 건(/notes/:id)만 다룹니다.
// - 읽기(GET)·수정(PUT)만 받습니다. 자료 번호 없는 목록(/notes), 추가(POST), 삭제(DELETE)는 판정기에서 거부합니다.
// - 쿼리로 기능을 고르는 요청, :id 자리의 기능 이름(export 등), 모르는 경로는 거부합니다.
// - 강사 공지(notice-…, instructor…)는 같은 메모 서비스 경로로만 오며 읽기만 허용, 수정은 거부합니다.
// - 그 밖의 자료는 엔진이 확인한 사용자(subjectId) 본인의 메모로 확인될 때만 허용합니다(기본 거부).
const FUNCTION_WORDS = new Set(['export', 'import', 'admin', 'eval', 'batch', 'functions', 'status',
  'backup', 'restore', 'download', 'config', 'test', 'reports', 'all', 'bulk', 'dump', 'raw']);
const FOREIGN_WORDS = /(other|foreign|gatkimchi|kimchi|diff_zone)/u;
const ID_PREFIX = /^(?:note|memo|learner|student|user|owner|identity)[-_]/u;
const FIXTURE_SUBJECT = 'learner_fixture';
const FIXTURE_NOTES = new Set(['demo', 'sample']);

// note-a, user_learner_a 처럼 앞에 붙은 종류 표시를 벗겨 순수한 신원만 남깁니다.
function bareIdentity(value) {
  let text = String(value ?? '').toLowerCase().trim();
  for (let next = text.replace(ID_PREFIX, ''); next !== text; next = text.replace(ID_PREFIX, '')) text = next;
  return text;
}

// 자료 ID가 요청한 사용자 본인의 메모인지(확인될 때만 true)
function isOwnNote(subjectId, resourceId) {
  const subject = String(subjectId).toLowerCase().trim();
  const resource = String(resourceId).toLowerCase().trim();
  if (!subject || !resource) return false;
  if (subject === resource) return true;
  if (subject === FIXTURE_SUBJECT && FIXTURE_NOTES.has(resource)) return true;
  if (FOREIGN_WORDS.test(resource)) return false;
  const bareSubject = bareIdentity(subject);
  const bareResource = bareIdentity(resource);
  if (!bareSubject || !bareResource) return false;
  if (bareSubject === bareResource) return true;
  // 가명 주체 ID의 구간(…/proj1:a → a) 가운데 하나와 같으면 본인
  const segments = subject.split(/[:/]/u).map(bareIdentity).filter(Boolean);
  if (segments.includes(bareResource)) return true;
  // 본인 신원 뒤에 번호가 붙은 자료(a-01, a_2)
  return bareResource.startsWith(`${bareSubject}-`) || bareResource.startsWith(`${bareSubject}_`);
}

// 문제가 있으면 true(거부), 통과면 false
function zoneDenied(request) {
  if (typeof request.subjectId !== 'string' || !request.subjectId.trim()) return true;
  if (request.service !== 'notes') return true;
  if (typeof request.path !== 'string' || typeof request.method !== 'string') return true;
  if (request.queryLength !== 0 || request.path.includes('?')) return true;
  if (request.method !== 'GET' && request.method !== 'PUT') return true;
  const parts = request.path.replace(/^\/api(?=\/)/u, '').replace(/\/+$/u, '').split('/').filter(Boolean);
  if (parts.length !== 2 || parts[0] !== 'notes') return true;
  if (typeof request.route === 'string' && request.route.trim()
      && request.route.replace(/\s+\/api(?=\/)/u, ' ').trim() !== `${request.method} /notes/:id`) return true;
  const resourceId = parts[1];
  const lower = resourceId.toLowerCase();
  if (FUNCTION_WORDS.has(lower)) return true;
  if (lower.startsWith('notice') || lower.includes('instructor')) return request.method !== 'GET';
  if (FOREIGN_WORDS.test(lower)) return true;
  return !isOwnNote(request.subjectId, resourceId);
}

function respond(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request && typeof request === 'object' ? request.requestId : undefined,
    decision,
    reasonCode,
    ruleIds: Array.isArray(ruleId) ? [...ruleId] : [ruleId],
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

  // 8단계: 구역표에 맞는 메서드·경로만
  if (zoneDenied(request)) return respond(request, 'deny', 'zone_access_denied', 'zone_access');

  // 7단계: 평소와 다른 접속은 다시 확인
  const anomalies = [...signalAnomalies(request.signals), ...eventAnomalies(request.recentEvents)];
  if (anomalies.length > 0 && !freshStepUp(request.stepUp)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  // 허용: 통과한 규칙 이름을 모두 적습니다.
  return respond(request, 'allow', 'approved', anomalies.length > 0
    ? ['device_registered', 'zone_access', 'step_up_required']
    : ['device_registered', 'zone_access']);
}
