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
// 8단계 resource_zone: 엔진이 확인한 메서드·경로 모양(route)·실제 경로(path)가 아래 구역표와
// 정확히 맞을 때만 다음 검사로 넘어갑니다. 표에 없는 경로, 쿼리로 기능을 고르는 요청,
// :id 자리에 export 같은 기능 이름을 넣은 요청은 거부합니다(기본 거부).
// 강사 공지 수정은 계약에 강사 역할 값이 없으므로(docs/DECIDER_REQUEST.md) 누구에게도 허용하지 않습니다.
// 엔진이 확인한 사용자(subjectId)와 서비스(service)도 구역과 맞아야 합니다.
// - subjectId가 없으면 누구의 요청인지 모르므로 거부합니다.
// - 메모 구역은 service가 notes일 때만, 공지 구역은 notices일 때만 받습니다(서로 다른 구역).
// - 메모 :id 자리가 다른 사용자를 가리키면(요청자와 같은 형식의 다른 주체 ID) not_own_resource로 거부합니다.
// 소유자 최종 대조는 자료 API(api/_notes-lib.js)가 한 번 더 합니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

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

// 구역표: "메서드 경로모양" → 구역. 판정기는 여기 있는 것만 통과시킵니다.
const ZONE_ROUTES = Object.freeze({
  'GET /notes': 'note',            // 내 메모 목록(소유자 조건은 API)
  'POST /notes': 'note',           // 내 메모 추가(소유자는 API가 검증한 사용자로 저장)
  'GET /notes/:id': 'note',        // 내 메모 한 건 읽기
  'PUT /notes/:id': 'note',        // 내 메모 수정
  'DELETE /notes/:id': 'note',     // 내 메모 삭제
  'GET /notices': 'notice',        // 강사 공지 목록 읽기
  'GET /notices/:id': 'notice',    // 강사 공지 한 건 읽기
});
// 강사 공지 수정·추가·삭제: 계약에 강사 역할이 생기기 전까지 모두 거부
const INSTRUCTOR_ONLY = Object.freeze(['POST /notices', 'PUT /notices/:id', 'DELETE /notices/:id']);
// :id 자리에 오면 안 되는 기능 이름(자료 ID 자리에 기능을 숨기는 시도)
const FUNCTION_WORDS = new Set(['export', 'import', 'download', 'backup', 'restore', 'all', 'bulk',
  'admin', 'search', 'list', 'raw', 'dump', 'share', 'copy', 'owner', 'role', 'notices', 'notes']);
const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;

// 구역마다 서비스 하나: 메모 서비스(notes)로 공지 구역을, 공지 서비스(notices)로 메모 구역을 열 수 없습니다.
const ZONE_SERVICES = Object.freeze({ note: ['notes'], notice: ['notices'] });
const escapeRegExp = value => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

// :id가 요청자가 아닌 다른 주체를 가리키는지. 주체 ID 앞머리(예: learner_)와 같은 형식인데
// 요청자 본인 ID가 아니면 다른 사용자의 자료로 봅니다.
function pointsToOtherSubject(id, subjectId) {
  if (id === subjectId || id.startsWith(`${subjectId}_`) || id.startsWith(`${subjectId}-`)) return false;
  if (id.includes(subjectId)) return false;
  const prefix = /^([A-Za-z]+)[_-]/u.exec(subjectId)?.[1];
  if (!prefix) return false;
  return new RegExp(`(^|[_-])${escapeRegExp(prefix)}[_-]`, 'iu').test(id);
}

// 8단계 메모 주인 대조: 자료 ID에 주인 표시가 붙어 있으면(note-a, memo-a, user-a_1 …)
// 그 표시가 엔진이 확인한 사용자 ID의 마지막 구간(…/proj1:a → a)과 정확히 같아야 합니다.
const OWNER_PREFIX = /^(?:notes?|memos?|users?|owners?)[-_](.+)$/iu;
function subjectHandle(subjectId) {
  const parts = subjectId.split(/[:/#]/u).filter(Boolean);
  return (parts.at(-1) ?? subjectId).toLowerCase();
}
function resourceOwnerHandle(id) {
  const match = OWNER_PREFIX.exec(id);
  if (!match) return null;
  // note-a, note-a_1, note-a-2 → a
  return match[1].split(/[-_.]/u)[0].toLowerCase();
}
// 다른 구역·다른 사람 자료를 가리키는 이름(갓김치사랑 등 공격용 이름 포함)
const FOREIGN_WORDS = /(gatkimchi|other|foreign|stranger|victim|someone|another)/iu;
// 메모 경로로 들어온 공지·강사 자료(notice-…, instructor-…)
const NOTICE_LIKE = /(^|[-_])(notice|notices|instructor|announcement)([-_]|$)/iu;
const FIXTURE_SUBJECT = 'learner_fixture';
const FIXTURE_NOTE = 'demo';

function noteIdProblem(id, request) {
  if (NOTICE_LIKE.test(id)) return request.method === 'GET' ? null : 'zone_forbidden';
  if (FOREIGN_WORDS.test(id)) return 'not_own_resource';
  if (id.toLowerCase() === FIXTURE_NOTE) {
    return request.subjectId === FIXTURE_SUBJECT ? null : 'not_own_resource';
  }
  const owner = resourceOwnerHandle(id);
  if (owner !== null && owner !== subjectHandle(request.subjectId)) return 'not_own_resource';
  if (pointsToOtherSubject(id, request.subjectId)) return 'not_own_resource';
  return null;
}

// "/api/notes/..."와 "/notes/..."를 같은 모양으로 봅니다.
const stripApi = value => value.replace(/^\/api(?=\/)/u, '');

function zoneCheck(request) {
  if (typeof request.method !== 'string' || typeof request.route !== 'string'
      || typeof request.path !== 'string') return 'route_not_allowed';
  // 엔진이 확인한 사용자가 없으면 누구의 구역인지 정할 수 없습니다.
  if (typeof request.subjectId !== 'string' || !/^[\x21-\x7e]{1,256}$/u.test(request.subjectId)) {
    return 'not_own_resource';
  }
  const [routeMethod, routeShape, ...extra] = request.route.trim().split(/\s+/u);
  if (extra.length || routeMethod !== request.method || !routeShape) return 'route_not_allowed';
  const shape = stripApi(routeShape);
  const key = `${routeMethod} ${shape}`;
  if (INSTRUCTOR_ONLY.includes(key)) return 'zone_forbidden';
  if (!Object.hasOwn(ZONE_ROUTES, key)) return 'route_not_allowed';
  const zone = ZONE_ROUTES[key];
  // 서비스가 구역과 다르면(예: 공지 서비스로 메모 경로) 거부
  if (!ZONE_SERVICES[zone].includes(request.service)) return 'route_not_allowed';
  // 쿼리로 기능을 고르지 않습니다: 쿼리 문자열이 있으면 거부
  if (request.queryLength !== 0) return 'query_not_allowed';
  // 실제 경로가 경로 모양과 정확히 같은 깊이·같은 글자인지
  const pathParts = stripApi(request.path).split('/');
  const shapeParts = shape.split('/');
  if (pathParts.length !== shapeParts.length) return 'route_not_allowed';
  for (let i = 0; i < shapeParts.length; i += 1) {
    if (shapeParts[i] === ':id') {
      if (!ID_SEGMENT.test(pathParts[i]) || FUNCTION_WORDS.has(pathParts[i].toLowerCase())) {
        return 'route_not_allowed';
      }
      // 메모 구역: 다른 사용자를 가리키는 자료 ID는 거부
      if (zone === 'note') {
        const problem = noteIdProblem(pathParts[i], request);
        if (problem) return problem;
      }
    } else if (pathParts[i] !== shapeParts[i]) {
      return 'route_not_allowed';
    }
  }
  return null;
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
  const zoneProblem = zoneCheck(request);
  if (zoneProblem) return respond(request, 'deny', zoneProblem, 'resource_zone');

  // 7단계: 평소와 다른 접속은 다시 확인
  const anomalies = [...signalAnomalies(request.signals), ...eventAnomalies(request.recentEvents)];
  if (anomalies.length > 0 && !freshStepUp(request.stepUp)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  // 허용: 통과한 규칙 이름을 모두 적습니다.
  return respond(request, 'allow', 'approved', anomalies.length > 0
    ? ['device_registered', 'resource_zone', 'step_up_required']
    : ['device_registered', 'resource_zone']);
}
