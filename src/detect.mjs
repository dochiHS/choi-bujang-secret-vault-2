// 9단계 탐지기: 반 엔진이 검증해 넘긴 가상 조회 사건만 읽고, 도플갱어로 보이는 신원에 회수 제안을 냅니다.
// 계약: docs/DETECT_EVENTS.md. 브라우저가 보낸 사용자 번호·메모 내용·토큰·실명은 읽지도 남기지도 않습니다.
// 이 함수는 제안만 돌려줍니다. 회수 API를 부르거나 기기 권한을 바꾸지 않습니다(실제 회수는 엔진·심판).

const WINDOW_MS = 10 * 60 * 1000;   // 10분 구간
const BURST_LIMIT = 120;            // 10분 안에 120건을 "넘으면"(121건부터) 의심
const SUBJECT = /^[\x21-\x7e]{1,256}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;

// 제작 1: 사건에서 가명 사용자·기기·요청 종류·시각(·판정·네트워크)만 꺼냅니다.
// 모양이 맞지 않는 사건은 버리고(세지 않음), 빈 값을 정상값으로 채우지 않습니다.
function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  const sub = event.identity && typeof event.identity === 'object' ? event.identity.sub : undefined;
  if (typeof sub !== 'string' || !SUBJECT.test(sub)) return null;
  if (typeof event.method !== 'string') return null;
  const time = typeof event.at === 'string' ? Date.parse(event.at) : Number.NaN;
  if (!Number.isFinite(time)) return null;
  const device = [event.deviceId, event.identity.deviceId, event.device?.id]
    .find(value => typeof value === 'string' && DEVICE_ID.test(value)) ?? null;
  const network = [event.network, event.signals?.network].find(value => typeof value === 'string') ?? null;
  const decision = typeof event.decision === 'string' ? event.decision : null;
  return { sub, method: event.method.toUpperCase(), time, device, network, decision };
}

// 제작 2: 한 신원의 GET이 어떤 10분 구간에서 120건을 넘는지(갑작스러운 다량 조회).
// 사건에 네트워크 정보가 있으면, 그 구간에 평소와 다른 네트워크가 함께 있을 때만 의심으로 봅니다.
// 지역 하나만으로는 확정하지 않습니다(지역 값은 보지 않음).
function findBurst(reads) {
  let start = 0;
  for (let end = 0; end < reads.length; end += 1) {
    while (reads[end].time - reads[start].time >= WINDOW_MS) start += 1;
    if (end - start + 1 > BURST_LIMIT) {
      const window = reads.slice(start, end + 1);
      const withNetwork = window.filter(item => item.network !== null);
      const unusualNetwork = withNetwork.length === 0
        || withNetwork.some(item => item.network !== 'usual');
      if (unusualNetwork) return { window, at: reads[end].time };
    }
  }
  return null;
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // 신원별로 GET 사건만 모읍니다. 다른 사용자의 사건은 합치지 않습니다.
  const bySubject = new Map();
  for (const raw of events) {
    const event = readEvent(raw);
    if (!event || event.method !== 'GET') continue;
    if (!bySubject.has(event.sub)) bySubject.set(event.sub, []);
    bySubject.get(event.sub).push(event);
  }

  // 가장 먼저 기준을 넘은 신원 하나만 제안합니다.
  let first = null;
  for (const [sub, reads] of bySubject) {
    reads.sort((a, b) => a.time - b.time);
    const burst = findBurst(reads);
    if (burst && (!first || burst.at < first.at)) first = { sub, ...burst };
  }
  if (!first) return { action: 'observe' };

  // 제작 3: 회수 제안(별도 결과). 대상은 확인된 신원 하나, 이유 코드 burst_read.
  // 사건에 확인된 기기가 딱 하나만 있으면 그 기기로 대상을 좁힙니다.
  const proposal = { action: 'propose_revocation', reasonCode: 'burst_read', subject: first.sub };
  const devices = new Set(first.window.map(item => item.device).filter(Boolean));
  if (devices.size === 1) proposal.deviceId = [...devices][0];
  return proposal;
}
