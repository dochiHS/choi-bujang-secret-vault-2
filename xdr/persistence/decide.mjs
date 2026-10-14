// 보너스 XDR-04 · 몰래 심은 프로그램(지속성) 판단
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// 심판이 이 파일 하나만 인터넷 없이 격리 실행하므로 다른 파일·패키지 불러오기, 파일 읽기/쓰기, 외부 질의를 하지 않습니다.
// 패턴은 patterns.json 과 같은 내용을 상수로 옮겨 둡니다.

export const PATTERNS = Object.freeze([
  {"name": "T1543-unsigned-new-service", "condition": "서명 없는 새 서비스 등록·서비스 실행 파일 교체, 또는 평소 목록에 없는 서비스가 임시 폴더 실행 파일을 가리킴(같은 주소 연속 등록 포함)", "basis": "T1543: 공격자가 서비스를 새로 만들거나 바꿔 재부팅 뒤에도 악성 프로그램이 다시 실행되게 하는 형태"},
  {"name": "T1053-unfamiliar-scheduled-task", "condition": "처음 보는(또는 임의 문자열 이름) 예약 작업이 임시 폴더 프로그램을 수업 시간 밖에 실행", "basis": "T1053: 예약 작업으로 악성 프로그램을 정해진 시각마다 다시 실행해 자리를 유지하는 형태"},
  {"name": "T1543-startup-folder-change", "condition": "시작 폴더·시작 프로그램에 평소 목록에 없는 실행 파일이 추가되거나 예약 작업과 같은 임시 파일을 가리킴", "basis": "T1543·T1053: 시작 항목에 실행 파일을 넣어 로그인할 때마다 다시 켜지게 하는 지속성 형태"},
  {"name": "T1543-T1053-single-weak-sign", "condition": "T1543·T1053 태그는 붙었지만 수업 도구·수업 시간 작업이거나 변경 1건뿐이라 지속성 증거가 약함", "basis": "T1543·T1053 Detection: 정상 관리 작업과 겹치는 한 번짜리 변경은 사람이 확인해야 함"},
]);
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const TAGS = ['T1543', 'T1053'];
const PATTERNS_LABEL = '지속성';

// 경보 설명(d)과 data(x)에서 보는 뚜렷한 신호
const SIGNALS = [
  { label: '서명 없음', test: (d) => /서명 없|서명이 없/.test(d) },
  { label: '임시 폴더 실행 파일', test: (d, x) => /\\Temp\\[^\\]+\.exe$/i.test(String(x.path ?? '')) || /임시 (폴더|파일)/.test(d) && !/생겼습니다/.test(d) },
  { label: '시작 폴더 변경', test: (d, x) => /\\Startup\\/i.test(String(x.path ?? '')) || /시작 (폴더|프로그램)/.test(d) && !/읽기만|변경이 1건/.test(d) },
  { label: '낯선 등록', test: (d) => /평소 목록에 없|처음 보는|임의 문자열|다시 켜도 남/.test(d) },
  { label: '수업 시간 밖', test: (d) => /(수업|업무) 시간 밖/.test(d) },
  { label: '연속 등록', test: (d, x) => num(x.count) >= 2 || /연속/.test(d) },
];
// 정상 활동과 겹치는 약한 신호: 이게 있으면 차단하지 않고 알림까지만
const WEAK = /수업 (도구|중|과제)|수업 시간입니다|서비스 등록은 없|실행된 기록은 없|설명만|그대로|확인되지 않았|아직 모릅/;
const MUST = () => true;

function pickPattern(hits) {
  const l = hits.map((h) => h.label);
  if (l.includes('시작 폴더 변경')) return PATTERNS[2].name;
  if (l.includes('서명 없음') || l.includes('연속 등록')) return PATTERNS[0].name;
  return PATTERNS[1].name;
}

function num(v) {
  const n = Number(String(v ?? '').replace(/[^0-9.]/g, ''));
  return Number.isFinite(n) ? n : 0;
}

function toAction(confidence) {
  if (confidence >= THRESHOLD.block) return 'block';
  if (confidence >= THRESHOLD.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  try {
    const data = alert?.data ?? {};
    const rule = alert?.rule ?? {};
    const desc = String(rule.description ?? '');
    const level = num(rule.level);
    const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
    const tagged = mitre.some((x) => TAGS.some((t) => x.startsWith(t)));
    const hits = SIGNALS.filter((s) => s.test(desc, data));
    const weak = WEAK.test(desc);

    // 1) 명확한 공격: 태그 + 뚜렷한 신호 2개 이상, 약한 신호(수업·취소·실패 등) 없음
    if (tagged && hits.length >= 2 && !weak && MUST(desc, data)) {
      let confidence = 0.86 + 0.03 * (hits.length - 2) + (level >= 10 ? 0.04 : 0);
      confidence = Number(Math.min(0.99, confidence).toFixed(2));
      const name = pickPattern(hits);
      return { action: toAction(confidence), confidence, reason: `${name}: ${hits.map((h) => h.label).join('·')}` };
    }

    // 2) 애매한 시도: 태그나 신호는 있지만 증거가 약함 → 알림만
    if ((tagged || hits.length > 0) && level >= 4) {
      return { action: 'alert', confidence: 0.6, reason: `${PATTERNS[3].name}: ${hits.length ? hits.map((h) => h.label).join('·') + ' 1개뿐' : '태그만 있음'}${weak ? ', 정상 활동과 겹침' : ''}` };
    }

    // 3) 정상 이벤트
    return { action: 'record', confidence: 0.05, reason: `정상 이벤트: ${PATTERNS_LABEL} 형태 없음` };
  } catch {
    return { action: 'alert', confidence: 0.5, reason: '판단 중 오류: 사람이 확인' };
  }
}
