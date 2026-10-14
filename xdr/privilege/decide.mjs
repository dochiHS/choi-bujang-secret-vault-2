// 보너스 XDR-05 · 권한 가로채기 판단
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// 심판이 이 파일 하나만 인터넷 없이 격리 실행하므로 다른 파일·패키지 불러오기, 파일 읽기/쓰기, 외부 질의를 하지 않습니다.
// 패턴은 patterns.json 과 같은 내용을 상수로 옮겨 둡니다.

export const PATTERNS = Object.freeze([
  {"name": "T1078-admin-group-add", "condition": "평범한 계정이 원격·같은 주소에서 관리자 그룹에 추가되거나(여러 계정·빠졌다 다시 들어옴 포함) 곧바로 권한 명령을 실행", "basis": "T1078: 정상 계정을 도용해 관리자 그룹에 넣어 권한을 얻는 형태"},
  {"name": "T1068-unfamiliar-admin-command", "condition": "방금 관리자가 된 계정·처음 보는 주소·다른 계정 권한으로 관리자 명령을 실행", "basis": "T1068: 권한 상승 취약점이나 빼앗은 권한으로 관리자 명령을 실행하는 형태"},
  {"name": "T1068-T1078-off-hours-privilege", "condition": "수업·업무 시간 밖에 관리자 그룹 추가나 관리자 명령 같은 권한 사용이 있음", "basis": "T1078 Detection: 평소 근무 시간이 아닌 때의 권한 사용은 계정 도용의 대표 신호"},
  {"name": "T1068-T1078-single-weak-sign", "condition": "T1068·T1078 태그는 붙었지만 관리자 그룹이 아니거나, 취소·실패·조회뿐인 1건", "basis": "T1068·T1078 Detection: 정상 수업 활동과 겹치는 한 번짜리 권한 신호는 사람이 확인해야 함"},
]);
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const TAGS = ['T1068', 'T1078'];
const PATTERNS_LABEL = '권한 상승';

// 경보 설명(d)과 data(x)에서 보는 뚜렷한 신호
const SIGNALS = [
  { label: '관리자 그룹 추가', test: (d, x) => String(x.group ?? '').toLowerCase() === 'administrators' || /관리자 그룹에 (추가|들어)/.test(d) },
  { label: '관리자 명령 실행', test: (d) => /(관리자|권한) 명령을 실행|명령 실행이|관리자 권한으로 바뀌/.test(d) },
  { label: '낯선 출처·계정', test: (d) => /처음 보는|처음 봅니다|원격 주소|다른 계정의 권한|방금 관리자가 된|평범한 계정/.test(d) },
  { label: '시간 밖 권한 사용', test: (d) => /(수업|업무) 시간 밖|업무처럼 보이지 않는 시각/.test(d) },
  { label: '반복', test: (d, x) => num(x.count) >= 2 || /계정 \d+개/.test(d) },
];
// 정상 활동과 겹치는 약한 신호: 이게 있으면 차단하지 않고 알림까지만
const WEAK = /취소|실패|조회한 뒤|관리자 그룹은 아닙|평소 주소|읽은 뒤|이어서 명령은 없|수업 중|수업 시간에/;
const MUST = () => true;

function pickPattern(hits) {
  const l = hits.map((h) => h.label);
  if (l.includes('시간 밖 권한 사용')) return PATTERNS[2].name;
  if (l.includes('관리자 그룹 추가')) return PATTERNS[0].name;
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
