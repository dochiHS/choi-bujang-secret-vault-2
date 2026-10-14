// 보너스 XDR-06 · 자료 빼돌리기(유출) 판단
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// 심판이 이 파일 하나만 인터넷 없이 격리 실행하므로 다른 파일·패키지 불러오기, 파일 읽기/쓰기, 외부 질의를 하지 않습니다.
// 패턴은 patterns.json 과 같은 내용을 상수로 옮겨 둡니다.

export const PATTERNS = Object.freeze([
  {"name": "T1048-bulk-to-new-destination", "condition": "처음 보는 목적지(외부 주소·평소 쓰지 않던 포트)로 대용량(50MB 이상) 또는 자료 50건 이상이 나감", "basis": "T1048: 평소 통로가 아닌 다른 프로토콜·목적지로 자료를 대량 반출하는 형태"},
  {"name": "T1041-repeated-c2-transfer", "condition": "명령 통로·같은 목적지로 대용량 전송이 5번 이상 반복", "basis": "T1041: 이미 열린 명령 통로를 통해 자료를 여러 번 나눠 빼내는 형태"},
  {"name": "T1048-off-hours-archive", "condition": "수업·업무 시간 밖에 압축 파일이 처음 보는 주소로 대용량 반출됨", "basis": "T1048: 감시가 느슨한 시간에 자료를 압축해 외부로 내보내는 형태"},
  {"name": "T1041-T1048-single-weak-sign", "condition": "T1041·T1048 태그는 붙었지만 전송량이 작거나(50MB 미만) 1~2건뿐이고 실패·수업 자료 주소인 경우", "basis": "T1041·T1048 Detection: 평소와 조금 다른 작은 전송은 백업·과제 제출과 겹쳐 사람이 확인해야 함"},
]);
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const TAGS = ['T1041', 'T1048'];
const PATTERNS_LABEL = '유출';
const BULK_BYTES = 50_000_000; // 50MB 이상이면 대용량
const MANY_FILES = 50;
const REPEAT_MIN = 5;

// 경보 설명(d)과 data(x)에서 보는 뚜렷한 신호
const SIGNALS = [
  { label: '대용량', test: (d, x) => num(x.bytes) >= BULK_BYTES },
  { label: '자료 다수', test: (d, x) => num(x.files) >= MANY_FILES || /자료실 전체/.test(d) },
  { label: '반복 전송', test: (d, x) => num(x.count) >= REPEAT_MIN },
  { label: '처음 보는 목적지', test: (d) => /처음 보는|외부 주소|평소에 쓰지 않던 포트/.test(d) },
  { label: '압축 파일 반출', test: (d) => /압축 파일/.test(d) && !/외부 전송은 아직 없/.test(d) },
  { label: '시간 밖 전송', test: (d) => /(수업|업무) 시간 밖/.test(d) },
];
// 정상 활동과 겹치는 약한 신호: 이게 있으면 차단하지 않고 알림까지만
const WEAK = /실패|수업 자료 주소|외부 전송은 아직 없|평소 목적지|백업처럼|작은 (파일|동기화)|큰 파일은 아닙/;
const MUST = (d, x) => num(x.bytes) >= BULK_BYTES;

function pickPattern(hits) {
  const l = hits.map((h) => h.label);
  if (l.includes('시간 밖 전송') && l.includes('압축 파일 반출')) return PATTERNS[2].name;
  if (l.includes('반복 전송')) return PATTERNS[1].name;
  return PATTERNS[0].name;
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
