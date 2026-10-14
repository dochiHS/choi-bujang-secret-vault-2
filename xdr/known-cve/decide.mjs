// 보너스 XDR-03 · 알려진 취약점 악용(CVE-2021-44228, Log4Shell) 판단
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// 심판이 이 파일 하나만 인터넷 없이 격리 실행하므로 다른 파일·패키지 불러오기, 파일 읽기/쓰기, 외부 질의를 하지 않습니다.
// 패턴은 patterns.json 과 같은 내용을 상수로 옮겨 둡니다.

export const PATTERNS = Object.freeze([
  { name: 'CVE-2021-44228-jndi-lookup-header', condition: '머리글에 완전한 ${jndi:<프로토콜>://주소} 구문', basis: 'CVE-2021-44228 · 머리글 값의 JNDI 조회로 외부 코드 실행' },
  { name: 'CVE-2021-44228-jndi-lookup-param', condition: '주소·인자에 완전한 ${jndi:<프로토콜>://주소} 구문', basis: 'T1190 · 공개 웹 앱 입력에 알려진 공격 문자열' },
  { name: 'CVE-2021-44228-scanner-probe', condition: '점검 도구 흔적 + 완전한 조회 구문', basis: 'T1190 · 공개 취약점 점검 도구로 대량 스캔' },
  { name: 'CVE-2021-44228-mention-only', condition: 'T1190 태그뿐, 완전한 조회 구문 없음', basis: 'T1190 Detection · 이름·조각만으로는 사람이 확인' },
]);
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });

// 완전한 원격 조회 구문: ${jndi:ldap://..} 형태(소문자 변환·중첩 표기 ${lower:j} 등 흔한 우회도 포함)
const JNDI_FULL = /\$\{\s*(?:j|\$\{[^}]*\})\s*(?:n|\$\{[^}]*\})\s*(?:d|\$\{[^}]*\})\s*(?:i|\$\{[^}]*\})\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?)\s*:\s*\/\//i;
const HEADER_FIELDS = ['useragent', 'user_agent', 'referer', 'x_forwarded_for', 'header', 'headers'];
const PARAM_FIELDS = ['url', 'query', 'path', 'body', 'param', 'params'];

function num(v) {
  const n = Number.parseInt(String(v ?? ''), 10);
  return Number.isFinite(n) ? n : 0;
}

function toAction(confidence) {
  if (confidence >= THRESHOLD.block) return 'block';
  if (confidence >= THRESHOLD.alert) return 'alert';
  return 'record';
}

function text(v) {
  if (v == null) return '';
  return typeof v === 'object' ? JSON.stringify(v) : String(v);
}

function hasLookup(data, fields) {
  return fields.some((f) => JNDI_FULL.test(text(data[f])));
}

export function decide(alert) {
  try {
    const data = alert?.data ?? {};
    const rule = alert?.rule ?? {};
    const desc = String(rule.description ?? '');
    const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
    const t1190 = mitre.some((x) => x.startsWith('T1190'));
    const inHeader = hasLookup(data, HEADER_FIELDS);
    const inParam = hasLookup(data, PARAM_FIELDS);
    const m = desc.match(/(\d+)\s*번/);
    const repeats = Math.max(num(data.count), m ? num(m[1]) : 0, 1);

    // 1) 명확한 공격: 완전한 원격 조회 구문이 머리글이나 인자에 실제로 있음
    if (inHeader || inParam) {
      const scanner = /점검\s*(도구|흔적)|scanner|probe/i.test(`${desc} ${text(data.url)}`);
      const name = scanner ? PATTERNS[2].name : inHeader ? PATTERNS[0].name : PATTERNS[1].name;
      let confidence = 0.9;
      if (inHeader && inParam) confidence += 0.04;
      if (repeats > 1) confidence += Math.min(0.05, repeats / 200);
      if (t1190) confidence += 0.01;
      confidence = Number(Math.min(0.99, confidence).toFixed(2));
      const where = inHeader && inParam ? '머리글+인자' : inHeader ? '머리글' : '인자';
      return { action: toAction(confidence), confidence, reason: `${name}: ${where}에 완전한 조회 구문, ${repeats}번` };
    }

    // 2) 애매한 시도: T1190 은 붙었지만 이름·단어·조각뿐 → 알림만
    if (t1190 || /CVE-\d{4}-\d+|jndi/i.test(`${desc} ${text(data.url)} ${text(data.useragent)}`)) {
      return { action: 'alert', confidence: 0.6, reason: `${PATTERNS[3].name}: 완전한 조회 구문 없음, 사람이 확인` };
    }

    // 3) 정상 이벤트
    return { action: 'record', confidence: 0.05, reason: '정상 요청: 알려진 취약점 악용 형태 없음' };
  } catch {
    return { action: 'alert', confidence: 0.5, reason: '판단 중 오류: 사람이 확인' };
  }
}
