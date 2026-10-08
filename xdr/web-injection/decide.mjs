// 보너스 XDR-02 · 웹 입력 조작 판단
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// 애매한 경보만 Jev 에게 묻고, 응답이 없으면 alert 로 떨어집니다.
// 심판이 이 파일 하나만 격리해 실행할 수 있으므로 다른 파일을 import 하지 않습니다.
// 패턴 이름은 patterns.json 과 같게 맞춰 둡니다.

const PATTERN = Object.freeze({
  sqli: 'T1190-sql-injection-repeat',
  xss: 'T1190-script-injection-repeat',
  traversal: 'T1190-path-traversal-repeat',
  cmd: 'T1190-command-separator-repeat',
  single: 'T1190-single-suspicious-input',
});
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const REPEAT_MIN = 8; // 같은 주소에서 주입 표기가 이만큼 반복되면 명확한 공격
const JEV_TIMEOUT_MS = 3000;

function num(v) {
  const n = Number.parseInt(String(v ?? ''), 10);
  return Number.isFinite(n) ? n : 0;
}

function toAction(confidence) {
  if (confidence >= THRESHOLD.block) return 'block';
  if (confidence >= THRESHOLD.alert) return 'alert';
  return 'record';
}

// 어떤 주입 형태인지: 설명 문구와 문서용 표식(doc-*)으로 고릅니다. 원문 공격 문자열은 쓰지 않습니다.
function kindOf(desc, url) {
  const t = `${desc} ${url}`.toLowerCase();
  if (/명령 구분자|doc-cmd/.test(t)) return 'cmd';
  if (/경로.*(거슬러|이탈)|doc-up-repeat/.test(t)) return 'traversal';
  if (/스크립트 (삽입 )?표[기식]|doc-script|doc-mixed/.test(t)) return 'xss';
  if (/sql 구문|데이터베이스 조회를 이어|doc-sql/.test(t)) return 'sqli';
  return null;
}

function signals(alert) {
  const data = alert?.data ?? {};
  const rule = alert?.rule ?? {};
  const desc = String(rule.description ?? '');
  const url = String(data.url ?? '');
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const m = desc.match(/(\d+)\s*번/);
  const repeats = Math.max(num(data.count), m ? num(m[1]) : 0);
  return {
    row: { id: String(alert?.id ?? ''), time: String(alert?.timestamp ?? ''), srcip: String(data.srcip ?? ''), url, level: num(rule.level), description: desc },
    repeats,
    kind: kindOf(desc, url),
    t1190: mitre.some((x) => x.startsWith('T1190')),
  };
}

export async function askJev(row, { fetchImpl = globalThis.fetch, url = globalThis.process?.env?.XDR_JEV_URL } = {}) {
  if (!url || typeof fetchImpl !== 'function') return null;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), JEV_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ task: 'web-injection-confidence', alert: row }),
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    const c = Number((await res.json())?.confidence);
    return Number.isFinite(c) && c >= 0 && c <= 1 ? c : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function decide(alert, options = {}) {
  try {
    const s = signals(alert);

    // 1) 명확한 공격: 주입 형태가 보이고 같은 주소에서 여러 번 반복
    if (s.t1190 && s.kind && s.repeats >= REPEAT_MIN) {
      const confidence = Number(Math.min(0.99, 0.88 + s.repeats / 200).toFixed(2));
      return { action: 'block', confidence, reason: `${PATTERN[s.kind]}: ${s.repeats}번 반복` };
    }

    // 2) 애매한 시도: T1190 이 붙었지만 한두 번뿐 → Jev, 응답 없으면 alert
    if (s.t1190) {
      const jev = await askJev(s.row, options);
      if (jev === null) {
        return { action: 'alert', confidence: 0.6, reason: `${PATTERN.single}: ${s.repeats || 1}번, Jev 응답 없음` };
      }
      const confidence = Math.min(jev, THRESHOLD.block - 0.01); // 한 번짜리로는 차단하지 않음
      return { action: toAction(confidence), confidence, reason: `${PATTERN.single}: ${s.repeats || 1}번, Jev ${jev}` };
    }

    // 3) 정상 이벤트
    return { action: 'record', confidence: 0.05, reason: '정상 요청: 주입 패턴 없음' };
  } catch {
    return { action: 'alert', confidence: 0.5, reason: '판단 중 오류: 사람이 확인' };
  }
}
