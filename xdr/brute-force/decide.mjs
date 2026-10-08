// 제작 3 · Jev 판단
// 경보를 patterns.json 의 패턴과 맞춰 보고, 애매한 경보만 Jev 에게 확신도(0~1)를 묻습니다.
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// Jev 가 없거나 응답하지 않으면 애매한 경보는 alert 로 떨어집니다.
// 심판은 이 파일 하나만 격리된 곳에서 실행할 수 있으므로 다른 파일을 import 하지 않습니다.
// 패턴 이름은 patterns.json 과 같게 맞춰 둡니다.

const PATTERN = Object.freeze({
  guess: 'T1110.001-password-guessing-burst',
  spray: 'T1110.003-password-spraying',
  low: 'T1110-low-volume-failures',
});
export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const BURST_FAILURES = 15; // 짧은 시간 같은 주소 실패 연속
const SPRAY_ACCOUNTS = 8;  // 여러 계정에 같은 비밀번호
const AMBIGUOUS_MIN = 2;   // 실패가 이만큼은 있어야 애매한 시도로 봄
const JEV_TIMEOUT_MS = 3000;

function toAction(confidence) {
  if (confidence >= THRESHOLD.block) return 'block';
  if (confidence >= THRESHOLD.alert) return 'alert';
  return 'record';
}

function num(v) {
  const n = Number.parseInt(String(v ?? ''), 10);
  return Number.isFinite(n) ? n : 0;
}

// 경보에서 판단에 쓸 값만 뽑습니다. 비밀값처럼 보이는 칸은 쓰지 않습니다.
function signals(alert) {
  const data = alert?.data ?? {};
  const rule = alert?.rule ?? {};
  const desc = String(rule.description ?? '');
  const mitre = Array.isArray(rule.mitre) ? rule.mitre.map(String) : [];
  const failMatch = desc.match(/실패\s*(\d+)\s*건/);
  const acctMatch = desc.match(/계정\s*(\d+)\s*개/);
  const accountsField = String(data.accounts ?? '');
  const failures = Math.max(num(data.count), failMatch ? num(failMatch[1]) : 0);
  const accounts = Math.max(accountsField ? accountsField.split(',').filter(Boolean).length : 0, acctMatch ? num(acctMatch[1]) : 0);
  const sprayWords = /여러 계정|계정 이름을 바꿔|같은 비밀번호/.test(desc);
  return {
    row: { id: String(alert?.id ?? ''), time: String(alert?.timestamp ?? ''), srcip: String(data.srcip ?? ''), user: String(data.srcuser ?? ''), level: num(rule.level), description: desc },
    failures,
    accounts,
    sprayWords,
    t1110: mitre.some((m) => m.startsWith('T1110')),
  };
}

// Jev 에게 묻기. 주소(XDR_JEV_URL)가 없거나 실패하면 null. 뽑은 다섯 칸만 보냅니다.
export async function askJev(row, { fetchImpl = globalThis.fetch, url = globalThis.process?.env?.XDR_JEV_URL } = {}) {
  if (!url || typeof fetchImpl !== 'function') return null;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), JEV_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ task: 'brute-force-confidence', alert: row }),
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

    // 1) 명확한 공격: 알려진 패턴에 그대로 맞으면 Jev 없이 막습니다.
    if (s.t1110 && (s.accounts >= SPRAY_ACCOUNTS || (s.sprayWords && s.failures >= BURST_FAILURES))) {
      return { action: 'block', confidence: 0.95, reason: `${PATTERN.spray}: 계정 ${s.accounts || '여러'}개 대입` };
    }
    if (s.t1110 && s.failures >= BURST_FAILURES) {
      const confidence = Number(Math.min(0.99, 0.88 + s.failures / 1000).toFixed(2));
      return { action: 'block', confidence, reason: `${PATTERN.guess}: 실패 ${s.failures}건` };
    }

    // 2) 애매한 시도: T1110 이 붙었지만 실패가 적음 → Jev 에게 묻고, 답이 없으면 alert.
    if (s.t1110 && s.failures >= AMBIGUOUS_MIN) {
      const jev = await askJev(s.row, options);
      if (jev === null) {
        return { action: 'alert', confidence: 0.6, reason: `${PATTERN.low}: 실패 ${s.failures}건, Jev 응답 없음` };
      }
      // 실패 수가 적은 경보는 Jev 확신도가 높아도 차단까지 가지 않습니다(정상 사용자 보호).
      const confidence = Math.min(jev, THRESHOLD.block - 0.01);
      return { action: toAction(confidence), confidence, reason: `${PATTERN.low}: 실패 ${s.failures}건, Jev ${jev}` };
    }

    // 3) 정상 이벤트: 성공·로그아웃·세션 유지, 실패 0~1건.
    return { action: 'record', confidence: 0.05, reason: '정상 로그인 흐름: 공격 패턴 없음' };
  } catch {
    return { action: 'alert', confidence: 0.5, reason: '판단 중 오류: 사람이 확인' };
  }
}
