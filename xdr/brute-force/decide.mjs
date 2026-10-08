// 제작 3 · Jev 판단
// 뽑은 경보를 patterns.json 과 맞춰 보고, 애매한 경보만 Jev 에게 확신도(0~1)를 묻습니다.
// 확신도 0.85 이상 block · 0.5 이상 alert · 그 아래 record.
// Jev 가 없거나 응답하지 않으면 애매한 경보는 alert 로 떨어집니다.
import catalog from './patterns.json' with { type: 'json' };
import { extract } from './read-alerts.mjs';

const byPrefix = (prefix) => catalog.patterns.find((p) => p.name.startsWith(prefix)).name;
const P = { guess: byPrefix('T1110.001'), spray: byPrefix('T1110.003'), low: byPrefix('T1110-low') };

export const THRESHOLD = Object.freeze({ block: 0.85, alert: 0.5 });
const BURST_FAILURES = 15; // 짧은 시간 같은 주소 실패 연속
const SPRAY_ACCOUNTS = 8;  // 여러 계정에 같은 비밀번호
const AMBIGUOUS_MIN = 3;   // 이보다 적은 실패는 오타로 봄
const JEV_TIMEOUT_MS = 3000;

function toAction(confidence) {
  if (confidence >= THRESHOLD.block) return 'block';
  if (confidence >= THRESHOLD.alert) return 'alert';
  return 'record';
}

function signals(alert) {
  const row = extract(alert);
  const failures = Number.parseInt(alert?.data?.count ?? '0', 10) || 0;
  const accountsField = String(alert?.data?.accounts ?? '');
  const accounts = accountsField ? accountsField.split(',').filter(Boolean).length : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  return { row, failures, accounts, t1110: mitre.some((m) => String(m).startsWith('T1110')) };
}

// Jev 에게 묻기. 주소(XDR_JEV_URL)가 없거나 실패하면 null 을 돌려줍니다.
// 비밀값·원본 경보 전체는 보내지 않고 뽑은 다섯 칸만 보냅니다.
export async function askJev(row, { fetchImpl = globalThis.fetch, url = process.env.XDR_JEV_URL } = {}) {
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
    const body = await res.json();
    const c = Number(body?.confidence);
    return Number.isFinite(c) && c >= 0 && c <= 1 ? c : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function decide(alert, options = {}) {
  const s = signals(alert);

  // 1) 명확한 공격: 알려진 패턴에 그대로 맞으면 Jev 없이 막습니다.
  if (s.t1110 && s.row.level >= 10 && s.accounts >= SPRAY_ACCOUNTS) {
    return { action: 'block', confidence: 0.95, reason: `${P.spray}: 계정 ${s.accounts}개 대입` };
  }
  if (s.t1110 && s.row.level >= 10 && s.failures >= BURST_FAILURES) {
    const confidence = Math.min(0.99, 0.88 + s.failures / 1000);
    return { action: 'block', confidence: Number(confidence.toFixed(2)), reason: `${P.guess}: 실패 ${s.failures}건` };
  }

  // 2) 애매한 시도: T1110 이 붙었지만 실패가 적음 → Jev 에게 묻고, 답이 없으면 alert.
  if (s.t1110 && s.failures >= AMBIGUOUS_MIN) {
    const jev = await askJev(s.row, options);
    if (jev === null) {
      return { action: 'alert', confidence: 0.6, reason: `${P.low}: 실패 ${s.failures}건, Jev 응답 없음` };
    }
    // 실패 수가 적은 경보는 Jev 확신도가 높아도 차단까지는 가지 않습니다(정상 사용자 보호).
    const confidence = Math.min(jev, THRESHOLD.block - 0.01);
    return { action: toAction(confidence), confidence, reason: `${P.low}: 실패 ${s.failures}건, Jev ${jev}` };
  }

  // 3) 정상 이벤트: 성공·로그아웃·세션 유지, 실패 1~2건.
  return { action: 'record', confidence: 0.05, reason: '정상 로그인 흐름: 공격 패턴 없음' };
}
