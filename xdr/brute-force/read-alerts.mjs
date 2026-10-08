// 제작 1 · 경보 읽기
// xdr/fixtures/brute-force.json 의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다.
// 원본 경보는 읽기만 하고 고치지 않습니다. 비밀값처럼 보이는 값은 [가림] 으로 바꿉니다.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const FIXTURE_PATH = join(here, '..', 'fixtures', 'brute-force.json');

const SECRET_LIKE = [
  /(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*\S+/gi,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, // JWT
  /\b(sk|pk|ghp|gho|sbp)_[A-Za-z0-9]{16,}\b/g, // 흔한 키 접두어
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g, // 긴 base64 덩어리
];

export function maskSecrets(text) {
  let out = String(text ?? '');
  for (const re of SECRET_LIKE) out = out.replace(re, '[가림]');
  return out;
}

// 경보 한 건 → 다섯 칸짜리 줄 하나
export function extract(alert) {
  return {
    id: String(alert?.id ?? ''),
    time: String(alert?.timestamp ?? ''),
    srcip: maskSecrets(alert?.data?.srcip ?? ''),
    user: maskSecrets(alert?.data?.srcuser ?? ''),
    level: Number(alert?.rule?.level ?? 0),
    description: maskSecrets(alert?.rule?.description ?? ''),
  };
}

export async function readAlerts(path = FIXTURE_PATH) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  const alerts = Array.isArray(fixture?.alerts) ? fixture.alerts : [];
  return { total: alerts.length, rows: alerts.map(extract) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const { total, rows } = await readAlerts();
  for (const r of rows) console.log([r.id, r.time, r.srcip, r.user, `L${r.level}`, r.description].join(' | '));
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
}
