// 제작 4 · 알림과 차단
// result.json 의 block 만 ZTNA 판정기 앞에 붙는 "XDR 거부 규칙"으로 만들고, alert 는 xdr/alerts.log 에 한 줄씩 쌓습니다.
// src/decider.mjs 의 기존 규칙은 고치지 않습니다. 이 모듈은 판정기 앞에서 한 번 더 확인하는 부품입니다.
//   - 규칙마다 만료 시각(expiresAt)과 근거 경보 번호(sourceAlertId)를 붙입니다.
//   - 같은 주소에서 정상 이벤트(record)가 있었다면 그 주소는 막지 않습니다(정상 사용자 보호).
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readAlerts } from './read-alerts.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const RULES_PATH = join(here, 'deny-rules.json');
const LOG_PATH = join(here, '..', 'alerts.log');
export const BLOCK_TTL_MINUTES = 60;

export function buildDenyRules(result, rows, ttlMinutes = BLOCK_TTL_MINUTES) {
  const byId = new Map(rows.map((r) => [r.id, r]));
  const normalIps = new Set(result.decisions.filter((d) => d.action === 'record').map((d) => byId.get(d.alertId)?.srcip));
  const rules = [];
  for (const d of result.decisions) {
    if (d.action !== 'block') continue;
    const row = byId.get(d.alertId);
    if (!row?.srcip || normalIps.has(row.srcip)) continue;
    const base = Date.parse(row.time);
    rules.push({
      ruleId: 'xdr.brute_force.deny',
      match: { srcip: row.srcip },
      sourceAlertId: d.alertId,
      reason: d.reason,
      createdAt: new Date(base).toISOString(),
      expiresAt: new Date(base + ttlMinutes * 60_000).toISOString(),
    });
  }
  return rules;
}

// 판정기 앞 확인 단계: 이 주소가 아직 만료되지 않은 XDR 거부 규칙에 걸리는지
export function xdrPreCheck(srcip, at, rules) {
  const t = Date.parse(at);
  const hit = rules.find((r) => r.match.srcip === srcip && t >= Date.parse(r.createdAt) && t < Date.parse(r.expiresAt));
  return hit ? { blocked: true, ruleId: hit.ruleId, sourceAlertId: hit.sourceAlertId } : { blocked: false };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const result = JSON.parse(await readFile(join(here, 'result.json'), 'utf8'));
  const { rows } = await readAlerts();
  const rules = buildDenyRules(result, rows);
  await writeFile(RULES_PATH, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'brute-force', rules }, null, 2)}\n`);

  const byId = new Map(rows.map((r) => [r.id, r]));
  const lines = result.decisions.filter((d) => d.action === 'alert').map((d) => {
    const r = byId.get(d.alertId);
    return `${r.time}\tbrute-force\t${d.alertId}\t${r.srcip}\t${r.user}\tconfidence=${d.confidence}\t${d.reason}`;
  });
  if (lines.length) await appendFile(LOG_PATH, `${lines.join('\n')}\n`);

  // 시험 경보 다시 흘리기: 각 경보 시각에 그 주소가 막히는지
  let wrong = 0;
  for (const d of result.decisions) {
    const r = byId.get(d.alertId);
    const { blocked } = xdrPreCheck(r.srcip, r.time, rules);
    const expect = d.action === 'block';
    if (blocked !== expect) { wrong += 1; console.log(`어긋남 ${d.alertId}: 판단 ${d.action}, 차단 ${blocked}`); }
  }
  console.log(`거부 규칙 ${rules.length}개 · 알림 ${lines.length}줄 추가 · 다시 흘린 경보 ${result.decisions.length}건 중 어긋남 ${wrong}건`);
}
