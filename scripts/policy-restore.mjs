// 10단계 제작 1·2: 침해 전에 검증한 안전 정책 사본(policy/verified)과 현재 시험 정책(src/decider.mjs, 허용 경로)을 비교하고,
// 확인을 거쳐 사본 버전으로 되돌립니다. 운영 반 엔진의 정책이나 다른 서비스 규칙, 감사 기록은 건드리지 않습니다.
//   npm run policy:diff               → 복원할 버전과 바뀔 항목만 보여 줌(아무것도 고치지 않음)
//   npm run policy:restore -- --yes   → 위 차이를 보여 준 뒤 src/decider.mjs만 사본으로 되돌림
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');
const fail = message => { process.stderr.write(`정책 복원 중단: ${message}\n`); process.exit(1); };

const manifestPath = resolve(root, 'policy/verified/manifest.json');
const copyPath = resolve(root, 'policy/verified/decider.mjs');
if (!existsSync(manifestPath) || !existsSync(copyPath)) fail('검증된 사본(policy/verified)이 없습니다.');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const copy = readFileSync(copyPath, 'utf8');
if (sha256(copy) !== manifest.deciderSha256) fail('사본 판정기의 지문이 목록(manifest)과 다릅니다. 사본을 믿을 수 없습니다.');

const current = readFileSync(resolve(root, 'src/decider.mjs'), 'utf8');
const config = JSON.parse(readFileSync(resolve(root, 'aleph.config.json'), 'utf8'));
const ruleIds = text => (/RULE_IDS\s*=\s*Object\.freeze\(\[([^\]]*)\]/u.exec(text)?.[1] ?? '')
  .split(',').map(s => s.trim().replace(/^['"]|['"]$/gu, '')).filter(Boolean);

const changes = [];
if (sha256(current) !== manifest.deciderSha256) changes.push('src/decider.mjs 내용이 사본과 다름');
const curRules = ruleIds(current);
for (const r of manifest.ruleIds) if (!curRules.includes(r)) changes.push(`규칙 빠짐: ${r}`);
for (const r of curRules) if (!manifest.ruleIds.includes(r)) changes.push(`규칙 추가됨: ${r}`);
const curRoutes = config.allowedRoutes ?? [];
for (const r of manifest.allowedRoutes) if (!curRoutes.includes(r)) changes.push(`허용 경로 빠짐: ${r}`);
for (const r of curRoutes) if (!manifest.allowedRoutes.includes(r)) changes.push(`허용 경로 추가됨: ${r}`);

process.stdout.write(`복원할 안전 정책: ${manifest.version} (판정기 지문 ${manifest.deciderSha256.slice(0, 12)})\n`);
process.stdout.write(changes.length ? `바뀔 항목 ${changes.length}개:\n- ${changes.join('\n- ')}\n` : '현재 시험 정책이 사본과 같습니다. 되돌릴 것이 없습니다.\n');

if (process.argv.includes('--apply')) {
  if (!process.argv.includes('--yes')) fail('위 항목을 확인했다면 --yes를 함께 붙여 다시 실행하세요.');
  if (!changes.some(c => c.startsWith('src/decider.mjs'))) {
    process.stdout.write('판정기는 이미 사본과 같습니다. 허용 경로는 aleph.config.json에서 직접 확인하세요.\n');
  } else {
    writeFileSync(resolve(root, 'src/decider.mjs'), copy, 'utf8');
    process.stdout.write('src/decider.mjs를 검증된 사본으로 되돌렸습니다. 다른 파일·감사 기록은 그대로입니다.\n');
  }
}
