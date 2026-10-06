import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (config.step < 2) {
  throw new Error('2단계부터는 공개 data.json을 만들지 않습니다. aleph.config.json의 step을 확인하세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
// 2단계: 메모는 정적 파일이 아니라 서버 함수(/api/notes)가 학습용 DB에서 읽습니다.
await rm(resolve(root, 'public', 'data.json'), { force: true });
console.log('공개 data.json은 만들지 않습니다. 메모는 /api/notes 서버 함수가 읽습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
