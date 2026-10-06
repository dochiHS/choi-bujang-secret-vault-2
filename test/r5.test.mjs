import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 2,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('stage 2 checks: static files hide notes, API weakness is recorded', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  try {
    globalThis.fetch = async (url, init) => {
      const path = new URL(String(url)).pathname;
      seen.push(path);
      assert.equal(init.redirect, 'error');
      if (path === '/data.json') return new Response('Not Found', { status: 404 });
      if (path === '/') return new Response('<html>자료실</html>', { status: 200 });
      return new Response(JSON.stringify({ notes: [{ title: 'a' }, { title: 'b' }] }), { status: 200 });
    };
    const results = await runAttackChecks(config);
    assert.deepEqual(seen, ['/data.json', '/', '/api/notes']);
    assert.match(results[0].observed, /보이지 않음 \(HTTP 404\)/u);
    assert.match(results[1].observed, /보이지 않음/u);
    assert.match(results[2].observed, /2건을 읽음/u);

    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === '/data.json') return new Response('{"sampleMarker":"SAMPLE_NOTE_1"}', { status: 200 });
      return new Response('<li>실습용 가상 표본</li>', { status: 200 });
    };
    const leaked = await runAttackChecks(config);
    assert.match(leaked[0].observed, /가상 메모가 보임/u);
    assert.match(leaked[1].observed, /문장이 보임/u);
    assert.match(leaked[2].observed, /읽지 못함/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
