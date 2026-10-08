# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 단계 기록

| 단계 | 상태 | 한 일 |
| --- | --- | --- |
| 1단계 | 통과 | 시작 틀을 그대로 배포해 `/`와 `/data.json`에서 가상 메모 네 건이 공개된 것을 확인 |
| 2단계 | 통과 | 메모를 정적 파일·코드에서 빼고 학습용 Supabase 테이블과 서버 함수 `/api/notes`로 옮김. 재제출로 보안 헤더(`X-Content-Type-Options: nosniff`) 추가 |
| 3단계 | 통과 | Supabase Auth 이메일·비밀번호 로그인·로그아웃, 서버의 토큰 검사(`src/verify-login.mjs`), 로그인 사용자의 가상 메모 추가·수정·삭제 |
| 4단계 | 통과 | API가 검증된 사용자 ID와 메모 `owner_id`를 비교(남의 메모 404, 소유자 변경 403), 메모 표에 RLS 자기 행 정책과 최소 권한 |
| 5단계 | 통과 | 브라우저는 우리 서버 함수만 부름(로그인도 `/api/auth/*`로 이동, 화면에 Supabase 키·SDK 없음), 메모 표의 PUBLIC·anon·authenticated 직접 권한 회수, `originalApiUrl` 기록 |

## 5단계: 자료 요청을 서버 한곳으로

- 제작 1 점검 결과: 4단계까지 화면이 메모 자료를 Supabase에서 직접 읽거나 고치는 곳은 **없었습니다**(메모는 처음부터 `/api/notes`만 호출, Supabase는 로그인에만 사용).
- 그다음 로그인도 서버로 옮겼습니다. `POST /api/auth/login`·`/api/auth/refresh`·`/api/auth/logout`(`api/_auth-lib.js`)이 브라우저 대신 Supabase Auth에 요청하고, 화면은 받은 토큰을 `Authorization: Bearer`로 `/api/notes`에 보냅니다. 그래서 화면 코드(`public/index.html`)에는 Supabase 주소·공개 키·SDK가 없습니다. 카드 제작 1의 "Auth 호출은 그대로" 이후에 따로 한 변경이며, 100점 조건(화면에 공개 키 없음)을 채우기 위해서입니다. 비밀번호는 서버 함수가 Supabase로 넘기기만 하고 저장·기록하지 않습니다.
- 서버 함수의 로그인 검사(`src/verify-login.mjs`)와 소유자 검사(4단계)는 그대로입니다.
- 빌드(`scripts/build-public.mjs`)가 배포 `/aleph.json`에 `aleph.config.json`의 `allowedRoutes`와 `originalApiUrl`도 함께 적습니다(비밀값 없음).
- 제작 2: `supabase/step5_revoke_direct.sql`로 메모 표의 `PUBLIC·anon·authenticated` 권한을 모두 회수했습니다. 이제 공개 키만으로도, 공개 키+시험 계정 토큰으로도 원본 자료 API(`aleph.config.json`의 `originalApiUrl` = `https://krdfqgaagoozlgdnsbww.supabase.co/rest/v1/vault_notes`)를 직접 읽거나 고칠 수 없습니다(42501). 서버 함수는 서버 전용 키(service_role)를 써서 그대로 동작합니다. 4단계 RLS 정책은 예비 벽으로 남겨 두었습니다.

### 5단계 확인 절차

1. 시크릿 창: 로그인 칸만 보이고, 페이지 소스(Ctrl+U)에 `sb_publishable_`·`supabase.co`가 없습니다. 개발자 도구 Network 탭에는 이 사이트의 `/api/...` 요청만 보입니다.
2. A 로그인: 자기 메모 세 건, 추가·수정·삭제 정상. B 로그인: B 메모만, A 메모 번호로 요청하면 404. 틀린 비밀번호는 실패 이유 표시.
3. 거부되어야 할 것: 공개 키로 `originalApiUrl` 직접 조회·수정 → 401(42501), 공개 키+A/B 토큰으로 직접 조회·수정 → 401(42501), 토큰 없는 `/api/notes` → 401 JSON.
4. `npm run test:r5`: 로그인 서버 함수, 공개 파일에 키 없음, 소유자 검사를 가짜 의존성으로 확인합니다(실제 심판 판정 아님).

## 4단계: 로그인해도 내 자료만

- API(`api/_notes-lib.js`)의 모든 DB 질의에 `owner_id = 서버가 검증한 사용자 ID` 조건이 붙습니다. 목록은 자기 메모만, 한 건 읽기·수정·삭제는 자기 메모일 때만 됩니다. 남의 메모는 없는 메모와 똑같이 `404`라 존재 여부도 알려 주지 않습니다(기본 거부).
- URL·본문의 `owner_id`·`userId`는 믿지 않습니다. 추가할 때는 검증된 ID로 저장하고, 수정 본문이 다른 사람을 소유자로 가리키면 `403`으로 거절합니다. 수정은 `owner_id`를 바꾸지 않으므로 기존 행과 새 행 모두 본인 소유입니다. 남의 메모 `id`로 `POST`해도 덮어쓰지 못하고 `409`입니다.
- 서버 함수는 서버 전용 키를 써서 RLS를 건너뛰므로 위 조건이 1차 방어입니다. DB에는 두 번째 벽으로 `supabase/step4_rls.sql`을 적용했습니다: `public, anon, authenticated` 권한을 모두 회수한 뒤 `authenticated`에 `SELECT·INSERT·UPDATE·DELETE`만 주고, 네 동작 모두 `auth.uid() = owner_id`일 때만 허용(`SELECT·DELETE`는 `USING`, `INSERT`는 `WITH CHECK`, `UPDATE`는 둘 다). `anon`은 권한이 없어 공개 키로 Supabase Data API를 직접 불러도 메모를 읽지 못합니다.
- 확인용 소유 관계는 `supabase/step4_owner_seed.sql`(자리표시자만 커밋)로 만들었습니다: 기존 가상 메모 세 건은 A 소유, B 소유 시험 메모 한 건. 이메일과 메모 문장은 저장소에 넣지 않았습니다.

### 4단계 확인 절차

1. A로 로그인: 자기 메모 세 건이 보이고, 추가·수정·삭제가 됩니다. B의 시험 메모는 보이지 않습니다.
2. B로 로그인(다른 창): B 시험 메모 한 건만 보이고 A 메모는 보이지 않습니다. 자기 메모 추가·수정·삭제는 됩니다.
3. 거부되어야 할 것: B 토큰으로 A 메모 `id`에 `GET`·`PUT`·`DELETE` → `404`, 소유자를 바꾸는 `PUT` → `403`, 토큰 없는 요청 → `401`, 공개(anon) 키로 `…/rest/v1/vault_notes` 직접 조회 → 거절 또는 0건.
4. `npm run test:r5`가 교차 접근·소유자 변경·DB 질의의 owner 조건을 가짜 토큰과 메모리 DB로 검사합니다(실제 심판 판정 아님).

## 3단계: 진짜 로그인을 붙임

- 3단계 당시 화면(`public/index.html`)은 공식 SDK `@supabase/supabase-js@2.117.2`(jsDelivr ESM)의 `signInWithPassword`·`signOut`으로 로그인·로그아웃했습니다(5단계에서 서버 함수로 이동). 실패하면 이유(예: 이메일 또는 비밀번호가 맞지 않음)를 화면에 보여 줍니다. 화면 코드에는 공개용 Project URL과 publishable key만 있습니다.
- 자료 API는 `Authorization: Bearer <access_token>`만 믿습니다. 시작 틀의 `createLoginVerifier`(`src/verify-login.mjs`, 수정하지 않음)로 토큰을 검사하고, 브라우저가 보낸 `userId`·`role`·`owner_id`는 읽지 않습니다. 토큰이 없거나 검사에 실패하면 자료 없이 `401`과 JSON 오류 문구를 돌려줍니다.
- 검사에 쓴 발급자 정보는 `aleph.config.json`의 `identityProvider`(발급자 `…/auth/v1`, 대상 `authenticated`, 공개키 주소 `…/auth/v1/.well-known/jwks.json`)에 있습니다. 비밀 키는 넣지 않습니다.
- 함수가 `aleph.config.json`을 읽을 수 있게 `vercel.json`의 `functions."api/**/*.js".includeFiles`에 넣었습니다. 모든 응답에 `X-Content-Type-Options: nosniff`가 붙습니다.

### API (허용 경로는 `aleph.config.json`의 `allowedRoutes`)

| 요청 | 결과 |
| --- | --- |
| `GET /api/notes` | 로그인 사용자의 메모 배열 `[{ id, title, body }]` |
| `POST /api/notes` `{ id?, title, body }` | `201 { id }`. `id`(UUID)가 없으면 서버가 만듦. 같은 `id`는 `409` |
| `GET /api/notes/:id` | `{ id, title, body }`, 없으면 `404` |
| `PUT /api/notes/:id` `{ title, body }` | 고친 `{ id, title, body }`, 없으면 `404` |
| `DELETE /api/notes/:id` | `204`, 지운 뒤 `GET`은 `404` |

- 추가할 때 `owner_id`는 서버가 확인한 로그인 사용자 ID로 저장합니다(`api/_notes-lib.js`).
- 표 변경은 `supabase/step3_notes_crud.sql`(본문 칸 `content`→`body`, `id`를 `uuid` 기본값 `gen_random_uuid()`로, `service_role`에만 읽기·추가·수정·삭제 권한)입니다. 새로 만들 때는 `supabase/vault_notes.sql` 하나로 같은 모양이 됩니다.

### 3단계 당시 남은 약점 (4단계에서 막음)

- 3단계 서버는 로그인 여부만 확인해서, B도 A 메모의 `id`를 알면 읽기·수정·삭제가 됐습니다. 4단계에서 소유자 비교와 RLS로 막았습니다.

### 3단계 확인 절차

1. 시크릿 창에서 배포 주소를 열면 로그인 칸만 보이고 메모는 보이지 않습니다. 같은 창에서 `/api/notes`를 열면 `401`과 `{"error":"로그인이 필요합니다."}`가 보입니다.
2. A 계정(Supabase Authentication → Users에서 학생이 직접 만듦)으로 로그인하면 "내 메모"와 추가 칸이 보입니다. 틀린 비밀번호를 넣으면 실패 이유가 보입니다.
3. 가상 메모를 추가 → 수정 → 삭제(삭제는 버튼을 두 번)하고, 로그아웃하면 다시 로그인 칸만 보입니다.
4. 자기 점검 `npm run bundle`은 토큰 없음·위조 토큰 요청이 거절되는지 실제로 보내 기록합니다. A 로그인 확인은 비밀번호가 필요해 미실행으로 남깁니다.

## 2단계: 자료를 코드 밖으로 옮김

- `data.json`과 `public/data.json`을 저장소에서 지웠고, 빌드(`npm run build`)는 더 이상 공개 `data.json`을 만들지 않습니다.
- 메모는 Supabase 테이블 `vault_notes`에 있습니다. 표 구조는 `supabase/vault_notes.sql`입니다(`owner_id uuid` 칸, auth.users 외래키 없음, RLS 켬, anon·authenticated 권한 없음).
- 메모 본문(시드)은 공개 저장소에 남기지 않도록 커밋하지 않는 `supabase/*.local.sql`로만 두고 SQL Editor에서 실행했습니다.
- 화면은 Vercel 서버 함수 `api/notes.js`를 부릅니다. 함수는 Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(서버 전용)를 읽고, 키를 브라우저 파일·응답·로그에 넣지 않습니다.

### 2단계 당시 남은 약점 (3단계에서 막음)

- 2단계의 `/api/notes`는 로그인 없이 누구나 불러 가상 메모 네 건을 읽을 수 있었습니다. 3단계에서 토큰 검사로 막았습니다.

### 메모 문장 검색 확인 절차

1. 현재 배포 파일: 시크릿 창에서 `/data.json`을 열어 404인지, `/`의 페이지 소스(Ctrl+U)에 `실습용 가상`이 없는지 봅니다. 화면에는 `/api/notes`로 읽은 카드 네 개가 보여야 합니다.
2. GitHub 최신 파일: 저장소 기본 브랜치에서 `실습용 가상`을 코드 검색하거나, 로컬에서 `git grep -n "실습용 가상" HEAD`를 실행해 결과가 없는지 봅니다.
3. 자기 점검: `npm run bundle`이 `src/attack-check.mjs`로 `/data.json`·`/`·`/api/notes`를 비로그인으로 요청한 결과를 기록합니다. 이 결과는 심판 판정이 아닙니다.

### 옛 공개 이력의 한계

- 1단계 커밋(`0f9a3c9`)과 그 커밋으로 만든 옛 Vercel 배포에는 가상 메모가 그대로 남아 있습니다. 최신 파일에서 지웠다고 과거 노출이 해소된 것은 아닙니다. 실제 자료였다면 이력 정리와 옛 배포 삭제, 노출된 값 교체가 따로 필요합니다.

### 다시 실행하는 방법

1. Supabase SQL Editor에서 `supabase/vault_notes.sql`을 실행하고, 가상 메모 시드를 넣습니다.
2. Vercel 프로젝트 Settings → Environment Variables에 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`를 넣고 Redeploy 합니다.
3. 정상(3단계 기준): 로그인 전 `/`에는 로그인 칸만, A 로그인 뒤에는 A의 메모. 거부되어야 할 것: `/data.json`은 404, 토큰 없는 `/api/notes`는 401.
4. 3단계부터는 `supabase/step3_notes_crud.sql`을 한 번 더 실행하고, Supabase Authentication → Users에서 확인용 A 계정을 직접 만듭니다(비밀번호는 저장소·채팅에 적지 않음).
5. 4단계부터는 B 계정도 만들고 `supabase/step4_owner_seed.sql`의 자리표시자를 바꿔 실행한 뒤 `supabase/step4_rls.sql`을 실행합니다.
6. 5단계부터는 `supabase/step5_revoke_direct.sql`을 실행합니다. Vercel 환경변수는 그대로 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 두 개뿐입니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 보너스 XDR-01: 무차별 로그인 공격을 잡아 냅니다

공식 경보 묶음(`xdr/fixtures/*`, `scripts/xdr-run.mjs`, `test/xdr-run.test.mjs`)은 원본 시작 틀 `main`에서 그대로 가져왔고 고치지 않았습니다.

| 파일 | 하는 일 |
| --- | --- |
| `xdr/brute-force/read-alerts.mjs` | 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑음. 비밀값처럼 보이는 값은 `[가림]` |
| `xdr/brute-force/patterns.json` | MITRE ATT&CK T1110 근거 패턴 3개(T1110.001 반복 대입, T1110.003 계정 대입, 적은 실패) |
| `xdr/brute-force/decide.mjs` | `decide(alert)` → `{action, confidence, reason}`. 0.85↑ block · 0.5↑ alert · 그 아래 record. 애매한 경보만 Jev(`XDR_JEV_URL`)에 묻고, 응답이 없으면 alert |
| `xdr/brute-force/ztna-link.mjs` | block 경보 주소만 `deny-rules.json`의 XDR 거부 규칙으로(만료 60분·근거 경보 번호). alert는 `xdr/alerts.log`에 한 줄씩. 판정기 앞 확인 단계 `xdrPreCheck()` 제공 |

`src/decider.mjs`의 기존 규칙은 고치지 않았습니다. 판정기 요청 계약(`docs/DECIDER_REQUEST.md`)에는 출발 주소가 없어서, XDR 거부 규칙은 판정기 앞에서 주소로 한 번 더 확인하는 별도 부품으로 둡니다.

다시 실행하기:

```
npm run xdr:run -- brute-force   # result.json 생성
npm run xdr:link                 # 거부 규칙·알림 로그·다시 흘려 보기
npm run xdr:test                 # 공식 경보 묶음 검사
```

최근 실행: block 10 · alert 9 · record 9, 정상 이벤트 차단 0건, 다시 흘린 경보 28건 중 어긋남 0건(로컬 자기 점검이며 심판 판정이 아님).

## 보너스 XDR-02: 웹 주입 공격을 잡아 냅니다

XDR-01과 같은 구조입니다(`xdr/web-injection/`). 근거는 MITRE ATT&CK T1190이고, 패턴은 SQL 주입·스크립트 주입·경로 거슬러 올라가기·명령 구분자 반복과 한 번뿐인 의심 입력 5개입니다. 같은 주소에서 주입 표기가 8번 이상 반복된 경보만 block, 한 번뿐인 의심 입력은 Jev에 묻고 응답이 없으면 alert, 태그 없는 정상 요청은 record입니다. `decide.mjs`는 다른 파일을 import하지 않아 단독으로 실행됩니다.

```
npm run xdr:run -- web-injection
node xdr/web-injection/ztna-link.mjs
```

최근 실행: block 8 · alert 9 · record 9, 정상 이벤트 차단 0건, 다시 흘린 경보 26건 중 어긋남 0건(로컬 자기 점검이며 심판 판정이 아님).
