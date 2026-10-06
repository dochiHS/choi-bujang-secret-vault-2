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
| 3단계 | 이 커밋 | Supabase Auth 이메일·비밀번호 로그인·로그아웃, 서버의 토큰 검사(`src/verify-login.mjs`), 로그인 사용자의 가상 메모 추가·수정·삭제 |

## 3단계: 진짜 로그인을 붙임

- 화면(`public/index.html`)은 공식 SDK `@supabase/supabase-js@2.117.2`(jsDelivr ESM)의 `signInWithPassword`·`signOut`으로 로그인·로그아웃합니다. 실패하면 이유(예: 이메일 또는 비밀번호가 맞지 않음)를 화면에 보여 줍니다. 화면 코드에는 공개용 Project URL과 publishable key만 있습니다.
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

### 남은 약점 (4단계에서 막을 것)

- 서버는 로그인 여부만 확인하고 메모 주인을 비교하지 않습니다. 그래서 B로 로그인해도 A 메모의 `id`를 알면 `GET`·`PUT`·`DELETE /api/notes/:id`가 됩니다(목록은 자기 메모만 보임).
- 2단계 이전에 만든 가상 메모 네 건은 `owner_id`가 비어 있어 누구의 목록에도 나오지 않습니다.

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

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
