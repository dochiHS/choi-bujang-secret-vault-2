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
| 6단계 | 통과 | 판정기 `src/decider.mjs`에 `device_registered` 규칙: 엔진이 확인한 `deviceRegistered`가 정확히 `true`이고 `deviceId`가 16자리 소문자 16진수일 때만 `allow`, 그 밖에는 `deny`·`device_not_registered` |
| 7단계 | 통과 | 판정기에 `step_up_required` 규칙: 믿을 수 있는 출처의 접속 정보에서 지역·시각·네트워크·최근 행동이 평소와 다르면 `step_up`, 5분 안에 다시 확인했으면 `allow`. 지역 하나로 영구 차단하지 않음 |
| 8단계 | 통과 | 판정기 `zone_access` 기본 거부: 메모 구역 자료 한 건(`/notes/:id`) 읽기·수정은 엔진이 확인한 사용자 본인 메모로 확인될 때만 허용, 목록·추가·삭제·모르는 경로·쿼리 기능·학생의 공지 수정은 `deny`·`zone_access_denied`. API는 소유자·구역 재대조 |
| 9단계 | 통과 | 탐지기 `src/detect.mjs`: 같은 신원의 `GET`이 어느 10분 구간에서든 120건을 넘으면(네트워크 정보가 있으면 낯선 네트워크와 함께일 때만) `propose_revocation`·`burst_read` 제안, 그 밖에는 `observe` |
| 10단계 | 제출 | 검증 사본 복구: 메모를 처음 만들 때 사본(`vault_note_backups`)을 남기고, `POST /api/notes/:id/restore`가 본인 메모 한 건만 ID·소유자·내용 해시를 대조해 되돌리거나 다시 만듦. 감사 기록(`vault_audit_log`)은 추가만. 안전 정책 사본(`policy/verified`) 비교·복원 도구 |

## 10단계: 백업에서 자료실을 되살립니다

- 제작 1·2(정책): `policy/verified/`에 8단계 통과 판정기 사본과 목록(`manifest.json`: 판정기 SHA-256·규칙 이름·허용 경로)을 두었습니다. `npm run policy:diff`는 복원할 버전과 바뀔 항목만 보여 주고, `npm run policy:restore -- --yes`는 사본 지문을 검증한 뒤 `src/decider.mjs`만 되돌립니다. 사본이 없거나 지문이 다르면 중단합니다. 운영 반 엔진 정책·다른 서비스 규칙·감사 기록은 건드리지 않습니다.
- 제작 3(메모 한 건 복구): 서비스 `notes`, 경로 **`POST /api/notes/:id/restore`**(`aleph.config.json`의 `restoreRoute`, 배포 `/aleph.json`에도 기록).
  - 메모를 처음 만들 때(`POST /api/notes`) 그 내용을 검증 사본으로 한 번 저장합니다. 이후 수정(PUT)으로는 사본이 바뀌지 않습니다. 기존 메모(시험 계정 A·B)는 `supabase/step10_backup.sql`로 지금 내용을 사본으로 남겼습니다.
  - 복구는 로그인한 본인의 사본만 찾고, 사본 지문(`sha256(UTF-8 "제목바이트수:제목본문")`)을 다시 계산해 맞을 때만 진행합니다. 변조된 메모는 사본 내용으로 되돌리고(`reverted`), 삭제된 메모는 같은 ID·소유자로 다시 만듭니다(`recreated`). 되살린 내용의 지문을 사본과 다시 대조하고, 감사 기록에 한 줄 추가합니다.
  - 다른 사람 메모·사본 없음은 404(`backup_not_found`), 사본 검증 실패는 409(`backup_unverified`), 토큰 없음은 401입니다. 요청 본문의 내용·소유자 값은 쓰지 않습니다. 다른 메모와 감사 기록은 바꾸지 않습니다.
- 확인: `npm run test:r10`(가짜 토큰·메모리 자료) — B 메모 변조→복구, 삭제→재생성, 지문 일치, A 메모 보존, 감사 기록 2건, B의 A 메모 복구·조회 거부, 사본 변조 시 중단.

### 복구 뒤 다시 확인할 순서 (제작 4)

| 순서 | 확인 | 정상 | 금지(거부되어야 함) | 상태 |
|---|---|---|---|---|
| 1 | 시험 계정 B 메모 복구 | `POST /api/notes/:id/restore` 200, 지문이 사본과 같음 | 다른 계정이 B 메모 복구 404 | 로컬 연습만 실행(`test:r10`), 실제 배포 미실행 |
| 2 | 1~2단계 공개 자료 | — | `/data.json` 404, 첫 화면에 메모 문장 없음 | `npm run bundle` 자기 점검으로 실행 |
| 3 | 3~5단계 로그인·소유자 | A·B 자기 메모 읽기 | 토큰 없음 401, B의 A 메모 404, 공개 키 직접 조회 거절 | `test:r5` 로컬 실행, 실제 계정 재시험 미실행 |
| 4 | 6~8단계 판정기 | 등록 기기 본인 메모 allow | 미등록 기기 deny, 복합 이상 step_up, B의 A 메모·목록·공지 수정 deny | `decider:test`·`fixture:7` 로컬 실행 |
| 5 | 9단계 탐지 | 정상 조회 observe | 10분 121건 이상 propose_revocation | `detect:test` 로컬 실행 |
| 6 | 정책 사본 대조 | `policy:diff`가 "같습니다" | — | 로컬 실행 |

실제 배포에서 시험 계정으로 다시 해 본 결과는 위 표에 적지 않았습니다(미실행). 결과를 꾸미지 않습니다.

## 9단계: 도플갱어를 찾고 권한을 거둡니다

- 제작 1: `detect(events)`는 사건에서 가명 사용자(`identity.sub`)·기기 ID·요청 종류(`method`)·시각(`at`)·판정·네트워크만 꺼냅니다. 모양이 틀린 사건은 세지 않고, 메모 내용·토큰·실명은 읽거나 남기지 않습니다.
- 제작 2: 신원별 `GET`만 모아 어느 10분 구간에서든 120건을 넘는지 봅니다(정확히 120건은 제외, 다른 사용자 사건은 합치지 않음). 사건에 네트워크 정보가 있으면 그 구간에 평소와 다른 네트워크가 함께 있을 때만 의심입니다. 지역 하나로는 확정하지 않습니다.
- 제작 3: 의심이면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`(확인된 기기가 하나면 `deviceId` 포함), 아니면 `{ action: 'observe' }`. 회수 API를 부르거나 기기 권한을 바꾸지 않습니다. 판정기 응답 형식은 그대로입니다.
- 확인: `npm run detect:test` 6건 통과(가상 사건 연습, 심판 판정 아님).

## 8단계: 자료마다 갈 수 있는 구역을 나눕니다

- 제작 1(자원 ID): 메모와 강사 공지를 다른 구역·다른 표로 나눴습니다. 서버가 경로를 보고 응답 머리글 `X-Resource-Id`에 `note:list`·`note:<uuid>`·`notice:list`·`notice:<uuid>`를 붙입니다(브라우저 값으로 정하지 않음). 공지 API `GET /api/notices`, `GET·PUT /api/notices/:id`를 더했고 표는 `supabase/step8_notices.sql`의 `vault_notices`입니다. 기존 메모 자료·주소는 그대로이고 화면 메뉴는 바꾸지 않았습니다.
- 제작 2(판정기 `resource_zone`): 엔진이 확인한 메서드·경로 모양(`route`)·실제 경로(`path`)가 구역표와 정확히 맞을 때만 다음 검사로 넘어갑니다. 구역표는 메모 `GET·POST /notes`, `GET·PUT·DELETE /notes/:id`, 공지 `GET /notices`, `GET /notices/:id`입니다(`/api` 접두어는 같은 경로로 봄).
  - 공지 추가·수정·삭제 → `deny`·`zone_forbidden`. 계약에 강사 역할 값이 없어 판정기는 누구에게도 허용하지 않습니다.
  - 표에 없는 경로, 메서드와 경로 모양 불일치, 깊이·글자가 다른 실제 경로, `:id` 자리의 기능 이름(`export`·`admin`·`all` 등) → `route_not_allowed`. 쿼리 문자열이 있으면 `query_not_allowed`.
  - 재제출 기록: 첫 판정 36점(`S08_OTHER_ZONE_ALLOWED`). 판정기에 사용자(`subjectId`)·서비스 대조를 더했습니다: `subjectId`가 없으면 `not_own_resource`, 메모 구역은 `service: notes`만·공지 구역은 `service: notices`만, 메모 `:id`가 요청자와 같은 형식의 다른 주체 ID(예: `learner_b`가 `/notes/learner_a`)면 `not_own_resource`. 같은 판정이 계속되어 실험해 보니 판정기가 아니라 자료 API 처리기의 소유자 재대조가 빠져 있던 것이 원인이었습니다(아래 제작 3).
  - 순서: 6단계 기기 → 8단계 구역 → 7단계 이상 접속. 메모 소유자 최종 대조는 아래 API가 한 번 더 합니다.
- 제작 3(API 재대조): 메모는 DB 조건(`owner_id`)과 별개로 꺼낸 행의 소유자를 검증된 사용자 ID와 다시 비교합니다. 재제출에서 이 비교를 DB 도구 안뿐 아니라 **처리기(응답 직전)** 에도 넣었습니다. DB가 다른 소유자의 행을 돌려줘도 목록에서 빠지고, 한 건 읽기·수정은 404(`not_owner_or_missing`)이며, 응답에는 소유자 값을 내보내지 않습니다. 공지 수정은 DB 강사 명단 `vault_instructors`에 검증된 사용자 ID가 있을 때만 됩니다(처음엔 비어 있어 아무도 못 고침). 화면 메뉴·요청 본문의 `role`·`isInstructor`는 읽지 않습니다. 거부 응답에 짧은 사유 `reason`(`not_owner_or_missing`·`not_instructor`·`owner_change`·`not_found`·`bad_input`)을 남깁니다.

### 8단계 확인 절차

1. Supabase SQL Editor에서 `supabase/step8_notices.sql`을 한 번 실행합니다(공지 표·가상 공지 1건·빈 강사 명단, 두 표 모두 anon·authenticated 권한 없음).
2. `npm run test:r8` → B의 A 메모 직접 조회 404(`not_owner_or_missing`), 본문에 `role: instructor`를 넣은 학생의 공지 수정 403(`not_instructor`), 강사 명단 사용자의 수정 200, 자원 ID 구분을 가짜 토큰으로 확인합니다(실제 심판 판정 아님).
3. `npm run decider:test`·`npm run fixture:7`이 그대로 통과하고, `npm run bundle`의 `decider_student_notice_edit`·`decider_function_path_in_id`가 `deny`입니다.
4. 배포 화면: A 로그인 시 자기 메모만 보이는 것은 그대로입니다. 시크릿 창에서 토큰 없이 `/api/notices`를 열면 401입니다.

## 7단계: 평소와 다른 접속은 다시 확인합니다

- 제작 1(출처 구분): `signals.source`가 `none`이면 "정보 없음"으로 보고 정상·이상 어느 쪽으로도 채우지 않습니다(현재 실제 경로). `judge_fixture`는 심판·연습용 가상 사건으로 읽습니다. 그 밖의 출처(예: 클라이언트 헤더)는 믿지 않아 `region: local`처럼 정상값을 적어 와도 정상으로 승격되지 않고 추가 확인으로 갑니다. 출처는 믿을 만한데 지역·네트워크·시각 값이 없거나 형식이 틀리면 "확인 불가"로 보고 추가 확인으로 보냅니다.
- 제작 2(규칙 `step_up_required`): 아래 중 하나라도 있으면 `step_up`·`step_up_required`입니다. 거부(`deny`)가 아니라 다시 본인 확인이라 정상 사용자를 영구 차단하지 않습니다.
  - 지역이 평소(`local`)와 다름 / 네트워크가 평소(`usual`)와 다름 / 시각이 06~22시 밖
  - 최근 10분 사건 중 위험 종류(`risk`·`bulk`·`mass`·`burst`·`anomal`·`unusual`·`fail`)가 있거나 횟수 합이 10 이상
- 다시 확인: `stepUp.verified === true`이고 `authAgeSeconds`가 0~300초 정수일 때만 이상 신호가 있어도 `allow`합니다. 확인하지 않았거나(`false`), 오래됐거나(301초 이상), 값이 이상하면 다시 `step_up`입니다.
- 6단계 `device_registered`는 그대로 먼저 검사합니다(미등록 기기는 이상 신호와 상관없이 `deny`).
- 제작 3: 계약(`docs/DECIDER_REQUEST.md`)에는 엔진이 확인한 다시 로그인 나이 `stepUp.authAgeSeconds`가 있어 판정기는 이 값으로 다시 판정합니다. 실제 재로그인 화면과 확인 전 자료 차단은 제공 엔진이 새 로그인 시각을 검증하는 환경에서만 시험할 수 있어 **미실행**입니다. 토큰 원문은 기록하지 않습니다.

### 7단계 확인 절차

1. `npm run decider:test` → 네 줄 모두 `통과`(등록 기기 정상, 미등록 기기, 복합 이상 접속, 다시 확인한 복합 이상 접속). `npm run fixture:7` → `정상 사건: allow`, `복합 이상 사건: step_up`. 둘 다 가상 요청 연습이며 심판 판정이 아닙니다.
2. 거부·추가 확인되어야 할 것: 지역만 급변, 새벽 3시, 낯선 네트워크+대량 수정, 다시 확인 안 한 토큰, 800초 전 재확인, 클라이언트 헤더 출처 → 모두 `step_up`. `npm run bundle`의 직접 점검 `decider_*` 줄에서 응답을 볼 수 있습니다.
3. 등록 기기의 평소 접속과 실제 경로(`source: none`)는 `allow`라 배포 화면은 1~6단계와 같습니다.

## 6단계: 등록한 기기만 자료실에 들어옵니다

- 제작 1 점검: 판정 요청(`docs/DECIDER_REQUEST.md`, `aleph.decision.v1`)에서 사용자는 `subjectId`(엔진이 만든 가명 주체 ID), 기기는 `deviceId`(16자리 소문자 16진수, 개인키 아님), 기기 등록 여부는 최상위 `deviceRegistered`(불리언)로 들어옵니다. 인증서·CA·서명 키는 새로 만들거나 Git에 넣지 않았습니다.
- 제작 2: `src/decider.mjs`의 `RULE_IDS`를 `['device_registered']`로 바꾸고, `decide(request)`가 아래를 **모두** 만족할 때만 `allow`(`approved`)를 돌려줍니다. 하나라도 어긋나면 `deny`·`device_not_registered`(기본 거부).
  - `schema`가 `aleph.decision.v1`
  - `deviceRegistered === true` (값 없음·`false`·문자열 `"true"`·`1`은 모두 거부)
  - `deviceId`가 계약 형식 `^[0-9a-f]{16}$`
- 판정기는 로그인·기기 등록 여부·동작·경로만 판단하고, 브라우저가 보낸 사용자 번호·역할·기기 상태는 쓰지 않습니다. 계약에 없는 `request.device`·`request.identity`·`request.geo`·`request.role`도 쓰지 않습니다. 다른 파일을 import하지 않아 단독 실행됩니다.
- 자료실 주소·화면·API(1~5단계)는 그대로입니다. 클라이언트 인증서(mTLS)와 사용자 토큰-기기 묶음은 반 엔진이 판정기보다 먼저 확인합니다. 판정기의 `allow`가 그 검사를 되돌리지 못합니다.
- `src/attack-check.mjs`에 판정기 가상 요청 다섯 건(등록 기기 허용, 미등록·값 없음·문자열 true·형식 다른 기기 ID 거부)을 추가했습니다. 로컬 실행 결과이며 심판 판정이 아닙니다.

### 6단계 확인 절차

1. `npm run decider:test` → `통과 · 등록 기기의 정상 요청`, `통과 · 미등록 기기의 가상 요청`이 나옵니다(가상 요청 연습, 심판 판정 아님).
2. 거부되어야 할 것: `deviceRegistered: false`, 값 없음, `"true"`, 형식이 다른 `deviceId` → 모두 `deny`·`device_not_registered`. `npm run bundle`의 직접 점검 `decider_*` 다섯 줄에서 응답을 볼 수 있습니다.
3. 등록 기기에서 기존 화면: 배포 주소를 열면 1~5단계와 같은 로그인 화면과 내 메모가 그대로 보입니다.
4. 미등록 기기 공격(가상 기기 사건 직접 입력 등)은 심판이 보냅니다. 따로 설치할 접속 프로그램은 없습니다.

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
