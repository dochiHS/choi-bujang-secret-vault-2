-- BYTE BACK 12단계: 가린 서버 기록(vault_request_log)
-- 자료 API 요청마다 한 줄: 요청 ID·시각·메서드·경로 모양·상태 코드·거부 사유·가린 주체·토큰 종류·기기 ID·점검 회차 ID.
-- 토큰·비밀번호·메모 제목/본문·실제 사용자 번호·메모 ID 원문은 남기지 않습니다(주체는 SHA-256 앞 16자리).
-- anon·authenticated 권한은 주지 않고 서버 함수(service_role)만 추가·읽기 합니다(수정·삭제 없음).
create table if not exists public.vault_request_log (
  id bigint generated always as identity primary key,
  request_id uuid not null unique,
  at timestamptz not null default now(),
  method text not null,
  route text not null,
  status integer not null,
  reason text,
  actor_hash text check (actor_hash is null or actor_hash ~ '^[0-9a-f]{16}$'),
  token_kind text check (token_kind is null or token_kind in ('student', 'judge')),
  device_id text check (device_id is null or device_id ~ '^[0-9a-f]{16}$'),
  run_id uuid
);
create index if not exists vault_request_log_actor_idx on public.vault_request_log (actor_hash, at desc);
create index if not exists vault_request_log_run_idx on public.vault_request_log (run_id);
alter table public.vault_request_log enable row level security;
revoke all on table public.vault_request_log from public, anon, authenticated, service_role;
grant select, insert on table public.vault_request_log to service_role;

-- [확인] anon·authenticated는 false, 서버는 select·insert만 true
select (select count(*) from public.vault_request_log) as request_rows,
       has_table_privilege('anon', 'public.vault_request_log', 'SELECT') as anon_select,
       has_table_privilege('authenticated', 'public.vault_request_log', 'SELECT') as auth_select,
       has_table_privilege('service_role', 'public.vault_request_log', 'INSERT') as server_insert,
       has_table_privilege('service_role', 'public.vault_request_log', 'UPDATE') as server_update,
       has_table_privilege('service_role', 'public.vault_request_log', 'DELETE') as server_delete;
