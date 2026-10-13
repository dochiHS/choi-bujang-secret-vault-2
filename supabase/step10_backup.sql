-- BYTE BACK 10단계: 침해 전에 검증한 메모 사본(vault_note_backups)과 감사 기록(vault_audit_log)
-- 메모 표(vault_notes)·공지·강사 명단은 바꾸지 않습니다. anon·authenticated 권한은 주지 않고 서버 함수(service_role)만 씁니다.

create table if not exists public.vault_note_backups (
  note_id uuid primary key,          -- 사본은 메모 한 건당 하나(처음 만든 검증된 내용)
  owner_id uuid not null,
  title text not null,
  body text not null,
  content_sha256 text not null,      -- sha256(UTF-8 '제목바이트수:제목본문'), 서버 noteHash와 같은 방식
  backed_up_at timestamptz not null default now()
);
alter table public.vault_note_backups enable row level security;
revoke all on table public.vault_note_backups from public, anon, authenticated, service_role;
grant select, insert on table public.vault_note_backups to service_role;   -- 사본은 추가·읽기만(수정·삭제 없음)

create table if not exists public.vault_audit_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  action text not null,
  note_id uuid,
  actor_id uuid,
  previous_state text,
  content_sha256 text
);
alter table public.vault_audit_log enable row level security;
revoke all on table public.vault_audit_log from public, anon, authenticated, service_role;
grant select, insert on table public.vault_audit_log to service_role;      -- 감사 기록은 추가·읽기만

-- 이미 있는 메모(시험 계정 A·B 포함)의 지금 내용을 침해 전 검증 사본으로 한 번 남깁니다(있으면 건너뜀).
-- 지문은 서버 noteHash와 같은 방식: sha256(UTF-8 '제목바이트수:' || 제목 || 본문)
insert into public.vault_note_backups (note_id, owner_id, title, body, content_sha256)
select n.id, n.owner_id, n.title, n.body,
       encode(extensions.digest(convert_to(octet_length(convert_to(n.title, 'UTF8'))::text || ':' || n.title || n.body, 'UTF8'), 'sha256'), 'hex')
  from public.vault_notes n
 where n.owner_id is not null
on conflict (note_id) do nothing;

-- [확인] 사본 수, 감사 기록 수, 권한(anon·authenticated는 모두 false여야 함)
select (select count(*) from public.vault_note_backups) as backups,
       (select count(*) from public.vault_audit_log) as audit_rows,
       has_table_privilege('anon', 'public.vault_note_backups', 'SELECT') as anon_backups,
       has_table_privilege('authenticated', 'public.vault_audit_log', 'SELECT') as auth_audit,
       has_table_privilege('service_role', 'public.vault_note_backups', 'INSERT') as server_backup_insert,
       has_table_privilege('service_role', 'public.vault_note_backups', 'UPDATE') as server_backup_update,
       has_table_privilege('service_role', 'public.vault_audit_log', 'DELETE') as server_audit_delete;
