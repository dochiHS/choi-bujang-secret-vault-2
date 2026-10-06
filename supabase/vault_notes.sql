-- BYTE BACK 가상 메모 표 (4단계 기준 최종 모양)
-- 새 Supabase 프로젝트에서 처음 만들 때 SQL Editor에서 한 번 실행합니다.
-- 이미 있는 표는 이 파일 대신 supabase/step3_notes_crud.sql → step4_rls.sql 순서로 실행합니다.
-- 실제 개인정보·비밀값·메모 본문(시드)은 이 파일에 넣지 않습니다.

create table if not exists public.vault_notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid,               -- 서버가 확인한 로그인 사용자 ID. auth.users 외래키는 걸지 않습니다.
  sort_order int not null default 0,
  title text not null,
  body text not null,
  created_at timestamptz not null default now()
);

create index if not exists vault_notes_owner_created_idx
  on public.vault_notes (owner_id, created_at);

-- RLS: 로그인한 사용자(authenticated)는 자기 행(auth.uid() = owner_id)만. anon은 권한 없음.
alter table public.vault_notes enable row level security;
revoke all on table public.vault_notes from public, anon, authenticated;
grant select, insert, update, delete on table public.vault_notes to authenticated;
create policy vault_notes_select_own on public.vault_notes
  for select to authenticated using ((select auth.uid()) = owner_id);
create policy vault_notes_insert_own on public.vault_notes
  for insert to authenticated with check ((select auth.uid()) = owner_id);
create policy vault_notes_update_own on public.vault_notes
  for update to authenticated using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy vault_notes_delete_own on public.vault_notes
  for delete to authenticated using ((select auth.uid()) = owner_id);

-- 서버 함수가 쓰는 service_role(서버 전용 키)은 RLS를 건너뜁니다. API가 owner_id 조건을 직접 겁니다.
grant select, insert, update, delete on table public.vault_notes to service_role;
