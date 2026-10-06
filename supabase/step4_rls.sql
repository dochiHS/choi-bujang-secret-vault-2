-- BYTE BACK 4단계 제작 3: 메모 표(public.vault_notes)에 RLS와 최소 권한
-- 다른 테이블은 건드리지 않습니다. SQL Editor에서 검토 후 한 번 실행합니다.
-- 서버 함수는 서버 전용 키(service_role)를 쓰므로 RLS를 건너뜁니다. 그래서 API는 별도로
-- owner_id = 검증된 사용자 ID 조건을 모든 질의에 겁니다(api/_notes-lib.js). 이 SQL은 그 아래 두 번째 벽입니다.

-- [적용 전] 두 역할의 실제 권한
select grantee, string_agg(privilege_type, ',' order by privilege_type) as grants
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'vault_notes'
   and grantee in ('anon', 'authenticated')
 group by grantee order by grantee;

begin;

-- 1) 기존 권한 회수
revoke all on table public.vault_notes from public, anon, authenticated;

-- 2) 로그인한 사용자 역할에만 네 가지 권한 (anon은 없음)
grant select, insert, update, delete on table public.vault_notes to authenticated;

-- 3) RLS: 자기 행만 (auth.uid() = owner_id)
alter table public.vault_notes enable row level security;

drop policy if exists vault_notes_select_own on public.vault_notes;
drop policy if exists vault_notes_insert_own on public.vault_notes;
drop policy if exists vault_notes_update_own on public.vault_notes;
drop policy if exists vault_notes_delete_own on public.vault_notes;

create policy vault_notes_select_own on public.vault_notes
  for select to authenticated using ((select auth.uid()) = owner_id);
create policy vault_notes_insert_own on public.vault_notes
  for insert to authenticated with check ((select auth.uid()) = owner_id);
create policy vault_notes_update_own on public.vault_notes
  for update to authenticated using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy vault_notes_delete_own on public.vault_notes
  for delete to authenticated using ((select auth.uid()) = owner_id);

commit;

-- [적용 후] 1) 표 권한: anon 행 없음, authenticated는 DELETE,INSERT,SELECT,UPDATE만
select grantee, string_agg(privilege_type, ',' order by privilege_type) as grants
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'vault_notes'
   and grantee in ('anon', 'authenticated')
 group by grantee order by grantee;

-- [적용 후] 2) has_table_privilege로 역할별 실제 권한 (anon 전부 false, authenticated는 앞의 넷만 true)
select r.role, p.priv, has_table_privilege(r.role, 'public.vault_notes', p.priv) as allowed
  from (values ('anon'), ('authenticated')) r(role)
 cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                    ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) p(priv)
 order by r.role, p.priv;

-- [적용 후] 3) 정책 네 개
select policyname, cmd, roles, qual, with_check
  from pg_policies where schemaname = 'public' and tablename = 'vault_notes' order by policyname;
