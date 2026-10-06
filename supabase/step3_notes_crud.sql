-- BYTE BACK 3단계: 로그인 사용자의 가상 메모 추가·수정·삭제를 위한 표 변경
-- 2단계 표(vault_notes)가 이미 있는 프로젝트에서 SQL Editor로 한 번 실행합니다.
-- 메모 문장·비밀값은 이 파일에 넣지 않습니다.

begin;

-- 1) 본문 칸 이름을 API 모양(body)에 맞춥니다.
alter table public.vault_notes rename column content to body;

-- 2) id를 UUID로 바꿉니다. 기존 가상 메모에도 새 UUID가 하나씩 들어갑니다.
alter table public.vault_notes drop constraint if exists vault_notes_pkey;
alter table public.vault_notes drop column id;
alter table public.vault_notes add column id uuid not null default gen_random_uuid();
alter table public.vault_notes add primary key (id);

-- 3) 목록 조회용 색인(로그인 사용자의 메모만 고를 때 씁니다).
create index if not exists vault_notes_owner_created_idx
  on public.vault_notes (owner_id, created_at);

-- 4) 권한: 브라우저 공개 키 역할에는 여전히 아무 권한도 주지 않고,
--    서버 함수가 쓰는 service_role에만 읽기·추가·수정·삭제를 줍니다.
revoke all on table public.vault_notes from anon, authenticated;
grant select, insert, update, delete on table public.vault_notes to service_role;

commit;

-- 확인용 질의
-- select column_name, data_type, column_default from information_schema.columns
--   where table_schema = 'public' and table_name = 'vault_notes' order by ordinal_position;
-- select grantee, privilege_type from information_schema.role_table_grants
--   where table_schema = 'public' and table_name = 'vault_notes' order by grantee;
