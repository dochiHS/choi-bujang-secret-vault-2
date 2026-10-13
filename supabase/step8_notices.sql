-- BYTE BACK 8단계 제작 1: 강사 공지 구역(vault_notices)
-- 메모 표(vault_notes)와 다른 표에 둡니다. 메모 표와 기존 메모는 건드리지 않습니다.
-- 5단계처럼 anon·authenticated 직접 권한은 주지 않고, 서버 함수(service_role)만 읽고 씁니다.

create table if not exists public.vault_notices (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.vault_notices enable row level security;
revoke all on table public.vault_notices from public, anon, authenticated;
-- 이 프로젝트는 새 표에 service_role 권한을 자동으로 주지 않아, 서버 함수에 필요한 읽기·수정만 줍니다(추가·삭제 없음).
revoke all on table public.vault_notices from service_role;
grant select, update on table public.vault_notices to service_role;

-- 확인용 가상 공지 한 건(실제 개인정보 없음). 이미 있으면 다시 넣지 않습니다.
insert into public.vault_notices (title, body)
select '가상 강사 공지', '8단계 구역 확인용 가상 공지입니다. 학생은 읽기만 할 수 있습니다.'
where not exists (select 1 from public.vault_notices);

-- [확인] 공지 1건 이상, anon·authenticated 권한은 비어 있어야 합니다.
select count(*) as notices from public.vault_notices;
select r.role, string_agg(p.priv, ',' order by p.priv)
         filter (where has_table_privilege(r.role, 'public.vault_notices', p.priv)) as allowed
  from (values ('anon'), ('authenticated'), ('service_role')) r(role)
 cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) p(priv)
 group by r.role order by r.role;

-- BYTE BACK 8단계 제작 3: 강사 명단(vault_instructors)
-- 공지 수정은 이 명단에 있는 사용자(서버가 검증한 로그인 ID)만 할 수 있습니다.
-- 화면·요청 본문의 role은 쓰지 않습니다. 명단은 비워 두면 아무도 공지를 고칠 수 없습니다(기본 거부).
-- 강사를 넣을 때만 Authentication → Users의 사용자 ID로 아래 주석의 insert를 따로 실행합니다(실제 ID는 저장소에 적지 않음).
create table if not exists public.vault_instructors (
  user_id uuid primary key,
  added_at timestamptz not null default now()
);
alter table public.vault_instructors enable row level security;
revoke all on table public.vault_instructors from public, anon, authenticated;
-- 서버 함수는 강사 명단을 읽기만 합니다(명단 추가는 SQL Editor에서만).
revoke all on table public.vault_instructors from service_role;
grant select on table public.vault_instructors to service_role;
-- insert into public.vault_instructors (user_id) values ('<강사 사용자 ID>');

-- [확인] 강사 명단 수(처음에는 0), anon·authenticated 권한은 비어 있어야 합니다.
select count(*) as instructors from public.vault_instructors;
select r.role, string_agg(p.priv, ',' order by p.priv)
         filter (where has_table_privilege(r.role, 'public.vault_instructors', p.priv)) as allowed
  from (values ('anon'), ('authenticated'), ('service_role')) r(role)
 cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) p(priv)
 group by r.role order by r.role;
