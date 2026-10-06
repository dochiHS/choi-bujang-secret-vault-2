-- BYTE BACK 2단계: 가상 메모를 담을 학습용 테이블
-- Supabase SQL Editor에서 한 번 실행합니다. 실제 개인정보·비밀값은 넣지 않습니다.
-- 메모 본문(시드)은 공개 저장소에 남기지 않도록 이 파일에 넣지 않습니다.
-- 시드는 커밋하지 않는 supabase/*.local.sql로 두고 SQL Editor에서 따로 실행합니다.

create table if not exists public.vault_notes (
  id bigint generated always as identity primary key,
  owner_id uuid,               -- 4단계에서 주인 구분에 씁니다. 지금은 auth.users 외래키를 걸지 않습니다.
  sort_order int not null default 0,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

-- RLS를 켜고 정책을 만들지 않습니다. anon·authenticated는 한 줄도 읽을 수 없습니다.
alter table public.vault_notes enable row level security;

-- 브라우저용 공개 키 역할(anon·authenticated)에는 테이블 권한 자체를 주지 않습니다.
revoke all on table public.vault_notes from anon, authenticated;

-- 서버 함수만 쓰는 service_role(서버 전용 키)에만 읽기 권한을 줍니다.
grant select on table public.vault_notes to service_role;

-- 확인용 질의
-- select column_name, data_type from information_schema.columns
--   where table_schema = 'public' and table_name = 'vault_notes';
-- select relrowsecurity from pg_class where oid = 'public.vault_notes'::regclass;  -- true
