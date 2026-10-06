-- BYTE BACK 가상 메모 표 (3단계 기준 최종 모양)
-- 새 Supabase 프로젝트에서 처음 만들 때 SQL Editor에서 한 번 실행합니다.
-- 2단계 표가 이미 있으면 이 파일 대신 supabase/step3_notes_crud.sql을 실행합니다.
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

-- RLS를 켜고 정책을 만들지 않습니다. anon·authenticated는 한 줄도 읽거나 쓸 수 없습니다.
alter table public.vault_notes enable row level security;
revoke all on table public.vault_notes from anon, authenticated;

-- 서버 함수만 쓰는 service_role(서버 전용 키)에만 읽기·추가·수정·삭제 권한을 줍니다.
grant select, insert, update, delete on table public.vault_notes to service_role;
