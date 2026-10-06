-- BYTE BACK 4단계 제작 1: 기존 가상 메모 세 건을 A 소유로 연결하고, B 소유 시험 메모 한 건을 준비합니다.
-- 학습용 SQL입니다. SQL Editor에서 아래 자리표시자만 바꿔 한 번 실행합니다.
--   A_EMAIL / B_EMAIL  : Supabase Authentication → Users에 있는 A·B 계정 이메일
--   B_NOTE_TITLE / B_NOTE_BODY : 공개해도 되는 가상 문장(실제 개인정보 금지)
-- 이메일과 메모 문장은 공개 저장소에 남기지 않도록, 바꾼 내용은 커밋하지 않습니다.
-- 아직 API와 권한 정책은 바꾸지 않습니다(제작 2·3).

begin;

do $$
declare
  a_id uuid := (select id from auth.users where lower(email) = lower('A_EMAIL'));
  b_id uuid := (select id from auth.users where lower(email) = lower('B_EMAIL'));
  linked int;
begin
  if a_id is null then raise exception 'A 계정을 auth.users에서 찾지 못했습니다.'; end if;
  if b_id is null then raise exception 'B 계정을 auth.users에서 찾지 못했습니다.'; end if;
  if a_id = b_id then raise exception 'A와 B는 서로 다른 계정이어야 합니다.'; end if;

  -- 1) 주인이 없는 기존 가상 메모 중 앞의 세 건을 A 소유로 연결
  update public.vault_notes set owner_id = a_id
   where id in (select id from public.vault_notes
                 where owner_id is null
                 order by sort_order, created_at
                 limit 3);
  get diagnostics linked = row_count;
  if linked <> 3 then raise exception 'A에 연결된 메모가 % 건입니다(3건이어야 함).', linked; end if;

  -- 2) B 소유 시험 메모 한 건 (같은 제목이 이미 있으면 다시 넣지 않음)
  insert into public.vault_notes (owner_id, sort_order, title, body)
  select b_id, 100, 'B_NOTE_TITLE', 'B_NOTE_BODY'
   where not exists (select 1 from public.vault_notes
                      where owner_id = b_id and title = 'B_NOTE_TITLE');
end $$;

commit;

-- 확인: A 3건, B 1건, 주인 없음 1건(나머지 가상 메모)이 나와야 합니다. 이메일은 결과에 내지 않습니다.
-- select case when n.owner_id is null then '주인 없음'
--             when n.owner_id = (select id from auth.users where lower(email) = lower('A_EMAIL')) then 'A'
--             when n.owner_id = (select id from auth.users where lower(email) = lower('B_EMAIL')) then 'B'
--             else '기타' end as owner, count(*)
--   from public.vault_notes n group by 1 order by 1;
