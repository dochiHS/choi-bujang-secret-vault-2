-- BYTE BACK 5단계 제작 2: 메모 표의 직접 접근 권한 회수
-- 브라우저와 공격자가 공개 키(+로그인 토큰)로 Supabase Data API를 직접 부르는 길을 닫습니다.
-- 메모는 이제 서버 함수(서버 전용 키 = service_role)만 읽고 씁니다. 다른 테이블은 건드리지 않습니다.
-- 4단계의 RLS 정책은 그대로 둡니다(권한이 없으면 쓰이지 않지만, 나중에 권한을 잘못 줘도 자기 행으로 제한).

-- [적용 전] 역할별 실제 권한
select r.role, string_agg(p.priv, ',' order by p.priv)
         filter (where has_table_privilege(r.role, 'public.vault_notes', p.priv)) as allowed
  from (values ('anon'), ('authenticated'), ('service_role')) r(role)
 cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                    ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) p(priv)
 group by r.role order by r.role;

begin;
revoke all on table public.vault_notes from public, anon, authenticated;
commit;

-- [적용 후] 1) 표 권한 목록: anon·authenticated 행이 없어야 합니다.
select grantee, string_agg(privilege_type, ',' order by privilege_type) as grants
  from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'vault_notes'
   and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
 group by grantee order by grantee;

-- [적용 후] 2) has_table_privilege: anon·authenticated는 전부 비어 있고(NULL), service_role만 남아야 합니다.
select r.role, string_agg(p.priv, ',' order by p.priv)
         filter (where has_table_privilege(r.role, 'public.vault_notes', p.priv)) as allowed
  from (values ('anon'), ('authenticated'), ('service_role')) r(role)
 cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                    ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) p(priv)
 group by r.role order by r.role;

-- 브라우저 쪽 확인(공개 키로 원본 자료 API 직접 호출, 메모가 나오면 안 됨):
--   GET https://<프로젝트>.supabase.co/rest/v1/vault_notes?select=id  (apikey: 공개 키)
--   → 401 / 42501 permission denied
