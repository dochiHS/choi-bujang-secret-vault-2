-- BYTE BACK 11단계: 기기 명단(vault_devices)
-- 서버에는 기기 공개키(JWK의 kty·crv·x·y)만 둡니다. 개인키는 브라우저 메모리에만 있고 서버·DB·Git에 오지 않습니다.
-- status: pending(등록만 됨) → approved(서버가 비밀번호 재확인 + 기기 서명 확인 후) / revoked(회수)
-- anon·authenticated 권한은 주지 않고 서버 함수(service_role)만 읽고 씁니다. 삭제 권한은 주지 않습니다.
create table if not exists public.vault_devices (
  device_id text primary key check (device_id ~ '^[0-9a-f]{16}$'),   -- 공개키 지문(RFC 7638) 앞 16자리
  owner_id uuid not null,
  public_jwk jsonb not null check (public_jwk ?& array['kty','crv','x','y'] and not (public_jwk ? 'd')),
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  created_at timestamptz not null default now(),
  approved_at timestamptz
);
create index if not exists vault_devices_owner_idx on public.vault_devices (owner_id);
alter table public.vault_devices enable row level security;
revoke all on table public.vault_devices from public, anon, authenticated, service_role;
grant select, insert, update on table public.vault_devices to service_role;

-- [확인] anon·authenticated는 모두 false, 서버는 select·insert·update만 true, delete는 false
select (select count(*) from public.vault_devices) as devices,
       has_table_privilege('anon', 'public.vault_devices', 'SELECT') as anon_select,
       has_table_privilege('authenticated', 'public.vault_devices', 'SELECT') as auth_select,
       has_table_privilege('service_role', 'public.vault_devices', 'INSERT') as server_insert,
       has_table_privilege('service_role', 'public.vault_devices', 'UPDATE') as server_update,
       has_table_privilege('service_role', 'public.vault_devices', 'DELETE') as server_delete;
