create extension if not exists pgcrypto;

create table if not exists delegations (
  id uuid primary key,
  name text not null,
  level text not null check (level in ('maison_mere', 'regional', 'national', 'diocese', 'parish')),
  country text not null,
  parent_id uuid references delegations (id)
);

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  password_hash text not null,
  role text not null check (role in ('candidate', 'member')),
  status text not null check (status in ('pending', 'active')),
  full_name text not null,
  phone text,
  birth_date date,
  birth_place text,
  address text,
  profession text,
  diocese_id uuid references delegations (id),
  parish_id uuid references delegations (id),
  oath_place text,
  oath_on date,
  member_number text unique,
  site_code text,
  profile_path text,
  country text,
  created_at timestamptz not null default now()
);

alter table users add column if not exists site_code text;
alter table users add column if not exists profile_path text;
alter table users add column if not exists country text;
create unique index if not exists users_site_code_unique on users (site_code) where site_code is not null;

create table if not exists service_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references users (id),
  kind text not null check (kind in (
    'academy', 'subsidy', 'shop', 'chancery',
    'contact', 'newsletter', 'listening', 'booklet',
    'project', 'contest', 'programme'
  )),
  payload jsonb not null,
  created_at timestamptz not null default now()
);

alter table service_requests drop constraint if exists service_requests_kind_check;
alter table service_requests add constraint service_requests_kind_check check (kind in (
  'academy', 'subsidy', 'shop', 'chancery',
  'contact', 'newsletter', 'listening', 'booklet',
  'project', 'contest', 'programme'
));

create table if not exists gatherings (
  id uuid primary key default gen_random_uuid(),
  host_id uuid not null references users (id),
  kind text not null check (kind in ('prayer', 'meeting', 'call')),
  title text not null,
  intention text,
  code text not null unique,
  status text not null default 'open' check (status in ('open', 'closed')),
  created_at timestamptz not null default now()
);

create table if not exists gathering_knocks (
  id uuid primary key default gen_random_uuid(),
  gathering_id uuid not null references gatherings (id) on delete cascade,
  display_name text not null,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'rejected')),
  created_at timestamptz not null default now()
);

create index if not exists gathering_knocks_pending_idx
  on gathering_knocks (gathering_id, status);

alter table gatherings add column if not exists starts_at timestamptz;

create table if not exists gathering_invites (
  gathering_id uuid not null references gatherings (id) on delete cascade,
  user_id uuid not null references users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (gathering_id, user_id)
);

create table if not exists gathering_delegates (
  gathering_id uuid not null references gatherings (id) on delete cascade,
  user_id uuid not null references users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (gathering_id, user_id)
);

create table if not exists notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users (id) on delete cascade,
  kind text not null,
  title text not null,
  body text not null,
  code text,
  read_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists notifications_user_idx
  on notifications (user_id, created_at desc);

create table if not exists site_posts (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('news', 'image')),
  external_key text not null,
  title text not null,
  body text,
  image_url text,
  source_url text,
  published_label text,
  position integer not null default 0,
  updated_at timestamptz not null default now(),
  unique (kind, external_key)
);

create table if not exists sync_state (
  id text primary key,
  last_success timestamptz,
  last_error text
);

create table if not exists mass_intentions (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text not null,
  kind text not null,
  for_whom text not null,
  intention text not null,
  preferred_date date,
  created_at timestamptz not null default now()
);
