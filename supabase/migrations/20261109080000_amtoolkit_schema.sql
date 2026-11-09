-- Asset Management Performance Toolkit — cloud schema
-- Workspaces (one per customer/site), their members, the saved toolkit state,
-- a rolling save history, and the provider-admin functions used by the
-- in-app admin panel. Every table has row-level security; the browser only
-- ever uses the publishable key plus the signed-in user's session.

-- ---------------------------------------------------------------- tables
create table public.amtoolkit_admins (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);
comment on table public.amtoolkit_admins is 'Provider admins: can create workspaces and manage members. Add rows from the SQL editor.';

create table public.amtoolkit_workspaces (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (length(btrim(name)) between 1 and 120),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users (id) on delete set null
);

create table public.amtoolkit_members (
  workspace_id uuid not null references public.amtoolkit_workspaces (id) on delete cascade,
  user_id      uuid not null references auth.users (id) on delete cascade,
  role         text not null default 'member' check (role in ('owner', 'member')),
  created_at   timestamptz not null default now(),
  primary key (workspace_id, user_id)
);
create index amtoolkit_members_user_idx on public.amtoolkit_members (user_id);

create table public.amtoolkit_workspace_state (
  workspace_id     uuid primary key references public.amtoolkit_workspaces (id) on delete cascade,
  data             jsonb not null,
  updated_at       timestamptz not null default now(),
  updated_by       uuid references auth.users (id) on delete set null,
  updated_by_email text
);

create table public.amtoolkit_workspace_history (
  id             bigint generated always as identity primary key,
  workspace_id   uuid not null references public.amtoolkit_workspaces (id) on delete cascade,
  data           jsonb not null,
  saved_at       timestamptz not null default now(),
  saved_by       uuid references auth.users (id) on delete set null,
  saved_by_email text
);
create index amtoolkit_workspace_history_ws_idx on public.amtoolkit_workspace_history (workspace_id, saved_at desc);
create index amtoolkit_workspace_history_saved_by_idx on public.amtoolkit_workspace_history (saved_by);
create index amtoolkit_workspace_state_updated_by_idx on public.amtoolkit_workspace_state (updated_by);
create index amtoolkit_workspaces_created_by_idx on public.amtoolkit_workspaces (created_by);

-- ---------------------------------------------------------------- helpers
create or replace function public.amtoolkit_is_admin()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.amtoolkit_admins a where a.user_id = (select auth.uid()));
$$;

create or replace function public.amtoolkit_can_access(ws uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.amtoolkit_members m where m.workspace_id = ws and m.user_id = (select auth.uid()))
      or exists (select 1 from public.amtoolkit_admins a where a.user_id = (select auth.uid()));
$$;

-- keep the newest 30 history snapshots per workspace (the Dashboard data makes snapshots ~0.5 MB)
create or replace function public.amtoolkit_prune_history()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  delete from public.amtoolkit_workspace_history h
   where h.workspace_id = new.workspace_id
     and h.id not in (select h2.id from public.amtoolkit_workspace_history h2
                       where h2.workspace_id = new.workspace_id
                       order by h2.saved_at desc, h2.id desc limit 30);
  return null;
end;
$$;
create trigger amtoolkit_prune_history_trg
  after insert on public.amtoolkit_workspace_history
  for each row execute function public.amtoolkit_prune_history();

-- ---------------------------------------------------------------- row-level security
alter table public.amtoolkit_admins            enable row level security;
alter table public.amtoolkit_workspaces        enable row level security;
alter table public.amtoolkit_members           enable row level security;
alter table public.amtoolkit_workspace_state   enable row level security;
alter table public.amtoolkit_workspace_history enable row level security;

-- admins: no direct access (managed from the SQL editor; checked through amtoolkit_is_admin())

create policy "workspaces visible to members and admins" on public.amtoolkit_workspaces
  for select to authenticated using ((select public.amtoolkit_can_access(id)));

create policy "members see their own memberships" on public.amtoolkit_members
  for select to authenticated using (user_id = (select auth.uid()));

create policy "state readable by workspace members" on public.amtoolkit_workspace_state
  for select to authenticated using ((select public.amtoolkit_can_access(workspace_id)));
create policy "state insertable by workspace members" on public.amtoolkit_workspace_state
  for insert to authenticated with check ((select public.amtoolkit_can_access(workspace_id)) and updated_by = (select auth.uid()));
create policy "state updatable by workspace members" on public.amtoolkit_workspace_state
  for update to authenticated using ((select public.amtoolkit_can_access(workspace_id)))
  with check ((select public.amtoolkit_can_access(workspace_id)) and updated_by = (select auth.uid()));

create policy "history readable by workspace members" on public.amtoolkit_workspace_history
  for select to authenticated using ((select public.amtoolkit_can_access(workspace_id)));
create policy "history insertable by workspace members" on public.amtoolkit_workspace_history
  for insert to authenticated with check ((select public.amtoolkit_can_access(workspace_id)) and saved_by = (select auth.uid()));

-- ---------------------------------------------------------------- admin panel functions
create or replace function public.amtoolkit_require_admin()
returns void
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not exists (select 1 from public.amtoolkit_admins a where a.user_id = (select auth.uid())) then
    raise exception 'Only provider admins can do this' using errcode = '42501';
  end if;
end;
$$;

create or replace function public.amtoolkit_admin_list_workspaces()
returns table (id uuid, name text, member_count integer, last_activity timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  perform public.amtoolkit_require_admin();
  return query
    select w.id, w.name,
           (select count(*)::int from public.amtoolkit_members m where m.workspace_id = w.id),
           (select s.updated_at from public.amtoolkit_workspace_state s where s.workspace_id = w.id)
      from public.amtoolkit_workspaces w
     order by w.name;
end;
$$;

create or replace function public.amtoolkit_admin_list_members(ws uuid)
returns table (email text, role text)
language plpgsql stable security definer set search_path = ''
as $$
begin
  perform public.amtoolkit_require_admin();
  return query
    select u.email::text, m.role
      from public.amtoolkit_members m join auth.users u on u.id = m.user_id
     where m.workspace_id = ws
     order by m.role, u.email;
end;
$$;

create or replace function public.amtoolkit_admin_create_workspace(ws_name text)
returns uuid
language plpgsql security definer set search_path = ''
as $$
declare new_id uuid;
begin
  perform public.amtoolkit_require_admin();
  if ws_name is null or length(btrim(ws_name)) = 0 then
    raise exception 'Enter a workspace name';
  end if;
  insert into public.amtoolkit_workspaces (name, created_by)
  values (btrim(ws_name), (select auth.uid())) returning id into new_id;
  return new_id;
end;
$$;

create or replace function public.amtoolkit_admin_add_member(ws uuid, member_email text, member_role text default 'member')
returns void
language plpgsql security definer set search_path = ''
as $$
declare uid uuid;
begin
  perform public.amtoolkit_require_admin();
  if coalesce(member_role, 'member') not in ('owner', 'member') then
    raise exception 'Role must be owner or member';
  end if;
  select u.id into uid from auth.users u where lower(u.email) = lower(btrim(member_email));
  if uid is null then
    raise exception 'No user with email % — create or invite them in Authentication → Users first', btrim(member_email);
  end if;
  if not exists (select 1 from public.amtoolkit_workspaces w where w.id = ws) then
    raise exception 'Workspace not found';
  end if;
  insert into public.amtoolkit_members (workspace_id, user_id, role)
  values (ws, uid, coalesce(member_role, 'member'))
  on conflict (workspace_id, user_id) do update set role = excluded.role;
end;
$$;

create or replace function public.amtoolkit_admin_remove_member(ws uuid, member_email text)
returns void
language plpgsql security definer set search_path = ''
as $$
begin
  perform public.amtoolkit_require_admin();
  delete from public.amtoolkit_members m
   using auth.users u
   where m.user_id = u.id and m.workspace_id = ws and lower(u.email) = lower(btrim(member_email));
end;
$$;

create or replace function public.amtoolkit_admin_rename_workspace(ws uuid, ws_name text)
returns void
language plpgsql security definer set search_path = ''
as $$
begin
  perform public.amtoolkit_require_admin();
  if ws_name is null or length(btrim(ws_name)) = 0 then
    raise exception 'Enter a workspace name';
  end if;
  update public.amtoolkit_workspaces set name = btrim(ws_name) where id = ws;
end;
$$;

create or replace function public.amtoolkit_admin_delete_workspace(ws uuid)
returns void
language plpgsql security definer set search_path = ''
as $$
begin
  perform public.amtoolkit_require_admin();
  delete from public.amtoolkit_workspaces where id = ws;
end;
$$;

-- ---------------------------------------------------------------- privileges
revoke execute on all functions in schema public from public, anon;
grant execute on function
  public.amtoolkit_is_admin(),
  public.amtoolkit_admin_list_workspaces(),
  public.amtoolkit_admin_list_members(uuid),
  public.amtoolkit_admin_create_workspace(text),
  public.amtoolkit_admin_add_member(uuid, text, text),
  public.amtoolkit_admin_remove_member(uuid, text),
  public.amtoolkit_admin_rename_workspace(uuid, text),
  public.amtoolkit_admin_delete_workspace(uuid)
  to authenticated;
-- amtoolkit_can_access is used inside RLS policies, so signed-in users need it too
grant execute on function public.amtoolkit_can_access(uuid) to authenticated;

revoke all on public.amtoolkit_admins from anon, authenticated;
revoke all on public.amtoolkit_members, public.amtoolkit_workspaces,
              public.amtoolkit_workspace_state, public.amtoolkit_workspace_history from anon;
grant select on public.amtoolkit_workspaces, public.amtoolkit_members to authenticated;
grant select, insert, update on public.amtoolkit_workspace_state to authenticated;
grant select, insert on public.amtoolkit_workspace_history to authenticated;
