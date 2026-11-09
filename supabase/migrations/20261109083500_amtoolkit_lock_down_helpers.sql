-- Internal helpers must not be callable through the REST API.
-- Supabase's default privileges grant EXECUTE on new public functions to
-- anon/authenticated, so revoke them explicitly.

-- trigger + guard used only inside SECURITY DEFINER functions / triggers
revoke execute on function public.amtoolkit_prune_history() from public, anon, authenticated;
revoke execute on function public.amtoolkit_require_admin() from public, anon, authenticated;

-- the RLS access check moves to a schema that the Data API does not expose;
-- policies reference the function by OID so they keep working
create schema if not exists amtoolkit_private;
revoke all on schema amtoolkit_private from public, anon;
grant usage on schema amtoolkit_private to authenticated;
alter function public.amtoolkit_can_access(uuid) set schema amtoolkit_private;
revoke execute on function amtoolkit_private.amtoolkit_can_access(uuid) from public, anon;
grant execute on function amtoolkit_private.amtoolkit_can_access(uuid) to authenticated;

-- the admin panel functions are intentionally callable by signed-in users:
-- each one starts with public.amtoolkit_require_admin() and raises for non-admins.
