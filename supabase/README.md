# Supabase backend

The toolkit signs users in and saves each workspace to the Supabase project **am-toolkit**
(`rsreqcbdmxszbrsklrkn`, region eu-west-1). The page uses the project URL and the
publishable key set in `SB_URL` / `SB_KEY` in `index.html` (and its copy `am_toolkit.html`).
The publishable key is safe to ship in the page: every table is protected by row-level security.

## Schema (`migrations/`)

| Object | Purpose |
|---|---|
| `amtoolkit_workspaces` | One workspace per customer / site |
| `amtoolkit_members` | Which users can open which workspace (`owner` or `member`) |
| `amtoolkit_workspace_state` | The saved toolkit state per workspace (one JSON row, autosaved) |
| `amtoolkit_workspace_history` | Snapshots saved at most every 3 minutes; the newest 30 per workspace are kept |
| `amtoolkit_admins` | Provider admins who see the in-app **Admin** panel |
| `amtoolkit_is_admin()`, `amtoolkit_admin_*()` | Functions behind the Admin panel; each one refuses non-admins |
| `amtoolkit_private.amtoolkit_can_access()` | Access check used by the RLS policies (not exposed through the API) |

Members and admins can read and write their workspaces. Everyone else sees nothing.

Apply the migrations to another project with the Supabase CLI:

```bash
supabase link --project-ref <project-ref>
```

```bash
supabase db push
```

## First-time setup (once, in the Supabase dashboard)

1. **Authentication → URL Configuration:** set **Site URL** to the deployed toolkit address (the Vercel URL),
   and add it under **Redirect URLs**, so that invite and password-reset links open the toolkit.
2. **Authentication → Sign In / Providers:** turn off **Allow new users to sign up**. Users are invited by an admin.
3. **Authentication → Users → Invite user:** invite yourself and set a password from the email link.
4. **SQL Editor:** make yourself a provider admin:

   ```sql
   insert into public.amtoolkit_admins (user_id)
   select id from auth.users where email = 'you@example.com';
   ```

5. Sign in to the toolkit, open **Admin**, create a workspace and add members by email.
   A member must first be invited under Authentication → Users.
