# Supabase Auth integration

Project: **zrenai** · `crzeiwqcsthxwcajnnai` · Singapore.
API: https://crzeiwqcsthxwcajnnai.supabase.co

## What is integrated

- Supabase email/password login, email-confirmed account activation, password changes and sign-out.
- The backend calls Supabase Auth over HTTPS and validates the current user with `GET /auth/v1/user` on authenticated requests. Invalid or unavailable identity verification fails closed.
- Admin/agent access is an explicit app allowlist, not user-editable Supabase metadata. Agents retain their existing own-customer/own-order scope.
- First successful verified login binds the approved local account to its Supabase user UUID. Deleting/recreating an Auth user with the same email cannot silently take over that role.
- Supabase access tokens remain server-side in the protected app database. The browser receives only an opaque HttpOnly, SameSite cookie. Refresh tokens are discarded; a session lasts at most one hour, then requires login again.
- Logout revokes the local session even when Supabase is unavailable. Password changes are made in Supabase and clear the user's app sessions.
- Local demo accounts stay separate. Supabase mode rejects a seeded demo database and does not accept legacy local-password sessions.

## Configure and run locally

Copy `.env.example` to `.env.supabase`. The example includes only the project's public URL and publishable key; no service-role key is needed or accepted. Set `SUPABASE_ADMIN_EMAIL` to the owner-approved first administrator email. Keep this file untracked.

On macOS, double-click `启动Supabase认证.command`. Alternatively:

```sh
cd agent-system
set -a
. ./.env.supabase
set +a
python3 server.py --supabase --port 8790 --db data/supabase.sqlite3
```

Open http://127.0.0.1:8790. This uses a separate app database and does not replace existing local/demo records.

The bootstrap email authorizes an administrator in the app. It does **not** create a Supabase user or send mail by itself. The owner activates that authorized email through the login page, sets their own password and confirms the Supabase email. They then return to the app to sign in. No default production password is created.

The administrator creates agents using their login email addresses. Agents activate those authorized addresses in the same way. Changing an existing bootstrap email does not silently change roles or add a second administrator.

## Supabase dashboard settings

Email/password and email confirmation were verified as enabled on 2026-10-20. The project had zero Auth users at the initial check; successful activation/login needs the owner's email and confirmation.

1. Set the Auth Site URL and allowed redirects to the actual app URL once hosting is selected. For local testing use `http://127.0.0.1:8790` if desired. Email confirmation still verifies the account before redirect, but the destination needs configuring for a smooth return.
2. Configure production SMTP before onboarding outside users. Supabase's built-in mail delivery has recipient/rate restrictions; do not assume it will deliver to every agent.
3. Keep email confirmation enabled. Disable anonymous sign-in. The app still denies unapproved accounts even if someone registers directly against Supabase's public Auth endpoint.

References: [password authentication](https://supabase.com/docs/guides/auth/passwords), [SMTP](https://supabase.com/docs/guides/auth/auth-smtp), [redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls), [Auth API](https://github.com/supabase/auth/blob/master/openapi.yaml).

## Verification

On 2026-10-20, all 27 automated tests passed, including commission, promotion, refund, agent isolation and mocked Supabase authentication scenarios. The live project's Auth settings confirmed email login and email confirmation; its real `/user` endpoint rejected an invalid token with HTTP 401. The activation form was checked in the browser. A real successful login remains pending the owner's password setup and email confirmation.

## Deployment boundary

This change integrates **authentication**, not business-database hosting. Orders, commissions, roles and session records still use the Python app's SQLite store. Supabase project URLs do not host this Python web server. A live deployment still needs a Python host, persistent storage and HTTPS. The existing local server deliberately remains loopback-only; it is not a public production server.

Do not upload local database files or demo credentials to a public host. Protect backups because server-side access tokens are sensitive until expiry. Provider-wide sign-out can leave already issued access tokens valid until their short expiry; local logout/disable is enforced immediately by this app.
