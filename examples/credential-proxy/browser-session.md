# Browser sessions as a test user

An agent's own browser (Playwright) can use a web app as a logged-in test user
without ever holding the user's password, the login client's secret or a
token. The browser loads the app with a ready-made login state that contains
only placeholders. When the app calls its API, Gatehouse swaps the placeholder
for a real access token it obtained for the test user. This retires the staging
email, password and automated-auth private key that agents hold today.

## How it works

| Step | What happens |
|---|---|
| Seed | The agent fetches `https://<api host>/.gatehouse/browser-seed` through Gatehouse. The answer is a Playwright storage state: the app's Auth0 localStorage entries with the placeholder as the access token, an unsigned ID token carrying the user's non-secret claims (`sub`, `org_id`, email), and the `auth0.<client>.is.authenticated` cookie. It expires at the worker Pod's deadline, at most 24 hours. |
| App | The app's own host (`appHost`) serves GET and HEAD with no credential. |
| API | Requests to the API host carry `Authorization: Bearer <placeholder>`, or none. Gatehouse replaces the placeholder with the real token. Any other credential is refused. |
| Sign-in | Gatehouse signs the user in by the entry's `auth0.login` method (below). It reads the sign-in secrets from Vault for each sign-in and caches the token until a quarter of its life is left. Requests that need a sign-in share one attempt, which runs on its own (up to 90 seconds) even if the request that started it gives up. After any attempt, successful or not, the entry makes no other for a minute: a failure answers 503 for that minute, and a failed renewal keeps the last token serving until it expires. It keeps no refresh token. |
| Paths | Only the entry's `pathPrefixes` reach the API, never all of it. Credential and account-admin routes are refused everywhere (see Path guard). |
| Rate | The per-Pod proxy limit applies: by default 20 requests a second with a burst of 200, and 64 in flight, per Pod and entry. Over it, 429 with outcome `rate_limited`. |
| Cookies | Never pass, in either direction: a cookie the app or API sets after a bearer call would be a session credential of its own. |
| Screening | Every response is screened for the real token. A response that carries it is cut off. |

The staging app (trm-b2b `packages/enterprise`) never decodes the access
token. It reads `sub` and `org_id` from the ID token, keeps tokens in
localStorage and streams agent chat over `fetch`, which passes as an ordinary
response. WebSocket upgrades are refused until an app needs them.

`browser-seed-check.mjs` loads auth0-spa-js 2.1.3 in Chromium, configured like
the staging app, with a seed from `TestBrowserSeedFile`. The client reports a
signed-in user, returns the placeholder from `getTokenSilently`, returns `sub`
and `org_id` from `getIdTokenClaims`, and makes no network call.

## Sign-in methods

| `auth0.login` | How | When |
|---|---|---|
| `password-realm` (default) | Auth0's password-realm grant through a confidential client (`auth0.realm`, `auth0.tokenClient`). | An app whose Auth0 application is not organization-enabled. |
| `automated-auth` | TRM's automated-auth service drives the app's Universal Login with the entry's organization. | An organization-enabled app. Auth0 refuses the password-realm grant for those, and the TRM Enterprise API refuses a token without `org_id`. |

With `automated-auth`, Gatehouse calls `POST <url>/v1/auth/login` with the service key, the profile, the organization and the user's email and password, all from Vault except the profile and organization. It then:

- reads only the top-level `accessToken`, `idToken` and `expiresAt` of the answer. The browser seed the service also returns is never parsed, and the answer is never logged; its error text can name the user.
- refuses the token unless the access token is a JWT whose `org_id` is the entry's `orgID`, whose `aud` includes the entry's audience, and which has at least two minutes left. An ID token, when present, must name the same user and organization.
- builds the seed's ID token from the ID token's claims, or from the access token's `sub` and `org_id` when the service returns none (its password sign-in does not).
- revokes the refresh token at `https://<auth0.domain>/oauth/revoke` with the app's public client ID, retrying once. The audit trail records binding `<entry>/revoke` with outcome `refresh_revoked` or `revoke_failed`; alert on `revoke_failed`. A failed revocation does not fail the sign-in, since Gatehouse keeps the token nowhere, but it stays valid in Auth0 until it expires.

The service URL is https only. Plain http to a Kubernetes Service name is accepted only by binaries built with the `e2e` tag, for the Kind fixture. Gatehouse dials only the service and Auth0 addresses the catalog names, through the guarded dialer, and never follows a redirect. A sign-in drives a real login page and can take tens of seconds (limit 60); the first API call of a session waits for it.

## Path guard

A browser-session entry acts as its test user, often an admin of its organization. The guard keeps a worker from using that session to mint a credential of its own or change the account.

- `pathPrefixes` are required and never `/`. A prefix may not contain a denied segment or lie within a `deniedPaths` template.
- Denied segments, refused anywhere in a path, in any case, with `-` and `_` ignored: `apikey(s)`, `password`, `change-password`, `reset-password`, `mfa`, `otp`, `totp`, `invitations`, `invites`, `oauth`, `token(s)`, `sso`, `saml`, `scim`, `connections`, `roles`, `ip-allowlist`, `authentication`, `admin`, `user-management`, `bulk-operations`, `rotate-secret`, `webhooks`, `credentials`, `secrets`, `keys`, `client-secret`, `permissions`, `impersonate`, `sessions`. Outcome `denied_path`, 403.
- `users-organizations` is read-only anywhere in a path: GET, HEAD and OPTIONS pass, every other method gets 403 with outcome `read_only_path`. The app reads it at start-up; the same routes invite and create users.
- `deniedPaths` and `readOnlyPaths` are templates per entry: segments are names or a single `*`. Each covers its path and everything below it. Under a denied one every method is refused (`denied_path`); under a read-only one only GET, HEAD and OPTIONS pass (`read_only_path`).
- A denied request is refused before any sign-in or upstream call.

## Catalog entry

An example staging app (placeholder values):

```json
{"name": "enterprise-staging", "kind": "browser-session", "host": "api.staging.example.com",
 "placeholder": "__vault_ENTERPRISE_STAGING__", "pools": ["<one pool>"],
 "pathPrefixes": ["<the API paths the workers need>"],
 "readOnlyPaths": ["/users-organizations"],
 "deniedPaths": ["/v1/parent-organizations/*/users", "/v1/parent-organizations/*/invitations",
                 "/v1/parent-organizations/*/environments/*/groups/*/members", "/v1/users/*/email", "/v1/intel-vault"],
 "browserSession": {
   "appHost": "app.staging.example.com",
   "auth0": {"domain": "auth.staging.example.com", "clientID": "<SPA client ID>",
             "audience": "https://app.staging.example.com/", "login": "automated-auth"},
   "automatedAuth": {"url": "https://automated-auth.staging.example.com", "profile": "app-staging",
                     "orgID": "org_example", "key": {"mount": "gatehouse", "path": "browser/automated-auth"}},
   "user": {"mount": "gatehouse", "path": "browser/enterprise-staging/user"}}}
```

- `key` holds `private_key`, the automated-auth service key. `user` holds `email` and `password`. They live only in Vault.
- One pool per entry, and a test user in one entry only, so its session and audit trail belong to one pool.
- A `password-realm` entry drops `automatedAuth` and sets `auth0.realm` and `auth0.tokenClient` (`client_id` and `client_secret` of a confidential client allowed the grant for that connection only).
- `forwardHeaders` adds request headers to the browser set.

## From the agent

```js
const proxy = { server: 'http://127.0.0.1:14322' }; // the worker's Gatehouse sidecar
const api = await request.newContext({ proxy });
const seed = await (await api.get('https://api.staging.example/.gatehouse/browser-seed')).json();
const context = await browser.newContext({ proxy, storageState: seed });
```

The worker image trusts Gatehouse's interception CA, as for every proxied
HTTPS call: `NODE_EXTRA_CA_CERTS` for Node, the NSS store for Chromium.

## Before staging

- For `password-realm`, an Auth0 confidential client with the grant, limited to the test-user connection, in the staging tenant. For `automated-auth`, the service's profile for the app and its key in Vault.
- The broker's egress (`AGENT_VAULT_NETWORK_ALLOWLIST`, `AGENT_VAULT_EGRESS_RANGES` and the namespace's network policy) allows the Auth0 tenant's addresses and, for `automated-auth`, the service's.
- Test users only. SSO and MFA employee accounts cannot use this, and the catalog never lists production.
