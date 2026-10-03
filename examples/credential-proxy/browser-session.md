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
| Seed | The agent fetches `https://<api host>/.gatehouse/browser-seed` through Gatehouse. The answer is a Playwright storage state: the app's Auth0 localStorage entries with the placeholder as the access token, an unsigned ID token carrying the user's non-secret claims (`sub`, `org_id`, email), and the `auth0.<client>.is.authenticated` cookie. It expires at the worker Pod's deadline, at most 8 hours. |
| App | The app's own host (`appHost`) serves GET and HEAD with no credential. |
| API | Requests to the API host carry `Authorization: Bearer <placeholder>`, or none. Gatehouse replaces the placeholder with the real token. Any other credential is refused. |
| Login | Gatehouse logs the user in with Auth0's password-realm grant through a confidential client. It reads the password and client secret from Vault for each login, caches the token until a quarter of its life is left, and logs in again after the API refuses it. |
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

## Catalog entry

```json
{"name": "staging-app", "kind": "browser-session", "host": "api.staging.example",
 "placeholder": "__vault_STAGING_APP__", "pools": ["database-developers"],
 "browserSession": {
   "appHost": "app.staging.example",
   "auth0": {"domain": "tenant.us.auth0.com", "clientID": "<the app's public client ID>",
             "audience": "<the app's API audience>", "realm": "Username-Password-Authentication",
             "tokenClient": {"mount": "gatehouse", "path": "browser/staging-login-client"}},
   "user": {"mount": "gatehouse", "path": "browser/staging-qa-user"}}}
```

- `tokenClient` holds `client_id` and `client_secret`: a confidential Auth0 client allowed the password-realm grant for that connection only.
- `user` holds `email` and `password`.
- Both live only in Vault. The entry's `pathPrefixes` default to `/`; `forwardHeaders` adds request headers to the browser set.

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

- An Auth0 confidential client with the password-realm grant, limited to the test-user connection, in the staging tenant.
- The broker's egress allows the Auth0 tenant's addresses.
- Test users only. SSO and MFA employee accounts cannot use this, and the catalog never lists production.
