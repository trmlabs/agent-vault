// Real-browser check: auth0-spa-js 2.1.3, configured like the staging app,
// treats the Gatehouse seed as a signed-in session with no network call.
import { createRequire } from 'node:module';
import fs from 'node:fs';
const require = createRequire(process.env.NM + '/');
const { chromium } = require('playwright');
const seed = JSON.parse(fs.readFileSync(process.env.SEED, 'utf8'));
const bundle = fs.readFileSync(process.env.NM + '/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', 'utf8');
const browser = await chromium.launch();
const context = await browser.newContext({ storageState: seed });
const outbound = [];
await context.route('**/*', async (route) => {
  const url = new URL(route.request().url());
  if (url.host === 'app.example.com') {
    return route.fulfill({ contentType: 'text/html', body: '<html><body><script>' + bundle + '</script></body></html>' });
  }
  outbound.push(url.href);
  return route.abort();
});
const page = await context.newPage();
await page.goto('https://app.example.com/');
const result = await page.evaluate(async () => {
  const client = new auth0.Auth0Client({
    domain: 'auth.example.com', clientId: 'spaClient1',
    authorizationParams: { audience: 'https://api.example.com', redirect_uri: location.origin },
    cacheLocation: 'localstorage', useRefreshTokens: true, useRefreshTokensFallback: true,
  });
  await client.checkSession();
  const claims = await client.getIdTokenClaims();
  return {
    authenticated: await client.isAuthenticated(),
    token: await client.getTokenSilently(),
    sub: claims && claims.sub, org: claims && claims.org_id,
    user: (await client.getUser())?.email,
  };
});
console.log(JSON.stringify({ ...result, outbound }));
await browser.close();
