package httpcatalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Synthetic values; never real credentials.
var automatedSecrets = map[string]string{"email": "qa-user@example.test", "password": "synthetic-password-9c1",
	"private_key": "synthetic-automated-auth-key-7e3"}

const syntheticRefresh = "synthetic-refresh-token-5d8"

type automatedVault struct{ down bool }

func (v automatedVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	if v.down {
		return nil, errors.New("vault unreachable")
	}
	data := map[string]interface{}{}
	for k, v := range automatedSecrets {
		data[k] = v
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

func automatedEntryJSON(automated string) string {
	return `{"name":"staging-app","kind":"browser-session","host":"api.example.com","placeholder":"__vault_STAGING_APP__",
		"pools":["database-developers"],"pathPrefixes":["/v1/deconflict"],"browserSession":{"appHost":"app.example.com",
		"auth0":{"domain":"auth.example.com","clientID":"spaClient1","audience":"https://api.example.com","login":"automated-auth"},
		"automatedAuth":{` + automated + `},"user":{"mount":"gatehouse","path":"browser/qa-user"}}}`
}

const automatedSettings = `"url":"https://automated-auth.example.com","profile":"trm-b2b-staging","orgID":"org_synthetic",
	"key":{"mount":"gatehouse","path":"browser/automated-auth"}`

func parseOne(entry string) error {
	_, err := Parse([]byte(`{"entries":[` + entry + `]}`))
	return err
}

func TestAutomatedAuthEntry(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + automatedEntryJSON(strings.Replace(automatedSettings, "automated-auth.example.com", "Automated-Auth.example.com:8443/", 1)) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Entries()[0].BrowserSession.AutomatedAuth
	if s.URL != "https://automated-auth.example.com:8443" || s.Addr() != "automated-auth.example.com:8443" ||
		!c.HasAutomatedAuth("automated-auth.example.com:8443") || c.HasAutomatedAuth("automated-auth.example.com:443") {
		t.Fatalf("service: %+v", s)
	}
	for name, settings := range map[string]string{
		"no org":        strings.Replace(automatedSettings, `"orgID":"org_synthetic",`, "", 1),
		"empty org":     strings.Replace(automatedSettings, `"org_synthetic"`, `""`, 1),
		"no profile":    strings.Replace(automatedSettings, `"profile":"trm-b2b-staging",`, "", 1),
		"no key":        strings.Replace(automatedSettings, ",\n\t\"key\":{\"mount\":\"gatehouse\",\"path\":\"browser/automated-auth\"}", "", 1),
		"plain http":    strings.Replace(automatedSettings, "https://automated-auth.example.com", "http://automated-auth.automated-auth.svc.cluster.local:4319", 1),
		"path":          strings.Replace(automatedSettings, "example.com", "example.com/v1/auth/login", 1),
		"query":         strings.Replace(automatedSettings, "example.com", "example.com/?next=x", 1),
		"credentials":   strings.Replace(automatedSettings, "https://", "https://user:pass@", 1),
		"bad port":      strings.Replace(automatedSettings, "example.com", "example.com:0", 1),
		"ip address":    strings.Replace(automatedSettings, "automated-auth.example.com", "10.0.0.7", 1),
		"unknown field": automatedSettings + `,"organizationName":"x"`,
	} {
		if parseOne(automatedEntryJSON(settings)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	base := automatedEntryJSON(automatedSettings)
	for name, entry := range map[string]string{
		"token client":       strings.Replace(base, `"login":"automated-auth"`, `"login":"automated-auth","tokenClient":{"mount":"gatehouse","path":"browser/client"}`, 1),
		"unknown login":      strings.Replace(base, `"login":"automated-auth"`, `"login":"device-code"`, 1),
		"settings, no login": strings.Replace(base, `,"login":"automated-auth"`, `,"realm":"Username-Password-Authentication","tokenClient":{"mount":"gatehouse","path":"browser/client"}`, 1),
		"login, no settings": strings.Replace(base, `"automatedAuth":{`+automatedSettings+`},`, "", 1),
	} {
		if parseOne(entry) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A realm is harmless with automated-auth: the catalog module's own test
	// entry carries one.
	if err := parseOne(strings.Replace(base, `"login":"automated-auth"`, `"login":"automated-auth","realm":"Username-Password-Authentication"`, 1)); err != nil {
		t.Errorf("realm with automated-auth: %v", err)
	}
	if parseOne(strings.Replace(browserEntryJSON(""), `"realm":"Username-Password-Authentication",`, "", 1)) == nil {
		t.Error("password-realm entry without a realm accepted")
	}
}

// One pool per entry, and a test user in one entry only.
func TestBrowserEntryPoolsAndUsers(t *testing.T) {
	base := automatedEntryJSON(automatedSettings)
	if parseOne(strings.Replace(base, `"pools":["database-developers"]`, `"pools":["database-developers","other-pool"]`, 1)) == nil {
		t.Error("two pools accepted")
	}
	second := strings.NewReplacer(`"name":"staging-app"`, `"name":"staging-app-2"`, "api.example.com", "api2.example.com",
		"app.example.com", "app2.example.com").Replace(base)
	if _, err := Parse([]byte(`{"entries":[` + base + `,` + second + `]}`)); err == nil {
		t.Error("shared test user accepted")
	}
	other := strings.Replace(second, "browser/qa-user", "browser/qa-user-2", 1)
	if _, err := Parse([]byte(`{"entries":[` + base + `,` + other + `]}`)); err != nil {
		t.Errorf("distinct users: %v", err)
	}
}

func TestBrowserPathRules(t *testing.T) {
	entry := func(fields string) string {
		return strings.Replace(automatedEntryJSON(automatedSettings), `"pathPrefixes":["/v1/deconflict"]`, fields, 1)
	}
	for name, fields := range map[string]string{
		"no prefixes":           `"pathPrefixes":[]`,
		"root":                  `"pathPrefixes":["/"]`,
		"dot segment":           `"pathPrefixes":["/v1/./x"]`,
		"dot-dot segment":       `"pathPrefixes":["/v1/../admin"]`,
		"denied segment":        `"pathPrefixes":["/organizations/1/apiKey"]`,
		"denied, other case":    `"pathPrefixes":["/v1/Change_Password"]`,
		"denied, added segment": `"pathPrefixes":["/v1/client-secret"]`,
		"equal to denied":       `"pathPrefixes":["/v1/intel-vault"],"deniedPaths":["/v1/intel-vault"]`,
		"under denied":          `"pathPrefixes":["/v1/parent-organizations/7/users/3"],"deniedPaths":["/v1/parent-organizations/*/users"]`,
		"bad template":          `"pathPrefixes":["/v1/deconflict"],"deniedPaths":["/v1/**"]`,
		"dot template":          `"pathPrefixes":["/v1/deconflict"],"readOnlyPaths":["/v1/../x"]`,
		"relative template":     `"pathPrefixes":["/v1/deconflict"],"deniedPaths":["v1/x"]`,
	} {
		if parseOne(entry(fields)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, fields := range map[string]string{
		"shared-with-me":   `"pathPrefixes":["/users/shared-with-me"]`,
		"enterprise shape": `"pathPrefixes":["/v1/deconflict","/v1/parent-organizations/7/environments","/users-organizations"],"readOnlyPaths":["/users-organizations"],"deniedPaths":["/v1/parent-organizations/*/users","/v1/parent-organizations/*/invitations","/v1/parent-organizations/*/environments/*/groups/*/members","/v1/users/*/email","/v1/intel-vault"]`,
		"members readable": `"pathPrefixes":["/v1/deconflict/members"]`,
		"above a denied":   `"pathPrefixes":["/v1/parent-organizations"],"deniedPaths":["/v1/parent-organizations/*/users"]`,
	} {
		if err := parseOne(entry(fields)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The templates belong to browser-session entries.
	if parseOne(`{"name":"vendor","host":"vendor.example.com","pathPrefixes":["/v1"],"methods":["GET"],"header":"Authorization",
		"placeholder":"__vault_V__","key":{"mount":"gatehouse","path":"v","field":"k"},"pools":["p"],"deniedPaths":["/v1/x"]}`) == nil {
		t.Error("deniedPaths on an HTTP entry accepted")
	}
}

// The runtime guard: built-in segments anywhere and in any spelling, and
// templates covering their path and everything below it.
func TestBrowserPathGuard(t *testing.T) {
	e := &Entry{DeniedPaths: []string{"/v1/parent-organizations/*/users", "/v1/users/*/email", "/v1/intel-vault"},
		ReadOnlyPaths: []string{"/v1/reports"}}
	for _, segment := range []string{"apikey", "apikeys", "api-key", "api-keys", "password", "change-password", "reset-password", "mfa", "otp", "totp",
		"invitations", "invites", "oauth", "tokens", "token", "sso", "saml", "scim", "connections", "roles", "ip-allowlist", "authentication", "admin",
		"user-management", "bulk-operations", "rotate-secret", "webhooks", "credentials", "secrets", "keys", "clientsecret", "client-secret",
		"client_secret", "permissions", "impersonate", "sessions"} {
		for _, path := range []string{"/" + segment, "/v1/x/" + strings.ToUpper(segment) + "/y", "/a/b/c/" + segment} {
			if err := e.guardBrowserPath("GET", path); !errors.Is(err, ErrDeniedPath) {
				t.Errorf("GET %s: %v", path, err)
			}
		}
	}
	for path, want := range map[string]error{
		"/organizations/123/apiKey":                 ErrDeniedPath,
		"/organizations/123/APIKEY":                 ErrDeniedPath,
		"/users/mfa":                                ErrDeniedPath,
		"/users/change-password":                    ErrDeniedPath,
		"/oauth/clients/x/rotate-secret":            ErrDeniedPath,
		"/parent-organizations/1/users/2/roles":     ErrDeniedPath,
		"/v1/organizations/1/apiKey":                ErrDeniedPath,
		"/v1/parent-organizations/7/users":          ErrDeniedPath,
		"/v1/parent-organizations/7/users/3/roles":  ErrDeniedPath,
		"/v1/parent-organizations/7/users/3/teams":  ErrDeniedPath,
		"/V1/Parent-Organizations/7/Users":          ErrDeniedPath,
		"/v1/users/9/email":                         ErrDeniedPath,
		"/v1/intel-vault/files/2":                   ErrDeniedPath,
		"/parent-organizations/7/users":             nil, // a /v1 template matches /v1 paths only
		"/v1/parent-organizations/7/environments/2": nil,
		"/v1/deconflict/members":                    nil,
		"/users/shared-with-me":                     nil,
		"/v1/users/9/profile":                       nil,
	} {
		if err := e.guardBrowserPath("POST", path); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("POST %s: %v, want %v", path, err, want)
		}
	}
	for _, tc := range []struct {
		method, path string
		want         error
	}{
		{"POST", "/users-organizations", ErrReadOnlyPath},
		{"PATCH", "/v1/users-organizations/users/2", ErrReadOnlyPath},
		{"DELETE", "/api/v1/users-organizations/users", ErrReadOnlyPath},
		{"PUT", "/v2/Users_Organizations", ErrReadOnlyPath},
		{"POST", "/v1/reports", ErrReadOnlyPath},
		{"POST", "/v1/reports/7/export", ErrReadOnlyPath},
		{"GET", "/users-organizations", nil},
		{"HEAD", "/v1/users-organizations/users/2", nil},
		{"OPTIONS", "/users-organizations", nil},
		{"GET", "/v1/reports/7", nil},
		{"POST", "/reports", nil},
	} {
		if err := e.guardBrowserPath(tc.method, tc.path); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s %s: %v, want %v", tc.method, tc.path, err, tc.want)
		}
	}
	// The built-in read-only segment holds for an entry with no templates.
	if err := (&Entry{}).guardBrowserPath("POST", "/v1/users-organizations"); !errors.Is(err, ErrReadOnlyPath) {
		t.Errorf("built-in read-only: %v", err)
	}
	// Through the catalog: the seed path is not guarded; API paths are.
	c, err := Parse([]byte(`{"entries":[` + strings.Replace(automatedEntryJSON(automatedSettings), `"pathPrefixes":["/v1/deconflict"]`,
		`"pathPrefixes":["/v1","/users-organizations"]`, 1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		want         error
	}{
		{"GET", BrowserSeedPath, nil},
		{"GET", "/v1/organizations/1/apiKey", ErrDeniedPath},
		{"POST", "/users-organizations", ErrReadOnlyPath},
		{"GET", "/users-organizations", nil},
	} {
		if _, ok, err := c.BrowserMatch("api.example.com", 443, tc.method, tc.path, "database-developers"); !ok || !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("match %s %s: %v", tc.method, tc.path, err)
		}
	}
}

type automatedFake struct {
	logins    atomic.Int32
	revokes   atomic.Int32
	status    atomic.Int32
	revokeErr atomic.Bool
	org       atomic.Value // org_id in the access token
	idOrg     atomic.Value // org_id in the ID token; "" sends none
	aud       atomic.Value // the access token's aud, as JSON
	lifetime  atomic.Int64 // seconds
	jwt       atomic.Bool  // the access token is a JWT
	kept      atomic.Int32 // sign-in and revoke requests that left their connection open
}

// fakeAutomatedAuth plays automated-auth and the app's Auth0 tenant.
func fakeAutomatedAuth(t *testing.T) (*automatedFake, *http.Client) {
	t.Helper()
	f := &automatedFake{}
	f.org.Store("org_synthetic")
	f.idOrg.Store("org_synthetic")
	f.aud.Store(`["https://api.example.com","https://auth.example.com/userinfo"]`)
	f.lifetime.Store(3600)
	f.jwt.Store(true)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.Close {
			f.kept.Add(1)
		}
		if r.URL.Path == "/oauth/revoke" {
			f.revokes.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.revokeErr.Load() || !reflect.DeepEqual(body, map[string]string{"client_id": "spaClient1", "token": syntheticRefresh}) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		f.logins.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := map[string]string{"privateKey": automatedSecrets["private_key"], "profile": "trm-b2b-staging", "orgId": "org_synthetic",
			"email": automatedSecrets["email"], "password": automatedSecrets["password"]}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/login" || r.Header.Get("Content-Type") != "application/json" || !reflect.DeepEqual(body, want) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"error":{"code":"invalid_request","message":"login failed for %s"}}`, automatedSecrets["email"])
			return
		}
		if s := f.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			_, _ = fmt.Fprintf(w, `{"error":{"code":"token_extraction_failed","message":"no token for %s","details":{"finalUrl":"https://app.example.com/"}}}`, automatedSecrets["email"])
			return
		}
		n := f.logins.Load()
		exp := time.Now().Add(time.Duration(f.lifetime.Load()) * time.Second)
		access := fmt.Sprintf("synthetic-access-token-%d", n)
		if f.jwt.Load() {
			payload, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": f.org.Load(), "aud": json.RawMessage(f.aud.Load().(string)), "exp": exp.Unix()})
			access = "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + "." + access
		}
		out := map[string]any{"accessToken": access, "refreshToken": syntheticRefresh, "target": "https://app.example.com/",
			"expiresAt": exp.UTC().Format(time.RFC3339),
			"browserAuthSeed": map[string]any{"strategy": "auth0-spa-js-localstorage-v1", "origin": "https://app.example.com",
				"localStorageEntries": []map[string]string{{"key": "@@auth0spajs@@::spaClient1::@@user@@", "value": `{"id_token":"seed-only"}`}}}}
		if org, _ := f.idOrg.Load().(string); org != "" {
			claims, _ := json.Marshal(map[string]any{"sub": "auth0|qa-user", "org_id": org, "email": automatedSecrets["email"], "nonce": "n", "sid": "s"})
			out["idToken"] = "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	client := srv.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return f, client
}

func automatedEntry(t *testing.T) *Entry {
	t.Helper()
	c, err := Parse([]byte(`{"entries":[` + automatedEntryJSON(automatedSettings) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := &c.Entries()[0]
	// Each test gets its own binding to change.
	binding := *e.BrowserSession
	settings := *binding.AutomatedAuth
	binding.AutomatedAuth = &settings
	e.BrowserSession = &binding
	return e
}

type revocations struct {
	mu   sync.Mutex
	seen []string
}

func (r *revocations) record(binding, outcome string, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, binding+" "+outcome)
}

func (r *revocations) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// reachableStrings is every string and byte slice reachable from v,
// unexported fields included.
func reachableStrings(v reflect.Value, seen map[uintptr]bool, out *[]string) {
	switch v.Kind() {
	case reflect.String:
		*out = append(*out, v.String())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			*out = append(*out, string(v.Bytes()))
			return
		}
		for i := 0; i < v.Len(); i++ {
			reachableStrings(v.Index(i), seen, out)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			reachableStrings(v.Index(i), seen, out)
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		if v.Kind() == reflect.Pointer {
			if seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
		}
		reachableStrings(v.Elem(), seen, out)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			reachableStrings(v.Field(i), seen, out)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			reachableStrings(iter.Key(), seen, out)
			reachableStrings(iter.Value(), seen, out)
		}
	}
}

func TestAutomatedAuthSignInCachesAndRevokes(t *testing.T) {
	fake, client := fakeAutomatedAuth(t)
	entry := automatedEntry(t)
	now := time.Now()
	revoked := &revocations{}
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.DiscardHandler)) })
	tokens := &Auth0Tokens{Keys: &Keys{Vault: automatedVault{}}, Client: client, AutomatedAuth: client, Revoked: revoked.record,
		Now: func() time.Time { return now }}
	first, err := tokens.Token(context.Background(), entry)
	if err != nil || !strings.HasSuffix(first.Value(), ".synthetic-access-token-1") {
		t.Fatalf("sign-in: %v", err)
	}
	// The ID token supplies the claims, protocol claims dropped.
	if first.Claims["sub"] != "auth0|qa-user" || first.Claims["org_id"] != "org_synthetic" || first.Claims["email"] != automatedSecrets["email"] ||
		first.Claims["nonce"] != nil || first.Claims["sid"] != nil {
		t.Fatalf("claims: %v", first.Claims)
	}
	if d := first.Expires.Sub(now); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("expiry: %v", d)
	}
	if fake.revokes.Load() != 1 || !reflect.DeepEqual(revoked.all(), []string{"staging-app refresh_revoked"}) {
		t.Fatalf("revocation: %d %v", fake.revokes.Load(), revoked.all())
	}
	if s := fmt.Sprintf("%v %+v %#v %s", first, first, first, first); strings.Contains(s, "synthetic-access-token") {
		t.Fatal("token printed")
	}
	// The refresh token is held nowhere, the key cache included; the
	// password and service key only in the shared key cache. Every request
	// closes its connection, so no idle connection's read buffer keeps the
	// answer either (the HTTP clients are left out of the walk: their
	// transports change under it).
	if fake.kept.Load() != 0 {
		t.Fatalf("%d requests kept their connection", fake.kept.Load())
	}
	var held, own []string
	keys, auth0, automated := tokens.Keys, tokens.Client, tokens.AutomatedAuth
	tokens.Client, tokens.AutomatedAuth = nil, nil
	reachableStrings(reflect.ValueOf(tokens), map[uintptr]bool{}, &held)
	tokens.Keys = nil
	reachableStrings(reflect.ValueOf(tokens), map[uintptr]bool{}, &own)
	tokens.Keys, tokens.Client, tokens.AutomatedAuth = keys, auth0, automated
	for _, s := range append(held, logs.String()) {
		if strings.Contains(s, syntheticRefresh) {
			t.Fatal("refresh token held or logged")
		}
	}
	for _, s := range append(own, logs.String()) {
		if strings.Contains(s, automatedSecrets["password"]) || strings.Contains(s, automatedSecrets["private_key"]) {
			t.Fatal("token source holds or logs a sign-in secret")
		}
	}
	if again, _ := tokens.Token(context.Background(), entry); again.Value() != first.Value() || fake.logins.Load() != 1 {
		t.Fatal("token not cached")
	}
	now = now.Add(46 * time.Minute) // a quarter of the token's life left: the margin
	if renewed, _ := tokens.Token(context.Background(), entry); !strings.HasSuffix(renewed.Value(), ".synthetic-access-token-2") {
		t.Fatal("token not renewed before expiry")
	}
	// A refused token younger than the relogin interval is kept, so a worker
	// cannot force sign-ins; an older one is dropped.
	tokens.Invalidate(entry)
	if kept, _ := tokens.Token(context.Background(), entry); fake.logins.Load() != 2 || !strings.HasSuffix(kept.Value(), "-2") {
		t.Fatal("fresh token dropped")
	}
	now = now.Add(reloginInterval)
	tokens.Invalidate(entry)
	if after, _ := tokens.Token(context.Background(), entry); fake.logins.Load() != 3 || !strings.HasSuffix(after.Value(), "-3") {
		t.Fatal("invalidated token reused")
	}
}

// Without a top-level ID token (automated-auth's password sign-in returns
// none), the claims come from the access token and the seed is not read.
func TestAutomatedAuthClaimsFromAccessToken(t *testing.T) {
	fake, client := fakeAutomatedAuth(t)
	fake.idOrg.Store("")
	tokens := &Auth0Tokens{Keys: &Keys{Vault: automatedVault{}}, Client: client, AutomatedAuth: client}
	token, err := tokens.Token(context.Background(), automatedEntry(t))
	if err != nil || !reflect.DeepEqual(token.Claims, map[string]any{"sub": "auth0|qa-user", "org_id": "org_synthetic"}) {
		t.Fatalf("claims: %v %v", token.Claims, err)
	}
}

func TestAutomatedAuthRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup   func(*automatedFake, *Entry, *Auth0Tokens)
		logins  int32
		revokes int32
	}{
		// The binding's org is checked again at sign-in, after the catalog.
		"org missing":     {func(_ *automatedFake, e *Entry, _ *Auth0Tokens) { e.BrowserSession.AutomatedAuth.OrgID = "" }, 0, 0},
		"no client":       {func(_ *automatedFake, _ *Entry, a *Auth0Tokens) { a.AutomatedAuth = nil }, 0, 0},
		"vault error":     {func(_ *automatedFake, _ *Entry, a *Auth0Tokens) { a.Keys = &Keys{Vault: automatedVault{down: true}} }, 0, 0},
		"access org":      {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.org.Store("org_other") }, 1, 1},
		"ID token org":    {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.idOrg.Store("org_other") }, 1, 1},
		"audience":        {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.aud.Store(`"https://other.example.com"`) }, 1, 1},
		"no audience":     {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.aud.Store("null") }, 1, 1},
		"opaque token":    {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.jwt.Store(false) }, 1, 1},
		"short life":      {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.lifetime.Store(60) }, 1, 1},
		"refused sign-in": {func(f *automatedFake, _ *Entry, _ *Auth0Tokens) { f.status.Store(http.StatusBadGateway) }, 1, 0},
		"other profile": {func(_ *automatedFake, e *Entry, _ *Auth0Tokens) {
			e.BrowserSession.AutomatedAuth.Profile = "trm-b2b-prod"
		}, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			fake, client := fakeAutomatedAuth(t)
			entry := automatedEntry(t)
			tokens := &Auth0Tokens{Keys: &Keys{Vault: automatedVault{}}, Client: client, AutomatedAuth: client}
			tc.setup(fake, entry, tokens)
			_, err := tokens.Token(context.Background(), entry)
			if !errors.Is(err, ErrBrowserLogin) || fake.logins.Load() != tc.logins || fake.revokes.Load() != tc.revokes {
				t.Fatalf("err=%v logins=%d revokes=%d", err, fake.logins.Load(), fake.revokes.Load())
			}
			for _, secret := range []string{syntheticRefresh, "app.example.com", automatedSecrets["email"], automatedSecrets["password"], automatedSecrets["private_key"]} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error carries %s", secret)
				}
			}
		})
	}
}

// A refused revocation is tried once more, then reported revoke_failed;
// the sign-in itself succeeds.
func TestAutomatedAuthRevokeRetriesThenReports(t *testing.T) {
	old := revokeBackoff
	revokeBackoff = time.Millisecond
	t.Cleanup(func() { revokeBackoff = old })
	fake, client := fakeAutomatedAuth(t)
	fake.revokeErr.Store(true)
	revoked := &revocations{}
	tokens := &Auth0Tokens{Keys: &Keys{Vault: automatedVault{}}, Client: client, AutomatedAuth: client, Revoked: revoked.record}
	if _, err := tokens.Token(context.Background(), automatedEntry(t)); err != nil {
		t.Fatalf("sign-in failed over a revocation: %v", err)
	}
	if fake.revokes.Load() != 2 || !reflect.DeepEqual(revoked.all(), []string{"staging-app revoke_failed"}) {
		t.Fatalf("revocation: %d %v", fake.revokes.Load(), revoked.all())
	}
}

// The sign-in body holds the user's password and the service key; a
// redirect, even a 307 that would re-send it, is never followed.
func TestAutomatedAuthNeverFollowsARedirect(t *testing.T) {
	var elsewhere atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" {
			elsewhere.Add(1)
			return
		}
		http.Redirect(w, r, "https://collector.example.com/steal", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	client := srv.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tokens := &Auth0Tokens{Keys: &Keys{Vault: automatedVault{}}, AutomatedAuth: client}
	if _, err := tokens.Token(context.Background(), automatedEntry(t)); !errors.Is(err, ErrBrowserLogin) || elsewhere.Load() != 0 {
		t.Fatalf("redirect followed: err=%v requests elsewhere=%d", err, elsewhere.Load())
	}
}
