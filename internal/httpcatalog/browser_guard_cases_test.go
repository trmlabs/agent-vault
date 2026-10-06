package httpcatalog

import (
	"errors"
	"strings"
	"testing"
)

// A browser-session entry names the API paths it needs, never "/", and none
// may reach a credential or account-admin route; its route templates are
// strict. Other kinds take no route templates.
func TestBrowserPathGuardAtLoad(t *testing.T) {
	entry := func(prefixes, extra string) string {
		return strings.Replace(browserEntryJSON(extra), `"pathPrefixes":["/v1"]`, `"pathPrefixes":`+prefixes, 1)
	}
	for name, doc := range map[string]string{
		"no prefixes":          strings.Replace(browserEntryJSON(""), `"pathPrefixes":["/v1"],`, "", 1),
		"root prefix":          entry(`["/"]`, ""),
		"api key prefix":       entry(`["/organizations/1/apiKey"]`, ""),
		"mixed case api key":   entry(`["/organizations/1/API_KEY"]`, ""),
		"password prefix":      entry(`["/users/change-password"]`, ""),
		"mfa prefix":           entry(`["/users/MFA"]`, ""),
		"oauth client prefix":  entry(`["/v1/oauth/clients"]`, ""),
		"user admin prefix":    entry(`["/v1/parent-organizations/1/users/2/roles"]`, ""),
		"client secret prefix": entry(`["/v1/apps/1/client_secret"]`, ""),
		"sessions prefix":      entry(`["/v1/sessions"]`, ""),
		"dot segment prefix":   entry(`["/v1/./cases"]`, ""),
		"dot-dot prefix":       entry(`["/v1/../admin"]`, ""),
		"partial wildcard":     browserEntryJSON(`,"deniedPaths":["/v1/parent-*/users"]`),
		"dot-dot template":     browserEntryJSON(`,"readOnlyPaths":["/v1/reports/.."]`),
		"query in template":    browserEntryJSON(`,"deniedPaths":["/v1/users?x=1"]`),
		"overlong template":    browserEntryJSON(`,"deniedPaths":["/` + strings.Repeat("a", 256) + `"]`),
		"templates on http kind": `{"name":"vendor","host":"vendor.example.com","pathPrefixes":["/v1"],"methods":["GET"],"header":"Authorization",
			"scheme":"Bearer","placeholder":"__vault_VENDOR__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["p"],"deniedPaths":["/v1/admin"]}`,
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, err := Parse([]byte(`{"entries":[` + entry(`["/v1","/users-organizations"]`,
		`,"deniedPaths":["/v1/parent-organizations/*/users"],"readOnlyPaths":["/v1/reports"]`) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Entries()[0]; len(e.DeniedPaths) != 1 || len(e.ReadOnlyPaths) != 1 {
		t.Fatalf("templates not kept: %+v", e)
	}
}

// Every API request is checked: credential and account-admin segments are
// refused anywhere in the path, a denied template refuses itself and every
// path below it, and membership and read-only templates admit only reads.
func TestBrowserPathGuardPerRequest(t *testing.T) {
	doc := strings.Replace(browserEntryJSON(`,"deniedPaths":["/v1/parent-organizations/*/users","/v1/parent-organizations/*/invitations",
		"/v1/users/*/email","/v1/intel-vault"],"readOnlyPaths":["/v1/reports"]`),
		`"pathPrefixes":["/v1"]`, `"pathPrefixes":["/v1","/v2","/api","/users-organizations","/organizations","/users"]`, 1)
	c, err := Parse([]byte(`{"entries":[` + doc + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		err          error
	}{
		{"POST", "/organizations/123/apiKey", ErrDeniedPath},
		{"GET", "/organizations/123/APIKEY", ErrDeniedPath},
		{"GET", "/organizations/123/api_key/", ErrDeniedPath},
		{"POST", "/users/change-password", ErrDeniedPath},
		{"GET", "/users/mfa", ErrDeniedPath},
		{"POST", "/v1/oauth/clients/x/rotate-secret", ErrDeniedPath},
		{"GET", "/v1/parent-organizations/1/users/2/roles", ErrDeniedPath},
		{"GET", "/v1/parent-organizations/7/users", ErrDeniedPath},
		{"GET", "/v1/Parent-Organizations/7/Users/3", ErrDeniedPath},
		{"POST", "/v1/parent-organizations/7/invitations", ErrDeniedPath},
		{"PATCH", "/v1/users/5/email", ErrDeniedPath},
		{"GET", "/v1/intel-vault/admin/1/permissions", ErrDeniedPath},
		{"GET", "/v1/intel-vault/cases", ErrDeniedPath},
		{"GET", "/v1/apps/1/client-secret", ErrDeniedPath},
		{"POST", "/users-organizations", ErrReadOnlyPath},
		{"PATCH", "/v1/users-organizations/users/2", ErrReadOnlyPath},
		{"POST", "/api/v1/users-organizations/users", ErrReadOnlyPath},
		{"DELETE", "/v2/Users_Organizations", ErrReadOnlyPath},
		{"POST", "/v1/reports/9", ErrReadOnlyPath},
		{"GET", "/users-organizations", nil},
		{"HEAD", "/users-organizations/users", nil},
		{"OPTIONS", "/users-organizations", nil},
		{"GET", "/v1/reports/9", nil},
		{"POST", "/v1/cases", nil},
		{"GET", "/v1/parent-organizations/7/environments", nil},
		{"GET", "/v1/users/5/shared-with-me", nil},
		{"GET", BrowserSeedPath, nil},
	} {
		if _, _, err := c.BrowserMatch("api.example.com", 443, tc.method, tc.path, "database-developers"); !errors.Is(err, tc.err) {
			t.Errorf("%s %s: %v, want %v", tc.method, tc.path, err, tc.err)
		}
	}
	// Membership stays read-only for an entry that names no read-only paths.
	plain, err := Parse([]byte(`{"entries":[` + browserEntryJSON("") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := plain.BrowserMatch("api.example.com", 443, "POST", "/v1/users-organizations", "database-developers"); !errors.Is(err, ErrReadOnlyPath) {
		t.Fatalf("membership write on an entry without readOnlyPaths: %v", err)
	}
}
