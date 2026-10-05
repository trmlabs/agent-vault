package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	gcpGroup = "22222222-2222-2222-2222-222222222222"
	gcpPools = `"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}]`
	gcsEntry = `{"name":"team-files","kind":"gcp","host":"storage.googleapis.com","tier":"T1","requires":["` + gcpGroup + `"],
	  "placeholder":"__vault_GCP__","pools":["claude"],
	  "gcp":{"bucket":"trm-agent-files","prefix":"teams/analytics/","role":"roles/storage.objectViewer"}}`
	bqEntry = `{"name":"bq-cases","kind":"gcp","host":"bigquery.googleapis.com","tier":"T1","requires":["` + gcpGroup + `"],
	  "placeholder":"__vault_GCP__","pools":["claude"],"pathPrefixes":["/bigquery/v2/projects/trm-analytics/"],
	  "gcp":{"serviceAccount":"gh-bq-cases@trm-analytics.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/bigquery"]}}`
)

func gcpCatalog(t *testing.T, entries ...string) Catalog {
	t.Helper()
	c, err := Parse([]byte(`{` + gcpPools + `,"entries":[` + strings.Join(entries, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGCPEntries(t *testing.T) {
	c := gcpCatalog(t, gcsEntry, bqEntry)
	gcs, ok, err := c.GCPMatch("storage.googleapis.com", 443, "GET", "/storage/v1/b/trm-agent-files/o/teams%2Fanalytics%2Fa.csv", "claude")
	if !ok || err != nil || gcs.Name != "team-files" || gcs.GCP.LifetimeSeconds != 900 || len(gcs.PathPrefixes) != 3 {
		t.Fatalf("gcs: %+v %v %v", gcs, ok, err)
	}
	if bq, _, err := c.GCPMatch("bigquery.googleapis.com", 443, "POST", "/bigquery/v2/projects/trm-analytics/queries", "claude"); err != nil || bq.GCP.ServiceAccount == "" {
		t.Fatalf("bigquery: %v", err)
	}
	if _, _, err := c.GCPMatch("bigquery.googleapis.com", 443, "GET", "/bigquery/v2/projects/other/datasets", "claude"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("other project: %v", err)
	}
	if _, _, err := c.GCPMatch("storage.googleapis.com", 443, "GET", "/storage/v1/b/other-bucket/o", "claude"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("other bucket: %v", err)
	}
	if _, _, err := c.GCPMatch("storage.googleapis.com", 443, "GET", "/storage/v1/b/trm-agent-files/o", "cursor"); !errors.Is(err, ErrPool) {
		t.Fatalf("cursor pool matched: %v", err)
	}
	if _, ok, _ := c.GCPMatch("pubsub.googleapis.com", 443, "GET", "/", "claude"); ok {
		t.Fatal("unlisted Google host routed")
	}
}

func TestGCPEntryRejects(t *testing.T) {
	sub := func(entry, old, new string) string { return strings.Replace(entry, old, new, 1) }
	for name, entry := range map[string]string{
		"granted to the Cursor pool":     sub(gcsEntry, `"pools":["claude"]`, `"pools":["claude","cursor"]`),
		"tier T0":                        sub(sub(gcsEntry, `"tier":"T1"`, `"tier":"T0"`), `"requires":["`+gcpGroup+`"],`, ``),
		"minting host":                   sub(bqEntry, `bigquery.googleapis.com`, `iamcredentials.googleapis.com`),
		"IAM-changing host":              sub(bqEntry, `bigquery.googleapis.com`, `cloudresourcemanager.googleapis.com`),
		"unlisted Google service":        sub(bqEntry, `bigquery.googleapis.com`, `compute.googleapis.com`),
		"not Google":                     sub(bqEntry, `bigquery.googleapis.com`, `bigquery.example.com`),
		"prefix without slash":           sub(gcsEntry, `teams/analytics/`, `teams/analytics`),
		"prefix breaking CEL":            sub(gcsEntry, `teams/analytics/`, `teams/a')||true||('/`),
		"bucket admin role":              sub(gcsEntry, `roles/storage.objectViewer`, `roles/storage.admin`),
		"downscope off storage":          sub(gcsEntry, `storage.googleapis.com`, `bigquery.googleapis.com`),
		"both modes":                     sub(gcsEntry, `"role":"roles/storage.objectViewer"`, `"role":"roles/storage.objectViewer","serviceAccount":"gh-x@trm-analytics.iam.gserviceaccount.com"`),
		"not a service account":          sub(bqEntry, `gh-bq-cases@trm-analytics.iam.gserviceaccount.com`, `someone@trmlabs.com`),
		"impersonation without paths":    sub(bqEntry, `"pathPrefixes":["/bigquery/v2/projects/trm-analytics/"],`, ``),
		"lifetime too long":              sub(bqEntry, `"scopes"`, `"lifetimeSeconds":7200,"scopes"`),
		"gcp settings on a header entry": sub(gcsEntry, `"kind":"gcp",`, `"header":"Authorization","methods":["GET"],"pathPrefixes":["/x"],"key":{"mount":"m","path":"p","field":"f"},`),
	} {
		if _, err := Parse([]byte(`{` + gcpPools + `,"entries":[` + entry + `]}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type staticRoot struct{ token *oauth2.Token }

func (s staticRoot) Token() (*oauth2.Token, error) { return s.token, nil }

func TestGCPTokensDownscopeAndImpersonate(t *testing.T) {
	var sts, iam atomic.Int32
	var boundary atomic.Value
	var minted atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/token":
			sts.Add(1)
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			_ = r.ParseForm()
			if r.Form.Get("subject_token") != "root-token" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			boundary.Store(r.Form.Get("options"))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("downscoped-%d", sts.Load()), "token_type": "Bearer"})
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			iam.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			minted.Store(r.URL.Path + " " + fmt.Sprint(body["lifetime"]))
			if r.Header.Get("Authorization") != "Bearer root-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "impersonated-" + url.PathEscape(r.URL.Path),
				"expireTime": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)})
		}
	}))
	defer srv.Close()
	c := gcpCatalog(t, gcsEntry, bqEntry)
	entries := c.Entries()
	now := time.Now()
	tokens := &GCPTokens{Root: staticRoot{&oauth2.Token{AccessToken: "root-token", Expiry: now.Add(time.Hour)}}, Client: srv.Client(),
		STSURL: srv.URL + "/v1/token", IAMCredentialsURL: srv.URL, Now: func() time.Time { return now }}

	gcs, err := tokens.Token(context.Background(), &entries[0])
	if err != nil || gcs.Value() != "downscoped-1" || gcs.Expires.Sub(now) != 15*time.Minute {
		t.Fatalf("downscope: %v %v", err, gcs)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(boundary.Load().(string)), &got); err != nil {
		t.Fatal(err)
	}
	rule := got["accessBoundary"].(map[string]any)["accessBoundaryRules"].([]any)[0].(map[string]any)
	condition := rule["availabilityCondition"].(map[string]any)["expression"].(string)
	if rule["availableResource"] != "//storage.googleapis.com/projects/_/buckets/trm-agent-files" ||
		fmt.Sprint(rule["availablePermissions"]) != "[inRole:roles/storage.objectViewer]" ||
		!strings.Contains(condition, "startsWith('projects/_/buckets/trm-agent-files/objects/teams/analytics/')") {
		t.Fatalf("boundary: %v", rule)
	}
	if again, _ := tokens.Token(context.Background(), &entries[0]); again.Value() != gcs.Value() || sts.Load() != 1 {
		t.Fatal("downscoped token not cached")
	}
	if s := fmt.Sprintf("%v %+v %#v %s", gcs, gcs, gcs, gcs); strings.Contains(s, "downscoped-") {
		t.Fatal("token printed")
	}

	bq, err := tokens.Token(context.Background(), &entries[1])
	if err != nil || !strings.Contains(bq.Value(), "gh-bq-cases@trm-analytics.iam.gserviceaccount.com") ||
		minted.Load() != "/v1/projects/-/serviceAccounts/gh-bq-cases@trm-analytics.iam.gserviceaccount.com:generateAccessToken 900s" {
		t.Fatalf("impersonate: %v %v %v", err, bq, minted.Load())
	}
	now = now.Add(12 * time.Minute) // a fifth of its use left: mint again
	if renewed, _ := tokens.Token(context.Background(), &entries[1]); iam.Load() != 2 || renewed.Value() == "" {
		t.Fatalf("not renewed: %d", iam.Load())
	}
	tokens.Root = staticRoot{&oauth2.Token{AccessToken: "wrong-root", Expiry: now.Add(time.Hour)}}
	tokens.Invalidate(&entries[1])
	if _, err := tokens.Token(context.Background(), &entries[1]); !errors.Is(err, ErrGCPToken) {
		t.Fatalf("refused mint: %v", err)
	}
}

// The billing header bills another project, so it passes only on opt-in.
func TestGCPUserProjectHeaderIsOptIn(t *testing.T) {
	c, err := Parse([]byte(`{` + gcpPools + `,"entries":[` + bqEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if !e.GCPForwardsHeader("x-goog-api-client") || e.GCPForwardsHeader("X-Goog-User-Project") {
		t.Fatal("billing header forwarded by default")
	}
	opted, err := Parse([]byte(`{` + gcpPools + `,"entries":[` + strings.Replace(bqEntry, `"gcp":`, `"forwardHeaders":["X-Goog-User-Project"],"gcp":`, 1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := opted.Entries()[0]; !e.GCPForwardsHeader("x-goog-user-project") {
		t.Fatal("opted-in billing header refused")
	}
}
