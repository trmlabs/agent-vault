package litellmkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// fakeVault is a KV version 2 mount with check-and-set.
type fakeVault struct {
	mu       sync.Mutex
	docs     map[string][]map[string]interface{} // path -> versions
	failCAS  bool
	failRead bool
}

func newFakeVault() *fakeVault { return &fakeVault{docs: map[string][]map[string]interface{}{}} }

func (v *fakeVault) ReadWithContext(_ context.Context, path string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failRead {
		return nil, errors.New("down")
	}
	versions := v.docs[path]
	if len(versions) == 0 {
		return nil, nil
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": versions[len(versions)-1],
		"metadata": map[string]interface{}{"version": json.Number(fmt.Sprint(len(versions)))}}}, nil
}

func (v *fakeVault) WriteWithContext(_ context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cas := data["options"].(map[string]interface{})["cas"].(int)
	if v.failCAS || cas != len(v.docs[path]) {
		return nil, errors.New("check-and-set parameter did not match the current version")
	}
	v.docs[path] = append(v.docs[path], data["data"].(map[string]interface{}))
	return &vaultapi.Secret{Data: map[string]interface{}{"version": json.Number(fmt.Sprint(len(v.docs[path])))}}, nil
}

func (v *fakeVault) put(path string, doc map[string]interface{}) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.docs[path] = append(v.docs[path], doc)
}

func (v *fakeVault) latest(path string) map[string]interface{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	versions := v.docs[path]
	if len(versions) == 0 {
		return nil
	}
	return versions[len(versions)-1]
}

func (v *fakeVault) versions(path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.docs[path])
}

// fakeLiteLLM mints keys for the team key only and records every call.
type fakeLiteLLM struct {
	mu           sync.Mutex
	generated    []map[string]any
	deleted      []string
	live         map[string]bool // alias -> live
	failMint     map[string]bool // pool -> 500
	deleteCode   int
	badKey       bool
	seq          int
	redirectTo   string
	authorized   int
	unauthorized int
}

const minterValue = "sk-team-admin-synthetic-0000"

func newFakeLiteLLM(t *testing.T) (*fakeLiteLLM, *httptest.Server) {
	f := &fakeLiteLLM{live: map[string]bool{}, failMint: map[string]bool{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.redirectTo != "" {
			http.Redirect(w, r, f.redirectTo, http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+minterValue {
			f.unauthorized++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.authorized++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/key/generate":
			pool := body["metadata"].(map[string]any)["gatehouse_pool"].(string)
			if f.failMint[pool] {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.seq++
			f.generated = append(f.generated, body)
			alias := body["key_alias"].(string)
			f.live[alias] = true
			key := fmt.Sprintf("sk-synthetic-virtual-key-%04d", f.seq)
			if f.badKey {
				key = "not-a-key"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"key": key, "key_alias": alias,
				"expires": time.Now().Add(365 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000000")})
		case "/key/delete":
			for _, a := range body["key_aliases"].([]any) {
				f.deleted = append(f.deleted, a.(string))
				if f.deleteCode != 0 {
					w.WriteHeader(f.deleteCode)
					return
				}
				if !f.live[a.(string)] {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				delete(f.live, a.(string))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted_keys": body["key_aliases"]})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

const devPath = "gatehouse/data/vendors/litellm-staging/gatehouse-trial-database-developer"

func testConfig(gateway string) Config {
	return Config{
		Gateway: gateway, TeamID: "gatehouse-staging",
		MinterKey:    KeyRef{Mount: "gatehouse", Path: "vendors/litellm-staging-minter", Field: "key"},
		RotateBefore: "7d", RevokeAfter: "1h",
		Keys: []Key{{Pool: "gatehouse-trial-database-developer", Mount: "gatehouse", Path: "vendors/litellm-staging/gatehouse-trial-database-developer",
			MaxBudget: 250, BudgetDuration: "30d", Duration: "30d", Models: []string{"claude-sonnet-5-5", "gpt-5.5"}}},
	}
}

func setup(t *testing.T) (*Reconciler, *fakeVault, *fakeLiteLLM, *time.Time, *bytes.Buffer) {
	f, srv := newFakeLiteLLM(t)
	v := newFakeVault()
	v.put("gatehouse/data/vendors/litellm-staging-minter", map[string]interface{}{"key": minterValue})
	now := time.Now()
	var logs bytes.Buffer
	r := &Reconciler{Config: testConfig(srv.URL), Vault: v, Client: srv.Client(), Now: func() time.Time { return now },
		Log: slog.New(slog.NewJSONHandler(&logs, nil))}
	return r, v, f, &now, &logs
}

func (f *fakeLiteLLM) counts() (generated, deleted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.generated), len(f.deleted)
}

func TestFirstRunMintsUnderTheTeam(t *testing.T) {
	r, v, f, _, logs := setup(t)
	res, err := r.Run(context.Background())
	if err != nil || res.Minted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.mu.Lock()
	body := f.generated[0]
	f.mu.Unlock()
	if body["team_id"] != "gatehouse-staging" || body["key_type"] != "llm_api" || body["max_budget"] != 250.0 || body["duration"] != "30d" || body["budget_duration"] != "30d" ||
		fmt.Sprint(body["models"]) != "[claude-sonnet-5-5 gpt-5.5]" || !strings.HasPrefix(body["key_alias"].(string), "gatehouse-gatehouse-trial-database-developer-") {
		t.Fatalf("minted with %v", body)
	}
	doc := v.latest(devPath)
	if doc["key"] != "sk-synthetic-virtual-key-0001" || doc["alias"] != body["key_alias"] || doc["expires"] == nil || doc["previousAlias"] != nil {
		t.Fatalf("document %v", doc)
	}
	if strings.Contains(logs.String(), "sk-") {
		t.Fatalf("a key reached the log: %s", logs.String())
	}
}

func TestCurrentKeyIsLeftAlone(t *testing.T) {
	r, v, f, now, _ := setup(t)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(22 * 24 * time.Hour) // eight days before expiry
	res, err := r.Run(context.Background())
	if err != nil || res.Current != 1 || res.Minted != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if generated, _ := f.counts(); generated != 1 || v.versions(devPath) != 1 {
		t.Fatalf("generated=%d versions=%d", generated, v.versions(devPath))
	}
}

func TestRotationKeepsTheOldKeyThenRevokesIt(t *testing.T) {
	r, v, f, now, _ := setup(t)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := v.latest(devPath)["alias"].(string)
	*now = now.Add(24 * 24 * time.Hour) // six days before expiry
	if res, err := r.Run(context.Background()); err != nil || res.Minted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	doc := v.latest(devPath)
	if doc["key"] != "sk-synthetic-virtual-key-0002" || doc["previousAlias"] != first {
		t.Fatalf("document %v", doc)
	}
	*now = now.Add(30 * time.Minute)
	if res, err := r.Run(context.Background()); err != nil || res.Revoked != 0 {
		t.Fatalf("revoked before revokeAfter: res=%+v err=%v", res, err)
	}
	*now = now.Add(31 * time.Minute)
	if res, err := r.Run(context.Background()); err != nil || res.Revoked != 1 || res.Current != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.mu.Lock()
	deleted, live := fmt.Sprint(f.deleted), f.live[first]
	f.mu.Unlock()
	if deleted != "["+first+"]" || live {
		t.Fatalf("deleted %s, first still live %v", deleted, live)
	}
	doc = v.latest(devPath)
	if doc["key"] != "sk-synthetic-virtual-key-0002" || doc["previousAlias"] != nil || doc["revokeAfter"] != nil {
		t.Fatalf("document after revoke %v", doc)
	}
}

func TestChangedSettingsReplaceTheKey(t *testing.T) {
	r, v, _, _, _ := setup(t)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Config.Keys[0].MaxBudget = 500
	if res, err := r.Run(context.Background()); err != nil || res.Minted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if v.latest(devPath)["previousAlias"] == nil {
		t.Fatal("the replaced key was not queued for revocation")
	}
}

func TestHandWrittenKeyIsReplacedNotRevoked(t *testing.T) {
	r, v, f, _, _ := setup(t)
	v.put(devPath, map[string]interface{}{"key": "sk-written-by-hand-synthetic"})
	if res, err := r.Run(context.Background()); err != nil || res.Minted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if doc := v.latest(devPath); doc["previousAlias"] != nil {
		t.Fatalf("a hand-written key was queued for revocation: %v", doc)
	}
	if _, deleted := f.counts(); deleted != 0 {
		t.Fatal("deleted something")
	}
}

func TestFailedWriteRevokesTheNewKey(t *testing.T) {
	r, v, f, _, _ := setup(t)
	v.failCAS = true
	if res, err := r.Run(context.Background()); err == nil || res.Failed != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.generated) != 1 || len(f.live) != 0 {
		t.Fatalf("a key Vault does not record is still live: %v", f.live)
	}
}

func TestOnePoolFailingDoesNotStopTheOthers(t *testing.T) {
	r, v, f, _, _ := setup(t)
	other := r.Config.Keys[0]
	other.Pool, other.Path = "gatehouse-other-pool", "vendors/litellm-staging/gatehouse-other-pool"
	r.Config.Keys = append(r.Config.Keys, other)
	f.failMint["gatehouse-trial-database-developer"] = true
	res, err := r.Run(context.Background())
	if err == nil || res.Failed != 1 || res.Minted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if v.latest("gatehouse/data/vendors/litellm-staging/gatehouse-other-pool") == nil {
		t.Fatal("the healthy pool got no key")
	}
}

func TestUnusableKeyIsRevokedAndNotWritten(t *testing.T) {
	r, v, f, _, _ := setup(t)
	f.badKey = true
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("an unusable key was accepted")
	}
	if v.latest(devPath) != nil {
		t.Fatal("an unusable key was written")
	}
	if _, deleted := f.counts(); deleted != 1 {
		t.Fatal("the unusable key was not revoked")
	}
}

func TestRevocationFailureKeepsThePreviousAlias(t *testing.T) {
	r, v, f, now, _ := setup(t)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * 24 * time.Hour)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.deleteCode = http.StatusInternalServerError
	f.mu.Unlock()
	*now = now.Add(2 * time.Hour)
	if res, err := r.Run(context.Background()); err == nil || res.Failed != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if v.latest(devPath)["previousAlias"] == nil {
		t.Fatal("a failed revocation was forgotten")
	}
}

func TestMinterKeyMissingFailsTheRun(t *testing.T) {
	r, v, f, _, _ := setup(t)
	v.mu.Lock()
	delete(v.docs, "gatehouse/data/vendors/litellm-staging-minter")
	v.mu.Unlock()
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("ran without a minter key")
	}
	if generated, _ := f.counts(); generated != 0 {
		t.Fatal("called LiteLLM")
	}
}

func TestRedirectIsNotFollowedWithTheTeamKey(t *testing.T) {
	r, _, f, _, _ := setup(t)
	elsewhere, other := newFakeLiteLLM(t)
	f.redirectTo = other.URL + "/key/generate"
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("a redirect was followed")
	}
	elsewhere.mu.Lock()
	defer elsewhere.mu.Unlock()
	if elsewhere.authorized+elsewhere.unauthorized != 0 {
		t.Fatal("the redirect target was called")
	}
}

func TestParseRefusesBadConfigs(t *testing.T) {
	good, _ := json.Marshal(testConfig("https://litellm.example.com"))
	if _, err := Parse(good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"http gateway":         func(c *Config) { c.Gateway = "http://litellm.example.com" },
		"gateway with path":    func(c *Config) { c.Gateway = "https://litellm.example.com/v1" },
		"no team":              func(c *Config) { c.TeamID = "" },
		"rotate after expiry":  func(c *Config) { c.RotateBefore = "30d" },
		"bad duration":         func(c *Config) { c.Keys[0].Duration = "1 month" },
		"zero budget":          func(c *Config) { c.Keys[0].MaxBudget = 0 },
		"no models":            func(c *Config) { c.Keys[0].Models = nil },
		"minter path reused":   func(c *Config) { c.Keys[0].Path = c.MinterKey.Path },
		"two keys on one path": func(c *Config) { c.Keys = append(c.Keys, c.Keys[0]) },
		"bad pool":             func(c *Config) { c.Keys[0].Pool = "Pool_A" },
		"path traversal":       func(c *Config) { c.Keys[0].Path = "vendors/../catalog" },
	} {
		c := testConfig("https://litellm.example.com")
		mutate(&c)
		data, _ := json.Marshal(c)
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	unknown := strings.Replace(string(good), `"teamID"`, `"masterKey":"x","teamID"`, 1)
	if _, err := Parse([]byte(unknown)); err == nil {
		t.Error("an unknown field was accepted")
	}
}
