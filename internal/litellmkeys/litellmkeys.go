// Package litellmkeys mints, rotates and revokes the LiteLLM virtual keys the
// broker injects for each pool. It runs as a short job with its own Vault
// login, never inside the broker: the team key that can mint keys never
// reaches a process that agents talk to.
//
// Each pool's key lives in one KV version 2 document. The document holds the
// key in its "key" field, which is the only field the broker reads, beside
// the bookkeeping this package needs: the key's alias and expiry, a digest of
// the settings it was minted with, and the previous alias waiting to be
// revoked. One versioned write records a new key and its bookkeeping
// together, so a failed run never strands a key Vault does not describe.
package litellmkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config is the job's whole input. It names Vault locations and LiteLLM
// settings only; Vault holds every key.
type Config struct {
	Gateway      string   `json:"gateway"`      // https://<LiteLLM host>
	TeamID       string   `json:"teamID"`       // the capped LiteLLM team every key belongs to
	MinterKey    KeyRef   `json:"minterKey"`    // the team admin key that mints and revokes
	RotateBefore Duration `json:"rotateBefore"` // mint a replacement this long before expiry
	RevokeAfter  Duration `json:"revokeAfter"`  // keep the replaced key this long, then revoke it
	Keys         []Key    `json:"keys"`
}

// Key is one pool's key: where it lives and what it is minted with.
type Key struct {
	Pool           string   `json:"pool"`
	Mount          string   `json:"mount"`
	Path           string   `json:"path"`
	MaxBudget      float64  `json:"maxBudget"` // US dollars per budget period
	BudgetDuration Duration `json:"budgetDuration"`
	Duration       Duration `json:"duration"` // the key's lifetime
	Models         []string `json:"models"`
}

// KeyRef locates a value in a KV version 2 secret.
type KeyRef struct {
	Mount string `json:"mount"`
	Path  string `json:"path"`
	Field string `json:"field"`
}

// Duration is a LiteLLM-style duration: a whole number of days ("30d"),
// hours ("12h") or minutes ("90m").
type Duration string

var durationShape = regexp.MustCompile(`^([1-9][0-9]{0,3})([dhm])$`)

func (d Duration) Value() (time.Duration, error) {
	m := durationShape.FindStringSubmatch(string(d))
	if m == nil {
		return 0, fmt.Errorf("duration %q must be a whole number of d, h or m", string(d))
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "m": time.Minute}[m[2]]
	return time.Duration(n) * unit, nil
}

var (
	poolName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	mountName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	kvPath    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)
	teamID    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	modelName = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
)

// Parse reads a config strictly: an unknown field refuses it.
func Parse(data []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("litellm keys config: %w", err)
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("litellm keys config: %w", err)
	}
	return c, nil
}

func (c Config) validate() error {
	u, err := url.Parse(c.Gateway)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return errors.New("gateway must be an https origin")
	}
	if !teamID.MatchString(c.TeamID) {
		return errors.New("teamID is required")
	}
	if !mountName.MatchString(c.MinterKey.Mount) || !kvPath.MatchString(c.MinterKey.Path) || c.MinterKey.Field == "" {
		return errors.New("minterKey needs a mount, path and field")
	}
	rotate, err := c.RotateBefore.Value()
	if err != nil {
		return fmt.Errorf("rotateBefore: %w", err)
	}
	if _, err := c.RevokeAfter.Value(); err != nil {
		return fmt.Errorf("revokeAfter: %w", err)
	}
	if len(c.Keys) == 0 {
		return errors.New("no keys")
	}
	seen := map[string]bool{c.MinterKey.Mount + "/" + c.MinterKey.Path: true}
	for _, k := range c.Keys {
		if !poolName.MatchString(k.Pool) {
			return fmt.Errorf("pool %q is not a pool name", k.Pool)
		}
		if !mountName.MatchString(k.Mount) || !kvPath.MatchString(k.Path) {
			return fmt.Errorf("%s: mount and path required", k.Pool)
		}
		if seen[k.Mount+"/"+k.Path] {
			return fmt.Errorf("%s: path repeats another key or the minter key", k.Pool)
		}
		seen[k.Mount+"/"+k.Path] = true
		if !(k.MaxBudget > 0) {
			return fmt.Errorf("%s: maxBudget must be positive", k.Pool)
		}
		if _, err := k.BudgetDuration.Value(); err != nil {
			return fmt.Errorf("%s budgetDuration: %w", k.Pool, err)
		}
		lifetime, err := k.Duration.Value()
		if err != nil {
			return fmt.Errorf("%s duration: %w", k.Pool, err)
		}
		if rotate >= lifetime {
			return fmt.Errorf("%s: rotateBefore must be shorter than the key's duration", k.Pool)
		}
		if len(k.Models) == 0 {
			return fmt.Errorf("%s: models required", k.Pool)
		}
		for _, m := range k.Models {
			if !modelName.MatchString(m) {
				return fmt.Errorf("%s: model %q", k.Pool, m)
			}
		}
	}
	return nil
}

// settingsDigest changes whenever a key's minted settings change, so a new
// budget or model list replaces the key on the next run.
func (c Config) settingsDigest(k Key) string {
	models := slices.Clone(k.Models)
	slices.Sort(models)
	doc, _ := json.Marshal([]any{c.TeamID, k.MaxBudget, k.BudgetDuration, k.Duration, models})
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:8])
}

// Vault is the KV access the job needs; *vaultapi.Logical has it.
type Vault interface {
	ReadWithContext(ctx context.Context, path string) (*vaultapi.Secret, error)
	WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error)
}

// Reconciler brings every configured key to a live, current, unexpired state.
type Reconciler struct {
	Config Config
	Vault  Vault
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time

	minterKey string
}

// document is one pool's KV document. Key is the only field the broker reads.
type document struct {
	Key           string `json:"key"`
	Alias         string `json:"alias,omitempty"`
	Expires       string `json:"expires,omitempty"`
	Settings      string `json:"settings,omitempty"`
	PreviousAlias string `json:"previousAlias,omitempty"`
	RevokeAfter   string `json:"revokeAfter,omitempty"`
}

// Result counts what one run did, for the job's single summary line.
type Result struct {
	Minted, Revoked, Current, Failed int
}

// Run reconciles every key and returns the counts. A failure on one key is
// logged and counted, and the others still run; the job exits non-zero when
// any key failed.
func (r *Reconciler) Run(ctx context.Context) (Result, error) {
	var res Result
	key, err := r.readField(ctx, r.Config.MinterKey)
	if err != nil {
		return res, fmt.Errorf("minter key: %w", err)
	}
	r.minterKey = key
	defer func() { r.minterKey = "" }()
	for _, k := range r.Config.Keys {
		minted, revoked, err := r.reconcile(ctx, k)
		res.Revoked += revoked
		switch {
		case err != nil:
			res.Failed++
			r.log().Warn("litellm key not reconciled", slog.String("pool", k.Pool), slog.String("reason", err.Error()))
		case minted:
			res.Minted++
		default:
			res.Current++
		}
	}
	if res.Failed > 0 {
		return res, fmt.Errorf("%d of %d keys failed", res.Failed, len(r.Config.Keys))
	}
	return res, nil
}

func (r *Reconciler) reconcile(ctx context.Context, k Key) (minted bool, revoked int, err error) {
	now := r.now()
	doc, version, err := r.readDocument(ctx, k)
	if err != nil {
		return false, 0, err
	}
	rotate, _ := r.Config.RotateBefore.Value()
	expires, _ := time.Parse(time.RFC3339, doc.Expires)
	due := doc.Key == "" || doc.Alias == "" || doc.Settings != r.Config.settingsDigest(k) || !now.Before(expires.Add(-rotate))

	// The replaced key is revoked once the broker has had time to read the
	// new one, or straight away when yet another replacement is due.
	if doc.PreviousAlias != "" {
		revokeAt, _ := time.Parse(time.RFC3339, doc.RevokeAfter)
		if due || !now.Before(revokeAt) {
			if err := r.deleteAlias(ctx, doc.PreviousAlias); err != nil {
				return false, 0, fmt.Errorf("revoke %s: %w", doc.PreviousAlias, err)
			}
			revoked = 1
			doc.PreviousAlias, doc.RevokeAfter = "", ""
			if !due {
				if version, err = r.writeDocument(ctx, k, doc, version); err != nil {
					return false, revoked, err
				}
			}
		}
	}
	if !due {
		return false, revoked, nil
	}

	alias := "gatehouse-" + k.Pool + "-" + strings.ToLower(now.UTC().Format("20060102t150405"))
	key, keyExpires, err := r.generate(ctx, k, alias)
	if err != nil {
		return false, revoked, fmt.Errorf("mint: %w", err)
	}
	revokeAfter, _ := r.Config.RevokeAfter.Value()
	next := document{Key: key, Alias: alias, Expires: keyExpires.UTC().Format(time.RFC3339), Settings: r.Config.settingsDigest(k)}
	if doc.Alias != "" && doc.Key != "" {
		// A key this job minted is replaced; one written by hand has no alias
		// and simply runs out.
		next.PreviousAlias, next.RevokeAfter = doc.Alias, now.Add(revokeAfter).UTC().Format(time.RFC3339)
	}
	if _, err := r.writeDocument(ctx, k, next, version); err != nil {
		// Never leave a key live that Vault does not record.
		if derr := r.deleteAlias(ctx, alias); derr != nil {
			return false, revoked, fmt.Errorf("write: %w; the new key %s is still live: %v", err, alias, derr)
		}
		return false, revoked, fmt.Errorf("write: %w", err)
	}
	r.log().Info("litellm key minted", slog.String("pool", k.Pool), slog.String("alias", alias), slog.String("expires", next.Expires))
	return true, revoked, nil
}

func (r *Reconciler) readDocument(ctx context.Context, k Key) (document, int, error) {
	secret, err := r.Vault.ReadWithContext(ctx, k.Mount+"/data/"+k.Path)
	if err != nil {
		return document{}, 0, errors.New("vault read failed")
	}
	if secret == nil || secret.Data == nil {
		return document{}, 0, nil
	}
	var doc document
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		doc.Key, _ = data["key"].(string)
		doc.Alias, _ = data["alias"].(string)
		doc.Expires, _ = data["expires"].(string)
		doc.Settings, _ = data["settings"].(string)
		doc.PreviousAlias, _ = data["previousAlias"].(string)
		doc.RevokeAfter, _ = data["revokeAfter"].(string)
	}
	version := 0
	if meta, ok := secret.Data["metadata"].(map[string]interface{}); ok {
		if n, ok := meta["version"].(json.Number); ok {
			v, _ := n.Int64()
			version = int(v)
		}
	}
	return doc, version, nil
}

// writeDocument writes a new version only if nobody wrote since the read
// (check-and-set), so two runs cannot interleave.
func (r *Reconciler) writeDocument(ctx context.Context, k Key, doc document, version int) (int, error) {
	data := map[string]interface{}{"key": doc.Key}
	for field, value := range map[string]string{"alias": doc.Alias, "expires": doc.Expires, "settings": doc.Settings,
		"previousAlias": doc.PreviousAlias, "revokeAfter": doc.RevokeAfter} {
		if value != "" {
			data[field] = value
		}
	}
	secret, err := r.Vault.WriteWithContext(ctx, k.Mount+"/data/"+k.Path, map[string]interface{}{"data": data, "options": map[string]interface{}{"cas": version}})
	if err != nil {
		return 0, errors.New("vault write failed")
	}
	if secret != nil {
		if n, ok := secret.Data["version"].(json.Number); ok {
			v, _ := n.Int64()
			return int(v), nil
		}
	}
	return version + 1, nil
}

func (r *Reconciler) readField(ctx context.Context, ref KeyRef) (string, error) {
	secret, err := r.Vault.ReadWithContext(ctx, ref.Mount+"/data/"+ref.Path)
	if err != nil || secret == nil {
		return "", errors.New("unavailable")
	}
	data, _ := secret.Data["data"].(map[string]interface{})
	value, _ := data[ref.Field].(string)
	if value == "" {
		return "", errors.New("empty")
	}
	return value, nil
}

func (r *Reconciler) generate(ctx context.Context, k Key, alias string) (string, time.Time, error) {
	body := map[string]any{
		"key_alias":       alias,
		"team_id":         r.Config.TeamID,
		"duration":        string(k.Duration),
		"max_budget":      k.MaxBudget,
		"budget_duration": string(k.BudgetDuration),
		"models":          k.Models,
		// Inference routes only: a pool key cannot manage keys, teams or users
		// even if it leaked.
		"key_type": "llm_api",
		"metadata": map[string]string{"gatehouse_pool": k.Pool, "gatehouse_managed": "true"},
	}
	var reply struct {
		Key     string `json:"key"`
		Expires string `json:"expires"`
	}
	if err := r.call(ctx, "/key/generate", body, &reply); err != nil {
		return "", time.Time{}, err
	}
	if !strings.HasPrefix(reply.Key, "sk-") || len(reply.Key) < 20 || strings.ContainsAny(reply.Key, " \r\n\t") {
		_ = r.deleteAlias(ctx, alias)
		return "", time.Time{}, errors.New("LiteLLM returned no usable key")
	}
	lifetime, _ := k.Duration.Value()
	expires := r.now().Add(lifetime)
	if t, err := parseLiteLLMTime(reply.Expires); err == nil && t.Before(expires) {
		expires = t
	}
	return reply.Key, expires, nil
}

// deleteAlias revokes a key by alias. An alias LiteLLM no longer knows is
// already gone.
func (r *Reconciler) deleteAlias(ctx context.Context, alias string) error {
	err := r.call(ctx, "/key/delete", map[string]any{"key_aliases": []string{alias}}, nil)
	var status statusError
	if errors.As(err, &status) && status == http.StatusNotFound {
		return nil
	}
	return err
}

type statusError int

func (s statusError) Error() string { return "LiteLLM answered " + strconv.Itoa(int(s)) }

func (r *Reconciler) call(ctx context.Context, route string, body any, into any) error {
	payload, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(r.Config.Gateway, "/")+route, bytes.NewReader(payload))
	if err != nil {
		return errors.New("request")
	}
	req.Header.Set("Authorization", "Bearer "+r.minterKey)
	req.Header.Set("Content-Type", "application/json")
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect with the team key attached.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return errors.New("LiteLLM unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("LiteLLM reply unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(resp.StatusCode)
	}
	if into != nil && json.Unmarshal(data, into) != nil {
		return errors.New("LiteLLM reply unreadable")
	}
	return nil
}

func parseLiteLLMTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("no time")
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}
