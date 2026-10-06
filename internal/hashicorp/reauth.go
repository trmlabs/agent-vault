package hashicorp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Database session child tokens die with the parent login that created them,
// and a JWT login has a fixed maximum lifetime. Instead of restarting the
// broker to replace that login, JWT mode logs in again on a schedule, mints
// new sessions only under a young login, and keeps each older login until its
// last session ends. There is no ceiling on older logins: each ends at its
// fixed maximum lifetime, so at most that lifetime divided by the refresh
// interval are ever held. Token and AppRole modes keep their single login.
const (
	defaultReauthInterval     = 20 * time.Minute
	defaultMinSessionLifetime = 35 * time.Minute
	defaultMintGrace          = 2 * time.Minute
	defaultReauthTick         = 15 * time.Second
	reauthCallTimeout         = 10 * time.Second
	maxJWTBytes               = 64 << 10
)

var errStaleLogin = errors.New("vault login refresh pending; no new database sessions")

type reauthOptions struct {
	interval           time.Duration // log in again this long after the current login
	minSessionLifetime time.Duration // a login stops minting once less than this remains
	mintGrace          time.Duration // a failed refresh stops minting this long after it was due
	tick               time.Duration
}

func defaultReauthOptions() reauthOptions {
	return reauthOptions{defaultReauthInterval, defaultMinSessionLifetime, defaultMintGrace, defaultReauthTick}
}

// heldLogin is one parent token. Its children are this process's live sessions.
type heldLogin struct {
	token      string
	issued     time.Time
	hardExpiry time.Time
	ttl        time.Duration
	renewedAt  time.Time
	pending    int
	children   map[string]time.Time
}

// mintUntil is the end of the window in which new sessions may use this login.
func (l *heldLogin) mintUntil(o reauthOptions) time.Time {
	until := l.issued.Add(o.interval + o.mintGrace)
	if last := l.hardExpiry.Add(-o.minSessionLifetime); last.Before(until) {
		until = last
	}
	// A login whose renewal is overdue may lapse before Vault's maximum.
	if renewal := l.renewedAt.Add(l.ttl * 3 / 4); renewal.Before(until) {
		until = renewal
	}
	return until
}

type loginSet struct {
	mu      sync.Mutex
	current *heldLogin
	retired []*heldLogin
	opts    reauthOptions
}

// acquire reserves the current login for one session mint. The returned
// function records the session's accessor, or "" when no session was created.
// Vault reports a session's own TTL, but the session dies with its parent, so
// the parent's fixed maximum is also returned as the session's real ceiling.
func (s *loginSet) acquire(now time.Time) (string, time.Time, func(string, time.Time), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.current
	if l == nil || !now.Before(l.mintUntil(s.opts)) {
		return "", time.Time{}, nil, errStaleLogin
	}
	l.pending++
	var once sync.Once
	return l.token, l.hardExpiry, func(accessor string, expiry time.Time) {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			l.pending--
			if accessor != "" {
				l.children[accessor] = expiry
			}
		})
	}, nil
}

// forget removes an ended session from whichever login created it.
func (s *loginSet) forget(accessor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range append([]*heldLogin{s.current}, s.retired...) {
		if l != nil {
			delete(l.children, accessor)
		}
	}
}

// idle removes older logins that need no further custody and returns those
// that must be revoked: no live session and no mint in flight. A login past
// its maximum lifetime is already gone in Vault and is only dropped.
func (s *loginSet) idle(now time.Time) []*heldLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	var revoke []*heldLogin
	kept := s.retired[:0]
	for _, l := range s.retired {
		for accessor, expiry := range l.children {
			if !now.Before(expiry) {
				delete(l.children, accessor)
			}
		}
		switch {
		case !now.Before(l.hardExpiry):
		case len(l.children) == 0 && l.pending == 0:
			revoke = append(revoke, l)
		default:
			kept = append(kept, l)
		}
	}
	s.retired = kept
	return revoke
}

// requeue returns a login whose revoke failed, so the next tick tries again.
func (s *loginSet) requeue(l *heldLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retired = append(s.retired, l)
}

// drain removes and returns every login that needs no further custody, the
// current one included, for revocation at Close. A login with a live session
// stays: revoking it would end the session.
func (s *loginSet) drain() []*heldLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*heldLogin
	kept := s.retired[:0]
	for _, l := range s.retired {
		if len(l.children) == 0 && l.pending == 0 {
			out = append(out, l)
		} else {
			kept = append(kept, l)
		}
	}
	s.retired = kept
	if l := s.current; l != nil && len(l.children) == 0 && l.pending == 0 {
		out = append(out, l)
		s.current = nil
	}
	return out
}

func (s *loginSet) rotationDue(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current == nil || !now.Before(s.current.issued.Add(s.opts.interval))
}

// rotate makes next current and retires the previous login.
func (s *loginSet) rotate(next *heldLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		s.retired = append(s.retired, s.current)
	}
	s.current = next
}

func (s *loginSet) all() []*heldLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]*heldLogin(nil), s.retired...)
	if s.current != nil {
		out = append(out, s.current)
	}
	return out
}

func (s *loginSet) counts() (retired, sessions int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range append([]*heldLogin{s.current}, s.retired...) {
		if l != nil {
			sessions += len(l.children)
		}
	}
	return len(s.retired), sessions
}

type jwtConfig struct{ mount, role, tokenFile string }

func jwtConfigFromEnv(getenv func(string) string) (jwtConfig, error) {
	c := jwtConfig{
		mount:     strings.Trim(strings.TrimSpace(getenv("VAULT_JWT_MOUNT")), "/"),
		role:      strings.TrimSpace(getenv("VAULT_JWT_ROLE")),
		tokenFile: strings.TrimSpace(getenv("VAULT_JWT_TOKEN_FILE")),
	}
	if c.mount == "" {
		c.mount = "jwt"
	}
	if c.role == "" || c.tokenFile == "" || !databasePathSegment.MatchString(c.role) {
		return c, fmt.Errorf("jwt login requires VAULT_JWT_ROLE and VAULT_JWT_TOKEN_FILE")
	}
	for _, part := range strings.Split(c.mount, "/") {
		if !databasePathSegment.MatchString(part) {
			return c, fmt.Errorf("invalid VAULT_JWT_MOUNT")
		}
	}
	return c, nil
}

func readJWT(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read login token file")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxJWTBytes+1))
	if err != nil || len(b) > maxJWTBytes {
		return "", fmt.Errorf("cannot read login token file")
	}
	jwt := strings.TrimSpace(string(b))
	if strings.Count(jwt, ".") != 2 || strings.ContainsAny(jwt, " \t\r\n") {
		return "", fmt.Errorf("login token file is not a JWT")
	}
	return jwt, nil
}

// jwtLogin reads the projected token fresh, because the kubelet rotates it in
// place. The maximum lifetime is measured from before the request, so the
// broker's view of expiry is never later than Vault's.
func jwtLogin(ctx context.Context, base *vaultapi.Client, c jwtConfig, now func() time.Time) (*heldLogin, error) {
	jwt, err := readJWT(c.tokenFile)
	if err != nil {
		return nil, err
	}
	api, err := base.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("prepare vault login failed")
	}
	api.ClearToken()
	api.SetMaxRetries(0)
	started := now()
	secret, err := api.Logical().WriteWithContext(ctx, "auth/"+c.mount+"/login", map[string]interface{}{"role": c.role, "jwt": jwt})
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" || secret.Auth.LeaseDuration <= 0 {
		return nil, fmt.Errorf("vault jwt login failed")
	}
	api.SetToken(secret.Auth.ClientToken)
	self, err := api.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || self == nil || self.Data == nil {
		revokeToken(base, secret.Auth.ClientToken)
		return nil, fmt.Errorf("vault jwt login lookup failed")
	}
	maxTTL, err := durationField(self.Data["explicit_max_ttl"])
	if err != nil || maxTTL <= 0 {
		revokeToken(base, secret.Auth.ClientToken)
		return nil, fmt.Errorf("vault jwt login has no fixed maximum lifetime")
	}
	return &heldLogin{token: secret.Auth.ClientToken, issued: started, hardExpiry: started.Add(maxTTL),
		ttl: time.Duration(secret.Auth.LeaseDuration) * time.Second, renewedAt: started, children: map[string]time.Time{}}, nil
}

func durationField(v interface{}) (time.Duration, error) {
	var seconds int64
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, err
		}
		seconds = i
	case float64:
		seconds = int64(n)
	default:
		return 0, fmt.Errorf("missing duration")
	}
	return time.Duration(seconds) * time.Second, nil
}

func tokenAPI(base *vaultapi.Client, token string) (*vaultapi.Client, error) {
	api, err := base.CloneWithHeaders()
	if err != nil {
		return nil, err
	}
	api.SetToken(token)
	api.SetMaxRetries(0)
	return api, nil
}

func revokeToken(base *vaultapi.Client, token string) {
	api, err := tokenAPI(base, token)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reauthCallTimeout)
	defer cancel()
	_ = api.Auth().Token().RevokeSelfWithContext(ctx, "")
}

// reauthLoop renews every held login, replaces the current one when due and
// revokes older logins whose sessions have all ended.
func (c *Client) reauthLoop(ctx context.Context) {
	defer close(c.reauthDone)
	ticker := time.NewTicker(c.logins.opts.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reauthTick(ctx)
		}
	}
}

func (c *Client) reauthTick(ctx context.Context) {
	now := c.clock()
	for _, l := range c.logins.all() {
		c.renewLogin(ctx, l, now)
	}
	c.revokeIdle(ctx)
	if !c.logins.rotationDue(now) {
		return
	}
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if !c.logins.rotationDue(now) { // a denied mint logged in again meanwhile
		return
	}
	if err := c.loginAgainLocked(ctx); err != nil {
		c.logger.Warn("vault login refresh failed; existing sessions continue, new sessions stop when the current login ages out",
			slog.String("err", err.Error()))
		return
	}
	retired, sessions := c.logins.counts()
	c.logger.Info("vault login refreshed", slog.Int("older_logins", retired), slog.Int("live_sessions", sessions))
}

// loginAgainLocked logs in and makes the new login current. c.loginMu is held.
func (c *Client) loginAgainLocked(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, reauthCallTimeout)
	next, err := jwtLogin(callCtx, c.api, c.jwt, c.clock)
	cancel()
	if err != nil {
		return err
	}
	c.logins.rotate(next)
	c.api.SetToken(next.token)
	return nil
}

// deniedReloginAfter is how old the current login must be before a denied
// session mint logs in again. A denial on a younger login means the policy
// itself is missing, not that the login predates it, so this bounds the
// logins a misconfigured database can cause to one a minute per replica,
// whatever the number of agents asking.
const deniedReloginAfter = time.Minute

var errLoginLacksPolicy = errors.New("vault refused this database's session policy to the broker's current login")

// reloginAfterDenial replaces the login that Vault refused a database
// session, because a login only holds the policies that existed when it was
// issued: a database the catalog added since needs a new login. Concurrent
// denials share one new login.
func (c *Client) reloginAfterDenial(ctx context.Context, denied string) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	c.logins.mu.Lock()
	current := c.logins.current
	same := current != nil && current.token == denied
	young := same && c.clock().Before(current.issued.Add(deniedReloginAfter))
	c.logins.mu.Unlock()
	switch {
	case !same:
		return nil // another mint or the schedule already logged in again
	case young:
		return errLoginLacksPolicy
	}
	if err := c.loginAgainLocked(ctx); err != nil {
		return err
	}
	c.logger.Info("vault login refreshed after a denied database session")
	return nil
}

func (c *Client) renewLogin(ctx context.Context, l *heldLogin, now time.Time) {
	c.logins.mu.Lock()
	due := !now.Before(l.renewedAt.Add(l.ttl/2)) && now.Before(l.hardExpiry)
	token, ttl := l.token, l.ttl
	c.logins.mu.Unlock()
	if !due {
		return
	}
	api, err := tokenAPI(c.api, token)
	if err != nil {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, reauthCallTimeout)
	defer cancel()
	secret, err := api.Auth().Token().RenewSelfWithContext(callCtx, int(ttl/time.Second))
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.LeaseDuration <= 0 {
		c.logger.Warn("vault login renewal failed")
		return
	}
	c.logins.mu.Lock()
	l.renewedAt = now
	l.ttl = time.Duration(secret.Auth.LeaseDuration) * time.Second
	c.logins.mu.Unlock()
}

// revokeIdle revokes each older login as soon as its last session has ended.
// A transient failure is retried at the next tick until the login's maximum
// lifetime, when Vault ends it anyway. A login whose policy does not grant
// revoke-self is released at once: it holds no session, and it ends at its
// maximum lifetime.
func (c *Client) revokeIdle(ctx context.Context) {
	for _, l := range c.logins.idle(c.clock()) {
		switch c.revokeLogin(ctx, l) {
		case loginRevoked:
			c.logger.Info("vault older login revoked")
		case loginRevokeRefused:
			c.logger.Info("vault older login released: its policy does not grant revoke-self, so it ends at its maximum lifetime")
		default:
			c.logins.requeue(l)
			c.logger.Warn("vault older login revoke failed; retrying")
		}
	}
}

type loginRevokeResult int

const (
	loginRevokeFailed loginRevokeResult = iota
	loginRevoked
	loginRevokeRefused // Vault answered 403: no revoke-self in the login's policy
)

func (c *Client) revokeLogin(ctx context.Context, l *heldLogin) loginRevokeResult {
	api, err := tokenAPI(c.api, l.token)
	if err != nil {
		return loginRevokeFailed
	}
	callCtx, cancel := context.WithTimeout(ctx, reauthCallTimeout)
	defer cancel()
	err = api.Auth().Token().RevokeSelfWithContext(callCtx, "")
	var refused *vaultapi.ResponseError
	switch {
	case err == nil:
		return loginRevoked
	case errors.As(err, &refused) && refused.StatusCode == http.StatusForbidden:
		return loginRevokeRefused
	default:
		return loginRevokeFailed
	}
}

// Close stops login refresh and revokes every held login with no live
// session, the current one included; the client mints nothing afterwards. A
// login still holding a session, or whose revoke fails, ends at its Vault
// maximum lifetime. Token and AppRole logins are the operator's and are
// never revoked.
func (c *Client) Close() { c.CloseContext(context.Background()) }

// CloseContext is Close within ctx, for a shutdown that must end in time.
func (c *Client) CloseContext(ctx context.Context) {
	if c == nil || c.stopReauth == nil {
		return
	}
	c.stopReauth()
	select {
	case <-c.reauthDone:
	case <-ctx.Done():
		c.logger.Warn("vault login refresh did not stop before shutdown; logins end at their maximum lifetime")
		return
	}
	for _, l := range c.logins.drain() {
		switch c.revokeLogin(ctx, l) {
		case loginRevokeRefused:
			c.logger.Info("vault login left to expire at close: its policy does not grant revoke-self")
		case loginRevokeFailed:
			c.logger.Warn("vault login revoke at close failed")
		}
	}
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Ready reports whether a new database session could be minted now. Token and
// AppRole modes keep one login, which they never renew: they are ready until
// it expires, and always for a login that does not expire.
func (c *Client) Ready() bool {
	if c == nil {
		return false
	}
	if c.logins == nil {
		return c.loginExpiry.IsZero() || c.clock().Before(c.loginExpiry)
	}
	c.logins.mu.Lock()
	defer c.logins.mu.Unlock()
	return c.logins.current != nil && c.clock().Before(c.logins.current.mintUntil(c.logins.opts))
}
