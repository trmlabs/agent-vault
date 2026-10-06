package auditchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Key is one version of the chain's HMAC key. Its bytes never leave this
// package: Key prints and logs as its version only.
type Key struct {
	Version int
	secret  []byte
}

// NewKey copies secret. Keys shorter than 32 bytes are rejected.
func NewKey(version int, secret []byte) (Key, error) {
	if version < 1 || len(secret) < 32 {
		return Key{}, errors.New("audit HMAC key must have a positive version and at least 32 bytes")
	}
	return Key{Version: version, secret: append([]byte(nil), secret...)}, nil
}

func (k Key) String() string   { return fmt.Sprintf("audit-hmac-key(v%d)", k.Version) }
func (k Key) GoString() string { return k.String() }

// KeySource returns the newest HMAC key version.
type KeySource interface {
	Current(context.Context) (Key, error)
}

// Signer signs a checkpoint input with a key that never leaves the signer
// and returns a Transit-format "vault:vN:<base64>" signature.
type Signer interface {
	Sign(context.Context, []byte) (string, error)
}

// BootStore persists each replica's boot counter and newest checkpoint row.
// *store.SQLStore implements it.
type BootStore interface {
	BeginAuditBoot(ctx context.Context, replica string) (uint64, store.AuditBoot, error)
	RecordAuditCheckpoint(ctx context.Context, replica string, boot, seq uint64, mac string) error
}

// Event is what a caller records; the chain fills in everything else.
type Event struct {
	Event     string
	Pool      string
	Agent     string
	PodUID    string
	Binding   string
	Session   string
	Outcome   string
	Requester string
	// Authorization decision: who stood behind the request and why it was
	// allowed or refused. TokenSHA256 identifies a runner session token
	// without storing it.
	RequesterKind string
	RequesterOID  string
	TokenSHA256   string
	Tier          string
	Decision      string
	Groups        string
	CacheAgeSec   int64
	// Signing-key refusals: see Row.
	Kid       string
	KidSHA256 string
	Peer      string
	// Proxy certificate issuance: see Row.
	Serial   string
	NotAfter string
	DNSNames string // comma-separated lower-case DNS names the certificate holds
	Method   string
	Status   int
	Duration int64 // milliseconds
}

var (
	ErrAuditFailed       = errors.New("audit trail unavailable")
	ErrCheckpointOverdue = errors.New("audit checkpoint overdue")
	ErrInvalidEvent      = errors.New("invalid audit event")
)

type Options struct {
	Out     io.Writer // one JSON row per line; os.Stdout in production
	Replica string    // stable replica name, such as the Pod name
	Keys    KeySource
	Signer  Signer
	Boots   BootStore
	// Grace is how long the chain may go without a signed checkpoint before
	// Admit refuses new sessions. Default 5 minutes.
	Grace time.Duration
	Now   func() time.Time
}

// Chain is one replica boot's audit chain. All methods are safe for
// concurrent use; rows are written whole and in sequence order.
type Chain struct {
	opts Options
	boot uint64

	mu             sync.Mutex
	seq            uint64
	prev           string
	key            Key
	lastCheckpoint time.Time
	failed         bool
	done           chan struct{} // closed when the chain fails
}

// New fetches the current key and writes the chain_start row. Without a key
// or a writable output there is no chain, and the caller must not serve.
func New(ctx context.Context, opts Options) (*Chain, error) {
	if opts.Out == nil || opts.Keys == nil || opts.Signer == nil || opts.Boots == nil || !identifier(opts.Replica, false) {
		return nil, errors.New("audit chain requires output, replica name, key source, signer and boot store")
	}
	if opts.Grace <= 0 {
		opts.Grace = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	key, err := opts.Keys.Current(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit HMAC key unavailable: %w", err)
	}
	boot, previous, err := opts.Boots.BeginAuditBoot(ctx, opts.Replica)
	if err != nil {
		return nil, fmt.Errorf("audit boot unavailable: %w", err)
	}
	c := &Chain{opts: opts, boot: boot, key: key, lastCheckpoint: opts.Now(), done: make(chan struct{})}
	c.mu.Lock()
	defer c.mu.Unlock()
	start := Row{Event: EventChainStart, PrevBoot: previous.Boot, PrevCheckpointSeq: previous.CheckpointSeq, PrevCheckpointMAC: previous.CheckpointMAC}
	if _, err := c.appendLocked(start); err != nil {
		return nil, err
	}
	return c, nil
}

// Admit reports whether a new session may start: the output is writable and
// a checkpoint has been signed within the grace period.
func (c *Chain) Admit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return ErrAuditFailed
	}
	if c.opts.Now().Sub(c.lastCheckpoint) > c.opts.Grace {
		return ErrCheckpointOverdue
	}
	return nil
}

// Validate reports whether Record would accept the event: a known event and
// method, and every text field a bounded identifier.
func (e Event) Validate() error {
	switch e.Event {
	case EventSessionOpen, EventSessionClose, EventDenied, EventHTTPRequest, EventHTTPResponse, EventTransaction, EventStateLeak, EventCertificate:
	default:
		return ErrInvalidEvent
	}
	switch e.Method {
	case "", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	default:
		return ErrInvalidEvent
	}
	if e.Status != 0 && (e.Status < 100 || e.Status > 599) || e.Duration < 0 {
		return ErrInvalidEvent
	}
	if e.CacheAgeSec < 0 {
		return ErrInvalidEvent
	}
	for _, v := range []string{e.Pool, e.Agent, e.PodUID, e.Binding, e.Session, e.Outcome, e.Requester, e.RequesterKind, e.RequesterOID, e.TokenSHA256, e.Tier, e.Decision, e.Kid, e.KidSHA256, e.Peer} {
		if !identifier(v, true) {
			return ErrInvalidEvent
		}
	}
	if !groupList(e.Groups) {
		return ErrInvalidEvent
	}
	if !dnsNameList(e.DNSNames) {
		return ErrInvalidEvent
	}
	if e.Serial != "" && !serialHex.MatchString(e.Serial) {
		return ErrInvalidEvent
	}
	if e.NotAfter != "" {
		if t, err := time.Parse(time.RFC3339, e.NotAfter); err != nil || t.UTC().Format(time.RFC3339) != e.NotAfter {
			return ErrInvalidEvent
		}
	}
	return nil
}

// serialHex is a certificate serial number: at most 20 octets (RFC 5280), in
// lower-case hex with no leading zeros.
var serialHex = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,39})$`)

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// dnsNameList admits comma-separated lower-case DNS names, any number, so no
// free text can enter the row.
func dnsNameList(s string) bool {
	if s == "" {
		return true
	}
	for _, n := range strings.Split(s, ",") {
		if len(n) > 253 || !dnsName.MatchString(n) {
			return false
		}
	}
	return true
}

var groupID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// groupList admits the comma-separated Entra object IDs of the groups a
// decision checked. It has no length limit: an entry may require any number
// of groups, the full list is recorded, and the row's MAC covers it. Every
// element must still be an object ID, so no free text can enter the row.
func groupList(s string) bool {
	if s == "" {
		return true
	}
	for _, g := range strings.Split(s, ",") {
		if !groupID.MatchString(g) {
			return false
		}
	}
	return true
}

// Record appends a caller event. An error means the row may not exist, so the
// caller must not start or continue the action it describes.
func (c *Chain) Record(e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.appendLocked(Row{Event: e.Event, Pool: e.Pool, Agent: e.Agent, PodUID: e.PodUID, Binding: e.Binding, Session: e.Session, Outcome: e.Outcome, Requester: e.Requester,
		RequesterKind: e.RequesterKind, RequesterOID: e.RequesterOID, TokenSHA256: e.TokenSHA256, Tier: e.Tier, Decision: e.Decision, Groups: e.Groups, CacheAgeSec: e.CacheAgeSec,
		Kid: e.Kid, KidSHA256: e.KidSHA256, Peer: e.Peer, Serial: e.Serial, NotAfter: e.NotAfter, DNSNames: e.DNSNames,
		Method: e.Method, Status: e.Status, Duration: e.Duration})
	return err
}

// Checkpoint signs the current head outside the lock, appends the signature
// as a row and persists that row as the boot's newest checkpoint. A signing
// or persistence failure is itself recorded in the chain, and the grace
// period keeps running until both succeed.
func (c *Chain) Checkpoint(ctx context.Context) error {
	c.mu.Lock()
	if c.failed {
		c.mu.Unlock()
		return ErrAuditFailed
	}
	seq, mac := c.seq-1, c.prev
	c.mu.Unlock()
	signature, err := c.opts.Signer.Sign(ctx, checkpointInput(c.opts.Replica, c.boot, seq, mac))
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil || !identifier(signature, false) {
		if _, appendErr := c.appendLocked(Row{Event: EventCheckpointFailed, Outcome: "signer_unavailable"}); appendErr != nil {
			return appendErr
		}
		return fmt.Errorf("audit checkpoint not signed: %w", ErrCheckpointOverdue)
	}
	row, err := c.appendLocked(Row{Event: EventCheckpoint, SignedSeq: seq, SignedMAC: mac, Signature: signature})
	if err != nil {
		return err
	}
	// Persist outside the lock so a slow store never stalls session rows.
	c.mu.Unlock()
	err = c.opts.Boots.RecordAuditCheckpoint(ctx, c.opts.Replica, c.boot, row.Seq, row.MAC)
	c.mu.Lock()
	if err != nil {
		if _, appendErr := c.appendLocked(Row{Event: EventCheckpointFailed, Outcome: "store_unavailable"}); appendErr != nil {
			return appendErr
		}
		return fmt.Errorf("audit checkpoint not persisted: %w", ErrCheckpointOverdue)
	}
	c.lastCheckpoint = c.opts.Now()
	return nil
}

// RefreshKey switches to a newer key version and records the rotation. The
// rotation row is the first row under the new key.
func (c *Chain) RefreshKey(ctx context.Context) error {
	key, err := c.opts.Keys.Current(ctx)
	if err != nil {
		return fmt.Errorf("audit HMAC key unavailable: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if key.Version <= c.key.Version {
		return nil
	}
	previous := c.key.Version
	c.key = key
	_, err = c.appendLocked(Row{Event: EventKeyRotated, PrevKey: previous})
	return err
}

// Run checkpoints every interval and polls for a rotated key every refresh
// until ctx ends. Failures are recorded in the chain and enforced by Admit.
func (c *Chain) Run(ctx context.Context, interval, refresh time.Duration) {
	checkpoint := time.NewTicker(interval)
	defer checkpoint.Stop()
	rotate := time.NewTicker(refresh)
	defer rotate.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-checkpoint.C:
			signCtx, cancel := context.WithTimeout(ctx, interval/2)
			_ = c.Checkpoint(signCtx)
			cancel()
		case <-rotate.C:
			keyCtx, cancel := context.WithTimeout(ctx, refresh/2)
			_ = c.RefreshKey(keyCtx)
			cancel()
		}
	}
}

// writeMACVersion is the MAC version new rows use; tests lower it to write
// the rows an older broker wrote.
var writeMACVersion = MACVersionCurrent

func (c *Chain) appendLocked(r Row) (Row, error) {
	if c.failed {
		return Row{}, ErrAuditFailed
	}
	r.Type, r.Replica, r.Boot, r.Seq = RowType, c.opts.Replica, c.boot, c.seq
	r.Time = c.opts.Now().UTC().Format(time.RFC3339Nano)
	r.KeyVersion, r.Prev, r.MACVersion = c.key.Version, c.prev, writeMACVersion
	r.MAC = r.computeMAC(c.key.secret)
	line, err := json.Marshal(r)
	if err != nil {
		c.failLocked()
		return Row{}, ErrAuditFailed
	}
	if _, err := c.opts.Out.Write(append(line, '\n')); err != nil {
		// A partial line may exist. Stop the chain rather than continue past
		// a row whose presence is unknown.
		c.failLocked()
		return Row{}, ErrAuditFailed
	}
	c.seq++
	c.prev = r.MAC
	return r, nil
}

// Failed is closed when the chain stops for good. Admit then refuses new
// sessions; sessions already open must end too, since nothing they do can be
// recorded any more.
func (c *Chain) Failed() <-chan struct{} { return c.done }

func (c *Chain) failLocked() {
	if !c.failed {
		c.failed = true
		close(c.done)
	}
}

// identifier admits bounded printable ASCII without spaces or quotes, which
// keeps rows free of free-form text that could carry a secret or forge a line.
func identifier(s string, optional bool) bool {
	if s == "" {
		return optional
	}
	if len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' || s[i] == '"' || s[i] == '\\' {
			return false
		}
	}
	return true
}
