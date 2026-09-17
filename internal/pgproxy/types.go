// Package pgproxy is Agent Vault's TCP credential-brokering path for
// PostgreSQL. It is the database-facing sibling of the HTTP MITM proxy: an
// agent opens a Postgres connection to this listener carrying only its Agent
// Vault identity token — never a database credential — and the broker mints a
// short-lived credential from HashiCorp Vault's database secrets engine,
// authenticates to the real upstream on the agent's behalf, and transparently
// relays the session. The database password is never exposed to the agent (the
// ephemeral username is necessarily visible to any SQL the agent runs).
package pgproxy

import (
	"context"
	"net"
	"time"
)

// AgentScope is the authorization result for an agent connection: the vault the
// agent's token is scoped to, plus a stable actor id for auditing.
type AgentScope struct {
	VaultID   string
	VaultName string
	ActorID   string
}

// AgentAuthenticator validates the agent's Agent Vault token (presented in the
// Postgres password field) and returns the vault scope it grants. This is the
// same identity check the HTTP path performs; the server adapts its
// SessionResolver to this interface. It must fail closed.
type AgentAuthenticator interface {
	Authenticate(ctx context.Context, token, vaultHint string) (*AgentScope, error)
}

// DatabaseService is a resolved upstream database the agent may reach: a
// network address plus the Vault mount and role that mint credentials for it.
type DatabaseService struct {
	Name     string // per-vault service slug (for logs/audit)
	Addr     string // upstream host:port
	Database string // upstream database name; empty means honor the client's requested database
	Mount    string // Vault database secrets-engine mount (e.g. "database")
	Role     string // Vault role granting a scoped set of SQL privileges
	SSLMode  string // upstream TLS mode: "disable" | "prefer" (default) | "require" | "verify-full"
	MaxConns int    // per-database connection budget (0 = the broker's default); bounds this upstream so a burst to one database cannot starve the others
}

// DatabaseResolver selects the database service an authorized agent is asking
// for within its vault. scope is the authorized agent scope; requestedDatabase
// is the database name from the startup packet. A resolver may key on the
// requested database; unknown and ambiguous selectors must be rejected.
type DatabaseResolver interface {
	ResolveDatabase(ctx context.Context, scope AgentScope, requestedDatabase string) (*DatabaseService, error)
}

// Lease is a minted dynamic database credential and its lifecycle metadata.
// Password is confidential from the agent and must never be logged or sent to
// it. Username is the ephemeral role name; it is necessarily visible to any SQL
// the agent runs (e.g. SELECT current_user) and is not a secret on its own, but
// it is still never logged.
type Lease struct {
	ID        string
	Username  string
	Password  string
	ExpiresAt time.Time
	Renewable bool
}

// LeaseMinter mints, renews, and revokes dynamic database credentials. The
// concrete implementation backs onto Vault's database secrets engine. Calls
// must honor context cancellation. Leases are not persisted across restarts;
// Vault's expiry/revocation machinery is the crash-recovery backstop.
type LeaseMinter interface {
	// Mint issues a fresh credential for svc within vaultID.
	Mint(ctx context.Context, vaultID string, svc *DatabaseService) (*Lease, error)
	// Renew extends a lease and returns its new expiry. minRemaining is a hint
	// for how much additional lifetime the caller wants.
	Renew(ctx context.Context, leaseID string, minRemaining time.Duration) (time.Time, error)
	// Revoke invalidates a lease immediately. It is called once per lease when
	// the connection ends (and on shutdown); an empty lease id is a no-op and a
	// returned error is logged, bounded by the lease TTL as a backstop.
	Revoke(ctx context.Context, leaseID string) error
}

// DialFunc dials an upstream database. The server supplies netguard's
// SSRF-guarded dialer so the DB path has the same egress protections as HTTP.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Default lifecycle timings and limits. Overridable via Options.
const (
	// Password and upstream handshake frames are small; bound allocation before auth.
	maxAuthMessageBytes = 64 * 1024
	// defaultHandshakeTimeout bounds the post-startup handshake (auth, mint,
	// upstream connect, SCRAM), which can be slow when role DDL serializes.
	defaultHandshakeTimeout = 15 * time.Second
	// defaultStartupTimeout bounds the pre-auth phase (reading the startup packet
	// and the token). Kept short so a client that opens a socket and stalls does
	// not tie up resources — mitigating a half-open (slowloris) flood.
	defaultStartupTimeout = 5 * time.Second
	// leaseRevokeTimeout bounds a per-connection revoke so shutdown, which waits
	// on in-flight handlers within the server's shutdown budget, is not starved
	// by a slow Vault. Kept below the server's 5s shutdown deadline.
	leaseRevokeTimeout = 4 * time.Second
	// renewLeadFraction renews a lease once this fraction of its lifetime
	// remains, so an in-flight session is never interrupted by expiry.
	renewLeadFraction = 4
	// defaultMinRenewInterval floors the renew cadence so a very short TTL does
	// not spin the renew loop. Overridable via Options.MinRenewInterval.
	defaultMinRenewInterval = 5 * time.Second
	// defaultMaxConns caps concurrent SERVING connections — those holding an
	// upstream database connection. Each brokered connection is one real DB
	// connection, so this must be tuned below the database's max_connections
	// (minus reserved + the Vault admin pool). The conservative default assumes
	// a small shared database.
	defaultMaxConns = 50
	// defaultMaxPendingConns caps accepted-but-not-yet-serving connections
	// (handshake in progress). Generous and independent of MaxConns so a flood of
	// stalled handshakes cannot starve the serving capacity real agents use.
	defaultMaxPendingConns = 512
	// defaultMaxLeasesPerActor caps how many live credentials (= live serving
	// connections) a single agent identity may hold at once. It bounds credential
	// amplification and, kept below MaxConns, prevents one noisy or compromised
	// agent from monopolizing the serving cap and starving other agents.
	defaultMaxLeasesPerActor = 16
)
