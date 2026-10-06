package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/proxyactivity"
	"github.com/Infisical/agent-vault/internal/proxycert"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/telemetry"
	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spf13/cobra"
)

const maxPasswordAttempts = 3

// resolveLogLevel turns the --log-level flag (or AGENT_VAULT_LOG_LEVEL env
// fallback) into a slog.Level. Flag wins if explicitly set. Accepts "info"
// and "debug" only — anything else is rejected with a clear error.
// flagChanged indicates whether the user passed --log-level explicitly.
func resolveLogLevel(flagValue string, flagChanged bool) (slog.Level, error) {
	value := flagValue
	if !flagChanged {
		if env := os.Getenv("AGENT_VAULT_LOG_LEVEL"); env != "" {
			value = env
		}
	}
	switch strings.ToLower(value) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (accepted: info, debug)", value)
	}
}

// resolveBaseURL returns the externally-reachable base URL for the server.
// Priority: AGENT_VAULT_ADDR env var > FLY_APP_NAME-derived URL > http://{addr}.
func resolveBaseURL(addr string) string {
	if v := os.Getenv("AGENT_VAULT_ADDR"); v != "" {
		return v
	}
	if app := os.Getenv("FLY_APP_NAME"); app != "" {
		return "https://" + app + ".fly.dev"
	}
	return "http://" + addr
}

// buildLogger constructs the process-wide slog logger. Text handler to
// stderr keeps it readable in a terminal without a dependency bump.
func buildLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start an Agent Vault server",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		detach, _ := cmd.Flags().GetBool("detach")
		mitmPort, _ := cmd.Flags().GetInt("mitm-port")
		postgresPort, _ := cmd.Flags().GetInt("postgres-port")
		logLevelFlag, _ := cmd.Flags().GetString("log-level")
		logLevelChanged := cmd.Flags().Changed("log-level")
		maxRespBytes, _ := cmd.Flags().GetInt64("max-response-bytes")
		maxReqBytes, _ := cmd.Flags().GetInt64("max-request-bytes")
		addr := fmt.Sprintf("%s:%d", host, port)

		logLevel, err := resolveLogLevel(logLevelFlag, logLevelChanged)
		if err != nil {
			return err
		}
		if err := checkShutdownSeconds(os.Getenv); err != nil {
			return err
		}
		logger := buildLogger(logLevel)

		// --- Detached child path: read master key + initialized flag from stdin pipe ---
		if os.Getenv("_AGENT_VAULT_DETACHED") == "1" {
			return runDetachedChild(host, addr, mitmPort, postgresPort, logger, maxRespBytes, maxReqBytes)
		}

		// Pre-flight before unlocking the vault: don't make the user type a
		// master password just to learn the port is taken.
		if pid, err := pidfile.Read(); err == nil {
			if pid != os.Getpid() && pidfile.IsRunning(pid) {
				return fmt.Errorf("server is already running (PID %d). Use 'agent-vault server stop' to stop it first", pid)
			}
			_ = pidfile.Remove()
		}

		dbURL, err := databaseURL()
		if err != nil {
			return err
		}
		if flagURL, _ := cmd.Flags().GetString("database-url"); flagURL != "" {
			dbURL = flagURL
		}
		dbPath, err := store.DefaultDBPath()
		if err != nil && dbURL == "" {
			return fmt.Errorf("resolving db path: %w", err)
		}

		db, err := store.OpenStore(store.StoreConfig{
			DatabaseURL: dbURL,
			SQLitePath:  dbPath,
		})
		if err != nil {
			return fmt.Errorf("opening store: %w", err)
		}
		defer func() { _ = db.Close() }()

		if dbURL != "" {
			if n, _ := db.CountUsers(context.Background()); n == 0 {
				if sqlitePath, err2 := store.DefaultDBPath(); err2 == nil {
					if _, err2 := os.Stat(sqlitePath); err2 == nil {
						fmt.Fprintln(cmd.OutOrStderr(),
							"warning: DATABASE_URL is set but the Postgres database has no users.",
							"If you have existing data in SQLite, run 'agent-vault migrate-db --to <url>' first.",
						)
					}
				}
			}
		}

		passwordStdin, _ := cmd.Flags().GetBool("password-stdin")
		interactive := !passwordStdin && os.Getenv("AGENT_VAULT_MASTER_PASSWORD") == ""

		masterKey, err := unlockOrSetup(cmd, db, passwordStdin)
		if err != nil {
			return err
		}

		// Check if owner account exists; create interactively if possible.
		ctx := context.Background()
		userCount, err := db.CountUsers(ctx)
		if err != nil {
			masterKey.Wipe()
			return fmt.Errorf("checking user count: %w", err)
		}
		initialized := userCount > 0

		if !initialized && interactive {
			if err := promptOwnerSetup(cmd, db, nil); err != nil {
				masterKey.Wipe()
				return err
			}
			initialized = true
		}

		if detach {
			var explicitLogLevel *string
			if logLevelChanged {
				explicitLogLevel = &logLevelFlag
			}
			return spawnDetached(cmd, masterKey, initialized, host, port, mitmPort, postgresPort, addr, explicitLogLevel, maxRespBytes, maxReqBytes)
		}

		// --- Foreground path ---
		defer masterKey.Wipe()
		baseURL := resolveBaseURL(addr)
		smtpCfg := notify.LoadSMTPConfig()
		_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
		notifier := notify.New(smtpCfg)
		srv := server.New(addr, db, masterKey.Key(), notifier, initialized, baseURL, logger)
		srv.SetSkills(skillCLI)
		srv.AttachTelemetry(tel)
		shutdownLogs := attachLogSink(srv, db, logger)
		defer shutdownLogs()
		if err := attachServerExtensions(srv, host, mitmPort, postgresPort, masterKey.Key(), db, logger, maxRespBytes, maxReqBytes); err != nil {
			return err
		}
		captureServerStart(mitmPort, db.DialectName())
		return srv.Start()
	},
}

// attachMITMIfEnabled initializes the CA and attaches a transparent MITM
// proxy to srv when mitmPort > 0. The CA is loaded or created under the
// standard ~/.agent-vault/ca/ directory, encrypted with the master key.
//
// CA init failures are non-fatal, matching the behavior for bind failures
// in server.Start: since the MITM proxy is default-on, environments that
// cannot create ~/.agent-vault/ca/ (read-only FS, containers without HOME,
// corrupted state) must still be able to run the core HTTP server.
func attachMITMIfEnabled(srv *server.Server, host string, mitmPort int, masterKey []byte, db store.Store, maxRespBytes, maxReqBytes int64, adapter *mitm.HeaderAdapter, resolver ...brokercore.SessionResolver) error {
	if mitmPort <= 0 {
		return nil
	}
	sessions := srv.SessionResolver()
	if len(resolver) > 0 {
		sessions = resolver[0]
	}
	// Pool workers are admitted by Attest by default. The fallback keeps every
	// caller on online TokenReview; hiding Attest makes pool bindings refuse.
	switch mode := os.Getenv("AGENT_VAULT_WORKLOAD_ATTESTATION"); mode {
	case "":
	case "tokenreview":
		sessions = tokenReviewOnly{sessions}
	default:
		return fmt.Errorf("AGENT_VAULT_WORKLOAD_ATTESTATION must be unset or tokenreview")
	}
	// Pool workers need a real peer address, which behind the in-Pod TLS
	// terminator only a PROXY header supplies; without it, keep token review.
	var attestor brokercore.Attestor
	var peerReader mitm.PeerReader
	if boolEnvValue("AGENT_VAULT_MITM_PROXY_PROTOCOL") {
		attestor, _ = sessions.(brokercore.Attestor)
		peerReader = func(c net.Conn) (netip.Addr, error) { return brokercore.ReadProxyV1(c, c.RemoteAddr()) }
	}
	var extraSANs []string
	if u, err := url.Parse(srv.BaseURL()); err == nil {
		if h := u.Hostname(); h != "" {
			extraSANs = []string{h}
		}
	}
	caOpts := ca.Options{ExtraSANs: extraSANs}
	if db.DialectName() == "postgres" {
		caOpts.Store = &caStoreAdapter{db: db}
	}
	caProv, err := newInterceptionCA(masterKey, caOpts, srv.Logger(), srv.CredentialProxyEnabled())
	if err != nil {
		if srv.CredentialProxyEnabled() {
			return fmt.Errorf("credential proxy CA initialization failed")
		}
		fmt.Fprintf(os.Stderr, "warning: transparent proxy disabled (CA init failed: %v); pass --mitm-port 0 to suppress\n", err)
		return nil
	}
	// A fleet replica drains its tunnels on SIGTERM; unset keeps the 5s stop
	// and leaves open tunnels to end with the process.
	drainSeconds := min(intEnvValue("AGENT_VAULT_SHUTDOWN_SECONDS"), maxShutdownSeconds)
	if drainSeconds > 0 {
		srv.SetShutdownTimeout(time.Duration(drainSeconds) * time.Second)
	}
	srv.AttachMITM(mitm.New(
		net.JoinHostPort(host, strconv.Itoa(mitmPort)),
		mitm.Options{
			CA:                    caProv,
			StrictCredentialProxy: srv.CredentialProxyEnabled(),
			DurableAudit:          requestlog.NewDurable(db),
			HeaderAdapter:         adapter,
			Sessions:              sessions,
			Attestor:              attestor,
			PeerReader:            peerReader,
			Credentials:           srv.CredentialProvider(),
			BaseURL:               srv.BaseURL(),
			Logger:                srv.Logger(),
			RateLimit:             srv.RateLimit(),
			LogSink:               srv.LogSink(),
			MaxResponseBytes:      maxRespBytes,
			MaxRequestBytes:       maxReqBytes,
			DrainTunnels:          drainSeconds > 0,
			// Pending or active credential-proxy tunnels per replica.
			MaxCredentialProxyTunnels: intEnvValue("AGENT_VAULT_MITM_MAX_TUNNELS"),
		},
	))
	return nil
}

// newInterceptionCA loads or creates the interception CA. In credential-proxy
// mode it logs the public root once, so the certificate workers must trust can
// be recorded from the broker's own logs. The root is stored with the broker,
// so the line repeats the same certificate on every restart.
func newInterceptionCA(masterKey []byte, opts ca.Options, logger *slog.Logger, credentialProxy bool) (*ca.SoftCA, error) {
	caProv, err := ca.New(masterKey, opts)
	if err != nil {
		return nil, err
	}
	if credentialProxy {
		logInterceptionCA(logger, caProv.RootPEM())
	}
	return caProv, nil
}

// logInterceptionCA logs the root certificate's SHA-256 (over its DER) and the
// exact PEM the broker serves. It logs only a single CERTIFICATE block, never
// anything else, so no key can reach the log.
func logInterceptionCA(logger *slog.Logger, rootPEM []byte) {
	block, rest := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		logger.Warn("interception CA root is not a single certificate; not logged", "event", "mitm-ca")
		return
	}
	sum := sha256.Sum256(block.Bytes)
	logger.Info("interception CA", "event", "mitm-ca", "sha256", hex.EncodeToString(sum[:]), "pem", string(rootPEM))
}

// attachProxyCertificates lets shared proxies in another cluster ask for
// their serving certificate on the cross-cluster listener, signed by a Vault
// PKI role limited to their names. Set all of AGENT_VAULT_PROXY_PKI_MOUNT,
// AGENT_VAULT_PROXY_PKI_ROLE and AGENT_VAULT_PROXY_CERT_NAMES, or none;
// AGENT_VAULT_PROXY_CERT_TTL defaults to 24h.
func attachProxyCertificates(srv *server.Server, resolver *workloadidentity.Resolver, logger *slog.Logger, getenv func(string) string) error {
	mount, role, names := getenv("AGENT_VAULT_PROXY_PKI_MOUNT"), getenv("AGENT_VAULT_PROXY_PKI_ROLE"), getenv("AGENT_VAULT_PROXY_CERT_NAMES")
	if mount == "" && role == "" && names == "" && getenv("AGENT_VAULT_PROXY_CERT_TTL") == "" {
		return nil
	}
	if mount == "" || role == "" || names == "" {
		return fmt.Errorf("proxy certificates need AGENT_VAULT_PROXY_PKI_MOUNT, AGENT_VAULT_PROXY_PKI_ROLE and AGENT_VAULT_PROXY_CERT_NAMES")
	}
	if getenv("AGENT_VAULT_CROSS_CLUSTER_PORT") == "" || resolver == nil || srv.HashicorpClient() == nil {
		return fmt.Errorf("proxy certificates need the cross-cluster listener, workload identity and Vault")
	}
	ttl := proxycert.MaxTTL
	if raw := getenv("AGENT_VAULT_PROXY_CERT_TTL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("AGENT_VAULT_PROXY_CERT_TTL must be a duration such as 24h")
		}
		ttl = parsed
	}
	var list []string
	for _, name := range strings.Split(names, ",") {
		if name = strings.TrimSpace(name); name != "" {
			list = append(list, name)
		}
	}
	// Every certificate issued is a row in the signed audit trail, so there is
	// no issuing without it.
	chain, err := sharedAuditChain(context.Background(), srv.HashicorpClient(), srv.CleanupStore(), getenv, logger)
	if err != nil {
		return err
	}
	if chain == nil {
		return fmt.Errorf("proxy certificates need the signed audit trail (AGENT_VAULT_AUDIT_CHAIN)")
	}
	// Issuance per proxy binding: AGENT_VAULT_PROXY_CERT_PER_HOUR and
	// AGENT_VAULT_PROXY_CERT_BURST (default 1,000 each).
	return srv.EnableProxyCertificates(&proxycert.Issuer{Mount: mount, Role: role, Names: list, TTL: ttl,
		Signer: srv.HashicorpClient(), Verifier: resolver, Audit: chain, Logger: logger,
		PerHour: intEnvValue("AGENT_VAULT_PROXY_CERT_PER_HOUR"), Burst: intEnvValue("AGENT_VAULT_PROXY_CERT_BURST")})
}

// attachProxyActivity keeps shared proxies' Sandbox activity in the shared
// store whenever the cross-cluster listener and workload identity are on, so
// the idle janitor's view outlives any proxy replica.
// AGENT_VAULT_PROXY_ACTIVITY_RETENTION (default 24h) is how long a row is kept;
// AGENT_VAULT_PROXY_ACTIVITY_MAX_ROWS (default proxyactivity.DefaultMaxRows) is
// the most rows one proxy binding may hold.
func attachProxyActivity(srv *server.Server, resolver *workloadidentity.Resolver, db store.Store, logger *slog.Logger, getenv func(string) string) error {
	raw := getenv("AGENT_VAULT_PROXY_ACTIVITY_RETENTION")
	if getenv("AGENT_VAULT_CROSS_CLUSTER_PORT") == "" || resolver == nil {
		if raw != "" {
			return fmt.Errorf("AGENT_VAULT_PROXY_ACTIVITY_RETENTION needs the cross-cluster listener and workload identity")
		}
		return nil
	}
	activityStore, ok := db.(proxyactivity.Store)
	if !ok {
		return fmt.Errorf("proxy activity needs the SQL store")
	}
	retention := 24 * time.Hour
	if raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("AGENT_VAULT_PROXY_ACTIVITY_RETENTION must be a duration such as 24h")
		}
		retention = parsed
	}
	maxRows := 0
	if raw := getenv("AGENT_VAULT_PROXY_ACTIVITY_MAX_ROWS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			return fmt.Errorf("AGENT_VAULT_PROXY_ACTIVITY_MAX_ROWS must be a positive whole number")
		}
		maxRows = parsed
	}
	return srv.EnableProxyActivity(&proxyactivity.Service{Store: activityStore, Identifier: proxyIdentifier{resolver}, Retention: retention,
		MaxRows: maxRows, Logger: logger})
}

// proxyIdentifier adapts workload identity to proxy activity.
type proxyIdentifier struct{ r *workloadidentity.Resolver }

func (p proxyIdentifier) IdentifyProxy(ctx context.Context, token string, peer netip.Addr) (proxyactivity.Identity, error) {
	id, err := p.r.IdentifyProxy(ctx, token, peer)
	return proxyactivity.Identity{Scope: id.Scope, Namespaces: id.Namespaces}, err
}

// attachServerExtensions wires optional subsystems (MITM, Infisical) onto srv.
// Both bootstrap paths (foreground and detached child) call this.
func attachServerExtensions(srv *server.Server, host string, mitmPort, postgresPort int, masterKey []byte, db store.Store, logger *slog.Logger, maxRespBytes, maxReqBytes int64) error {
	strictMode := false
	if raw := os.Getenv("AGENT_VAULT_CREDENTIAL_PROXY"); raw != "" {
		var err error
		strictMode, err = strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("AGENT_VAULT_CREDENTIAL_PROXY must be true or false")
		}
	}
	if strictMode {
		listenHost := host
		if listenHost == "localhost" {
			listenHost = "127.0.0.1"
		}
		listenIP := net.ParseIP(listenHost)
		if listenIP == nil || !listenIP.IsLoopback() {
			return fmt.Errorf("credential proxy requires loopback listeners behind a verified TLS transport")
		}
		if os.Getenv("AGENT_VAULT_WORKLOAD_IDENTITY_FILE") == "" {
			return fmt.Errorf("credential proxy requires workload identity configuration")
		}
		if boolEnvValue("VAULT_SKIP_VERIFY") {
			return fmt.Errorf("credential proxy forbids VAULT_SKIP_VERIFY")
		}
		if mitmPort <= 0 {
			return fmt.Errorf("credential proxy requires its HTTP proxy listener")
		}
		vaultURL, err := url.Parse(os.Getenv("VAULT_ADDR"))
		if err != nil || vaultURL.Host == "" || vaultURL.User != nil {
			return fmt.Errorf("credential proxy requires a valid Vault address")
		}
		ip := net.ParseIP(vaultURL.Hostname())
		if vaultURL.Scheme != "https" && (vaultURL.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("credential proxy requires Vault TLS; HTTP is allowed only on a loopback IP for local fixtures")
		}
		srv.EnableCredentialProxy()
	}
	if port := os.Getenv("AGENT_VAULT_CROSS_CLUSTER_PORT"); port != "" {
		// Agents in another cluster arrive through their shared proxy and a
		// private link, behind a TLS front that names the source in a PROXY
		// header. Both protocol listeners must trust that header.
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || !srv.CredentialProxyEnabled() || !boolEnvValue("AGENT_VAULT_MITM_PROXY_PROTOCOL") ||
			(postgresPort > 0 && !boolEnvValue("AGENT_VAULT_DB_PROXY_PROTOCOL")) {
			return fmt.Errorf("AGENT_VAULT_CROSS_CLUSTER_PORT needs a port, the credential proxy and PROXY headers on both protocol listeners")
		}
		if err := srv.EnableCrossCluster(net.JoinHostPort("127.0.0.1", port)); err != nil {
			return err
		}
	}
	sessions := srv.SessionResolver()
	var proxyIdentity workloadidentity.Config
	var proxyResolver *workloadidentity.Resolver
	if path := os.Getenv("AGENT_VAULT_WORKLOAD_IDENTITY_FILE"); path != "" {
		config, err := workloadidentity.LoadConfig(path)
		if err != nil {
			return err
		}
		resolver, err := workloadidentity.New(config, db)
		if err != nil {
			return err
		}
		resolver.SetLogger(logger)
		sessions = resolver
		proxyIdentity = config
		proxyResolver = resolver
	}
	attachInfisicalIfConfigured(srv, logger)
	attachHashicorpIfConfigured(srv, logger)
	if srv.CredentialProxyEnabled() && srv.HashicorpClient() == nil {
		return fmt.Errorf("credential proxy requires a working HashiCorp Vault client")
	}
	// The HTTP header adapter reads keys through the HashiCorp client, so the
	// MITM proxy is attached after it.
	adapter, err := httpHeaderAdapter(context.Background(), srv, os.Getenv)
	if err != nil {
		return fmt.Errorf("http header adapter: %w", err)
	}
	if proxyResolver != nil && adapter != nil {
		proxyResolver.SetProfiles(catalogProfiles(adapter.Catalog))
	}
	if err := attachProxyCertificates(srv, proxyResolver, logger, os.Getenv); err != nil {
		return err
	}
	if err := attachProxyActivity(srv, proxyResolver, db, logger, os.Getenv); err != nil {
		return err
	}
	if err := attachMITMIfEnabled(srv, host, mitmPort, masterKey, db, maxRespBytes, maxReqBytes, adapter, sessions); err != nil {
		return err
	}
	// The postgres broker depends on the HashiCorp client, so attach it after
	// attachHashicorpIfConfigured has run.
	if err := attachPostgresBrokerIfEnabled(srv, host, postgresPort, logger, sessions); err != nil {
		return err
	}
	observerPort, err := cleanupObserverPort(os.Getenv("AGENT_VAULT_CLEANUP_OBSERVER_FILE"), os.Getenv("AGENT_VAULT_CLEANUP_OBSERVER_PORT"))
	if err != nil {
		return err
	}
	if path := os.Getenv("AGENT_VAULT_CLEANUP_OBSERVER_FILE"); path != "" {
		observer, err := workloadidentity.LoadConfig(path)
		if err != nil {
			return err
		}
		if err := workloadidentity.ValidateObserverSeparation(observer, proxyIdentity); err != nil {
			return err
		}
		identity, err := workloadidentity.NewObserver(observer)
		if err != nil {
			return err
		}
		var grants []runtimestatus.Grants
		if proxyResolver != nil {
			grants = append(grants, proxyResolver.BindingsAuthorized)
		}
		if err := srv.EnableCleanupObserver(identity.Authorize, observerPort, grants...); err != nil {
			return err
		}
	}
	return nil
}

// attachPostgresBrokerIfEnabled wires the PostgreSQL credential-brokering TCP
// listener when --postgres-port > 0, a HashiCorp Vault client is available
// (VAULT_ADDR set), and the broker is enabled — either explicitly via
// AGENT_VAULT_DB_BROKER, or implicitly because bootstrap database services are
// configured via AGENT_VAULT_DB_SERVICES(_FILE). Database services are resolved
// live from the store, so they can be added or removed at runtime through the
// management API; configured services seed an empty store on startup without
// clobbering runtime edits. It disables quietly otherwise so deployments that
// do not use it are unaffected. The upstream dial goes through netguard for
// SSRF parity with the HTTP proxy; database upstreams on private networks
// require AGENT_VAULT_ALLOW_PRIVATE_RANGES or an allowlist.
func attachPostgresBrokerIfEnabled(srv *server.Server, host string, postgresPort int, logger *slog.Logger, resolver ...brokercore.SessionResolver) error {
	if postgresPort <= 0 {
		return nil
	}
	services, err := server.LoadDatabaseServices(os.Getenv)
	if err != nil {
		return fmt.Errorf("postgres broker: %w", err)
	}
	// Managed mode: the broker runs whenever explicitly enabled or when bootstrap
	// services are configured (which implies intent). Explicit enablement lets an
	// operator start with an empty store and add the first database at runtime.
	if !boolEnvValue("AGENT_VAULT_DB_BROKER") && len(services) == 0 {
		logger.Debug("postgres broker disabled: set AGENT_VAULT_DB_BROKER=1 or configure AGENT_VAULT_DB_SERVICES")
		return nil
	}
	// A broker that was asked for but has no Vault login fails startup, rather
	// than starting without it and reporting ready with no way to mint.
	client := srv.HashicorpClient()
	if client == nil {
		return fmt.Errorf("postgres broker requires a working HashiCorp Vault client (set VAULT_ADDR)")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("postgres broker requires --host to be a loopback IP; use a local sidecar or authenticated tunnel")
	}
	if seeded, err := srv.SeedDatabaseServices(context.Background(), services); err != nil {
		return fmt.Errorf("postgres broker: %w", err)
	} else if seeded > 0 {
		logger.Info("postgres broker: seeded database services from config", slog.Int("count", seeded))
	}
	sessions := srv.SessionResolver()
	if len(resolver) > 0 {
		sessions = resolver[0]
	}
	// Pool workers are admitted by Attest by default. The fallback keeps every
	// caller on online TokenReview; hiding Attest makes pool bindings refuse.
	switch mode := os.Getenv("AGENT_VAULT_WORKLOAD_ATTESTATION"); mode {
	case "":
	case "tokenreview":
		sessions = tokenReviewOnly{sessions}
	default:
		return fmt.Errorf("AGENT_VAULT_WORKLOAD_ATTESTATION must be unset or tokenreview")
	}
	opts := pgproxy.Options{
		Auth:      server.NewAgentAuthAdapter(sessions),
		Databases: srv.DatabaseResolver(),
		Leases:    server.NewVaultLeaseMinter(client),
		Dialer:    netguard.SafeDialContext(netguard.AllowPrivateFromEnv()),
		Logger:    logger,
	}
	// With a broker catalog, databases come from it and reload without a restart.
	if catalog, err := brokerCatalog(context.Background(), client, os.Getenv, logger); err != nil {
		return fmt.Errorf("postgres broker catalog: %w", err)
	} else if catalog != nil {
		authz, err := loadAuthorization(os.Getenv)
		if err != nil {
			return fmt.Errorf("postgres broker authorization: %w", err)
		}
		opts.Databases = server.NewCatalogDatabaseResolver(catalog, authz.verifier(), authz.entitlements, sessionBinder(srv.CleanupStore()))
	}
	if chain, err := sharedAuditChain(context.Background(), client, srv.CleanupStore(), os.Getenv, logger); err != nil {
		return fmt.Errorf("postgres broker audit: %w", err)
	} else if chain != nil {
		opts.Audit = chain
	}
	if srv.CredentialProxyEnabled() {
		minter, err := server.NewDurableVaultLeaseMinter(context.Background(), client, srv.CleanupStore())
		if err != nil {
			return fmt.Errorf("postgres durable cleanup initialization failed: %w", err)
		}
		opts.Leases = minter
		srv.AttachDatabaseCleanup(minter)
		// Per-Pod caps hold across every replica sharing this store.
		opts.Sessions = server.NewSessionLedger(srv.CleanupStore(), minter)
	}
	// Each database's ceiling is its catalog entry's maxConns; MaxConns only
	// bounds the broker across all of them. A database whose entry sets none
	// gets AGENT_VAULT_DB_DEFAULT_DATABASE_CONNS (default 50).
	if v := intEnvValue("AGENT_VAULT_DB_MAX_CONNS"); v > 0 {
		opts.MaxConns = v
	}
	if v := intEnvValue("AGENT_VAULT_DB_DEFAULT_DATABASE_CONNS"); v > 0 {
		opts.DefaultDatabaseConns = v
	}
	if v := intEnvValue("AGENT_VAULT_DB_MAX_LEASES_PER_ACTOR"); v > 0 {
		opts.MaxLeasesPerActor = v
	}
	if v := intEnvValue("AGENT_VAULT_DB_MAX_LEASES_PER_AGENT"); v > 0 {
		opts.MaxLeasesPerAgent = v
	}
	// MaxPendingConns bounds accepted-but-not-yet-serving connections. The
	// half-open mitigation protects the serving cap, not the accept cap: a
	// sustained flood above this bound is refused at accept until stalled
	// sockets are reclaimed at StartupTimeout. Operators facing hostile clients
	// raise it (or front the listener with a connection limiter).
	if v := intEnvValue("AGENT_VAULT_DB_MAX_PENDING_CONNS"); v > 0 {
		opts.MaxPendingConns = v
	}
	// The PROXY header names the worker's address for pool admission. Only the
	// in-Pod TLS terminator may send it, so it is refused off loopback.
	if boolEnvValue("AGENT_VAULT_DB_PROXY_PROTOCOL") {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("AGENT_VAULT_DB_PROXY_PROTOCOL requires a loopback PostgreSQL listener")
		}
		opts.TrustProxyHeader = true
	}
	// Transaction-mode multiplexing: client sessions share server connections
	// and one rotating credential per pool and database. MaxConns then caps
	// client sessions; each database's server budget comes from the catalog.
	if boolEnvValue("AGENT_VAULT_DB_POOLING") {
		opts.Pool = &pgproxy.PoolOptions{Replicas: intEnvValue("AGENT_VAULT_DB_POOL_REPLICAS"), DefaultBudget: firstPositive(intEnvValue("AGENT_VAULT_DB_POOL_BUDGET"), intEnvValue("AGENT_VAULT_DB_DEFAULT_DATABASE_CONNS")),
			QueueFactor: intEnvValue("AGENT_VAULT_DB_POOL_QUEUE_FACTOR"), QueueWait: time.Duration(intEnvValue("AGENT_VAULT_DB_POOL_QUEUE_WAIT_MS")) * time.Millisecond,
			// A graceful stop ends each session between transactions.
			DrainSessions: intEnvValue("AGENT_VAULT_SHUTDOWN_SECONDS") > 0}
	}
	srv.AttachPostgresBroker(pgproxy.New(net.JoinHostPort(host, strconv.Itoa(postgresPort)), opts))
	return nil
}

// firstPositive returns the first value above zero, or 0.
func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

// tokenReviewOnly exposes only ResolveForProxy, hiding a resolver's Attest.
type tokenReviewOnly struct{ brokercore.SessionResolver }

// boolEnvValue reports whether the named environment variable is set to a
// truthy value (per strconv.ParseBool). Unset or unparseable is false.
func boolEnvValue(key string) bool {
	if raw := os.Getenv(key); raw != "" {
		if b, err := strconv.ParseBool(raw); err == nil {
			return b
		}
	}
	return false
}

// intEnvValue reads a positive integer from the named environment variable,
// returning 0 when unset or invalid.
// maxShutdownSeconds keeps a drain, the 5 s database cleanup and the 5 s
// Vault login revoke inside a 75 s termination grace. It is a ceiling only: a
// preStop pause spends the same grace before SIGTERM, so a render with one
// must set a shorter drain.
const maxShutdownSeconds = 65

// checkShutdownSeconds refuses a drain the Pod's grace cannot hold: past it,
// the kubelet kills the broker before the Vault logins are revoked.
func checkShutdownSeconds(getenv func(string) string) error {
	raw := getenv("AGENT_VAULT_SHUTDOWN_SECONDS")
	if raw == "" {
		return nil
	}
	if n, err := strconv.Atoi(raw); err != nil || n < 0 || n > maxShutdownSeconds {
		return fmt.Errorf("AGENT_VAULT_SHUTDOWN_SECONDS must be 0 to %d", maxShutdownSeconds)
	}
	return nil
}

func intEnvValue(key string) int {
	if raw := os.Getenv(key); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// attachInfisicalIfConfigured wires the Infisical client when INFISICAL_URL
// is set. The 10s deadline uses time.After because the SDK login is
// synchronous and ignores ctx; on timeout we proceed without a client so
// external vaults serve-stale until next restart.
func attachInfisicalIfConfigured(srv *server.Server, logger *slog.Logger) {
	if os.Getenv("INFISICAL_URL") == "" {
		return
	}
	type result struct {
		c   *infisical.Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := infisical.NewClient(context.Background(), logger)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			logger.Warn("infisical client unavailable; external-store vaults will not refresh",
				slog.String("err", r.err.Error()))
			return
		}
		srv.AttachInfisical(r.c)
	case <-time.After(10 * time.Second):
		logger.Warn("infisical client login exceeded 10s deadline; continuing without external store")
	}
}

// attachHashicorpIfConfigured wires the HashiCorp Vault client when VAULT_ADDR
// is set. The 10s deadline bounds an AppRole login (token auth is instant); on
// timeout we proceed without a client so external vaults serve-stale until next
// restart.
func attachHashicorpIfConfigured(srv *server.Server, logger *slog.Logger) {
	if os.Getenv("VAULT_ADDR") == "" {
		return
	}
	type result struct {
		c   *hashicorp.Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := hashicorp.NewClient(context.Background(), logger)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			logger.Warn("hashicorp client unavailable; external-store vaults will not refresh",
				slog.String("err", r.err.Error()))
			return
		}
		srv.AttachHashicorp(r.c)
		srv.AttachReadiness("vault-login", r.c.Ready)
	case <-time.After(10 * time.Second):
		logger.Warn("hashicorp client login exceeded 10s deadline; continuing without external store")
	}
}

// attachLogSink wires the request-log pipeline: a BatchSink with async
// batching feeds persistent storage, and a retention goroutine trims old
// rows. Returns a shutdown function the caller runs after Start()
// returns to flush pending records and stop retention.
func attachLogSink(srv *server.Server, db store.Store, logger *slog.Logger) func() {
	sink := requestlog.NewBatchSink(db, logger, requestlog.BatchSinkConfig{})
	srv.AttachLogSink(sink)

	retentionCtx, cancelRetention := context.WithCancel(context.Background()) // #nosec G118 -- returned shutdown closure owns cancellation.
	go requestlog.RunRetention(retentionCtx, db, logger)

	return func() {
		cancelRetention()
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sink.Close(flushCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: request_log sink flush: %v\n", err)
		}
	}
}

// promptOwnerSetup interactively creates the owner account.
// masterPassword is optional — if provided, the admin password is checked against it.
func promptOwnerSetup(cmd *cobra.Command, db store.Store, masterPassword []byte) error {
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Create owner account:"))

	email, err := auth.PromptEmail("  Admin email: ")
	if err != nil {
		return fmt.Errorf("email input: %w", err)
	}

	pw, err := auth.PromptNewPassword("  Admin password: ", "  Confirm admin password: ")
	if err != nil {
		return fmt.Errorf("password input: %w", err)
	}

	if len(pw) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}

	if masterPassword != nil && string(pw) == string(masterPassword) {
		return fmt.Errorf("admin password must be different from the master password")
	}

	hash, salt, kdfP, err := auth.HashUserPassword(pw)
	crypto.WipeBytes(pw)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Get the default vault so the owner is granted admin access on it.
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		return fmt.Errorf("looking up default vault: %w", err)
	}

	if _, err := db.RegisterFirstUser(context.Background(), email, hash, salt, vault.ID, kdfP.Time, kdfP.Memory, kdfP.Threads); err != nil {
		return fmt.Errorf("creating owner account: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s Owner account created for %s\n", successText("✓"), email)
	return nil
}

// unlockOrSetup resolves the master password and returns the DEK.
// Priority: AGENT_VAULT_MASTER_PASSWORD envvar > --password-stdin > interactive prompt.
// When no password is provided (envvar empty, no --password-stdin), sets up in passwordless mode.
func unlockOrSetup(cmd *cobra.Command, db store.Store, passwordStdin bool) (*auth.MasterKey, error) {
	// 1. AGENT_VAULT_MASTER_PASSWORD envvar (highest priority, for containerized/cloud deployments)
	if envPw := os.Getenv("AGENT_VAULT_MASTER_PASSWORD"); envPw != "" {
		_ = os.Unsetenv("AGENT_VAULT_MASTER_PASSWORD")
		return unlockOrSetupWithPassword(db, []byte(envPw))
	}

	// 2. --password-stdin (non-interactive, single attempt)
	if passwordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return nil, err
		}
		return unlockOrSetupWithPassword(db, password)
	}

	// 3. Interactive prompt
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		// First-time setup — prompt with confirmation, allow empty for passwordless
		fmt.Fprintln(cmd.OutOrStderr(), boldText("Setting up for the first time."))
		pw, err := auth.PromptNewPassword(
			"Enter master password (leave empty for passwordless): ",
			"Confirm master password: ",
		)
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}
		return setupMasterKey(db, pw)
	}

	// Existing record — check if passwordless
	if record.DEKPlaintext != nil {
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — interactive unlock, up to 3 attempts
	verRec := buildVerificationRecord(record)
	fmt.Fprintln(cmd.OutOrStderr(), boldText("Agent Vault is locked. Enter master password to unlock."))

	for attempt := 1; attempt <= maxPasswordAttempts; attempt++ {
		password, err := auth.PromptPassword("Master password: ")
		if err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}

		mk, err := auth.Unlock(password, verRec)
		crypto.WipeBytes(password)
		if err == nil {
			return mk, nil
		}

		if attempt < maxPasswordAttempts {
			fmt.Fprintf(cmd.OutOrStderr(), "%s Wrong password. %d attempt(s) remaining.\n", warningText("!"), maxPasswordAttempts-attempt)
		} else {
			return nil, fmt.Errorf("too many failed attempts")
		}
	}

	return nil, fmt.Errorf("too many failed attempts")
}

// unlockOrSetupWithPassword resolves the DEK using a known password (no prompting, no retry).
// Used by the AGENT_VAULT_MASTER_PASSWORD envvar and --password-stdin code paths.
func unlockOrSetupWithPassword(db store.Store, password []byte) (*auth.MasterKey, error) {
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}

	if record == nil {
		return setupMasterKey(db, password)
	}

	// Passwordless instance — password is ignored, unlock without it
	if record.DEKPlaintext != nil {
		crypto.WipeBytes(password)
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return nil, fmt.Errorf("unlocking (passwordless): %w", err)
		}
		return mk, nil
	}

	// Password-protected — single attempt, no retry
	verRec := buildVerificationRecord(record)
	mk, err := auth.Unlock(password, verRec)
	crypto.WipeBytes(password)
	if err != nil {
		return nil, fmt.Errorf("wrong password")
	}
	return mk, nil
}

// setupMasterKey runs first-time DEK generation and KEK wrapping.
// If password is empty, sets up in passwordless mode.
//
// In HA (Postgres), another pod may have already created the master key
// record. SetMasterKeyRecord uses ON CONFLICT DO NOTHING, so if the
// record already exists, we re-read it and unlock using the existing
// record instead of the locally-generated one.
func setupMasterKey(db store.Store, password []byte) (*auth.MasterKey, error) {
	var mk *auth.MasterKey
	var rec *auth.VerificationRecord
	var err error

	if len(password) == 0 {
		mk, rec, err = auth.SetupPasswordless()
	} else {
		mk, rec, err = auth.SetupWithPassword(password)
	}
	if err != nil {
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("setting up master key: %w", err)
	}

	ctx := context.Background()
	storeRec := verificationToStoreRecord(rec)
	if err := db.SetMasterKeyRecord(ctx, storeRec); err != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("persisting master key record: %w", err)
	}

	// Re-read the record: if another pod won the race (ON CONFLICT DO
	// NOTHING), the DB has THEIR record, not ours. We need to unlock
	// using whatever is actually stored.
	existing, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return nil, fmt.Errorf("re-reading master key after setup: %w", err)
	}

	verRec := buildVerificationRecord(existing)
	if existing.DEKPlaintext != nil {
		mk.Wipe()
		if len(password) > 0 {
			crypto.WipeBytes(password)
		}
		return auth.UnlockPasswordless(verRec)
	}

	if len(password) > 0 {
		mk.Wipe()
		unlocked, err := auth.Unlock(password, verRec)
		crypto.WipeBytes(password)
		if err != nil {
			return nil, fmt.Errorf("unlocking with password after race: %w", err)
		}
		return unlocked, nil
	}

	// If we reach here, len(password) == 0 and existing.DEKPlaintext
	// was handled above (passwordless unlock). The only remaining case
	// is a password-protected DB record with no local password.
	mk.Wipe()
	return nil, fmt.Errorf("master key in database is password-protected but AGENT_VAULT_MASTER_PASSWORD is not set; all pods must use the same master password")
}

// verificationToStoreRecord converts an auth VerificationRecord to a store MasterKeyRecord.
func verificationToStoreRecord(rec *auth.VerificationRecord) *store.MasterKeyRecord {
	r := &store.MasterKeyRecord{
		Sentinel:      rec.Sentinel,
		SentinelNonce: rec.SentinelNonce,
		DEKCiphertext: rec.DEKCiphertext,
		DEKNonce:      rec.DEKNonce,
		DEKPlaintext:  rec.DEKPlaintext,
		Salt:          rec.Salt,
	}
	if rec.Params.Time > 0 {
		r.KDFTime = &rec.Params.Time
		r.KDFMemory = &rec.Params.Memory
		r.KDFThreads = &rec.Params.Threads
	}
	return r
}

// buildVerificationRecord converts a store record to an auth verification record.
func buildVerificationRecord(record *store.MasterKeyRecord) *auth.VerificationRecord {
	vr := &auth.VerificationRecord{
		Sentinel:      record.Sentinel,
		SentinelNonce: record.SentinelNonce,
		DEKCiphertext: record.DEKCiphertext,
		DEKNonce:      record.DEKNonce,
		DEKPlaintext:  record.DEKPlaintext,
		Salt:          record.Salt,
	}
	if record.KDFTime != nil {
		defaults := crypto.DefaultKDFParams()
		vr.Params = crypto.KDFParams{
			Time:    *record.KDFTime,
			Memory:  *record.KDFMemory,
			Threads: *record.KDFThreads,
			KeyLen:  defaults.KeyLen,
			SaltLen: defaults.SaltLen,
		}
	}
	return vr
}

// readPasswordFromStdin reads a single line from stdin for non-interactive password input.
func readPasswordFromStdin() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read password from stdin")
	}
	return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
}

// runDetachedChild is the entry point for the detached child process.
// It reads 33 bytes from stdin: 32-byte master key + 1-byte initialized flag.
func runDetachedChild(host, addr string, mitmPort, postgresPort int, logger *slog.Logger, maxRespBytes, maxReqBytes int64) error {
	buf := make([]byte, 33)
	if _, err := io.ReadFull(os.Stdin, buf); err != nil {
		return fmt.Errorf("reading master key from pipe: %w", err)
	}
	key := buf[:32]
	initialized := buf[32] == 1

	dbURL, err := databaseURL()
	if err != nil {
		return err
	}
	dbPath, err := store.DefaultDBPath()
	if err != nil && dbURL == "" {
		return fmt.Errorf("resolving db path: %w", err)
	}

	db, err := store.OpenStore(store.StoreConfig{
		DatabaseURL: dbURL,
		SQLitePath:  dbPath,
	})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() { _ = db.Close() }()

	baseURL := resolveBaseURL(addr)
	smtpCfg := notify.LoadSMTPConfig()
	_ = os.Unsetenv("AGENT_VAULT_SMTP_PASSWORD")
	notifier := notify.New(smtpCfg)
	srv := server.New(addr, db, key, notifier, initialized, baseURL, logger)
	srv.SetSkills(skillCLI)
	srv.AttachTelemetry(tel)
	shutdownLogs := attachLogSink(srv, db, logger)
	defer shutdownLogs()
	if err := attachServerExtensions(srv, host, mitmPort, postgresPort, key, db, logger, maxRespBytes, maxReqBytes); err != nil {
		return err
	}
	captureServerStart(mitmPort, db.DialectName())
	return srv.Start()
}

// spawnDetached re-execs the server as a background process, passing the master key + initialized flag via a pipe.
// explicitLogLevel, when non-nil, forwards the parent's --log-level flag to the child so a flag-only
// invocation (no env var) still takes effect after re-exec.
func spawnDetached(cmd *cobra.Command, masterKey *auth.MasterKey, initialized bool, host string, port, mitmPort, postgresPort int, addr string, explicitLogLevel *string, maxRespBytes, maxReqBytes int64) error {
	defer masterKey.Wipe()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}

	logPath, err := serverLogPath()
	if err != nil {
		return fmt.Errorf("resolving log path: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("opening log file: %w", err)
	}

	childArgs := []string{"server", "--port", strconv.Itoa(port), "--host", host, "--mitm-port", strconv.Itoa(mitmPort), "--postgres-port", strconv.Itoa(postgresPort)}
	if explicitLogLevel != nil {
		childArgs = append(childArgs, "--log-level", *explicitLogLevel)
	}
	childArgs = append(childArgs, "--max-response-bytes", strconv.FormatInt(maxRespBytes, 10))
	childArgs = append(childArgs, "--max-request-bytes", strconv.FormatInt(maxReqBytes, 10))
	child := exec.Command(exe, childArgs...)
	child.Stdin = pr
	child.Stdout = logFile
	child.Stderr = logFile
	flagURL, _ := cmd.Flags().GetString("database-url")
	childEnv := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if flagURL != "" && strings.HasPrefix(kv, "DATABASE_URL=") {
			continue
		}
		childEnv = append(childEnv, kv)
	}
	childEnv = append(childEnv, "_AGENT_VAULT_DETACHED=1")
	if flagURL != "" {
		childEnv = append(childEnv, "DATABASE_URL="+flagURL)
	}
	child.Env = childEnv
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = logFile.Close()
		return fmt.Errorf("starting detached server: %w", err)
	}

	// Send the master key + initialized flag (33 bytes) to the child via the pipe.
	var initByte byte
	if initialized {
		initByte = 1
	}
	payload := make([]byte, 33)
	copy(payload, masterKey.Key())
	payload[32] = initByte
	if _, err := pw.Write(payload); err != nil {
		crypto.WipeBytes(payload)
		_ = pw.Close()
		_ = pr.Close()
		_ = logFile.Close()
		return fmt.Errorf("sending master key to child: %w", err)
	}
	crypto.WipeBytes(payload)
	_ = pw.Close()
	_ = pr.Close()
	_ = logFile.Close()

	// Poll the health endpoint to verify the child started.
	healthURL := fmt.Sprintf("http://%s/health", addr)
	started := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				started = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if started {
		fmt.Fprintf(cmd.OutOrStdout(), "%s Server started in background (PID %d). Logs: %s\n",
			successText("✓"), child.Process.Pid, logPath)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStderr(), "%s Server may still be starting. Check %s for details.\n",
		warningText("!"), logPath)
	return fmt.Errorf("server did not respond within 3 seconds")
}

func serverLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agent-vault", "server.log"), nil
}

// --- Stop subcommand ---

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running Agent Vault server",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := pidfile.Read()
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("no server appears to be running (PID file not found)")
			}
			return fmt.Errorf("reading PID file: %w", err)
		}

		if !pidfile.IsRunning(pid) {
			_ = pidfile.Remove()
			return fmt.Errorf("server process %d is not running (stale PID file removed)", pid)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Stopping server (PID %d)...\n", pid)

		if err := stopServer(); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Server stopped.\n", successText("✓"))
		return nil
	},
}

func captureServerStart(mitmPort int, dbBackend string) {
	distinctID := telemetry.MachineID()
	if sess, _ := session.Load(); sess != nil && sess.Email != "" {
		distinctID = sess.Email
	}
	if distinctID == "" {
		distinctID = "anonymous_server"
	}
	tel.CaptureEvent(distinctID, "av.server-start", map[string]string{
		"mitm_enabled":     strconv.FormatBool(mitmPort > 0),
		"database_backend": dbBackend,
	})
}

func init() {
	serverCmd.Flags().IntP("port", "p", defaultPort(), "port to listen on (also respects PORT env var)")
	serverCmd.Flags().String("host", DefaultHost, "host to bind to")
	serverCmd.Flags().String("database-url", "", "PostgreSQL connection URL (also respects DATABASE_URL env var)")
	serverCmd.Flags().BoolP("detach", "d", false, "run server in background after unlocking")
	serverCmd.Flags().Bool("password-stdin", false, "read master password from stdin (for non-interactive use)")
	serverCmd.Flags().Int("mitm-port", DefaultMITMPort, "port for the transparent MITM proxy (0 = disabled)")
	serverCmd.Flags().Int("postgres-port", DefaultPostgresPort, "port for the loopback PostgreSQL broker (0 = disabled; requires VAULT_ADDR and AGENT_VAULT_DB_BROKER or DB_SERVICES)")
	serverCmd.Flags().String("log-level", "info", "log level: info (default) or debug (per-request proxy logs)")
	serverCmd.Flags().Int64("max-response-bytes", defaultMaxResponseBytes(), "max response body bytes streamed to agents (default: unlimited; also respects AGENT_VAULT_MAX_RESPONSE_BYTES)")
	serverCmd.Flags().Int64("max-request-bytes", defaultMaxRequestBytes(), "max request body bytes forwarded to upstreams (default: 1 GiB; also respects AGENT_VAULT_MAX_REQUEST_BYTES)")
	serverCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(serverCmd)
}

// caStoreAdapter bridges store.Store to the ca.CAStore interface.
type caStoreAdapter struct {
	db store.Store
}

func (a *caStoreAdapter) GetCAState(ctx context.Context) (*ca.CAStateRecord, error) {
	state, err := a.db.GetCAState(ctx)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, nil
	}
	return &ca.CAStateRecord{
		RootCert:     state.RootCert,
		RootKeyCT:    state.RootKeyCT,
		RootKeyNonce: state.RootKeyNonce,
	}, nil
}

func (a *caStoreAdapter) SetCAState(ctx context.Context, rec *ca.CAStateRecord) error {
	return a.db.SetCAState(ctx, &store.CAState{
		RootCert:     rec.RootCert,
		RootKeyCT:    rec.RootKeyCT,
		RootKeyNonce: rec.RootKeyNonce,
		Source:       "auto",
	})
}

// Both settings are required so adding observer identity cannot expose the owner API.
func cleanupObserverPort(path, value string) (int, error) {
	if path == "" && value == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(value)
	if path == "" || err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
		return 0, fmt.Errorf("cleanup observer requires both policy file and a numeric port from 1 through 65535")
	}
	return port, nil
}

// catalogProfiles reads each pool's declared harness profile from the live
// catalog, so every admission also matches it.
func catalogProfiles(catalog interface{ Current() httpcatalog.Catalog }) workloadidentity.ProfileSource {
	return func(name string) (workloadidentity.Profile, bool) {
		pool, ok := catalog.Current().Pool(name)
		if !ok {
			return workloadidentity.Profile{}, false
		}
		p := pool.Profile()
		if !p.Explicit {
			return workloadidentity.Profile{}, false
		}
		return workloadidentity.Profile{Name: p.Name, Issuer: p.TrustDomain.Issuer, Audience: p.TrustDomain.Audience, Remote: p.TrustDomain.Keys != httpcatalog.KeysInCluster,
			Kind: p.Identity.Kind, OwnerKind: p.Identity.OwnerKind, Namespaces: p.Identity.Namespaces, ImageDigests: p.Identity.ImageDigests,
			ImagePrefix: p.Identity.ImagePrefix}, true
	}
}
