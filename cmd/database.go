package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Infisical/agent-vault/internal/server"
	"github.com/spf13/cobra"
)

// databaseServiceView mirrors the server's API representation of a managed
// PostgreSQL-broker database. It carries references only (the Vault mount and
// role that mint credentials), never a database password.
type databaseServiceView struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
	Database string `json:"database,omitempty"`
	Mount    string `json:"mount"`
	Role     string `json:"role"`
	SSLMode  string `json:"sslmode"`
	MaxConns int    `json:"max_conns,omitempty"`
}

var databaseCmd = &cobra.Command{
	Use:     "database",
	Aliases: []string{"db"},
	Short:   "Manage PostgreSQL-broker databases in a vault",
	Long: `Manage the upstream databases the PostgreSQL broker fronts for a vault.

Each database references a HashiCorp Vault database secrets-engine mount and
role; the broker mints short-lived credentials from them at connect time and
never stores a database password. An agent connects to the broker carrying only
its Agent Vault token and selects a database by name.

Changes take effect immediately — the broker resolves databases live, so no
restart is needed after add or remove.`,
}

var databaseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the vault's databases",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/databases", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Databases []databaseServiceView `json:"databases"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if len(resp.Databases) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText(fmt.Sprintf("No databases in vault %q.", vault)))
			return nil
		}

		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tUPSTREAM\tDATABASE\tMOUNT/ROLE\tSSLMODE\tMAX_CONNS")
		for _, db := range resp.Databases {
			maxConns := "default"
			if db.MaxConns > 0 {
				maxConns = fmt.Sprintf("%d", db.MaxConns)
			}
			database := db.Database
			if database == "" {
				database = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\t%s\n",
				db.Name, db.Upstream, database, db.Mount, db.Role, db.SSLMode, maxConns)
		}
		return tw.Flush()
	},
}

var databaseAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add or update a database (instance owner required)",
	Long: `Add a database the broker will front, or update an existing one (upsert
by name). Requires an instance owner because this binds the server's Vault identity.

  agent-vault vault database add --name alloy --upstream alloy.internal:5432 \
      --mount database --role app-ro --sslmode verify-full

--mount and --role name the Vault database secrets-engine mount and role that
mint credentials for this upstream. --sslmode controls the broker's TLS to the
upstream (disable|prefer|require|verify-full; default prefer). --database
overrides the upstream database name; when omitted the client's requested
database is honored. --max-conns caps this database's share of broker
connections (0 = the broker default). Services sharing an upstream address use
the strictest explicit limit; updates apply to new admissions.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)

		name, _ := cmd.Flags().GetString("name")
		upstream, _ := cmd.Flags().GetString("upstream")
		mount, _ := cmd.Flags().GetString("mount")
		role, _ := cmd.Flags().GetString("role")
		if name == "" || upstream == "" || mount == "" || role == "" {
			return fmt.Errorf("--name, --upstream, --mount, and --role are required")
		}
		database, _ := cmd.Flags().GetString("database")
		sslmode, _ := cmd.Flags().GetString("sslmode")
		maxConns, _ := cmd.Flags().GetInt("max-conns")

		cfg := server.DatabaseServiceConfig{Name: name, Upstream: upstream, Database: database, Mount: mount, Role: role, SSLMode: sslmode, MaxConns: maxConns}
		if err := cfg.Validate(vault); err != nil {
			return err
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			return err
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/databases", sess.Address, vault)
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, body)
		if err != nil {
			return err
		}

		var resp struct {
			Created  bool                `json:"created"`
			Database databaseServiceView `json:"database"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		verb := "updated"
		if resp.Created {
			verb = "added"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Database %s: %s (%s → mount=%s role=%s, sslmode=%s)\n",
			successText("✓"), verb, resp.Database.Name, resp.Database.Upstream,
			resp.Database.Mount, resp.Database.Role, resp.Database.SSLMode)
		return nil
	},
}

var databaseRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a database by name",
	Long: `Remove a database from the vault. Existing agent connections continue on
their already-minted credentials until they close or the credential expires;
new connections can no longer select the removed database.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		name := args[0]
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			fmt.Fprintf(cmd.OutOrStderr(), "Remove database %q from vault %q? [y/N] ", name, vault)
			reader := bufio.NewReader(os.Stdin)
			answer, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), mutedText("Aborted."))
				return nil
			}
		}

		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/databases/%s", sess.Address, vault, url.PathEscape(name))
		if _, err := doAdminRequestWithBody("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Database removed: %s\n", successText("✓"), name)
		return nil
	},
}

func init() {
	databaseAddCmd.Flags().String("name", "", "Database name the agent selects by (required)")
	databaseAddCmd.Flags().String("upstream", "", "Upstream host:port (required)")
	databaseAddCmd.Flags().String("mount", "", "Vault database secrets-engine mount, e.g. database (required)")
	databaseAddCmd.Flags().String("role", "", "Vault role that mints credentials for this upstream (required)")
	databaseAddCmd.Flags().String("database", "", "Upstream database name override (default: honor the client's requested database)")
	databaseAddCmd.Flags().String("sslmode", "", "Upstream TLS mode: disable|prefer|require|verify-full (default prefer)")
	databaseAddCmd.Flags().Int("max-conns", 0, "Per-database connection budget (0 = broker default)")

	databaseRemoveCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	databaseCmd.AddCommand(databaseListCmd)
	databaseCmd.AddCommand(databaseAddCmd)
	databaseCmd.AddCommand(databaseRemoveCmd)
	vaultCmd.AddCommand(databaseCmd)
}
