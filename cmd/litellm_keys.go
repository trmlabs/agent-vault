package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/litellmkeys"
)

var litellmKeysCmd = &cobra.Command{
	Use:   "litellm-keys",
	Short: "Mint and rotate the LiteLLM keys the broker injects",
}

var litellmKeysReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Mint missing or expiring LiteLLM keys into Vault and revoke replaced ones",
	Long: `Reconcile runs once, as a scheduled job with its own Vault login
(VAULT_ADDR, VAULT_JWT_MOUNT, VAULT_JWT_ROLE, VAULT_JWT_TOKEN_FILE). For each
key in --config it mints a LiteLLM virtual key under the configured team when
the key is missing, expires within rotateBefore, or was minted with other
settings, writes it to Vault, and revokes the replaced key after revokeAfter.
It reads the team's admin key from Vault and never prints a key.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path, _ := cmd.Flags().GetString("config")
		data, err := os.ReadFile(path) // #nosec G304 -- the operator names the config file.
		if err != nil {
			return err
		}
		cfg, err := litellmkeys.Parse(data)
		if err != nil {
			return err
		}
		logical, done, err := hashicorp.LoginOnce(cmd.Context(), os.Getenv)
		if err != nil {
			return err
		}
		defer done()
		logger := slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), nil))
		r := &litellmkeys.Reconciler{Config: cfg, Vault: logical, Log: logger}
		res, runErr := r.Run(cmd.Context())
		summary, _ := json.Marshal(map[string]int{"minted": res.Minted, "revoked": res.Revoked, "current": res.Current, "failed": res.Failed})
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(summary))
		return runErr
	},
}

func init() {
	litellmKeysReconcileCmd.Flags().String("config", "/etc/gatehouse/litellm-keys.json", "the job's config file")
	litellmKeysCmd.AddCommand(litellmKeysReconcileCmd)
	rootCmd.AddCommand(litellmKeysCmd)
}
