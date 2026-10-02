package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Check the PostgreSQL broker's signed audit trail",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify exported audit rows for gaps, reordering and edits",
	Long: `Verify reads newline-delimited audit rows, bare or as Cloud Logging
entries, and checks each replica's HMAC chain and Transit-signed checkpoints.
It reads HMAC key versions and the Transit public keys from Vault using the
standard VAULT_ADDR and authentication environment. It prints findings, never
key material, and exits 1 if the trail cannot be trusted as complete.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		flags := cmd.Flags()
		input, _ := flags.GetString("input")
		maxUnsigned, _ := flags.GetDuration("max-unsigned")
		sortBySeq, _ := flags.GetBool("sort-by-seq")
		partial, _ := flags.GetBool("partial-history")
		heads, err := readAuditHeads(stringFlag(cmd, "heads"))
		if err != nil {
			return err
		}
		keys := auditchain.KVKeys{Mount: stringFlag(cmd, "hmac-mount"), Path: stringFlag(cmd, "hmac-path"), Field: stringFlag(cmd, "hmac-field")}
		signer := auditchain.TransitSigner{Mount: stringFlag(cmd, "transit-mount"), Key: stringFlag(cmd, "transit-key")}
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
		defer cancel()
		client, err := hashicorp.NewClient(ctx, slog.New(slog.DiscardHandler))
		if err != nil {
			return fmt.Errorf("vault client: %w", err)
		}
		keys.Vault, signer.Vault = client.Logical(), client.Logical()
		public, err := signer.PublicKeys(ctx)
		if err != nil {
			return err
		}
		var r io.Reader = os.Stdin
		if input != "-" {
			f, err := os.Open(input)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		verifier := auditchain.Verifier{HMACKey: func(version int) ([]byte, error) { return keys.Version(ctx, version) }, PublicKeys: public, MaxUnsigned: maxUnsigned, SortBySeq: sortBySeq, PartialHistory: partial, Heads: heads}
		return runAuditVerify(r, cmd.OutOrStdout(), verifier)
	},
}

var auditHeadsCmd = &cobra.Command{
	Use:   "heads",
	Short: "Print each replica's audit head from the store, for audit verify --heads",
	Long: `Heads prints one JSON object per broker replica: its current audit boot and
the newest checkpoint row it persisted. Pass the output to audit verify
--heads so a deleted newest boot or a tail cut back to an earlier checkpoint
is reported. It reads the store named by DATABASE_URL, or the default SQLite
file, and prints no secrets.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		db, closeDB, err := openDB()
		if err != nil {
			return err
		}
		defer closeDB()
		lister, ok := db.(interface {
			ListAuditHeads(context.Context) ([]store.AuditHead, error)
		})
		if !ok {
			return fmt.Errorf("this store does not hold audit heads")
		}
		heads, err := lister.ListAuditHeads(cmd.Context())
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		for _, head := range heads {
			if err := encoder.Encode(head); err != nil {
				return err
			}
		}
		return nil
	},
}

// readAuditHeads reads audit heads output. An empty path means no head check.
func readAuditHeads(path string) ([]auditchain.Head, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	heads := []auditchain.Head{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	for decoder.More() {
		var head auditchain.Head
		if err := decoder.Decode(&head); err != nil {
			return nil, fmt.Errorf("audit heads file: %w", err)
		}
		heads = append(heads, head)
	}
	return heads, nil
}

func stringFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func runAuditVerify(r io.Reader, w io.Writer, verifier auditchain.Verifier) error {
	report, err := verifier.Verify(r)
	if err != nil {
		return err
	}
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintln(w, finding)
	}
	_, _ = fmt.Fprintf(w, "chains=%d rows=%d findings=%d\n", report.Chains, report.Rows, len(report.Findings))
	if len(report.Findings) > 0 || report.Rows == 0 {
		return &ExitCodeError{Code: 1}
	}
	return nil
}

func init() {
	f := auditVerifyCmd.Flags()
	f.String("input", "-", "file of exported rows, or - for stdin")
	f.String("hmac-mount", "gatehouse", "KV version 2 mount holding the HMAC key")
	f.String("hmac-path", "", "KV path of the HMAC key")
	f.String("hmac-field", "key", "field holding the base64 HMAC key")
	f.String("transit-mount", "transit", "Transit mount of the checkpoint key")
	f.String("transit-key", "", "Transit ed25519 checkpoint key name")
	f.Duration("max-unsigned", 5*time.Minute, "longest allowed run of rows after the last checkpoint; 0 disables")
	f.Bool("sort-by-seq", false, "check rows in sequence order, for exports that do not preserve order")
	f.Bool("partial-history", false, "accept that each replica's earliest exported boot links to a boot outside the export")
	f.String("heads", "", "output of agent-vault audit heads; each replica's newest boot must reach its head")
	_ = auditVerifyCmd.MarkFlagRequired("hmac-path")
	_ = auditVerifyCmd.MarkFlagRequired("transit-key")
	auditCmd.AddCommand(auditVerifyCmd, auditHeadsCmd)
	rootCmd.AddCommand(auditCmd)
}
