package cmd

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

// readyCmd is the readiness probe for a broker whose listeners are loopback
// only: the kubelet runs it inside the container.
var readyCmd = &cobra.Command{
	Use:   "ready",
	Short: "Exit 0 when the local server reports ready (for Kubernetes readiness probes)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		port, _ := cmd.Flags().GetInt("port")
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/readyz")
		if err != nil {
			return fmt.Errorf("not ready: server unreachable")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("not ready")
		}
		return nil
	},
}

func init() {
	readyCmd.Flags().Int("port", DefaultPort, "local server port")
	serverCmd.AddCommand(readyCmd)
}
