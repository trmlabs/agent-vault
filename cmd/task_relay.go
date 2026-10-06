package cmd

import (
	"os/signal"
	"syscall"

	"github.com/Infisical/agent-vault/internal/taskrelay"
	"github.com/spf13/cobra"
)

func init() {
	var configPath string
	command := &cobra.Command{Use: "task-relay", Short: "Serve a fixed trusted relay for one isolated task", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		config, e := taskrelay.LoadConfig(configPath)
		if e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return taskrelay.Run(ctx, config)
	}}
	command.Flags().StringVar(&configPath, "config", "", "Operator-owned fixed task relay JSON configuration")
	_ = command.MarkFlagRequired("config")
	var janitorConfig string
	janitor := &cobra.Command{Use: "janitor", Short: "Retire agent Sandboxes no shared proxy replica has seen in use, in one pass", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			config, e := taskrelay.LoadJanitorConfig(janitorConfig)
			if e != nil {
				return e
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return taskrelay.RunJanitor(ctx, config, cmd.OutOrStdout())
		}}
	janitor.Flags().StringVar(&janitorConfig, "config", "", "Operator-owned janitor JSON configuration")
	_ = janitor.MarkFlagRequired("config")
	command.AddCommand(janitor)
	rootCmd.AddCommand(command)
}
