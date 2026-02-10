package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	policyPath string
	auditLog   string
	logLevel   string
	dryRun     bool
)

func main() {
	root := &cobra.Command{
		Use:   "constellation",
		Short: "MCP access control proxy",
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the proxy for an MCP server",
		RunE:  runProxy,
	}
	runCmd.Flags().StringVar(&policyPath, "policy", "constellation.yaml", "path to policy file")
	runCmd.Flags().StringVar(&auditLog, "audit-log", "", "path to audit log file (default: stderr)")
	runCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "evaluate policies but forward all calls")
	runCmd.Flags().String("server", "", "server name from policy file")
	runCmd.MarkFlagRequired("server")

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a policy file",
		RunE:  validatePolicy,
	}
	validateCmd.Flags().StringVar(&policyPath, "policy", "constellation.yaml", "path to policy file")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("constellation v0.1.0")
		},
	}

	root.AddCommand(runCmd, validateCmd, versionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runProxy(cmd *cobra.Command, args []string) error {
	fmt.Println("proxy not yet implemented")
	return nil
}

func validatePolicy(cmd *cobra.Command, args []string) error {
	fmt.Println("validate not yet implemented")
	return nil
}
