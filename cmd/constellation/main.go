package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/bdubs00/constellation/internal/audit"
	"github.com/bdubs00/constellation/internal/config"
	"github.com/bdubs00/constellation/internal/policy"
	"github.com/bdubs00/constellation/internal/proxy"
	"github.com/bdubs00/constellation/internal/secrets"
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
	serverName, _ := cmd.Flags().GetString("server")

	cfg, err := config.Load(policyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	srv, ok := cfg.Servers[serverName]
	if !ok {
		return fmt.Errorf("server %q not found in policy file", serverName)
	}

	// Set up audit logger
	var auditWriter *os.File
	if auditLog != "" {
		f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening audit log: %w", err)
		}
		defer f.Close()
		auditWriter = f
	} else {
		auditWriter = os.Stderr
	}
	logger := audit.New(auditWriter)

	// Resolve secrets
	extraEnv := map[string]string{}
	if srv.Secrets != nil && len(srv.Secrets.Env) > 0 {
		providers := map[string]secrets.Provider{
			"env": secrets.NewStaticProvider(),
		}

		// Set up Vault provider if configured
		if cfg.Vault != nil {
			vaultProvider, err := secrets.NewVaultProvider(*cfg.Vault)
			if err != nil {
				return fmt.Errorf("initializing vault: %w", err)
			}
			cancel := vaultProvider.StartRenewal()
			defer cancel()
			providers["vault"] = vaultProvider
		}

		resolved, err := secrets.Resolve(srv.Secrets.Env, providers)
		if err != nil {
			return fmt.Errorf("resolving secrets: %w", err)
		}
		extraEnv = resolved
	}

	engine := policy.NewEngine(srv)

	return proxy.Run(serverName, srv, engine, logger, dryRun, extraEnv)
}

func validatePolicy(cmd *cobra.Command, args []string) error {
	_, err := config.Load(policyPath)
	if err != nil {
		return err
	}
	fmt.Println("policy file is valid")
	return nil
}
