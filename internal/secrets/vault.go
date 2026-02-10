package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	approle "github.com/hashicorp/vault/api/auth/approle"

	"github.com/bdubs00/constellation/internal/config"
)

// VaultProvider fetches secrets from HashiCorp Vault.
type VaultProvider struct {
	client *vaultapi.Client
}

// NewVaultProvider creates a Vault provider and authenticates using the given config.
func NewVaultProvider(cfg config.VaultConfig) (*VaultProvider, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.Address

	if cfg.TLS.CACert != "" || cfg.TLS.SkipVerify {
		tlsCfg := &tls.Config{}

		if cfg.TLS.SkipVerify {
			log.Println("WARNING: Vault TLS verification disabled — do not use in production")
			tlsCfg.InsecureSkipVerify = true
		}

		if cfg.TLS.CACert != "" {
			caCert, err := os.ReadFile(cfg.TLS.CACert)
			if err != nil {
				return nil, fmt.Errorf("reading CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA cert")
			}
			tlsCfg.RootCAs = pool
		}

		vaultCfg.HttpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	if err := authenticate(client, cfg.Auth); err != nil {
		return nil, fmt.Errorf("vault authentication: %w", err)
	}

	return &VaultProvider{client: client}, nil
}

func authenticate(client *vaultapi.Client, auth config.AuthConfig) error {
	switch auth.Method {
	case "token":
		// Token is read from VAULT_TOKEN env var by the client automatically.
		if client.Token() == "" {
			return fmt.Errorf("VAULT_TOKEN environment variable not set")
		}
		return nil

	case "approle":
		roleID, err := os.ReadFile(auth.RoleIDPath)
		if err != nil {
			return fmt.Errorf("reading role_id: %w", err)
		}
		secretID, err := os.ReadFile(auth.SecretIDPath)
		if err != nil {
			return fmt.Errorf("reading secret_id: %w", err)
		}

		appRoleAuth, err := approle.NewAppRoleAuth(
			strings.TrimSpace(string(roleID)),
			&approle.SecretID{FromString: strings.TrimSpace(string(secretID))},
		)
		if err != nil {
			return fmt.Errorf("creating approle auth: %w", err)
		}

		_, err = client.Auth().Login(context.Background(), appRoleAuth)
		if err != nil {
			return fmt.Errorf("approle login: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported auth method: %q", auth.Method)
	}
}

// Fetch resolves a reference like "secret/myapp#connection_string".
// The part before # is the Vault path, the part after is the field key.
func (p *VaultProvider) Fetch(reference string) (string, error) {
	parts := strings.SplitN(reference, "#", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid vault reference %q: expected path#field", reference)
	}
	path, field := parts[0], parts[1]

	secret, err := p.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("reading vault path %q: %w", path, err)
	}
	if secret == nil {
		return "", fmt.Errorf("no secret found at vault path %q", path)
	}

	// KV v2 wraps data in a "data" key
	data := secret.Data
	if inner, ok := data["data"].(map[string]interface{}); ok {
		data = inner
	}

	val, ok := data[field]
	if !ok {
		return "", fmt.Errorf("field %q not found at vault path %q", field, path)
	}
	return fmt.Sprintf("%v", val), nil
}

// StartRenewal starts a background goroutine that keeps the Vault token alive.
// Call the returned cancel function to stop renewal.
func (p *VaultProvider) StartRenewal() (cancel func()) {
	ctx, cancelFn := context.WithCancel(context.Background())

	go func() {
		watcher, err := p.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
			Secret: &vaultapi.Secret{
				Auth: &vaultapi.SecretAuth{
					ClientToken:   p.client.Token(),
					Renewable:     true,
					LeaseDuration: 3600,
				},
			},
		})
		if err != nil {
			log.Printf("WARNING: failed to start vault token renewal: %v", err)
			return
		}

		go watcher.Start()
		defer watcher.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case err := <-watcher.DoneCh():
				if err != nil {
					log.Printf("WARNING: vault token renewal stopped: %v", err)
				}
				return
			case <-watcher.RenewCh():
				log.Println("vault token renewed successfully")
			}
		}
	}()

	return cancelFn
}
