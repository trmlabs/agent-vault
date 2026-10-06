package hashicorp

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SignCertificate asks a Vault PKI role to sign a certificate request for
// exactly the given DNS names. The role, not the broker, holds the CA key and
// limits what Vault will sign; the broker checks the request first as well.
// It returns the PEM certificate and the PEM chain above it.
func (c *Client) SignCertificate(ctx context.Context, mount, role, csrPEM string, names []string, ttl time.Duration) (string, string, error) {
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return "", "", fmt.Errorf("invalid Vault PKI mount or role")
	}
	if len(names) == 0 || ttl < time.Minute || ttl > 24*time.Hour {
		return "", "", fmt.Errorf("certificate needs names and a TTL of one minute to 24 hours")
	}
	path := strings.Trim(strings.TrimSpace(mount), "/") + "/sign/" + strings.TrimSpace(role)
	secret, err := c.api.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"csr":         csrPEM,
		"common_name": names[0],
		"alt_names":   strings.Join(names[1:], ","),
		"ttl":         ttl.String(),
		"format":      "pem",
	})
	if err != nil {
		return "", "", fmt.Errorf("vault certificate signing failed")
	}
	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("vault returned no certificate")
	}
	certificate, _ := secret.Data["certificate"].(string)
	if certificate == "" {
		return "", "", fmt.Errorf("vault returned no certificate")
	}
	var chain []string
	if list, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range list {
			if pem, ok := item.(string); ok && pem != "" {
				chain = append(chain, strings.TrimSpace(pem))
			}
		}
	}
	if len(chain) == 0 {
		if issuing, _ := secret.Data["issuing_ca"].(string); issuing != "" {
			chain = append(chain, strings.TrimSpace(issuing))
		}
	}
	if len(chain) == 0 {
		return "", "", fmt.Errorf("vault returned no issuing chain")
	}
	return strings.TrimSpace(certificate) + "\n", strings.Join(chain, "\n") + "\n", nil
}
