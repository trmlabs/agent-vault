package hashicorp

import vaultapi "github.com/hashicorp/vault/api"

// Logical exposes the broker's authenticated Vault client to the signed audit
// chain, which reads its HMAC key and signs checkpoints with it.
func (c *Client) Logical() *vaultapi.Logical { return c.api.Logical() }
