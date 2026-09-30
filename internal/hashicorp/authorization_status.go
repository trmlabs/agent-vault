package hashicorp

import (
	"context"
	"fmt"
)

// CheckAuthorization verifies the current parent login without returning its
// token metadata. It does not establish each destination role's permissions.
func (c *Client) CheckAuthorization(ctx context.Context) error {
	if c == nil || c.api == nil {
		return fmt.Errorf("vault authorization unavailable")
	}
	secret, err := c.api.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || secret == nil || secret.Data == nil {
		return fmt.Errorf("vault authorization unavailable")
	}
	return nil
}
