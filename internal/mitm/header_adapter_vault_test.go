package mitm

import (
	"context"

	vaultapi "github.com/hashicorp/vault/api"
)

type staticVault string

func (v staticVault) ReadWithDataWithContext(context.Context, string, map[string][]string) (*vaultapi.Secret, error) {
	return &vaultapi.Secret{Data: map[string]interface{}{"data": map[string]interface{}{"key": string(v)}, "metadata": map[string]interface{}{"version": float64(1)}}}, nil
}
