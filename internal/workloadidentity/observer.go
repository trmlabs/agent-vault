package workloadidentity

import (
	"context"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// Observer verifies live Kubernetes identity for a read-only status surface.
// It deliberately has no SessionResolver methods and receives no store or
// destination grants. Use a separate audience and dedicated service account.
type Observer struct{ resolver *Resolver }

// NewObserver accepts operator-owned trust and workload bindings. AgentID and
// VaultID must be empty: observer access must not implicitly authorize proxying.
func NewObserver(c Config) (*Observer, error) {
	r, err := newResolver(c, nil, true)
	if err != nil {
		return nil, err
	}
	return &Observer{resolver: r}, nil
}

// Authorize repeats TokenReview and live Pod checks for every observation.
func (o *Observer) Authorize(ctx context.Context, proof string) error {
	if o == nil || o.resolver == nil {
		return brokercore.ErrInvalidSession
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(o.resolver.config.TimeoutSeconds)*time.Second)
	defer cancel()
	_, c, err := o.resolver.verifyProof(ctx, proof)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || c.Expires <= o.resolver.now().Unix() {
		return brokercore.ErrInvalidSession
	}
	return nil
}

// ValidateObserverSeparation must run before mounting the observer route beside
// a proxy. Separate audiences alone are not sufficient when the same service
// account can request both proofs, so the account policies must also differ.
func ValidateObserverSeparation(observer, proxy Config) error {
	if observer.Audience == "" || observer.Audience == proxy.Audience {
		return fmt.Errorf("cleanup observer requires a separate audience")
	}
	for _, observed := range observer.Bindings {
		for _, admitted := range proxy.Bindings {
			if observed.Namespace == admitted.Namespace && observed.ServiceAccount == admitted.ServiceAccount {
				return fmt.Errorf("cleanup observer must not share a proxy service account")
			}
		}
	}
	return nil
}
