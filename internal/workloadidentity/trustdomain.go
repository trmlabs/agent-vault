package workloadidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// TrustDomain is another cluster whose service-account tokens the broker
// accepts, verified locally against the signing keys the cluster publishes.
// The broker's own cluster is the Config's top-level issuer and audience; a
// listed domain is always remote, because the broker cannot read its Pods.
// Only a proxy binding may name a remote domain: a proxy in that cluster
// runs the Pod check there and presents its own token.
type TrustDomain struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// Keys must be "remote". JWKSURL is the HTTPS address of the issuer's
	// published keys (for GKE, the issuer URL followed by /jwks). CAFile, when
	// set, replaces the system roots for that address.
	Keys    string `json:"keys"`
	JWKSURL string `json:"jwksURL"`
	CAFile  string `json:"caFile,omitempty"`
	// MaxTokenLifetimeSeconds bounds accepted tokens (default 3600). A remote
	// token is never checked against a live Pod in the broker's cluster, so
	// its lifetime is the revocation window.
	MaxTokenLifetimeSeconds int64 `json:"maxTokenLifetimeSeconds,omitempty"`
}

// domain is one trust domain at run time: its issuer and audience, its key
// cache and how keys are fetched.
type domain struct {
	name        string // "" for the broker's own cluster
	issuer      string
	audience    string
	maxLifetime int64
	remote      bool
	keys        *signingKeys
	fetch       func(context.Context, any) error
}

// remoteKeys returns a fetch for a published key set: HTTPS only, no
// redirects, no proxy from the environment, a bounded response.
func remoteKeys(td TrustDomain, timeout time.Duration) (func(context.Context, any) error, error) {
	u, err := url.Parse(td.JWKSURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("trust domain jwksURL must be an HTTPS URL")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if td.CAFile != "" {
		pem, err := os.ReadFile(td.CAFile)
		if err != nil {
			return nil, errors.New("cannot read trust domain CA")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid trust domain CA")
		}
		tlsConfig.RootCAs = pool
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxResponseHeaderBytes: 16 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	address := u.String()
	return func(ctx context.Context, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return errors.New("trust domain keys unavailable")
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("trust domain keys unavailable")
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("trust domain keys refused (status %d)", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(b) > 1<<20 || json.Unmarshal(b, out) != nil {
			return errors.New("invalid trust domain keys")
		}
		return nil
	}, nil
}

// buildDomains validates the listed trust domains and returns them after the
// broker's own cluster, which is always first.
func (r *Resolver) buildDomains(c Config) error {
	own := &domain{issuer: c.Issuer, audience: c.Audience, maxLifetime: c.MaxTokenLifetimeSeconds, keys: &signingKeys{}}
	own.fetch = func(ctx context.Context, out any) error {
		return r.api(ctx, http.MethodGet, "/openid/v1/jwks", nil, out)
	}
	r.domains = []*domain{own}
	names := map[string]bool{"": true}
	issuers := map[string]bool{c.Issuer: true}
	for _, td := range c.TrustDomains {
		if !pathSegment(td.Name) || names[td.Name] {
			return errors.New("trust domain names must be unique lowercase DNS-style names")
		}
		u, err := url.Parse(td.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || issuers[td.Issuer] {
			return errors.New("trust domain issuer must be a distinct HTTPS URL")
		}
		if td.Audience == "" || td.Keys != "remote" {
			return errors.New("trust domain needs an audience and remote keys")
		}
		if td.MaxTokenLifetimeSeconds == 0 {
			td.MaxTokenLifetimeSeconds = 3600
		}
		if td.MaxTokenLifetimeSeconds < 600 || td.MaxTokenLifetimeSeconds > 3600 {
			return errors.New("trust domain maxTokenLifetimeSeconds must be between 600 and 3600")
		}
		fetch, err := remoteKeys(td, jwksFetchTimeout)
		if err != nil {
			return err
		}
		names[td.Name], issuers[td.Issuer] = true, true
		r.domains = append(r.domains, &domain{name: td.Name, issuer: td.Issuer, audience: td.Audience,
			maxLifetime: td.MaxTokenLifetimeSeconds, remote: true, keys: &signingKeys{}, fetch: fetch})
	}
	return nil
}

// domainFor returns the trust domain that issued a token, by its exact issuer.
func (r *Resolver) domainFor(issuer string) *domain {
	for _, d := range r.domains {
		if d.issuer == issuer {
			return d
		}
	}
	return nil
}
