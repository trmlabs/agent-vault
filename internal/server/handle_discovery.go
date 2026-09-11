package server

import (
	"encoding/json"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
)

type discoverService struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

// discoverDatabase is one managed PostgreSQL-broker database an agent may select
// by Name. It carries the selector and upstream host only — never the Vault
// mount/role or any credential.
type discoverDatabase struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

type discoverResponse struct {
	Vault                string             `json:"vault"`
	Services             []discoverService  `json:"services"`
	Databases            []discoverDatabase `json:"databases"`
	AvailableCredentials []string           `json:"available_credentials"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Require scoped session or agent token with X-Vault.
	sess := sessionFromContext(ctx)
	if sess == nil {
		proxyError(w, http.StatusForbidden, "forbidden", "Discovery requires a vault-scoped session")
		return
	}

	ns, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}

	credentialKeys := s.listCredentialKeys(ctx, ns.ID)

	// Managed PostgreSQL-broker databases the agent may select by name.
	databases := []discoverDatabase{}
	if dbRows, err := s.store.ListDatabaseServices(ctx, ns.ID); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to list databases")
		return
	} else {
		for _, row := range dbRows {
			databases = append(databases, discoverDatabase{Name: row.Name, Host: row.Upstream})
		}
	}

	// Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil || brokerCfg == nil {
		// No config means no services — return empty list.
		jsonOK(w, discoverResponse{
			Vault:                ns.Name,
			Services:             []discoverService{},
			Databases:            databases,
			AvailableCredentials: credentialKeys,
		})
		return
	}

	var svcList []broker.Service
	if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
		return
	}
	// MarshalJSON persists Host in joined form; re-split so
	// MatcherPattern emits the same shape regardless of storage form.
	for i := range svcList {
		svcList[i].Host, svcList[i].Path, svcList[i].Port = broker.SplitInlineHost(svcList[i].Host, svcList[i].Path)
	}
	// Heal legacy unnamed entries on the agent-facing read path too —
	// agents identify services by Name (per skill_cli.md) and a blank
	// Name in this response makes the service un-addressable.
	broker.AssignSlugNames(svcList)

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Name: svc.Name,
			Host: svc.MatcherPattern(),
		}
	}

	jsonOK(w, discoverResponse{
		Vault:                ns.Name,
		Services:             services,
		Databases:            databases,
		AvailableCredentials: credentialKeys,
	})
}
