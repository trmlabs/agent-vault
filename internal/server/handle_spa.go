package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"time"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.store.DialectName() == "postgres" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.Ping(ctx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "error": "database unreachable"})
			return
		}
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// handleReady is the readiness gate. Unlike handleHealth it also requires a
// listening database broker that holds a fresh cleanup owner row, so a
// restarted broker takes no traffic until it has registered as a new owner.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	unready := func(reason string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unready", "error": reason})
	}
	if s.store.DialectName() == "postgres" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.store.Ping(ctx); err != nil {
			unready("database unreachable")
			return
		}
	}
	if s.pgBroker != nil && !s.pgBroker.IsListening() {
		unready("database broker not listening")
		return
	}
	if cleanup, ok := s.pgLeaseCloser.(interface{ Ready() bool }); ok && !cleanup.Ready() {
		unready("database cleanup ownership not fresh")
		return
	}
	// Attached checks (Vault login, pools, catalog) report by name only.
	for _, c := range s.readiness {
		if !c.check() {
			unready(c.name + " not ready")
			return
		}
	}
	jsonOK(w, map[string]string{"status": "ready"})
}

// handleStatus returns the instance initialization status (public, no auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"initialized":      s.initialized.Load(),
		"needs_first_user": !s.initialized.Load(),
	}

	// Expose base_url only when the operator has explicitly set
	// AGENT_VAULT_ADDR. Auto-derived fallbacks may not be reachable from a
	// remote agent, so we suppress them and let the client show a placeholder.
	if os.Getenv("AGENT_VAULT_ADDR") != "" {
		resp["base_url"] = s.BaseURL()
	}

	// Read all settings in one query instead of two separate reads.
	if settings, err := s.store.GetAllSettings(r.Context()); err == nil {
		if raw, ok := settings[settingAllowedDomains]; ok {
			var domains []string
			if json.Unmarshal([]byte(raw), &domains) == nil && len(domains) > 0 {
				resp["allowed_email_domains"] = domains
			}
		}
		if raw, ok := settings[settingInviteOnly]; ok && raw == "true" {
			resp["invite_only"] = true
		}
	}

	jsonOK(w, resp)
}

// handleSPA serves the SPA index.html for client-side routing.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	indexHTML, err := fs.ReadFile(webDistFS, "webdist/index.html")
	if err != nil {
		http.Error(w, "Frontend not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}
