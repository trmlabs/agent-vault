package workloadidentity

import (
	"context"
	"testing"
)

func observerFor(t *testing.T, f *fixture) *Observer {
	t.Helper()
	config := f.r.config
	config.Audience = "cleanup-observer"
	f.c.Audience = []string{"cleanup-observer"}
	f.review.Status.Audiences = []string{"cleanup-observer"}
	config.Bindings = append([]Binding(nil), config.Bindings...)
	for i := range config.Bindings {
		config.Bindings[i].AgentID = ""
		config.Bindings[i].VaultID = ""
	}
	observer, err := NewObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	return observer
}

func TestObserverHasNoProxyGrant(t *testing.T) {
	f := setup(t)
	if _, err := NewObserver(f.r.config); err == nil {
		t.Fatal("proxy grant accepted as observer policy")
	}
	observer := observerFor(t, f)
	f.s.role = "proxy"
	if _, err := observer.Authorize(context.Background(), token(f.c)); err != nil {
		t.Fatal(err)
	}
	if observer.resolver.store != nil {
		t.Fatal("observer has store authority")
	}
	if _, err := f.r.ResolveForProxy(context.Background(), token(f.c), ""); err == nil {
		t.Fatal("observer admitted as proxy")
	}
	if f.calls.Load() != 2 {
		t.Fatal("live token and Pod verification required")
	}
}

func TestObserverLiveIdentityDenials(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"wrong audience":     func(f *fixture) { f.c.Audience = []string{"other"} },
		"wrong account":      func(f *fixture) { f.c.Kubernetes.ServiceAccount.Name = "other" },
		"review unavailable": func(f *fixture) { f.reviewStatus = 503 },
		"deleted Pod":        func(f *fixture) { f.podStatus = 404 },
		"replacement Pod":    func(f *fixture) { f.pod["metadata"].(map[string]any)["uid"] = "replacement" },
		"terminating Pod":    func(f *fixture) { f.pod["metadata"].(map[string]any)["deletionTimestamp"] = "2026-01-01T00:00:00Z" },
		"expired":            func(f *fixture) { f.c.Expires = f.c.Issued },
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			o := observerFor(t, f)
			if _, err := o.Authorize(context.Background(), token(f.c)); err != nil {
				t.Fatal(err)
			}
			change(f)
			if _, err := o.Authorize(context.Background(), token(f.c)); err == nil {
				t.Fatal("invalid observer admitted")
			}
		})
	}
}

func TestObserverConfigurationSeparation(t *testing.T) {
	proxy := Config{Audience: "proxy", Bindings: []Binding{{Namespace: "trusted", ServiceAccount: "relay"}}}
	observer := Config{Audience: "observer", Bindings: []Binding{{Namespace: "trusted", ServiceAccount: "manager"}}}
	if err := ValidateObserverSeparation(observer, proxy); err != nil {
		t.Fatal(err)
	}
	observer.Audience = "proxy"
	if err := ValidateObserverSeparation(observer, proxy); err == nil {
		t.Fatal("shared audience accepted")
	}
	observer.Audience = "observer"
	observer.Bindings[0].ServiceAccount = "relay"
	if err := ValidateObserverSeparation(observer, proxy); err == nil {
		t.Fatal("shared account accepted")
	}
}

func TestObserverListAgentsIsPerBindingAndObserverOnly(t *testing.T) {
	f := setup(t)
	plain := observerFor(t, f)
	if access, err := plain.Authorize(context.Background(), token(f.c)); err != nil || access.ListAgents {
		t.Fatalf("list access without capability: %+v %v", access, err)
	}
	config := plain.resolver.config
	config.Bindings = append([]Binding(nil), config.Bindings...)
	config.Bindings[0].ListAgents = true
	controller, err := NewObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	if access, err := controller.Authorize(context.Background(), token(f.c)); err != nil || !access.ListAgents {
		t.Fatalf("controller capability lost: %+v %v", access, err)
	}
	f.podStatus = 404
	if access, err := controller.Authorize(context.Background(), token(f.c)); err == nil || access.ListAgents {
		t.Fatal("capability returned for a denied proof")
	}
	proxy := f.r.config
	proxy.Bindings = append([]Binding(nil), proxy.Bindings...)
	proxy.Bindings[0].ListAgents = true
	if _, err := New(proxy, f.s); err == nil {
		t.Fatal("observer access accepted in proxy policy")
	}
}
