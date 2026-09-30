package workloadidentity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

func TestObserverOverVerifiedTLS(t *testing.T) {
	f := setup(t)
	o := observerFor(t, f)
	h, err := runtimestatus.New(o.Authorize, func(context.Context) (runtimestatus.Observation, error) {
		return runtimestatus.Observation{Initialized: true, Healthy: true, Consistent: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	request := func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequest("GET", srv.URL+"/v1/runtime/cleanup-status", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token(f.c))
		return client.Do(req)
	}
	response, err := request(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	err = json.NewDecoder(response.Body).Decode(&body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || body["status"] != "ready" || len(body) != 6 {
		t.Fatalf("unexpected sanitized response: %v", body)
	}
	if f.calls.Load() != 2 {
		t.Fatal("missing TokenReview and live Pod read")
	}
	if unexpected, err := request(http.DefaultClient); err == nil {
		unexpected.Body.Close()
		t.Fatal("untrusted certificate accepted")
	}
	f.podStatus = 404
	response, err = request(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("deleted observer Pod remained authorized")
	}
}
