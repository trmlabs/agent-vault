package httpcatalog

import (
	"strings"
	"testing"
)

// A pool at the external ceiling may exist, but no entry may grant it.
func TestExternalPoolHoldsNoEntries(t *testing.T) {
	pools := `{"name":"p","namespace":"n","serviceAccount":"s"},{"name":"orion","namespace":"o","serviceAccount":"s","ceiling":"external"}`
	if _, err := Parse([]byte(`{"pools":[` + pools + `],"entries":[{` + entryBase + `}]}`)); err != nil {
		t.Fatalf("external pool with no entries refused: %v", err)
	}
	for name, grant := range map[string]string{
		"T0 entry":   `"pools":["p","orion"]`,
		"only grant": `"pools":["orion"]`,
	} {
		entry := strings.Replace(entryBase, `"pools":["p"]`, grant, 1)
		if _, err := Parse([]byte(`{"pools":[` + pools + `],"entries":[{` + entry + `}]}`)); err == nil {
			t.Errorf("%s granted to an external pool", name)
		}
	}
	for name, pool := range map[string]string{
		"with a person":   `{"name":"orion","namespace":"o","serviceAccount":"s","ceiling":"external","identity":"claude-session","ccpoolID":"ccpool_abc"}`,
		"with a workload": `{"name":"orion","namespace":"o","serviceAccount":"s","ceiling":"external","identity":"workload"}`,
		"unknown ceiling": `{"name":"orion","namespace":"o","serviceAccount":"s","ceiling":"T-1"}`,
	} {
		if _, err := Parse([]byte(`{"pools":[{"name":"p","namespace":"n","serviceAccount":"s"},` + pool + `],"entries":[{` + entryBase + `}]}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
