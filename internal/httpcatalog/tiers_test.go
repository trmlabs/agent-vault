package httpcatalog

import (
	"fmt"
	"strings"
	"testing"
)

const group = "11111111-1111-1111-1111-111111111111"

func catalogWith(pool, entry string) string {
	return `{"pools":[` + pool + `],"entries":[` + entry + `]}`
}

const entryBase = `"name":"vendor","host":"api.vendor.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["p"]`

func TestTierGrantRules(t *testing.T) {
	cases := map[string]struct {
		pool, tier string
		ok         bool
	}{
		"T0 to Cursor pool":          {`{"name":"p","namespace":"n","serviceAccount":"s"}`, ``, true},
		"T1 to Cursor pool":          {`{"name":"p","namespace":"n","serviceAccount":"s"}`, `,"tier":"T1","requires":["` + group + `"]`, false},
		"T1 to claude pool":          {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}`, `,"tier":"T1","requires":["` + group + `"]`, true},
		"T2 over a T1 ceiling":       {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}`, `,"tier":"T2","requires":["` + group + `"]`, false},
		"T1 to entitled workload":    {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"workload","ceiling":"T1","entitlements":["` + group + `"]}`, `,"tier":"T1","requires":["` + group + `"]`, true},
		"T1 to unentitled workload":  {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"workload","ceiling":"T1"}`, `,"tier":"T1","requires":["` + group + `"]`, false},
		"T1 without groups":          {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}`, `,"tier":"T1"`, false},
		"T0 with groups":             {`{"name":"p","namespace":"n","serviceAccount":"s"}`, `,"requires":["` + group + `"]`, false},
		"group not an object ID":     {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}`, `,"tier":"T1","requires":["admins"]`, false},
		"claude pool without ccpool": {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"claude-session","ceiling":"T1"}`, ``, false},
		"workload with a T2 ceiling": {`{"name":"p","namespace":"n","serviceAccount":"s","identity":"workload","ceiling":"T2"}`, ``, false},
		"Cursor pool with a ceiling": {`{"name":"p","namespace":"n","serviceAccount":"s","ceiling":"T1"}`, ``, false},
	}
	for name, c := range cases {
		_, err := Parse([]byte(catalogWith(c.pool, "{"+entryBase+c.tier+"}")))
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if _, err := Parse([]byte(`{"entries":[{` + strings.Replace(entryBase, `"pools":["p"]`, `"pools":["any"]`, 1) + `,"tier":"T1","requires":["` + group + `"]}]}`)); err == nil {
		t.Error("a T1 entry was accepted without defined pools")
	}
}

func TestRequiresIsCapped(t *testing.T) {
	var groups []string
	for i := 0; i < 9; i++ {
		groups = append(groups, fmt.Sprintf("%08d-0000-0000-0000-000000000000", i))
	}
	e := Entry{Tier: "T1", Requires: groups}
	if err := e.validateTier(); err == nil {
		t.Fatal("an entry requiring 9 groups was accepted")
	}
	e.Requires = groups[:8]
	if err := e.validateTier(); err != nil {
		t.Fatalf("8 groups refused: %v", err)
	}
}
