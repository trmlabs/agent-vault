package cmd

import (
	"bytes"
	"strings"
	"testing"
)

const exampleCatalogYAML = `pools:
  - {name: cursor, namespace: cursor-agents, serviceAccount: cursor-worker}
entries:
  - name: b2bcore
    kind: postgres
    host: p.abc.db.postgresbridge.com
    pools: [cursor]
    postgres: {database: core, mount: database, role: staging.us.crunchy.core-readonly}
  - name: serpapi
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [cursor]
`

func TestBrokerCatalogValidate(t *testing.T) {
	var out bytes.Buffer
	if err := validateBrokerCatalog([]byte(exampleCatalogYAML), []string{".postgresbridge.com", "serpapi.com"}, true, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "valid: pools=1 postgres=1 http=1\n" {
		t.Fatalf("summary %q", got)
	}
	for name, tc := range map[string]struct {
		doc      string
		suffixes []string
		pools    bool
	}{
		"wildcard host":   {strings.Replace(exampleCatalogYAML, "host: serpapi.com", "host: '*.serpapi.com'", 1), nil, false},
		"undefined pool":  {strings.Replace(exampleCatalogYAML, "pools: [cursor]\n    postgres", "pools: [ci]\n    postgres", 1), nil, false},
		"outside domains": {exampleCatalogYAML, []string{".postgresbridge.com"}, false},
		"pools required":  {strings.Replace(exampleCatalogYAML, "pools:\n  - {name: cursor, namespace: cursor-agents, serviceAccount: cursor-worker}\n", "", 1), nil, true},
		"unknown field":   {exampleCatalogYAML + "    insecure: true\n", nil, false},
		"not yaml":        {"entries: [", nil, false},
	} {
		if err := validateBrokerCatalog([]byte(tc.doc), tc.suffixes, tc.pools, &bytes.Buffer{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
