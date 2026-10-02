package brokercore

import (
	"strings"
	"testing"
)

func TestStartupValue(t *testing.T) {
	cases := []struct {
		key, value, want string
		ok               bool
	}{
		{"statement_timeout", "30000", "30000", true},
		{"statement_timeout", "2147483647", "2147483647", true},
		{"statement_timeout", "", "", false},
		{"statement_timeout", "0", "", false},
		{"statement_timeout", "-1", "", false},
		{"statement_timeout", "30s", "", false},
		{"statement_timeout", "2147483648", "", false},
		{"statement_timeout", "abc -c role=admin", "", false},
		{"application_name", "PostgreSQL JDBC Driver", "PostgreSQL JDBC Driver", true},
		{"application_name", strings.Repeat("a", 64), "", false},
		{"application_name", "injected\nlog", "", false},
		{"application_name", "客户端", "", false},
		// Encodings as the server matches them, forwarded canonical.
		{"client_encoding", "UTF8", "UTF8", true},
		{"client_encoding", "utf-8", "UTF8", true},
		{"client_encoding", "unicode", "UTF8", true},
		{"client_encoding", "SQL_ASCII", "SQL_ASCII", true},
		{"client_encoding", "latin1", "LATIN1", true},
		{"client_encoding", "ISO-8859-1", "LATIN1", true},
		{"client_encoding", "WIN1252", "WIN1252", true},
		{"client_encoding", "SJIS", "", false}, // client-only: trail bytes can be a backslash
		{"client_encoding", "GBK", "", false},
		{"client_encoding", "BIG5", "", false},
		{"client_encoding", "UTF8'; SET role admin", "", false},
		{"client_encoding", "nonsense", "", false},
		{"DateStyle", "ISO, MDY", "ISO, MDY", true},
		{"TimeZone", "America/Denver", "America/Denver", true},
		{"TimeZone", "UTC\r\nrole=admin", "", false},
		{"extra_float_digits", "3", "3", true},
		{"search_path", "public, analytics", "public, analytics", true},
		{"search_path", "public\x00; drop table t", "", false},
		{"search_path", strings.Repeat("s", 257), "", false},
		{"standard_conforming_strings", "on", "on", true},
		// Fail closed on everything else.
		{"options", "-c statement_timeout=0", "", false},
		{"replication", "database", "", false},
		{"role", "admin", "", false},
		{"datestyle", "ISO", "", false}, // keys are exact, as PostgreSQL reports them
	}
	for _, c := range cases {
		got, ok := StartupValue(c.key, c.value)
		if ok != c.ok || got != c.want {
			t.Errorf("StartupValue(%q, %q) = %q, %v; want %q, %v", c.key, c.value, got, ok, c.want, c.ok)
		}
	}
}

// What drivers send by default passes as a whole.
func TestStartupValueAcceptsDriverDefaults(t *testing.T) {
	drivers := map[string]map[string]string{
		// pgJDBC 42.x
		"jdbc": {"client_encoding": "UTF8", "DateStyle": "ISO", "TimeZone": "America/Denver",
			"extra_float_digits": "2", "application_name": "PostgreSQL JDBC Driver"},
		// libpq (psql, psycopg) with PGTZ and PGDATESTYLE set, under the C locale
		"libpq": {"TimeZone": "Asia/Tokyo", "DateStyle": "ISO, DMY", "client_encoding": "SQL_ASCII", "application_name": "psql"},
		// node-postgres sends nothing extra; asyncpg sends client_encoding
		"asyncpg": {"client_encoding": "utf8"},
	}
	for name, params := range drivers {
		for key, value := range params {
			if _, ok := StartupValue(key, value); !ok {
				t.Errorf("%s default %s=%q refused", name, key, value)
			}
		}
	}
	if len(StartupParameters) != 8 {
		t.Fatalf("accepted set changed: %v", StartupParameters)
	}
	for _, key := range StartupParameters {
		if _, ok := StartupValue(key, ""); key != "statement_timeout" && key != "client_encoding" && !ok {
			t.Errorf("%s refused an empty value", key)
		}
	}
}
