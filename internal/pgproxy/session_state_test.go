package pgproxy

import (
	"strings"
	"testing"
)

func TestNeedsSession(t *testing.T) {
	for sql, want := range map[string]bool{
		"SELECT 1":                    false,
		"select * from t where x = 1": false,
		"BEGIN; SET LOCAL statement_timeout = 5; COMMIT": false,
		"  set local search_path to app":                 false,
		"SELECT pg_advisory_xact_lock(1)":                false,
		"INSERT INTO t VALUES (1)":                       false,
		"SET search_path TO app":                         true,
		"set session statement_timeout = 0":              true,
		"select 1; SET TimeZone = 'UTC'":                 true,
		"RESET ALL":                                      true,
		"LISTEN jobs":                                    true,
		"CREATE TEMP TABLE scratch (id int)":             true,
		"create temporary table scratch (id int)":        true,
		"CREATE GLOBAL TEMPORARY TABLE x (id int)":       true,
		"DECLARE c CURSOR WITH HOLD FOR SELECT 1":        true,
		"PREPARE s AS SELECT 1":                          true,
		"SELECT set_config('search_path', 'x', false)":   true,
		"SELECT pg_advisory_lock(42)":                    true,
		"select pg_try_advisory_lock(42)":                true,
		"DISCARD ALL":                                    true,
	} {
		if got := needsSession(sql); got != want {
			t.Errorf("needsSession(%q) = %v, want %v", sql, got, want)
		}
	}
}

func TestDollarQuoteClosesOnlyAtTheEnd(t *testing.T) {
	for _, value := range []string{"Asia/Tokyo", `"$user", public`, "x$gh$y", "ends$gh", "$gh0$", "it's"} {
		quoted := dollarQuote(value)
		tagEnd := strings.Index(quoted[1:], "$") + 2
		tag := quoted[:tagEnd]
		if !strings.HasSuffix(quoted, tag) || strings.Index(quoted[len(tag):], tag) != len(value) {
			t.Errorf("dollarQuote(%q) = %q closes early", value, quoted)
		}
	}
}
