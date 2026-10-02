package pgproxy

import (
	"strings"
	"testing"
)

func TestNeedsSessionFailsSafe(t *testing.T) {
	for sql, want := range map[string]bool{
		// Transaction-safe.
		"SELECT 1":                    false,
		"select * from t where x = 1": false,
		"BEGIN; SET LOCAL statement_timeout = 5; COMMIT": false,
		"  set local search_path to app":                 false,
		"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE":   false,
		"SELECT pg_advisory_xact_lock(1)":                false,
		"INSERT INTO t VALUES (1) RETURNING id":          false,
		"WITH x AS (SELECT 1) SELECT * FROM x":           false,
		"CREATE TABLE t (id int)":                        false,
		"SELECT 'SET search_path TO x'":                  false, // keyword only inside a string
		"SELECT $tag$; SET search_path TO x$tag$":        false,
		"SELECT \"set\" FROM t":                          false,
		"/* SET x */ SELECT 1":                           false,
		"-- SET x\nSELECT 1":                             false,
		"SELECT $1::int + $2":                            false,
		"DECLARE c CURSOR FOR SELECT 1":                  false,
		"":                                               false,
		// Session state, including hidden by comments or quotes.
		"SET search_path TO app":                               true,
		"/* comment */ SET search_path TO app":                 true,
		"-- leading comment\nset search_path = x":              true,
		"SELECT 1; /* ; */ SET TimeZone = 'UTC'":               true,
		"SELECT 'a'';'; SET x = 1":                             true,
		"SELECT E'\\''; SET x = 1":                             true, // backslash-escaped quote in an E-string
		"set session statement_timeout = 0":                    true,
		"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY": true,
		"RESET ALL":                          true,
		"LISTEN jobs":                        true,
		"UNLISTEN *":                         true,
		"CREATE TEMP TABLE scratch (id int)": true,
		"create temporary table scratch (id int)":      true,
		"CREATE GLOBAL TEMPORARY TABLE x (id int)":     true,
		"SELECT * INTO TEMP scratch FROM t":            true,
		"DECLARE c CURSOR WITH HOLD FOR SELECT 1":      true,
		"PREPARE s AS SELECT 1":                        true,
		"SELECT set_config('search_path', 'x', false)": true,
		"SELECT pg_advisory_lock(42)":                  true,
		"select pg_try_advisory_lock(42)":              true,
		"DISCARD ALL":                                  true,
		"DO $$ BEGIN PERFORM 1; END $$":                true, // unknown effect
		"CALL refresh_things()":                        true,
		"SELECT 'unterminated":                         true,
		"SELECT 1 /* unterminated":                     true,
		"SELECT $q$ never closed":                      true,
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

// A change to the shared login or a database default is refused outright on
// a pooled connection; it would reach every later client of that login.
func TestChangesRole(t *testing.T) {
	for sql, want := range map[string]bool{
		"ALTER ROLE CURRENT_USER SET search_path = evil":       true,
		"alter user current_user password 'x'":                 true,
		"SELECT 1; ALTER GROUP g ADD USER u":                   true,
		"ALTER DATABASE appdb SET search_path = evil":          true,
		"/* c */ Alter\nRole x SET work_mem = '1GB'":           true,
		"ALTER TABLE t ADD COLUMN c int":                       false,
		"SELECT 'ALTER ROLE x'":                                false,
		"SELECT 1 -- ALTER ROLE x":                             false,
		"SELECT $$ unterminated":                               true,
		"ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO r": false,
	} {
		if got := changesRole(sql); got != want {
			t.Errorf("changesRole(%q) = %v, want %v", sql, got, want)
		}
	}
}

// Anything naming the temporary schema pins: a planted temporary domain,
// function or operator would otherwise resolve first for the next client.
func TestNeedsSessionPinsTheTemporarySchema(t *testing.T) {
	for _, sql := range []string{
		"CREATE DOMAIN pg_temp.uuid AS text CHECK (pg_notify('x', VALUE) IS NULL)",
		"CREATE FUNCTION pg_temp.lower(text) RETURNS text AS 'SELECT $1' LANGUAGE sql",
		"CREATE OPERATOR pg_temp.= (LEFTARG = int, RIGHTARG = int, FUNCTION = int4eq)",
		"SELECT * FROM pg_temp_3.t",
	} {
		if !needsSession(sql) {
			t.Errorf("%q did not pin", sql)
		}
	}
	if needsSession("SELECT 1") {
		t.Error("plain select pinned")
	}
}
