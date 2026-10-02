package pgproxy

import (
	"strings"
	"unicode"
)

// needsSession reports whether SQL text may leave session state on a server
// connection, so the client must keep that connection for the rest of its
// session (session mode) instead of returning it after each transaction.
//
// It is a conservative scan, not a parser: comments and literals are not
// understood, so a keyword inside a string can pin a session unnecessarily.
// That costs a session-mode slot, never correctness. A statement that sets
// session state through a construct not listed here (for example a function
// that calls set_config internally) is the residual risk; such functions must
// not be granted to pooled roles.
func needsSession(sql string) bool {
	lower := strings.ToLower(sql)
	for _, statement := range strings.Split(lower, ";") {
		words := strings.FieldsFunc(statement, func(r rune) bool { return unicode.IsSpace(r) || r == '(' })
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "set":
			// SET LOCAL lasts until the transaction ends; anything else persists.
			if len(words) < 2 || words[1] != "local" {
				return true
			}
		case "reset", "listen", "prepare", "load", "discard":
			return true
		case "create":
			for _, w := range words[1:min(len(words), 4)] {
				if w == "temp" || w == "temporary" {
					return true
				}
			}
		case "declare":
			if strings.Contains(statement, " with hold") {
				return true
			}
		}
	}
	for _, function := range []string{"set_config", "pg_advisory_lock", "pg_advisory_lock_shared", "pg_try_advisory_lock",
		"pg_try_advisory_lock_shared", "dblink_connect"} {
		if strings.Contains(lower, function) {
			// The transaction-scoped variants (pg_advisory_xact_lock) do not
			// match these names; set_config with is_local true still pins,
			// which is safe.
			return true
		}
	}
	return false
}
