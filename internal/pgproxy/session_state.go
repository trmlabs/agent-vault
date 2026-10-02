package pgproxy

import (
	"strings"
)

// needsSession reports whether SQL text might leave session state on a
// server connection, so the client must keep that connection for the rest of
// its session (session mode) instead of returning it after each transaction.
//
// It fails safe: the text is lexed (comments, quoted strings, E-strings,
// dollar quotes and quoted identifiers), and every statement must start with
// a keyword known to leave no session state, and call no function known to
// set it. Anything else pins, including unterminated text. The check-in
// verification in verifyClean is the backstop for state this misses, such as
// a function that calls set_config internally.
func needsSession(sql string) bool {
	statements, ok := splitStatements(sql)
	if !ok {
		return true
	}
	for _, statement := range statements {
		if !transactionSafe(statement) {
			return true
		}
	}
	return false
}

// splitStatements returns each statement with comments removed and string
// contents blanked, so keywords inside them are not seen. ok is false when
// the text ends inside a comment, string or quoted identifier.
func splitStatements(sql string) ([]string, bool) {
	var statements []string
	var cur strings.Builder
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
			cur.WriteByte(' ')
		case c == '/' && i+1 < n && sql[i+1] == '*':
			depth := 0
		comment:
			for i < n {
				switch {
				case i+1 < n && sql[i] == '/' && sql[i+1] == '*':
					depth++
					i += 2
				case i+1 < n && sql[i] == '*' && sql[i+1] == '/':
					depth--
					i += 2
					if depth == 0 {
						break comment
					}
				default:
					i++
				}
			}
			if depth != 0 {
				return nil, false
			}
			cur.WriteByte(' ')
		case c == '\'':
			// An E-string (E'...' or e'...') honors backslash escapes.
			escapes := i > 0 && (sql[i-1] == 'e' || sql[i-1] == 'E') && (i < 2 || !identChar(sql[i-2]))
			i++
			closed := false
			for i < n {
				if escapes && sql[i] == '\\' {
					i += 2
					continue
				}
				if sql[i] == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, false
			}
			cur.WriteString("''")
		case c == '"':
			i++
			closed := false
			for i < n {
				if sql[i] == '"' {
					if i+1 < n && sql[i+1] == '"' {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, false
			}
			cur.WriteString(`"x"`)
		case c == '$' && (i == 0 || !identChar(sql[i-1])):
			end := i + 1
			for end < n && identChar(sql[end]) && (end != i+1 || sql[end] < '0' || sql[end] > '9') {
				end++
			}
			if end >= n || sql[end] != '$' {
				cur.WriteByte(c) // a positional parameter such as $1
				i++
				continue
			}
			tag := sql[i : end+1]
			closing := strings.Index(sql[end+1:], tag)
			if closing < 0 {
				return nil, false
			}
			i = end + 1 + closing + len(tag)
			cur.WriteString("''")
		case c == ';':
			statements = append(statements, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	return append(statements, cur.String()), true
}

// changesRole reports whether SQL text alters a role or a database's
// defaults. On a pooled connection that would persist for every later client
// of the shared login (ALTER ROLE CURRENT_USER SET search_path survives
// DISCARD ALL) or lock them all out (a new password), so it is refused.
// Unterminated text is refused too.
func changesRole(sql string) bool {
	statements, ok := splitStatements(sql)
	if !ok {
		return true
	}
	for _, statement := range statements {
		words := strings.FieldsFunc(strings.ToLower(statement), func(r rune) bool { return r > 0x7f || !identChar(byte(r)) })
		if len(words) >= 2 && words[0] == "alter" && (words[1] == "role" || words[1] == "user" || words[1] == "group" || words[1] == "database") {
			return true
		}
	}
	return false
}

func identChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// sessionFunctions set state that outlives the transaction. The transaction
// variants of advisory locks (pg_advisory_xact_lock) are not listed.
var sessionFunctions = []string{"set_config", "pg_advisory_lock", "pg_try_advisory_lock", "pg_advisory_unlock", "dblink_connect", "lo_open"}

func transactionSafe(statement string) bool {
	lower := strings.ToLower(statement)
	words := strings.FieldsFunc(lower, func(r rune) bool { return r > 0x7f || !identChar(byte(r)) })
	if len(words) == 0 {
		return true // empty statement
	}
	for _, f := range sessionFunctions {
		for _, w := range words {
			if strings.HasPrefix(w, f) {
				return false
			}
		}
	}
	for i, w := range words {
		// SELECT ... INTO TEMP creates a temporary table.
		if w == "into" && i+1 < len(words) && (words[i+1] == "temp" || words[i+1] == "temporary") {
			return false
		}
		// Anything naming the temporary schema (CREATE DOMAIN pg_temp.uuid)
		// can plant an object later clients would resolve first.
		if strings.HasPrefix(w, "pg_temp") {
			return false
		}
	}
	switch words[0] {
	case "select", "insert", "update", "delete", "merge", "with", "values", "table", "begin", "start", "commit", "end",
		"rollback", "abort", "savepoint", "release", "show", "explain", "copy", "lock", "notify", "fetch", "move", "close",
		"alter", "drop", "comment", "grant", "revoke", "truncate", "analyze", "refresh", "reindex", "cluster", "vacuum":
		return true
	case "declare":
		return !strings.Contains(" "+strings.Join(words, " ")+" ", " with hold ")
	case "create":
		for _, w := range words[1:min(len(words), 5)] {
			if w == "temp" || w == "temporary" {
				return false
			}
		}
		return true
	case "set":
		// SET LOCAL, SET TRANSACTION and SET CONSTRAINTS end with the
		// transaction; every other SET persists.
		return len(words) > 1 && (words[1] == "local" || words[1] == "transaction" || words[1] == "constraints")
	}
	return false // unknown or session-scoped: pin
}
