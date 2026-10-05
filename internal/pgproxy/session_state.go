package pgproxy

import (
	"regexp"
	"slices"
	"strings"

	"github.com/Infisical/agent-vault/internal/brokercore"
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
	statements, _, ok := splitStatementsRaw(sql)
	return statements, ok
}

// splitStatementsRaw is splitStatements that also returns each statement's
// original text, for the few checks that need a literal's value.
func splitStatementsRaw(sql string) ([]string, []string, bool) {
	var statements, raw []string
	start := 0
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
				return nil, nil, false
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
				return nil, nil, false
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
				return nil, nil, false
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
				return nil, nil, false
			}
			i = end + 1 + closing + len(tag)
			cur.WriteString("''")
		case c == ';':
			statements = append(statements, cur.String())
			raw = append(raw, sql[start:i])
			cur.Reset()
			i++
			start = i
		default:
			cur.WriteByte(c)
			i++
		}
	}
	return append(statements, cur.String()), append(raw, sql[start:]), true
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

// createsTemporary reports whether SQL text on a read-only login could
// create a temporary table, view, sequence or other object. PUBLIC holds the
// TEMP privilege by default, so the broker refuses these itself rather than
// rely on a database change. It fails closed: besides CREATE ... TEMP and
// SELECT ... INTO TEMP, it refuses what could create one unseen (pg_temp in
// any text, Unicode escapes that could spell it, DO blocks and set_config
// with computed text, UPDATE pg_settings), and settings that would make the
// server read later text differently from the broker's lexer. Unterminated
// text is refused too.
func createsTemporary(sql string) bool {
	lower := strings.ToLower(sql)
	if strings.Contains(lower, "pg_temp") || strings.Contains(lower, "u&'") || strings.Contains(lower, `u&"`) {
		return true
	}
	statements, ok := splitStatements(sql)
	if !ok {
		return true
	}
	for _, statement := range statements {
		words := strings.FieldsFunc(strings.ToLower(statement), func(r rune) bool { return r > 0x7f || !identChar(byte(r)) })
		if len(words) == 0 {
			continue
		}
		if words[0] == "do" {
			return true
		}
		var update, settings, searchPath bool
		for i, w := range words {
			switch {
			case w == "temp" || w == "temporary":
				// CREATE [OR REPLACE] [GLOBAL | LOCAL] TEMP, and
				// SELECT ... INTO [GLOBAL | LOCAL] TEMP.
				for _, before := range words[max(0, i-3):i] {
					if before == "create" || before == "into" {
						return true
					}
				}
			case strings.HasPrefix(w, "set_config"):
				return true
			case w == "update":
				update = true
			case w == "pg_settings":
				settings = true
			case w == "search_path" || words[0] == "set" && i <= 2 && w == "schema":
				searchPath = true
			}
		}
		// UPDATE pg_settings calls set_config.
		if update && settings {
			return true
		}
		// An escape string could spell pg_temp in a search path.
		if searchPath && strings.ContainsRune(sql, '\\') {
			return true
		}
	}
	return false
}

// lexerSet matches one plain SET of a setting that decides how the server
// reads later text, such as Sequelize's SET standard_conforming_strings=on.
var lexerSet = regexp.MustCompile(`(?i)^\s*set\s+(?:session\s+)?(standard_conforming_strings|client_encoding|names)\s*(?:=|\s+to\s+|\s)\s*'?([A-Za-z0-9_-]+)'?\s*$`)

// lexerSetting reports whether a statement sets standard_conforming_strings,
// client_encoding or NAMES, and whether it is the one safe form: a lone SET
// to on, or to UTF8. Any other value could make the server read later text
// differently from the broker's lexer, hiding a statement inside a literal.
func lexerSetting(words []string, raw string) (isSet, safe bool) {
	if len(words) < 2 || words[0] != "set" {
		return false, false
	}
	for _, w := range words[1:min(len(words), 3)] {
		if w == "standard_conforming_strings" || w == "client_encoding" || w == "names" {
			isSet = true
		}
	}
	if !isSet {
		return false, false
	}
	m := lexerSet.FindStringSubmatch(raw)
	if m == nil {
		return true, false
	}
	value := strings.ToLower(m[2])
	if strings.EqualFold(m[1], "standard_conforming_strings") {
		return true, value == "on"
	}
	return true, value == "utf8"
}

// changesLexer reports whether SQL text changes how the server reads later
// text, which no pooled session may do: the only exception is the safe form
// (standard_conforming_strings on, client_encoding UTF8) before the session's
// first other statement, as drivers send on connect. started reports whether
// the session has run another statement; next is its value after this text.
func changesLexer(sql string, started bool) (refuse, next bool) {
	statements, raw, ok := splitStatementsRaw(sql)
	if !ok {
		return false, true // unterminated: the server refuses it
	}
	for i, statement := range statements {
		words := sqlWords(statement)
		if len(words) == 0 {
			continue
		}
		isSet, safe := lexerSetting(words, raw[i])
		if isSet && (!safe || started) {
			return true, true
		}
		if !isSet {
			started = true
		}
	}
	return false, started
}

// unsafeLexerParameter reports a server-reported setting, from ParameterStatus,
// that would make the server read text differently from the broker's lexer.
// It is the backstop for a change the classifier did not see.
func unsafeLexerParameter(name, value string) bool {
	if name != "standard_conforming_strings" && name != "client_encoding" {
		return false
	}
	_, ok := brokercore.StartupValue(name, value)
	return !ok
}

func sqlWords(statement string) []string {
	return strings.FieldsFunc(strings.ToLower(statement), func(r rune) bool { return r > 0x7f || !identChar(byte(r)) })
}

// readOnlyAllowed reports whether SQL text may run on a read-only login. It is
// an allowlist: every statement must be a read (SELECT, VALUES, TABLE, a WITH
// or EXPLAIN of one, SHOW, a cursor over one), transaction control that keeps
// the transaction read-only, or a SET or RESET of a listed setting. Behind it,
// text naming pg_temp, set_config or pg_settings in any spelling or quoting,
// or using Unicode escapes, is refused, as is anything createsTemporary
// refuses. The login's transactions are also read-only on the database side
// (default_transaction_read_only), which the allowlist keeps on.
func readOnlyAllowed(sql string) bool {
	lower := strings.ToLower(sql)
	for _, banned := range []string{"pg_temp", "set_config", "pg_settings", "u&'", `u&"`} {
		if strings.Contains(lower, banned) {
			return false
		}
	}
	if createsTemporary(sql) {
		return false
	}
	statements, raw, ok := splitStatementsRaw(sql)
	if !ok {
		return false
	}
	for i, statement := range statements {
		if words := sqlWords(statement); len(words) > 0 && !readOnlyStatement(words, raw[i]) {
			return false
		}
	}
	return true
}

func readOnlyStatement(words []string, raw string) bool {
	switch words[0] {
	case "select", "values", "table", "with", "declare":
		return readQuery(words)
	case "explain":
		// EXPLAIN [ANALYZE] runs or plans only a read.
		for i, w := range words[1:] {
			switch w {
			case "select", "values", "table", "with":
				return readQuery(words[i+1:])
			case "insert", "update", "delete", "merge", "create", "execute", "declare":
				return false
			}
		}
		return false
	case "show", "commit", "end", "rollback", "abort", "savepoint", "release", "fetch", "move", "close", "deallocate":
		return true
	case "begin", "start":
		return !slices.Contains(words, "write")
	case "set":
		return readOnlySet(words, raw)
	case "reset":
		return len(words) == 2 && readOnlySettings[words[1]]
	}
	return false
}

// readQuery reports whether a query only reads: it names no data-modifying
// or object-creating keyword anywhere, including in a WITH clause, a cursor,
// SELECT ... INTO, or a row lock (FOR UPDATE).
func readQuery(words []string) bool {
	for _, w := range words {
		switch w {
		case "insert", "update", "delete", "merge", "into", "create", "drop", "alter", "truncate", "grant", "revoke",
			"copy", "call", "do", "lock", "listen", "notify", "refresh", "vacuum", "cluster", "reindex", "import", "security":
			return false
		}
	}
	return true
}

// readOnlySettings are what a read-only login may SET or RESET, sized from
// what drivers and the internal API send (Sequelize: client_min_messages and
// TIME ZONE on connect; node-postgres: startup parameters only).
var readOnlySettings = map[string]bool{
	"search_path": true, "schema": true, "statement_timeout": true, "lock_timeout": true, "idle_in_transaction_session_timeout": true,
	"application_name": true, "timezone": true, "datestyle": true, "intervalstyle": true, "extra_float_digits": true,
	"client_min_messages": true, "bytea_output": true, "standard_conforming_strings": true, "client_encoding": true, "names": true,
}

func readOnlySet(words []string, raw string) bool {
	if slices.Contains(words, "write") {
		return false // SET TRANSACTION or SESSION CHARACTERISTICS ... READ WRITE
	}
	name := words[1:]
	if len(name) > 0 && (name[0] == "session" || name[0] == "local") {
		name = name[1:]
	}
	if len(name) == 0 {
		return false
	}
	switch {
	case name[0] == "transaction", name[0] == "characteristics", name[0] == "constraints":
		return true
	case name[0] == "time" && len(name) > 1 && name[1] == "zone":
		return true
	case name[0] == "search_path" || name[0] == "schema":
		// An escape string could spell pg_temp.
		return !strings.ContainsRune(raw, '\\')
	}
	return readOnlySettings[name[0]]
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
