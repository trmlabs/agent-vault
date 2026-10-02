package brokercore

import (
	"strconv"
	"strings"
)

// StartupParameters are the PostgreSQL startup parameters a client may send
// through Gatehouse, besides user and database. They are what drivers send by
// default (libpq from PGTZ, PGDATESTYLE and the locale; JDBC always sends
// client_encoding, DateStyle, TimeZone and extra_float_digits) and what the
// pooled broker re-applies per connection. Everything else fails closed, in
// particular "options" (backend command-line arguments, which set arbitrary
// settings) and "replication".
var StartupParameters = []string{"application_name", "client_encoding", "DateStyle", "extra_float_digits",
	"search_path", "standard_conforming_strings", "statement_timeout", "TimeZone"}

// StartupValue reports whether a client may send key with value at startup,
// and returns the value to forward. The relay and the broker share it, so the
// two can never disagree.
//
// A startup parameter overrides a role-level ALTER ROLE ... SET, so values
// are bounded, not only keys:
//   - statement_timeout: 1 to 10 ASCII digits parsing to 1..2147483647,
//     refusing 0 (no timeout), units and embedded options.
//   - application_name: at most 63 bytes of printable ASCII.
//   - client_encoding: a name from PostgreSQL's fixed list of server
//     encodings, matched as the server does (case and punctuation ignored,
//     with its aliases), forwarded in canonical form. No free text. The
//     client-only encodings (SJIS, BIG5, GBK, UHC, GB18030, JOHAB,
//     SHIFT_JIS_2004) are refused: their multibyte characters can end in a
//     backslash, so the broker's SQL lexer and the server could split a
//     string literal differently. PostgreSQL refuses them as server encodings
//     for the same reason.
//   - the rest: at most 256 bytes of printable ASCII. These settings are
//     bounded in effect; the server parses them and rejects invalid values.
func StartupValue(key, value string) (string, bool) {
	switch key {
	case "statement_timeout":
		if value == "" || len(value) > 10 {
			return "", false
		}
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return "", false
			}
		}
		if n, err := strconv.ParseUint(value, 10, 31); err != nil || n == 0 {
			return "", false
		}
		return value, true
	case "application_name":
		if len(value) > 63 || !printable(value) {
			return "", false
		}
		return value, true
	case "client_encoding":
		canonical, ok := encodings[cleanEncoding(value)]
		return canonical, ok
	case "DateStyle", "extra_float_digits", "search_path", "standard_conforming_strings", "TimeZone":
		if len(value) > 256 || !printable(value) {
			return "", false
		}
		return value, true
	default:
		return "", false
	}
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// cleanEncoding lowercases and drops everything but letters and digits, as
// PostgreSQL's clean_encoding_name does, so "UTF-8", "utf8" and "UTF_8" match.
func cleanEncoding(s string) string {
	if len(s) > 32 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// encodings maps cleaned names to PostgreSQL's canonical names for its server
// encodings (pg_enc2name_tbl, PostgreSQL 16) plus the common aliases its
// pg_encname_tbl accepts for them. Every one keeps ASCII bytes as ASCII.
var encodings = func() map[string]string {
	canonical := []string{"SQL_ASCII", "EUC_JP", "EUC_CN", "EUC_KR", "EUC_TW", "EUC_JIS_2004", "UTF8", "MULE_INTERNAL",
		"LATIN1", "LATIN2", "LATIN3", "LATIN4", "LATIN5", "LATIN6", "LATIN7", "LATIN8", "LATIN9", "LATIN10",
		"WIN1256", "WIN1258", "WIN866", "WIN874", "KOI8R", "WIN1251", "WIN1252", "ISO_8859_5", "ISO_8859_6",
		"ISO_8859_7", "ISO_8859_8", "WIN1250", "WIN1253", "WIN1254", "WIN1255", "WIN1257", "KOI8U"}
	m := make(map[string]string, len(canonical)+32)
	for _, name := range canonical {
		m[cleanEncoding(name)] = name
	}
	aliases := map[string]string{
		"unicode": "UTF8", "iso88591": "LATIN1", "iso88592": "LATIN2", "iso88593": "LATIN3", "iso88594": "LATIN4",
		"iso88599": "LATIN5", "iso885910": "LATIN6", "iso885913": "LATIN7", "iso885914": "LATIN8", "iso885915": "LATIN9",
		"iso885916": "LATIN10", "koi8": "KOI8R", "win": "WIN1251", "alt": "WIN866", "cp866": "WIN866", "cp874": "WIN874",
		"cp1250": "WIN1250", "cp1251": "WIN1251", "cp1252": "WIN1252",
		"cp1253": "WIN1253", "cp1254": "WIN1254", "cp1255": "WIN1255", "cp1256": "WIN1256", "cp1257": "WIN1257",
		"cp1258": "WIN1258", "tcvn": "WIN1258", "tcvn5712": "WIN1258",
		"vscii": "WIN1258", "abc": "WIN1258",
	}
	for alias, name := range aliases {
		m[alias] = name
	}
	return m
}()
