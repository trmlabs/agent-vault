package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var fixedQueryKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// ValidateFixedQuery restricts literal, non-secret query parameters to an exact
// service. Only strict HTTPS GET forwarding supports this configuration. It
// never accepts parameters from an agent or expands credential placeholders.
func (s Service) ValidateFixedQuery() error {
	if s.FixedQuery == nil {
		return nil
	}
	invalid := errors.New("fixed_query requires an exact host/path and 1-16 bounded literal parameters")
	if len(s.FixedQuery) == 0 || len(s.FixedQuery) > 16 || s.Host == "" || strings.ContainsAny(s.Host, "*?[]") || s.Path == "" || !strings.HasPrefix(s.Path, "/") || path.Clean(s.Path) != s.Path || strings.ContainsAny(s.Path, "*?[]{}%#") || strings.Contains(s.Path, "__") {
		return invalid
	}
	query := url.Values{}
	for key, value := range s.FixedQuery {
		if !fixedQueryKey.MatchString(key) || len(value) > 512 || !utf8.ValidString(value) || strings.Contains(value, "__") || strings.ContainsAny(value, "{}") {
			return invalid
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return invalid
			}
		}
		query.Set(key, value)
	}
	if len(query.Encode()) > 4096 {
		return invalid
	}
	return nil
}

// FixedQuery rejects duplicate JSON parameter names instead of choosing a value.
// Values are configuration literals, not a place to store secrets.
type FixedQuery map[string]string

func (q *FixedQuery) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*q = nil
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("fixed_query must be an object")
	}
	parsed := FixedQuery{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return errors.New("invalid fixed_query parameter")
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid fixed_query parameter name")
		}
		if _, exists := parsed[key]; exists {
			return errors.New("duplicate fixed_query parameter")
		}
		token, err = decoder.Token()
		value, isString := token.(string)
		if err != nil || !isString {
			return errors.New("fixed_query values must be strings")
		}
		parsed[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return errors.New("invalid fixed_query object")
	}
	*q = parsed
	return nil
}

// ValidateFixedQueryBindings rejects any service pattern overlapping a fixed
// operation, so matching precedence cannot discard its configured parameters.
func ValidateFixedQueryBindings(services []Service) error {
	for i, s := range services {
		if err := s.ValidateFixedQuery(); err != nil {
			return err
		}
		if s.FixedQuery == nil {
			continue
		}
		for j, other := range services {
			if i == j {
				continue
			}
			if _, matches := matchHostPattern(other.Host, s.Host); !matches {
				continue
			}
			if _, matches := matchPathGlob(other.Path, s.Path); !matches {
				continue
			}
			if s.Port == nil || other.Port == nil || *s.Port == *other.Port {
				return errors.New("ambiguous fixed_query service binding")
			}
		}
	}
	return nil
}
