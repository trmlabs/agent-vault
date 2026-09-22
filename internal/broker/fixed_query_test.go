package broker

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFixedQueryValidation(t *testing.T) {
	valid := Service{Name: "search", Host: "api.example.test", Path: "/v1/search", FixedQuery: FixedQuery{"keyword": "synthetic sample", "limit": "1"}}
	if err := valid.ValidateFixedQuery(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Service){
		"wildcard-host":        func(s *Service) { s.Host = "*.example.test" },
		"wildcard-path":        func(s *Service) { s.Path = "/v1/*" },
		"no-path":              func(s *Service) { s.Path = "" },
		"traversal":            func(s *Service) { s.Path = "/v1/../search" },
		"encoded-path":         func(s *Service) { s.Path = "/v1/%73earch" },
		"empty":                func(s *Service) { s.FixedQuery = FixedQuery{} },
		"duplicate-key-syntax": func(s *Service) { s.FixedQuery = FixedQuery{"x&y": "z"} },
		"control":              func(s *Service) { s.FixedQuery = FixedQuery{"x": "a\r\nb"} },
		"placeholder":          func(s *Service) { s.FixedQuery = FixedQuery{"x": "__vault_KEY__"} },
		"template":             func(s *Service) { s.FixedQuery = FixedQuery{"x": "{{KEY}}"} },
		"key-limit":            func(s *Service) { s.FixedQuery = FixedQuery{strings.Repeat("x", 65): "y"} },
		"count-limit": func(s *Service) {
			s.FixedQuery = FixedQuery{}
			for i := 0; i < 17; i++ {
				s.FixedQuery[fmt.Sprintf("key%d", i)] = "x"
			}
		},
		"encoded-limit": func(s *Service) {
			s.FixedQuery = FixedQuery{}
			for i := 0; i < 9; i++ {
				s.FixedQuery[fmt.Sprintf("key%d", i)] = strings.Repeat("&", 512)
			}
		},
		"value-limit": func(s *Service) { s.FixedQuery = FixedQuery{"x": strings.Repeat("x", 513)} },
	} {
		t.Run(name, func(t *testing.T) {
			s := valid
			change(&s)
			if s.ValidateFixedQuery() == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	for _, input := range []string{`{"x":"a","x":"b"}`, `{"x":1}`, `{"x":null}`, `{"x":"a","\u0078":"b"}`, `[]`} {
		var q FixedQuery
		if json.Unmarshal([]byte(input), &q) == nil {
			t.Fatalf("invalid JSON accepted: %s", input)
		}
	}
	duplicate := valid
	duplicate.Name = "other"
	if ValidateFixedQueryBindings([]Service{valid, duplicate}) == nil {
		t.Fatal("ambiguous profile accepted")
	}
	duplicate.FixedQuery = nil
	if ValidateFixedQueryBindings([]Service{valid, duplicate}) == nil {
		t.Fatal("unrestricted collision accepted")
	}
	port1, port2 := 443, 8443
	valid.Port = &port1
	duplicate.Port = &port2
	if err := ValidateFixedQueryBindings([]Service{valid, duplicate}); err != nil {
		t.Fatal(err)
	}
}

func TestFixedQueryRejectsOverlappingPatterns(t *testing.T) {
	fixed := Service{Name: "fixed", Host: "api.example.test", Path: "/v1/search", FixedQuery: FixedQuery{"limit": "1"}}
	for _, other := range []Service{
		{Name: "glob", Host: fixed.Host, Path: "/v1/search*"},
		{Name: "wide", Host: fixed.Host, Path: "/v1/*"},
		{Name: "catchall", Host: fixed.Host},
		{Name: "hostglob", Host: "*.example.test", Path: fixed.Path},
	} {
		for _, pair := range [][]Service{{fixed, other}, {other, fixed}} {
			if ValidateFixedQueryBindings(pair) == nil {
				t.Errorf("accepted overlap with %s", other.Name)
			}
		}
	}
	for _, other := range []Service{{Name: "different-path", Host: fixed.Host, Path: "/v1/other"}, {Name: "different-host", Host: "other.example.test", Path: fixed.Path}} {
		if err := ValidateFixedQueryBindings([]Service{fixed, other}); err != nil {
			t.Fatal(err)
		}
	}
}
