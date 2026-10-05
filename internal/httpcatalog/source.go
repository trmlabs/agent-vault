package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Source is the live catalog. The broker reads Current per request; Watch
// swaps in each new valid version. A version that fails validation never
// replaces the last good catalog.
type Source struct {
	current atomic.Pointer[Catalog]
	version atomic.Int64

	mu       sync.Mutex
	onChange []func(Catalog)
}

// OnChange runs f after each new catalog version is swapped in, so state
// derived from an older version (cached tokens) can follow it.
func (s *Source) OnChange(f func(Catalog)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, f)
	s.mu.Unlock()
}

// NewSource starts from a validated catalog at a version (0 for a file).
func NewSource(c Catalog, version int) *Source {
	s := &Source{}
	s.current.Store(&c)
	s.version.Store(int64(version))
	return s
}

func (s *Source) Current() Catalog { return *s.current.Load() }

func (s *Source) Version() int { return int(s.version.Load()) }

// Loader returns the newest catalog document and its version.
type Loader func(context.Context) (data []byte, version int, err error)

// Open reads and validates a catalog once, for startup: no catalog, no broker.
func Open(ctx context.Context, load Loader) (*Source, error) {
	data, version, err := load(ctx)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return NewSource(c, version), nil
}

// Watch polls every interval until ctx ends. A new version is parsed and, if
// valid, swapped in atomically; a rejected version is reported to rejected
// (with no catalog content) and the previous catalog stays in force.
func (s *Source) Watch(ctx context.Context, interval time.Duration, load Loader, rejected func(version int, err error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refused := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		loadCtx, cancel := context.WithTimeout(ctx, interval/2)
		data, version, err := load(loadCtx)
		cancel()
		if err != nil {
			rejected(version, fmt.Errorf("catalog unavailable: %w", err))
			continue
		}
		if version == s.Version() || version == refused {
			continue
		}
		c, err := Parse(data)
		if err != nil {
			refused = version
			rejected(version, err)
			continue
		}
		s.current.Store(&c)
		s.version.Store(int64(version))
		s.mu.Lock()
		hooks := append([](func(Catalog)){}, s.onChange...)
		s.mu.Unlock()
		for _, f := range hooks {
			f(c)
		}
	}
}

// VaultLoader reads the catalog document from field of a KV version 2
// secret, where Terraform writes it; the KV version is the catalog version.
func VaultLoader(vault Logical, mount, path, field string) Loader {
	return func(ctx context.Context) ([]byte, int, error) {
		if vault == nil || !kvPattern.MatchString(mount) || !kvPattern.MatchString(path) || field == "" {
			return nil, 0, errors.New("catalog location is not configured")
		}
		resp, err := vault.ReadWithDataWithContext(ctx, mount+"/data/"+path, nil)
		if err != nil || resp == nil || resp.Data == nil {
			return nil, 0, errors.New("catalog read failed")
		}
		data, _ := resp.Data["data"].(map[string]interface{})
		metadata, _ := resp.Data["metadata"].(map[string]interface{})
		document, _ := data[field].(string)
		version := 0
		switch n := metadata["version"].(type) {
		case json.Number:
			version, _ = strconv.Atoi(n.String())
		case float64:
			version = int(n)
		}
		if document == "" || version < 1 {
			return nil, 0, errors.New("catalog response incomplete")
		}
		return []byte(document), version, nil
	}
}

// FromYAML converts a YAML catalog (the reviewed source form) to the JSON the
// broker reads, so both pass through the same Parse.
func FromYAML(data []byte) ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid catalog YAML: %w", err)
	}
	return json.Marshal(doc)
}
