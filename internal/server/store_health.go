package server

import (
	"context"
	"time"
)

// The readiness gate reads the store's reachability from a background check
// instead of pinging per probe: a probe that waits for a connection from the
// shared pool queues behind the broker's own store traffic under load, and
// one slow probe would pull a healthy replica out of the Service.
const (
	storePingEvery   = 2 * time.Second
	storePingTimeout = 2 * time.Second
	// storeStaleAfter is how long the store may go unreached before the
	// replica reports unready: several missed pings, not one.
	storeStaleAfter = 10 * time.Second
)

// watchStore pings the store until ctx ends, recording each success.
func (s *Server) watchStore(ctx context.Context) {
	ticker := time.NewTicker(storePingEvery)
	defer ticker.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, storePingTimeout)
		if s.store.Ping(pingCtx) == nil {
			s.storeOK.Store(time.Now().UnixMilli())
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// storeReachable reports whether a store ping succeeded within storeStaleAfter.
func (s *Server) storeReachable(now time.Time) bool {
	last := s.storeOK.Load()
	return last != 0 && now.Sub(time.UnixMilli(last)) <= storeStaleAfter
}
