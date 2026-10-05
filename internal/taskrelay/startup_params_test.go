package taskrelay

import (
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// What real drivers send at startup reaches the broker unchanged: JDBC's
// defaults, and libpq with PGTZ and PGDATESTYLE set. The broker applies the
// same rule (brokercore.StartupValue), so it accepts what passes here.
func TestPostgresPassesDriverStartupParameters(t *testing.T) {
	f := newRelayFixture(t)
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	startups := make(chan map[string]string, 4)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				packet, e := readStartupPacket(c)
				if e != nil {
					return
				}
				var message pgproto3.StartupMessage
				if message.Decode(packet[4:]) == nil {
					startups <- message.Parameters
				}
			}()
		}
	}()
	f.c.Postgres = &PostgresConfig{Listen: freeAddress(t), Upstream: f.upstream(t, l.Addr().String()), Database: "canary", User: "workload", Placeholder: "public-placeholder"}
	f.start(t)
	drivers := map[string]map[string]string{
		"jdbc": {"client_encoding": "UTF8", "DateStyle": "ISO", "TimeZone": "America/Denver", "extra_float_digits": "2",
			"application_name": "PostgreSQL JDBC Driver"},
		// libpq sends PGTZ and PGDATESTYLE under lowercase keys.
		"psql with PGTZ and PGDATESTYLE": {"timezone": "Asia/Tokyo", "datestyle": "ISO, DMY", "client_encoding": "SQL_ASCII",
			"application_name": "psql"},
		"search_path and conforming strings": {"search_path": "public, analytics", "standard_conforming_strings": "on",
			"statement_timeout": "30000"},
	}
	for name, extra := range drivers {
		parameters := map[string]string{"user": "workload", "database": "canary"}
		for k, v := range extra {
			parameters[k] = v
		}
		c := f.dial(t, f.c.Postgres.Listen)
		b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
		_, _ = c.Write(b)
		typ, body, e := readPGFrame(c, 1024)
		if e != nil || typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
			t.Fatalf("%s: startup refused", name)
		}
		_, _ = c.Write(encodePGFrame('p', []byte("public-placeholder\x00")))
		select {
		case got := <-startups:
			for k, v := range extra {
				canonical := map[string]string{"timezone": "TimeZone", "datestyle": "DateStyle"}[k]
				if canonical == "" {
					canonical = k
				}
				if got[canonical] != v {
					t.Errorf("%s: %s reached the broker as %q, want %q", name, canonical, got[canonical], v)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: startup never reached the broker", name)
		}
		c.Close()
	}
}
