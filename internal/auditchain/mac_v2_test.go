package auditchain

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Every field of a row except the MAC itself must change the MAC input, so
// no field added later can be left out of the tamper check.
func TestEveryRowFieldIsInTheMAC(t *testing.T) {
	base := Row{MACVersion: MACVersionCurrent}
	baseInput := base.macInput()
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Name == "MAC" {
			continue
		}
		changed := base
		v := reflect.ValueOf(&changed).Elem().Field(i)
		switch v.Kind() {
		case reflect.String:
			v.SetString("x")
		case reflect.Int, reflect.Int64:
			v.SetInt(v.Int() + 7)
		case reflect.Uint64:
			v.SetUint(7)
		default:
			t.Fatalf("field %s has kind %s: teach this test and macInput about it", field.Name, v.Kind())
		}
		if bytes.Equal(changed.macInput(), baseInput) {
			t.Errorf("field %s is not covered by the MAC", field.Name)
		}
	}
}

// Rows written before v2 keep verifying under the v1 input.
func TestV1InputIsUnchanged(t *testing.T) {
	r := Row{Type: RowType, Replica: "broker-0", Event: EventSessionOpen}
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v1\x00")) {
		t.Fatal("a row without a MAC version no longer uses the v1 input")
	}
	r.MACVersion = 2
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v2\x00")) {
		t.Fatal("a v2 row does not use the v2 input")
	}
	r.MACVersion = MACVersionCurrent
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v3\x00")) {
		t.Fatal("a current row does not use the v3 input")
	}
}

func authzFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventDenied, Pool: "claude", Binding: "vault/core", Outcome: "not_entitled",
		RequesterKind: "person", RequesterOID: "oid-1", TokenSHA256: "ab", Tier: "T1", Decision: "not_entitled", Groups: "g1", CacheAgeSec: 3,
		Kid: "invalid", KidSHA256: "0123456789ab", Peer: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	return f, f.out.String()
}

// The High finding: a log-sink editor flips a decision and the chain must fail.
func TestAuthorizationFieldEditsAreDetected(t *testing.T) {
	for name, edit := range map[string][2]string{
		"decision":  {`"decision":"not_entitled"`, `"decision":"entitled"`},
		"tier":      {`"tier":"T1"`, `"tier":"T0"`},
		"groups":    {`"groups":"g1"`, `"groups":"g2"`},
		"person":    {`"requesterOID":"oid-1"`, `"requesterOID":"oid-2"`},
		"kind":      {`"requesterKind":"person"`, `"requesterKind":"workload"`},
		"token":     {`"tokenSHA256":"ab"`, `"tokenSHA256":"cd"`},
		"cache age": {`"cacheAgeSec":3`, `"cacheAgeSec":4`},
		"kid":       {`"kid":"invalid"`, `"kid":"k1"`},
		"kid hash":  {`"kidSHA256":"0123456789ab"`, `"kidSHA256":"ba9876543210"`},
		"peer":      {`"peer":"10.0.0.5"`, `"peer":"10.0.0.6"`},
		"version":   {`"macVersion":3`, `"macVersion":2`},
	} {
		t.Run(name, func(t *testing.T) {
			f, out := authzFixture(t)
			if !strings.Contains(out, edit[0]) {
				t.Fatalf("fixture row lacks %s", edit[0])
			}
			report := verify(t, f.verifier(), strings.Replace(out, edit[0], edit[1], 1))
			if !hasKind(report, FindingEdit) {
				t.Fatalf("edit not detected: %v", kinds(report))
			}
		})
	}
	f, out := authzFixture(t)
	if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
		t.Fatalf("untouched trail: %v", kinds(report))
	}
}

// A forged row with a valid v1 MAC (someone holding the HMAC key, or a row
// downgraded by removing its version) cannot carry authorization fields, and a
// chain never steps down from v2 to v1.
func TestV1RowsCannotCarryAuthorizationOrDowngrade(t *testing.T) {
	for name, forge := range map[string]func(*Row){
		"v1 row with a decision": func(r *Row) { r.Decision = "entitled" },
		"v2 row with a peer":     func(r *Row) { r.MACVersion, r.Peer = 2, "10.0.0.5" },
		"v2 row with a kid":      func(r *Row) { r.MACVersion, r.Kid = 2, "k1" },
		"plain downgrade":        func(*Row) {},
		"unknown version":        func(r *Row) { r.MACVersion = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			f, out := authzFixture(t)
			parsed := rows(t, out)
			last := parsed[len(parsed)-1]
			key, _ := f.keys.lookup(last.KeyVersion)
			forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time,
				Event: EventSessionOpen, Pool: "claude", KeyVersion: last.KeyVersion, Prev: last.MAC}
			forge(&forged)
			forged.MAC = forged.computeMAC(key)
			line, _ := json.Marshal(forged)
			if report := verify(t, f.verifier(), out+string(line)+"\n"); !hasKind(report, FindingEdit) {
				t.Fatalf("forged row accepted: %v", kinds(report))
			}
		})
	}
}

func hasKind(r Report, kind string) bool {
	for _, k := range kinds(r) {
		if k == kind {
			return true
		}
	}
	return false
}

// A trail written by a v2 broker and then, after an upgrade, a v3 one
// verifies; a v2 row after a v3 row is a step down and does not.
func TestUpgradeFromV2VerifiesAndNeverStepsDown(t *testing.T) {
	writeMACVersion = 2
	t.Cleanup(func() { writeMACVersion = MACVersionCurrent })
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	writeMACVersion = MACVersionCurrent
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "authentication", Decision: "identity_token_signature", Kid: "k1", Peer: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	f.session(t, 2)
	f.checkpoint(t)
	out := f.out.String()
	versions := map[int]int{}
	for _, r := range rows(t, out) {
		versions[r.MACVersion]++
	}
	if versions[2] == 0 || versions[3] == 0 || len(versions) != 2 {
		t.Fatalf("trail versions %v, want v2 then v3", versions)
	}
	if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
		t.Fatalf("upgraded trail: %v", kinds(report))
	}
	// A forged v2 row with a valid MAC after the v3 rows.
	parsed := rows(t, out)
	last := parsed[len(parsed)-1]
	key, _ := f.keys.lookup(last.KeyVersion)
	forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time,
		Event: EventSessionOpen, Pool: "claude", KeyVersion: last.KeyVersion, Prev: last.MAC, MACVersion: 2}
	forged.MAC = forged.computeMAC(key)
	line, _ := json.Marshal(forged)
	if report := verify(t, f.verifier(), out+string(line)+"\n"); !hasKind(report, FindingEdit) {
		t.Fatalf("step down from v3 to v2 accepted: %v", kinds(report))
	}
}
