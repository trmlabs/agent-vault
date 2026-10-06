package auditchain

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	r.MACVersion = 3
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v3\x00")) {
		t.Fatal("a v3 row does not use the v3 input")
	}
	r.MACVersion = MACVersionCurrent
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v4\x00")) {
		t.Fatal("a current row does not use the v4 input")
	}
}

func authzFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventDenied, Pool: "claude", Binding: "vault/core", Outcome: "not_entitled",
		RequesterKind: "person", RequesterOID: "oid-1", TokenSHA256: "ab", Tier: "T1", Decision: "not_entitled", Groups: "11111111-2222-3333-4444-555555555555", CacheAgeSec: 3,
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
		"groups":    {`"groups":"11111111-2222-3333-4444-555555555555"`, `"groups":"11111111-2222-3333-4444-555555555556"`},
		"person":    {`"requesterOID":"oid-1"`, `"requesterOID":"oid-2"`},
		"kind":      {`"requesterKind":"person"`, `"requesterKind":"workload"`},
		"token":     {`"tokenSHA256":"ab"`, `"tokenSHA256":"cd"`},
		"cache age": {`"cacheAgeSec":3`, `"cacheAgeSec":4`},
		"kid":       {`"kid":"invalid"`, `"kid":"k1"`},
		"kid hash":  {`"kidSHA256":"0123456789ab"`, `"kidSHA256":"ba9876543210"`},
		"peer":      {`"peer":"10.0.0.5"`, `"peer":"10.0.0.6"`},
		"version":   {`"macVersion":4`, `"macVersion":3`},
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
		"v3 row with a serial":   func(r *Row) { r.MACVersion, r.Serial = 3, "1a" },
		"v3 row with a notAfter": func(r *Row) { r.MACVersion, r.NotAfter = 3, "2026-10-07T00:00:00Z" },
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

// A trail written by a v2 broker, then after upgrades by v3 and v4 ones,
// verifies; an older row after a newer one is a step down and does not.
func TestUpgradeFromV2VerifiesAndNeverStepsDown(t *testing.T) {
	writeMACVersion = 2
	t.Cleanup(func() { writeMACVersion = MACVersionCurrent })
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	writeMACVersion = 3
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "authentication", Decision: "identity_token_signature", Kid: "k1", Peer: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = MACVersionCurrent
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventCertificate, Outcome: "issued", Peer: "10.0.0.5", Serial: "1a2b", NotAfter: "2026-10-07T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	f.session(t, 2)
	f.checkpoint(t)
	out := f.out.String()
	versions := map[int]int{}
	for _, r := range rows(t, out) {
		versions[r.MACVersion]++
	}
	if versions[2] == 0 || versions[3] == 0 || versions[MACVersionCurrent] == 0 || len(versions) != 3 {
		t.Fatalf("trail versions %v, want v2, v3 then v4", versions)
	}
	if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
		t.Fatalf("upgraded trail: %v", kinds(report))
	}
	parsed := rows(t, out)
	last := parsed[len(parsed)-1]
	key, _ := f.keys.lookup(last.KeyVersion)
	for _, older := range []int{2, 3} {
		forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time,
			Event: EventSessionOpen, Pool: "claude", KeyVersion: last.KeyVersion, Prev: last.MAC, MACVersion: older}
		forged.MAC = forged.computeMAC(key)
		line, _ := json.Marshal(forged)
		if report := verify(t, f.verifier(), out+string(line)+"\n"); !hasKind(report, FindingEdit) {
			t.Fatalf("step down from v4 to v%d accepted: %v", older, kinds(report))
		}
	}
}

// A certificate row's serial and notAfter are covered by the MAC, and only a
// hex serial and an RFC 3339 UTC time are accepted.
func TestCertificateFieldsAreCoveredAndBounded(t *testing.T) {
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventCertificate, Outcome: "issued", Peer: "10.0.0.5", Serial: "7f00aa", NotAfter: "2026-10-07T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	out := f.out.String()
	for _, edit := range [][2]string{{`"serial":"7f00aa"`, `"serial":"7f00ab"`}, {`"notAfter":"2026-10-07T00:00:00Z"`, `"notAfter":"2027-10-07T00:00:00Z"`}} {
		if !strings.Contains(out, edit[0]) {
			t.Fatalf("row lacks %s", edit[0])
		}
		if report := verify(t, f.verifier(), strings.Replace(out, edit[0], edit[1], 1)); !hasKind(report, FindingEdit) {
			t.Fatalf("%s edit not detected", edit[0])
		}
	}
	for _, e := range []Event{
		{Event: EventCertificate, Serial: "7F00AA"},
		{Event: EventCertificate, Serial: "007f"},
		{Event: EventCertificate, Serial: strings.Repeat("a", 41)},
		{Event: EventCertificate, NotAfter: "2026-10-07T02:00:00+02:00"},
		{Event: EventCertificate, NotAfter: "tomorrow"},
	} {
		if e.Validate() == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

// A decision may check any number of groups: the row records the full list,
// which only Entra object IDs may form, and its MAC covers it.
func TestManyGroupsAreRecordedInFull(t *testing.T) {
	var groups []string
	for i := range 1000 {
		groups = append(groups, fmt.Sprintf("%08x-0000-0000-0000-%012x", i, i))
	}
	many := strings.Join(groups, ",")
	if (Event{Event: EventDenied, Groups: many}).Validate() != nil {
		t.Fatal("1,000 groups refused")
	}
	for _, bad := range []string{"g1", many + ",", many + ",not a group", "11111111-2222-3333-4444-555555555555 "} {
		if (Event{Event: EventDenied, Groups: bad}).Validate() == nil {
			t.Errorf("group list %.40q accepted", bad)
		}
	}
}
