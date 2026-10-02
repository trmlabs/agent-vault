package auditchain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Synthetic test keys, generated per run; never real credentials.
type testKeys struct {
	mu       sync.Mutex
	versions map[int][]byte
	current  int
	err      error
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	k := &testKeys{versions: map[int][]byte{}}
	k.rotate()
	return k
}

func (k *testKeys) rotate() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.current++
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(k.current*31 + i*7 + 1)
	}
	k.versions[k.current] = secret
}

func (k *testKeys) Current(context.Context) (Key, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return Key{}, k.err
	}
	return NewKey(k.current, k.versions[k.current])
}

func (k *testKeys) lookup(version int) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if v, ok := k.versions[version]; ok {
		return v, nil
	}
	return nil, errors.New("no such version")
}

type testSigner struct {
	mu      sync.Mutex
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	down    bool
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{private: private, public: public}
}

func (s *testSigner) Sign(_ context.Context, input []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return "", errors.New("transit unavailable")
	}
	return "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, input)), nil
}

func (s *testSigner) setDown(down bool) { s.mu.Lock(); s.down = down; s.mu.Unlock() }

// memBoots mirrors the store's boot table for one process.
type memBoots struct {
	mu        sync.Mutex
	replicas  map[string]store.AuditBoot
	recordErr error
}

func newMemBoots() *memBoots { return &memBoots{replicas: map[string]store.AuditBoot{}} }

func (m *memBoots) BeginAuditBoot(_ context.Context, replica string) (uint64, store.AuditBoot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.replicas[replica]
	m.replicas[replica] = store.AuditBoot{Boot: previous.Boot + 1}
	return previous.Boot + 1, previous, nil
}

func (m *memBoots) RecordAuditCheckpoint(_ context.Context, replica string, boot, seq uint64, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordErr != nil {
		return m.recordErr
	}
	if m.replicas[replica].Boot != boot {
		return errors.New("boot no longer current")
	}
	m.replicas[replica] = store.AuditBoot{Boot: boot, CheckpointSeq: seq, CheckpointMAC: mac}
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type fixture struct {
	out    *bytes.Buffer
	keys   *testKeys
	signer *testSigner
	boots  *memBoots
	clock  *clock
	chain  *Chain
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{out: &bytes.Buffer{}, keys: newTestKeys(t), signer: newTestSigner(t), boots: newMemBoots(), clock: &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}}
	f.restart(t)
	return f
}

// restart begins the replica's next boot, appending to the same output.
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	chain, err := New(context.Background(), Options{Out: f.out, Replica: "broker-0", Keys: f.keys, Signer: f.signer, Boots: f.boots, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	f.chain = chain
}

func (f *fixture) verifier() Verifier {
	return Verifier{HMACKey: f.keys.lookup, PublicKeys: map[int]ed25519.PublicKey{1: f.signer.public}, MaxUnsigned: 5 * time.Minute}
}

func (f *fixture) session(t *testing.T, n int) {
	t.Helper()
	for _, e := range []Event{
		{Event: EventSessionOpen, Pool: "pool-agent", PodUID: fmt.Sprintf("pod-%d", n), Binding: "vault/core", Session: fmt.Sprintf("s%d", n), Outcome: "admitted"},
		{Event: EventSessionClose, Pool: "pool-agent", PodUID: fmt.Sprintf("pod-%d", n), Binding: "vault/core", Session: fmt.Sprintf("s%d", n), Outcome: "closed"},
	} {
		if err := f.chain.Record(e); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) checkpoint(t *testing.T) {
	t.Helper()
	f.clock.advance(time.Minute)
	if err := f.chain.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func rows(t *testing.T, out string) []Row {
	t.Helper()
	var parsed []Row
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r Row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, r)
	}
	return parsed
}

func verify(t *testing.T, v Verifier, input string) Report {
	t.Helper()
	report, err := v.Verify(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func kinds(r Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Kind)
	}
	return out
}

func TestChainVerifiesAcrossCheckpointsAndRotation(t *testing.T) {
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	f.keys.rotate()
	if err := f.chain.RefreshKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.RefreshKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.session(t, 2)
	f.checkpoint(t)
	got := rows(t, f.out.String())
	events := []string{}
	for i, r := range got {
		if r.Seq != uint64(i) || r.Type != RowType || r.Replica != "broker-0" {
			t.Fatalf("row %d: %+v", i, r)
		}
		events = append(events, r.Event)
	}
	want := "chain_start session_open session_close checkpoint key_rotated session_open session_close checkpoint"
	if strings.Join(events, " ") != want {
		t.Fatalf("events = %v", events)
	}
	if got[4].KeyVersion != 2 || got[4].PrevKey != 1 || got[3].KeyVersion != 1 {
		t.Fatalf("rotation not recorded: %+v", got[4])
	}
	if report := verify(t, f.verifier(), f.out.String()); len(report.Findings) != 0 || report.Rows != 8 || report.Chains != 1 {
		t.Fatalf("clean chain rejected: %+v", report)
	}
}

// Tamper test: every way of altering an exported trail is reported.
func TestVerifierDetectsTampering(t *testing.T) {
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	f.session(t, 2)
	f.session(t, 3)
	f.checkpoint(t)
	clean := strings.Split(strings.TrimSpace(f.out.String()), "\n")
	parsed := rows(t, f.out.String())
	encode := func(r Row) string { b, _ := json.Marshal(r); return string(b) }
	join := func(lines []string) string { return strings.Join(lines, "\n") + "\n" }
	replace := func(i int, line string) string {
		lines := append([]string(nil), clean...)
		lines[i] = line
		return join(lines)
	}
	key1, _ := f.keys.lookup(1)
	// A compromised broker holds the HMAC key: it rewrites row 5 and re-links
	// every later row, but cannot re-sign the checkpoint covering them.
	rewritten := func() string {
		lines := append([]string(nil), clean[:5]...)
		prev := parsed[4].MAC
		for _, r := range parsed[5:] {
			if r.Seq == 5 {
				r.Outcome = "forged"
			}
			r.Prev = prev
			if r.Event == EventCheckpoint && r.SignedSeq >= 5 {
				r.SignedMAC = prev
			}
			r.MAC = r.computeMAC(key1)
			prev = r.MAC
			lines = append(lines, encode(r))
		}
		return join(lines)
	}()
	edited := parsed[2]
	edited.Outcome = "admitted"
	forgedSignature := parsed[3]
	forgedSignature.Signature = "vault:v1:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	forgedSignature.MAC = forgedSignature.computeMAC(key1)

	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"edited field", replace(2, encode(edited)), FindingEdit},
		{"deleted row", join(append(append([]string(nil), clean[:4]...), clean[5:]...)), FindingGap},
		{"swapped rows", join(append(append(append([]string(nil), clean[:4]...), clean[5], clean[4]), clean[6:]...)), FindingReorder},
		{"duplicated row", join(append(append([]string(nil), clean[:5]...), clean[4:]...)), FindingDuplicate},
		{"rewritten history", rewritten, FindingBadCheckpoint},
		{"forged checkpoint signature", replace(3, encode(forgedSignature)), FindingBadCheckpoint},
		{"truncated start", join(clean[1:]), FindingNoStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := verify(t, f.verifier(), tc.input)
			found := false
			for _, k := range kinds(report) {
				found = found || k == tc.want
			}
			if !found {
				t.Fatalf("want %s, got %v", tc.want, kinds(report))
			}
		})
	}
}

// After a rotation, a leaked old key cannot append rows that verify.
func TestVerifierRejectsOldKeyAfterRotation(t *testing.T) {
	f := newFixture(t)
	f.keys.rotate()
	if err := f.chain.RefreshKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	parsed := rows(t, f.out.String())
	last := parsed[len(parsed)-1]
	key1, _ := f.keys.lookup(1)
	forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time, Event: EventSessionOpen, Pool: "p", KeyVersion: 1, Prev: last.MAC}
	forged.MAC = forged.computeMAC(key1)
	line, _ := json.Marshal(forged)
	report := verify(t, f.verifier(), f.out.String()+string(line)+"\n")
	if strings.Join(kinds(report), " ") != FindingKeyChange {
		t.Fatalf("old-key row accepted: %v", kinds(report))
	}
}

func TestVerifierFlagsLongUnsignedTail(t *testing.T) {
	f := newFixture(t)
	f.checkpoint(t)
	f.clock.advance(10 * time.Minute)
	f.session(t, 1)
	if got := kinds(verify(t, f.verifier(), f.out.String())); strings.Join(got, " ") != FindingUnsigned {
		t.Fatalf("unsigned tail not flagged: %v", got)
	}
}

func TestVerifierReadsCloudLoggingEntries(t *testing.T) {
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	var wrapped strings.Builder
	wrapped.WriteString(`{"severity":"INFO","textPayload":"unrelated"}` + "\n")
	for _, line := range strings.Split(strings.TrimSpace(f.out.String()), "\n") {
		wrapped.WriteString(`{"logName":"projects/p/logs/stdout","jsonPayload":` + line + "}\n")
	}
	if report := verify(t, f.verifier(), wrapped.String()); len(report.Findings) != 0 || report.Rows != 4 {
		t.Fatalf("wrapped rows: %+v", report)
	}
}

// Transit down: rows keep flowing and each failure is recorded in the chain,
// but new sessions are refused once the grace period passes unsigned.
func TestTransitOutageRefusesAdmissionAfterGrace(t *testing.T) {
	f := newFixture(t)
	f.signer.setDown(true)
	for range 5 {
		f.clock.advance(time.Minute)
		if err := f.chain.Checkpoint(context.Background()); !errors.Is(err, ErrCheckpointOverdue) {
			t.Fatalf("checkpoint error = %v", err)
		}
		if err := f.chain.Admit(); err != nil {
			t.Fatalf("refused inside grace: %v", err)
		}
	}
	f.session(t, 1)
	f.clock.advance(time.Second)
	if err := f.chain.Admit(); !errors.Is(err, ErrCheckpointOverdue) {
		t.Fatalf("admitted past grace: %v", err)
	}
	f.signer.setDown(false)
	f.checkpoint(t)
	if err := f.chain.Admit(); err != nil {
		t.Fatalf("not restored after checkpoint: %v", err)
	}
	failed := 0
	for _, r := range rows(t, f.out.String()) {
		if r.Event == EventCheckpointFailed && r.Outcome == "signer_unavailable" {
			failed++
		}
	}
	if failed != 5 {
		t.Fatalf("recorded %d failures", failed)
	}
	if report := verify(t, f.verifier(), f.out.String()); len(report.Findings) != 0 {
		t.Fatalf("outage trail rejected: %v", kinds(report))
	}
}

type failingWriter struct{ after int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.after == 0 {
		return 0, errors.New("stdout closed")
	}
	w.after--
	return len(p), nil
}

func TestOutputFailureFailsClosed(t *testing.T) {
	keys, signer := newTestKeys(t), newTestSigner(t)
	if _, err := New(context.Background(), Options{Out: &failingWriter{}, Replica: "broker-0", Keys: keys, Signer: signer, Boots: newMemBoots()}); err == nil {
		t.Fatal("chain started without a writable output")
	}
	c, err := New(context.Background(), Options{Out: &failingWriter{after: 1}, Replica: "broker-0", Keys: keys, Signer: signer, Boots: newMemBoots()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Record(Event{Event: EventSessionOpen, Pool: "p"}); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("write failure = %v", err)
	}
	if c.Admit() == nil || c.Record(Event{Event: EventDenied}) == nil || c.Checkpoint(context.Background()) == nil {
		t.Fatal("chain continued after a lost row")
	}
}

func TestChainRequiresKeyAndRejectsFreeText(t *testing.T) {
	keys := newTestKeys(t)
	keys.err = errors.New("vault sealed")
	if _, err := New(context.Background(), Options{Out: &bytes.Buffer{}, Replica: "broker-0", Keys: keys, Signer: newTestSigner(t), Boots: newMemBoots()}); err == nil {
		t.Fatal("chain started without a key")
	}
	if _, err := New(context.Background(), Options{Out: &bytes.Buffer{}, Replica: "broker-0", Keys: newTestKeys(t), Signer: newTestSigner(t)}); err == nil {
		t.Fatal("chain started without a boot store")
	}
	f := newFixture(t)
	for _, e := range []Event{
		{Event: EventCheckpoint},
		{Event: EventDenied, Outcome: "password=hunter2 rejected"},
		{Event: EventDenied, Pool: `a"b`},
		{Event: EventDenied, Requester: strings.Repeat("x", 513)},
	} {
		if err := f.chain.Record(e); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("accepted %+v", e)
		}
	}
}

func TestKeyNeverAppearsInOutput(t *testing.T) {
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	key, _ := f.keys.Current(context.Background())
	secret, _ := f.keys.lookup(1)
	printed := fmt.Sprintf("%v %+v %#v %s", key, key, key, key)
	for _, form := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), string(secret)} {
		if strings.Contains(f.out.String(), form) || strings.Contains(printed, form) {
			t.Fatal("HMAC key disclosed")
		}
	}
	if !strings.Contains(printed, "audit-hmac-key(v1)") {
		t.Fatalf("unexpected key rendering %q", printed)
	}
}

func TestConcurrentRecordsStayInSequence(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() { defer wg.Done(); f.session(t, i) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = f.chain.Checkpoint(context.Background()) }()
	wg.Wait()
	if report := verify(t, f.verifier(), f.out.String()); len(report.Findings) != 0 || report.Rows != 102 {
		t.Fatalf("concurrent chain: rows=%d %v", report.Rows, kinds(report))
	}
}

func TestSortBySeqAcceptsShuffledExportButNotEdits(t *testing.T) {
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	lines := strings.Split(strings.TrimSpace(f.out.String()), "\n")
	shuffled := strings.Join([]string{lines[3], lines[0], lines[2], lines[1]}, "\n") + "\n"
	v := f.verifier()
	if got := kinds(verify(t, v, shuffled)); len(got) == 0 {
		t.Fatal("input-order check missed the reorder")
	}
	v.SortBySeq = true
	if got := kinds(verify(t, v, shuffled)); len(got) != 0 {
		t.Fatalf("sorted export rejected: %v", got)
	}
	if got := kinds(verify(t, v, strings.Replace(shuffled, `"outcome":"closed"`, `"outcome":"admitted"`, 1))); strings.Join(got, " ") != FindingEdit {
		t.Fatalf("edit hidden by sorting: %v", got)
	}
}

// threeBoots writes boots 1 to 3 of one replica, each with a session and a
// checkpoint, and returns each boot's lines.
func threeBoots(t *testing.T) (*fixture, [][]string) {
	t.Helper()
	f := newFixture(t)
	var boots [][]string
	written := 0
	for boot := 1; boot <= 3; boot++ {
		if boot > 1 {
			f.restart(t)
		}
		f.session(t, boot)
		f.checkpoint(t)
		lines := strings.Split(strings.TrimSpace(f.out.String()), "\n")
		boots = append(boots, lines[written:])
		written = len(lines)
	}
	return f, boots
}

func joinBoots(boots ...[]string) string {
	var all []string
	for _, b := range boots {
		all = append(all, b...)
	}
	return strings.Join(all, "\n") + "\n"
}

func TestBootsLinkToTheirPredecessor(t *testing.T) {
	f, boots := threeBoots(t)
	if report := verify(t, f.verifier(), f.out.String()); len(report.Findings) != 0 || report.Chains != 3 {
		t.Fatalf("linked boots rejected: %d %v", report.Chains, kinds(report))
	}
	first := rows(t, boots[0][0])[0]
	second := rows(t, boots[1][0])[0]
	lastOfFirst := rows(t, boots[0][len(boots[0])-1])[0]
	if first.Boot != 1 || first.PrevBoot != 0 || second.Boot != 2 || second.PrevBoot != 1 ||
		second.PrevCheckpointSeq != lastOfFirst.Seq || second.PrevCheckpointMAC != lastOfFirst.MAC || lastOfFirst.Event != EventCheckpoint {
		t.Fatalf("boot link: first=%+v second=%+v", first, second)
	}
}

// Deleting a whole boot is detected, unless it predates the export window and
// the verifier is told the history is partial.
func TestVerifierDetectsMissingBoot(t *testing.T) {
	f, boots := threeBoots(t)
	report := verify(t, f.verifier(), joinBoots(boots[0], boots[2]))
	if len(report.Findings) != 1 || report.Findings[0].Kind != FindingMissingBoot || report.Findings[0].Boot != 2 {
		t.Fatalf("deleted boot not reported: %v", report.Findings)
	}
	if got := kinds(verify(t, f.verifier(), joinBoots(boots[1], boots[2]))); strings.Join(got, " ") != FindingMissingBoot {
		t.Fatalf("missing first boot not reported: %v", got)
	}
	partial := f.verifier()
	partial.PartialHistory = true
	if got := kinds(verify(t, partial, joinBoots(boots[1], boots[2]))); len(got) != 0 {
		t.Fatalf("partial history rejected: %v", got)
	}
	if got := kinds(verify(t, partial, joinBoots(boots[0], boots[2]))); strings.Join(got, " ") != FindingMissingBoot {
		t.Fatalf("partial history hid an interior boot: %v", got)
	}
}

// Cutting a boot's tail back past the checkpoint its successor recorded is
// detected even though the remaining rows chain correctly.
func TestVerifierDetectsTruncatedTailAcrossBoots(t *testing.T) {
	f, boots := threeBoots(t)
	truncated := boots[0][:len(boots[0])-1] // drop boot 1's final checkpoint
	report := verify(t, f.verifier(), joinBoots(truncated, boots[1], boots[2]))
	if len(report.Findings) != 1 || report.Findings[0].Kind != FindingTruncatedTail || report.Findings[0].Boot != 1 {
		t.Fatalf("truncated tail not reported: %v", report.Findings)
	}
}

// A broker holding the HMAC key cannot re-point a boot at a different
// predecessor checkpoint.
func TestVerifierDetectsForgedBootLink(t *testing.T) {
	f, boots := threeBoots(t)
	start := rows(t, boots[1][0])[0]
	start.PrevCheckpointSeq = 0
	start.PrevCheckpointMAC = rows(t, boots[0][0])[0].MAC // points at chain_start, not a checkpoint
	key, _ := f.keys.lookup(start.KeyVersion)
	start.MAC = start.computeMAC(key)
	line, _ := json.Marshal(start)
	forged := append([]string{string(line)}, boots[1][1:]...)
	got := kinds(verify(t, f.verifier(), joinBoots(boots[0], forged, boots[2])))
	found := false
	for _, k := range got {
		found = found || k == FindingBootLink
	}
	if !found {
		t.Fatalf("forged boot link accepted: %v", got)
	}
}

// A checkpoint that cannot be persisted does not count: it is recorded, and
// admission closes once the grace period passes.
func TestCheckpointPersistenceFailureCountsAsMissed(t *testing.T) {
	f := newFixture(t)
	f.boots.mu.Lock()
	f.boots.recordErr = errors.New("store unavailable")
	f.boots.mu.Unlock()
	f.clock.advance(6 * time.Minute)
	if err := f.chain.Checkpoint(context.Background()); !errors.Is(err, ErrCheckpointOverdue) {
		t.Fatalf("checkpoint error = %v", err)
	}
	if err := f.chain.Admit(); !errors.Is(err, ErrCheckpointOverdue) {
		t.Fatalf("admitted with an unpersisted checkpoint: %v", err)
	}
	got := rows(t, f.out.String())
	if last := got[len(got)-1]; last.Event != EventCheckpointFailed || last.Outcome != "store_unavailable" {
		t.Fatalf("failure not recorded: %+v", last)
	}
}
