package auditchain

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Finding kinds. Any finding means the trail cannot be trusted as complete.
const (
	FindingEdit           = "edit"            // MAC does not match the row
	FindingGap            = "gap"             // a sequence number is missing
	FindingReorder        = "reorder"         // rows appear out of sequence order
	FindingDuplicate      = "duplicate"       // a sequence number appears twice
	FindingBrokenLink     = "broken_link"     // prev does not match the previous row's MAC
	FindingNoStart        = "no_chain_start"  // the chain does not begin with chain_start
	FindingBadCheckpoint  = "bad_checkpoint"  // signature or signed head does not verify
	FindingUnsigned       = "unsigned_tail"   // rows after the last checkpoint exceed the limit
	FindingKeyUnavailable = "key_unavailable" // no HMAC key for the row's version
	FindingKeyChange      = "key_change"      // key version changed without a key_rotated row
	FindingMalformed      = "malformed"       // an audit row that cannot be parsed
	FindingMissingBoot    = "missing_boot"    // a boot the next boot links to is absent
	FindingTruncatedTail  = "truncated_tail"  // a boot ends before the checkpoint its successor links to
	FindingBootLink       = "boot_link"       // a boot's link to its predecessor does not match
	FindingMissingHead    = "missing_head"    // the export does not reach the head the store holds for a replica
	FindingUnknownBoot    = "unknown_boot"    // a boot or replica the store never issued
	FindingKeyDowngrade   = "key_downgrade"   // a boot starts under an older key than its predecessor ended on
)

type Finding struct {
	Kind    string
	Replica string
	Boot    uint64
	Seq     uint64
}

func (f Finding) String() string {
	return fmt.Sprintf("%s replica=%s boot=%d seq=%d", f.Kind, f.Replica, f.Boot, f.Seq)
}

type Report struct {
	Chains   int
	Rows     int
	Findings []Finding
}

// Verifier checks exported rows offline. HMACKey returns one key version's
// bytes; PublicKeys maps Transit key versions to their ed25519 public keys.
type Verifier struct {
	HMACKey    func(version int) ([]byte, error)
	PublicKeys map[int]ed25519.PublicKey
	// MaxUnsigned bounds the time between the last checkpoint and the last
	// row of each chain. Zero disables the check.
	MaxUnsigned time.Duration
	// SortBySeq checks each chain in sequence order instead of input order,
	// for exports that do not preserve order. Reorder findings are then
	// impossible, but a moved row still cannot hide an edit: sequence numbers
	// and links are inside the MAC.
	SortBySeq bool
	// PartialHistory accepts that each replica's earliest exported boot links
	// to a boot outside the export. Without it, every link must resolve.
	PartialHistory bool
	// Heads, when set, is the store's head for every replica (agent-vault
	// audit heads). Each replica's newest boot must be present and reach its
	// head's checkpoint, so deleting a whole boot or cutting a tail back to an
	// earlier checkpoint is a finding even for a boot with no successor. Rows
	// after the newest persisted checkpoint (at most one checkpoint interval)
	// are bounded only by MaxUnsigned.
	Heads []Head
}

// Head is one replica's current boot and newest persisted checkpoint row.
type Head struct {
	Replica       string `json:"replica"`
	Boot          uint64 `json:"boot"`
	CheckpointSeq uint64 `json:"checkpointSeq"`
	CheckpointMAC string `json:"checkpointMac"`
}

type chainKey struct {
	replica string
	boot    uint64
}

// chainState is what boot linking needs from a verified chain.
type chainState struct {
	start   *Row
	rows    map[uint64]Row
	maxSeq  uint64
	lastKey int // key version of the highest-sequence row
}

// Verify reads newline-delimited rows, either bare or wrapped as Cloud
// Logging entries ({"jsonPayload": row}). Other lines are ignored. Rows are
// checked in input order per chain, so moving a line is a reorder.
func (v Verifier) Verify(r io.Reader) (Report, error) {
	var report Report
	chains := map[chainKey][]Row{}
	var order []chainKey
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row, ok, err := parseLine([]byte(line))
		if !ok {
			continue
		}
		if err != nil {
			report.Findings = append(report.Findings, Finding{Kind: FindingMalformed})
			continue
		}
		k := chainKey{row.Replica, row.Boot}
		if _, seen := chains[k]; !seen {
			order = append(order, k)
		}
		chains[k] = append(chains[k], row)
		report.Rows++
	}
	if err := scanner.Err(); err != nil {
		return report, err
	}
	sort.Slice(order, func(i, j int) bool {
		return order[i].replica < order[j].replica || order[i].replica == order[j].replica && order[i].boot < order[j].boot
	})
	keys := map[int][]byte{}
	states := map[chainKey]chainState{}
	for _, k := range order {
		report.Chains++
		if v.SortBySeq {
			rows := chains[k]
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
		}
		findings, state := v.verifyChain(k, chains[k], keys)
		report.Findings = append(report.Findings, findings...)
		states[k] = state
	}
	earliest := map[string]uint64{}
	for _, k := range order {
		if b, ok := earliest[k.replica]; !ok || k.boot < b {
			earliest[k.replica] = k.boot
		}
	}
	for _, k := range order {
		report.Findings = append(report.Findings, v.verifyBootLink(k, states, earliest[k.replica] == k.boot)...)
	}
	if v.Heads != nil {
		report.Findings = append(report.Findings, v.verifyHeads(order, states)...)
	}
	return report, nil
}

// verifyHeads checks the export against the store: every replica's newest
// boot is present and reaches its persisted checkpoint, and no exported boot
// is newer than the store's (or belongs to a replica the store never saw).
func (v Verifier) verifyHeads(order []chainKey, states map[chainKey]chainState) []Finding {
	var findings []Finding
	heads := map[string]Head{}
	for _, head := range v.Heads {
		heads[head.Replica] = head
		state, ok := states[chainKey{head.Replica, head.Boot}]
		if !ok {
			findings = append(findings, Finding{Kind: FindingMissingHead, Replica: head.Replica, Boot: head.Boot})
			continue
		}
		if head.CheckpointMAC == "" {
			continue // the boot has not persisted a checkpoint yet
		}
		row, ok := state.rows[head.CheckpointSeq]
		if !ok || row.Event != EventCheckpoint || !hmac.Equal([]byte(row.MAC), []byte(head.CheckpointMAC)) {
			findings = append(findings, Finding{Kind: FindingMissingHead, Replica: head.Replica, Boot: head.Boot, Seq: head.CheckpointSeq})
		}
	}
	for _, k := range order {
		if head, ok := heads[k.replica]; !ok || k.boot > head.Boot {
			findings = append(findings, Finding{Kind: FindingUnknownBoot, Replica: k.replica, Boot: k.boot})
		}
	}
	return findings
}

// verifyBootLink checks that boot N's first row names boot N-1 and that boot
// N-1 is present and reaches the checkpoint row boot N recorded for it.
func (v Verifier) verifyBootLink(k chainKey, states map[chainKey]chainState, earliest bool) []Finding {
	start := states[k].start
	if start == nil {
		return nil // already reported as no_chain_start
	}
	finding := func(kind string, boot, seq uint64) []Finding {
		return []Finding{{Kind: kind, Replica: k.replica, Boot: boot, Seq: seq}}
	}
	if k.boot == 0 || start.PrevBoot != k.boot-1 || (start.PrevBoot == 0 && (start.PrevCheckpointSeq != 0 || start.PrevCheckpointMAC != "")) {
		return finding(FindingBootLink, k.boot, 0)
	}
	if start.PrevBoot == 0 {
		return nil
	}
	previous, ok := states[chainKey{k.replica, start.PrevBoot}]
	if !ok {
		if earliest && v.PartialHistory {
			return nil
		}
		return finding(FindingMissingBoot, start.PrevBoot, 0)
	}
	// A boot never starts under an older key than its predecessor ended on, so
	// a retired key cannot fabricate a later boot.
	if start.KeyVersion < previous.lastKey {
		return finding(FindingKeyDowngrade, k.boot, 0)
	}
	if start.PrevCheckpointMAC == "" {
		return nil // the previous boot never persisted a checkpoint
	}
	linked, ok := previous.rows[start.PrevCheckpointSeq]
	switch {
	case !ok && start.PrevCheckpointSeq > previous.maxSeq:
		return finding(FindingTruncatedTail, start.PrevBoot, previous.maxSeq+1)
	case !ok:
		return nil // the missing row is already reported as a gap
	case linked.Event != EventCheckpoint || !hmac.Equal([]byte(linked.MAC), []byte(start.PrevCheckpointMAC)):
		return finding(FindingBootLink, k.boot, 0)
	}
	return nil
}

func parseLine(line []byte) (Row, bool, error) {
	var probe struct {
		Type        string          `json:"type"`
		JSONPayload json.RawMessage `json:"jsonPayload"`
	}
	if json.Unmarshal(line, &probe) != nil {
		return Row{}, false, nil
	}
	payload := line
	if probe.Type != RowType {
		if len(probe.JSONPayload) == 0 {
			return Row{}, false, nil
		}
		var inner struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(probe.JSONPayload, &inner) != nil || inner.Type != RowType {
			return Row{}, false, nil
		}
		payload = probe.JSONPayload
	}
	var row Row
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&row); err != nil {
		return Row{}, true, err
	}
	return row, true, nil
}

func (v Verifier) verifyChain(k chainKey, rows []Row, keys map[int][]byte) ([]Finding, chainState) {
	var findings []Finding
	state := chainState{rows: map[uint64]Row{}}
	add := func(kind string, seq uint64) {
		findings = append(findings, Finding{Kind: kind, Replica: k.replica, Boot: k.boot, Seq: seq})
	}
	macs := map[uint64]string{}
	var prev *Row
	var lastSigned time.Time
	signedAny := false
	for i := range rows {
		row := rows[i]
		key, ok := keys[row.KeyVersion]
		if !ok && v.HMACKey != nil {
			if fetched, err := v.HMACKey(row.KeyVersion); err == nil {
				key, ok = fetched, true
				keys[row.KeyVersion] = fetched
			}
		}
		switch {
		case !ok:
			add(FindingKeyUnavailable, row.Seq)
		case !hmac.Equal([]byte(row.computeMAC(key)), []byte(row.MAC)):
			add(FindingEdit, row.Seq)
		case row.MACVersion != 0 && (row.MACVersion < 2 || row.MACVersion > MACVersionCurrent):
			// An unknown version is never trusted.
			add(FindingEdit, row.Seq)
		case row.MACVersion < 2 && row.v2Only():
			// Fields a v1 MAC does not cover cannot be trusted on a v1 row.
			add(FindingEdit, row.Seq)
		case row.MACVersion < 3 && row.v3Only():
			add(FindingEdit, row.Seq)
		case row.MACVersion < 4 && row.v4Only():
			add(FindingEdit, row.Seq)
		case row.MACVersion < 5 && row.v5Only():
			add(FindingEdit, row.Seq)
		case prev != nil && row.MACVersion < prev.MACVersion:
			// A chain never steps down to a weaker MAC.
			add(FindingEdit, row.Seq)
		}
		if prev == nil {
			if row.Seq != 0 || row.Event != EventChainStart || row.Prev != "" {
				add(FindingNoStart, row.Seq)
			}
		} else {
			switch {
			case row.Seq == prev.Seq:
				add(FindingDuplicate, row.Seq)
			case row.Seq < prev.Seq:
				add(FindingReorder, row.Seq)
			case row.Seq > prev.Seq+1:
				add(FindingGap, prev.Seq+1)
			}
			if row.Seq == prev.Seq+1 && row.Prev != prev.MAC {
				add(FindingBrokenLink, row.Seq)
			}
			// Only a rotation row may move to a newer key, so a leaked old key
			// cannot be used to append rows after a rotation.
			rotated := row.Event == EventKeyRotated && row.PrevKey == prev.KeyVersion && row.KeyVersion > row.PrevKey
			if row.KeyVersion != prev.KeyVersion && !rotated || row.Event == EventKeyRotated && !rotated {
				add(FindingKeyChange, row.Seq)
			}
		}
		if row.Event == EventCheckpoint {
			if !v.checkpointValid(row, macs) {
				add(FindingBadCheckpoint, row.Seq)
			} else if t, err := time.Parse(time.RFC3339Nano, row.Time); err == nil {
				lastSigned, signedAny = t, true
			}
		}
		if _, dup := macs[row.Seq]; !dup {
			macs[row.Seq] = row.MAC
			state.rows[row.Seq] = row
		}
		if row.Seq == 0 && row.Event == EventChainStart && state.start == nil {
			state.start = &rows[i]
		}
		if row.Seq >= state.maxSeq {
			state.maxSeq, state.lastKey = row.Seq, row.KeyVersion
		}
		if prev == nil || row.Seq > prev.Seq {
			prev = &rows[i]
		}
	}
	// A boot signs a checkpoint as it starts, so one with none at all is
	// unsigned however short: anyone holding a key could have written it.
	switch {
	case prev == nil:
	case !signedAny:
		add(FindingUnsigned, prev.Seq)
	case v.MaxUnsigned > 0:
		last, err := time.Parse(time.RFC3339Nano, prev.Time)
		if err != nil || last.Sub(lastSigned) > v.MaxUnsigned {
			add(FindingUnsigned, prev.Seq)
		}
	}
	return findings, state
}

func (v Verifier) checkpointValid(row Row, macs map[uint64]string) bool {
	signed, ok := macs[row.SignedSeq]
	if !ok || row.SignedSeq >= row.Seq || !hmac.Equal([]byte(signed), []byte(row.SignedMAC)) {
		return false
	}
	version, signature, ok := parseTransitSignature(row.Signature)
	if !ok {
		return false
	}
	public, ok := v.PublicKeys[version]
	if !ok {
		return false
	}
	return ed25519.Verify(public, checkpointInput(row.Replica, row.Boot, row.SignedSeq, row.SignedMAC), signature)
}

func parseTransitSignature(s string) (int, []byte, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return 0, nil, false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	if err != nil || version < 1 {
		return 0, nil, false
	}
	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, false
	}
	return version, signature, true
}
