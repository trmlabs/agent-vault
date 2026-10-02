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
)

type Finding struct {
	Kind    string
	Replica string
	Boot    string
	Seq     uint64
}

func (f Finding) String() string {
	return fmt.Sprintf("%s replica=%s boot=%s seq=%d", f.Kind, f.Replica, f.Boot, f.Seq)
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
}

type chainKey struct{ replica, boot string }

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
	for _, k := range order {
		report.Chains++
		if v.SortBySeq {
			rows := chains[k]
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
		}
		report.Findings = append(report.Findings, v.verifyChain(k, chains[k], keys)...)
	}
	return report, nil
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

func (v Verifier) verifyChain(k chainKey, rows []Row, keys map[int][]byte) []Finding {
	var findings []Finding
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
		}
		if prev == nil || row.Seq > prev.Seq {
			prev = &rows[i]
		}
	}
	if v.MaxUnsigned > 0 && prev != nil {
		if !signedAny {
			lastSigned, _ = time.Parse(time.RFC3339Nano, rows[0].Time)
		}
		last, err := time.Parse(time.RFC3339Nano, prev.Time)
		if err != nil || lastSigned.IsZero() || last.Sub(lastSigned) > v.MaxUnsigned {
			add(FindingUnsigned, prev.Seq)
		}
	}
	return findings
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
