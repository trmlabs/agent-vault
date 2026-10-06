package taskrelay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

type relayAudit struct {
	mu     sync.Mutex
	file   *os.File
	config FixedConfig
	// stdout: a shared proxy may write its rows to standard output, for the
	// logging pipeline, with no file to sync.
	stdout bool
}

// StdoutAudit is the audit file a shared proxy may name to write its rows to
// standard output.
const StdoutAudit = "/dev/stdout"

func newAudit(c FixedConfig) (*relayAudit, error) {
	return openAudit(c, syncAuditDirectory)
}

func openAudit(c FixedConfig, syncDirectory func(string) error) (*relayAudit, error) {
	if c.Shared != nil && c.AuditFile == StdoutAudit {
		a := &relayAudit{file: os.Stdout, config: c, stdout: true}
		if e := a.record("relay", "mapping"); e != nil {
			return nil, e
		}
		return a, nil
	}
	// Paired and sidecar relays keep a durable, synced file.
	if c.AuditFile == StdoutAudit {
		return nil, errDenied
	}
	f, e := os.OpenFile(c.AuditFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return nil, errDenied
	}
	if syncDirectory(filepath.Dir(c.AuditFile)) != nil {
		_ = f.Close()
		return nil, errDenied
	}
	a := &relayAudit{file: f, config: c}
	if e = a.record("relay", "mapping"); e != nil {
		_ = f.Close()
		return nil, e
	}
	return a, nil
}

// Persist creation of the journal's directory entry before acknowledging any
// mapping. The backing persistent volume must honor file and directory fsync.
func syncAuditDirectory(path string) error {
	directory, e := os.Open(path)
	if e != nil {
		return errDenied
	}
	defer func() { _ = directory.Close() }()
	if directory.Sync() != nil {
		return errDenied
	}
	return nil
}
func (a *relayAudit) record(protocol, outcome string) error {
	return a.recordAgent(protocol, outcome, nil)
}

// recordAgent writes one row; a shared proxy's admissions name the agent Pod,
// its namespace and the images it pulled.
func (a *relayAudit) recordAgent(protocol, outcome string, agent *workloadidentity.Attestation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row := struct {
		Time       time.Time `json:"time"`
		TaskID     string    `json:"taskID"`
		SandboxUID string    `json:"sandboxUID"`
		Protocol   string    `json:"protocol"`
		Outcome    string    `json:"outcome"`
		PodUID     string    `json:"podUID,omitempty"`
		Namespace  string    `json:"namespace,omitempty"`
		Images     []string  `json:"images,omitempty"`
		Requester  string    `json:"requester,omitempty"`
	}{Time: time.Now().UTC(), TaskID: a.config.TaskID, SandboxUID: a.config.Sandbox.UID, Protocol: protocol, Outcome: outcome}
	if agent != nil {
		row.SandboxUID, row.PodUID, row.Namespace, row.Images, row.Requester = agent.OwnerUID, agent.PodUID, agent.Namespace, agent.Images, agent.Requester
	}
	if json.NewEncoder(a.file).Encode(row) != nil || (!a.stdout && a.file.Sync() != nil) {
		return errDenied
	}
	return nil
}
