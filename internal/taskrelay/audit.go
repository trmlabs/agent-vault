package taskrelay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type relayAudit struct {
	mu     sync.Mutex
	file   *os.File
	config FixedConfig
}

func newAudit(c FixedConfig) (*relayAudit, error) {
	return openAudit(c, syncAuditDirectory)
}

func openAudit(c FixedConfig, syncDirectory func(string) error) (*relayAudit, error) {
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
	a.mu.Lock()
	defer a.mu.Unlock()
	row := struct {
		Time       time.Time `json:"time"`
		TaskID     string    `json:"taskID"`
		SandboxUID string    `json:"sandboxUID"`
		Protocol   string    `json:"protocol"`
		Outcome    string    `json:"outcome"`
	}{time.Now().UTC(), a.config.TaskID, a.config.Sandbox.UID, protocol, outcome}
	if json.NewEncoder(a.file).Encode(row) != nil || a.file.Sync() != nil {
		return errDenied
	}
	return nil
}
