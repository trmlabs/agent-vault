package taskrelay

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type relayAudit struct {
	mu     sync.Mutex
	file   *os.File
	config FixedConfig
}

func newAudit(c FixedConfig) (*relayAudit, error) {
	f, e := os.OpenFile(c.AuditFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return nil, errDenied
	}
	a := &relayAudit{file: f, config: c}
	if e = a.record("relay", "mapping"); e != nil {
		_ = f.Close()
		return nil, e
	}
	return a, nil
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
