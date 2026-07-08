package evidence_set

import (
	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/evidence"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

type EvidenceSet struct {
	SchemaVersion      string                     `json:"schema_version"`
	SSHSessions        []session.SSHSession       `json:"ssh_sessions,omitempty"`
	AuditSessions      []correlation.AuditSession `json:"audit_sessions,omitempty"`
	UncorrelatedEvents []evidence.Event           `json:"uncorrelated_events,omitempty"`
}

func New() EvidenceSet {
	return EvidenceSet{
		SchemaVersion:      "0.1",
		SSHSessions:        []session.SSHSession{},
		AuditSessions:      []correlation.AuditSession{},
		UncorrelatedEvents: []evidence.Event{},
	}
}
