package change

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
)

type CriticalChange struct {
	Serial        string   `json:"serial"`
	AuditSession  int      `json:"audit_session,omitempty"`
	OriginalActor string   `json:"original_actor,omitempty"`
	EffectiveUser string   `json:"effective_user,omitempty"`
	Executable    string   `json:"executable,omitempty"`
	Command       string   `json:"command,omitempty"`
	PID           int      `json:"pid,omitempty"`
	ParentPID     int      `json:"parent_pid,omitempty"`
	Terminal      string   `json:"terminal,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	Keys          []string `json:"keys,omitempty"`
}

func Build(records []auditrecord.Record) []CriticalChange {
	result := make([]CriticalChange, 0)

	for _, record := range records {
		if len(record.Paths) == 0 || len(record.Keys) == 0 {
			continue
		}

		change := CriticalChange{
			Serial:        record.Serial,
			AuditSession:  record.SessionID,
			OriginalActor: record.AUID,
			EffectiveUser: record.EUID,
			Executable:    record.Executable,
			Command:       record.Command,
			PID:           record.PID,
			ParentPID:     record.ParentPID,
			Terminal:      record.Terminal,
			Paths:         append([]string(nil), record.Paths...),
			Keys:          append([]string(nil), record.Keys...),
		}

		result = append(result, change)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Serial < result[j].Serial
	})

	return result
}
