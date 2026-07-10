package change

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
)

const (
	OperationCreate         = "create"
	OperationModify         = "modify"
	OperationMetadataChange = "metadata_change"
	OperationDelete         = "delete"
	OperationUnknown        = "unknown"
)

type CriticalChange struct {
	Serial        string              `json:"serial"`
	Operation     string              `json:"operation,omitempty"`
	AuditSession  int                 `json:"audit_session,omitempty"`
	OriginalActor string              `json:"original_actor,omitempty"`
	EffectiveUser string              `json:"effective_user,omitempty"`
	Executable    string              `json:"executable,omitempty"`
	Command       string              `json:"command,omitempty"`
	PID           int                 `json:"pid,omitempty"`
	ParentPID     int                 `json:"parent_pid,omitempty"`
	Terminal      string              `json:"terminal,omitempty"`
	Paths         []string            `json:"paths,omitempty"`
	PathTypes     map[string][]string `json:"path_types,omitempty"`
	Keys          []string            `json:"keys,omitempty"`
}

func Build(records []auditrecord.Record) []CriticalChange {
	result := make([]CriticalChange, 0)

	for _, record := range records {
		if len(record.Paths) == 0 || !hasCriticalWatchKey(record.Keys) {
			continue
		}

		change := CriticalChange{
			Serial:        record.Serial,
			Operation:     classifyOperation(record),
			AuditSession:  record.SessionID,
			OriginalActor: record.AUID,
			EffectiveUser: record.EUID,
			Executable:    record.Executable,
			Command:       record.Command,
			PID:           record.PID,
			ParentPID:     record.ParentPID,
			Terminal:      record.Terminal,
			Paths:         append([]string(nil), record.Paths...),
			PathTypes:     clonePathTypes(record.PathTypes),
			Keys:          append([]string(nil), record.Keys...),
		}

		result = append(result, change)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Serial < result[j].Serial
	})

	return result
}

func hasCriticalWatchKey(keys []string) bool {
	for _, key := range keys {
		switch key {
		case "", "root_exec", "root_exec_user":
			continue
		default:
			return true
		}
	}

	return false
}

func classifyOperation(record auditrecord.Record) string {
	if recordHasPathType(record, "DELETE") {
		return OperationDelete
	}

	if recordHasPathType(record, "CREATE") {
		return OperationCreate
	}

	switch record.Syscall {
	case "chmod", "fchmod", "fchmodat":
		return OperationMetadataChange

	case "write", "pwrite64", "open", "openat", "truncate", "ftruncate":
		return OperationModify

	default:
		return OperationUnknown
	}
}

func recordHasPathType(record auditrecord.Record, expected string) bool {
	for _, pathTypes := range record.PathTypes {
		for _, pathType := range pathTypes {
			if pathType == expected {
				return true
			}
		}
	}

	return false
}

func clonePathTypes(source map[string][]string) map[string][]string {
	if len(source) == 0 {
		return nil
	}

	result := make(map[string][]string, len(source))

	for path, pathTypes := range source {
		result[path] = append([]string(nil), pathTypes...)
	}

	return result
}
