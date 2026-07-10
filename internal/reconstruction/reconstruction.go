package reconstruction

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/change"
	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

type RecordedExecution struct {
	TimestampRaw  string `json:"timestamp_raw,omitempty"`
	OriginalActor string `json:"original_actor,omitempty"`
	EffectiveUser string `json:"effective_user,omitempty"`
	Executable    string `json:"executable,omitempty"`
	Command       string `json:"command,omitempty"`
	PID           int    `json:"pid,omitempty"`
	ParentPID     int    `json:"parent_pid,omitempty"`
	Terminal      string `json:"terminal,omitempty"`
}

type Reconstruction struct {
	SSHSessionID    string                  `json:"ssh_session_id"`
	User            string                  `json:"user,omitempty"`
	RemoteIP        string                  `json:"remote_ip,omitempty"`
	RemotePort      int                     `json:"remote_port,omitempty"`
	AuthMethod      string                  `json:"auth_method,omitempty"`
	StartRaw        string                  `json:"start_raw,omitempty"`
	EndRaw          string                  `json:"end_raw,omitempty"`
	AuditSessionID  int                     `json:"audit_session_id,omitempty"`
	OriginalActor   string                  `json:"original_actor,omitempty"`
	EffectiveUsers  []string                `json:"effective_users,omitempty"`
	Terminals       []string                `json:"terminals,omitempty"`
	Executions      []RecordedExecution     `json:"executions,omitempty"`
	LinkReasons     []string                `json:"link_reasons,omitempty"`
	CriticalChanges []change.CriticalChange `json:"critical_changes,omitempty"`
	FileActivities  []FileActivity          `json:"file_activities,omitempty"`
}

func Build(
	sshSessions []session.SSHSession,
	auditSessions []correlation.AuditSession,
	links []link.EvidenceLink,
	criticalChanges []change.CriticalChange,
) []Reconstruction {
	sshByID := make(map[string]session.SSHSession, len(sshSessions))
	for _, sshSession := range sshSessions {
		sshByID[sshSession.SessionID] = sshSession
	}

	auditByID := make(map[int]correlation.AuditSession, len(auditSessions))
	for _, auditSession := range auditSessions {
		auditByID[auditSession.SessionID] = auditSession
	}

	result := make([]Reconstruction, 0, len(links))

	changesByAuditSession := map[int][]change.CriticalChange{}
	for _, criticalChange := range criticalChanges {
		changesByAuditSession[criticalChange.AuditSession] =
			append(changesByAuditSession[criticalChange.AuditSession], criticalChange)
	}

	for _, evidenceLink := range links {
		sshSession, sshOK := sshByID[evidenceLink.SSHSessionID]
		auditSession, auditOK := auditByID[evidenceLink.AuditSessionID]

		if !sshOK || !auditOK {
			continue
		}

		sessionCriticalChanges := append(
			[]change.CriticalChange(nil),
			changesByAuditSession[auditSession.SessionID]...,
		)

		reconstruction := Reconstruction{
			SSHSessionID:    sshSession.SessionID,
			User:            sshSession.User,
			RemoteIP:        sshSession.RemoteIP,
			RemotePort:      sshSession.RemotePort,
			AuthMethod:      authMethodFromSSHSession(sshSession),
			StartRaw:        sshSession.StartRaw,
			EndRaw:          sshSession.EndRaw,
			AuditSessionID:  auditSession.SessionID,
			OriginalActor:   auditSession.AUID,
			EffectiveUsers:  append([]string(nil), auditSession.EffectiveUsers...),
			Terminals:       append([]string(nil), auditSession.Terminals...),
			Executions:      executionsFromAuditSession(auditSession),
			LinkReasons:     append([]string(nil), evidenceLink.Reasons...),
			CriticalChanges: sessionCriticalChanges,
			FileActivities:  BuildFileActivities(sessionCriticalChanges),
		}

		result = append(result, reconstruction)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].SSHSessionID < result[j].SSHSessionID
	})

	return result
}

func authMethodFromSSHSession(sshSession session.SSHSession) string {
	for _, ev := range sshSession.Events {
		if ev.Context == nil {
			continue
		}

		value, ok := ev.Context["auth_method"]
		if !ok {
			continue
		}

		authMethod, ok := value.(string)
		if ok && authMethod != "" {
			return authMethod
		}
	}

	return ""
}

func executionsFromAuditSession(
	auditSession correlation.AuditSession,
) []RecordedExecution {
	executions := make([]RecordedExecution, 0)

	for _, ev := range auditSession.Events {
		if ev.EventType != "auditd.syscall" {
			continue
		}

		if stringFromContext(ev.Context, "syscall") != "execve" {
			continue
		}

		execution := RecordedExecution{
			TimestampRaw:  ev.TimestampRaw,
			OriginalActor: stringFromActor(ev.Actor, "auid"),
			EffectiveUser: stringFromActor(ev.Actor, "euid"),
			Executable:    stringFromActor(ev.Actor, "exe"),
			Command:       stringFromActor(ev.Actor, "comm"),
			PID:           ev.PID,
			ParentPID:     intFromContext(ev.Context, "ppid"),
			Terminal:      stringFromActor(ev.Actor, "tty"),
		}

		executions = append(executions, execution)
	}

	sort.Slice(executions, func(i, j int) bool {
		return executions[i].TimestampRaw < executions[j].TimestampRaw
	})

	return executions
}

func stringFromActor(actor map[string]any, key string) string {
	value, ok := actor[key]
	if !ok {
		return ""
	}

	result, ok := value.(string)
	if !ok {
		return ""
	}

	return result
}

func stringFromContext(context map[string]any, key string) string {
	value, ok := context[key]
	if !ok {
		return ""
	}

	result, ok := value.(string)
	if !ok {
		return ""
	}

	return result
}

func intFromContext(context map[string]any, key string) int {
	value, ok := context[key]
	if !ok {
		return 0
	}

	result, ok := value.(int)
	if !ok {
		return 0
	}

	return result
}
