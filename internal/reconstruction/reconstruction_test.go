package reconstruction

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/change"
	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/evidence"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

func TestBuildReconstruction(t *testing.T) {
	sshSessions := []session.SSHSession{
		{
			SessionID:  "ssh-session-1",
			User:       "wagner",
			RemoteIP:   "190.5.138.94",
			RemotePort: 62133,
			StartRaw:   "Jul  8 18:00:28",
			EndRaw:     "Jul  8 18:00:28",
			Events: []evidence.Event{
				{
					EventType: "ssh.auth.accepted_publickey",
					Context: map[string]any{
						"auth_method": "publickey",
					},
				},
			},
		},
	}

	auditSessions := []correlation.AuditSession{
		{
			SessionID:      16695,
			AUID:           "wagner",
			EffectiveUsers: []string{"root"},
			Terminals:      []string{"/dev/pts/4", "pts5"},
			Events: []evidence.Event{
				{
					EventType:    "auditd.syscall",
					TimestampRaw: "07/08/2026 18:00:48.134:3528891",
					PID:          2634931,
					Actor: map[string]any{
						"auid": "wagner",
						"euid": "root",
						"exe":  "/usr/bin/touch",
						"comm": "touch",
						"tty":  "pts5",
					},
					Context: map[string]any{
						"syscall": "execve",
						"ppid":    2634891,
					},
				},
			},
		},
	}

	links := []link.EvidenceLink{
		{
			SSHSessionID:   "ssh-session-1",
			AuditSessionID: 16695,
			Reasons: []string{
				link.ReasonActorIdentityMatch,
				link.ReasonRemoteAddressMatch,
			},
		},
	}

	criticalPath := "/root/.ssh/test.tmp"

	criticalChanges := []change.CriticalChange{
		{
			Serial:       "3528892",
			AuditSession: 16695,
			Operation:    change.OperationCreate,
			Paths:        []string{"/root/.ssh/", criticalPath},
			PathTypes: map[string][]string{
				"/root/.ssh/": {"PARENT"},
				criticalPath:  {"CREATE"},
			},
		},
	}

	result := Build(
		sshSessions,
		auditSessions,
		links,
		criticalChanges,
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 reconstruction, got %d", len(result))
	}

	r := result[0]

	if r.User != "wagner" {
		t.Fatalf("expected user wagner, got %s", r.User)
	}

	if r.AuthMethod != "publickey" {
		t.Fatalf("expected publickey auth, got %s", r.AuthMethod)
	}

	if r.AuditSessionID != 16695 {
		t.Fatalf("expected audit session 16695, got %d", r.AuditSessionID)
	}

	if len(r.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(r.Executions))
	}

	if r.Executions[0].Executable != "/usr/bin/touch" {
		t.Fatalf(
			"expected /usr/bin/touch, got %s",
			r.Executions[0].Executable,
		)
	}

	if r.Executions[0].OriginalActor != "wagner" {
		t.Fatalf(
			"expected original actor wagner, got %s",
			r.Executions[0].OriginalActor,
		)
	}

	if r.Executions[0].EffectiveUser != "root" {
		t.Fatalf(
			"expected effective user root, got %s",
			r.Executions[0].EffectiveUser,
		)
	}

	if len(r.CriticalChanges) != 1 {
		t.Fatalf(
			"expected 1 critical change, got %d",
			len(r.CriticalChanges),
		)
	}

	if len(r.FileActivities) != 1 {
		t.Fatalf(
			"expected 1 file activity, got %d",
			len(r.FileActivities),
		)
	}

	if r.FileActivities[0].Path != criticalPath {
		t.Fatalf(
			"expected file activity path %s, got %s",
			criticalPath,
			r.FileActivities[0].Path,
		)
	}

	if len(r.FileActivities[0].Changes) != 1 {
		t.Fatalf(
			"expected 1 change in file activity, got %d",
			len(r.FileActivities[0].Changes),
		)
	}

	if r.FileActivities[0].Changes[0].Serial != "3528892" {
		t.Fatalf(
			"expected serial 3528892, got %s",
			r.FileActivities[0].Changes[0].Serial,
		)
	}
}

func TestBuildIgnoresBrokenLinks(t *testing.T) {
	links := []link.EvidenceLink{
		{
			SSHSessionID:   "missing-ssh",
			AuditSessionID: 99999,
		},
	}

	result := Build(nil, nil, links, nil)

	if len(result) != 0 {
		t.Fatalf("expected no reconstructions, got %d", len(result))
	}
}
