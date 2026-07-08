package correlation

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

func TestAuditSessionBuilderGroupsByAuditSessionID(t *testing.T) {
	b := NewAuditSessionBuilder()

	b.AddEvent(auditEvent("auditd.user_login", 2634610, "wagner", 16695))
	b.AddEvent(auditEvent("auditd.syscall", 2634931, "wagner", 16695))
	b.AddEvent(auditEvent("auditd.syscall", 2634932, "wagner", 16695))

	sessions := b.Sessions()

	if len(sessions) != 1 {
		t.Fatalf("expected 1 audit session, got %d", len(sessions))
	}

	if sessions[0].SessionID != 16695 {
		t.Fatalf("expected audit session 16695, got %d", sessions[0].SessionID)
	}

	if sessions[0].AUID != "wagner" {
		t.Fatalf("expected auid wagner, got %s", sessions[0].AUID)
	}

	if sessions[0].EventCount != 3 {
		t.Fatalf("expected 3 events, got %d", sessions[0].EventCount)
	}
}

func auditEvent(eventType string, pid int, auid string, ses int) evidence.Event {
	return evidence.Event{
		EventType: eventType,
		PID:       pid,
		Actor: map[string]any{
			"auid": auid,
			"ses":  ses,
		},
	}
}
