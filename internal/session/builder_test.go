package session

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

func TestBuilderGroupsEventsByPID(t *testing.T) {
	b := NewBuilder()

	b.AddEvent(evidence.Event{
		EventType:    "ssh.auth.invalid_user",
		TimestampRaw: "Jul  8 10:00:01",
		PID:          1234,
		Actor: map[string]any{
			"username": "admin",
			"ip":       "203.0.113.10",
			"port":     51234,
		},
	})

	b.AddEvent(evidence.Event{
		EventType:    "ssh.session.disconnected",
		TimestampRaw: "Jul  8 10:00:03",
		PID:          1234,
		Actor: map[string]any{
			"username": "admin",
			"ip":       "203.0.113.10",
			"port":     51234,
		},
	})

	sessions := b.Sessions()

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	if sessions[0].EventCount != 2 {
		t.Fatalf("expected 2 events, got %d", sessions[0].EventCount)
	}

	if sessions[0].User != "admin" {
		t.Fatalf("expected user admin, got %s", sessions[0].User)
	}

	if sessions[0].RemoteIP != "203.0.113.10" {
		t.Fatalf("expected remote ip 203.0.113.10, got %s", sessions[0].RemoteIP)
	}

	if len(sessions[0].Events) != 2 {
		t.Fatalf("expected session to keep 2 full events, got %d", len(sessions[0].Events))
	}

	if sessions[0].Events[0].EventType != "ssh.auth.invalid_user" {
		t.Fatalf("expected first event type ssh.auth.invalid_user, got %s", sessions[0].Events[0].EventType)
	}

}
