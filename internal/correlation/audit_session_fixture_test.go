package correlation

import (
	"bufio"
	"os"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
)

func TestAuditSessionBuilderFromFixture(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/bavaria-ssh-session.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	b := NewAuditSessionBuilder()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("expected line to match: %s", scanner.Text())
		}

		b.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	sessions := b.Sessions()

	if len(sessions) != 1 {
		t.Fatalf("expected 1 audit session, got %d", len(sessions))
	}

	if sessions[0].SessionID != 16695 {
		t.Fatalf("expected session id 16695, got %d", sessions[0].SessionID)
	}

	if sessions[0].AUID != "wagner" {
		t.Fatalf("expected auid wagner, got %s", sessions[0].AUID)
	}

	if sessions[0].EventCount != 3 {
		t.Fatalf("expected 3 events, got %d", sessions[0].EventCount)
	}

	if sessions[0].StartRaw != "07/08/2026 18:00:28.674:3528770" {
		t.Fatalf("expected start_raw from login event, got %s", sessions[0].StartRaw)
	}

	if sessions[0].EndRaw != "07/08/2026 18:00:48.136:3528892" {
		t.Fatalf("expected end_raw from last syscall event, got %s", sessions[0].EndRaw)
	}

	if sessions[0].Events[0].EventType != "auditd.user_login" {
		t.Fatalf("expected first event to be auditd.user_login, got %s", sessions[0].Events[0].EventType)
	}
}
