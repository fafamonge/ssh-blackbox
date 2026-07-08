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

	if sessions[0].EventCount != 4 {
		t.Fatalf("expected 4 events, got %d", sessions[0].EventCount)
	}

	if sessions[0].StartRaw != "07/08/2026 18:00:28.674:3528770" {
		t.Fatalf("expected start_raw from login event, got %s", sessions[0].StartRaw)
	}

	if sessions[0].EndRaw != "07/08/2026 18:00:48.138:3528893" {
		t.Fatalf("expected end_raw from last syscall event, got %s", sessions[0].EndRaw)
	}

	if sessions[0].Events[0].EventType != "auditd.user_login" {
		t.Fatalf("expected first event to be auditd.user_login, got %s", sessions[0].Events[0].EventType)
	}

	if sessions[0].RemoteAddr != "190.5.138.94" {
		t.Fatalf("expected remote addr 190.5.138.94, got %s", sessions[0].RemoteAddr)
	}

	if len(sessions[0].Terminals) != 2 {
		t.Fatalf("expected 2 terminals, got %v", sessions[0].Terminals)
	}

	if sessions[0].Terminals[0] != "/dev/pts/4" {
		t.Fatalf("expected first terminal /dev/pts/4, got %s", sessions[0].Terminals[0])
	}

	if sessions[0].Terminals[1] != "pts5" {
		t.Fatalf("expected second terminal pts5, got %s", sessions[0].Terminals[1])
	}

	if len(sessions[0].EffectiveUsers) != 1 || sessions[0].EffectiveUsers[0] != "root" {
		t.Fatalf("expected effective user root, got %v", sessions[0].EffectiveUsers)
	}

	if len(sessions[0].Executables) != 3 {
		t.Fatalf("expected 3 executables, got %v", sessions[0].Executables)
	}

	if len(sessions[0].ProcessIDs) != 4 {
		t.Fatalf("expected 4 process ids, got %v", sessions[0].ProcessIDs)
	}

	if len(sessions[0].ParentPIDs) != 1 || sessions[0].ParentPIDs[0] != 2634891 {
		t.Fatalf("expected parent pid 2634891, got %v", sessions[0].ParentPIDs)
	}

	if len(sessions[0].Keys) != 1 || sessions[0].Keys[0] != "root_exec" {
		t.Fatalf("expected key root_exec, got %v", sessions[0].Keys)
	}
}
