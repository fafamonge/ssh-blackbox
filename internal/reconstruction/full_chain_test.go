package reconstruction

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/change"
	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/evidence"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
	"github.com/fafamonge/ssh-blackbox/internal/parser/openssh"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

func TestFullLinkedCriticalChangeChain(t *testing.T) {
	sshEvents := parseSSHFixture(t, "../../tests/fixtures/secure/bavaria-ssh-session.log")
	auditEvents := parseAuditFixture(t, "../../tests/fixtures/auditd/full-linked-critical-change.log")

	sshBuilder := session.NewBuilder()
	for _, ev := range sshEvents {
		sshBuilder.AddEvent(ev)
	}
	sshSessions := sshBuilder.Sessions()

	auditBuilder := correlation.NewAuditSessionBuilder()
	recordBuilder := auditrecord.NewBuilder()

	for _, ev := range auditEvents {
		auditBuilder.AddEvent(ev)
		recordBuilder.AddEvent(ev)
	}

	auditSessions := auditBuilder.Sessions()
	criticalChanges := change.Build(recordBuilder.Records())
	evidenceLinks := link.Build(sshSessions, auditSessions)

	result := Build(
		sshSessions,
		auditSessions,
		evidenceLinks,
		criticalChanges,
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 reconstruction, got %d", len(result))
	}

	r := result[0]

	if r.User != "wagner" {
		t.Fatalf("expected user wagner, got %s", r.User)
	}

	if r.RemoteIP != "190.5.138.94" {
		t.Fatalf("expected remote IP 190.5.138.94, got %s", r.RemoteIP)
	}

	if r.AuditSessionID != 16695 {
		t.Fatalf("expected audit session 16695, got %d", r.AuditSessionID)
	}

	if len(r.CriticalChanges) != 1 {
		t.Fatalf("expected 1 critical change, got %d", len(r.CriticalChanges))
	}

	criticalChange := r.CriticalChanges[0]

	if criticalChange.OriginalActor != "wagner" {
		t.Fatalf(
			"expected critical change actor wagner, got %s",
			criticalChange.OriginalActor,
		)
	}

	if len(criticalChange.Paths) != 1 ||
		criticalChange.Paths[0] != "/root/.ssh/authorized_keys" {
		t.Fatalf(
			"expected authorized_keys critical path, got %v",
			criticalChange.Paths,
		)
	}

	var output strings.Builder

	if err := WriteText(&output, result, nil); err != nil {
		t.Fatal(err)
	}

	text := output.String()

	required := []string{
		"Actor:        wagner",
		"Remote:       190.5.138.94:62133",
		"Audit session: 16695",
		"CRITICAL FILE CHANGES",
		"actor=wagner",
		"euid=root",
		"exe=/usr/bin/cp",
		"paths=/root/.ssh/authorized_keys",
		"actor_identity_match",
		"remote_address_match",
	}

	for _, expected := range required {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected output to contain %q\noutput:\n%s", expected, text)
		}
	}
}

func parseSSHFixture(t *testing.T, path string) []evidence.Event {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []evidence.Event
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := openssh.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			events = append(events, *ev)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return events
}

func parseAuditFixture(t *testing.T, path string) []evidence.Event {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []evidence.Event
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			events = append(events, *ev)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return events
}
