package openssh

import (
	"bufio"
	"os"
	"testing"
)

func TestParseAlmaLinuxFixture(t *testing.T) {
	result := parseFixture(t, "../../../tests/fixtures/secure/openssh-almalinux8.log")

	if result.count != 8 {
		t.Fatalf("expected 8 events, got %d", result.count)
	}

	if result.byType["ssh.auth.invalid_user"] != 2 {
		t.Fatalf("expected 2 invalid user events, got %d", result.byType["ssh.auth.invalid_user"])
	}
}

func TestParseSuccessFixture(t *testing.T) {
	result := parseFixture(t, "../../../tests/fixtures/secure/openssh-success.log")

	expected := map[string]int{
		"ssh.auth.accepted_publickey":   1,
		"ssh.session.opened":            1,
		"ssh.session.subsystem":         1,
		"ssh.session.closed":            1,
		"ssh.auth.failed_password":      1,
		"ssh.session.connection_closed": 1,
	}

	for eventType, want := range expected {
		if result.byType[eventType] != want {
			t.Fatalf("expected %d events of type %s, got %d", want, eventType, result.byType[eventType])
		}
	}
}

type fixtureResult struct {
	count  int
	byType map[string]int
}

func parseFixture(t *testing.T, path string) fixtureResult {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	result := fixtureResult{
		byType: map[string]int{},
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}

		result.count++
		result.byType[ev.EventType]++
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return result
}

func TestParseSSHDSessionProcessName(t *testing.T) {
	line := "Jul  9 23:20:29 bavaria sshd-session[3902454]: Accepted publickey for wagner from 190.5.138.94 port 57654 ssh2: ED25519 SHA256:UH+BxqPfMEmQI1hU2dDFHLM/wF6gMkrNKUaJmV/9coY"

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected sshd-session line to match")
	}
	if ev.EventType != "ssh.auth.accepted_publickey" {
		t.Fatalf("expected accepted publickey event, got %s", ev.EventType)
	}
	if ev.PID != 3902454 {
		t.Fatalf("expected pid 3902454, got %d", ev.PID)
	}
	if ev.Actor["username"] != "wagner" {
		t.Fatalf("expected username wagner, got %v", ev.Actor["username"])
	}
	if ev.Actor["ip"] != "190.5.138.94" {
		t.Fatalf("expected ip 190.5.138.94, got %v", ev.Actor["ip"])
	}
}
