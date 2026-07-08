package openssh

import (
	"bufio"
	"os"
	"testing"
)

func TestParseAlmaLinuxFixture(t *testing.T) {
	f, err := os.Open("../../../tests/fixtures/secure/openssh-almalinux8.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	count := 0
	invalidUsers := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}
		count++
		if ev.EventType == "ssh.auth.invalid_user" {
			invalidUsers++
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if count != 8 {
		t.Fatalf("expected 8 events, got %d", count)
	}

	if invalidUsers != 2 {
		t.Fatalf("expected 2 invalid user events, got %d", invalidUsers)
	}
}
