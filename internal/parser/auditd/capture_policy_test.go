package auditd

import (
	"bufio"
	"os"
	"testing"
)

func TestParseAttributedRootExecFixture(t *testing.T) {
	f, err := os.Open("../../../tests/fixtures/auditd/attributed-root-exec.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events int
	var syscalls int

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}

		events++

		if ev.EventType == "auditd.syscall" {
			syscalls++

			if ev.Context["key"] != "root_exec_user" {
				t.Fatalf("expected key root_exec_user, got %v", ev.Context["key"])
			}

			if ev.Actor["auid"] != "wagner" {
				t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
			}

			if ev.Actor["euid"] != "root" {
				t.Fatalf("expected euid root, got %v", ev.Actor["euid"])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if events != 3 {
		t.Fatalf("expected 3 events, got %d", events)
	}

	if syscalls != 2 {
		t.Fatalf("expected 2 syscall events, got %d", syscalls)
	}
}
