package auditrecord

import (
	"bufio"
	"os"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
)

func TestBuildAuditRecordFromCriticalFileFixture(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/critical-file-change.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	b := NewBuilder()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}
		b.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	records := b.Records()

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Serial != "5000001" {
		t.Fatalf("expected serial 5000001, got %s", records[0].Serial)
	}

	if len(records[0].Paths) != 1 || records[0].Paths[0] != "/root/.ssh/authorized_keys" {
		t.Fatalf("expected authorized_keys path, got %v", records[0].Paths)
	}

	if len(records[0].Keys) != 1 || records[0].Keys[0] != "ssh_blackbox" {
		t.Fatalf("expected ssh_blackbox key, got %v", records[0].Keys)
	}
}

func TestBuildPreservesAuditOperationSemantics(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/bavaria-real-ses-16949.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	b := NewBuilder()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			b.AddEvent(*ev)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	records := b.Records()

	bySerial := make(map[string]Record, len(records))
	for _, record := range records {
		bySerial[record.Serial] = record
	}

	created := bySerial["4104131"]

	if created.Syscall != "openat" {
		t.Fatalf("expected syscall openat, got %q", created.Syscall)
	}

	if created.Success != "yes" {
		t.Fatalf("expected success yes, got %q", created.Success)
	}

	path := "/root/.ssh/sshbb_20260709_232012.tmp"
	pathTypes := created.PathTypes[path]

	if len(pathTypes) != 1 || pathTypes[0] != "CREATE" {
		t.Fatalf("expected CREATE path type for %s, got %v", path, pathTypes)
	}

	deleted := bySerial["4104136"]

	if deleted.Syscall != "unlinkat" {
		t.Fatalf("expected syscall unlinkat, got %q", deleted.Syscall)
	}

	pathTypes = deleted.PathTypes[path]

	if len(pathTypes) != 1 || pathTypes[0] != "DELETE" {
		t.Fatalf("expected DELETE path type for %s, got %v", path, pathTypes)
	}
}
