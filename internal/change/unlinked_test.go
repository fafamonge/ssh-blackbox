package change

import (
	"bufio"
	"os"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
)

func TestCriticalChangeExistsWithoutSSHLink(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/critical-file-change.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	builder := auditrecord.NewBuilder()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			builder.AddEvent(*ev)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	changes := Build(builder.Records())

	if len(changes) != 1 {
		t.Fatalf("expected 1 preserved critical change, got %d", len(changes))
	}

	if changes[0].AuditSession != 17001 {
		t.Fatalf("expected audit session 17001, got %d", changes[0].AuditSession)
	}

	if changes[0].OriginalActor != "wagner" {
		t.Fatalf("expected original actor wagner, got %s", changes[0].OriginalActor)
	}
}
