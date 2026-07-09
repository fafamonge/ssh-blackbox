package change

import (
	"bufio"
	"os"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
)

func TestBuildCriticalChangeFromFixture(t *testing.T) {
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
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}

		builder.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	changes := Build(builder.Records())

	if len(changes) != 1 {
		t.Fatalf("expected 1 critical change, got %d", len(changes))
	}

	change := changes[0]

	if change.Serial != "5000001" {
		t.Fatalf("expected serial 5000001, got %s", change.Serial)
	}

	if change.AuditSession != 17001 {
		t.Fatalf(
			"expected audit session 17001, got %d",
			change.AuditSession,
		)
	}

	if change.OriginalActor != "wagner" {
		t.Fatalf(
			"expected original actor wagner, got %s",
			change.OriginalActor,
		)
	}

	if change.EffectiveUser != "root" {
		t.Fatalf(
			"expected effective user root, got %s",
			change.EffectiveUser,
		)
	}

	if change.Executable != "/usr/bin/cp" {
		t.Fatalf(
			"expected executable /usr/bin/cp, got %s",
			change.Executable,
		)
	}

	if len(change.Paths) != 1 ||
		change.Paths[0] != "/root/.ssh/authorized_keys" {
		t.Fatalf(
			"expected authorized_keys path, got %v",
			change.Paths,
		)
	}

	if len(change.Keys) != 1 ||
		change.Keys[0] != "ssh_blackbox" {
		t.Fatalf(
			"expected ssh_blackbox key, got %v",
			change.Keys,
		)
	}
}
