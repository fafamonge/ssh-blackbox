package auditd

import (
	"bufio"
	"os"
	"testing"
)

func TestParseAuditLoginLine(t *testing.T) {
	line := `type=USER_LOGIN msg=audit(07/08/2026 18:00:28.674:3528770) : pid=2634610 uid=root auid=wagner ses=16695 msg='op=login id=wagner exe=/usr/libexec/openssh/sshd-session hostname=bavaria.hybridsync.com addr=190.5.138.94 terminal=/dev/pts/4 res=success'`

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected line to match")
	}

	if ev.EventType != "auditd.user_login" {
		t.Fatalf("expected auditd.user_login, got %s", ev.EventType)
	}

	if ev.PID != 2634610 {
		t.Fatalf("expected pid 2634610, got %d", ev.PID)
	}

	if ev.Actor["auid"] != "wagner" {
		t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
	}

	if ev.Actor["ses"] != 16695 {
		t.Fatalf("expected ses 16695, got %v", ev.Actor["ses"])
	}
}

func TestParseAuditExecveLine(t *testing.T) {
	line := `type=SYSCALL msg=audit(07/08/2026 18:00:48.134:3528891) : arch=x86_64 syscall=execve success=yes exit=0 ppid=2634891 pid=2634931 auid=wagner uid=root gid=root euid=root tty=pts5 ses=16695 comm=touch exe=/usr/bin/touch key=root_exec`

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected line to match")
	}

	if ev.EventType != "auditd.syscall" {
		t.Fatalf("expected auditd.syscall, got %s", ev.EventType)
	}

	if ev.PID != 2634931 {
		t.Fatalf("expected pid 2634931, got %d", ev.PID)
	}

	if ev.Actor["auid"] != "wagner" {
		t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
	}

	if ev.Actor["euid"] != "root" {
		t.Fatalf("expected euid root, got %v", ev.Actor["euid"])
	}

	if ev.Actor["ses"] != 16695 {
		t.Fatalf("expected ses 16695, got %v", ev.Actor["ses"])
	}
}

func TestParseBavariaSSHSessionFixture(t *testing.T) {
	f, err := os.Open("../../../tests/fixtures/auditd/bavaria-ssh-session.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	count := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("expected line to match: %s", scanner.Text())
		}
		if ev.Actor["ses"] != 16695 {
			t.Fatalf("expected ses 16695, got %v", ev.Actor["ses"])
		}
		if ev.Actor["auid"] != "wagner" {
			t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
		}

		count++
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if count != 4 {
		t.Fatalf("expected 4 auditd events, got %d", count)
	}
}

func TestParseRawAuditIdentityNormalization(t *testing.T) {
	line := `type=SYSCALL msg=audit(07/09/2026 18:50:54.123:4022783) : arch=c000003e syscall=90 success=yes exit=0 a0=7ffd00000000 a1=180 a2=0 a3=0 items=1 ppid=3664566 pid=3685494 auid=1011 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=16901 comm="chmod" exe="/usr/bin/chmod" key="ssh_blackbox" AUID="wagner" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"`

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected raw audit line to match")
	}

	if ev.Actor["auid"] != "wagner" {
		t.Fatalf("expected normalized auid wagner, got %v", ev.Actor["auid"])
	}

	if ev.Actor["euid"] != "root" {
		t.Fatalf("expected normalized euid root, got %v", ev.Actor["euid"])
	}

	if ev.Actor["auid_id"] != 1011 {
		t.Fatalf("expected auid_id 1011, got %v", ev.Actor["auid_id"])
	}

	if ev.Actor["euid_id"] != 0 {
		t.Fatalf("expected euid_id 0, got %v", ev.Actor["euid_id"])
	}

	if ev.Actor["ses"] != 16901 {
		t.Fatalf("expected ses 16901, got %v", ev.Actor["ses"])
	}

	if ev.Actor["exe"] != "/usr/bin/chmod" {
		t.Fatalf("expected exe /usr/bin/chmod, got %v", ev.Actor["exe"])
	}
}

func TestParseInterpretedAuditIdentityCompatibility(t *testing.T) {
	line := `type=SYSCALL msg=audit(07/08/2026 18:00:48.134:3528891) : arch=x86_64 syscall=execve success=yes exit=0 ppid=2634891 pid=2634931 auid=wagner uid=root gid=root euid=root tty=pts5 ses=16695 comm=touch exe=/usr/bin/touch key=root_exec`

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected interpreted audit line to match")
	}

	if ev.Actor["auid"] != "wagner" {
		t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
	}

	if ev.Actor["euid"] != "root" {
		t.Fatalf("expected euid root, got %v", ev.Actor["euid"])
	}

	if _, exists := ev.Actor["auid_id"]; exists {
		t.Fatalf("did not expect auid_id for interpreted identity, got %v", ev.Actor["auid_id"])
	}

	if _, exists := ev.Actor["euid_id"]; exists {
		t.Fatalf("did not expect euid_id for interpreted identity, got %v", ev.Actor["euid_id"])
	}
}

func TestParseRawSyscallNormalization(t *testing.T) {
	line := `type=SYSCALL msg=audit(1783632088.782:4104065): arch=c000003e syscall=59 success=yes exit=0 ppid=3902480 pid=3903260 auid=1011 uid=1011 euid=0 tty=pts2 ses=16949 comm="sudo" exe="/usr/bin/sudo" key="root_exec"ARCH=x86_64 SYSCALL=execve AUID="wagner" UID="wagner" EUID="root"`

	ev, matched, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("expected raw syscall line to match")
	}

	if ev.Context["syscall"] != "execve" {
		t.Fatalf("expected syscall execve, got %v", ev.Context["syscall"])
	}

	if ev.Context["syscall_id"] != 59 {
		t.Fatalf("expected syscall_id 59, got %v", ev.Context["syscall_id"])
	}
}
