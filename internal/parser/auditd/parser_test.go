package auditd

import "testing"

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
	lines := []string{
		`type=USER_LOGIN msg=audit(07/08/2026 18:00:28.674:3528770) : pid=2634610 uid=root auid=wagner ses=16695 msg='op=login id=wagner exe=/usr/libexec/openssh/sshd-session hostname=bavaria.hybridsync.com addr=190.5.138.94 terminal=/dev/pts/4 res=success'`,
		`type=SYSCALL msg=audit(07/08/2026 18:00:48.134:3528891) : arch=x86_64 syscall=execve success=yes exit=0 ppid=2634891 pid=2634931 auid=wagner uid=root gid=root euid=root tty=pts5 ses=16695 comm=touch exe=/usr/bin/touch key=root_exec`,
		`type=SYSCALL msg=audit(07/08/2026 18:00:48.136:3528892) : arch=x86_64 syscall=execve success=yes exit=0 ppid=2634891 pid=2634932 auid=wagner uid=root gid=root euid=root tty=pts5 ses=16695 comm=stat exe=/usr/bin/stat key=root_exec`,
	}

	for _, line := range lines {
		ev, matched, err := ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("expected line to match: %s", line)
		}
		if ev.Actor["ses"] != 16695 {
			t.Fatalf("expected ses 16695, got %v", ev.Actor["ses"])
		}
		if ev.Actor["auid"] != "wagner" {
			t.Fatalf("expected auid wagner, got %v", ev.Actor["auid"])
		}
	}
}
