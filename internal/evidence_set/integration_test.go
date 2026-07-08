package evidence_set

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
	"github.com/fafamonge/ssh-blackbox/internal/parser/openssh"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

func TestBavariaEvidenceLink(t *testing.T) {
	sshLines := []string{
		"Jul  8 18:00:28 bavaria.hybridsync.com sshd[2634610]: Accepted publickey for wagner from 190.5.138.94 port 62133 ssh2: ED25519 SHA256:UH+BxqPfMEmQI1hU2dDFHLM/wF6gMkrNKUaJmV/9coY",
		"Jul  8 18:00:28 bavaria.hybridsync.com sshd[2634610]: pam_unix(sshd:session): session opened for user wagner(uid=1011) by wagner(uid=0)",
	}

	auditLines := []string{
		"type=USER_LOGIN msg=audit(07/08/2026 18:00:28.674:3528770) : pid=2634610 uid=root auid=wagner ses=16695 msg='op=login id=wagner exe=/usr/libexec/openssh/sshd-session hostname=bavaria.hybridsync.com addr=190.5.138.94 terminal=/dev/pts/4 res=success'",
	}

	sshBuilder := session.NewBuilder()

	for _, line := range sshLines {
		ev, matched, err := openssh.ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			sshBuilder.AddEvent(*ev)
		}
	}

	auditBuilder := correlation.NewAuditSessionBuilder()

	for _, line := range auditLines {
		ev, matched, err := auditd.ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			auditBuilder.AddEvent(*ev)
		}
	}

	sshSessions := sshBuilder.Sessions()
	auditSessions := auditBuilder.Sessions()
	links := link.Build(sshSessions, auditSessions)

	if len(sshSessions) != 1 {
		t.Fatalf("expected 1 ssh session, got %d", len(sshSessions))
	}

	if len(auditSessions) != 1 {
		t.Fatalf("expected 1 audit session, got %d", len(auditSessions))
	}

	if len(links) != 1 {
		t.Fatalf("expected 1 evidence link, got %d", len(links))
	}

	if len(links[0].Reasons) != 2 {
		t.Fatalf("expected 2 link reasons, got %v", links[0].Reasons)
	}
}
