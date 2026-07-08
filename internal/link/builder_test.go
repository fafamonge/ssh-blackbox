package link

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

func TestBuildCreatesLinkOnIdentityAndAddressMatch(t *testing.T) {
	sshSessions := []session.SSHSession{
		{
			SessionID: "ssh-session-1",
			User:      "wagner",
			RemoteIP:  "190.5.138.94",
		},
	}

	auditSessions := []correlation.AuditSession{
		{
			SessionID:  16695,
			AUID:       "wagner",
			RemoteAddr: "190.5.138.94",
		},
	}

	links := Build(sshSessions, auditSessions)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}

	if links[0].SSHSessionID != "ssh-session-1" {
		t.Fatalf("unexpected ssh session id: %s", links[0].SSHSessionID)
	}

	if links[0].AuditSessionID != 16695 {
		t.Fatalf("unexpected audit session id: %d", links[0].AuditSessionID)
	}

	if len(links[0].Reasons) != 2 {
		t.Fatalf("expected 2 reasons, got %v", links[0].Reasons)
	}
}

func TestBuildRejectsIdentityOnlyMatch(t *testing.T) {
	sshSessions := []session.SSHSession{
		{
			SessionID: "ssh-session-1",
			User:      "wagner",
			RemoteIP:  "190.5.138.94",
		},
	}

	auditSessions := []correlation.AuditSession{
		{
			SessionID:  16695,
			AUID:       "wagner",
			RemoteAddr: "198.51.100.10",
		},
	}

	links := Build(sshSessions, auditSessions)

	if len(links) != 0 {
		t.Fatalf("expected no links, got %v", links)
	}
}

func TestBuildRejectsAddressOnlyMatch(t *testing.T) {
	sshSessions := []session.SSHSession{
		{
			SessionID: "ssh-session-1",
			User:      "wagner",
			RemoteIP:  "190.5.138.94",
		},
	}

	auditSessions := []correlation.AuditSession{
		{
			SessionID:  16695,
			AUID:       "another-user",
			RemoteAddr: "190.5.138.94",
		},
	}

	links := Build(sshSessions, auditSessions)

	if len(links) != 0 {
		t.Fatalf("expected no links, got %v", links)
	}
}

func TestBuildPreservesUnmatchedSessionsByNotCreatingLinks(t *testing.T) {
	sshSessions := []session.SSHSession{
		{
			SessionID: "ssh-session-1",
			User:      "root",
			RemoteIP:  "192.0.2.20",
		},
	}

	auditSessions := []correlation.AuditSession{
		{
			SessionID:  16695,
			AUID:       "wagner",
			RemoteAddr: "190.5.138.94",
		},
	}

	links := Build(sshSessions, auditSessions)

	if len(links) != 0 {
		t.Fatalf("expected no links, got %v", links)
	}

	if len(sshSessions) != 1 {
		t.Fatal("ssh session evidence was modified")
	}

	if len(auditSessions) != 1 {
		t.Fatal("audit session evidence was modified")
	}
}
