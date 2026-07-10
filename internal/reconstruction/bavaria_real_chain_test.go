package reconstruction

import (
	"strings"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/change"
	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

func TestBavariaRealParallelSSHChain(t *testing.T) {
	sshEvents := parseSSHFixture(t, "../../tests/fixtures/secure/bavaria-real-parallel-ssh.log")
	auditEvents := parseAuditFixture(t, "../../tests/fixtures/auditd/bavaria-real-ses-16949.log")

	sshBuilder := session.NewBuilder()
	for _, ev := range sshEvents {
		sshBuilder.AddEvent(ev)
	}
	sshSessions := sshBuilder.Sessions()

	auditBuilder := correlation.NewAuditSessionBuilder()
	recordBuilder := auditrecord.NewBuilder()

	for _, ev := range auditEvents {
		auditBuilder.AddEvent(ev)
		recordBuilder.AddEvent(ev)
	}

	auditSessions := auditBuilder.Sessions()
	criticalChanges := change.Build(recordBuilder.Records())
	evidenceLinks := link.Build(sshSessions, auditSessions)

	result := Build(sshSessions, auditSessions, evidenceLinks, criticalChanges)

	if len(result) != 1 {
		t.Fatalf("expected 1 reconstruction, got %d", len(result))
	}

	r := result[0]

	if r.User != "wagner" {
		t.Fatalf("expected user wagner, got %s", r.User)
	}

	if r.RemoteIP != "190.5.138.94" {
		t.Fatalf("expected remote IP 190.5.138.94, got %s", r.RemoteIP)
	}

	if r.AuditSessionID != 16949 {
		t.Fatalf("expected audit session 16949, got %d", r.AuditSessionID)
	}

	var output strings.Builder
	if err := WriteText(&output, result, nil); err != nil {
		t.Fatal(err)
	}

	text := output.String()

	required := []string{
		"Remote:       190.5.138.94:57654",
		"Audit session: 16949",
		"actor=wagner",
		"euid=root",
		"serial=4104131",
		"serial=4104133",
		"serial=4104134",
		"serial=4104136",
		"actor_identity_match",
		"remote_address_match",
		"process_id_match",
	}

	for _, expected := range required {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected output to contain %q\noutput:\n%s", expected, text)
		}
	}
}
