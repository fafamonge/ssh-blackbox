package evidence_set

import "testing"

func TestNewEvidenceSet(t *testing.T) {
	es := New()

	if es.SchemaVersion != "0.1" {
		t.Fatalf("expected schema version 0.1, got %s", es.SchemaVersion)
	}

	if es.SSHSessions == nil {
		t.Fatal("expected ssh_sessions to be initialized")
	}

	if es.AuditSessions == nil {
		t.Fatal("expected audit_sessions to be initialized")
	}

	if es.UncorrelatedEvents == nil {
		t.Fatal("expected uncorrelated_events to be initialized")
	}
}
