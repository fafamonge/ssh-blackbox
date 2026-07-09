package reconstruction

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func TestUnlinkedCriticalChanges(t *testing.T) {
	reconstructions := []Reconstruction{{AuditSessionID: 16695}}

	criticalChanges := []change.CriticalChange{
		{Serial: "3528892", AuditSession: 16695},
		{Serial: "5000001", AuditSession: 17001},
	}

	result := UnlinkedCriticalChanges(reconstructions, criticalChanges)

	if len(result) != 1 {
		t.Fatalf("expected 1 unlinked critical change, got %d", len(result))
	}

	if result[0].Serial != "5000001" {
		t.Fatalf("expected unlinked serial 5000001, got %s", result[0].Serial)
	}
}
