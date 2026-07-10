package reconstruction

import (
	"strings"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func TestWriteTextIncludesUnlinkedCriticalEvidence(t *testing.T) {
	unlinkedChanges := []change.CriticalChange{
		{
			Serial:        "5000001",
			Operation:     change.OperationModify,
			AuditSession:  17001,
			OriginalActor: "wagner",
			EffectiveUser: "root",
			Executable:    "/usr/bin/cp",
			PID:           3100201,
			ParentPID:     3100100,
			Terminal:      "pts3",
			Paths:         []string{"/root/.ssh/authorized_keys"},
			Keys:          []string{"ssh_blackbox"},
		},
	}

	var output strings.Builder

	if err := WriteText(&output, nil, unlinkedChanges); err != nil {
		t.Fatal(err)
	}

	text := output.String()

	required := []string{
		"UNLINKED CRITICAL EVIDENCE",
		"not attributed to a linked SSH session",
		"serial=5000001",
		"audit_session=17001",
		"operation=modify",
		"actor=wagner",
		"euid=root",
		"exe=/usr/bin/cp",
		"paths=/root/.ssh/authorized_keys",
	}

	for _, expected := range required {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected output to contain %q\noutput:\n%s", expected, text)
		}
	}
}
