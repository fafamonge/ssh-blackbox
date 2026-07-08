package reconstruction

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteText(t *testing.T) {
	reconstructions := []Reconstruction{
		{
			User:           "wagner",
			RemoteIP:       "190.5.138.94",
			RemotePort:     62133,
			AuthMethod:     "publickey",
			StartRaw:       "Jul  8 18:00:28",
			AuditSessionID: 16695,
			OriginalActor:  "wagner",
			EffectiveUsers: []string{"root"},
			Terminals:      []string{"/dev/pts/4", "pts5"},
			Executions: []RecordedExecution{
				{
					TimestampRaw:  "07/08/2026 18:00:48.134:3528891",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/touch",
					PID:           2634931,
					ParentPID:     2634891,
					Terminal:      "pts5",
				},
			},
			LinkReasons: []string{
				"actor_identity_match",
				"remote_address_match",
			},
		},
	}

	var output bytes.Buffer

	if err := WriteText(&output, reconstructions); err != nil {
		t.Fatal(err)
	}

	text := output.String()

	expectedFragments := []string{
		"SSH SESSION",
		"wagner",
		"190.5.138.94:62133",
		"publickey",
		"LINKED AUDIT SESSION",
		"16695",
		"RECORDED EXECUTIONS",
		"/usr/bin/touch",
		"actor_identity_match",
		"remote_address_match",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(text, fragment) {
			t.Fatalf("expected output to contain %q", fragment)
		}
	}
}
