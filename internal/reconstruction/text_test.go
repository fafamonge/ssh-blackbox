package reconstruction

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/change"
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
			FileActivities: []FileActivity{
				{
					Path: "/root/.ssh/test.tmp",
					Changes: []change.CriticalChange{
						{
							Serial:    "3528892",
							Operation: change.OperationCreate,
						},
					},
				},
			},
			FileMovements: []FileMovement{
				{
					Serial:     "3528893",
					SourcePath: "/root/.bash_history-00001.tmp",
					TargetPath: "/root/.bash_history",
				},
			},
			LinkReasons: []string{
				"actor_identity_match",
				"remote_address_match",
			},
		},
	}

	var output bytes.Buffer

	if err := WriteText(&output, reconstructions, nil); err != nil {
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
		"FILE ACTIVITY",
		"/root/.ssh/test.tmp",
		"- serial=3528892 operation=create",
		"FILE MOVEMENTS",
		"serial=3528893 source=/root/.bash_history-00001.tmp target=/root/.bash_history",
		"actor_identity_match",
		"remote_address_match",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(text, fragment) {
			t.Fatalf("expected output to contain %q", fragment)
		}
	}
}

func TestWriteTextSummarizesAuxiliaryExecutions(t *testing.T) {
	reconstructions := []Reconstruction{
		{
			User:           "wagner",
			RemoteIP:       "190.5.138.94",
			RemotePort:     57654,
			AuthMethod:     "publickey",
			AuditSessionID: 16949,
			Executions: []RecordedExecution{
				{
					TimestampRaw:  "1",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/sudo",
					PID:           100,
				},
				{
					TimestampRaw:  "2",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/bash",
					PID:           200,
				},
				{
					TimestampRaw:  "3",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/grep",
					PID:           300,
				},
				{
					TimestampRaw:  "4",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/grep",
					PID:           301,
				},
				{
					TimestampRaw:  "5",
					OriginalActor: "wagner",
					EffectiveUser: "root",
					Executable:    "/usr/bin/rm",
					PID:           400,
					ParentPID:     200,
				},
			},
			CriticalChanges: []change.CriticalChange{
				{
					Serial:    "5001",
					PID:       400,
					ParentPID: 200,
					Keys:      []string{"ssh_blackbox"},
				},
			},
		},
	}

	var output bytes.Buffer

	if err := WriteText(&output, reconstructions, nil); err != nil {
		t.Fatal(err)
	}

	text := output.String()

	required := []string{
		"exe=/usr/bin/sudo",
		"exe=/usr/bin/bash",
		"exe=/usr/bin/rm",
		"Additional recorded executions:",
		"- /usr/bin/grep: 2 record(s)",
	}

	for _, expected := range required {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected output to contain %q\noutput:\n%s", expected, text)
		}
	}

	if strings.Contains(text, "exe=/usr/bin/grep") {
		t.Fatalf("expected grep executions to be summarized\noutput:\n%s", text)
	}
}
