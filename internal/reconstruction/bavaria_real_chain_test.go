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

	if len(r.Executions) == 0 {
		t.Fatal("expected recorded root executions")
	}

	if len(r.CriticalChanges) != 8 {
		t.Fatalf(
			"expected 8 critical file changes, got %d",
			len(r.CriticalChanges),
		)
	}

	if len(r.FileActivities) != 3 {
		t.Fatalf(
			"expected 3 file activities, got %d",
			len(r.FileActivities),
		)
	}

	sshActivity := fileActivityByPath(
		r.FileActivities,
		"/root/.ssh/sshbb_20260709_232012.tmp",
	)
	if sshActivity == nil {
		t.Fatal("expected SSH temporary file activity")
	}

	expectedSSHOperations := []string{
		change.OperationCreate,
		change.OperationMetadataChange,
		change.OperationModify,
		change.OperationDelete,
	}

	if len(sshActivity.Changes) != len(expectedSSHOperations) {
		t.Fatalf(
			"expected %d SSH file changes, got %d",
			len(expectedSSHOperations),
			len(sshActivity.Changes),
		)
	}

	for index, expectedOperation := range expectedSSHOperations {
		if sshActivity.Changes[index].Operation != expectedOperation {
			t.Fatalf(
				"SSH file change %d: expected operation %s, got %s",
				index,
				expectedOperation,
				sshActivity.Changes[index].Operation,
			)
		}
	}

	if fileActivityByPath(r.FileActivities, "/root/.bash_history") == nil {
		t.Fatal("expected bash history file activity")
	}

	if fileActivityByPath(
		r.FileActivities,
		"/root/.bash_history-03263.tmp",
	) == nil {
		t.Fatal("expected temporary bash history file activity")
	}

	if !hasRecordedExecution(r.Executions, "/usr/bin/sudo") {
		t.Fatal("expected recorded sudo execution")
	}

	if !hasRecordedExecution(r.Executions, "/usr/bin/rm") {
		t.Fatal("expected recorded rm execution")
	}

	for _, criticalChange := range r.CriticalChanges {
		for _, key := range criticalChange.Keys {
			if key == "root_exec" || key == "root_exec_user" {
				t.Fatalf(
					"execution-only key %s must not become critical change",
					key,
				)
			}
		}
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
		"Additional recorded executions:",
		"- /usr/bin/grep: 4 record(s)",
		"- /usr/bin/xargs: 6 record(s)",
		"exe=/usr/bin/sudo",
		"exe=/usr/bin/chmod",
		"exe=/usr/bin/rm",
		"serial=4104131 operation=create",
		"serial=4104133 operation=metadata_change",
		"serial=4104134 operation=modify",
		"serial=4104136 operation=delete",
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

func TestBavariaRealFileMovement(t *testing.T) {
	sshEvents := parseSSHFixture(
		t,
		"../../tests/fixtures/secure/bavaria-real-parallel-ssh.log",
	)
	auditEvents := parseAuditFixture(
		t,
		"../../tests/fixtures/auditd/bavaria-real-ses-16949.log",
	)

	sshBuilder := session.NewBuilder()
	for _, ev := range sshEvents {
		sshBuilder.AddEvent(ev)
	}

	auditBuilder := correlation.NewAuditSessionBuilder()
	recordBuilder := auditrecord.NewBuilder()

	for _, ev := range auditEvents {
		auditBuilder.AddEvent(ev)
		recordBuilder.AddEvent(ev)
	}

	criticalChanges := change.Build(recordBuilder.Records())
	movements := BuildFileMovements(criticalChanges)

	if len(movements) != 1 {
		t.Fatalf("expected 1 file movement, got %d", len(movements))
	}

	movement := movements[0]

	if movement.Serial != "4104160" {
		t.Fatalf("expected serial 4104160, got %s", movement.Serial)
	}

	if movement.SourcePath != "/root/.bash_history-03263.tmp" {
		t.Fatalf(
			"expected source /root/.bash_history-03263.tmp, got %s",
			movement.SourcePath,
		)
	}

	if movement.TargetPath != "/root/.bash_history" {
		t.Fatalf(
			"expected target /root/.bash_history, got %s",
			movement.TargetPath,
		)
	}
}

func hasRecordedExecution(
	executions []RecordedExecution,
	executable string,
) bool {
	for _, execution := range executions {
		if execution.Executable == executable {
			return true
		}
	}

	return false
}

func fileActivityByPath(
	activities []FileActivity,
	path string,
) *FileActivity {
	for index := range activities {
		if activities[index].Path == path {
			return &activities[index]
		}
	}

	return nil
}
