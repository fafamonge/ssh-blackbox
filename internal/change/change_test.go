package change

import (
	"bufio"
	"os"
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
)

func TestBuildCriticalChangeFromFixture(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/critical-file-change.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	builder := auditrecord.NewBuilder()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Fatalf("line did not match: %s", scanner.Text())
		}

		builder.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	changes := Build(builder.Records())

	if len(changes) != 1 {
		t.Fatalf("expected 1 critical change, got %d", len(changes))
	}

	change := changes[0]

	if change.Serial != "5000001" {
		t.Fatalf("expected serial 5000001, got %s", change.Serial)
	}

	if change.AuditSession != 17001 {
		t.Fatalf(
			"expected audit session 17001, got %d",
			change.AuditSession,
		)
	}

	if change.OriginalActor != "wagner" {
		t.Fatalf(
			"expected original actor wagner, got %s",
			change.OriginalActor,
		)
	}

	if change.EffectiveUser != "root" {
		t.Fatalf(
			"expected effective user root, got %s",
			change.EffectiveUser,
		)
	}

	if change.Executable != "/usr/bin/cp" {
		t.Fatalf(
			"expected executable /usr/bin/cp, got %s",
			change.Executable,
		)
	}

	if len(change.Paths) != 1 ||
		change.Paths[0] != "/root/.ssh/authorized_keys" {
		t.Fatalf(
			"expected authorized_keys path, got %v",
			change.Paths,
		)
	}

	if len(change.Keys) != 1 ||
		change.Keys[0] != "ssh_blackbox" {
		t.Fatalf(
			"expected ssh_blackbox key, got %v",
			change.Keys,
		)
	}
}

func TestBuildExcludesRootExecutionRecordsFromCriticalChanges(t *testing.T) {
	records := []auditrecord.Record{
		{
			Serial:     "6000001",
			SessionID:  16949,
			AUID:       "wagner",
			EUID:       "root",
			Executable: "/usr/bin/grep",
			PID:        3903269,
			ParentPID:  3903268,
			Terminal:   "pts3",
			Paths:      []string{"/bin/grep", "/lib64/ld-linux-x86-64.so.2"},
			Keys:       []string{"root_exec"},
		},
	}

	changes := Build(records)

	if len(changes) != 0 {
		t.Fatalf("expected root_exec record not to become critical change, got %v", changes)
	}
}

func TestBuildPreservesCriticalWatchRecordWithExecutionKey(t *testing.T) {
	records := []auditrecord.Record{
		{
			Serial:     "6000002",
			SessionID:  16949,
			AUID:       "wagner",
			EUID:       "root",
			Executable: "/usr/bin/rm",
			PID:        3903390,
			ParentPID:  3903263,
			Terminal:   "pts3",
			Paths:      []string{"/root/.ssh/test.tmp"},
			Keys:       []string{"root_exec", "ssh_blackbox"},
		},
	}

	changes := Build(records)

	if len(changes) != 1 {
		t.Fatalf("expected critical watch record to be preserved, got %d changes", len(changes))
	}

	if changes[0].Serial != "6000002" {
		t.Fatalf("expected serial 6000002, got %s", changes[0].Serial)
	}
}

func TestBuildClassifiesCriticalOperations(t *testing.T) {
	path := "/root/.ssh/test.tmp"

	records := []auditrecord.Record{
		{
			Serial:    "7000001",
			Paths:     []string{path},
			PathTypes: map[string][]string{path: []string{"CREATE"}},
			Keys:      []string{"ssh_blackbox"},
			Syscall:   "openat",
		},
		{
			Serial:    "7000002",
			Paths:     []string{path},
			PathTypes: map[string][]string{path: []string{"NORMAL"}},
			Keys:      []string{"ssh_blackbox"},
			Syscall:   "fchmodat",
		},
		{
			Serial:    "7000003",
			Paths:     []string{path},
			PathTypes: map[string][]string{path: []string{"NORMAL"}},
			Keys:      []string{"ssh_blackbox"},
			Syscall:   "openat",
		},
		{
			Serial:    "7000004",
			Paths:     []string{path},
			PathTypes: map[string][]string{path: []string{"DELETE"}},
			Keys:      []string{"ssh_blackbox"},
			Syscall:   "unlinkat",
		},
		{
			Serial:    "7000005",
			Paths:     []string{path},
			PathTypes: map[string][]string{path: []string{"NORMAL"}},
			Keys:      []string{"ssh_blackbox"},
			Syscall:   "renameat2",
		},
	}

	changes := Build(records)

	if len(changes) != 5 {
		t.Fatalf("expected 5 critical changes, got %d", len(changes))
	}

	expected := map[string]string{
		"7000001": OperationCreate,
		"7000002": OperationMetadataChange,
		"7000003": OperationModify,
		"7000004": OperationDelete,
		"7000005": OperationUnknown,
	}

	for _, criticalChange := range changes {
		want := expected[criticalChange.Serial]

		if criticalChange.Operation != want {
			t.Fatalf(
				"serial %s: expected operation %s, got %s",
				criticalChange.Serial,
				want,
				criticalChange.Operation,
			)
		}
	}
}

func TestBuildClassifiesBavariaRealOperations(t *testing.T) {
	f, err := os.Open("../../tests/fixtures/auditd/bavaria-real-ses-16949.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	builder := auditrecord.NewBuilder()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			builder.AddEvent(*ev)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	changes := Build(builder.Records())

	operations := make(map[string]string, len(changes))
	for _, criticalChange := range changes {
		operations[criticalChange.Serial] = criticalChange.Operation
	}

	expected := map[string]string{
		"4104131": OperationCreate,
		"4104133": OperationMetadataChange,
		"4104134": OperationModify,
		"4104136": OperationDelete,
	}

	for serial, want := range expected {
		if got := operations[serial]; got != want {
			t.Fatalf(
				"serial %s: expected operation %s, got %s",
				serial,
				want,
				got,
			)
		}
	}
}

func TestBuildPreservesPathTypes(t *testing.T) {
	path := "/root/.ssh/authorized_keys"

	records := []auditrecord.Record{
		{
			Serial:    "7000001",
			SessionID: 17001,
			Paths:     []string{"/root/.ssh/", path},
			PathTypes: map[string][]string{
				"/root/.ssh/": {"PARENT"},
				path:          {"CREATE"},
			},
			Keys:    []string{"ssh_blackbox"},
			Syscall: "openat",
		},
	}

	result := Build(records)

	if len(result) != 1 {
		t.Fatalf("expected 1 critical change, got %d", len(result))
	}

	criticalChange := result[0]

	if len(criticalChange.PathTypes["/root/.ssh/"]) != 1 ||
		criticalChange.PathTypes["/root/.ssh/"][0] != "PARENT" {
		t.Fatalf(
			"expected parent path type to be preserved, got %v",
			criticalChange.PathTypes["/root/.ssh/"],
		)
	}

	if len(criticalChange.PathTypes[path]) != 1 ||
		criticalChange.PathTypes[path][0] != "CREATE" {
		t.Fatalf(
			"expected create path type to be preserved, got %v",
			criticalChange.PathTypes[path],
		)
	}
}
