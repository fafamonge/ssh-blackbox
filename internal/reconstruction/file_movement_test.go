package reconstruction

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func TestBuildFileMovementsDerivesRenameByInode(t *testing.T) {
	criticalChanges := []change.CriticalChange{
		{
			Serial: "4104160",
			PathEntries: []auditrecord.PathEntry{
				{
					Item:     0,
					Name:     "/root/",
					NameType: "PARENT",
					Inode:    20618497,
				},
				{
					Item:     1,
					Name:     "/root/",
					NameType: "PARENT",
					Inode:    20618497,
				},
				{
					Item:     2,
					Name:     "/root/.bash_history-03263.tmp",
					NameType: "DELETE",
					Inode:    20619027,
				},
				{
					Item:     3,
					Name:     "/root/.bash_history",
					NameType: "DELETE",
					Inode:    20618964,
				},
				{
					Item:     4,
					Name:     "/root/.bash_history",
					NameType: "CREATE",
					Inode:    20619027,
				},
			},
		},
	}

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
			"expected source path /root/.bash_history-03263.tmp, got %s",
			movement.SourcePath,
		)
	}

	if movement.TargetPath != "/root/.bash_history" {
		t.Fatalf(
			"expected target path /root/.bash_history, got %s",
			movement.TargetPath,
		)
	}
}

func TestBuildFileMovementsRejectsUnmatchedInodes(t *testing.T) {
	criticalChanges := []change.CriticalChange{
		{
			Serial: "7000001",
			PathEntries: []auditrecord.PathEntry{
				{
					Item:     0,
					Name:     "/tmp/source",
					NameType: "DELETE",
					Inode:    100,
				},
				{
					Item:     1,
					Name:     "/tmp/target",
					NameType: "CREATE",
					Inode:    200,
				},
			},
		},
	}

	movements := BuildFileMovements(criticalChanges)

	if len(movements) != 0 {
		t.Fatalf(
			"expected no movement for unmatched inodes, got %d",
			len(movements),
		)
	}
}

func TestBuildFileMovementsRejectsIncompleteEvidence(t *testing.T) {
	criticalChanges := []change.CriticalChange{
		{
			Serial: "7000002",
			PathEntries: []auditrecord.PathEntry{
				{
					Item:     0,
					Name:     "/tmp/source",
					NameType: "DELETE",
					Inode:    100,
				},
			},
		},
	}

	movements := BuildFileMovements(criticalChanges)

	if len(movements) != 0 {
		t.Fatalf(
			"expected no movement for incomplete evidence, got %d",
			len(movements),
		)
	}
}

func TestBuildFileMovementsMatchesCreateWithCorrectDeletedInode(t *testing.T) {
	criticalChanges := []change.CriticalChange{
		{
			Serial: "7000003",
			PathEntries: []auditrecord.PathEntry{
				{
					Item:     0,
					Name:     "/tmp/unrelated-old-target",
					NameType: "DELETE",
					Inode:    100,
				},
				{
					Item:     1,
					Name:     "/tmp/source",
					NameType: "DELETE",
					Inode:    200,
				},
				{
					Item:     2,
					Name:     "/tmp/target",
					NameType: "CREATE",
					Inode:    200,
				},
			},
		},
	}

	movements := BuildFileMovements(criticalChanges)

	if len(movements) != 1 {
		t.Fatalf("expected 1 file movement, got %d", len(movements))
	}

	if movements[0].SourcePath != "/tmp/source" {
		t.Fatalf(
			"expected source /tmp/source, got %s",
			movements[0].SourcePath,
		)
	}

	if movements[0].TargetPath != "/tmp/target" {
		t.Fatalf(
			"expected target /tmp/target, got %s",
			movements[0].TargetPath,
		)
	}
}
