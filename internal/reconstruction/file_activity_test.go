package reconstruction

import (
	"testing"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func TestBuildFileActivitiesGroupsOperationalPath(t *testing.T) {
	parentPath := "/root/.ssh/"
	filePath := "/root/.ssh/test.tmp"

	criticalChanges := []change.CriticalChange{
		{
			Serial:    "4104131",
			Operation: change.OperationCreate,
			Paths:     []string{parentPath, filePath},
			PathTypes: map[string][]string{
				parentPath: {"PARENT"},
				filePath:   {"CREATE"},
			},
		},
		{
			Serial:    "4104133",
			Operation: change.OperationMetadataChange,
			Paths:     []string{filePath},
			PathTypes: map[string][]string{
				filePath: {"NORMAL"},
			},
		},
		{
			Serial:    "4104134",
			Operation: change.OperationModify,
			Paths:     []string{parentPath, filePath},
			PathTypes: map[string][]string{
				parentPath: {"PARENT"},
				filePath:   {"NORMAL"},
			},
		},
		{
			Serial:    "4104136",
			Operation: change.OperationDelete,
			Paths:     []string{parentPath, filePath},
			PathTypes: map[string][]string{
				parentPath: {"PARENT"},
				filePath:   {"DELETE"},
			},
		},
	}

	activities := BuildFileActivities(criticalChanges)

	if len(activities) != 1 {
		t.Fatalf("expected 1 file activity, got %d", len(activities))
	}

	activity := activities[0]

	if activity.Path != filePath {
		t.Fatalf("expected path %s, got %s", filePath, activity.Path)
	}

	if len(activity.Changes) != 4 {
		t.Fatalf(
			"expected 4 changes for %s, got %d",
			filePath,
			len(activity.Changes),
		)
	}

	expectedOperations := []string{
		change.OperationCreate,
		change.OperationMetadataChange,
		change.OperationModify,
		change.OperationDelete,
	}

	for index, expectedOperation := range expectedOperations {
		if activity.Changes[index].Operation != expectedOperation {
			t.Fatalf(
				"index %d: expected operation %s, got %s",
				index,
				expectedOperation,
				activity.Changes[index].Operation,
			)
		}
	}
}

func TestBuildFileActivitiesPreservesPathWithoutSemantics(t *testing.T) {
	path := "/root/.ssh/authorized_keys"

	criticalChanges := []change.CriticalChange{
		{
			Serial:    "5000001",
			Operation: change.OperationModify,
			Paths:     []string{path},
		},
	}

	activities := BuildFileActivities(criticalChanges)

	if len(activities) != 1 {
		t.Fatalf("expected 1 file activity, got %d", len(activities))
	}

	if activities[0].Path != path {
		t.Fatalf("expected path %s, got %s", path, activities[0].Path)
	}
}

func TestBuildFileActivitiesPreservesParentOnlyEvidence(t *testing.T) {
	path := "/root/.ssh/"

	criticalChanges := []change.CriticalChange{
		{
			Serial:    "5000002",
			Operation: change.OperationUnknown,
			Paths:     []string{path},
			PathTypes: map[string][]string{
				path: {"PARENT"},
			},
		},
	}

	activities := BuildFileActivities(criticalChanges)

	if len(activities) != 1 {
		t.Fatalf(
			"expected parent-only evidence to be preserved, got %d activities",
			len(activities),
		)
	}

	if activities[0].Path != path {
		t.Fatalf("expected path %s, got %s", path, activities[0].Path)
	}
}
