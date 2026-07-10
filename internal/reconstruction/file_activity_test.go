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

func TestBuildFileActivitiesRefinesOperationPerPath(t *testing.T) {
	sourcePath := "/root/.bash_history-03263.tmp"
	targetPath := "/root/.bash_history"

	criticalChanges := []change.CriticalChange{
		{
			Serial:    "4104160",
			Operation: change.OperationDelete,
			Paths:     []string{sourcePath, targetPath},
			PathTypes: map[string][]string{
				sourcePath: {"DELETE"},
				targetPath: {"DELETE", "CREATE"},
			},
		},
	}

	activities := BuildFileActivities(criticalChanges)

	if len(activities) != 2 {
		t.Fatalf("expected 2 file activities, got %d", len(activities))
	}

	sourceActivity := fileActivityByPathForTest(activities, sourcePath)
	if sourceActivity == nil {
		t.Fatalf("expected source activity for %s", sourcePath)
	}

	if sourceActivity.Changes[0].Operation != change.OperationDelete {
		t.Fatalf(
			"expected source operation %s, got %s",
			change.OperationDelete,
			sourceActivity.Changes[0].Operation,
		)
	}

	targetActivity := fileActivityByPathForTest(activities, targetPath)
	if targetActivity == nil {
		t.Fatalf("expected target activity for %s", targetPath)
	}

	if targetActivity.Changes[0].Operation != change.OperationCreate {
		t.Fatalf(
			"expected target operation %s, got %s",
			change.OperationCreate,
			targetActivity.Changes[0].Operation,
		)
	}
}

func fileActivityByPathForTest(
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
