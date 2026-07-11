package reconstruction

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/auditrecord"
	"github.com/fafamonge/ssh-blackbox/internal/change"
)

type FileMovement struct {
	Serial     string `json:"serial"`
	SourcePath string `json:"source_path"`
	TargetPath string `json:"target_path"`
}

func BuildFileMovements(
	criticalChanges []change.CriticalChange,
) []FileMovement {
	movements := make([]FileMovement, 0)

	for _, criticalChange := range criticalChanges {
		movement, ok := fileMovementFromChange(criticalChange)
		if !ok {
			continue
		}

		movements = append(movements, movement)
	}

	sort.Slice(movements, func(i, j int) bool {
		return movements[i].Serial < movements[j].Serial
	})

	return movements
}

func fileMovementFromChange(
	criticalChange change.CriticalChange,
) (FileMovement, bool) {
	var source *auditrecord.PathEntry
	var target *auditrecord.PathEntry

	for createIndex := range criticalChange.PathEntries {
		createEntry := &criticalChange.PathEntries[createIndex]

		if createEntry.NameType != "CREATE" || createEntry.Inode == 0 {
			continue
		}

		for deleteIndex := range criticalChange.PathEntries {
			deleteEntry := &criticalChange.PathEntries[deleteIndex]

			if deleteEntry.NameType != "DELETE" {
				continue
			}

			if deleteEntry.Inode != createEntry.Inode {
				continue
			}

			source = deleteEntry
			target = createEntry
			break
		}

		if source != nil {
			break
		}
	}

	if source == nil || target == nil {
		return FileMovement{}, false
	}

	if source.Name == "" || target.Name == "" {
		return FileMovement{}, false
	}

	return FileMovement{
		Serial:     criticalChange.Serial,
		SourcePath: source.Name,
		TargetPath: target.Name,
	}, true
}
