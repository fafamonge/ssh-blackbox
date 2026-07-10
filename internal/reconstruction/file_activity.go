package reconstruction

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

type FileActivity struct {
	Path    string                  `json:"path"`
	Changes []change.CriticalChange `json:"changes,omitempty"`
}

func BuildFileActivities(
	criticalChanges []change.CriticalChange,
) []FileActivity {
	activitiesByPath := make(map[string][]change.CriticalChange)

	for _, criticalChange := range criticalChanges {
		for _, path := range operationalPaths(criticalChange) {
			activitiesByPath[path] = append(
				activitiesByPath[path],
				criticalChange,
			)
		}
	}

	paths := make([]string, 0, len(activitiesByPath))
	for path := range activitiesByPath {
		paths = append(paths, path)
	}

	sort.Strings(paths)

	activities := make([]FileActivity, 0, len(paths))

	for _, path := range paths {
		changes := activitiesByPath[path]

		sort.Slice(changes, func(i, j int) bool {
			return changes[i].Serial < changes[j].Serial
		})

		activities = append(activities, FileActivity{
			Path:    path,
			Changes: changes,
		})
	}

	return activities
}

func operationalPaths(
	criticalChange change.CriticalChange,
) []string {
	if len(criticalChange.Paths) == 0 {
		return nil
	}

	operational := make([]string, 0)

	for _, path := range criticalChange.Paths {
		pathTypes := criticalChange.PathTypes[path]

		if len(pathTypes) == 0 || !onlyParentPathTypes(pathTypes) {
			operational = append(operational, path)
		}
	}

	if len(operational) > 0 {
		return operational
	}

	// Si toda la evidencia disponible marca PARENT, conservamos las rutas.
	// Es preferible mantener evidencia incompleta antes que descartarla.
	return append([]string(nil), criticalChange.Paths...)
}

func onlyParentPathTypes(pathTypes []string) bool {
	if len(pathTypes) == 0 {
		return false
	}

	for _, pathType := range pathTypes {
		if pathType != "PARENT" {
			return false
		}
	}

	return true
}
