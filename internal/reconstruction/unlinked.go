package reconstruction

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func UnlinkedCriticalChanges(
	reconstructions []Reconstruction,
	criticalChanges []change.CriticalChange,
) []change.CriticalChange {
	linkedAuditSessions := make(map[int]struct{})

	for _, reconstruction := range reconstructions {
		linkedAuditSessions[reconstruction.AuditSessionID] = struct{}{}
	}

	result := make([]change.CriticalChange, 0)

	for _, criticalChange := range criticalChanges {
		if _, linked := linkedAuditSessions[criticalChange.AuditSession]; linked {
			continue
		}

		result = append(result, criticalChange)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].AuditSession != result[j].AuditSession {
			return result[i].AuditSession < result[j].AuditSession
		}
		return result[i].Serial < result[j].Serial
	})

	return result
}
