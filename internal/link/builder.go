package link

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

const (
	ReasonActorIdentityMatch = "actor_identity_match"
	ReasonRemoteAddressMatch = "remote_address_match"
	ReasonProcessIDMatch     = "process_id_match"
)

type linkCandidate struct {
	link  EvidenceLink
	score int
}

func Build(
	sshSessions []session.SSHSession,
	auditSessions []correlation.AuditSession,
) []EvidenceLink {
	candidatesByAuditSession := map[int][]linkCandidate{}

	for _, sshSession := range sshSessions {
		for _, auditSession := range auditSessions {
			reasons := matchReasons(sshSession, auditSession)

			if len(reasons) < 2 {
				continue
			}

			score := len(reasons)
			if processIDMatches(sshSession.PID, auditSession.ProcessIDs) {
				reasons = append(reasons, ReasonProcessIDMatch)
				score++
			}

			candidatesByAuditSession[auditSession.SessionID] = append(
				candidatesByAuditSession[auditSession.SessionID],
				linkCandidate{
					link: EvidenceLink{
						SSHSessionID:   sshSession.SessionID,
						AuditSessionID: auditSession.SessionID,
						Reasons:        reasons,
					},
					score: score,
				},
			)
		}
	}

	links := make([]EvidenceLink, 0)

	for _, candidates := range candidatesByAuditSession {
		selected, ok := selectBestCandidate(candidates)
		if !ok {
			continue
		}

		links = append(links, selected.link)
	}

	sort.Slice(links, func(i, j int) bool {
		if links[i].SSHSessionID == links[j].SSHSessionID {
			return links[i].AuditSessionID < links[j].AuditSessionID
		}
		return links[i].SSHSessionID < links[j].SSHSessionID
	})

	return links
}

func matchReasons(
	sshSession session.SSHSession,
	auditSession correlation.AuditSession,
) []string {
	reasons := make([]string, 0, 3)

	if sshSession.User != "" &&
		auditSession.AUID != "" &&
		sshSession.User == auditSession.AUID {
		reasons = append(reasons, ReasonActorIdentityMatch)
	}

	if sshSession.RemoteIP != "" &&
		auditSession.RemoteAddr != "" &&
		sshSession.RemoteIP == auditSession.RemoteAddr {
		reasons = append(reasons, ReasonRemoteAddressMatch)
	}

	return reasons
}

func processIDMatches(pid int, processIDs []int) bool {
	if pid == 0 {
		return false
	}

	for _, processID := range processIDs {
		if pid == processID {
			return true
		}
	}

	return false
}

func selectBestCandidate(candidates []linkCandidate) (linkCandidate, bool) {
	if len(candidates) == 0 {
		return linkCandidate{}, false
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].link.SSHSessionID < candidates[j].link.SSHSessionID
		}
		return candidates[i].score > candidates[j].score
	})

	if len(candidates) > 1 && candidates[0].score == candidates[1].score {
		return linkCandidate{}, false
	}

	return candidates[0], true
}
