package link

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/session"
)

const (
	ReasonActorIdentityMatch = "actor_identity_match"
	ReasonRemoteAddressMatch = "remote_address_match"
)

func Build(
	sshSessions []session.SSHSession,
	auditSessions []correlation.AuditSession,
) []EvidenceLink {
	links := make([]EvidenceLink, 0)

	for _, sshSession := range sshSessions {
		for _, auditSession := range auditSessions {
			reasons := matchReasons(sshSession, auditSession)

			if len(reasons) < 2 {
				continue
			}

			links = append(links, EvidenceLink{
				SSHSessionID:   sshSession.SessionID,
				AuditSessionID: auditSession.SessionID,
				Reasons:        reasons,
			})
		}
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
	reasons := make([]string, 0, 2)

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
