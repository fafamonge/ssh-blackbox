package link

type EvidenceLink struct {
	SSHSessionID   string   `json:"ssh_session_id"`
	AuditSessionID int      `json:"audit_session_id"`
	Reasons        []string `json:"reasons"`
}
