package session

import (
	"time"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

type SSHSession struct {
	SessionID  string           `json:"session_id"`
	User       string           `json:"user,omitempty"`
	RemoteIP   string           `json:"remote_ip,omitempty"`
	RemotePort int              `json:"remote_port,omitempty"`
	PID        int              `json:"pid,omitempty"`
	StartRaw   string           `json:"start_raw,omitempty"`
	EndRaw     string           `json:"end_raw,omitempty"`
	StartTime  *time.Time       `json:"start_time,omitempty"`
	EndTime    *time.Time       `json:"end_time,omitempty"`
	EventCount int              `json:"event_count"`
	Events     []evidence.Event `json:"events,omitempty"`
}
