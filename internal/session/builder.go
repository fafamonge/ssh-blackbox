package session

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

type Builder struct {
	sessions map[string]*SSHSession
}

func NewBuilder() *Builder {
	return &Builder{
		sessions: make(map[string]*SSHSession),
	}
}

func (b *Builder) AddEvent(ev evidence.Event) {
	key := sessionKey(ev)

	s, ok := b.sessions[key]
	if !ok {
		s = &SSHSession{
			SessionID:  buildSessionID(key),
			User:       stringFromMap(ev.Actor, "username"),
			RemoteIP:   stringFromMap(ev.Actor, "ip"),
			RemotePort: intFromMap(ev.Actor, "port"),
			PID:        ev.PID,
			StartRaw:   ev.TimestampRaw,
		}
		b.sessions[key] = s
	}

	s.EndRaw = ev.TimestampRaw
	s.Events = append(s.Events, ev)
	s.EventCount = len(s.Events)
}

func (b *Builder) Sessions() []SSHSession {
	result := make([]SSHSession, 0, len(b.sessions))

	for _, s := range b.sessions {
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].StartRaw < result[j].StartRaw
	})

	return result
}

func sessionKey(ev evidence.Event) string {
	if ev.PID != 0 {
		return fmt.Sprintf("pid:%d", ev.PID)
	}

	user := stringFromMap(ev.Actor, "username")
	ip := stringFromMap(ev.Actor, "ip")
	port := intFromMap(ev.Actor, "port")

	return fmt.Sprintf("user:%s|ip:%s|port:%d", user, ip, port)
}

func buildSessionID(key string) string {
	sum := sha1.Sum([]byte(key))
	return hex.EncodeToString(sum[:])
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}

	v, ok := m[key]
	if !ok {
		return ""
	}

	s, ok := v.(string)
	if !ok {
		return ""
	}

	return s
}

func intFromMap(m map[string]any, key string) int {
	if m == nil {
		return 0
	}

	v, ok := m[key]
	if !ok {
		return 0
	}

	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
