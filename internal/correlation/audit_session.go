package correlation

import "github.com/fafamonge/ssh-blackbox/internal/evidence"

type AuditSession struct {
	SessionID  int              `json:"session_id"`
	AUID       string           `json:"auid,omitempty"`
	EventCount int              `json:"event_count"`
	Events     []evidence.Event `json:"events,omitempty"`
}

type AuditSessionBuilder struct {
	sessions map[int]*AuditSession
}

func NewAuditSessionBuilder() *AuditSessionBuilder {
	return &AuditSessionBuilder{
		sessions: map[int]*AuditSession{},
	}
}

func (b *AuditSessionBuilder) AddEvent(ev evidence.Event) {
	ses, ok := intFromActor(ev, "ses")
	if !ok {
		return
	}

	s, exists := b.sessions[ses]
	if !exists {
		s = &AuditSession{
			SessionID: ses,
			AUID:      stringFromActor(ev, "auid"),
			Events:    []evidence.Event{},
		}
		b.sessions[ses] = s
	}

	if s.AUID == "" {
		s.AUID = stringFromActor(ev, "auid")
	}

	s.Events = append(s.Events, ev)
	s.EventCount = len(s.Events)
}

func (b *AuditSessionBuilder) Sessions() []AuditSession {
	result := make([]AuditSession, 0, len(b.sessions))

	for _, s := range b.sessions {
		result = append(result, *s)
	}

	return result
}

func intFromActor(ev evidence.Event, key string) (int, bool) {
	if ev.Actor == nil {
		return 0, false
	}

	v, ok := ev.Actor[key]
	if !ok {
		return 0, false
	}

	n, ok := v.(int)
	return n, ok
}

func stringFromActor(ev evidence.Event, key string) string {
	if ev.Actor == nil {
		return ""
	}

	v, ok := ev.Actor[key]
	if !ok {
		return ""
	}

	s, ok := v.(string)
	if !ok {
		return ""
	}

	return s
}
