package correlation

import (
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

type AuditSession struct {
	SessionID            int              `json:"session_id"`
	AUID                 string           `json:"auid,omitempty"`
	RemoteAddr           string           `json:"remote_addr,omitempty"`
	Terminals            []string         `json:"terminals,omitempty"`
	EffectiveUsers       []string         `json:"effective_users,omitempty"`
	Executables          []string         `json:"executables,omitempty"`
	ProcessIDs           []int            `json:"process_ids,omitempty"`
	ParentPIDs           []int            `json:"parent_pids,omitempty"`
	Keys                 []string         `json:"keys,omitempty"`
	HasRootExecution     bool             `json:"has_root_execution"`
	HasRemoteAddress     bool             `json:"has_remote_address"`
	HasMultipleTerminals bool             `json:"has_multiple_terminals"`
	StartRaw             string           `json:"start_raw,omitempty"`
	EndRaw               string           `json:"end_raw,omitempty"`
	EventCount           int              `json:"event_count"`
	Events               []evidence.Event `json:"events,omitempty"`
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
			StartRaw:  ev.TimestampRaw,
			EndRaw:    ev.TimestampRaw,
			Events:    []evidence.Event{},
		}
		b.sessions[ses] = s
	}

	if s.AUID == "" {
		s.AUID = stringFromActor(ev, "auid")
	}

	if s.RemoteAddr == "" {
		s.RemoteAddr = stringFromActor(ev, "addr")
	}

	if terminal := firstNonEmpty(
		stringFromActor(ev, "terminal"),
		stringFromActor(ev, "tty"),
	); terminal != "" {
		s.Terminals = appendUnique(s.Terminals, terminal)
	}

	if euid := stringFromActor(ev, "euid"); euid != "" {
		s.EffectiveUsers = appendUnique(s.EffectiveUsers, euid)
	}

	if exe := stringFromActor(ev, "exe"); exe != "" {
		s.Executables = appendUnique(s.Executables, exe)
	}

	if ev.PID != 0 {
		s.ProcessIDs = appendUniqueInt(s.ProcessIDs, ev.PID)
	}

	if ppid, ok := intFromContext(ev, "ppid"); ok {
		s.ParentPIDs = appendUniqueInt(s.ParentPIDs, ppid)
	}

	if key := stringFromContext(ev, "key"); key != "" {
		s.Keys = appendUnique(s.Keys, key)
	}

	if s.StartRaw == "" || ev.TimestampRaw < s.StartRaw {
		s.StartRaw = ev.TimestampRaw
	}

	if s.EndRaw == "" || ev.TimestampRaw > s.EndRaw {
		s.EndRaw = ev.TimestampRaw
	}

	s.HasRemoteAddress = s.RemoteAddr != ""
	s.HasMultipleTerminals = len(s.Terminals) > 1

	for _, euid := range s.EffectiveUsers {
		if euid == "root" {
			s.HasRootExecution = true
			break
		}
	}

	s.Events = append(s.Events, ev)
	sort.Slice(s.Events, func(i, j int) bool {
		return s.Events[i].TimestampRaw < s.Events[j].TimestampRaw
	})
	s.EventCount = len(s.Events)
}

func (b *AuditSessionBuilder) Sessions() []AuditSession {
	result := make([]AuditSession, 0, len(b.sessions))

	for _, s := range b.sessions {
		sort.Strings(s.EffectiveUsers)
		sort.Strings(s.Terminals)
		sort.Strings(s.Executables)
		sort.Ints(s.ProcessIDs)
		sort.Ints(s.ParentPIDs)
		sort.Strings(s.Keys)
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].SessionID < result[j].SessionID
	})

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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func intFromContext(ev evidence.Event, key string) (int, bool) {
	if ev.Context == nil {
		return 0, false
	}

	v, ok := ev.Context[key]
	if !ok {
		return 0, false
	}

	n, ok := v.(int)
	return n, ok
}

func stringFromContext(ev evidence.Event, key string) string {
	if ev.Context == nil {
		return ""
	}

	v, ok := ev.Context[key]
	if !ok {
		return ""
	}

	s, ok := v.(string)
	if !ok {
		return ""
	}

	return s
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
