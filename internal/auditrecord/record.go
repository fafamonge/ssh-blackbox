package auditrecord

import (
	"regexp"
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

var serialRE = regexp.MustCompile(`audit\(.*:(\d+)\)`)

type Record struct {
	Serial     string           `json:"serial"`
	SessionID  int              `json:"session_id,omitempty"`
	AUID       string           `json:"auid,omitempty"`
	EUID       string           `json:"euid,omitempty"`
	Executable string           `json:"executable,omitempty"`
	Command    string           `json:"command,omitempty"`
	PID        int              `json:"pid,omitempty"`
	ParentPID  int              `json:"parent_pid,omitempty"`
	Terminal   string           `json:"terminal,omitempty"`
	EventTypes []string         `json:"event_types,omitempty"`
	Events     []evidence.Event `json:"events,omitempty"`
	Paths      []string         `json:"paths,omitempty"`
	Keys       []string         `json:"keys,omitempty"`
}

type Builder struct {
	records map[string]*Record
}

func NewBuilder() *Builder {
	return &Builder{records: map[string]*Record{}}
}

func (b *Builder) AddEvent(ev evidence.Event) {
	serial := serialFromRaw(ev.Raw)
	if serial == "" {
		return
	}

	r, exists := b.records[serial]
	if !exists {
		r = &Record{Serial: serial}
		b.records[serial] = r
	}

	r.Events = append(r.Events, ev)
	r.EventTypes = appendUniqueString(r.EventTypes, ev.EventType)

	if r.SessionID == 0 {
		r.SessionID = intFromMap(ev.Actor, "ses")
	}

	if r.AUID == "" {
		r.AUID = stringFromMap(ev.Actor, "auid")
	}

	if r.EUID == "" {
		r.EUID = stringFromMap(ev.Actor, "euid")
	}

	if r.Executable == "" {
		r.Executable = stringFromMap(ev.Actor, "exe")
	}

	if r.Command == "" {
		r.Command = stringFromMap(ev.Actor, "comm")
	}

	if r.PID == 0 {
		r.PID = ev.PID
	}

	if r.ParentPID == 0 {
		r.ParentPID = intFromMap(ev.Context, "ppid")
	}

	if r.Terminal == "" {
		r.Terminal = stringFromMap(ev.Actor, "tty")
	}

	if name, ok := ev.Context["name"].(string); ok && name != "" {
		r.Paths = appendUniqueString(r.Paths, name)
	}

	if key, ok := ev.Context["key"].(string); ok && key != "" {
		r.Keys = appendUniqueString(r.Keys, key)
	}
}

func (b *Builder) Records() []Record {
	result := make([]Record, 0, len(b.records))
	for _, r := range b.records {
		sort.Strings(r.EventTypes)
		sort.Strings(r.Paths)
		sort.Strings(r.Keys)
		result = append(result, *r)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Serial < result[j].Serial
	})

	return result
}

func serialFromRaw(raw string) string {
	m := serialRE.FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	return m[1]
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func stringFromMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}

	result, ok := value.(string)
	if !ok {
		return ""
	}

	return result
}

func intFromMap(values map[string]any, key string) int {
	value, ok := values[key]
	if !ok {
		return 0
	}

	result, ok := value.(int)
	if !ok {
		return 0
	}

	return result
}
