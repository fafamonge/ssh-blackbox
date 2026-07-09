package auditrecord

import (
	"regexp"
	"sort"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

var serialRE = regexp.MustCompile(`audit\(.*:(\d+)\)`)

type Record struct {
	Serial     string           `json:"serial"`
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
