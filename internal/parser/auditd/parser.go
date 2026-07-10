package auditd

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

var (
	typeRE = regexp.MustCompile(`^type=([A-Z_]+)\s+msg=audit\(([^)]+)\)\s*:\s*(.*)$`)
	pairRE = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_-]*)=("[^"]*"|'[^']*'|\S+)`)
)

func ParseLine(line string) (*evidence.Event, bool, error) {
	m := typeRE.FindStringSubmatch(line)
	if m == nil {
		return nil, false, nil
	}

	auditType := m[1]
	timestampRaw := m[2]
	body := m[3]

	ev := &evidence.Event{
		SchemaVersion: "0.1",
		EventType:     "auditd." + strings.ToLower(auditType),
		Source:        "auditd",
		TimestampRaw:  timestampRaw,
		Raw:           line,
		Actor:         map[string]any{},
		Context:       map[string]any{},
	}

	for _, mm := range pairRE.FindAllStringSubmatch(body, -1) {
		key := mm[1]
		value := cleanValue(mm[2])

		switch key {
		case "pid":
			ev.PID = mustInt(value)

		case "auid", "uid", "euid":
			storeActorIdentity(ev, key, value)

		case "AUID", "UID", "EUID":
			storeResolvedActorIdentity(ev, key, value)

		case "ses", "tty", "comm", "exe", "addr", "terminal":
			ev.Actor[key] = typedValue(value)

		case "syscall":
			ev.Context["syscall_id"] = typedValue(value)
			if _, exists := ev.Context["syscall"]; !exists {
				ev.Context["syscall"] = typedValue(value)
			}

		case "SYSCALL":
			ev.Context["syscall"] = value

		default:
			ev.Context[key] = typedValue(value)
		}
	}

	parseNestedMsgPairs(ev)

	return ev, true, nil
}

func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	v = strings.Trim(v, `'`)
	return v
}

func typedValue(v string) any {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return v
}

func mustInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func storeActorIdentity(ev *evidence.Event, key, value string) {
	typed := typedValue(value)

	if _, ok := typed.(int); ok {
		ev.Actor[key+"_id"] = typed

		if _, exists := ev.Actor[key]; !exists {
			ev.Actor[key] = typed
		}
		return
	}

	ev.Actor[key] = typed
}

func storeResolvedActorIdentity(ev *evidence.Event, key, value string) {
	normalizedKey := strings.ToLower(key)
	ev.Actor[normalizedKey] = value
}

func parseNestedMsgPairs(ev *evidence.Event) {
	msg, ok := ev.Context["msg"].(string)
	if !ok || msg == "" {
		return
	}

	for _, mm := range pairRE.FindAllStringSubmatch(msg, -1) {
		key := mm[1]
		value := cleanValue(mm[2])

		switch key {
		case "addr", "terminal":
			if _, exists := ev.Actor[key]; !exists {
				ev.Actor[key] = typedValue(value)
			}
		default:
			if _, exists := ev.Context[key]; !exists {
				ev.Context[key] = typedValue(value)
			}
		}
	}
}
