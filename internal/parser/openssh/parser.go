package openssh

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fafamonge/ssh-blackbox/internal/evidence"
)

var (
	baseRE = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+(.*)$`)

	invalidUserRE              = regexp.MustCompile(`^Invalid user (\S+) from ([0-9a-fA-F:.]+) port (\d+)$`)
	disconnectInvalidRE        = regexp.MustCompile(`^Disconnected from invalid user (\S+) ([0-9a-fA-F:.]+) port (\d+) \[preauth\]$`)
	disconnectAuthenticatingRE = regexp.MustCompile(`^Disconnected from authenticating user (\S+) ([0-9a-fA-F:.]+) port (\d+) \[preauth\]$`)
	receivedDisconnectRE       = regexp.MustCompile(`^Received disconnect from ([0-9a-fA-F:.]+) port (\d+):(.+)$`)
	acceptedPasswordRE         = regexp.MustCompile(`^Accepted password for (\S+) from ([0-9a-fA-F:.]+) port (\d+) ssh2$`)
	acceptedPublickeyRE        = regexp.MustCompile(`^Accepted publickey for (\S+) from ([0-9a-fA-F:.]+) port (\d+) ssh2`)
	failedPasswordRE           = regexp.MustCompile(`^Failed password for (invalid user )?(\S+) from ([0-9a-fA-F:.]+) port (\d+) ssh2$`)
	sessionOpenedRE            = regexp.MustCompile(`^pam_unix\(sshd:session\): session opened for user (\S+)\(uid=\d+\) by`)
	sessionClosedRE            = regexp.MustCompile(`^pam_unix\(sshd:session\): session closed for user (\S+)$`)
	connectionClosedRE         = regexp.MustCompile(`^Connection closed by (invalid user )?(\S+) ([0-9a-fA-F:.]+) port (\d+) \[preauth\]$`)
	subsystemRE                = regexp.MustCompile(`^subsystem request for (\S+) by user (\S+)$`)
)

func ParseLine(line string) (*evidence.Event, bool, error) {
	m := baseRE.FindStringSubmatch(line)
	if m == nil {
		return nil, false, nil
	}

	pid, err := strconv.Atoi(m[3])
	if err != nil {
		return nil, true, fmt.Errorf("invalid pid: %w", err)
	}

	ev := &evidence.Event{
		SchemaVersion: "0.1",
		Source:        "openssh_secure_log",
		TimestampRaw:  m[1],
		Hostname:      m[2],
		PID:           pid,
		Raw:           line,
		Actor:         map[string]any{},
		Context:       map[string]any{},
	}

	now := time.Now()
	ts, err := parseSyslogTimestamp(ev.TimestampRaw, now.Year(), time.Local)
	if err == nil {
		ev.Timestamp = ts
	}

	msg := m[4]

	if mm := invalidUserRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.auth.invalid_user"
		ev.Actor["username"] = mm[1]
		ev.Actor["ip"] = mm[2]
		ev.Actor["port"] = mustInt(mm[3])
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := disconnectInvalidRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.disconnected"
		ev.Actor["username"] = mm[1]
		ev.Actor["ip"] = mm[2]
		ev.Actor["port"] = mustInt(mm[3])
		ev.Context["user_state"] = "invalid"
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := disconnectAuthenticatingRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.disconnected"
		ev.Actor["username"] = mm[1]
		ev.Actor["ip"] = mm[2]
		ev.Actor["port"] = mustInt(mm[3])
		ev.Context["user_state"] = "authenticating"
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := receivedDisconnectRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.disconnect_received"
		ev.Actor["ip"] = mm[1]
		ev.Actor["port"] = mustInt(mm[2])
		ev.Context["message"] = strings.TrimSpace(mm[3])
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := acceptedPasswordRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.auth.accepted_password"
		ev.Actor["username"] = mm[1]
		ev.Actor["ip"] = mm[2]
		ev.Actor["port"] = mustInt(mm[3])
		ev.Context["auth_method"] = "password"
		return ev, true, nil
	}

	if mm := acceptedPublickeyRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.auth.accepted_publickey"
		ev.Actor["username"] = mm[1]
		ev.Actor["ip"] = mm[2]
		ev.Actor["port"] = mustInt(mm[3])
		ev.Context["auth_method"] = "publickey"
		return ev, true, nil
	}

	if mm := failedPasswordRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.auth.failed_password"
		ev.Actor["username"] = mm[2]
		ev.Actor["ip"] = mm[3]
		ev.Actor["port"] = mustInt(mm[4])
		if mm[1] != "" {
			ev.Context["user_state"] = "invalid"
		}
		ev.Context["auth_method"] = "password"
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := sessionOpenedRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.opened"
		ev.Actor["username"] = mm[1]
		return ev, true, nil
	}

	if mm := sessionClosedRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.closed"
		ev.Actor["username"] = mm[1]
		return ev, true, nil
	}

	if mm := connectionClosedRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.connection_closed"
		ev.Actor["username"] = mm[2]
		ev.Actor["ip"] = mm[3]
		ev.Actor["port"] = mustInt(mm[4])
		if mm[1] != "" {
			ev.Context["user_state"] = "invalid"
		}
		ev.Context["phase"] = "preauth"
		return ev, true, nil
	}

	if mm := subsystemRE.FindStringSubmatch(msg); mm != nil {
		ev.EventType = "ssh.session.subsystem"
		ev.Actor["username"] = mm[2]
		ev.Context["subsystem"] = mm[1]
		return ev, true, nil
	}

	ev.EventType = "ssh.unclassified"
	ev.Context["message"] = msg
	return ev, true, nil
}

func mustInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
