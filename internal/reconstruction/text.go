package reconstruction

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fafamonge/ssh-blackbox/internal/change"
)

func WriteText(
	w io.Writer,
	reconstructions []Reconstruction,
	unlinkedChanges []change.CriticalChange,
) error {
	for index, r := range reconstructions {
		if index > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintln(w, "SSH SESSION"); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(w, "Actor:        %s\n", r.User); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(
			w,
			"Remote:       %s:%d\n",
			r.RemoteIP,
			r.RemotePort,
		); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(w, "Auth:         %s\n", r.AuthMethod); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(w, "Opened:       %s\n", r.StartRaw); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(w, "LINKED AUDIT SESSION"); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(
			w,
			"Audit session: %d\n",
			r.AuditSessionID,
		); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(
			w,
			"Original actor: %s\n",
			r.OriginalActor,
		); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(
			w,
			"Effective users: %s\n",
			strings.Join(r.EffectiveUsers, ", "),
		); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(
			w,
			"Terminals:      %s\n",
			strings.Join(r.Terminals, ", "),
		); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(w, "RECORDED EXECUTIONS"); err != nil {
			return err
		}

		relevantExecutions, summarizedExecutions := selectExecutionsForText(
			r.Executions,
			r.CriticalChanges,
		)

		for _, execution := range relevantExecutions {
			if _, err := fmt.Fprintf(
				w,
				"%s  actor=%s  euid=%s  exe=%s  pid=%d  ppid=%d  tty=%s\n",
				execution.TimestampRaw,
				execution.OriginalActor,
				execution.EffectiveUser,
				execution.Executable,
				execution.PID,
				execution.ParentPID,
				execution.Terminal,
			); err != nil {
				return err
			}
		}

		if len(summarizedExecutions) > 0 {
			if _, err := fmt.Fprintln(w, "Additional recorded executions:"); err != nil {
				return err
			}

			for _, summary := range summarizedExecutions {
				if _, err := fmt.Fprintf(
					w,
					"- %s: %d record(s)\n",
					summary.Executable,
					summary.Count,
				); err != nil {
					return err
				}
			}
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}

		if len(r.CriticalChanges) > 0 {

			if _, err := fmt.Fprintln(w, "CRITICAL FILE CHANGES"); err != nil {
				return err
			}

			for _, change := range r.CriticalChanges {
				if _, err := fmt.Fprintf(
					w,
					"serial=%s operation=%s actor=%s euid=%s exe=%s pid=%d ppid=%d tty=%s paths=%s keys=%s\n",
					change.Serial,
					change.Operation,
					change.OriginalActor,
					change.EffectiveUser,
					change.Executable,
					change.PID,
					change.ParentPID,
					change.Terminal,
					strings.Join(change.Paths, ", "),
					strings.Join(change.Keys, ", "),
				); err != nil {
					return err
				}
			}
		}

		if _, err := fmt.Fprintln(w, "LINK BASIS"); err != nil {
			return err
		}

		for _, reason := range r.LinkReasons {
			if _, err := fmt.Fprintf(w, "- %s\n", reason); err != nil {
				return err
			}
		}
	}

	if len(unlinkedChanges) > 0 {
		if len(reconstructions) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprintln(w, "UNLINKED CRITICAL EVIDENCE"); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(
			w,
			"Recorded critical changes not attributed to a linked SSH session.",
		); err != nil {
			return err
		}

		for _, criticalChange := range unlinkedChanges {
			if _, err := fmt.Fprintf(
				w,
				"serial=%s audit_session=%d operation=%s actor=%s euid=%s exe=%s pid=%d ppid=%d tty=%s paths=%s keys=%s\n",
				criticalChange.Serial,
				criticalChange.AuditSession,
				criticalChange.Operation,
				criticalChange.OriginalActor,
				criticalChange.EffectiveUser,
				criticalChange.Executable,
				criticalChange.PID,
				criticalChange.ParentPID,
				criticalChange.Terminal,
				strings.Join(criticalChange.Paths, ", "),
				strings.Join(criticalChange.Keys, ", "),
			); err != nil {
				return err
			}
		}
	}

	return nil
}

type executionSummary struct {
	Executable string
	Count      int
}

func selectExecutionsForText(
	executions []RecordedExecution,
	criticalChanges []change.CriticalChange,
) ([]RecordedExecution, []executionSummary) {
	if len(executions) == 0 {
		return nil, nil
	}

	relevantPIDs := make(map[int]struct{})

	for _, criticalChange := range criticalChanges {
		if criticalChange.PID != 0 {
			relevantPIDs[criticalChange.PID] = struct{}{}
		}

		if criticalChange.ParentPID != 0 {
			relevantPIDs[criticalChange.ParentPID] = struct{}{}
		}
	}

	relevant := make([]RecordedExecution, 0)
	summaryCounts := make(map[string]int)

	for index, execution := range executions {
		_, pidRelevant := relevantPIDs[execution.PID]

		if index == 0 || pidRelevant {
			relevant = append(relevant, execution)
			continue
		}

		executable := execution.Executable
		if executable == "" {
			executable = "(unknown)"
		}

		summaryCounts[executable]++
	}

	executables := make([]string, 0, len(summaryCounts))
	for executable := range summaryCounts {
		executables = append(executables, executable)
	}

	sort.Strings(executables)

	summaries := make([]executionSummary, 0, len(executables))
	for _, executable := range executables {
		summaries = append(summaries, executionSummary{
			Executable: executable,
			Count:      summaryCounts[executable],
		})
	}

	return relevant, summaries
}
