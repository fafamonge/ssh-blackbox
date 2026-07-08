package reconstruction

import (
	"fmt"
	"io"
	"strings"
)

func WriteText(w io.Writer, reconstructions []Reconstruction) error {
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

		for _, execution := range r.Executions {
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

		if _, err := fmt.Fprintln(w); err != nil {
			return err
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

	return nil
}
