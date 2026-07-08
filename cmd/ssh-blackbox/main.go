package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fafamonge/ssh-blackbox/internal/correlation"
	"github.com/fafamonge/ssh-blackbox/internal/evidence_set"
	"github.com/fafamonge/ssh-blackbox/internal/link"
	"github.com/fafamonge/ssh-blackbox/internal/parser/auditd"
	"github.com/fafamonge/ssh-blackbox/internal/parser/openssh"
	"github.com/fafamonge/ssh-blackbox/internal/session"
	"github.com/fafamonge/ssh-blackbox/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("%s %s\n", version.Name, version.Version)
			return
		case "status":
			fmt.Println("ssh-blackbox: evidence core not running yet")
			return
		case "parse":
			if err := runParse(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		case "parse-audit":
			if err := runParseAudit(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		case "evidence-set":
			if err := runEvidenceSet(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	printUsage()
}

func runParse(args []string) error {
	filePath, err := parseFileArg("parse", args)
	if err != nil {
		return err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	builder := session.NewBuilder()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := openssh.ParseLine(scanner.Text())
		if err != nil {
			return err
		}

		if !matched {
			continue
		}

		builder.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)

	for _, s := range builder.Sessions() {
		if err := encoder.Encode(s); err != nil {
			return err
		}
	}

	return nil
}

func runParseAudit(args []string) error {
	filePath, err := parseFileArg("parse-audit", args)
	if err != nil {
		return err
	}

	sessions, err := buildAuditSessionsFromFile(filePath)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)

	for _, s := range sessions {
		if err := encoder.Encode(s); err != nil {
			return err
		}
	}

	return nil
}

func runEvidenceSet(args []string) error {
	var sshFile string
	var auditFile string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ssh-file":
			if i+1 >= len(args) {
				return fmt.Errorf("--ssh-file requires a path")
			}
			sshFile = args[i+1]
			i++
		case "--audit-file":
			if i+1 >= len(args) {
				return fmt.Errorf("--audit-file requires a path")
			}
			auditFile = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown evidence-set argument: %s", args[i])
		}
	}

	es := evidence_set.New()

	if sshFile != "" {
		sshSessions, err := buildSSHSessionsFromFile(sshFile)
		if err != nil {
			return err
		}
		es.SSHSessions = sshSessions
	}

	if auditFile != "" {
		auditSessions, err := buildAuditSessionsFromFile(auditFile)
		if err != nil {
			return err
		}
		es.AuditSessions = auditSessions
	}

	es.Links = link.Build(es.SSHSessions, es.AuditSessions)

	encoder := json.NewEncoder(os.Stdout)
	return encoder.Encode(es)
}

func buildSSHSessionsFromFile(filePath string) ([]session.SSHSession, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	builder := session.NewBuilder()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := openssh.ParseLine(scanner.Text())
		if err != nil {
			return nil, err
		}

		if !matched {
			continue
		}

		builder.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return builder.Sessions(), nil
}

func buildAuditSessionsFromFile(filePath string) ([]correlation.AuditSession, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	builder := correlation.NewAuditSessionBuilder()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		ev, matched, err := auditd.ParseLine(scanner.Text())
		if err != nil {
			return nil, err
		}

		if !matched {
			continue
		}

		builder.AddEvent(*ev)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return builder.Sessions(), nil
}

func parseFileArg(command string, args []string) (string, error) {
	var filePath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 >= len(args) {
				return "", fmt.Errorf("--file requires a path")
			}
			filePath = args[i+1]
			i++
		default:
			return "", fmt.Errorf("unknown %s argument: %s", command, args[i])
		}
	}

	if filePath == "" {
		return "", fmt.Errorf("%s requires --file", command)
	}

	return filePath, nil
}

func printUsage() {
	fmt.Println("ssh-blackbox")
	fmt.Println("Evidence-first SSH security telemetry and forensic audit system.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ssh-blackbox version")
	fmt.Println("  ssh-blackbox status")
	fmt.Println("  ssh-blackbox parse --file <secure.log>")
	fmt.Println("  ssh-blackbox parse-audit --file <audit.log>")
	fmt.Println("  ssh-blackbox evidence-set --ssh-file <secure.log> --audit-file <audit.log>")
}
