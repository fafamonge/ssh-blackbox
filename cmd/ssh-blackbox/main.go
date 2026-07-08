package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

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
		}
	}

	printUsage()
}

func runParse(args []string) error {
	var filePath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("--file requires a path")
			}
			filePath = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown parse argument: %s", args[i])
		}
	}

	if filePath == "" {
		return fmt.Errorf("parse requires --file")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	builder := session.NewBuilder()
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		ev, matched, err := openssh.ParseLine(line)
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

func printUsage() {
	fmt.Println("ssh-blackbox")
	fmt.Println("Evidence-first SSH security telemetry and forensic audit system.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ssh-blackbox version")
	fmt.Println("  ssh-blackbox status")
	fmt.Println("  ssh-blackbox parse --file <secure.log>")
}
