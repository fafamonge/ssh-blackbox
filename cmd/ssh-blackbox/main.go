package main

import (
	"fmt"
	"os"

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
		}
	}

	fmt.Println("ssh-blackbox")
	fmt.Println("Evidence-first SSH security telemetry and forensic audit system.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ssh-blackbox version")
	fmt.Println("  ssh-blackbox status")
}
