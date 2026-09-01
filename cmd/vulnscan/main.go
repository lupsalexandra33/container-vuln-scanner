// Command vulnscan is the command-line entry point.
//
// It is deliberately thin: it parses arguments, calls the library under pkg/,
// and formats the result. No business logic lives here.
package main

import (
	"fmt"
	"os"
)

var version = "dev" // overridden at build time via -ldflags

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vulnscan <command> [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("vulnscan", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}
