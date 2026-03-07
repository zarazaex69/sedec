// sedec is a production-grade decompiler for x86_64 binaries.
// it transforms compiled executables back into readable pseudocode through
// sophisticated analysis including disassembly, cfg recovery, ir lifting,
// ssa optimization, type inference, and code generation.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const version = "0.1.0-dev"

var (
	// errUnknownCommand indicates unknown command.
	errUnknownCommand = errors.New("unknown command")
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the cli with dependency injection for testability.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return nil
	}

	// handle global flags
	if args[0] == "--version" || args[0] == "-version" {
		//nolint:errcheck // version output is informational, errors are non-critical
		fmt.Fprintf(stdout, "sedec version %s\n", version)
		return nil
	}

	if args[0] == "--help" || args[0] == "-help" || args[0] == "help" {
		printUsage(stdout)
		return nil
	}

	// dispatch to subcommand
	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "disasm":
		return runDisasm(subArgs, stdin, stdout, stderr)
	case "cfg":
		return runCFG(subArgs, stdin, stdout, stderr)
	default:
		//nolint:errcheck,gosec // error message output is informational, subcommand is from args
		fmt.Fprintf(stderr, "unknown command: %s\n\n", subcommand)
		printUsage(stderr)
		return fmt.Errorf("%w: %s", errUnknownCommand, subcommand)
	}
}

// printUsage displays comprehensive help information.
func printUsage(w io.Writer) {
	//nolint:errcheck // usage output is informational, errors are non-critical
	fmt.Fprintf(w, `sedec - static executable decompiler
version: %s

usage:
  sedec <command> [options] [binary]
  sedec --version
  sedec --help

commands:
  disasm    disassemble binary to assembly output
  cfg       export control flow graph in dot format

global options:
  --version    print version information
  --help       print this help message

examples:
  # disassemble entire binary
  sedec disasm /bin/ls

  # disassemble specific function
  sedec disasm --function main /bin/ls

  # output to file
  sedec disasm --output output.asm /bin/ls

  # read from stdin (pipeline composition)
  cat /bin/ls | sedec disasm

  # specify output format
  sedec disasm --format intel /bin/ls

  # export control flow graph
  sedec cfg --output cfg.dot /bin/ls
  dot -Tpng cfg.dot -o cfg.png

run 'sedec <command> --help' for command-specific options.
`, version)
}
