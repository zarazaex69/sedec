// sedec is a production-grade decompiler for x86_64 binaries.
// It transforms compiled executables back into readable pseudocode through
// sophisticated analysis including disassembly, CFG recovery, IR lifting,
// SSA optimization, type inference, and code generation.
package main

import (
	"flag"
	"fmt"
	"os"
)

const version = "0.1.0-dev"

func main() {
	// parse command line flags
	versionFlag := flag.Bool("version", false, "print version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("sedec version %s\n", version)
		os.Exit(0)
	}

	// entry point for sedec decompiler
	fmt.Println("sedec: static executable decompiler")
	fmt.Printf("version: %s\n", version)
	fmt.Println("usage: sedec [options] <binary>")
}
