// Command stdioharness serves the tplaiter MCP tools over stdio JSON-RPC
// with the direct transport: every tool executes the tplaiter binary given
// by -exe, with the same sanitized environment, process-group cancellation
// and bounded output as the installed server, but without the installed
// held-stage image.
//
// It is a test fixture for the stdio contract suite (tests/mcp_stdio_test.go)
// and is never shipped: the production entry point is `tplaiter mcp-server`,
// which requires an installed registration. Its only extra knobs are the
// limits, so that the suite can prove timeout and cancellation behaviour in
// seconds rather than minutes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/mcpsrv"
)

func main() {
	exe := flag.String("exe", "", "absolute path of the tplaiter binary the tools execute")
	version := flag.String("version", "dev", "version reported in initialize and meta.tplaiterVersion")
	timeout := flag.Duration("timeout", 0, "deadline of quick tools (0 = production default)")
	longTimeout := flag.Duration("long-timeout", 0, "deadline of long tools (0 = production default)")
	grace := flag.Duration("grace", 0, "SIGTERM-to-SIGKILL grace for stopped children (0 = production default)")
	flag.Parse()

	path, err := filepath.Abs(*exe)
	if *exe == "" || err != nil {
		fmt.Fprintln(os.Stderr, "stdioharness: -exe must name the tplaiter binary")
		os.Exit(2)
	}
	srv := mcpsrv.NewDirect(path, *version)
	if srv == nil {
		fmt.Fprintln(os.Stderr, "stdioharness: invalid -exe")
		os.Exit(2)
	}
	srv.SetLimits(mcpsrv.Limits{DefaultTimeout: *timeout, LongTimeout: *longTimeout, KillGrace: *grace})
	if err := srv.ServeStdio(); err != nil {
		fmt.Fprintln(os.Stderr, "stdioharness:", err)
		os.Exit(1)
	}
}
