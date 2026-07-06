// Command cmmc-audit is the CLI entry point for the CMMC Level 2 audit platform.
//
// Usage:
//
//	cmmc-audit [flags]
//
// Flags:
//
//	-apply        Apply remediation tasks (requires elevated privileges for some checks)
//	-output-dir   Directory for report files (default: current directory)
//	-format       Report format: text | json | both (default: both)
//	-verbose      Print progress information
//	-scan-only    Scan and report only; skip hardening and verification
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/realjkg/agentic-cmmc-platform/internal/orchestrator"
)

func main() {
	var (
		apply     = flag.Bool("apply", false, "Apply remediation tasks (requires root for most fixes)")
		outputDir = flag.String("output-dir", ".", "Directory to write report files into")
		format    = flag.String("format", "both", "Report format: text | json | both")
		verbose   = flag.Bool("verbose", true, "Print progress information")
		scanOnly  = flag.Bool("scan-only", false, "Only scan and report; skip hardening and verification")
	)
	flag.Parse()

	dryRun := !*apply

	if *scanOnly {
		dryRun = true
	}

	cfg := orchestrator.Config{
		OutputDir: *outputDir,
		DryRun:    dryRun,
		Format:    *format,
		Verbose:   *verbose,
		Stdout:    os.Stdout,
	}

	o := orchestrator.New(cfg)
	result, err := o.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit failed: %v\n", err)
		os.Exit(1)
	}

	// Exit code 1 when non-compliant findings remain after remediation.
	if result.PostReport.Score.NonCompliant > 0 {
		fmt.Fprintf(os.Stderr,
			"\n%d non-compliant control(s) remain after remediation. Review the report for manual steps.\n",
			result.PostReport.Score.NonCompliant)
		os.Exit(1)
	}
}
