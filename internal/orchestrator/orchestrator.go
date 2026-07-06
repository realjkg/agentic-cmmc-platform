// Package orchestrator coordinates the full CMMC L2 audit workflow.
//
// The workflow is:
//  1. Scanner   – identify non-compliant controls
//  2. Reporter  – produce a pre-hardening report
//  3. Hardening – generate (and optionally apply) remediations
//  4. Verifier  – confirm remediations succeeded
//  5. Reporter  – produce a post-hardening report
package orchestrator

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/hardening"
	"github.com/realjkg/agentic-cmmc-platform/internal/models"
	"github.com/realjkg/agentic-cmmc-platform/internal/reporter"
	"github.com/realjkg/agentic-cmmc-platform/internal/scanner"
	"github.com/realjkg/agentic-cmmc-platform/internal/verifier"
)

// Config holds orchestrator configuration.
type Config struct {
	// OutputDir is the directory where report files are written.
	// An empty string disables file output.
	OutputDir string

	// DryRun controls whether the hardening agent actually applies changes.
	DryRun bool

	// Format is "text", "json", or "both" (default: "both").
	Format string

	// Verbose prints extra progress lines to Stdout when true.
	Verbose bool

	// Stdout is the writer for console output (defaults to os.Stdout).
	Stdout io.Writer
}

// Result contains the outputs of a completed audit run.
type Result struct {
	PreReport      models.Report
	Tasks          []models.RemediationTask
	TestResults    []models.TestResult
	PostReport     models.Report
	PreReportPath  string
	PostReportPath string
}

// Orchestrator coordinates the CMMC audit pipeline.
type Orchestrator struct {
	cfg      Config
	scanner  *scanner.Scanner
	reporter *reporter.Reporter
	hardener *hardening.Agent
	verifier *verifier.Agent
}

// New returns an Orchestrator wired to the real OS.
func New(cfg Config) *Orchestrator {
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Format == "" {
		cfg.Format = "both"
	}
	sc := scanner.New()
	return &Orchestrator{
		cfg:      cfg,
		scanner:  sc,
		reporter: reporter.New("CMMC Level 2 Compliance Audit"),
		hardener: hardening.New(),
		verifier: verifier.NewWithScanner(sc),
	}
}

// NewWithAgents returns an Orchestrator using the supplied agents (for testing).
func NewWithAgents(
	cfg Config,
	sc *scanner.Scanner,
	rep *reporter.Reporter,
	hard *hardening.Agent,
	ver *verifier.Agent,
) *Orchestrator {
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Format == "" {
		cfg.Format = "both"
	}
	return &Orchestrator{
		cfg:      cfg,
		scanner:  sc,
		reporter: rep,
		hardener: hard,
		verifier: ver,
	}
}

// Run executes the full CMMC audit pipeline and returns the Result.
func (o *Orchestrator) Run() (*Result, error) {
	host, _ := os.Hostname()
	result := &Result{}

	// ── Step 1: Scan ──────────────────────────────────────────────────────────
	o.log("▶ [1/5] Running CMMC L2 compliance scan on %s …", host)
	findings := o.scanner.Scan()
	o.log("   %d checks completed.", len(findings))

	// ── Step 2: Pre-hardening report ─────────────────────────────────────────
	o.log("▶ [2/5] Building pre-hardening compliance report …")
	preReport := o.reporter.BuildReport(host, findings)
	result.PreReport = preReport

	if err := o.writeReport(preReport, "pre-hardening"); err != nil {
		return nil, err
	}
	if err := o.reporter.WriteText(preReport, o.cfg.Stdout); err != nil {
		return nil, err
	}

	// ── Step 3: Hardening ─────────────────────────────────────────────────────
	mode := "dry-run"
	if !o.cfg.DryRun {
		mode = "apply"
	}
	o.log("▶ [3/5] Running hardening agent (%s mode) …", mode)
	tasks := o.hardener.Remediate(findings)
	result.Tasks = tasks

	applied, manual := 0, 0
	for _, t := range tasks {
		if t.Applied {
			applied++
		} else if t.Command == "" {
			manual++
		}
	}
	o.log("   %d remediation task(s) generated (%d applied, %d manual).",
		len(tasks), applied, manual)

	printTasks(tasks, o.cfg.Stdout, o.cfg.DryRun)

	// ── Step 4: Verify ────────────────────────────────────────────────────────
	o.log("▶ [4/5] Running verification (testing) agent …")
	var testResults []models.TestResult
	if !o.cfg.DryRun {
		testResults = o.verifier.Verify(tasks)
	} else {
		// In dry-run mode, verifier re-uses the same pre-hardening findings
		// (nothing was changed) so we produce results directly.
		testResults = scanFindingsToTestResults(findings)
	}
	result.TestResults = testResults

	passed, failed := 0, 0
	for _, tr := range testResults {
		if tr.Passed {
			passed++
		} else {
			failed++
		}
	}
	o.log("   Verification: %d passed, %d failed.", passed, failed)

	// ── Step 5: Post-hardening report ─────────────────────────────────────────
	o.log("▶ [5/5] Building post-hardening compliance report …")
	// Build post findings from test results so the report reflects
	// verification outcomes.
	postFindings := testResultsToFindings(testResults, host)
	postReport := o.reporter.BuildReport(host, postFindings)
	postReport.Title = "CMMC Level 2 Post-Hardening Audit Report"
	result.PostReport = postReport

	if err := o.writeReport(postReport, "post-hardening"); err != nil {
		return nil, err
	}

	fmt.Fprintln(o.cfg.Stdout, "\n── Final Compliance Score ──────────────────────────────────")
	fmt.Fprintf(o.cfg.Stdout, "  Pre-hardening  : %.1f%%\n", preReport.Score.Percentage)
	fmt.Fprintf(o.cfg.Stdout, "  Post-hardening : %.1f%%\n", postReport.Score.Percentage)
	fmt.Fprintf(o.cfg.Stdout, "  Improvement    : %.1f%%\n",
		postReport.Score.Percentage-preReport.Score.Percentage)
	fmt.Fprintln(o.cfg.Stdout)

	return result, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (o *Orchestrator) log(format string, args ...any) {
	if o.cfg.Verbose {
		fmt.Fprintf(o.cfg.Stdout, format+"\n", args...)
	}
}

func (o *Orchestrator) writeReport(report models.Report, label string) error {
	if o.cfg.OutputDir == "" {
		return nil
	}
	if err := os.MkdirAll(o.cfg.OutputDir, 0o700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	ts := time.Now().Format("20060102-150405")
	base := filepath.Join(o.cfg.OutputDir, fmt.Sprintf("cmmc-audit-%s-%s", label, ts))

	if o.cfg.Format == "text" || o.cfg.Format == "both" {
		if err := o.reporter.WriteTextFile(report, base+".txt"); err != nil {
			return err
		}
	}
	if o.cfg.Format == "json" || o.cfg.Format == "both" {
		if err := o.reporter.WriteJSONFile(report, base+".json"); err != nil {
			return err
		}
	}
	return nil
}

func printTasks(tasks []models.RemediationTask, w io.Writer, dryRun bool) {
	if len(tasks) == 0 {
		return
	}
	mode := "DRY-RUN"
	if !dryRun {
		mode = "APPLIED"
	}
	fmt.Fprintf(w, "\n── Remediation Tasks [%s] ─────────────────────────────────\n", mode)
	for i, t := range tasks {
		status := "PENDING"
		if t.Applied {
			status = "APPLIED"
		} else if t.Error != "" {
			status = "FAILED"
		}
		fmt.Fprintf(w, " %2d. [%s] %s\n", i+1, status, t.Finding.Control.ID)
		fmt.Fprintf(w, "     Action : %s\n", t.Action)
		if t.Command != "" {
			fmt.Fprintf(w, "     Command: %s\n", t.Command)
		} else {
			fmt.Fprintf(w, "     Command: (manual remediation required)\n")
		}
		if t.Error != "" {
			fmt.Fprintf(w, "     Error  : %s\n", t.Error)
		}
	}
	fmt.Fprintln(w)
}

// scanFindingsToTestResults converts scan findings to TestResults.
func scanFindingsToTestResults(findings []models.Finding) []models.TestResult {
	results := make([]models.TestResult, 0, len(findings))
	now := time.Now()
	for _, f := range findings {
		results = append(results, models.TestResult{
			Control:  f.Control,
			Passed:   f.Status == models.StatusCompliant,
			Status:   f.Status,
			Details:  f.Details,
			TestedAt: now,
		})
	}
	return results
}

// testResultsToFindings converts TestResults back to Findings for report building.
// The original Status is preserved so NOT_CHECKED does not inflate the non-compliant count.
func testResultsToFindings(results []models.TestResult, host string) []models.Finding {
	findings := make([]models.Finding, 0, len(results))
	now := time.Now()
	for _, r := range results {
		status := r.Status
		if status == "" {
			// Fallback for TestResults without an explicit Status field.
			if r.Passed {
				status = models.StatusCompliant
			} else {
				status = models.StatusNonCompliant
			}
		}
		findings = append(findings, models.Finding{
			Control:   r.Control,
			Status:    status,
			Severity:  models.SeverityLow,
			Details:   r.Details,
			CheckedAt: now,
			Host:      host,
		})
	}
	return findings
}
