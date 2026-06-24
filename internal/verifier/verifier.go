// Package verifier implements the CMMC post-hardening testing agent.
//
// After the hardening agent has applied remediations, the verifier re-runs
// a targeted set of scanner checks to confirm the fixes are in place.
package verifier

import (
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
	"github.com/realjkg/agentic-cmmc-platform/internal/scanner"
)

// Agent verifies that remediations from the hardening agent were applied
// successfully by re-scanning the affected controls.
type Agent struct {
	s *scanner.Scanner
}

// New returns a Verifier that uses the real operating system scanner.
func New() *Agent {
	return &Agent{s: scanner.New()}
}

// NewWithScanner returns a Verifier backed by the supplied scanner.
// This is the primary constructor for tests.
func NewWithScanner(s *scanner.Scanner) *Agent {
	return &Agent{s: s}
}

// Verify re-scans the controls that had remediation tasks applied and returns
// a TestResult for each one.
func (a *Agent) Verify(tasks []models.RemediationTask) []models.TestResult {
	// Build an index of applied control IDs → RemediationTask
	applied := make(map[string]models.RemediationTask, len(tasks))
	for _, t := range tasks {
		applied[t.Finding.Control.ID] = t
	}

	// Re-run a full scan and filter down to the relevant controls.
	allFindings := a.s.Scan()

	results := make([]models.TestResult, 0, len(applied))
	for _, f := range allFindings {
		t, ok := applied[f.Control.ID]
		if !ok {
			continue
		}

		passed := f.Status == models.StatusCompliant
		details := f.Details
		if !passed && t.Error != "" {
			details = "Remediation failed: " + t.Error + ". Re-scan result: " + f.Details
		}

		results = append(results, models.TestResult{
			Control:  f.Control,
			Passed:   passed,
			Status:   f.Status,
			Details:  details,
			TestedAt: time.Now(),
		})
	}

	return results
}

// VerifyAll re-scans all controls (not just remediated ones) and returns a
// complete set of TestResults.  Useful for a final compliance gate check.
func (a *Agent) VerifyAll() []models.TestResult {
	findings := a.s.Scan()
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

// PassRate returns the percentage of TestResults that passed.
func PassRate(results []models.TestResult) float64 {
	if len(results) == 0 {
		return 0
	}
	var passed int
	for _, r := range results {
		if r.Passed {
			passed++
		}
	}
	return float64(passed) / float64(len(results)) * 100
}
