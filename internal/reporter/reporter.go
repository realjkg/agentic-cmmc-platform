// Package reporter implements the CMMC audit reporting agent.
//
// It converts a slice of Findings into a structured Report and renders
// that report as human-readable text or machine-readable JSON.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
)

// Reporter generates compliance reports from scan findings.
type Reporter struct {
	title string
}

// New returns a Reporter with the given report title.
func New(title string) *Reporter {
	return &Reporter{title: title}
}

// BuildReport constructs a Report from a slice of Findings.
func (r *Reporter) BuildReport(host string, findings []models.Finding) models.Report {
	score := calcScore(findings)
	return models.Report{
		Title:       r.title,
		GeneratedAt: time.Now(),
		Host:        host,
		Findings:    findings,
		Score:       score,
		Summary:     buildSummary(score),
	}
}

// WriteText renders report as a human-readable table to w.
func (r *Reporter) WriteText(report models.Report, w io.Writer) error {
	fmt.Fprintf(w, "\n══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " %s\n", report.Title)
	fmt.Fprintf(w, " Host:         %s\n", report.Host)
	fmt.Fprintf(w, " Generated at: %s\n", report.GeneratedAt.Format(time.RFC1123))
	fmt.Fprintf(w, "══════════════════════════════════════════════════════════════\n\n")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTROL ID\tDOMAIN\tSTATUS\tSEVERITY\tTITLE")
	fmt.Fprintln(tw, strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 6)+"\t"+
		strings.Repeat("-", 14)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 50))

	for _, f := range report.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.Control.ID,
			string(f.Control.Domain),
			string(f.Status),
			string(f.Severity),
			f.Control.Title,
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "── Findings Detail ──────────────────────────────────────────")
	for _, f := range report.Findings {
		if f.Status == models.StatusNonCompliant {
			fmt.Fprintf(w, "\n[%s] %s – %s\n", f.Status, f.Control.ID, f.Control.Title)
			fmt.Fprintf(w, "  Severity   : %s\n", f.Severity)
			fmt.Fprintf(w, "  Details    : %s\n", f.Details)
			fmt.Fprintf(w, "  Remediation: %s\n", f.Remediation)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "── Compliance Score ─────────────────────────────────────────")
	fmt.Fprintf(w, "  Total checks    : %d\n", report.Score.Total)
	fmt.Fprintf(w, "  Compliant       : %d\n", report.Score.Compliant)
	fmt.Fprintf(w, "  Non-compliant   : %d\n", report.Score.NonCompliant)
	fmt.Fprintf(w, "  Not checked     : %d\n", report.Score.NotChecked)
	fmt.Fprintf(w, "  Score           : %.1f%%\n", report.Score.Percentage)
	fmt.Fprintf(w, "  Summary         : %s\n\n", report.Summary)

	return nil
}

// WriteJSON renders the report as indented JSON to w.
func (r *Reporter) WriteJSON(report models.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteTextFile writes a text report to path.
func (r *Reporter) WriteTextFile(report models.Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()
	return r.WriteText(report, f)
}

// WriteJSONFile writes a JSON report to path.
func (r *Reporter) WriteJSONFile(report models.Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JSON report file: %w", err)
	}
	defer f.Close()
	return r.WriteJSON(report, f)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func calcScore(findings []models.Finding) models.ComplianceScore {
	s := models.ComplianceScore{Total: len(findings)}
	for _, f := range findings {
		switch f.Status {
		case models.StatusCompliant:
			s.Compliant++
		case models.StatusNonCompliant:
			s.NonCompliant++
		default:
			s.NotChecked++
		}
	}
	if s.Total > 0 {
		// Score based on compliant + not-checked (not-checked is neutral)
		checked := s.Compliant + s.NonCompliant
		if checked > 0 {
			s.Percentage = math.Round(float64(s.Compliant)/float64(checked)*1000) / 10
		}
	}
	return s
}

func buildSummary(score models.ComplianceScore) string {
	switch {
	case score.Percentage >= 90:
		return "EXCELLENT – System is well-configured for CMMC L2 compliance"
	case score.Percentage >= 75:
		return "GOOD – Minor remediations required"
	case score.Percentage >= 50:
		return "NEEDS IMPROVEMENT – Significant gaps identified"
	default:
		return "CRITICAL – Major compliance gaps; immediate action required"
	}
}
