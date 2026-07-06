package reporter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
	"github.com/realjkg/agentic-cmmc-platform/internal/reporter"
)

func sampleFindings() []models.Finding {
	return []models.Finding{
		{
			Control:     models.Control{ID: "AC.L2-3.1.6", Domain: models.DomainAC, Title: "Non-Privileged Account Use"},
			Status:      models.StatusCompliant,
			Severity:    models.SeverityLow,
			Details:     "PermitRootLogin is set to 'no'",
			CheckedAt:   time.Now(),
			Host:        "testhost",
		},
		{
			Control:     models.Control{ID: "SC.L2-3.13.1", Domain: models.DomainSC, Title: "Boundary Protection"},
			Status:      models.StatusNonCompliant,
			Severity:    models.SeverityHigh,
			Details:     "No firewall active",
			Remediation: "Enable ufw",
			CheckedAt:   time.Now(),
			Host:        "testhost",
		},
	}
}

func TestBuildReport(t *testing.T) {
	r := reporter.New("Test Report")
	report := r.BuildReport("testhost", sampleFindings())

	if report.Title != "Test Report" {
		t.Errorf("unexpected title: %s", report.Title)
	}
	if report.Host != "testhost" {
		t.Errorf("unexpected host: %s", report.Host)
	}
	if report.Score.Total != 2 {
		t.Errorf("expected 2 total findings, got %d", report.Score.Total)
	}
	if report.Score.Compliant != 1 {
		t.Errorf("expected 1 compliant, got %d", report.Score.Compliant)
	}
	if report.Score.NonCompliant != 1 {
		t.Errorf("expected 1 non-compliant, got %d", report.Score.NonCompliant)
	}
	if report.Score.Percentage != 50.0 {
		t.Errorf("expected 50%% score, got %.1f%%", report.Score.Percentage)
	}
}

func TestWriteText(t *testing.T) {
	r := reporter.New("CMMC Audit")
	report := r.BuildReport("testhost", sampleFindings())

	var buf bytes.Buffer
	if err := r.WriteText(report, &buf); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CMMC Audit") {
		t.Error("text report should contain title")
	}
	if !strings.Contains(output, "AC.L2-3.1.6") {
		t.Error("text report should contain control IDs")
	}
	if !strings.Contains(output, "NON_COMPLIANT") {
		t.Error("text report should mention non-compliant status")
	}
	if !strings.Contains(output, "testhost") {
		t.Error("text report should contain host name")
	}
}

func TestWriteJSON(t *testing.T) {
	r := reporter.New("CMMC Audit")
	report := r.BuildReport("testhost", sampleFindings())

	var buf bytes.Buffer
	if err := r.WriteJSON(report, &buf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var decoded models.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}
	if decoded.Title != "CMMC Audit" {
		t.Errorf("decoded title mismatch: %s", decoded.Title)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("expected 2 findings in JSON, got %d", len(decoded.Findings))
	}
}

func TestBuildReport_EmptyFindings(t *testing.T) {
	r := reporter.New("Empty Report")
	report := r.BuildReport("host", []models.Finding{})

	if report.Score.Total != 0 {
		t.Errorf("expected 0 total, got %d", report.Score.Total)
	}
	if report.Score.Percentage != 0 {
		t.Errorf("expected 0%% percentage, got %f", report.Score.Percentage)
	}
}

func TestBuildReport_AllCompliant(t *testing.T) {
	findings := []models.Finding{
		{Status: models.StatusCompliant, Control: models.Control{ID: "AC.L2-3.1.1"}},
		{Status: models.StatusCompliant, Control: models.Control{ID: "AC.L2-3.1.6"}},
	}
	r := reporter.New("All Compliant")
	report := r.BuildReport("host", findings)

	if report.Score.Percentage != 100.0 {
		t.Errorf("expected 100%%, got %.1f%%", report.Score.Percentage)
	}
	if !strings.Contains(report.Summary, "EXCELLENT") {
		t.Errorf("expected EXCELLENT summary for 100%% score, got: %s", report.Summary)
	}
}

func TestBuildReport_NotChecked(t *testing.T) {
	findings := []models.Finding{
		{Status: models.StatusNotChecked, Control: models.Control{ID: "AC.L2-3.1.1"}},
		{Status: models.StatusCompliant, Control: models.Control{ID: "AC.L2-3.1.6"}},
	}
	r := reporter.New("Mixed")
	report := r.BuildReport("host", findings)

	if report.Score.NotChecked != 1 {
		t.Errorf("expected 1 not-checked, got %d", report.Score.NotChecked)
	}
	// Only 1 checked (compliant), so percentage = 100%
	if report.Score.Percentage != 100.0 {
		t.Errorf("expected 100%% when only checked finding is compliant, got %.1f%%",
			report.Score.Percentage)
	}
}
