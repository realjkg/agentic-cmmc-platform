package models_test

import (
	"testing"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
)

func TestDomainConstants(t *testing.T) {
	domains := []models.Domain{
		models.DomainAC, models.DomainAT, models.DomainAU, models.DomainCM,
		models.DomainIA, models.DomainIR, models.DomainMA, models.DomainMP,
		models.DomainPE, models.DomainPS, models.DomainRA, models.DomainCA,
		models.DomainSC, models.DomainSI,
	}
	if len(domains) != 14 {
		t.Fatalf("expected 14 CMMC domains, got %d", len(domains))
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}
	if len(severities) != 4 {
		t.Fatalf("expected 4 severity levels, got %d", len(severities))
	}
}

func TestStatusConstants(t *testing.T) {
	statuses := []models.Status{
		models.StatusCompliant,
		models.StatusNonCompliant,
		models.StatusNotChecked,
	}
	if len(statuses) != 3 {
		t.Fatalf("expected 3 status values, got %d", len(statuses))
	}
}

func TestFindingFields(t *testing.T) {
	ctrl := models.Control{
		ID:      "AC.L2-3.1.1",
		Domain:  models.DomainAC,
		Title:   "Authorized Access Control",
		NISTRef: "NIST SP 800-171 Rev 2 3.1.1",
	}
	f := models.Finding{
		Control:     ctrl,
		Status:      models.StatusNonCompliant,
		Severity:    models.SeverityCritical,
		Details:     "Empty password detected",
		Remediation: "Set a password: passwd <user>",
		CheckedAt:   time.Now(),
		Host:        "testhost",
	}
	if f.Control.ID != "AC.L2-3.1.1" {
		t.Errorf("unexpected control ID: %s", f.Control.ID)
	}
	if f.Status != models.StatusNonCompliant {
		t.Errorf("unexpected status: %s", f.Status)
	}
}

func TestRemediationTaskFields(t *testing.T) {
	task := models.RemediationTask{
		Finding: models.Finding{
			Control: models.Control{ID: "SI.L2-3.14.1"},
			Status:  models.StatusNonCompliant,
		},
		Action:  "Install ClamAV",
		Command: "apt-get install -y clamav",
	}
	if task.Applied {
		t.Error("newly created task should not be marked as applied")
	}
	if task.Command == "" {
		t.Error("task should have a command")
	}
}

func TestReportComplianceScore(t *testing.T) {
	report := models.Report{
		Title:       "Test Report",
		GeneratedAt: time.Now(),
		Score: models.ComplianceScore{
			Total:        10,
			Compliant:    7,
			NonCompliant: 3,
			Percentage:   70.0,
		},
	}
	if report.Score.Total != 10 {
		t.Errorf("expected total 10, got %d", report.Score.Total)
	}
	if report.Score.Percentage != 70.0 {
		t.Errorf("expected percentage 70.0, got %f", report.Score.Percentage)
	}
}
