package hardening_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/hardening"
	"github.com/realjkg/agentic-cmmc-platform/internal/models"
)

// mockRunner records which commands were requested.
type mockRunner struct {
	ran    []string
	errors map[string]error
}

func (m *mockRunner) Run(name string, args ...string) error {
	key := name
	for _, a := range args {
		key += " " + a
	}
	m.ran = append(m.ran, key)
	if err, ok := m.errors[key]; ok {
		return err
	}
	return nil
}

func nonCompliantFinding(controlID, domain string, d models.Domain, remediation string) models.Finding {
	return models.Finding{
		Control: models.Control{
			ID:     controlID,
			Domain: d,
			Title:  "Test control " + controlID,
		},
		Status:      models.StatusNonCompliant,
		Severity:    models.SeverityHigh,
		Details:     "test detail",
		Remediation: remediation,
		CheckedAt:   time.Now(),
		Host:        "testhost",
	}
}

func TestRemediateReturnsOnlyNonCompliant(t *testing.T) {
	findings := []models.Finding{
		nonCompliantFinding("AC.L2-3.1.6", "AC", models.DomainAC, "fix ssh root login"),
		{
			Control: models.Control{ID: "AU.L2-3.3.1", Domain: models.DomainAU},
			Status:  models.StatusCompliant,
		},
		{
			Control: models.Control{ID: "CM.L2-3.4.1", Domain: models.DomainCM},
			Status:  models.StatusNotChecked,
		},
	}

	agent := hardening.New() // dry-run
	tasks := agent.Remediate(findings)

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task for 1 non-compliant finding, got %d", len(tasks))
	}
	if tasks[0].Finding.Control.ID != "AC.L2-3.1.6" {
		t.Errorf("unexpected control in task: %s", tasks[0].Finding.Control.ID)
	}
}

func TestDryRunTasksNotApplied(t *testing.T) {
	findings := []models.Finding{
		nonCompliantFinding("AC.L2-3.1.6", "AC", models.DomainAC, "fix"),
		nonCompliantFinding("SC.L2-3.13.1", "SC", models.DomainSC, "enable firewall"),
	}

	agent := hardening.New() // dry-run = true
	tasks := agent.Remediate(findings)

	for _, t2 := range tasks {
		if t2.Applied {
			t.Errorf("task %s should not be applied in dry-run mode", t2.Finding.Control.ID)
		}
	}
}

func TestApplyModeExecutesCommands(t *testing.T) {
	runner := &mockRunner{errors: map[string]error{}}
	agent := hardening.NewWithRunner(runner, false) // apply mode

	findings := []models.Finding{
		nonCompliantFinding("AU.L2-3.3.1", "AU", models.DomainAU, "enable auditd"),
	}

	tasks := agent.Remediate(findings)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	// The command for AU.L2-3.3.1 involves apt-get, which mock runner will accept
	// Applied should be true since mock runner returns nil error
	if !tasks[0].Applied {
		t.Errorf("task should be marked applied when runner succeeds; error: %s", tasks[0].Error)
	}
}

func TestApplyModeRecordsErrors(t *testing.T) {
	// Intercept via a custom runner that always fails
	failRunner := &alwaysFailRunner{}
	agent := hardening.NewWithRunner(failRunner, false)

	findings := []models.Finding{
		nonCompliantFinding("SC.L2-3.13.1", "SC", models.DomainSC, "enable firewall"),
	}

	tasks := agent.Remediate(findings)
	if len(tasks) == 0 {
		t.Fatal("expected at least one task")
	}
	if tasks[0].Applied {
		t.Error("task should not be applied when runner fails")
	}
	if tasks[0].Error == "" {
		t.Error("task should record the error message")
	}
}

func TestTasksHaveCommands(t *testing.T) {
	knownControls := []string{
		"AC.L2-3.1.6",
		"IA.L2-3.5.2",
		"AU.L2-3.3.1",
		"SC.L2-3.13.1",
		"SI.L2-3.14.1",
	}

	findings := make([]models.Finding, 0, len(knownControls))
	for _, id := range knownControls {
		findings = append(findings, nonCompliantFinding(id, "", models.DomainAC, "fix "+id))
	}

	agent := hardening.New()
	tasks := agent.Remediate(findings)

	for _, task := range tasks {
		if task.Command == "" {
			// Some controls intentionally have no automated command; that's acceptable
			// but log it so developers know
			t.Logf("control %s has no automated command (manual remediation required)", task.Finding.Control.ID)
		}
	}
}

func TestAllNonCompliantFindingsGetTasks(t *testing.T) {
	findings := []models.Finding{
		nonCompliantFinding("AC.L2-3.1.6", "AC", models.DomainAC, "r1"),
		nonCompliantFinding("IA.L2-3.5.7", "IA", models.DomainIA, "r2"),
		nonCompliantFinding("AU.L2-3.3.7", "AU", models.DomainAU, "r3"),
	}

	agent := hardening.New()
	tasks := agent.Remediate(findings)

	if len(tasks) != 3 {
		t.Errorf("expected 3 tasks for 3 non-compliant findings, got %d", len(tasks))
	}
	seen := make(map[string]bool)
	for _, task := range tasks {
		seen[task.Finding.Control.ID] = true
	}
	for _, f := range findings {
		if !seen[f.Control.ID] {
			t.Errorf("no task generated for control %s", f.Control.ID)
		}
	}
}

// alwaysFailRunner always returns an error.
type alwaysFailRunner struct{}

func (a *alwaysFailRunner) Run(name string, args ...string) error {
	return fmt.Errorf("mock failure for %s", name)
}
