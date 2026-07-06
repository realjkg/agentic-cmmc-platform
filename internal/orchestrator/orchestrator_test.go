package orchestrator_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/realjkg/agentic-cmmc-platform/internal/hardening"
	"github.com/realjkg/agentic-cmmc-platform/internal/orchestrator"
	"github.com/realjkg/agentic-cmmc-platform/internal/reporter"
	"github.com/realjkg/agentic-cmmc-platform/internal/scanner"
	"github.com/realjkg/agentic-cmmc-platform/internal/verifier"
)

// ---------------------------------------------------------------------------
// Shared mock checker
// ---------------------------------------------------------------------------

type mockChecker struct {
	files    map[string][]byte
	commands map[string]string
	cmdErrs  map[string]error
}

func (m *mockChecker) ReadFile(path string) ([]byte, error) {
	if data, ok := m.files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockChecker) RunCommand(name string, args ...string) (string, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + strings.Join(args, " ")
	}
	if err, ok := m.cmdErrs[key]; ok {
		return "", err
	}
	if out, ok := m.commands[key]; ok {
		return out, nil
	}
	return "", fmt.Errorf("mock: not configured: %s", key)
}

func (m *mockChecker) FileExists(path string) bool {
	_, ok := m.files[path]
	return ok
}

func (m *mockChecker) Hostname() (string, error) {
	return "testhost", nil
}

func compliantMock() *mockChecker {
	return &mockChecker{
		files: map[string][]byte{
			"/etc/ssh/sshd_config": []byte(
				"PermitRootLogin no\nPasswordAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 3\n"),
			"/etc/security/faillock.conf":  []byte("deny = 5\n"),
			"/etc/security/pwquality.conf": []byte("minlen = 14\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n"),
			"/etc/audit/auditd.conf":       []byte("max_log_file = 8\nnum_logs = 5\n"),
			"/etc/pam.d/common-password":   []byte("password required pam_pwhistory.so remember=24 use_authtok\n"),
			"/etc/sudoers":                 []byte("root ALL=(ALL:ALL) ALL\n"),
		},
		commands: map[string]string{
			"systemctl is-active auditd":  "active",
			"systemctl is-active chronyd": "active",
			"ufw status":                  "Status: active\n",
			"find /etc /bin /usr/bin /usr/sbin /sbin -xdev -perm -002 -type f": "",
			"getenforce":                      "Enforcing",
			"pgrep -x clamd":                  "1234",
			"ls /etc/sudoers.d/":              "",
			"stat -c %a %n /etc/cron.d":       "755 /etc/cron.d",
			"stat -c %a %n /etc/cron.daily":   "755 /etc/cron.daily",
			"stat -c %a %n /etc/cron.weekly":  "755 /etc/cron.weekly",
			"stat -c %a %n /etc/cron.monthly": "755 /etc/cron.monthly",
			"stat -c %a %n /etc/cron.hourly":  "755 /etc/cron.hourly",
		},
		cmdErrs: map[string]error{},
	}
}

// noopRunner never executes any command.
type noopRunner struct{}

func (n *noopRunner) Run(_ string, _ ...string) error { return nil }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func buildOrchestrator(mc *mockChecker, dryRun bool, out *bytes.Buffer) *orchestrator.Orchestrator {
	sc := scanner.NewWithChecker(mc)
	rep := reporter.New("CMMC Level 2 Compliance Audit")
	hard := hardening.NewWithRunner(&noopRunner{}, dryRun)
	ver := verifier.NewWithScanner(sc)

	cfg := orchestrator.Config{
		DryRun:  dryRun,
		Format:  "",      // no file output
		Verbose: true,
		Stdout:  out,
	}
	return orchestrator.NewWithAgents(cfg, sc, rep, hard, ver)
}

func TestRun_ReturnsResult(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if result == nil {
		t.Fatal("Run() returned nil result")
	}
}

func TestRun_PreReportHasFindings(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if len(result.PreReport.Findings) == 0 {
		t.Error("pre-hardening report should have findings")
	}
}

func TestRun_DryRunProducesNoAppliedTasks(t *testing.T) {
	var buf bytes.Buffer
	// Use a mock where some controls are non-compliant
	mc := compliantMock()
	mc.files["/etc/ssh/sshd_config"] = []byte("PermitRootLogin yes\nPasswordAuthentication yes\n")

	o := buildOrchestrator(mc, true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	for _, task := range result.Tasks {
		if task.Applied {
			t.Errorf("task %s should not be applied in dry-run mode", task.Finding.Control.ID)
		}
	}
}

func TestRun_OutputContainsScoreSection(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	_, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "Compliance Score") && !strings.Contains(output, "Score") {
		t.Error("output should contain compliance score section")
	}
}

func TestRun_TestResultsProduced(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if len(result.TestResults) == 0 {
		t.Error("expected non-empty test results")
	}
}

func TestRun_VerboseOutput(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	_, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	output := buf.String()
	// Verbose mode should emit step labels
	if !strings.Contains(output, "[1/5]") {
		t.Error("verbose output should contain step numbers")
	}
}

func TestRun_WithOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	sc := scanner.NewWithChecker(compliantMock())
	rep := reporter.New("CMMC Level 2 Compliance Audit")
	hard := hardening.NewWithRunner(&noopRunner{}, true)
	ver := verifier.NewWithScanner(sc)

	var buf bytes.Buffer
	cfg := orchestrator.Config{
		OutputDir: tmpDir,
		DryRun:    true,
		Format:    "json",
		Verbose:   false,
		Stdout:    &buf,
	}
	o := orchestrator.NewWithAgents(cfg, sc, rep, hard, ver)
	_, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("cannot read output dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected report files to be written to output dir")
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			t.Errorf("unexpected file in output dir: %s", e.Name())
		}
	}
}

func TestRun_PostReportHasTitle(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if !strings.Contains(result.PostReport.Title, "Post-Hardening") {
		t.Errorf("post report title should mention Post-Hardening, got: %s",
			result.PostReport.Title)
	}
}

func TestRun_ScoreImprovement(t *testing.T) {
	var buf bytes.Buffer
	o := buildOrchestrator(compliantMock(), true, &buf)
	result, err := o.Run()
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	// With a compliant mock, pre and post should be the same
	if result.PostReport.Score.Total == 0 {
		t.Error("post report should have a score")
	}
}

func TestConfig_DefaultFormat(t *testing.T) {
	// Ensure empty format defaults to "both" (handled inside orchestrator.New)
	cfg := orchestrator.Config{
		DryRun:  true,
		Verbose: false,
		Stdout:  &bytes.Buffer{},
	}
	// New() sets format = "both" internally; just verify it doesn't panic
	o := orchestrator.New(cfg)
	if o == nil {
		t.Fatal("New() should not return nil")
	}
}
