package verifier_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
	"github.com/realjkg/agentic-cmmc-platform/internal/scanner"
	"github.com/realjkg/agentic-cmmc-platform/internal/verifier"
)

// ---------------------------------------------------------------------------
// Shared mock checker (duplicated here to keep packages independent)
// ---------------------------------------------------------------------------

type mockChecker struct {
	files    map[string][]byte
	commands map[string]string
	cmdErrs  map[string]error
	hostname string
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
	return "", fmt.Errorf("mock: command not configured: %s", key)
}

func (m *mockChecker) FileExists(path string) bool {
	_, ok := m.files[path]
	return ok
}

func (m *mockChecker) Hostname() (string, error) {
	if m.hostname == "" {
		return "testhost", nil
	}
	return m.hostname, nil
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
			// Provide a shadow file with properly locked/hashed accounts (no empty hashes)
			"/etc/shadow": []byte(
				"root:$6$abcdef$hashvalue:19000:0:99999:7:::\n" +
					"daemon:*:19000:0:99999:7:::\n" +
					"nobody:!:19000:0:99999:7:::\n"),
		},
		commands: map[string]string{
			"systemctl is-active auditd":  "active",
			"systemctl is-active chronyd": "active",
			"ufw status":                  "Status: active\n",
			"find /etc /bin /usr/bin /usr/sbin /sbin -xdev -perm -002 -type f": "",
			"getenforce":     "Enforcing",
			"pgrep -x clamd": "1234",
			"ls /etc/sudoers.d/": "",
			"stat -c %a %n /etc/cron.d":       "755 /etc/cron.d",
			"stat -c %a %n /etc/cron.daily":   "755 /etc/cron.daily",
			"stat -c %a %n /etc/cron.weekly":  "755 /etc/cron.weekly",
			"stat -c %a %n /etc/cron.monthly": "755 /etc/cron.monthly",
			"stat -c %a %n /etc/cron.hourly":  "755 /etc/cron.hourly",
		},
		cmdErrs: map[string]error{},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestVerifyAll_AllCompliant(t *testing.T) {
	sc := scanner.NewWithChecker(compliantMock())
	agent := verifier.NewWithScanner(sc)

	results := agent.VerifyAll()
	if len(results) == 0 {
		t.Fatal("expected non-empty test results")
	}

	for _, r := range results {
		if !r.Passed {
			t.Errorf("expected all results to pass with compliant config; %s failed: %s",
				r.Control.ID, r.Details)
		}
	}
}

func TestVerify_OnlyIncludesAppliedControls(t *testing.T) {
	sc := scanner.NewWithChecker(compliantMock())
	agent := verifier.NewWithScanner(sc)

	tasks := []models.RemediationTask{
		{
			Finding: models.Finding{
				Control: models.Control{ID: "AC.L2-3.1.6", Domain: models.DomainAC},
				Status:  models.StatusNonCompliant,
			},
			Applied: true,
		},
	}

	results := agent.Verify(tasks)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 1 task, got %d", len(results))
	}
	if results[0].Control.ID != "AC.L2-3.1.6" {
		t.Errorf("unexpected control ID in result: %s", results[0].Control.ID)
	}
}

func TestPassRate_AllPassed(t *testing.T) {
	results := []models.TestResult{
		{Passed: true},
		{Passed: true},
		{Passed: true},
	}
	rate := verifier.PassRate(results)
	if rate != 100.0 {
		t.Errorf("expected 100%% pass rate, got %.1f%%", rate)
	}
}

func TestPassRate_HalfPassed(t *testing.T) {
	results := []models.TestResult{
		{Passed: true},
		{Passed: false},
	}
	rate := verifier.PassRate(results)
	if rate != 50.0 {
		t.Errorf("expected 50%% pass rate, got %.1f%%", rate)
	}
}

func TestPassRate_Empty(t *testing.T) {
	rate := verifier.PassRate([]models.TestResult{})
	if rate != 0 {
		t.Errorf("expected 0%% for empty results, got %.1f%%", rate)
	}
}

func TestVerifyAll_ResultsHaveTimestamp(t *testing.T) {
	sc := scanner.NewWithChecker(compliantMock())
	agent := verifier.NewWithScanner(sc)

	results := agent.VerifyAll()
	for _, r := range results {
		if r.TestedAt.IsZero() {
			t.Errorf("result for %s has zero timestamp", r.Control.ID)
		}
	}
}
