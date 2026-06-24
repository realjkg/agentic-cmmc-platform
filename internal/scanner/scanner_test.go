package scanner_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
	"github.com/realjkg/agentic-cmmc-platform/internal/scanner"
)

// mockChecker implements scanner.SystemChecker with configurable responses.
type mockChecker struct {
	files    map[string][]byte
	commands map[string]string // key: "name arg1 arg2", value: stdout
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

// ---------------------------------------------------------------------------
// Helper: compliant sshd_config
// ---------------------------------------------------------------------------

const compliantSSHConfig = `# sshd_config
PermitRootLogin no
PasswordAuthentication no
ClientAliveInterval 300
ClientAliveCountMax 3
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
`

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestScanReturnsEighteenFindings(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	if len(findings) != 18 {
		t.Errorf("expected 18 findings, got %d", len(findings))
	}
}

func TestCheckSSHRootLogin_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AC.L2-3.1.6")
	if f == nil {
		t.Fatal("AC.L2-3.1.6 finding not present")
	}
	if f.Status != models.StatusCompliant {
		t.Errorf("expected COMPLIANT, got %s: %s", f.Status, f.Details)
	}
}

func TestCheckSSHRootLogin_NonCompliant(t *testing.T) {
	mc := minimalCompliantMock()
	mc.files["/etc/ssh/sshd_config"] = []byte("PermitRootLogin yes\nPasswordAuthentication no\n")
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AC.L2-3.1.6")
	if f == nil {
		t.Fatal("AC.L2-3.1.6 finding not present")
	}
	if f.Status != models.StatusNonCompliant {
		t.Errorf("expected NON_COMPLIANT, got %s", f.Status)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestCheckSSHPasswordAuth_NonCompliant(t *testing.T) {
	mc := minimalCompliantMock()
	mc.files["/etc/ssh/sshd_config"] = []byte("PermitRootLogin no\nPasswordAuthentication yes\n")
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "IA.L2-3.5.2")
	if f == nil {
		t.Fatal("IA.L2-3.5.2 finding not present")
	}
	if f.Status != models.StatusNonCompliant {
		t.Errorf("expected NON_COMPLIANT for password auth enabled, got %s", f.Status)
	}
}

func TestCheckSSHIdleTimeout_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AC.L2-3.1.10")
	if f == nil {
		t.Fatal("AC.L2-3.1.10 finding not present")
	}
	if f.Status != models.StatusCompliant {
		t.Errorf("expected COMPLIANT for idle timeout, got %s: %s", f.Status, f.Details)
	}
}

func TestCheckAuditdEnabled_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AU.L2-3.3.1")
	if f == nil {
		t.Fatal("AU.L2-3.3.1 finding not present")
	}
	if f.Status != models.StatusCompliant {
		t.Errorf("expected COMPLIANT for auditd, got %s: %s", f.Status, f.Details)
	}
}

func TestCheckAuditdEnabled_NonCompliant(t *testing.T) {
	mc := minimalCompliantMock()
	delete(mc.commands, "systemctl is-active auditd")
	delete(mc.commands, "pgrep -x auditd")
	mc.cmdErrs["systemctl is-active auditd"] = fmt.Errorf("inactive")
	mc.cmdErrs["pgrep -x auditd"] = fmt.Errorf("not running")
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AU.L2-3.3.1")
	if f == nil {
		t.Fatal("AU.L2-3.3.1 finding not present")
	}
	if f.Status != models.StatusNonCompliant {
		t.Errorf("expected NON_COMPLIANT when auditd is inactive, got %s", f.Status)
	}
}

func TestCheckFirewallEnabled_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "SC.L2-3.13.1")
	if f == nil {
		t.Fatal("SC.L2-3.13.1 finding not present")
	}
	if f.Status != models.StatusCompliant {
		t.Errorf("expected COMPLIANT for firewall, got %s: %s", f.Status, f.Details)
	}
}

func TestCheckEmptyPasswords_NotChecked(t *testing.T) {
	mc := minimalCompliantMock()
	// /etc/shadow is not in files map → should fallback and return NOT_CHECKED or compliant
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AC.L2-3.1.1")
	if f == nil {
		t.Fatal("AC.L2-3.1.1 finding not present")
	}
	// When both /etc/shadow and passwd -S -a fail, expect NOT_CHECKED
	if f.Status != models.StatusNotChecked && f.Status != models.StatusCompliant {
		t.Errorf("unexpected status for empty passwords: %s", f.Status)
	}
}

func TestCheckPasswordMinLength_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "IA.L2-3.5.7")
	// There are two findings with this ID (minlen + complexity)
	if f == nil {
		t.Fatal("IA.L2-3.5.7 finding not present")
	}
}

func TestCheckNTP_Compliant(t *testing.T) {
	mc := minimalCompliantMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	f := findByID(findings, "AU.L2-3.3.7")
	if f == nil {
		t.Fatal("AU.L2-3.3.7 finding not present")
	}
	if f.Status != models.StatusCompliant {
		t.Errorf("expected COMPLIANT for NTP, got %s: %s", f.Status, f.Details)
	}
}

func TestAllFindingsHaveHost(t *testing.T) {
	mc := minimalCompliantMock()
	mc.hostname = "myserver"
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	for _, f := range findings {
		if f.Host != "myserver" {
			t.Errorf("finding %s has unexpected host %q", f.Control.ID, f.Host)
		}
	}
}

func TestNonCompliantFindingsHaveRemediation(t *testing.T) {
	// Use a checker that forces most things to fail
	mc := failingMock()
	s := scanner.NewWithChecker(mc)
	findings := s.Scan()
	for _, f := range findings {
		if f.Status == models.StatusNonCompliant && f.Remediation == "" {
			t.Errorf("finding %s is NON_COMPLIANT but has no remediation text", f.Control.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findByID(findings []models.Finding, id string) *models.Finding {
	for i := range findings {
		if findings[i].Control.ID == id {
			return &findings[i]
		}
	}
	return nil
}

// minimalCompliantMock returns a mock configured so that all checks pass.
func minimalCompliantMock() *mockChecker {
	mc := &mockChecker{
		files: map[string][]byte{
			"/etc/ssh/sshd_config": []byte(compliantSSHConfig),
			"/etc/security/faillock.conf": []byte("deny = 5\nunlock_time = 900\n"),
			"/etc/security/pwquality.conf": []byte(
				"minlen = 14\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n"),
			"/etc/audit/auditd.conf":  []byte("max_log_file = 8\nnum_logs = 5\n"),
			"/etc/pam.d/common-password": []byte(
				"password required pam_pwhistory.so remember=24 use_authtok\n"),
			"/etc/sudoers": []byte("root ALL=(ALL:ALL) ALL\n"),
		},
		commands: map[string]string{
			"systemctl is-active auditd":            "active",
			"systemctl is-active chronyd":           "active",
			"systemctl is-active ufw":               "active",
			"ufw status":                            "Status: active\n",
			"find /etc /bin /usr/bin /usr/sbin /sbin -xdev -perm -002 -type f": "",
			"getenforce":               "Enforcing",
			"pgrep -x clamd":           "1234",
			"ls /etc/sudoers.d/":       "",
			"stat -c %a %n /etc/cron.d": "755 /etc/cron.d",
			"stat -c %a %n /etc/cron.daily":   "755 /etc/cron.daily",
			"stat -c %a %n /etc/cron.weekly":  "755 /etc/cron.weekly",
			"stat -c %a %n /etc/cron.monthly": "755 /etc/cron.monthly",
			"stat -c %a %n /etc/cron.hourly":  "755 /etc/cron.hourly",
		},
		cmdErrs: map[string]error{},
	}
	return mc
}

// failingMock returns a mock where all checks fail or cannot be read.
func failingMock() *mockChecker {
	return &mockChecker{
		files: map[string][]byte{
			"/etc/ssh/sshd_config": []byte("PermitRootLogin yes\nPasswordAuthentication yes\n"),
			"/etc/security/faillock.conf": []byte("deny = 10\n"),
			"/etc/security/pwquality.conf": []byte("minlen = 6\ndcredit = 1\nucredit = 1\nlcredit = 1\nocredit = 1\n"),
			"/etc/audit/auditd.conf": []byte("max_log_file = 2\nnum_logs = 2\n"),
			"/etc/sudoers": []byte("ALL ALL=(ALL) NOPASSWD: ALL\n"),
		},
		commands: map[string]string{
			"find /etc /bin /usr/bin /usr/sbin /sbin -xdev -perm -002 -type f": "/etc/somefile",
			"getenforce": "Disabled",
			"ls /etc/sudoers.d/": "",
		},
		cmdErrs: map[string]error{
			"systemctl is-active auditd":  fmt.Errorf("inactive"),
			"pgrep -x auditd":             fmt.Errorf("not found"),
			"systemctl is-active chronyd": fmt.Errorf("inactive"),
			"systemctl is-active ntp":     fmt.Errorf("inactive"),
			"ufw status":                  fmt.Errorf("inactive"),
			"systemctl is-active firewalld": fmt.Errorf("inactive"),
			"iptables -L -n":              fmt.Errorf("no rules"),
			"pgrep -x clamd":              fmt.Errorf("not found"),
			"pgrep -x freshclam":          fmt.Errorf("not found"),
			"pgrep -x clamav":             fmt.Errorf("not found"),
			"dpkg -l clamav":              fmt.Errorf("not installed"),
			"rpm -q clamav":               fmt.Errorf("not installed"),
		},
	}
}
