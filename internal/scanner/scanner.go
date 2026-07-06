// Package scanner implements the CMMC Level 2 compliance scanning agent.
//
// It performs 18 technical checks across the AC, AU, CM, IA, SC, and SI
// domains.  All operating-system interactions are performed through the
// SystemChecker interface so that tests can substitute a mock implementation.
package scanner

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
)

// SystemChecker abstracts all operating-system interactions so the scanner
// can be tested without requiring a real Linux host.
type SystemChecker interface {
	ReadFile(path string) ([]byte, error)
	RunCommand(name string, args ...string) (string, error)
	FileExists(path string) bool
	Hostname() (string, error)
}

// Scanner performs CMMC Level 2 compliance checks against a host.
type Scanner struct {
	checker SystemChecker
}

// New returns a Scanner that calls the real operating system.
func New() *Scanner {
	return NewWithChecker(&defaultChecker{})
}

// NewWithChecker returns a Scanner using the supplied SystemChecker.
// This is the primary constructor for tests.
func NewWithChecker(c SystemChecker) *Scanner {
	return &Scanner{checker: c}
}

// Scan executes all CMMC L2 checks and returns the collected findings.
func (s *Scanner) Scan() []models.Finding {
	host, _ := s.checker.Hostname()
	now := time.Now()

	checks := []func(string, time.Time) models.Finding{
		// Access Control
		s.checkSSHRootLogin,
		s.checkSSHPasswordAuth,
		s.checkSSHIdleTimeout,
		s.checkSSHWeakCiphers,
		s.checkAccountLockout,
		s.checkEmptyPasswords,
		s.checkSudoersNoPassword,
		// Identification & Authentication
		s.checkPasswordMinLength,
		s.checkPasswordComplexity,
		s.checkPasswordReuse,
		// Audit & Accountability
		s.checkAuditdEnabled,
		s.checkAuditLogRetention,
		s.checkNTPConfigured,
		// Configuration Management
		s.checkWorldWritableFiles,
		s.checkSELinuxAppArmor,
		s.checkCronJobPermissions,
		// System & Communications Protection
		s.checkFirewallEnabled,
		// System & Information Integrity
		s.checkAVSoftware,
	}

	findings := make([]models.Finding, 0, len(checks))
	for _, fn := range checks {
		findings = append(findings, fn(host, now))
	}
	return findings
}

// ---------------------------------------------------------------------------
// Access Control checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkSSHRootLogin(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AC.L2-3.1.6",
		Domain:      models.DomainAC,
		Title:       "Non-Privileged Account Use",
		Description: "Use non-privileged accounts or roles when accessing non-security functions.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.1.6",
	}

	data, err := s.checker.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return notChecked(ctrl, host, at, "cannot read /etc/ssh/sshd_config: "+err.Error())
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "PermitRootLogin") {
			val := strings.ToLower(fields[1])
			if val == "no" {
				return compliant(ctrl, host, at, "PermitRootLogin is set to 'no'")
			}
			return nonCompliant(ctrl, host, at, models.SeverityHigh,
				fmt.Sprintf("PermitRootLogin is '%s'; expected 'no'", fields[1]),
				"Set 'PermitRootLogin no' in /etc/ssh/sshd_config and run: systemctl restart sshd")
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"PermitRootLogin is not explicitly set; default may allow root login",
		"Add 'PermitRootLogin no' to /etc/ssh/sshd_config and run: systemctl restart sshd")
}

func (s *Scanner) checkSSHPasswordAuth(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "IA.L2-3.5.2",
		Domain:      models.DomainIA,
		Title:       "Authenticator Management – SSH Password Authentication",
		Description: "Authenticate (or verify) the identities of users, processes, or devices as a prerequisite to allowing access.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.5.2",
	}

	data, err := s.checker.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return notChecked(ctrl, host, at, "cannot read /etc/ssh/sshd_config: "+err.Error())
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "PasswordAuthentication") {
			if strings.ToLower(fields[1]) == "no" {
				return compliant(ctrl, host, at, "PasswordAuthentication is disabled; key-based auth required")
			}
			return nonCompliant(ctrl, host, at, models.SeverityHigh,
				"PasswordAuthentication is enabled; brute-force attacks are possible",
				"Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and run: systemctl restart sshd")
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"PasswordAuthentication is not explicitly set; default may permit password logins",
		"Add 'PasswordAuthentication no' to /etc/ssh/sshd_config and run: systemctl restart sshd")
}

func (s *Scanner) checkSSHIdleTimeout(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AC.L2-3.1.10",
		Domain:      models.DomainAC,
		Title:       "Session Lock – Idle Session Termination",
		Description: "Use session lock with pattern-hiding displays after a period of inactivity.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.1.10",
	}

	data, err := s.checker.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return notChecked(ctrl, host, at, "cannot read /etc/ssh/sshd_config: "+err.Error())
	}

	var interval, maxCount int
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "clientaliveinterval":
			fmt.Sscanf(fields[1], "%d", &interval)
		case "clientalivecountmax":
			fmt.Sscanf(fields[1], "%d", &maxCount)
		}
	}

	if interval > 0 && interval <= 300 && maxCount >= 0 && maxCount <= 3 {
		return compliant(ctrl, host, at,
			fmt.Sprintf("SSH idle timeout configured (ClientAliveInterval=%d, ClientAliveCountMax=%d)",
				interval, maxCount))
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		fmt.Sprintf("SSH idle timeout not properly configured (ClientAliveInterval=%d, ClientAliveCountMax=%d)",
			interval, maxCount),
		"Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in /etc/ssh/sshd_config, then run: systemctl restart sshd")
}

func (s *Scanner) checkSSHWeakCiphers(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "SC.L2-3.13.8",
		Domain:      models.DomainSC,
		Title:       "Transmission Confidentiality – Cryptographic Mechanisms",
		Description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.13.8",
	}

	weakCiphers := []string{"arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}

	data, err := s.checker.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return notChecked(ctrl, host, at, "cannot read /etc/ssh/sshd_config: "+err.Error())
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Ciphers") {
			continue
		}
		ciphers := strings.ToLower(fields[1])
		for _, wk := range weakCiphers {
			if strings.Contains(ciphers, wk) {
				return nonCompliant(ctrl, host, at, models.SeverityHigh,
					fmt.Sprintf("Weak cipher '%s' found in SSH Ciphers directive", wk),
					"Remove weak ciphers from the 'Ciphers' line in /etc/ssh/sshd_config and run: systemctl restart sshd")
			}
		}
		return compliant(ctrl, host, at, "SSH Ciphers directive does not include known-weak algorithms")
	}

	return compliant(ctrl, host, at, "No explicit Ciphers directive; OpenSSH defaults exclude weak ciphers in recent versions")
}

func (s *Scanner) checkAccountLockout(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AC.L2-3.1.8",
		Domain:      models.DomainAC,
		Title:       "Unsuccessful Logon Attempts",
		Description: "Limit unsuccessful logon attempts.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.1.8",
	}

	// Check /etc/security/faillock.conf first (modern systems)
	if s.checker.FileExists("/etc/security/faillock.conf") {
		data, err := s.checker.ReadFile("/etc/security/faillock.conf")
		if err == nil {
			var deny int
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				if strings.HasPrefix(line, "deny") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &deny)
					}
				}
			}
			if deny > 0 && deny <= 5 {
				return compliant(ctrl, host, at,
					fmt.Sprintf("Account lockout configured via faillock.conf (deny=%d)", deny))
			}
			if deny == 0 {
				return nonCompliant(ctrl, host, at, models.SeverityHigh,
					"faillock.conf found but 'deny' threshold is not set",
					"Set 'deny = 5' in /etc/security/faillock.conf")
			}
			return nonCompliant(ctrl, host, at, models.SeverityMedium,
				fmt.Sprintf("faillock.conf deny threshold is %d (recommended ≤ 5)", deny),
				"Set 'deny = 5' in /etc/security/faillock.conf")
		}
	}

	// Fallback: inspect /etc/pam.d/common-auth for pam_faillock or pam_tally2
	pamPaths := []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth"}
	for _, p := range pamPaths {
		data, err := s.checker.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "pam_faillock") || strings.Contains(content, "pam_tally2") {
			return compliant(ctrl, host, at, fmt.Sprintf("Account lockout module detected in %s", p))
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		"No account lockout policy detected (pam_faillock or pam_tally2 not configured)",
		"Install and configure pam_faillock in /etc/pam.d/common-auth and /etc/security/faillock.conf")
}

func (s *Scanner) checkEmptyPasswords(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AC.L2-3.1.1",
		Domain:      models.DomainAC,
		Title:       "Authorized Access Control – No Empty Passwords",
		Description: "Limit system access to authorized users.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.1.1",
	}

	data, err := s.checker.ReadFile("/etc/shadow")
	if err != nil {
		// Try passwd -S -a as unprivileged fallback
		out, cmdErr := s.checker.RunCommand("passwd", "-S", "-a")
		if cmdErr != nil {
			return notChecked(ctrl, host, at, "cannot read /etc/shadow and passwd -S -a failed: "+cmdErr.Error())
		}
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			// passwd -S output: username status date min max warn inactive
			// status "NP" means no password
			if len(fields) >= 2 && fields[1] == "NP" {
				return nonCompliant(ctrl, host, at, models.SeverityCritical,
					fmt.Sprintf("Account '%s' has no password set", fields[0]),
					fmt.Sprintf("Set a password for account '%s': passwd %s", fields[0], fields[0]))
			}
		}
		return compliant(ctrl, host, at, "No accounts with empty passwords detected via passwd -S")
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		user, hash := fields[0], fields[1]
		// Empty hash means no password required; "!" or "*" means locked/disabled
		if hash == "" {
			return nonCompliant(ctrl, host, at, models.SeverityCritical,
				fmt.Sprintf("Account '%s' has an empty password hash in /etc/shadow", user),
				fmt.Sprintf("Set a password for '%s': passwd %s", user, user))
		}
	}

	return compliant(ctrl, host, at, "No accounts with empty password hashes found in /etc/shadow")
}

func (s *Scanner) checkSudoersNoPassword(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AC.L2-3.1.2",
		Domain:      models.DomainAC,
		Title:       "Transaction and Function Control – Sudo NOPASSWD",
		Description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.1.2",
	}

	checkContent := func(content, source string) *models.Finding {
		sc := bufio.NewScanner(strings.NewReader(content))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
				f := nonCompliant(ctrl, host, at, models.SeverityHigh,
					fmt.Sprintf("NOPASSWD entry found in %s: %s", source, line),
					"Remove NOPASSWD entries from sudoers; require password for all sudo operations")
				return &f
			}
		}
		return nil
	}

	files := []string{"/etc/sudoers"}
	if s.checker.FileExists("/etc/sudoers.d") {
		// List drop-in files via RunCommand ls
		out, err := s.checker.RunCommand("ls", "/etc/sudoers.d/")
		if err == nil {
			for _, name := range strings.Fields(out) {
				files = append(files, "/etc/sudoers.d/"+name)
			}
		}
	}

	for _, f := range files {
		data, err := s.checker.ReadFile(f)
		if err != nil {
			continue
		}
		if finding := checkContent(string(data), f); finding != nil {
			return *finding
		}
	}

	return compliant(ctrl, host, at, "No NOPASSWD entries detected in sudoers configuration")
}

// ---------------------------------------------------------------------------
// Identification & Authentication checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkPasswordMinLength(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "IA.L2-3.5.7",
		Domain:      models.DomainIA,
		Title:       "Password Complexity – Minimum Length",
		Description: "Enforce a minimum password complexity and change of characters when new passwords are created.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.5.7",
	}

	// Prefer /etc/security/pwquality.conf
	if data, err := s.checker.ReadFile("/etc/security/pwquality.conf"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if strings.TrimSpace(parts[0]) == "minlen" {
				var minLen int
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &minLen)
				if minLen >= 12 {
					return compliant(ctrl, host, at,
						fmt.Sprintf("Password minimum length is %d (≥12)", minLen))
				}
				return nonCompliant(ctrl, host, at, models.SeverityHigh,
					fmt.Sprintf("Password minimum length is %d (should be ≥12)", minLen),
					"Set 'minlen = 12' in /etc/security/pwquality.conf")
			}
		}
	}

	// Fallback: /etc/login.defs
	if data, err := s.checker.ReadFile("/etc/login.defs"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "PASS_MIN_LEN" {
				var minLen int
				fmt.Sscanf(fields[1], "%d", &minLen)
				if minLen >= 12 {
					return compliant(ctrl, host, at,
						fmt.Sprintf("PASS_MIN_LEN is %d in /etc/login.defs (≥12)", minLen))
				}
				return nonCompliant(ctrl, host, at, models.SeverityHigh,
					fmt.Sprintf("PASS_MIN_LEN is %d in /etc/login.defs (should be ≥12)", minLen),
					"Set 'PASS_MIN_LEN 12' in /etc/login.defs and 'minlen = 12' in /etc/security/pwquality.conf")
			}
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"Password minimum length setting not found in pwquality.conf or login.defs",
		"Install libpam-pwquality and set 'minlen = 12' in /etc/security/pwquality.conf")
}

func (s *Scanner) checkPasswordComplexity(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "IA.L2-3.5.7",
		Domain:      models.DomainIA,
		Title:       "Password Complexity – Character Classes",
		Description: "Enforce a minimum password complexity including uppercase, lowercase, digits, and special characters.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.5.7",
	}

	data, err := s.checker.ReadFile("/etc/security/pwquality.conf")
	if err != nil {
		// Check PAM common-password for pam_pwquality or pam_cracklib
		for _, p := range []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth"} {
			pamData, pamErr := s.checker.ReadFile(p)
			if pamErr == nil && (strings.Contains(string(pamData), "pam_pwquality") ||
				strings.Contains(string(pamData), "pam_cracklib")) {
				return compliant(ctrl, host, at, fmt.Sprintf("Password complexity enforced via PAM in %s", p))
			}
		}
		return nonCompliant(ctrl, host, at, models.SeverityHigh,
			"Password complexity enforcement not detected",
			"Install libpam-pwquality and configure /etc/security/pwquality.conf")
	}

	var dcredit, ucredit, lcredit, ocredit int
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		var val int
		fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &val)
		switch key {
		case "dcredit":
			dcredit = val
		case "ucredit":
			ucredit = val
		case "lcredit":
			lcredit = val
		case "ocredit":
			ocredit = val
		}
	}

	// Negative values in pwquality mean "require at least N of this class"
	if dcredit < 0 && ucredit < 0 && lcredit < 0 && ocredit < 0 {
		return compliant(ctrl, host, at,
			"Password complexity requires digits, upper, lower, and special characters")
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"Password complexity requirements are incomplete (dcredit, ucredit, lcredit, ocredit not all set)",
		"Set 'dcredit = -1', 'ucredit = -1', 'lcredit = -1', 'ocredit = -1' in /etc/security/pwquality.conf")
}

func (s *Scanner) checkPasswordReuse(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "IA.L2-3.5.8",
		Domain:      models.DomainIA,
		Title:       "Password Reuse Prohibition",
		Description: "Prohibit password reuse for a specified number of generations.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.5.8",
	}

	pamPaths := []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
	for _, p := range pamPaths {
		data, err := s.checker.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "pam_pwhistory") || strings.Contains(line, "remember=") {
				var remember int
				for _, field := range strings.Fields(line) {
					if strings.HasPrefix(field, "remember=") {
						fmt.Sscanf(field, "remember=%d", &remember)
					}
				}
				if remember >= 24 {
					return compliant(ctrl, host, at,
						fmt.Sprintf("Password history enforces %d previous passwords (≥24)", remember))
				}
				return nonCompliant(ctrl, host, at, models.SeverityMedium,
					fmt.Sprintf("Password history remember=%d (should be ≥24)", remember),
					fmt.Sprintf("Set 'remember=24' in the pam_pwhistory line in %s", p))
			}
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"Password reuse restriction (pam_pwhistory) not found in PAM configuration",
		"Add 'password required pam_pwhistory.so remember=24 use_authtok' to /etc/pam.d/common-password")
}

// ---------------------------------------------------------------------------
// Audit & Accountability checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkAuditdEnabled(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AU.L2-3.3.1",
		Domain:      models.DomainAU,
		Title:       "System Auditing",
		Description: "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.3.1",
	}

	out, err := s.checker.RunCommand("systemctl", "is-active", "auditd")
	if err == nil && strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "auditd service is active")
	}

	// Fallback: check if the process is running
	psOut, psErr := s.checker.RunCommand("pgrep", "-x", "auditd")
	if psErr == nil && strings.TrimSpace(psOut) != "" {
		return compliant(ctrl, host, at, "auditd process is running")
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		"auditd service is not active",
		"Install and enable auditd: apt-get install auditd && systemctl enable --now auditd")
}

func (s *Scanner) checkAuditLogRetention(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AU.L2-3.3.2",
		Domain:      models.DomainAU,
		Title:       "User Accountability – Audit Log Retention",
		Description: "Ensure that the actions of individual users can be traced to those users so they can be held accountable for their actions.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.3.2",
	}

	data, err := s.checker.ReadFile("/etc/audit/auditd.conf")
	if err != nil {
		return notChecked(ctrl, host, at, "cannot read /etc/audit/auditd.conf: "+err.Error())
	}

	var maxLogFile, numLogs int
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "max_log_file":
			fmt.Sscanf(val, "%d", &maxLogFile)
		case "num_logs":
			fmt.Sscanf(val, "%d", &numLogs)
		}
	}

	if maxLogFile >= 8 && numLogs >= 5 {
		return compliant(ctrl, host, at,
			fmt.Sprintf("Audit log retention configured (max_log_file=%dMB, num_logs=%d)", maxLogFile, numLogs))
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		fmt.Sprintf("Audit log retention insufficient (max_log_file=%d, num_logs=%d)", maxLogFile, numLogs),
		"Set 'max_log_file = 8' and 'num_logs = 5' in /etc/audit/auditd.conf, then run: systemctl restart auditd")
}

func (s *Scanner) checkNTPConfigured(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "AU.L2-3.3.7",
		Domain:      models.DomainAU,
		Title:       "Authoritative Time Source",
		Description: "Provide a system capability that compares and synchronizes internal system clocks with authoritative sources.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.3.7",
	}

	// Check chrony (preferred on modern systems)
	if out, err := s.checker.RunCommand("systemctl", "is-active", "chronyd"); err == nil && strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "chronyd is active and synchronizing time")
	}

	// Check systemd-timesyncd
	if out, err := s.checker.RunCommand("systemctl", "is-active", "systemd-timesyncd"); err == nil && strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "systemd-timesyncd is active")
	}

	// Check ntpd
	if out, err := s.checker.RunCommand("systemctl", "is-active", "ntp"); err == nil && strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "ntpd is active")
	}

	// Check config files exist
	for _, f := range []string{"/etc/chrony.conf", "/etc/ntp.conf", "/etc/systemd/timesyncd.conf"} {
		if s.checker.FileExists(f) {
			return compliant(ctrl, host, at, fmt.Sprintf("NTP configuration found at %s", f))
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		"No NTP/time synchronisation service detected",
		"Install and enable chrony: apt-get install chrony && systemctl enable --now chronyd")
}

// ---------------------------------------------------------------------------
// Configuration Management checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkWorldWritableFiles(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "CM.L2-3.4.1",
		Domain:      models.DomainCM,
		Title:       "Baseline Configuration – World-Writable Files",
		Description: "Establish and maintain baseline configurations and inventories of organisational systems.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.4.1",
	}

	// Search a restricted set of directories to avoid long scan times
	out, err := s.checker.RunCommand("find", "/etc", "/bin", "/usr/bin", "/usr/sbin", "/sbin",
		"-xdev", "-perm", "-002", "-type", "f")
	if err != nil {
		return notChecked(ctrl, host, at, "find command failed: "+err.Error())
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var found []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			found = append(found, l)
		}
	}

	if len(found) == 0 {
		return compliant(ctrl, host, at, "No world-writable files found in system directories")
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		fmt.Sprintf("%d world-writable file(s) found: %s", len(found), strings.Join(found, ", ")),
		"Remove world-write permission: chmod o-w <file> for each affected file")
}

func (s *Scanner) checkSELinuxAppArmor(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "CM.L2-3.4.6",
		Domain:      models.DomainCM,
		Title:       "Least Functionality – Mandatory Access Control",
		Description: "Employ the principle of least functionality by configuring the system to provide only essential capabilities.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.4.6",
	}

	// Check SELinux
	out, err := s.checker.RunCommand("getenforce")
	if err == nil {
		status := strings.TrimSpace(out)
		if status == "Enforcing" {
			return compliant(ctrl, host, at, "SELinux is in Enforcing mode")
		}
		if status == "Permissive" {
			return nonCompliant(ctrl, host, at, models.SeverityMedium,
				"SELinux is in Permissive mode (not enforcing policies)",
				"Enable SELinux enforcing mode: setenforce 1 and set SELINUX=enforcing in /etc/selinux/config")
		}
	}

	// Check AppArmor
	out, err = s.checker.RunCommand("aa-status", "--enabled")
	if err == nil && strings.TrimSpace(out) == "Yes" {
		return compliant(ctrl, host, at, "AppArmor is enabled")
	}

	// Check via systemctl
	if out, err = s.checker.RunCommand("systemctl", "is-active", "apparmor"); err == nil &&
		strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "AppArmor service is active")
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		"Neither SELinux nor AppArmor is active/enforcing",
		"Enable AppArmor: systemctl enable --now apparmor, or enable SELinux in enforcing mode")
}

func (s *Scanner) checkCronJobPermissions(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "CM.L2-3.4.2",
		Domain:      models.DomainCM,
		Title:       "Security Configuration Settings – Cron Permissions",
		Description: "Establish and enforce security configuration settings for systems.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.4.2",
	}

	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.hourly"}
	issues := []string{}

	for _, dir := range cronDirs {
		out, err := s.checker.RunCommand("stat", "-c", "%a %n", dir)
		if err != nil {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(out))
		if len(fields) < 2 {
			continue
		}
		perm := fields[0]
		// Cron directories should not be world-writable (last octet < 2)
		if len(perm) >= 3 {
			lastDigit := perm[len(perm)-1]
			val := int(lastDigit - '0')
			if val&2 != 0 {
				issues = append(issues, fmt.Sprintf("%s is world-writable (mode %s)", dir, perm))
			}
		}
	}

	if len(issues) == 0 {
		return compliant(ctrl, host, at, "Cron directories have proper permissions")
	}

	return nonCompliant(ctrl, host, at, models.SeverityMedium,
		strings.Join(issues, "; "),
		"Remove world-write from cron directories: chmod o-w /etc/cron.*")
}

// ---------------------------------------------------------------------------
// System & Communications Protection checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkFirewallEnabled(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "SC.L2-3.13.1",
		Domain:      models.DomainSC,
		Title:       "Boundary Protection – Host Firewall",
		Description: "Monitor, control, and protect communications at the external boundaries and key internal boundaries of systems.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.13.1",
	}

	// Check ufw
	if out, err := s.checker.RunCommand("ufw", "status"); err == nil {
		if strings.Contains(strings.ToLower(out), "status: active") {
			return compliant(ctrl, host, at, "ufw firewall is active")
		}
	}

	// Check firewalld
	if out, err := s.checker.RunCommand("systemctl", "is-active", "firewalld"); err == nil &&
		strings.TrimSpace(out) == "active" {
		return compliant(ctrl, host, at, "firewalld is active")
	}

	// Check iptables for non-default rules
	if out, err := s.checker.RunCommand("iptables", "-L", "-n"); err == nil {
		lines := strings.Split(out, "\n")
		// More than the 3 default chain header lines means rules exist
		nonEmpty := 0
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				nonEmpty++
			}
		}
		if nonEmpty > 6 {
			return compliant(ctrl, host, at, "iptables rules are configured")
		}
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		"No host-based firewall (ufw, firewalld, or iptables) is active",
		"Enable ufw: ufw default deny incoming && ufw allow ssh && ufw enable")
}

// ---------------------------------------------------------------------------
// System & Information Integrity checks
// ---------------------------------------------------------------------------

func (s *Scanner) checkAVSoftware(host string, at time.Time) models.Finding {
	ctrl := models.Control{
		ID:          "SI.L2-3.14.1",
		Domain:      models.DomainSI,
		Title:       "Malicious Code Protection",
		Description: "Employ malicious code protection mechanisms at appropriate locations within systems.",
		NISTRef:     "NIST SP 800-171 Rev 2 3.14.1",
	}

	avBinaries := []string{"clamd", "freshclam", "clamav"}
	for _, bin := range avBinaries {
		if out, err := s.checker.RunCommand("pgrep", "-x", bin); err == nil && strings.TrimSpace(out) != "" {
			return compliant(ctrl, host, at, fmt.Sprintf("ClamAV (%s) is running", bin))
		}
	}

	// Check if clamav is installed
	if out, err := s.checker.RunCommand("dpkg", "-l", "clamav"); err == nil &&
		strings.Contains(out, "ii") {
		return compliant(ctrl, host, at, "ClamAV is installed (verify it is running and up-to-date)")
	}
	if out, err := s.checker.RunCommand("rpm", "-q", "clamav"); err == nil &&
		!strings.Contains(out, "not installed") {
		return compliant(ctrl, host, at, "ClamAV is installed via rpm (verify it is running and up-to-date)")
	}

	return nonCompliant(ctrl, host, at, models.SeverityHigh,
		"No antivirus/malware protection software detected",
		"Install ClamAV: apt-get install clamav clamav-daemon && systemctl enable --now clamav-daemon")
}

// ---------------------------------------------------------------------------
// Finding constructors
// ---------------------------------------------------------------------------

func compliant(ctrl models.Control, host string, at time.Time, details string) models.Finding {
	return models.Finding{
		Control:   ctrl,
		Status:    models.StatusCompliant,
		Severity:  models.SeverityLow,
		Details:   details,
		CheckedAt: at,
		Host:      host,
	}
}

func nonCompliant(ctrl models.Control, host string, at time.Time,
	severity models.Severity, details, remediation string) models.Finding {
	return models.Finding{
		Control:     ctrl,
		Status:      models.StatusNonCompliant,
		Severity:    severity,
		Details:     details,
		Remediation: remediation,
		CheckedAt:   at,
		Host:        host,
	}
}

func notChecked(ctrl models.Control, host string, at time.Time, details string) models.Finding {
	return models.Finding{
		Control:   ctrl,
		Status:    models.StatusNotChecked,
		Severity:  models.SeverityLow,
		Details:   details,
		CheckedAt: at,
		Host:      host,
	}
}
