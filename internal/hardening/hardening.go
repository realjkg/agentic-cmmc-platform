// Package hardening implements the CMMC infrastructure hardening agent.
//
// For every non-compliant finding the agent produces a RemediationTask that
// describes the shell command required to fix the issue.  In dry-run mode
// (the default) only the tasks are returned.  In apply mode the commands are
// executed on the host.
package hardening

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/realjkg/agentic-cmmc-platform/internal/models"
)

// CommandRunner executes shell commands.  Inject a mock in tests.
type CommandRunner interface {
	Run(name string, args ...string) error
}

// defaultRunner executes commands via os/exec.
type defaultRunner struct{}

func (d *defaultRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// Agent generates and optionally applies remediation tasks for CMMC findings.
type Agent struct {
	runner  CommandRunner
	dryRun  bool
}

// New returns an Agent that only prints remediation commands (dry-run mode).
func New() *Agent {
	return &Agent{runner: &defaultRunner{}, dryRun: true}
}

// NewWithRunner returns an Agent using the supplied CommandRunner.
// Set dryRun=false to actually execute commands.
func NewWithRunner(r CommandRunner, dryRun bool) *Agent {
	return &Agent{runner: r, dryRun: dryRun}
}

// Remediate generates a RemediationTask for each non-compliant finding.
// Tasks are applied when the agent is not in dry-run mode.
func (a *Agent) Remediate(findings []models.Finding) []models.RemediationTask {
	tasks := make([]models.RemediationTask, 0)
	for _, f := range findings {
		if f.Status != models.StatusNonCompliant {
			continue
		}
		task := a.buildTask(f)
		if !a.dryRun && task.Command != "" {
			task = a.applyTask(task)
		}
		tasks = append(tasks, task)
	}
	return tasks
}

// buildTask maps a finding to a RemediationTask with a shell command.
func (a *Agent) buildTask(f models.Finding) models.RemediationTask {
	cmd := remediationCommand(f)
	return models.RemediationTask{
		Finding: f,
		Action:  f.Remediation,
		Command: cmd,
	}
}

// applyTask executes the task's command and records the outcome.
func (a *Agent) applyTask(task models.RemediationTask) models.RemediationTask {
	if task.Command == "" {
		task.Error = "no automated command available; manual remediation required"
		return task
	}

	parts := strings.Fields(task.Command)
	if len(parts) == 0 {
		task.Error = "empty command"
		return task
	}

	err := a.runner.Run(parts[0], parts[1:]...)
	task.AppliedAt = time.Now()
	if err != nil {
		task.Error = fmt.Sprintf("command '%s' failed: %v", task.Command, err)
	} else {
		task.Applied = true
	}
	return task
}

// ---------------------------------------------------------------------------
// remediationCommand maps a control ID to an automated shell command.
// Returns "" when the fix must be applied manually or requires multi-step
// configuration that is too risky to automate without operator review.
// ---------------------------------------------------------------------------

func remediationCommand(f models.Finding) string {
	switch f.Control.ID {
	case "AC.L2-3.1.6": // SSH root login
		// Use sed to update if the directive exists, otherwise append; then validate syntax before restart.
		return "grep -qE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config && " +
			"sed -i 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || " +
			"echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; " +
			"sshd -t && systemctl restart sshd"

	case "IA.L2-3.5.2": // SSH password authentication
		return "grep -qE '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config && " +
			"sed -i 's/^[[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || " +
			"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config; " +
			"sshd -t && systemctl restart sshd"

	case "AC.L2-3.1.10": // SSH idle timeout
		return "grep -qE '^[[:space:]]*ClientAliveInterval' /etc/ssh/sshd_config && " +
			"sed -i 's/^[[:space:]]*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || " +
			"echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config; " +
			"grep -qE '^[[:space:]]*ClientAliveCountMax' /etc/ssh/sshd_config && " +
			"sed -i 's/^[[:space:]]*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config || " +
			"echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config; " +
			"sshd -t && systemctl restart sshd"

	case "AU.L2-3.3.1": // auditd
		return "apt-get install -y auditd audispd-plugins && systemctl enable --now auditd"

	case "AU.L2-3.3.2": // audit log retention
		return "grep -q '^max_log_file' /etc/audit/auditd.conf && " +
			"sed -i 's/^max_log_file.*/max_log_file = 8/' /etc/audit/auditd.conf || " +
			"echo 'max_log_file = 8' >> /etc/audit/auditd.conf; " +
			"grep -q '^num_logs' /etc/audit/auditd.conf && " +
			"sed -i 's/^num_logs.*/num_logs = 5/' /etc/audit/auditd.conf || " +
			"echo 'num_logs = 5' >> /etc/audit/auditd.conf; " +
			"systemctl restart auditd"

	case "AU.L2-3.3.7": // NTP
		return "apt-get install -y chrony && systemctl enable --now chronyd"

	case "AC.L2-3.1.8": // account lockout
		return "apt-get install -y libpam-modules; " +
			"grep -q '^deny' /etc/security/faillock.conf && " +
			"sed -i 's/^deny.*/deny = 5/' /etc/security/faillock.conf || " +
			"echo 'deny = 5' >> /etc/security/faillock.conf"

	case "IA.L2-3.5.7": // password length / complexity
		return "apt-get install -y libpam-pwquality; " +
			"grep -q '^minlen' /etc/security/pwquality.conf && " +
			"sed -i 's/^minlen.*/minlen = 12/' /etc/security/pwquality.conf || " +
			"echo 'minlen = 12' >> /etc/security/pwquality.conf; " +
			"for key in dcredit ucredit lcredit ocredit; do " +
			"  grep -q \"^${key}\" /etc/security/pwquality.conf && " +
			"  sed -i \"s/^${key}.*/${key} = -1/\" /etc/security/pwquality.conf || " +
			"  echo \"${key} = -1\" >> /etc/security/pwquality.conf; " +
			"done"

	case "IA.L2-3.5.8": // password reuse
		return "" // PAM stack modifications require careful editing; flag for manual review

	case "SC.L2-3.13.1": // firewall
		return "ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw --force enable"

	case "SC.L2-3.13.8": // SSH weak ciphers
		return "grep -qE '^[[:space:]]*Ciphers' /etc/ssh/sshd_config && " +
			"sed -i 's/^[[:space:]]*Ciphers.*/Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config || " +
			"echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config; " +
			"sshd -t && systemctl restart sshd"

	case "CM.L2-3.4.6": // SELinux/AppArmor
		return "systemctl enable --now apparmor"

	case "SI.L2-3.14.1": // AV software
		return "apt-get install -y clamav clamav-daemon && freshclam && systemctl enable --now clamav-daemon"

	default:
		return "" // manual remediation required
	}
}
