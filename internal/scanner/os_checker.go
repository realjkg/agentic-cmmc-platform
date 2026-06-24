package scanner

import (
	"os"
	"os/exec"
	"strings"
)

// defaultChecker implements SystemChecker against the real operating system.
type defaultChecker struct{}

func (d *defaultChecker) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (d *defaultChecker) RunCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func (d *defaultChecker) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (d *defaultChecker) Hostname() (string, error) {
	return os.Hostname()
}

// sshConfigValue is a helper that returns the value for a key in sshd_config content.
// Returns ("", false) when not present.
func sshConfigValue(content, key string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			return fields[1], true
		}
	}
	return "", false
}
