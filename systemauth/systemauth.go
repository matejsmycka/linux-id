// Package systemauth delegates system-owned user verification to PolicyKit.
package systemauth

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const ActionID = "io.github.matejsmycka.linux-id.authenticate"

var ErrDenied = errors.New("system authentication denied")

// Authenticate asks PolicyKit to authenticate the user running linux-id.
// The systemd unit keeps the daemon in the host PID and user namespaces so
// PolicyKit can resolve this process subject directly.
func Authenticate() error {
	startTime, err := processStartTime()
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("%d,%s,%d", os.Getpid(), startTime, os.Getuid())
	cmd := exec.Command("/usr/bin/pkcheck",
		"--action-id", ActionID,
		"--process", subject,
		"--allow-user-interaction",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return ErrDenied
		}
		return fmt.Errorf("PolicyKit authorization failed: %w (%s)", err, strings.TrimSpace(output.String()))
	}
	return nil
}

func processStartTime() (string, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", fmt.Errorf("read process start time: %w", err)
	}
	// The executable name is parenthesized and can contain spaces or ')'.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return "", errors.New("invalid /proc/self/stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	// fields starts at proc(5) field 3; starttime is field 22.
	if len(fields) <= 19 {
		return "", errors.New("incomplete /proc/self/stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", fmt.Errorf("invalid process start time: %w", err)
	}
	return fields[19], nil
}
