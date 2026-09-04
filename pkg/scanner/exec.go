package scanner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// ExecResult represents the outcome of an external tool invocation.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// RunTool invokes an external command. It captures stdout and stderr, and enforces
// context cancellation (which handles timeouts if the context has a deadline).
func RunTool(ctx context.Context, workingDir string, command string, args ...string) (ExecResult, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	if workingDir != "" {
		cmd.Dir = workingDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			// e.g. command not found, context deadline exceeded, etc.
			return ExecResult{
				Stdout: stdout.Bytes(),
				Stderr: stderr.Bytes(),
			}, err
		}
	}

	return ExecResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: exitCode,
	}, nil
}
