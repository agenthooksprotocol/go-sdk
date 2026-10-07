//go:build !unix

package client

import "os/exec"

func configureBackendProcess(cmd *exec.Cmd) {}
func killBackendProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
