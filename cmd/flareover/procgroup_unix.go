// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// detachProcessGroup puts cmd in its own process group.
//
// The guard's rollback trigger is the one child process this tool starts, and
// it is started at the worst possible moment: the site is already failing.
// Without this it inherits the foreground process group, so a Ctrl-C aimed at
// the watchdog delivers SIGINT to the rollback as well — interrupting a DNS
// write halfway, which is precisely the outcome the failguard exists to
// prevent. With its own group, stopping the watcher leaves the rollback to
// finish.
func detachProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
