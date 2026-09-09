// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package main

import "os/exec"

// detachProcessGroup is a no-op outside unix.
//
// Windows has no process groups in the POSIX sense, and console control events
// are delivered on a different model; getting that right needs
// CREATE_NEW_PROCESS_GROUP plus its own handling, which is not warranted until
// somebody actually runs the failguard there. Doing nothing is honest: the
// trigger simply keeps the platform's default behaviour.
func detachProcessGroup(*exec.Cmd) {}
