package browser

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

// killProcessTree kills a process and all its children.
// On Windows, proc.Kill() only terminates the parent process — Chrome's child
// processes (GPU helper, renderer, crashpad) survive and block indefinitely.
// On Linux/macOS, proc.Kill() only sends SIGKILL to the parent; children get
// reparented to PID 1 and keep running.
func killProcessTree(proc *os.Process) {
	if proc == nil {
		return
	}
	if runtime.GOOS == "windows" {
		// taskkill /F = force, /T = tree (kill children too)
		_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(proc.Pid)).Run()
	} else {
		// Try to kill the entire process group via external kill command.
		// chromedp launches Chrome with Setpgid=true so the group ID equals
		// the parent PID. Negative PID targets the process group.
		err := exec.Command("kill", "-9", "--", "-"+strconv.Itoa(proc.Pid)).Run()
		if err != nil {
			// Fallback: kill just the parent process
			_ = proc.Kill()
		}
	}
}
