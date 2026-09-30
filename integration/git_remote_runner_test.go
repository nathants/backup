package integration

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nathants/go-libsodium"
	"golang.org/x/sys/unix"
)

// Use real Git and the required sibling helper. Only process lifetimes are
// controlled here; provider behavior belongs to the guarded live AWS gate.
func TestGitPrimaryProcessLifecycle(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "git-remote-aws")
	run(t, "../../git-remote-aws", "go", "build", "-o", helper, ".")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	libsodium.Init()
	public, _, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "failure", "timeout", "interrupt", "terminate", "force-kill", "killed-parent"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			marker := filepath.Join(directory, "drained")
			deadline := "20"
			wantStatus := 0
			switch scenario {
			case "failure":
				wantStatus = 1
			case "timeout":
				deadline, wantStatus = "5", 124
			case "interrupt":
				wantStatus = 130
			case "terminate", "force-kill":
				wantStatus = 143
			case "killed-parent":
				wantStatus = 137
			}
			command := exec.CommandContext(t.Context(), "python3", "-I", "./reap.py", "--timeout", deadline, "--kill-after", "0.2", "--drained", marker, "--", binary, "-test.run=^TestGitPrimaryProcessTree$")
			command.Env = cleanEnvironment(t, map[string]string{
				"BACKUP_REAP_SCENARIO": scenario, "BACKUP_REAP_DIRECTORY": directory,
				"BACKUP_REAP_HELPER": helper, "GIT_REMOTE_AWS_PUBLICKEY": hex.EncodeToString(public),
			})
			command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
			command.WaitDelay = 15 * time.Second
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = command.Process.Signal(syscall.SIGTERM)
					_ = command.Wait()
				}
			})
			waitForProcessFile(t, filepath.Join(directory, "ready"))
			var descriptors []unix.PollFd
			for _, name := range []string{"parent", "git", "helper"} {
				data, err := os.ReadFile(filepath.Join(directory, name+".pid"))
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(string(data))
				if err != nil {
					t.Fatal(err)
				}
				fd, err := unix.PidfdOpen(pid, 0)
				if err != nil {
					t.Fatalf("%s exited before the lifecycle trigger: %v", name, err)
				}
				t.Cleanup(func() {
					_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
					_ = unix.Close(fd)
				})
				descriptors = append(descriptors, unix.PollFd{Fd: int32(fd), Events: unix.POLLIN})
			}
			writeFile(t, filepath.Join(directory, "release"), nil, 0600)
			switch scenario {
			case "interrupt":
				err = command.Process.Signal(syscall.SIGINT)
			case "terminate", "force-kill":
				err = command.Process.Signal(syscall.SIGTERM)
			case "killed-parent":
				err = unix.PidfdSendSignal(int(descriptors[0].Fd), unix.SIGKILL, nil, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			runErr := command.Wait()
			waited = true
			status := 0
			if runErr != nil {
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) {
					t.Fatalf("supervisor: %v\n%s", runErr, output.String())
				}
				status = exit.ExitCode()
			}
			if status != wantStatus {
				t.Fatalf("exit status %d, want %d\n%s", status, wantStatus, output.String())
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("cleanup was not authorized: %v\n%s", err, output.String())
			}
			if count, err := unix.Poll(descriptors, 0); err != nil || count != len(descriptors) {
				t.Fatalf("authorized cleanup with surviving descendants: exited=%d: %v", count, err)
			}
			for _, descriptor := range descriptors {
				if descriptor.Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
					t.Fatalf("pidfd did not confirm process exit: events=%#x", descriptor.Revents)
				}
			}
		})
	}
}

// This subprocess leaves real, blocked tools in separate groups/sessions.
// Opening the FIFOs read/write keeps their input open even after this parent dies.
func TestGitPrimaryProcessTree(t *testing.T) {
	scenario := os.Getenv("BACKUP_REAP_SCENARIO")
	if scenario == "" {
		t.Skip("process-lifecycle child")
	}
	directory := os.Getenv("BACKUP_REAP_DIRECTORY")
	if scenario == "force-kill" {
		signal.Ignore(syscall.SIGTERM)
	}
	writeFile(t, filepath.Join(directory, "parent.pid"), []byte(strconv.Itoa(os.Getpid())), 0600)
	for _, name := range []string{"git", "helper"} {
		fifo := filepath.Join(directory, name+".input")
		if err := syscall.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		input, err := os.OpenFile(fifo, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command("git", "hash-object", "--stdin")
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if name == "helper" {
			command = exec.Command(os.Getenv("BACKUP_REAP_HELPER"), "--encrypt")
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		}
		command.Stdin, command.Stderr = input, os.Stderr
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(directory, name+".pid"), []byte(strconv.Itoa(command.Process.Pid)), 0600)
		if name == "helper" {
			// Require actual recipient-stream output, not merely a successful exec.
			if _, err := io.ReadFull(output, make([]byte, 1)); err != nil {
				t.Fatalf("helper encryption did not start: %v", err)
			}
		}
	}
	writeFile(t, filepath.Join(directory, "ready"), nil, 0600)
	waitForProcessFile(t, filepath.Join(directory, "release"))
	switch scenario {
	case "success":
		return
	case "failure":
		t.Fatal("abort after starting descendants")
	default:
		for {
			time.Sleep(time.Hour)
		}
	}
}

func waitForProcessFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process did not reach %s", path)
}

func TestGitPrimaryContractRequiresRunner(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"", "production-bucket"} {
		command := exec.CommandContext(t.Context(), binary, "-test.run=^TestAWSGitRemoteKeychains$")
		command.Env = cleanEnvironment(t, map[string]string{
			"BACKUP_GIT_REMOTE_CONTRACT": "1", "BACKUP_GIT_REMOTE_RESOURCE": resource,
			"LIBAWS_TEST_ACCOUNT": "123456789012", "PATH": t.TempDir(),
		})
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "runner-owned scratch resource required") {
			t.Fatalf("unguarded resource %q did not fail before provider access: %v: %s", resource, err, output)
		}
	}
}
