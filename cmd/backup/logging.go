package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	debugLogRetention = 14 * 24 * time.Hour
	debugLogChunkSize = 16 << 10
)

var debugLogName = regexp.MustCompile(`^backup-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9a-f]{32}\.jsonl$`)

// execute owns process-level diagnostics so help, parse failures, and final
// errors use the same logging path as successful commands.
func execute(ctx context.Context, arguments []string, stdout, stderr io.Writer) (status int) {
	// Only a normal return supplies an exit status, not panic unwinding.
	status = -1
	// A tee hides *os.File from the progress reporter's SIGPIPE guard. Use a
	// private stderr descriptor so optional progress and logging warnings still
	// get ordinary write errors; mandatory diagnostics continue to return them.
	canLog := true
	if file, ok := stderr.(*os.File); ok && (file.Fd() == 1 || file.Fd() == 2) {
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			warnDebugLog(stderr, err)
			canLog = false
		} else {
			owned := os.NewFile(uintptr(fd), "backup-stderr")
			defer func() { _ = owned.Close() }()
			stderr = owned
		}
	}
	if canLog {
		home, err := os.UserHomeDir()
		var log *commandLog
		if err == nil {
			log, err = newCommandLog(home, debugCommand(arguments), stderr, time.Now)
		}
		if err != nil {
			warnDebugLog(stderr, err)
		} else {
			defer func() { log.close(status) }()
			stdout = &loggedOutput{terminal: stdout, log: log, stream: "stdout"}
			stderr = &loggedOutput{terminal: stderr, log: log, stream: "stderr"}
		}
	}
	if err := run(ctx, arguments, stdout, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, "backup:", escapeTerminal(err.Error()))
		return 1
	}
	return 0
}

// Record only allowlisted command names, never argv or environment values.
func debugCommand(arguments []string) string {
	if len(arguments) == 0 {
		return "help"
	}
	switch arguments[0] {
	case "help", "-h", "--help":
		return "help"
	case "init", "add", "replan", "diff", "commit", "reset", "find", "restore", "verify", "sync", "recover", "server", "mirror-init":
		return arguments[0]
	case "repair":
		if len(arguments) > 1 && (arguments[1] == "data" || arguments[1] == "metadata") {
			return "repair " + arguments[1]
		}
		return "repair"
	default:
		return "unknown"
	}
}

func warnDebugLog(output io.Writer, err error) {
	message := "backup: warning: disk debug logging unavailable: " + escapeTerminal(err.Error()) + "\n"
	// Even a failure to duplicate stderr must not turn this optional warning
	// into process termination on a closed pipe.
	if file, ok := output.(*os.File); ok && (file.Fd() == 1 || file.Fd() == 2) {
		_, _ = unix.Write(int(file.Fd()), []byte(message))
		return
	}
	_, _ = io.WriteString(output, message)
}

type commandLog struct {
	mu        sync.Mutex
	directory *os.File
	file      *os.File
	day       string
	run       string
	command   string
	warning   io.Writer
	now       func() time.Time
	failed    bool
}

type debugRecord struct {
	Time    time.Time `json:"time"`
	Run     string    `json:"run"`
	Command string    `json:"command"`
	Stream  string    `json:"stream"`
	Message string    `json:"message"`
}

func newCommandLog(home, command string, warning io.Writer, now func() time.Time) (*commandLog, error) {
	directory, err := openDebugLogDirectory(home)
	if err != nil {
		return nil, err
	}
	log := &commandLog{directory: directory, command: command, warning: warning, now: now}
	log.writeLocked("command", []byte("start"))
	return log, nil
}

type loggedOutput struct {
	terminal io.Writer
	log      *commandLog
	stream   string
}

func (output *loggedOutput) Write(data []byte) (int, error) {
	output.log.mu.Lock()
	defer output.log.mu.Unlock()
	// Capture attempted output even when the terminal subsequently fails.
	output.log.writeLocked(output.stream, data)
	n, err := output.terminal.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (log *commandLog) writeLocked(stream string, data []byte) {
	if log.failed || len(data) == 0 {
		return
	}
	now := log.now().UTC()
	if err := log.rotate(now); err != nil {
		log.fail(err)
		return
	}
	for len(data) > 0 {
		size := min(len(data), debugLogChunkSize)
		// Keep UTF-8 characters intact when splitting large textual writes.
		if size < len(data) {
			for size > 0 && !utf8.RuneStart(data[size]) {
				size--
			}
			if size == 0 {
				size = debugLogChunkSize
			}
		}
		record := debugRecord{Time: now, Run: log.run, Command: log.command, Stream: stream, Message: string(data[:size])}
		if err := json.NewEncoder(log.file).Encode(record); err != nil {
			log.fail(err)
			return
		}
		data = data[size:]
	}
}

func (log *commandLog) rotate(now time.Time) error {
	day := now.Format(time.DateOnly)
	if log.file != nil && log.day == day {
		return nil
	}
	if log.file != nil {
		err := log.file.Close()
		log.file = nil
		if err != nil {
			return err
		}
	}
	// Startup and daily rollover both prune; a long-running server must not
	// retain an ever-growing file just because it has not been restarted.
	if err := pruneDebugLogs(log.directory, now); err != nil {
		return fmt.Errorf("prune expired logs: %w", err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := fmt.Sprintf("%x", random)
	name := "backup-" + day + "-" + id + ".jsonl"
	fd, err := unix.Openat(int(log.directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	log.file, log.day = os.NewFile(uintptr(fd), name), day
	if log.run == "" {
		log.run = id
	}
	return nil
}

func (log *commandLog) fail(err error) {
	if !log.failed {
		log.failed = true
		warnDebugLog(log.warning, err)
	}
}

func (log *commandLog) close(status int) {
	log.mu.Lock()
	defer log.mu.Unlock()
	message := "aborted"
	if status >= 0 {
		message = fmt.Sprintf("exit %d", status)
	}
	log.writeLocked("command", []byte(message))
	if log.file != nil {
		if err := log.file.Close(); err != nil {
			log.fail(err)
		}
	}
	if err := log.directory.Close(); err != nil {
		log.fail(err)
	}
}

func openDebugLogDirectory(home string) (*os.File, error) {
	if !filepath.IsAbs(home) {
		return nil, fmt.Errorf("HOME must be an absolute directory")
	}
	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(homeFD) }()
	const name = ".backup-logs"
	if err := unix.Mkdirat(homeFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(homeFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("debug log directory %q must be owned by this user with no group/other permissions: %w", name, os.ErrPermission)
	}
	return os.NewFile(uintptr(fd), filepath.Join(home, name)), nil
}

func pruneDebugLogs(directory *os.File, now time.Time) error {
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	entries := os.NewFile(uintptr(fd), directory.Name())
	defer func() { _ = entries.Close() }()
	cutoff := now.Add(-debugLogRetention)
	for {
		names, readErr := entries.Readdirnames(128)
		for _, name := range names {
			if !debugLogName.MatchString(name) {
				continue
			}
			if _, err := time.Parse(time.DateOnly, name[len("backup-"):len("backup-2006-01-02")]); err != nil {
				continue
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue // Another command already pruned it.
				}
				return err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).Before(cutoff) {
				continue
			}
			if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
