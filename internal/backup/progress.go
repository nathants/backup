package backup

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const progressInterval = 5 * time.Second

// operationProgress is best-effort diagnostics, never evidence of durability or
// completion. The timer reads only this small snapshot, not live operation state.
// All stderr writes share its lock so warnings cannot race the heartbeat.
type operationProgress struct {
	mu      sync.Mutex
	output  io.Writer
	owned   *os.File
	command string
	phase   string
	detail  string
	started time.Time
	failed  bool
	stop    chan struct{}
	done    chan struct{}
}

func startProgress(options *Options, command string) func() {
	if options.Stderr == nil || options.Stderr == io.Discard {
		return func() {}
	}
	p := newOperationProgress(options.Stderr, command, progressInterval)
	options.Stderr = p
	options.progress = p
	return p.close
}

func newOperationProgress(output io.Writer, command string, interval time.Duration) *operationProgress {
	p := &operationProgress{output: output, command: command, started: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	// Go terminates the process on EPIPE from fd 1 or 2. A private duplicate
	// turns optional progress writes into ordinary errors without changing the
	// process-wide SIGPIPE policy or mandatory diagnostic writes.
	if file, ok := output.(*os.File); ok && (file.Fd() == 1 || file.Fd() == 2) {
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			p.failed = true
		} else {
			p.owned = os.NewFile(uintptr(fd), "backup-progress")
		}
	}
	p.phasef("opening configuration and local state")
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				p.emitLocked("still running")
				p.mu.Unlock()
			}
		}
	}()
	return p
}

// Write preserves error reporting for mandatory diagnostics even after optional
// progress has failed. It does not use the best-effort progress path.
func (p *operationProgress) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, err := p.output.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (p *operationProgress) writeLocked(message string) {
	if p.failed {
		return
	}
	line := fmt.Sprintf("progress: %s: %s; elapsed=%s\n", p.command, message, time.Since(p.started).Truncate(time.Second))
	output := p.output
	if p.owned != nil {
		output = p.owned
	}
	n, err := io.WriteString(output, line)
	p.failed = err != nil || n != len(line)
}

func (p *operationProgress) emitLocked(status string) {
	message := p.phase
	if p.detail != "" {
		message += "; " + p.detail
	}
	p.writeLocked(message + "; " + status)
}

func (p *operationProgress) phasef(pattern string, args ...any) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	phase := terminalEscape(fmt.Sprintf(pattern, args...))
	if phase == p.phase {
		return
	}
	if p.detail != "" {
		p.emitLocked("observed")
	}
	p.phase, p.detail = phase, ""
	p.emitLocked("starting")
}

// detailf updates counters without per-file output. The next heartbeat, phase
// change, or close reports them, including when the command exits with an error.
func (p *operationProgress) detailf(pattern string, args ...any) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detail = terminalEscape(fmt.Sprintf(pattern, args...))
}

// eventf reports a self-contained observation without changing the active phase
// or its counters. Concurrent pipeline stages use events, not phase changes.
func (p *operationProgress) eventf(pattern string, args ...any) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeLocked(terminalEscape(fmt.Sprintf(pattern, args...)))
}

func (p *operationProgress) close() {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.detail != "" {
		p.emitLocked("observed")
	}
	if p.owned != nil {
		_ = p.owned.Close()
	}
}
