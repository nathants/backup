package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestProgressCoalescesCountersAndEscapesTerminalControls(t *testing.T) {
	var output bytes.Buffer
	p := newOperationProgress(&output, "test", time.Hour)
	p.phasef("mirror %s", "unsafe\n\x1b[31m")
	before := output.Len()
	for index := range 1000 {
		p.detailf("objects checked=%d", index)
	}
	if output.Len() != before {
		t.Fatal("counter updates produced per-object chatter")
	}
	p.close()
	text := output.String()
	if !strings.Contains(text, "objects checked=999") || strings.Contains(text, "\x1b") || strings.Contains(text, "unsafe\n") {
		t.Fatalf("missing final counters or unsafe terminal output: %q", text)
	}
	select {
	case <-p.done:
	default:
		t.Fatal("reporter returned before timer stopped")
	}
}

func TestProgressHeartbeatDoesNotSkipTicksAfterPhaseChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		p := newOperationProgress(&output, "commit", progressInterval)
		defer p.close()
		snapshot := func() string {
			p.mu.Lock()
			defer p.mu.Unlock()
			return strings.Clone(output.String())
		}
		synctest.Wait()
		time.Sleep(4 * time.Second)
		p.phasef("pushing primary Git metadata")
		time.Sleep(time.Second)
		synctest.Wait()
		text := snapshot()
		if strings.Count(text, "still running") != 1 || !strings.Contains(text, "pushing primary Git metadata; still running; elapsed=5s") {
			t.Fatalf("phase change skipped the five-second heartbeat: %s", text)
		}
		time.Sleep(progressInterval)
		synctest.Wait()
		text = snapshot()
		if strings.Count(text, "still running") != 2 {
			t.Fatalf("idle operation lost its heartbeat: %s", text)
		}
	})
}

type progressFailWriter struct{ err error }

func (writer progressFailWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestProgressOutputFailurePreservesOperationError(t *testing.T) {
	failure := errors.New("stderr failed")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Add(ctx, Options{Stderr: progressFailWriter{failure}}, false)
	if err != context.Canceled {
		t.Fatalf("progress failure changed the operation error: %v", err)
	}
}

func TestProgressSerializesWarningsAndEvents(t *testing.T) {
	var output bytes.Buffer
	p := newOperationProgress(&output, "test", time.Millisecond)
	p.phasef("capturing and uploading planned paths")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := range 1000 {
			p.detailf("capture processed paths=%d", index)
			p.eventf("mirror local acknowledged part=%d", index)
		}
	}()
	for range 1000 {
		if _, err := fmt.Fprintln(p, "warning: example"); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	p.close()
	text := output.String()
	if strings.Count(text, "warning: example\n") != 1000 || strings.Count(text, "mirror local acknowledged part=") != 1000 {
		t.Fatal("concurrent progress damaged diagnostic output")
	}
	if !strings.Contains(text, "capturing and uploading planned paths; capture processed paths=999; observed") {
		t.Fatalf("upload events replaced capture state: %s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "acknowledged part=") && strings.Contains(line, "capture processed") {
			t.Fatalf("upload event inherited capture counters: %s", line)
		}
	}
}

func TestProgressWorkflowPreservesResultsAndDryRun(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "payload"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr, stdout bytes.Buffer
	h.options.Stderr, h.options.Stdout = &stderr, &stdout
	check := func(command, phase string) {
		t.Helper()
		if !strings.Contains(stderr.String(), "progress: "+command+":") || !strings.Contains(stderr.String(), phase) {
			t.Fatalf("missing %s progress (%s): %s", command, phase, &stderr)
		}
		if stdout.Len() != 0 {
			t.Fatalf("progress polluted stdout: %s", &stdout)
		}
		stderr.Reset()
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	check("add", "selected paths=")
	if _, err := Replan(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	check("replan", "reused files=")
	h.options.PartSize = 128 // Exercise multiple asynchronous part uploads.
	committed, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(stderr.String(), "acknowledged ciphertext part") < 2 || strings.Count(stderr.String(), "capturing and uploading planned paths; starting") != 1 {
		t.Fatalf("capture/upload fixture lacks multiple uploads or changed its shared phase: %s", &stderr)
	}
	check("commit", "pushing primary Git metadata")
	verified, err := Verify(ctx, h.options, 1, committed.CommitID)
	if err != nil || verified.Passed != 1 {
		t.Fatalf("verify: %#v %v", verified, err)
	}
	check("verify", "objects checked=")
	target := t.TempDir()
	request := RestoreRequest{Pattern: `^\./payload$`, Revision: committed.CommitID, TargetRoot: target, DryRun: true}
	if _, err := Restore(ctx, h.options, request); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "decrypting") || strings.Contains(stderr.String(), "publishing verified restore") {
		t.Fatalf("dry run claimed content work: %s", &stderr)
	}
	if _, err := os.Stat(filepath.Join(target, "payload")); !os.IsNotExist(err) {
		t.Fatalf("dry run published content: %v", err)
	}
	check("restore", "dry-run=true")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	request.DryRun = false
	if _, err := Restore(ctx, h.options, request); err != nil {
		t.Fatal(err)
	}
	check("restore", "nothing published yet")
	data, err := os.ReadFile(filepath.Join(target, "payload"))
	if err != nil || string(data) != "content" {
		t.Fatalf("restore: %q %v", data, err)
	}
	if _, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: committed.CommitID, ListOnly: true}); err != nil {
		t.Fatal(err)
	}
	check("recover", "verified tips=1")
	if _, err := RepairMetadataEdge(ctx, h.options, "local", committed.CommitID); err != nil {
		t.Fatal(err)
	}
	check("repair metadata", "validating rebuilt metadata edge")
}

func TestProgressFailureDoesNotHidePublishedRevision(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "data"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	h.options.Stderr = progressFailWriter{io.ErrClosedPipe}
	result, err := Commit(ctx, h.options)
	if err != nil || result.CommitID == "" || len(result.CompleteMirrors) == 0 {
		t.Fatalf("progress failure hid publication: result=%+v err=%v", result, err)
	}
	verified, err := Verify(ctx, h.options, 1, result.CommitID)
	if err != nil || verified.Passed != 1 {
		t.Fatalf("verify with broken progress output: %+v %v", verified, err)
	}
}

type progressWriteFunc func([]byte) (int, error)

func (write progressWriteFunc) Write(data []byte) (int, error) { return write(data) }

func TestProgressStopsOnOutputFailureButWarningsRemainStrict(t *testing.T) {
	for _, failure := range []error{io.ErrClosedPipe, nil} {
		calls := 0
		writer := progressWriteFunc(func([]byte) (int, error) {
			calls++
			return 0, failure
		})
		p := newOperationProgress(writer, "test", time.Hour)
		p.phasef("another phase")
		p.detailf("objects checked=1")
		p.eventf("part acknowledged")
		p.close()
		if calls != 1 {
			t.Fatalf("failed progress sink was retried %d times", calls)
		}
		run := runtime{options: Options{Stderr: p}}
		err := run.reportf("warning: example\n")
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || calls != 2 {
			t.Fatalf("mandatory diagnostic failure was hidden: calls=%d err=%v", calls, err)
		}
	}
}
