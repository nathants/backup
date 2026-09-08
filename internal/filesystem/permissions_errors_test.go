package filesystem

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSourceCopyDistinguishesReadAndWriteFailures(t *testing.T) {
	for _, failure := range []error{unix.EACCES, unix.EPERM, unix.EIO} {
		for _, writeFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/write=%t", failure, writeFailure), func(t *testing.T) {
				reader, writer := io.Pipe()
				defer func() { _ = reader.Close() }()
				if err := writer.CloseWithError(failure); err != nil {
					t.Fatal(err)
				}
				source := sourceReader{Reader: io.MultiReader(strings.NewReader("partial bytes"), reader)}
				var destination bytes.Buffer
				var output io.Writer = &destination
				if writeFailure {
					output = failedPermissionWriter{failure}
				}
				_, err := io.CopyBuffer(output, source, make([]byte, 32))
				var readErr *sourceReadError
				if !errors.Is(err, failure) || errors.As(err, &readErr) == writeFailure {
					t.Fatalf("copy lost error provenance: %T %v", err, err)
				}
				if !writeFailure {
					if destination.String() != "partial bytes" {
						t.Fatal("fixture did not copy bytes before the source failed")
					}
					captured, captureErr := captureSourceFailure(err)
					if errors.Is(failure, os.ErrPermission) {
						if captureErr != nil || !captured.Changed || captured.Entry != nil || captured.Plain != nil {
							t.Fatalf("permission failure was not a complete omission: %+v, %v", captured, captureErr)
						}
					} else if !errors.Is(captureErr, failure) {
						t.Fatalf("non-permission source failure was hidden: %v", captureErr)
					}
				}
			})
		}
	}
}

type failedPermissionWriter struct{ err error }

func (writer failedPermissionWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestCaptureCleanupPermissionFailureRemainsFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	path := t.TempDir()
	mustWrite(t, filepath.Join(path, "file"), []byte("readable"), 0600)
	root, planned := openPlannedPath(t, path, "./file")
	defer func() { _ = root.Close() }()
	spool, err := PrepareSpool(t.TempDir(), "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.CloseAndRemove() })
	root.captureOpened = func(string) error {
		denySourceAccess(t, spool.Path(), 0500)
		return io.ErrUnexpectedEOF
	}
	_, err = root.CapturePath(planned, spool, 1)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("capture lost its plaintext cleanup failure: %v", err)
	}
}
