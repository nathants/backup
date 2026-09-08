package filesystem

import (
	"errors"
	"io"
	"os"
)

func reportPermissionSkip(err error, path string, result *Result, reporter Reporter) bool {
	if !errors.Is(err, os.ErrPermission) {
		return false
	}
	result.SkippedPermissionDenied++
	report(reporter, Event{Kind: EventPermissionSkipped, Path: path, Detail: err.Error()})
	return true
}

// Only call this at source-access boundaries, never for staging or policy errors.
func captureSourceFailure(err error) (CaptureResult, error) {
	if errors.Is(err, os.ErrPermission) {
		return CaptureResult{Changed: true, Reason: err.Error() + "; omitted"}, nil
	}
	return CaptureResult{}, err
}

// Keep source-read failures distinct from spool-write failures in io.CopyBuffer.
type sourceReader struct{ io.Reader }

type sourceReadError struct{ err error }

func (err *sourceReadError) Error() string { return err.err.Error() }
func (err *sourceReadError) Unwrap() error { return err.err }

func (reader sourceReader) Read(buffer []byte) (int, error) {
	count, err := reader.Reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return count, &sourceReadError{err: err}
	}
	return count, err
}
