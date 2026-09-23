package objectstore

import (
	"context"
	"io"
	"os"
)

// Store supplies immutable ciphertext creation and integrity-checked reads.
// GetVerified may write unverified bytes to private staging before returning an
// error; callers must not publish that staging until it succeeds.
type Store interface {
	PutFile(context.Context, string, string, Object) CreateResult
	PutOpenFile(context.Context, string, *os.File, Object) CreateResult
	Audit(context.Context, string, Object) error
	GetVerified(context.Context, string, Object, io.Writer) error
	GetManifest(context.Context, string, string) ([]byte, error)
	List(context.Context, string) ([]string, error)
	ListLimited(context.Context, string, int) ([]string, error)
	Close() error
}

func (client *Client) Close() error { return nil }

var _ Store = (*Client)(nil)
var _ Store = (*Filesystem)(nil)
