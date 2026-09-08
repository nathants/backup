package objectstore

import (
	"errors"
	"fmt"
	"net/http"

	"backup/internal/format"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Only conclusive remote evidence carries these classifications. Transport,
// authorization and unsupported checksum capabilities remain ordinary errors.
var (
	ErrCorrupt = errors.New("object integrity failure")
	ErrMissing = errors.New("object missing")
)

func (client *Client) classifyReadError(err error) error {
	if responseStatus(err) == http.StatusNotFound {
		return fmt.Errorf("%w: %w", ErrMissing, err)
	}
	var response *smithyhttp.ResponseError
	if client.mirror.Kind == format.MirrorBackupServer && errors.As(err, &response) && response.HTTPStatusCode() == http.StatusInternalServerError && response.HTTPResponse().Header.Get("X-Backup-Integrity") == "corrupt" {
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return err
}
