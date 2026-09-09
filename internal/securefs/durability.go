package securefs

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// SyncParent makes an opened directory's containing entry durable. Resolve the
// parent through the retained directory descriptor, not a pathname that may use
// an alias or trailing slash. The caller exclusively controls the namespace.
func SyncParent(directoryFD int) error {
	parentFD, err := unix.Openat(directoryFD, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open containing directory for fsync: %w", err)
	}
	return errors.Join(unix.Fsync(parentFD), unix.Close(parentFD))
}
