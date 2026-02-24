package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Lock struct {
	file *os.File
	path string
}

func AcquireLock(root string) (*Lock, error) {
	lockPath := filepath.Join(root, ".backup", "lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	_, err = file.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Lock{file: file, path: lockPath}, nil
}

func (lock *Lock) Release() {
	if lock == nil {
		return
	}
	if lock.file == nil {
		return
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	if err != nil {
		panic(err)
	}
	err = lock.file.Close()
	if err != nil {
		panic(err)
	}
}
