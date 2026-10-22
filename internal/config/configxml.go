package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// ErrConfigXMLIncomplete is a config.xml that is empty or does not end with
// its closing tag: what a read can see while OPNsense saves the file.
var ErrConfigXMLIncomplete = errors.New("the file is empty or does not end with </opnsense>")

// ErrConfigXMLLocked is a config.xml a writer kept locked past the wait.
var ErrConfigXMLLocked = errors.New("a configuration write kept the file locked")

var (
	configXMLLockWait   = 30 * time.Second
	configXMLLockPoll   = 50 * time.Millisecond
	configXMLAttempts   = 3
	configXMLRetryDelay = 250 * time.Millisecond

	readConfigXMLAttempt = readConfigXMLOnce
)

// ReadConfigXML returns the whole of OPNsense's config.xml.
//
// OPNsense saves the file by truncating and rewriting it in place, holding an
// exclusive flock on it through the write and the backup copy, so a plain read
// can return an empty or partial file and no error. ReadConfigXML reads under
// a shared flock, which no save can hold its exclusive one against, waiting
// at most configXMLLockWait for it (nothing bounds how long another process
// keeps the exclusive lock), and only accepts a file that ends with
// </opnsense>. A file that does not is read again, up to configXMLAttempts
// times, then reported as ErrConfigXMLIncomplete.
func ReadConfigXML(ctx context.Context, path string) ([]byte, error) {
	var err error
	for attempt := 1; attempt <= configXMLAttempts; attempt++ {
		if attempt > 1 {
			if werr := sleepCtx(ctx, configXMLRetryDelay); werr != nil {
				return nil, werr
			}
		}
		var data []byte
		data, err = readConfigXMLAttempt(ctx, path)
		if !errors.Is(err, ErrConfigXMLIncomplete) {
			return data, err
		}
	}
	return nil, err
}

func readConfigXMLOnce(ctx context.Context, path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Closing the file releases the lock.
	defer f.Close()
	if err := lockShared(ctx, f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !bytes.HasSuffix(bytes.TrimRight(data, " \t\r\n"), []byte("</opnsense>")) {
		return nil, ErrConfigXMLIncomplete
	}
	return data, nil
}

func lockShared(ctx context.Context, f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(configXMLLockWait)
	for {
		var lockErr error
		if err := conn.Control(func(fd uintptr) {
			lockErr = syscall.Flock(int(fd), syscall.LOCK_SH|syscall.LOCK_NB)
		}); err != nil {
			return err
		}
		if lockErr == nil {
			return nil
		}
		if !errors.Is(lockErr, syscall.EWOULDBLOCK) && !errors.Is(lockErr, syscall.EINTR) {
			return fmt.Errorf("lock %s: %w", f.Name(), lockErr)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w for %s", ErrConfigXMLLocked, configXMLLockWait)
		}
		if err := sleepCtx(ctx, configXMLLockPoll); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
