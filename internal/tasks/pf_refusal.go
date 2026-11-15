package tasks

// A filter apply answers OK when pf refused the ruleset: rc.filter_configure
// exits 0 and puts the previous ruleset back (NDAgent-go#305). Its
// filter_configure_sync runs `pfctl -f /tmp/rules.debug > /tmp/rules.debug.error
// 2>&1` and deletes that file after a load that succeeded, so a file with pf's
// output in it after the apply means the last load was refused. The shell
// creates it empty when a load starts, so an empty file is a load still under
// way. /tmp/rules.error carries the message the WebAdmin banner shows; it
// stays until somebody dismisses the banner and is also written for warnings
// with the ruleset loaded, so it never decides anything, it only words it.
// The same on 26.1 and 26.7.
//
// The check reads the device's last load, whoever started it: a reload from
// the GUI, cron or another service between the apply and the check is read
// as this one's.
//
// Both files are in /tmp, which anybody can write to, and the agent runs as
// root: only a regular file of root's with a single link is read, never
// through a symbolic link, and never more than pfFileReadMax bytes of it.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Overridable by tests. Tests in this package that change them must not run
// in parallel.
var (
	pfLoadErrorPath   = "/tmp/rules.debug.error"
	pfRulesBannerPath = "/tmp/rules.error"
	pfFileOwnerOK     = func(uid uint32) bool { return uid == 0 }
)

const (
	codeRulesetRefused = "RULESET_REFUSED"
	// pfMessageMax bounds pf's message in the task result.
	pfMessageMax  = 1024
	pfFileReadMax = 64 << 10
)

// pfRulesetRefused reports whether pf refused the last ruleset load, with
// pf's message. A file that cannot be read says nothing, and err says why.
func pfRulesetRefused() (refused bool, message string, err error) {
	out, modTime, err := readPfFile(pfLoadErrorPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return false, "", nil
	}
	message = firstLine(out)
	if banner, ok := pfBanner(modTime); ok {
		message = banner
	}
	return true, clipMessage(message, pfMessageMax), nil
}

// pfBanner is the WebAdmin banner's text when it was written by the same load
// as the load error, or after it.
func pfBanner(loadErrorWritten time.Time) (string, bool) {
	data, modTime, err := readPfFile(pfRulesBannerPath)
	if err != nil || modTime.Before(loadErrorWritten) {
		return "", false
	}
	text := strings.TrimSpace(string(data))
	return text, text != ""
}

// readPfFile reads at most pfFileReadMax bytes of one of pf's files, with its
// modification time.
func readPfFile(path string) ([]byte, time.Time, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return nil, time.Time{}, fmt.Errorf("%s is not a regular file", path)
	case !ok:
		return nil, time.Time{}, fmt.Errorf("%s: its owner cannot be read", path)
	case !pfFileOwnerOK(st.Uid):
		return nil, time.Time{}, fmt.Errorf("%s is owned by uid %d, not root", path, st.Uid)
	case uint64(st.Nlink) != 1:
		return nil, time.Time{}, fmt.Errorf("%s has %d links", path, st.Nlink)
	}
	data, err := io.ReadAll(io.LimitReader(f, pfFileReadMax))
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime(), nil
}

func firstLine(data []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			return line
		}
	}
	return strings.TrimSpace(string(data))
}

// clipMessage drops control characters and cuts s to at most limit bytes on a
// rune boundary.
func clipMessage(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || (r < 0x20 && r != '\t') || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= limit {
		return s
	}
	cut := limit - len("...")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// rulesetRefusedError words a refused ruleset for the task result. pf reads
// the whole ruleset, so the rule it names may be one NetDefense does not
// manage.
func rulesetRefusedError(message string) string {
	return fmt.Sprintf("Rule apply: pf refused the firewall ruleset, so the firewall keeps its previous rules (the rule pf names may be any rule on the device, local rules included): %s", message)
}
