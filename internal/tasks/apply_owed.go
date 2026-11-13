package tasks

// Applies a SYNC owes. A service's apply call stops and starts it or reloads
// it (Unbound and Zabbix restart, the alias reconfigure restarts cron and
// reloads the filter), so a SYNC applies a service only when it wrote to it,
// or when an earlier write was not followed by an apply that succeeded. That
// is known from a record on disk: a service is entered before its first write
// goes out and cleared once its apply succeeded, so an apply that failed, or
// an agent that stopped between the write and the apply, is caught up by the
// next SYNC (NDAgent-go#248). A record that is missing or cannot be read says
// nothing about what came before, so every service is owed, except one in
// which the device holds nothing managed and the SYNC wants nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// applyService is a service whose configuration a SYNC writes and applies.
type applyService string

const (
	applyFirewallAliases applyService = "firewall_aliases"
	applyFirewallRules   applyService = "firewall_rules"
	applyUnbound         applyService = "unbound"
	applyZabbix          applyService = "zabbix"
	applyWireGuard       applyService = "wireguard"
)

var applyServices = []applyService{applyFirewallAliases, applyFirewallRules, applyUnbound, applyZabbix, applyWireGuard}

// codeApplyOwed marks an apply item that ran only because an earlier SYNC
// left the apply owed.
const codeApplyOwed = "APPLY_OWED"

// applyWritePrefixes map a write's path to the service it owes an apply.
var applyWritePrefixes = []struct {
	prefix  string
	service applyService
}{
	{"/firewall/alias/", applyFirewallAliases},
	{"/firewall/filter/", applyFirewallRules},
	{"/unbound/settings/", applyUnbound},
	{"/zabbixagent/settings/", applyZabbix},
	{"/wireguard/general/", applyWireGuard},
	{"/wireguard/server/", applyWireGuard},
	{"/wireguard/client/", applyWireGuard},
}

// applyCalls are the applies the prefixes above also match. The other
// families' reconfigures sit under /<plugin>/service/, which no prefix
// matches.
var applyCalls = map[string]bool{
	"/firewall/alias/reconfigure": true,
	"/firewall/filter/apply":      true,
}

// applyServiceOf is the service a write to path owes an apply, or "" when it
// owes none.
func applyServiceOf(path string) applyService {
	path, _, _ = strings.Cut(path, "?")
	if applyCalls[path] {
		return ""
	}
	for _, p := range applyWritePrefixes {
		if strings.HasPrefix(path, p.prefix) {
			return p.service
		}
	}
	return ""
}

// Overridable by tests.
var (
	applyOwedPath = "/var/db/ndagent/apply-owed.json"
	applyOwedNow  = time.Now
)

const applyOwedVersion = 1

type applyOwedFile struct {
	V int `json:"v"`
	// Owed maps a service to when it was first owed (RFC 3339, UTC).
	Owed map[applyService]string `json:"owed"`
	// Guessed are the owed services only a missing or unreadable record put
	// there. They stay guesses on disk until a SYNC settles them, so a SYNC cut
	// short does not turn them into entries the agent recorded.
	Guessed []applyService `json:"guessed,omitempty"`
}

type applyOwedKey struct{}

// applyOwed is one SYNC's view of the record.
type applyOwed struct {
	mu sync.Mutex
	// owed is what the record holds, kept in step with the file.
	owed map[applyService]string
	// before is what was owed when the SYNC began.
	before map[applyService]bool
	// wrote is what this SYNC wrote and has not applied yet.
	wrote map[applyService]bool
	// guessed are the owed services not known to be owed: a missing or
	// unreadable record put them there.
	guessed map[applyService]bool
}

// loadApplyOwed reads the record. A missing or unreadable record owes every
// service.
func loadApplyOwed() *applyOwed {
	a := newApplyOwed()
	f, err := readApplyOwed()
	if err != nil {
		now := applyOwedNow().UTC().Format(time.RFC3339)
		for _, s := range applyServices {
			a.owed[s] = now
			a.guessed[s] = true
		}
		// An unreadable record is replaced at once, or it is reported on
		// every SYNC until an apply succeeds.
		if !errors.Is(err, fs.ErrNotExist) {
			logging.Named("SYNC_API").Warnw("Apply record unreadable: every service is applied this SYNC", "path", applyOwedPath, "error", err)
			if err := a.save(); err != nil {
				logging.Named("SYNC_API").Warnw("Could not replace the unreadable apply record", "path", applyOwedPath, "error", err)
			}
		}
	} else {
		for s, since := range f.Owed {
			a.owed[s] = since
		}
		for _, s := range f.Guessed {
			if _, ok := a.owed[s]; ok {
				a.guessed[s] = true
			}
		}
	}
	for s := range a.owed {
		a.before[s] = true
	}
	return a
}

func newApplyOwed() *applyOwed {
	return &applyOwed{owed: map[applyService]string{}, before: map[applyService]bool{}, wrote: map[applyService]bool{}, guessed: map[applyService]bool{}}
}

// attach returns ctx carrying the record, with every write made with it
// noted before it goes out.
func (a *applyOwed) attach(ctx context.Context) context.Context {
	return context.WithValue(opnapi.WithWriteHook(ctx, a.noteWrite), applyOwedKey{}, a)
}

// applyOwedFrom is the record ctx carries, or nil.
func applyOwedFrom(ctx context.Context) *applyOwed {
	a, _ := ctx.Value(applyOwedKey{}).(*applyOwed)
	return a
}

// noteWrite enters the service a write owes an apply, on disk, before the
// write is sent. A write that then fails or is refused still owes it: it may
// have been saved. A write whose entry cannot be saved still goes out: this
// SYNC applies its service anyway, and only a retry after a failed apply is
// lost.
func (a *applyOwed) noteWrite(_, path string) {
	s := applyServiceOf(path)
	if s == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wrote[s] {
		return
	}
	a.wrote[s] = true
	_, owed := a.owed[s]
	if owed && !a.guessed[s] {
		return
	}
	delete(a.guessed, s)
	if !owed {
		a.owed[s] = applyOwedNow().UTC().Format(time.RFC3339)
	}
	if err := a.save(); err != nil {
		logging.Named("SYNC_API").Warnw("Could not record the apply this write owes; if the apply fails, the next SYNC does not retry it",
			"service", string(s), "path", applyOwedPath, "error", err)
	}
}

// due reports whether s is applied in this SYNC, and whether only because an
// earlier SYNC owed it. Without a record every service is applied.
func (a *applyOwed) due(s applyService) (apply, owedOnly bool) {
	if a == nil {
		return true, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wrote[s] {
		return true, false
	}
	return a.before[s], a.before[s]
}

// applied records that s was applied: it owes nothing any more.
func (a *applyOwed) applied(s applyService) {
	a.forget(s, "Could not record the apply that ran; the next SYNC applies it again")
}

// unused drops an entry only a missing or unreadable record put there, for a
// service in which the device holds nothing managed and the SYNC wants
// nothing: the agent has nothing in it to apply, so it neither restarts the
// service nor fails every SYNC on a service it never touched.
func (a *applyOwed) unused(s applyService) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.guessed[s] && !a.wrote[s] {
		a.forgetLocked(s, "Could not record that the service holds nothing managed; the next SYNC looks again")
	}
}

// gone records that s has nothing to apply on this device: its plugin is not
// installed.
func (a *applyOwed) gone(s applyService) {
	a.forget(s, "Could not record that the service is not installed; the next SYNC looks again")
}

func (a *applyOwed) forget(s applyService, warning string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forgetLocked(s, warning)
}

func (a *applyOwed) forgetLocked(s applyService, warning string) {
	a.wrote[s], a.before[s] = false, false
	delete(a.guessed, s)
	if _, ok := a.owed[s]; !ok {
		return
	}
	delete(a.owed, s)
	if err := a.save(); err != nil {
		logging.Named("SYNC_API").Warnw(warning, "service", string(s), "path", applyOwedPath, "error", err)
	}
}

// appliedItem is the result item of an apply that ran.
func appliedItem(itemType, name string, owedOnly bool) SyncAPIItemResult {
	item := SyncAPIItemResult{Type: itemType, Name: name, Action: "apply", Status: "success"}
	if owedOnly {
		item.Code = codeApplyOwed
	}
	return item
}

func readApplyOwed() (applyOwedFile, error) {
	var f applyOwedFile
	data, err := os.ReadFile(applyOwedPath)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return applyOwedFile{}, fmt.Errorf("decode %s: %w", applyOwedPath, err)
	}
	if f.V != applyOwedVersion {
		return applyOwedFile{}, fmt.Errorf("%s: version %d, want %d", applyOwedPath, f.V, applyOwedVersion)
	}
	return f, nil
}

// save replaces the file, with the file and then its directory synced: an
// entry must outlive a power loss between the write it was made for and the
// apply, and on ZFS a rename can wait in the open transaction group. It never
// creates the agent's directory, which a decommission removes.
func (a *applyOwed) save() error {
	f := applyOwedFile{V: applyOwedVersion, Owed: a.owed}
	for _, s := range applyServices {
		if a.guessed[s] {
			f.Guessed = append(f.Guessed, s)
		}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(applyOwedPath)
	tmp, err := os.CreateTemp(dir, ".apply-owed.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), applyOwedPath); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
