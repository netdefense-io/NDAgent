package track

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The device side of a series upgrade: what SystemDevice reads from the box and from
// the REST API. The commands and the places are replaced; the answers are the ones
// the lab measured.

type commandLog struct {
	mu      sync.Mutex
	calls   []string
	answers map[string]string
	errs    map[string]error
}

func (l *commandLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

// stubCommands replaces runCommand: each call is logged as "name arg arg" and
// answered from the map (keyed by the same text), or fails when errs has the key.
func stubCommands(t *testing.T, answers map[string]string, errs map[string]error) *commandLog {
	t.Helper()
	l := &commandLog{answers: answers, errs: errs}
	saved := runCommand
	t.Cleanup(func() { runCommand = saved })
	runCommand = func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		l.mu.Lock()
		l.calls = append(l.calls, key)
		l.mu.Unlock()
		if err := l.errs[key]; err != nil {
			return "", err
		}
		return l.answers[key], nil
	}
	return l
}

func apiDevice(t *testing.T, handler http.HandlerFunc) *SystemDevice {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &SystemDevice{client: opnapi.NewClient(server.URL, "k", "s", true)}
}

// --- HA ---------------------------------------------------------------------------------

func TestSystemDevice_HAMemberReadsTheThreeSignals(t *testing.T) {
	const (
		quietVIPs = `{"total":1,"rows":[{"mode":"ipalias","vhid":"","password":"SECRET"}]}`
		carpVIPs  = `{"total":1,"rows":[{"mode":"carp","vhid":"199","password":"SECRET"}]}`
		quietHA   = `{"hasync":{"pfsyncinterface":{"":{"value":"None","selected":1}},"synchronizetoip":"","password":"SECRET"}}`
	)
	for name, tc := range map[string]struct {
		vips, hasync string
		want         bool
		wantHAAsked  bool
	}{
		"nothing configured":        {quietVIPs, quietHA, false, true},
		"a CARP virtual IP":         {carpVIPs, quietHA, true, false},
		"a pfsync interface":        {quietVIPs, `{"hasync":{"pfsyncinterface":"lan","synchronizetoip":""}}`, true, true},
		"a sync address":            {quietVIPs, `{"hasync":{"pfsyncinterface":"","synchronizetoip":"192.168.3.2"}}`, true, true},
		"no virtual IP at all":      {`{"total":0,"rows":[]}`, quietHA, false, true},
		"a vhid on an alias":        {`{"total":1,"rows":[{"mode":"ipalias","vhid":"5"}]}`, quietHA, true, false},
		"a numeric vhid on a proxy": {`{"total":1,"rows":[{"mode":"proxyarp","vhid":3}]}`, quietHA, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			asked := false
			d := apiDevice(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/interfaces/vip_settings/searchItem":
					_, _ = io.WriteString(w, tc.vips)
				case "/core/hasync/get":
					asked = true
					_, _ = io.WriteString(w, tc.hasync)
				default:
					t.Errorf("unexpected %s", r.URL.Path)
				}
			})
			got, err := d.HAMember(context.Background())
			if err != nil || got != tc.want {
				t.Fatalf("member %v (%v), want %v", got, err, tc.want)
			}
			if asked != tc.wantHAAsked {
				t.Errorf("hasync asked: %v, want %v", asked, tc.wantHAAsked)
			}
		})
	}
}

func TestSystemDevice_HAMemberFailsWhenEitherReadFailsAndNamesNoBody(t *testing.T) {
	const secret = "SECRET-IN-A-BODY"
	for name, failing := range map[string]string{
		"the virtual IPs": "/interfaces/vip_settings/searchItem",
		"hasync":          "/core/hasync/get",
	} {
		t.Run(name, func(t *testing.T) {
			d := apiDevice(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == failing {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, secret)
					return
				}
				_, _ = io.WriteString(w, `{"total":0,"rows":[]}`)
			})
			_, err := d.HAMember(context.Background())
			if err == nil {
				t.Fatal("an unreadable signal was taken for no HA")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error quotes the body of the answer: %v", err)
			}
		})
	}
}

// --- the repositories and packages --------------------------------------------------------

func TestSystemDevice_RepoAuditNamesWhatIsFromOutsideAndNeverHoldsOnIt(t *testing.T) {
	dir := t.TempDir()
	saved := pkgReposDir
	t.Cleanup(func() { pkgReposDir = saved })
	pkgReposDir = dir
	files := map[string]string{
		"OPNsense.conf":     "OPNsense: { url: \"pkg+https://pkg.opnsense.org/${ABI}/26.1/latest\", enabled: yes }\n",
		"OPNsense-aux.conf": "OPNsense-aux: { url: \"x\", enabled: yes }\n",
		"NetDefense.conf":   "NetDefense: { url: \"x\", enabled: yes }\n",
		"FreeBSD.conf":      "FreeBSD: { enabled: no }\n",
		"Foreign.conf":      "Foreign: {\n  url: \"https://example.test/${ABI}\",\n  enabled: yes\n}\n",
		"Quiet.conf":        "Quiet: {\n  url: \"https://example.test\",\n  enabled: no\n}\n",
		"Implicit.conf":     "Implicit: { url: \"https://example.test\" }\n",
		"notes.txt":         "not a repository file",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := stubCommands(t, map[string]string{
		"/usr/sbin/pkg query %n %R": "curl OPNsense\nos-netdefense-dev NetDefense\nbase-tools FreeBSD\nfoo Foreign\nbar unknown-repository\nos-netdefense-dev-x unknown-repository\nmalformed line here\n",
	}, nil)

	audit, err := (&SystemDevice{}).RepoAudit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := append([]string(nil), audit.Repositories...); !reflect.DeepEqual(sorted(got), []string{"Foreign", "Implicit"}) {
		t.Errorf("repositories %v: an enabled file outside OPNsense and NetDefense is named, a disabled one and the generated ones are not", audit.Repositories)
	}
	if !reflect.DeepEqual(sorted(audit.Packages), []string{"bar", "foo"}) {
		t.Errorf("packages %v: the agent's own package is excepted, whatever repository it reads", audit.Packages)
	}
	if calls := l.list(); len(calls) != 1 {
		t.Errorf("commands %v", calls)
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestSystemDevice_RepoAuditOfAQuietBoxIsEmptyAndAFailedQueryIsAnError(t *testing.T) {
	dir := t.TempDir()
	saved := pkgReposDir
	t.Cleanup(func() { pkgReposDir = saved })
	pkgReposDir = dir
	stubCommands(t, map[string]string{"/usr/sbin/pkg query %n %R": "curl OPNsense\n"}, nil)
	audit, err := (&SystemDevice{}).RepoAudit(context.Background())
	if err != nil || len(audit.Repositories) != 0 || len(audit.Packages) != 0 {
		t.Fatalf("audit %+v (%v)", audit, err)
	}

	stubCommands(t, nil, map[string]error{"/usr/sbin/pkg query %n %R": errors.New("pkg: database is locked")})
	if _, err := (&SystemDevice{}).RepoAudit(context.Background()); err == nil {
		t.Error("a query that failed was taken for a clean box")
	}
}

// --- the free space ------------------------------------------------------------------------

func TestSystemDevice_DiskFreeSyncsThePoolBeforeItReadsAnything(t *testing.T) {
	cache := t.TempDir()
	savedDir, savedStatfs, savedDev := cacheDir, statfsFunc, statDev
	t.Cleanup(func() { cacheDir, statfsFunc, statDev = savedDir, savedStatfs, savedDev })
	cacheDir = cache

	const giB = int64(1 << 30)
	synced := false
	l := stubCommands(t, map[string]string{
		"/sbin/zfs get -Hp -o value available zroot":               "53687091200\n",
		"/sbin/zfs get -Hp -o value referenced zroot/ROOT/default": "1339559936\n",
		"/sbin/zpool sync zroot":                                   "",
	}, nil)
	base := runCommand
	runCommand = func(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
		out, err := base(ctx, timeout, name, args...)
		if name == "/sbin/zpool" {
			synced = true
		}
		return out, err
	}
	// ZFS gives back freed space in two steps: the figure read before the sync is the
	// stale one.
	statfsFunc = func(path string) (fsInfo, error) {
		switch path {
		case cache:
			if synced {
				return fsInfo{Avail: 5 * giB, Type: "zfs", From: "zroot/var/cache"}, nil
			}
			return fsInfo{Avail: 1 * giB, Type: "zfs", From: "zroot/var/cache"}, nil
		case "/":
			return fsInfo{Avail: 20 * giB, Type: "zfs", From: "zroot/ROOT/default"}, nil
		}
		return fsInfo{}, errors.New("unexpected " + path)
	}
	statDev = func(path string) (uint64, error) {
		if path == "/" {
			return 1, nil
		}
		return 2, nil // a dataset of its own
	}

	disk, err := (&SystemDevice{}).DiskFree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := Disk{
		CacheFree: 5 * giB, RootFree: 20 * giB, SplitRoot: true, ZFS: true, Pool: "zroot", PoolFree: 53687091200,
		BootDataset: "zroot/ROOT/default", BootCost: 1339559936,
	}
	if disk != want {
		t.Fatalf("disk %+v, want %+v: every figure is read after the pool was synced", disk, want)
	}
	calls := l.list()
	if len(calls) == 0 || calls[0] != "/sbin/zpool sync zroot" {
		t.Errorf("commands %v: the sync comes first", calls)
	}
}

func TestSystemDevice_DiskFreeOnUFSRunsNoZFSCommandAndKnowsASingleFilesystem(t *testing.T) {
	cache := t.TempDir()
	savedDir, savedStatfs, savedDev := cacheDir, statfsFunc, statDev
	t.Cleanup(func() { cacheDir, statfsFunc, statDev = savedDir, savedStatfs, savedDev })
	cacheDir = cache
	l := stubCommands(t, nil, nil)
	statfsFunc = func(path string) (fsInfo, error) {
		return fsInfo{Avail: 7 << 30, Type: "ufs", From: "/dev/da0p2"}, nil
	}
	statDev = func(string) (uint64, error) { return 7, nil }

	disk, err := (&SystemDevice{}).DiskFree(context.Background())
	if err != nil || disk.ZFS || disk.SplitRoot || disk.CacheFree != 7<<30 || disk.RootFree != 7<<30 || disk.Pool != "" {
		t.Fatalf("disk %+v (%v)", disk, err)
	}
	if calls := l.list(); len(calls) != 0 {
		t.Errorf("commands %v: a UFS box needs no pool", calls)
	}
}

func TestSystemDevice_DiskFreeFailsRatherThanGuess(t *testing.T) {
	cache := t.TempDir()
	savedDir, savedStatfs, savedDev := cacheDir, statfsFunc, statDev
	t.Cleanup(func() { cacheDir, statfsFunc, statDev = savedDir, savedStatfs, savedDev })
	cacheDir = cache
	zfs := func(path string) (fsInfo, error) {
		return fsInfo{Avail: 9 << 30, Type: "zfs", From: "zroot/ROOT/default"}, nil
	}
	statDev = func(string) (uint64, error) { return 1, nil }

	for name, tc := range map[string]struct {
		statfs func(string) (fsInfo, error)
		errs   map[string]error
		out    map[string]string
	}{
		"the filesystem cannot be read": {statfs: func(string) (fsInfo, error) { return fsInfo{}, errors.New("statfs failed") }},
		"the pool cannot be synced":     {statfs: zfs, errs: map[string]error{"/sbin/zpool sync zroot": errors.New("zpool: no such pool")}},
		"the pool's free space is not a number": {statfs: zfs, out: map[string]string{
			"/sbin/zfs get -Hp -o value available zroot": "lots\n"}},
		"the pool's free space cannot be read": {statfs: zfs, errs: map[string]error{"/sbin/zfs get -Hp -o value available zroot": errors.New("zfs: failed")}},
		"the boot dataset's size is negative": {statfs: zfs, out: map[string]string{
			"/sbin/zfs get -Hp -o value available zroot":               "100\n",
			"/sbin/zfs get -Hp -o value referenced zroot/ROOT/default": "-4\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			statfsFunc = tc.statfs
			stubCommands(t, tc.out, tc.errs)
			if disk, err := (&SystemDevice{}).DiskFree(context.Background()); err == nil {
				t.Fatalf("disk %+v: a figure that could not be read was taken for one", disk)
			}
		})
	}
}

// --- the commands that clean and refresh ------------------------------------------------

func TestSystemDevice_TheCleanupAndTheRefreshAreTheCommandsOfTheDesign(t *testing.T) {
	l := stubCommands(t, nil, nil)
	d := &SystemDevice{}
	ctx := context.Background()
	if err := d.ClearStaleWork(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearUpgradeCache(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.RefreshCatalog(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/local/sbin/opnsense-update -es",
		"/usr/local/sbin/opnsense-update -es",
		"/usr/sbin/pkg update -f -r OPNsense",
	}
	if got := l.list(); !equal(got, want) {
		t.Errorf("commands %v, want %v", got, want)
	}

	stubCommands(t, nil, map[string]error{"/usr/local/sbin/opnsense-update -es": errors.New("exit status 1")})
	if err := d.ClearUpgradeCache(ctx); err == nil {
		t.Error("a cleanup that failed was taken for one that worked")
	}
}

// --- the NetDefense repository ---------------------------------------------------------------

func TestSystemDevice_AgentRepoProbeAsksTheTargetABIsTree(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "NetDefense.conf")
	savedConf, savedFetch := agentRepoConf, fetchFunc
	t.Cleanup(func() { agentRepoConf, fetchFunc = savedConf, savedFetch })
	agentRepoConf = conf

	var mu sync.Mutex
	var asked []string
	answer := func(code int, output string, err error) {
		mu.Lock()
		asked = nil
		mu.Unlock()
		fetchFunc = func(_ context.Context, url string) (int, string, error) {
			mu.Lock()
			asked = append(asked, url)
			mu.Unlock()
			return code, output, err
		}
	}
	write := func(body string) {
		if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const nested = "NetDefense: {\n  url: \"pkg+https://repo.netdefense.io/prod/opnsense/${ABI}\",\n  enabled: yes\n}\n"

	t.Run("a tree under the target ABI", func(t *testing.T) {
		write(nested)
		answer(0, "", nil)
		got, err := (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64")
		if err != nil || got != (AgentRepo{Nested: true, Tree: true}) {
			t.Fatalf("got %+v (%v)", got, err)
		}
		want := []string{
			"https://repo.netdefense.io/prod/opnsense/FreeBSD:15:amd64/meta.conf",
			"https://repo.netdefense.io/prod/opnsense/FreeBSD:15:amd64/packagesite.pkg",
		}
		if !equal(asked, want) {
			t.Errorf("asked %v, want %v", asked, want)
		}
	})
	t.Run("no tree under the target ABI", func(t *testing.T) {
		write(nested)
		answer(1, "fetch: https://repo.netdefense.io/prod/opnsense/FreeBSD:15:amd64/meta.conf: Not Found", nil)
		got, err := (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64")
		if err != nil || !got.Nested || got.Tree || got.Why == "" {
			t.Fatalf("got %+v (%v)", got, err)
		}
	})
	t.Run("the host cannot be reached", func(t *testing.T) {
		write(nested)
		answer(1, "fetch: Unknown host", nil)
		got, err := (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64")
		if err != nil || !got.Nested || got.Tree {
			t.Fatalf("got %+v (%v)", got, err)
		}
		answer(0, "", errors.New("exec: no such file"))
		if got, err = (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64"); err != nil || got.Tree {
			t.Fatalf("got %+v (%v)", got, err)
		}
	})
	t.Run("a flat url", func(t *testing.T) {
		write("NetDefense: {\n  url: \"pkg+https://repo.netdefense.io/prod/opnsense/FreeBSD:14:amd64\",\n}\n")
		answer(0, "", nil)
		got, err := (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64")
		if err != nil || got.Nested || got.Tree || got.Why == "" {
			t.Fatalf("got %+v (%v)", got, err)
		}
		if len(asked) != 0 {
			t.Errorf("asked %v: a flat url is refused before anything is fetched", asked)
		}
	})
	t.Run("no repository file", func(t *testing.T) {
		_ = os.Remove(conf)
		answer(0, "", nil)
		got, err := (&SystemDevice{}).AgentRepoProbe(context.Background(), "FreeBSD:15:amd64")
		if err != nil || got.Nested || got.Tree {
			t.Fatalf("got %+v (%v)", got, err)
		}
	})
}

// --- the state the stages leave ------------------------------------------------------------------

func TestReadStageState_ReadsTheMarkersTheSetsTheKernelsAndTheLogs(t *testing.T) {
	cache := t.TempDir()
	savedDir, savedVersion := cacheDir, setVersionFunc
	t.Cleanup(func() { cacheDir, setVersionFunc = savedDir, savedVersion })
	cacheDir = cache
	versions := map[string]string{"base": "26.1.11", "kernel": "26.1.11", "pkgs": "26.1.6_2"}
	setVersionFunc = func(_ context.Context, which string) (string, error) {
		if v, ok := versions[which]; ok {
			return v, nil
		}
		return "", errors.New("no such set")
	}
	stubCommands(t, map[string]string{
		"/usr/bin/uname -r":       "14.3-RELEASE-p16\n",
		"/bin/freebsd-version -u": "14.3-RELEASE-p16\n",
	}, nil)
	ctx := context.Background()

	// A quiet box.
	st, err := readStageState(ctx, "26.1.11_10")
	if err != nil {
		t.Fatal(err)
	}
	want := StageState{
		Core: "26.1.11_10", Base: "26.1.11", Kernel: "26.1.11", Pkgs: "26.1.6_2", SetsPendingEmpty: true,
		RunningKernel: "14.3-RELEASE-p16", Userland: "14.3-RELEASE-p16",
	}
	if !reflect.DeepEqual(st, want) {
		t.Fatalf("a quiet box: %+v, want %+v", st, want)
	}

	// An upgrade staged: two markers, the extracted sets, both logs.
	for _, name := range []string{".kernel.pending", ".pkgs.pending"} {
		if err := os.WriteFile(filepath.Join(cache, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(cache, ".sets.pending", "packages-26.7"), 0o755); err != nil {
		t.Fatal(err)
	}
	logTime := time.Date(2026, 10, 12, 11, 0, 0, 0, time.UTC)
	for name, text := range map[string]string{".update.log": "Disc quota exceeded\n", ".upgrade.log": ""} {
		path := filepath.Join(cache, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, logTime, logTime); err != nil {
			t.Fatal(err)
		}
	}
	st, err = readStageState(ctx, "26.1.11_10")
	if err != nil {
		t.Fatal(err)
	}
	if st.Markers != (Markers{Kernel: true, Pkgs: true}) || !st.Markers.Any() || st.SetsPendingEmpty {
		t.Errorf("markers %+v sets-empty %v", st.Markers, st.SetsPendingEmpty)
	}
	if !st.UpdateLog.Exists || st.UpdateLog.Text != "Disc quota exceeded\n" || !st.UpdateLog.ModTime.Equal(logTime) {
		t.Errorf("update log %+v", st.UpdateLog)
	}
	if !st.UpgradeLog.Exists || st.UpgradeLog.Text != "" {
		t.Errorf("an empty log is still a log that exists: %+v", st.UpgradeLog)
	}

	// Anything that cannot be read is an error, not a guess.
	versions["pkgs"] = ""
	delete(versions, "pkgs")
	if _, err := readStageState(ctx, "26.1.11_10"); err == nil {
		t.Error("a set version that could not be read was taken for a state")
	}
	versions["pkgs"] = "26.1.6_2"
	stubCommands(t, nil, map[string]error{"/usr/bin/uname -r": errors.New("uname failed")})
	if _, err := readStageState(ctx, "26.1.11_10"); err == nil {
		t.Error("a running kernel that could not be read was taken for a state")
	}
}

func TestReadLogFile_IsBoundedToItsTailAndAMissingFileIsNoLog(t *testing.T) {
	dir := t.TempDir()
	saved := logReadMaxBytes
	t.Cleanup(func() { logReadMaxBytes = saved })
	logReadMaxBytes = 16
	path := filepath.Join(dir, ".update.log")
	if err := os.WriteFile(path, []byte("0123456789abcdefghijklmnopqrstuvwxyz"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readLogFile(path)
	if !got.Exists || got.Text != "klmnopqrstuvwxyz" {
		t.Errorf("log %+v: the tail of a log is what is read", got)
	}
	if got := readLogFile(filepath.Join(dir, "absent")); got.Exists || got.Text != "" || !got.ModTime.IsZero() {
		t.Errorf("a missing file: %+v", got)
	}
}

// --- the request and the boot environments --------------------------------------------------

func TestSystemDevice_TriggerUpgradeIsAPostToTheUpgradeEndpointAndAnswersItsStatus(t *testing.T) {
	var method, path string
	d := apiDevice(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		_, _ = io.WriteString(w, `{"status":"ok","msg_uuid":"abc"}`)
	})
	got, err := d.TriggerUpgrade(context.Background())
	if err != nil || got != "ok" || method != http.MethodPost || path != "/core/firmware/upgrade" {
		t.Fatalf("answer %q (%v) from %s %s", got, err, method, path)
	}

	d = apiDevice(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if _, err := d.TriggerUpgrade(context.Background()); err == nil {
		t.Error("a request the API refused was taken for one that was made")
	}
}

func TestSystemDevice_BootEnvironments(t *testing.T) {
	d := apiDevice(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/core/snapshots/isSupported":
			_, _ = io.WriteString(w, `{"supported":true}`)
		case "/core/snapshots/search":
			_, _ = io.WriteString(w, `{"total":2,"rows":[{"uuid":"33ab88e4","name":"default","active":"NR"},{"uuid":"6f50742b","name":"ndagent-pre-26.7","active":"-"}]}`)
		case "/core/snapshots/add":
			_, _ = io.WriteString(w, `{"status":"failed","errors":"A snapshot already exists by this name"}`)
		}
	})
	ctx := context.Background()
	if ok, err := d.SnapshotSupported(ctx); err != nil || !ok {
		t.Errorf("supported: %v (%v)", ok, err)
	}
	be, found, err := d.FindBootEnvironment(ctx, "ndagent-pre-26.7")
	if err != nil || !found || be.UUID != "6f50742b" || be.Active != "-" {
		t.Errorf("found %+v %v (%v)", be, found, err)
	}
	if _, found, err := d.FindBootEnvironment(ctx, "ndagent-pre-26.7-2"); err != nil || found {
		t.Errorf("a name that is not there: %v (%v)", found, err)
	}
	if err := d.CreateBootEnvironment(ctx, "ndagent-pre-26.7", "x"); !errors.Is(err, ErrBootEnvironmentExists) {
		t.Errorf("a taken name: %v", err)
	}
}

func TestRepositoryEnabled_ReadsTheFlagWhereverTheFilePutsIt(t *testing.T) {
	for name, tc := range map[string]struct {
		conf string
		want bool
	}{
		"OPNsense's one-line FreeBSD.conf":    {"FreeBSD: { enabled: no }\n", false},
		"a flag on a line of its own":         {"Foreign: {\n  url: \"https://x/y\",\n  enabled: no\n}\n", false},
		"yes on a line of its own":            {"Foreign: {\n  url: \"https://x/y\",\n  enabled: yes\n}\n", true},
		"inline, after the url":               {"Foreign: { url: \"https://x/y\", enabled: yes }\n", true},
		"inline and disabled, after the url":  {"Foreign: { url: \"https://x/y\", enabled: no }\n", false},
		"an equals sign and a semicolon":      {"Foreign: {\n  enabled = false;\n}\n", false},
		"quoted keys and values":              {"Foreign: {\n  \"enabled\": \"no\",\n}\n", false},
		"upper case":                          {"Foreign: {\n  enabled: NO\n}\n", false},
		"no flag: a repository is enabled":    {"Foreign: {\n  url: \"https://x/y\"\n}\n", true},
		"a commented flag is no flag":         {"Foreign: {\n  # enabled: no\n  url: \"https://x/y\"\n}\n", true},
		"a trailing comment after the flag":   {"Foreign: {\n  enabled: no # off for now\n}\n", false},
		"a url that holds a hash and no flag": {"Foreign: { url: \"https://x/y#enabled: no\" }\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := repositoryEnabled(tc.conf); got != tc.want {
				t.Errorf("enabled %v, want %v for %q", got, tc.want, tc.conf)
			}
		})
	}
}

// The state of the box is read through the real SetVersion: a box that never ran
// stage P has no packages marker, `opnsense-update -vp` prints an empty line, and
// that must not fail the read (it did, and every window then held
// held_check_failed at the first look at the markers). Base and kernel stay strict.
func TestReadStageState_ABoxWithNoPackagesMarkerIsReadAndOneWithNoBaseIsNot(t *testing.T) {
	cache := t.TempDir()
	savedDir := cacheDir
	t.Cleanup(func() { cacheDir = savedDir })
	cacheDir = cache
	stubCommands(t, map[string]string{
		"/usr/bin/uname -r":       "14.3-RELEASE-p16\n",
		"/bin/freebsd-version -u": "14.3-RELEASE-p16\n",
	}, nil)

	printed := map[string]string{"-vb": "26.1.11", "-vk": "26.1.11", "-vp": ""}
	restore := firmware.SetVersionCommandForTest(func(_ context.Context, flag string) (string, error) {
		return printed[flag], nil
	})
	t.Cleanup(restore)

	st, err := readStageState(context.Background(), "26.1.11_10")
	if err != nil {
		t.Fatalf("a box with no packages marker cannot be read: %v", err)
	}
	if st.Base != "26.1.11" || st.Kernel != "26.1.11" || st.Pkgs != "" {
		t.Errorf("state %+v", st)
	}

	printed["-vb"] = ""
	if _, err := readStageState(context.Background(), "26.1.11_10"); err == nil {
		t.Error("a box that printed no base version was read")
	}
	printed["-vb"], printed["-vk"] = "26.1.11", ""
	if _, err := readStageState(context.Background(), "26.1.11_10"); err == nil {
		t.Error("a box that printed no kernel version was read")
	}
}
