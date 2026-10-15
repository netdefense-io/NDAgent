package track

// device_major.go — what the box is asked beyond the firmware backend when a
// series upgrade is considered, started and settled: the HA signals, the
// repositories and packages it holds, its free space and boot environments, the
// state the three stages leave on disk, and the commands that start and clean up
// the upgrade. The types are the answers; SystemDevice reads the real box and the
// simulator of the tests stands a small one in its place.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/netdefense-io/ndagent/internal/firmware"
	"github.com/netdefense-io/ndagent/internal/opnapi"
	"github.com/netdefense-io/ndagent/internal/util"
)

// ErrBootEnvironmentExists is CreateBootEnvironment's answer for a name that is
// taken; the caller tries the next one.
var ErrBootEnvironmentExists = opnapi.ErrBootEnvironmentExists

// BootEnvironment is a ZFS boot environment as the snapshots API lists it.
type BootEnvironment = opnapi.BootEnvironment

// RepoAudit is what the box holds from outside OPNsense and NetDefense. The names
// stay in the agent's log and progress text: the contract carries two tokens and
// never a name.
type RepoAudit struct {
	// Repositories are the enabled repository files other than OPNsense,
	// OPNsense-aux and NetDefense (and FreeBSD, which OPNsense ships disabled).
	Repositories []string
	// Packages are the installed packages whose repository is outside that set, the
	// agent's own package excepted.
	Packages []string
}

// Disk is the box's free space as a series upgrade needs it read: on the
// filesystem that holds the upgrade's work (/var/cache/opnsense-update), on /, and
// on ZFS the pool's and the boot dataset's. On ZFS every figure is read after a
// `zpool sync`, because ZFS gives back freed space in two steps, part at once and
// the rest at the next transaction-group commit (51 to 61 seconds later in the lab).
type Disk struct {
	// CacheFree and RootFree are the bytes available on the filesystem of the cache
	// and on /. SplitRoot says they are two filesystems.
	CacheFree int64
	RootFree  int64
	SplitRoot bool
	// ZFS says the cache is on a ZFS dataset; Pool is its pool and PoolFree the
	// pool's available bytes (`zfs get available <pool>`: a dataset's refquota does
	// not show the cost of a boot environment, the pool does).
	ZFS      bool
	Pool     string
	PoolFree int64
	// BootDataset is the dataset mounted at / and BootCost its referenced bytes
	// (`zfs get referenced`), read on each box before the upgrade: what a boot
	// environment can cost at most, by ZFS construction.
	BootDataset string
	BootCost    int64
}

// AgentRepo is the NetDefense repository as the box's own file sees it.
type AgentRepo struct {
	// Nested says the repository file's url carries pkg's ${ABI}: the layout that
	// follows the ABI the box runs, which a flat url does not.
	Nested bool
	// Tree says meta.conf and packagesite.pkg answer under the target ABI.
	Tree bool
	// Why is for the log: which of the two failed and how.
	Why string
}

// Markers are the pending markers the stages of an upgrade leave in
// /var/cache/opnsense-update.
type Markers struct {
	Kernel bool
	Base   bool
	Pkgs   bool
}

// Any reports whether a stage is still waiting for a reboot.
func (m Markers) Any() bool { return m.Kernel || m.Base || m.Pkgs }

// LogFile is a log the upgrade scripts leave on disk, read once and whole (to a
// bound) before anything cleans the directory.
type LogFile struct {
	Exists  bool
	ModTime time.Time
	Text    string
}

// StageState is what a series upgrade has left on the box, read only. After the
// landing it says every set is at the new series; after an abort it says nothing
// changed; after a stage that ended short it says which.
type StageState struct {
	// Core is the installed core release; Base, Kernel and Pkgs what `opnsense-update
	// -vb`, `-vk` and `-vp` read (the pkgs marker is written only when stage P's pkg
	// upgrade succeeded, not by its exit code).
	Core   string
	Base   string
	Kernel string
	Pkgs   string
	// Markers are the three pending markers; SetsPendingEmpty says
	// .sets.pending holds nothing (an absent directory is empty).
	Markers          Markers
	SetsPendingEmpty bool
	// RunningKernel is `uname -r` and Userland `freebsd-version -u`: they agree
	// once the base is whole.
	RunningKernel string
	Userland      string
	// UpdateLog and UpgradeLog are .update.log and .upgrade.log. Their presence
	// decides nothing: the 25.7 landing of the same-ABI lab left no .update.log.
	UpdateLog  LogFile
	UpgradeLog LogFile
}

// --- what SystemDevice reads and runs ------------------------------------------------

// The places and commands, as variables so that tests do not touch the box.
var (
	cacheDir        = "/var/cache/opnsense-update"
	pkgReposDir     = "/usr/local/etc/pkg/repos"
	agentRepoConf   = pkgReposDir + "/NetDefense.conf"
	logReadMaxBytes = int64(4 << 20)

	// runCommand runs a command to its end with the device's PATH and returns its
	// standard output; a non-zero exit is an *exec.ExitError carrying the tail of
	// what it printed.
	runCommand = func(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = util.DeviceExecEnv()
		cmd.WaitDelay = 2 * time.Second
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return stdout.String(), fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, firstLine(tailLines(stderr.String(), 3)))
		}
		return stdout.String(), nil
	}

	// statfsFunc reads a filesystem; statDev the device number of a path.
	statfsFunc = statfs
	statDev    = func(path string) (uint64, error) {
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, errors.New("no device number")
		}
		return uint64(st.Dev), nil
	}
)

// fsInfo is what statfs says about the filesystem a path is on.
type fsInfo struct {
	Avail int64
	Type  string
	From  string
}

const (
	commandTimeout   = 2 * time.Minute
	fastCommandLimit = 30 * time.Second
)

// HAMember reports whether the box is a member of an HA pair, from three
// configuration signals (a saved value counts whether or not it was applied, which
// errs toward the hold): a CARP virtual IP, a pfsync interface, a sync address. The
// reads decode into structs that have no place for the passwords the answers
// carry, and no error quotes a body.
func (d *SystemDevice) HAMember(ctx context.Context) (bool, error) {
	vips, err := d.client.GetVIPList(ctx)
	if err != nil {
		return false, err
	}
	for _, row := range vips.Rows {
		if row.IsCARP() {
			return true, nil
		}
	}
	ha, err := d.client.GetHASync(ctx)
	if err != nil {
		return false, err
	}
	return ha.PfsyncInterface != "" || ha.SynchronizeToIP != "", nil
}

var (
	// repoEnabledRE reads the enabled flag wherever a repository file puts it: on a
	// line of its own, or inline as in OPNsense's one-line FreeBSD.conf
	// (`FreeBSD: { enabled: no }`).
	// repoCommentRE drops a `#` comment, from the `#` to the end of the line; a `#`
	// inside a url is not preceded by white space.
	repoCommentRE = regexp.MustCompile(`(?m)(^|\s)#.*$`)
	repoEnabledRE = regexp.MustCompile(`(?im)(?:^|[\s{;,])"?enabled"?\s*[:=]\s*"?(yes|true|on|1|no|false|off|0)"?\s*(?:[;,}]|$)`)
	// thirdPartyOK are the repositories OPNsense generates and the agent's own.
	thirdPartyOK = []string{"OPNsense", "OPNsense-aux", "NetDefense"}
	// packageRepoOK are the repositories a package may report with no remark; FreeBSD
	// is in the set because OPNsense ships that repository, disabled.
	packageRepoOK = []string{"OPNsense", "OPNsense-aux", "NetDefense", "FreeBSD"}
)

// RepoAudit lists what the box holds from outside OPNsense and NetDefense: the
// repository files of /usr/local/etc/pkg/repos that are enabled and are not the
// generated ones, and the installed packages whose `pkg query %R` is outside the
// same set. The REST check sees neither (it reads OPNsense's repositories and
// reports connection ok, repository ok with a foreign one present), and a catalog
// directory a removed repository left behind is no signal.
func (d *SystemDevice) RepoAudit(ctx context.Context) (RepoAudit, error) {
	var audit RepoAudit
	files, err := filepath.Glob(filepath.Join(pkgReposDir, "*.conf"))
	if err != nil {
		return RepoAudit{}, err
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".conf")
		raw, err := os.ReadFile(file)
		if err != nil {
			return RepoAudit{}, fmt.Errorf("read a repository file: %w", err)
		}
		if !repositoryEnabled(string(raw)) {
			continue
		}
		if !contains(thirdPartyOK, name) {
			audit.Repositories = append(audit.Repositories, name)
		}
	}
	out, err := runCommand(ctx, commandTimeout, "/usr/sbin/pkg", "query", "%n %R")
	if err != nil {
		return RepoAudit{}, err
	}
	audit.Packages = foreignPackages(out)
	return audit, nil
}

// repositoryEnabled reads the enabled flag of a repository file: a repository is
// enabled unless the file says otherwise (pkg's default).
func repositoryEnabled(conf string) bool {
	conf = repoCommentRE.ReplaceAllString(conf, "$1")
	if m := repoEnabledRE.FindStringSubmatch(conf); m != nil {
		switch strings.ToLower(m[1]) {
		case "no", "false", "off", "0":
			return false
		}
	}
	return true
}

// foreignPackages reads the output of `pkg query "%n %R"` and returns the names of
// the packages that come from outside the repositories OPNsense and NetDefense
// generate: a package installed from a file reads "unknown-repository", one from a
// repository of its own reads that repository's name. The agent's own package,
// whatever it reads, is not one.
func foreignPackages(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name, repo := fields[0], fields[1]
		if strings.HasPrefix(name, "os-netdefense") || contains(packageRepoOK, repo) {
			continue
		}
		names = append(names, name)
	}
	return names
}

// DiskFree reads the box's free space (see Disk). On ZFS it runs `zpool sync`
// first, every time, so that no figure it returns lags the last delete.
func (d *SystemDevice) DiskFree(ctx context.Context) (Disk, error) {
	var disk Disk
	cache := nearestExisting(cacheDir)
	before, err := statfsFunc(cache)
	if err != nil {
		return Disk{}, fmt.Errorf("read the free space of the cache: %w", err)
	}
	if before.Type == "zfs" {
		disk.ZFS = true
		disk.Pool = strings.SplitN(before.From, "/", 2)[0]
		if disk.Pool == "" {
			return Disk{}, errors.New("the cache is on ZFS and its pool is unknown")
		}
		if _, err := runCommand(ctx, commandTimeout, "/sbin/zpool", "sync", disk.Pool); err != nil {
			return Disk{}, fmt.Errorf("sync the pool before reading its free space: %w", err)
		}
	}
	// Read after the sync.
	after, err := statfsFunc(cache)
	if err != nil {
		return Disk{}, fmt.Errorf("read the free space of the cache: %w", err)
	}
	disk.CacheFree = after.Avail

	root, err := statfsFunc("/")
	if err != nil {
		return Disk{}, fmt.Errorf("read the free space of /: %w", err)
	}
	disk.RootFree = root.Avail
	cacheDev, cerr := statDev(cache)
	rootDev, rerr := statDev("/")
	disk.SplitRoot = cerr == nil && rerr == nil && cacheDev != rootDev

	if disk.ZFS {
		if disk.PoolFree, err = zfsBytes(ctx, "available", disk.Pool); err != nil {
			return Disk{}, err
		}
		if root.Type == "zfs" && root.From != "" {
			disk.BootDataset = root.From
			if disk.BootCost, err = zfsBytes(ctx, "referenced", root.From); err != nil {
				return Disk{}, err
			}
		}
	}
	return disk, nil
}

// zfsBytes reads one property of a pool or dataset in bytes.
func zfsBytes(ctx context.Context, property, name string) (int64, error) {
	out, err := runCommand(ctx, fastCommandLimit, "/sbin/zfs", "get", "-Hp", "-o", "value", property, name)
	if err != nil {
		return 0, fmt.Errorf("read %s of %s: %w", property, name, err)
	}
	n, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if perr != nil || n < 0 {
		return 0, fmt.Errorf("read %s of %s: not a number of bytes", property, name)
	}
	return n, nil
}

// nearestExisting is path, or its closest parent that exists: the cache directory
// is made by opnsense-update the first time it runs.
func nearestExisting(path string) string {
	for path != "/" && path != "." && path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		path = filepath.Dir(path)
	}
	return "/"
}

// RefreshCatalog refreshes the catalog of OPNsense's repository alone, through the
// exec path: `pkg update -f -r OPNsense`. Unlike the REST check it reads no other
// repository, so one that is dead does not fail it.
func (d *SystemDevice) RefreshCatalog(ctx context.Context) error {
	_, err := runCommand(ctx, commandTimeout, "/usr/sbin/pkg", "update", "-f", "-r", "OPNsense")
	return err
}

// ClearStaleWork empties /var/cache/opnsense-update with `opnsense-update -es`
// before the free space is measured: the numbered work directory of an aborted
// stage 0, a partial .sets.pending and the old logs. The caller has checked what
// makes that safe (no job running, no marker, no operation of the agent's in
// flight), because the command removes the markers too.
func (d *SystemDevice) ClearStaleWork(ctx context.Context) error { return clearUpgradeCache(ctx) }

// ClearUpgradeCache is the cleanup that follows an aborted upgrade, after every log
// has been read: `opnsense-update -es` empties the whole directory, the logs
// included, and a leftover .pkgs.pending would make the next reboot of any kind run
// stage P over the old base.
func (d *SystemDevice) ClearUpgradeCache(ctx context.Context) error { return clearUpgradeCache(ctx) }

func clearUpgradeCache(ctx context.Context) error {
	_, err := runCommand(ctx, commandTimeout, "/usr/local/sbin/opnsense-update", "-es")
	return err
}

var abiSeriesRE = regexp.MustCompile(`\{?\$\{ABI\}?`)

// AgentRepoProbe checks the NetDefense repository for the ABI the box is moving
// to: the repository file's url must carry ${ABI} (the nested layout the plugin
// writes; the pre-nesting flat url keeps fetching the old ABI's build after the
// hop and fails every check with pkg's "wrong architecture"), and meta.conf and
// packagesite.pkg must answer under the target ABI. A box with no such file is not
// nested either.
func (d *SystemDevice) AgentRepoProbe(ctx context.Context, abi string) (AgentRepo, error) {
	raw, err := os.ReadFile(agentRepoConf)
	if err != nil {
		return AgentRepo{Why: "the NetDefense repository file cannot be read"}, nil
	}
	m := repoURLRE.FindStringSubmatch(string(raw))
	if m == nil {
		return AgentRepo{Why: "the NetDefense repository file has no url"}, nil
	}
	rawURL := strings.TrimPrefix(m[1], "pkg+")
	if !strings.Contains(rawURL, "${ABI}") {
		return AgentRepo{Why: "the NetDefense repository url is not laid out per ABI"}, nil
	}
	base := strings.TrimRight(strings.ReplaceAll(rawURL, "${ABI}", abi), "/")
	for _, leaf := range []string{"meta.conf", "packagesite.pkg"} {
		fctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		code, output, err := fetchFunc(fctx, base+"/"+leaf)
		cancel()
		switch {
		case ctx.Err() != nil:
			return AgentRepo{}, ctx.Err()
		case err != nil:
			return AgentRepo{Nested: true, Why: "the NetDefense repository cannot be reached"}, nil
		case code == 0:
		case fetchSaysNotFound(output):
			return AgentRepo{Nested: true, Why: "the NetDefense repository has no " + leaf + " under " + abi}, nil
		default:
			return AgentRepo{Nested: true, Why: "the NetDefense repository cannot be reached"}, nil
		}
	}
	return AgentRepo{Nested: true, Tree: true}, nil
}

// TriggerUpgrade asks OPNsense for the series upgrade: POST /core/firmware/upgrade.
// It answers the status OPNsense gave, which proves nothing: the launcher drops a
// request that finds its lock held while the API still says ok.
func (d *SystemDevice) TriggerUpgrade(ctx context.Context) (string, error) {
	resp, err := d.client.TriggerFirmwareUpgrade(ctx)
	if err != nil {
		return "", err
	}
	return resp.Status, nil
}

// setVersionFunc reads the version of one installed set (base, kernel, pkgs); a
// test replaces it.
var setVersionFunc = firmware.SetVersion

// StageState reads what the upgrade has left on the box. It only reads.
func (d *SystemDevice) StageState(ctx context.Context) (StageState, error) {
	core, err := d.Installed(ctx)
	if err != nil {
		return StageState{}, fmt.Errorf("read the installed release: %w", err)
	}
	return readStageState(ctx, core)
}

// readStageState is StageState for a core release already read.
func readStageState(ctx context.Context, core string) (StageState, error) {
	st := StageState{Core: core}
	var err error
	for _, set := range []struct {
		which string
		dst   *string
	}{{"base", &st.Base}, {"kernel", &st.Kernel}, {"pkgs", &st.Pkgs}} {
		if *set.dst, err = setVersionFunc(ctx, set.which); err != nil {
			return StageState{}, fmt.Errorf("read the %s version: %w", set.which, err)
		}
	}
	st.Markers = Markers{
		Kernel: fileExists(filepath.Join(cacheDir, ".kernel.pending")),
		Base:   fileExists(filepath.Join(cacheDir, ".base.pending")),
		Pkgs:   fileExists(filepath.Join(cacheDir, ".pkgs.pending")),
	}
	entries, rerr := os.ReadDir(filepath.Join(cacheDir, ".sets.pending"))
	switch {
	case rerr == nil:
		st.SetsPendingEmpty = len(entries) == 0
	case errors.Is(rerr, os.ErrNotExist):
		st.SetsPendingEmpty = true
	default:
		return StageState{}, fmt.Errorf("read the sets directory: %w", rerr)
	}
	out, err := runCommand(ctx, fastCommandLimit, "/usr/bin/uname", "-r")
	if err != nil {
		return StageState{}, err
	}
	st.RunningKernel = strings.TrimSpace(out)
	if out, err = runCommand(ctx, fastCommandLimit, "/bin/freebsd-version", "-u"); err != nil {
		return StageState{}, err
	}
	st.Userland = strings.TrimSpace(out)
	st.UpdateLog = readLogFile(filepath.Join(cacheDir, ".update.log"))
	st.UpgradeLog = readLogFile(filepath.Join(cacheDir, ".upgrade.log"))
	return st, nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readLogFile reads the tail of a log to a bound; a file that cannot be read is
// no log (and no evidence).
func readLogFile(path string) LogFile {
	f, err := os.Open(path)
	if err != nil {
		return LogFile{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return LogFile{}
	}
	if info.Size() > logReadMaxBytes {
		if _, err := f.Seek(-logReadMaxBytes, io.SeekEnd); err != nil {
			return LogFile{}
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, logReadMaxBytes))
	if err != nil {
		return LogFile{}
	}
	return LogFile{Exists: true, ModTime: info.ModTime(), Text: string(b)}
}

// SnapshotSupported reports whether the box can make boot environments (ZFS).
func (d *SystemDevice) SnapshotSupported(ctx context.Context) (bool, error) {
	return d.client.SnapshotsSupported(ctx)
}

// CreateBootEnvironment makes a boot environment through the snapshots API;
// ErrBootEnvironmentExists says the name is taken.
func (d *SystemDevice) CreateBootEnvironment(ctx context.Context, name, note string) error {
	return d.client.CreateBootEnvironment(ctx, name, note)
}

// FindBootEnvironment finds an environment by name in the API's listing. The
// answer to the add carries no uuid, so this is where the uuid comes from.
func (d *SystemDevice) FindBootEnvironment(ctx context.Context, name string) (BootEnvironment, bool, error) {
	list, err := d.client.ListBootEnvironments(ctx)
	if err != nil {
		return BootEnvironment{}, false, err
	}
	for _, be := range list {
		if be.Name == name {
			return be, true, nil
		}
	}
	return BootEnvironment{}, false, nil
}
