package track

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"
)

// The shared vectors are NDDataModels' (plugin/tests/fixtures/firmware-track/SOURCE.md
// says from where). The digests are literal on purpose: a change to a file is a
// decision, made in NDDataModels and in every copy together.
var vectorDigests = map[string]string{
	"dead-man.json":        "71041fe7855b77f17eebf4869dcb3d9d3815b48868a54d432686b516f5b8f171",
	"failure-details.json": "071b45bd86766f7a01a2ab4a5f35b418a73aff05a301b0c5fa7385a331237fdf",
	"payloads.json":        "e9c1abdc8130ac4bf8702d0fccddc9a5c9017bfd0bfdc43ba93d3bfedaf914db",
	"results.json":         "86251ac7784e0a4e40ca0059158152c0c8051e8e30ce138a0271dd44155cfc5d",
	"versions.json":        "f99fa1bcf27cdfceeff8af3f8c7b9ea7b3c9deff2c9119f73909f3d477020cb5",
}

const vectorDir = "testdata/firmware-track"

func readVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func loadVectors(t *testing.T, name string, dst interface{}) {
	t.Helper()
	if err := json.Unmarshal(readVectorFile(t, name), dst); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func TestVectorFilesAreTheSharedOnes(t *testing.T) {
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			onDisk = append(onDisk, e.Name())
		}
	}
	var pinned []string
	for name := range vectorDigests {
		pinned = append(pinned, name)
	}
	sort.Strings(onDisk)
	sort.Strings(pinned)
	if len(onDisk) != len(pinned) {
		t.Fatalf("the directory holds %v, the pins name %v", onDisk, pinned)
	}
	for i := range onDisk {
		if onDisk[i] != pinned[i] {
			t.Fatalf("the directory holds %v, the pins name %v", onDisk, pinned)
		}
	}
	for name, want := range vectorDigests {
		data := readVectorFile(t, name)
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s has sha256 %s, want the shared %s: copy the files from NDDataModels, never edit them", name, got, want)
		}
		for _, b := range data {
			if b > 0x7f {
				t.Errorf("%s is not plain ASCII", name)
				break
			}
		}
	}
}

// --- versions.json -------------------------------------------------------------

type versionVectors struct {
	SeriesPattern  string `json:"series_pattern"`
	VersionPattern string `json:"version_pattern"`
	SeriesOf       []struct {
		Version     string `json:"version"`
		Series      string `json:"series"`
		Description string `json:"description"`
	} `json:"series_of"`
	Ordering []struct {
		Description string   `json:"description"`
		Ascending   []string `json:"ascending"`
	} `json:"ordering"`
	Comparisons []struct {
		Installed   string `json:"installed"`
		Target      string `json:"target"`
		AtOrAbove   bool   `json:"at_or_above"`
		Description string `json:"description"`
	} `json:"comparisons"`
	Vectors []struct {
		Value       string `json:"value"`
		Series      bool   `json:"series"`
		Version     bool   `json:"version"`
		Description string `json:"description"`
	} `json:"vectors"`
	SeriesHops []struct {
		Source    string `json:"source"`
		Target    string `json:"target"`
		SourceABI string `json:"source_abi"`
		TargetABI string `json:"target_abi"`
	} `json:"series_hops"`
	HopTarget []struct {
		Series      string  `json:"series"`
		Target      *string `json:"target"`
		Description string  `json:"description"`
	} `json:"hop_target"`
	HopSource []struct {
		Series      string  `json:"series"`
		Source      *string `json:"source"`
		Description string  `json:"description"`
	} `json:"hop_source"`
	HopABIs []struct {
		Series      string    `json:"series"`
		ABIs        *[]string `json:"abis"`
		Description string    `json:"description"`
	} `json:"hop_abis"`
}

func TestVersionPatternsAreTheSharedOnes(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	if SeriesPattern != v.SeriesPattern {
		t.Errorf("series pattern %q, the vectors carry %q", SeriesPattern, v.SeriesPattern)
	}
	if VersionPattern != v.VersionPattern {
		t.Errorf("version pattern %q, the vectors carry %q", VersionPattern, v.VersionPattern)
	}
}

func TestVersionNamesAgreeWithEveryVector(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	if len(v.Vectors) < 40 {
		t.Fatalf("only %d version vectors were loaded", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		if got := ValidSeries(vec.Value); got != vec.Series {
			t.Errorf("%s (%q): ValidSeries = %v, want %v", vec.Description, vec.Value, got, vec.Series)
		}
		if got := ValidVersion(vec.Value); got != vec.Version {
			t.Errorf("%s (%q): ValidVersion = %v, want %v", vec.Description, vec.Value, got, vec.Version)
		}
	}
}

func TestSeriesOfAgreesWithEveryVector(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	for _, vec := range v.SeriesOf {
		got, ok := SeriesOf(vec.Version)
		if !ok || got != vec.Series {
			t.Errorf("%s: SeriesOf(%q) = %q, %v; want %q", vec.Description, vec.Version, got, ok, vec.Series)
		}
	}
	if _, ok := SeriesOf("26.7.x"); ok {
		t.Error("SeriesOf accepted a name that is not a release")
	}
}

func TestReleaseOrderingAgreesWithEveryVector(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	for _, vec := range v.Ordering {
		keys := make([]Key, len(vec.Ascending))
		for i, name := range vec.Ascending {
			k, ok := ParseKey(name)
			if !ok {
				t.Fatalf("%s: %q has no key", vec.Description, name)
			}
			keys[i] = k
		}
		for i := 1; i < len(keys); i++ {
			if keys[i-1].Compare(keys[i]) >= 0 {
				t.Errorf("%s: %q is not before %q", vec.Description, vec.Ascending[i-1], vec.Ascending[i])
			}
		}
		shuffled := append([]string(nil), vec.Ascending...)
		rand.New(rand.NewSource(7)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		sort.Slice(shuffled, func(i, j int) bool {
			a, _ := ParseKey(shuffled[i])
			b, _ := ParseKey(shuffled[j])
			return a.Compare(b) < 0
		})
		for i := range shuffled {
			if shuffled[i] != vec.Ascending[i] {
				t.Errorf("%s: sorted order %v, want %v", vec.Description, shuffled, vec.Ascending)
				break
			}
		}
	}
}

func TestInstalledAgainstTargetAgreesWithEveryVector(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	for _, vec := range v.Comparisons {
		got, ok := AtOrAbove(vec.Installed, vec.Target)
		if !ok || got != vec.AtOrAbove {
			t.Errorf("%s: AtOrAbove(%q, %q) = %v, %v; want %v", vec.Description, vec.Installed, vec.Target, got, ok, vec.AtOrAbove)
		}
	}
	if _, ok := AtOrAbove("26.7.x", "26.7.3"); ok {
		t.Error("AtOrAbove compared a name that is not a release")
	}
}

func TestStripHotfix(t *testing.T) {
	for in, want := range map[string]string{
		"26.7.3_11": "26.7.3", "26.7.3": "26.7.3", "26.7": "26.7", "26.7_1": "26.7", "24.7.12_4": "24.7.12",
	} {
		if got := StripHotfix(in); got != want {
			t.Errorf("StripHotfix(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- the supported series hops (versions.json) --------------------------------------

// The hop table is NDDataModels' (FIRMWARE_SERIES_HOPS) and the agent's copy is held
// to it the way the reasons are: row by row, in order, with both ABIs. A pair is
// added by a schema release after a lab run of that very hop, and this test is
// what makes the agent's copy follow it.
func TestSeriesHopsAreTheSharedOnes(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	if len(v.SeriesHops) == 0 {
		t.Fatal("the vectors carry no hop table")
	}
	got := Hops()
	if len(got) != len(v.SeriesHops) {
		t.Fatalf("the agent has %d hops, the vectors carry %d", len(got), len(v.SeriesHops))
	}
	abi := regexp.MustCompile(`\AFreeBSD:[0-9]{1,2}:[a-z][a-z0-9]*\z`)
	sources, targets := map[string]bool{}, map[string]bool{}
	for i, row := range v.SeriesHops {
		want := Hop{Source: row.Source, Target: row.Target, SourceABI: row.SourceABI, TargetABI: row.TargetABI}
		if got[i] != want {
			t.Errorf("hop %d: the agent has %+v, the vectors carry %+v", i, got[i], want)
		}
		if !ValidSeries(row.Source) || !ValidSeries(row.Target) || !abi.MatchString(row.SourceABI) || !abi.MatchString(row.TargetABI) {
			t.Errorf("hop %d is not well formed: %+v", i, row)
		}
		sk, _ := ParseKey(row.Source)
		tk, _ := ParseKey(row.Target)
		if tk.Compare(sk) <= 0 {
			t.Errorf("hop %d goes to a series that is not later: %+v", i, row)
		}
		// A chain, never a branch: a series is the source of at most one row and the
		// target of at most one.
		if sources[row.Source] || targets[row.Target] {
			t.Errorf("hop %d branches: %+v", i, row)
		}
		sources[row.Source], targets[row.Target] = true, true
	}
}

func TestHopHelpersAgreeWithEveryVector(t *testing.T) {
	var v versionVectors
	loadVectors(t, "versions.json", &v)
	if len(v.HopTarget) < 8 || len(v.HopSource) < 8 || len(v.HopABIs) < 8 {
		t.Fatalf("only %d, %d and %d hop vectors were loaded", len(v.HopTarget), len(v.HopSource), len(v.HopABIs))
	}
	for _, vec := range v.HopTarget {
		target, ok := HopTarget(vec.Series)
		switch {
		case vec.Target == nil && ok:
			t.Errorf("%s (%q): HopTarget answered %q, want none", vec.Description, vec.Series, target)
		case vec.Target != nil && (!ok || target != *vec.Target):
			t.Errorf("%s (%q): HopTarget = %q, %v; want %q", vec.Description, vec.Series, target, ok, *vec.Target)
		}
	}
	for _, vec := range v.HopSource {
		source, ok := HopSource(vec.Series)
		switch {
		case vec.Source == nil && ok:
			t.Errorf("%s (%q): HopSource answered %q, want none", vec.Description, vec.Series, source)
		case vec.Source != nil && (!ok || source != *vec.Source):
			t.Errorf("%s (%q): HopSource = %q, %v; want %q", vec.Description, vec.Series, source, ok, *vec.Source)
		}
	}
	for _, vec := range v.HopABIs {
		src, dst, ok := HopABIs(vec.Series)
		switch {
		case vec.ABIs == nil && ok:
			t.Errorf("%s (%q): HopABIs answered %q, %q, want none", vec.Description, vec.Series, src, dst)
		case vec.ABIs != nil && (!ok || len(*vec.ABIs) != 2 || src != (*vec.ABIs)[0] || dst != (*vec.ABIs)[1]):
			t.Errorf("%s (%q): HopABIs = %q, %q, %v; want %v", vec.Description, vec.Series, src, dst, ok, *vec.ABIs)
		}
	}
	// The row between two series is the row the helpers read, and only that one.
	for _, row := range v.SeriesHops {
		h, ok := HopBetween(row.Source, row.Target)
		if !ok || h.SourceABI != row.SourceABI || h.TargetABI != row.TargetABI {
			t.Errorf("HopBetween(%q, %q) = %+v, %v", row.Source, row.Target, h, ok)
		}
		if _, ok := HopBetween(row.Target, row.Source); ok {
			t.Errorf("HopBetween went backwards from %q to %q", row.Target, row.Source)
		}
	}
	if h := Hops()[0]; !h.ABIChanges() {
		t.Errorf("the one shipped hop changes its ABI: %+v", h)
	}
}

// --- dead-man.json -------------------------------------------------------------

func TestDeadManAgreesWithEveryVector(t *testing.T) {
	var v struct {
		Days    int    `json:"days"`
		Seconds int64  `json:"seconds"`
		Reason  string `json:"reason"`
		Vectors []struct {
			Description   string `json:"description"`
			SilentSeconds int64  `json:"silent_seconds"`
			Release       bool   `json:"release"`
		} `json:"vectors"`
	}
	loadVectors(t, "dead-man.json", &v)
	if v.Days != DeadManDays || v.Seconds != DeadManSeconds {
		t.Errorf("the figure is %d days / %d s, the vectors say %d / %d", DeadManDays, DeadManSeconds, v.Days, v.Seconds)
	}
	if v.Reason != "dead_man" {
		t.Errorf("the control plane's reason is %q in the vectors", v.Reason)
	}
	if len(v.Vectors) < 8 {
		t.Fatalf("only %d dead-man vectors were loaded", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		if got := DeadManDue(time.Duration(vec.SilentSeconds) * time.Second); got != vec.Release {
			t.Errorf("%s (%d s): DeadManDue = %v, want %v", vec.Description, vec.SilentSeconds, got, vec.Release)
		}
	}
	if ValidReason("dead_man") {
		t.Error("dead_man is the control plane's reason and must not be one an agent may give")
	}
}

// --- payloads.json -------------------------------------------------------------

type payloadVectors struct {
	Actions            []string `json:"actions"`
	Tracks             []string `json:"tracks"`
	ApprovedMaxEntries int      `json:"approved_max_entries"`
	Vectors            []struct {
		Description string          `json:"description"`
		Payload     json.RawMessage `json:"payload"`
		PayloadText *string         `json:"payload_text"`
		Valid       bool            `json:"valid"`
		Fault       string          `json:"fault"`
	} `json:"vectors"`
}

func TestPayloadsAgreeWithEveryVector(t *testing.T) {
	var v payloadVectors
	loadVectors(t, "payloads.json", &v)
	if v.ApprovedMaxEntries != ApprovedMaxEntries {
		t.Errorf("approved cap %d, the vectors say %d", ApprovedMaxEntries, v.ApprovedMaxEntries)
	}
	if len(v.Vectors) < 50 {
		t.Fatalf("only %d payload vectors were loaded", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		var text []byte
		if vec.PayloadText != nil {
			text = []byte(*vec.PayloadText)
		} else {
			var compact bytes.Buffer
			if err := json.Compact(&compact, vec.Payload); err != nil {
				t.Fatalf("%s: %v", vec.Description, err)
			}
			text = compact.Bytes()
		}
		p, f := ParsePayloadJSON(text)
		switch {
		case vec.Valid && f != nil:
			t.Errorf("%s: refused: %v", vec.Description, f)
		case !vec.Valid && f == nil:
			t.Errorf("%s: accepted, want the %s refusal", vec.Description, vec.Fault)
		case !vec.Valid && f.Kind != vec.Fault:
			t.Errorf("%s: refused as %s (%s), want %s", vec.Description, f.Kind, f.Detail, vec.Fault)
		case vec.Valid:
			var want struct {
				Action          string            `json:"action"`
				Track           string            `json:"track"`
				Approved        map[string]string `json:"approved"`
				Reboot          *bool             `json:"reboot"`
				Major           string            `json:"major"`
				BootEnvironment *bool             `json:"boot_environment"`
			}
			if err := json.Unmarshal(vec.Payload, &want); err != nil {
				t.Fatalf("%s: %v", vec.Description, err)
			}
			wantReboot := want.Reboot == nil || *want.Reboot
			wantBootEnvironmentOff := want.BootEnvironment != nil && !*want.BootEnvironment
			if p.Action != want.Action || p.Track != want.Track || p.Reboot != wantReboot || len(p.Approved) != len(want.Approved) ||
				p.Major != want.Major || p.BootEnvironmentOff != wantBootEnvironmentOff {
				t.Errorf("%s: parsed %+v, the vector says %+v", vec.Description, p, want)
			}
			for series, version := range want.Approved {
				if p.Approved[series] != version {
					t.Errorf("%s: approved[%s] = %q, want %q", vec.Description, series, p.Approved[series], version)
				}
			}
		}
	}
}

func TestPayloadVocabularyIsTheSharedOne(t *testing.T) {
	var v payloadVectors
	loadVectors(t, "payloads.json", &v)
	if !equalStrings(v.Actions, actions) {
		t.Errorf("actions %v, the vectors say %v", actions, v.Actions)
	}
	if !equalStrings(v.Tracks, tracks) {
		t.Errorf("tracks %v, the vectors say %v", tracks, v.Tracks)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- results.json --------------------------------------------------------------

type resultVectors struct {
	Outcomes        []string          `json:"outcomes"`
	Reasons         []string          `json:"reasons"`
	HeldReasons     []string          `json:"held_reasons"`
	ReleasedReasons []string          `json:"released_reasons"`
	RequiredKeys    []string          `json:"required_keys"`
	VersionKeys     []string          `json:"version_keys"`
	OptionalKeys    []string          `json:"optional_keys"`
	Kinds           []string          `json:"kinds"`
	Notes           []string          `json:"notes"`
	NotesMax        int               `json:"notes_max"`
	ReinstallMax    int               `json:"reinstall_entries_max"`
	MaxSize         int               `json:"max_size"`
	Raw             []json.RawMessage `json:"vectors"`
	Vectors         []resultVector    `json:"-"`
}

type resultVector struct {
	Description string                     `json:"description"`
	Message     map[string]json.RawMessage `json:"message"`
	MessageText *string                    `json:"message_text"`
	Valid       bool                       `json:"valid"`
	Fault       string                     `json:"fault"`
	// DispatchedMajor is the `major` of the payload the task was dispatched with;
	// a vector without it was dispatched with none.
	DispatchedMajor string `json:"dispatched_major"`
}

func loadResultVectors(t *testing.T) resultVectors {
	t.Helper()
	var v resultVectors
	loadVectors(t, "results.json", &v)
	for _, raw := range v.Raw {
		var vec resultVector
		if err := json.Unmarshal(raw, &vec); err != nil {
			t.Fatalf("decode a result vector: %v", err)
		}
		v.Vectors = append(v.Vectors, vec)
	}
	if len(v.Vectors) < 80 {
		t.Fatalf("only %d result vectors were loaded", len(v.Vectors))
	}
	return v
}

// text is the vector as the message text the validator takes: message_text
// verbatim, else the compact JSON of the message object.
func (vec resultVector) text(t *testing.T) string {
	t.Helper()
	if vec.MessageText != nil {
		return *vec.MessageText
	}
	text, err := json.Marshal(vec.Message)
	if err != nil {
		t.Fatalf("%s: %v", vec.Description, err)
	}
	return string(text)
}

func TestResultVocabularyIsTheSharedOne(t *testing.T) {
	v := loadResultVectors(t)
	if !equalStrings(v.Outcomes, []string{OutcomeSuccess, OutcomeNoop, OutcomeHeld, OutcomeReleased}) {
		t.Errorf("outcomes: the vectors say %v", v.Outcomes)
	}
	if !equalStrings(v.Reasons, reasons) {
		t.Errorf("reasons: the vectors say %v, the agent has %v", v.Reasons, reasons)
	}
	if !equalStrings(v.HeldReasons, heldReasons) {
		t.Errorf("held reasons: the vectors say %v", v.HeldReasons)
	}
	if !equalStrings(v.ReleasedReasons, releasedReasons) {
		t.Errorf("released reasons: the vectors say %v", v.ReleasedReasons)
	}
	if !equalStrings(v.RequiredKeys, []string{"action", "track", "outcome", "reason", "drift", "reinstall_entries"}) {
		t.Errorf("required keys: the vectors say %v", v.RequiredKeys)
	}
	if !equalStrings(v.VersionKeys, []string{"from_version", "to_version", "target_version", "pinned_version"}) {
		t.Errorf("version keys: the vectors say %v", v.VersionKeys)
	}
	if !equalStrings(v.OptionalKeys, []string{"kind", "notes"}) {
		t.Errorf("optional keys: the vectors say %v", v.OptionalKeys)
	}
	if !equalStrings(v.Kinds, []string{KindMajor}) {
		t.Errorf("kinds: the vectors say %v", v.Kinds)
	}
	if !equalStrings(v.Notes, noteTokens) {
		t.Errorf("notes: the vectors say %v, the agent has %v", v.Notes, noteTokens)
	}
	if v.NotesMax != notesMax {
		t.Errorf("notes bound %d, the vectors say %d", notesMax, v.NotesMax)
	}
	if v.MaxSize != ResultMaxSize || v.ReinstallMax != ReinstallEntriesMax {
		t.Errorf("bounds: %d / %d, the vectors say %d / %d", ResultMaxSize, ReinstallEntriesMax, v.MaxSize, v.ReinstallMax)
	}
}

func TestResultValidatorAgreesWithEveryVector(t *testing.T) {
	v := loadResultVectors(t)
	for _, vec := range v.Vectors {
		// The dispatch is the vector's: a task dispatched with no major refuses a kind.
		f := ValidateResult(vec.text(t), &Expect{Major: vec.DispatchedMajor})
		switch {
		case vec.Valid && f != nil:
			t.Errorf("%s: refused: %v", vec.Description, f)
		case !vec.Valid && f == nil:
			t.Errorf("%s: accepted, want the %s refusal", vec.Description, vec.Fault)
		case !vec.Valid && f.Kind != vec.Fault:
			t.Errorf("%s: refused as %s (%s), want %s", vec.Description, f.Kind, f.Detail, vec.Fault)
		}
	}
}

// The builder produces exactly what each valid vector says, and refuses the
// invalid ones that a typed result can express.
func TestResultBuilderProducesEveryValidVectorAndNothingInvalid(t *testing.T) {
	v := loadResultVectors(t)
	built := 0
	for _, vec := range v.Vectors {
		if vec.Message == nil {
			continue
		}
		r, ok := resultFromVector(vec.Message)
		if !ok {
			continue // a vector whose point is a key or a type the builder cannot express
		}
		text, err := r.message(&Expect{Major: vec.DispatchedMajor})
		if vec.Valid {
			if err != nil {
				t.Errorf("%s: the builder refused a valid result: %v", vec.Description, err)
				continue
			}
			built++
			if !sameJSON(t, text, vec.text(t)) {
				t.Errorf("%s: built %s, the vector says %s", vec.Description, text, vec.text(t))
			}
		} else if err == nil {
			t.Errorf("%s: the builder produced %s for an invalid result (%s)", vec.Description, text, vec.Fault)
		}
	}
	if built < 30 {
		t.Fatalf("only %d valid vectors were rebuilt", built)
	}
}

func resultFromVector(m map[string]json.RawMessage) (Result, bool) {
	var r Result
	str := func(key string, dst *string) bool {
		raw, present := m[key]
		if !present {
			return true
		}
		return json.Unmarshal(raw, dst) == nil
	}
	if !str("action", &r.Action) || !str("track", &r.Track) || !str("outcome", &r.Outcome) || !str("reason", &r.Reason) ||
		!str("from_version", &r.FromVersion) || !str("to_version", &r.ToVersion) ||
		!str("target_version", &r.TargetVersion) || !str("pinned_version", &r.PinnedVersion) ||
		!str("kind", &r.Kind) {
		return Result{}, false
	}
	// notes is a list of strings; a typed result cannot be asked for null, a string,
	// an entry that is not a string, or an empty list (omit it instead).
	if raw, present := m["notes"]; present {
		if json.Unmarshal(raw, &r.Notes) != nil || len(r.Notes) == 0 {
			return Result{}, false
		}
	}
	// A typed result always carries drift and reinstall_entries and never an
	// empty version, so a vector that is invalid for lacking one, or for holding
	// null or "", is a shape the builder cannot be asked for.
	for _, key := range []string{"drift", "reinstall_entries"} {
		if raw, present := m[key]; !present || string(raw) == "null" {
			return Result{}, false
		}
	}
	if json.Unmarshal(m["drift"], &r.Drift) != nil || json.Unmarshal(m["reinstall_entries"], &r.ReinstallEntries) != nil {
		return Result{}, false
	}
	for _, key := range []string{"from_version", "to_version", "target_version", "pinned_version", "kind"} {
		if raw, present := m[key]; present && string(raw) == `""` {
			return Result{}, false
		}
	}
	for key := range m {
		switch key {
		case "action", "track", "outcome", "reason", "drift", "reinstall_entries",
			"from_version", "to_version", "target_version", "pinned_version", "kind", "notes":
		default:
			return Result{}, false
		}
	}
	for _, key := range []string{"from_version", "to_version", "target_version", "pinned_version", "kind"} {
		if raw, present := m[key]; present && string(raw) == "null" {
			return Result{}, false // null is "omit it instead": not expressible as an empty string either
		}
	}
	return r, true
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y interface{}
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatalf("not JSON: %s", a)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("not JSON: %s", b)
	}
	xa, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xa) == string(yb)
}

// The control plane's stricter check, made with the map the payload would have
// carried: a target_version in a valid vector is the release its series holds.
func TestResultTargetsAreTheOnesAPayloadWouldHaveCarried(t *testing.T) {
	v := loadResultVectors(t)
	for _, vec := range v.Vectors {
		if !vec.Valid || vec.Message == nil {
			continue
		}
		raw, ok := vec.Message["target_version"]
		if !ok {
			continue
		}
		var target string
		_ = json.Unmarshal(raw, &target)
		series, _ := SeriesOf(target)
		if f := ValidateResult(vec.text(t), &Expect{Approved: map[string]string{series: target}, Major: vec.DispatchedMajor}); f != nil {
			t.Errorf("%s: refused against its own target: %v", vec.Description, f)
		}
		if _, isMajor := vec.Message["kind"]; isMajor {
			// Under a kind the target is the series, judged against the dispatched
			// major and not against the approved map: a different major is refused.
			if f := ValidateResult(vec.text(t), &Expect{Major: "27.1"}); f == nil {
				t.Errorf("%s: accepted a series the dispatch did not carry", vec.Description)
			}
			continue
		}
		if f := ValidateResult(vec.text(t), &Expect{Approved: map[string]string{}, Major: vec.DispatchedMajor}); f == nil {
			t.Errorf("%s: accepted a target the dispatch did not carry", vec.Description)
		}
	}
}

// --- failure-details.json ------------------------------------------------------

func TestFailureDetailAgreesWithEveryVector(t *testing.T) {
	var v struct {
		Key      string   `json:"key"`
		Keys     []string `json:"keys"`
		Kinds    []string `json:"kinds"`
		Notes    []string `json:"notes"`
		NotesMax int      `json:"notes_max"`
		Reasons  []string `json:"reasons"`
		Vectors  []struct {
			Description     string                 `json:"description"`
			Response        map[string]interface{} `json:"response"`
			DispatchedMajor string                 `json:"dispatched_major"`
			Valid           bool                   `json:"valid"`
			Fault           string                 `json:"fault"`
		} `json:"vectors"`
	}
	loadVectors(t, "failure-details.json", &v)
	if v.Key != FailureKey {
		t.Errorf("the side-channel key is %q in the vectors, %q here", v.Key, FailureKey)
	}
	if !equalStrings(v.Keys, []string{"target", "reason", "pinned_version", "kind", "notes"}) {
		t.Errorf("detail keys %v", v.Keys)
	}
	if !equalStrings(v.Kinds, []string{KindMajor}) || !equalStrings(v.Notes, noteTokens) || v.NotesMax != notesMax {
		t.Errorf("kinds %v, notes %v, bound %d: the agent has %q, %v and %d", v.Kinds, v.Notes, v.NotesMax, KindMajor, noteTokens, notesMax)
	}
	if !equalStrings(v.Reasons, reasons) {
		t.Errorf("failure reasons %v, the agent has %v", v.Reasons, reasons)
	}
	if len(v.Vectors) < 25 {
		t.Fatalf("only %d failure vectors were loaded", len(v.Vectors))
	}
	for _, vec := range v.Vectors {
		detail, present := vec.Response[FailureKey]
		if !present {
			if !vec.Valid {
				t.Errorf("%s: an invalid vector without the key", vec.Description)
			}
			continue // a response without the key is valid
		}
		f := ValidateFailureDetail(detail, &Expect{Major: vec.DispatchedMajor})
		switch {
		case vec.Valid && f != nil:
			t.Errorf("%s: refused: %v", vec.Description, f)
		case !vec.Valid && f == nil:
			t.Errorf("%s: accepted, want the %s refusal", vec.Description, vec.Fault)
		case !vec.Valid && f.Kind != vec.Fault:
			t.Errorf("%s: refused as %s (%s), want %s", vec.Description, f.Kind, f.Detail, vec.Fault)
		}
		// The drain knows no dispatch, so it judges a detail by itself: it agrees with
		// every vector except the one fault that is about the dispatch alone.
		wantClean := vec.Valid || vec.Fault == "kind_not_dispatched"
		if _, ok := CleanFailureDetail(detail); ok != wantClean {
			t.Errorf("%s: CleanFailureDetail = %v, want %v", vec.Description, ok, wantClean)
		}
	}
}
