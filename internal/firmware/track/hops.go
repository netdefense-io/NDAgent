package track

// The supported series hops: the pairs of series a device may be upgraded between
// as part of its track. The mirror offers far more pairs than anyone has tried
// (the 25.7 to 26.1 packages tar, the 24.7 and 25.1 equivalents, and three in the
// FreeBSD:13 tree), and business series names such as 23.4 and 23.10 fit the series
// pattern, so neither the mirror's listing nor a pattern says which pairs are ours
// to run. This table does, and it is the only place: nothing derives "the next
// series", "the previous one" or an ABI from a number.
//
// It is NDDataModels' table (FIRMWARE_SERIES_HOPS), copied here the way the
// reasons are: tests/fixtures/firmware-track/versions.json carries it with the
// answers of the three helpers, and TestSeriesHopsAreTheSharedOnes holds this copy
// to it. A pair is added by a schema release, after a lab run of that very hop. A
// pair that keeps its ABI also needs that run to repeat the reads made on one:
// after such a hop the old pin still resolves, which the cross-ABI hop's does not,
// so the re-pin is the only guard in the minutes after the last reboot.

// Hop is one supported series upgrade. SourceABI is the FreeBSD ABI the device
// runs before it and the root the upgrade payload sits under on the mirror
// (FreeBSD:14:amd64/26.1/sets/ for 26.1 to 26.7); TargetABI is the ABI after it,
// the root of the target series' own tree. Whether the ABI changes is the property
// of the row (SourceABI != TargetABI), never a stored flag.
type Hop struct {
	Source    string
	Target    string
	SourceABI string
	TargetABI string
}

// ABIChanges reports whether the hop moves the device to another FreeBSD ABI.
func (h Hop) ABIChanges() bool { return h.SourceABI != h.TargetABI }

// hops is the table. It is a variable so that a test can add a pair the shipped
// table does not have (a hop that keeps its ABI); production code never writes it.
var hops = []Hop{
	{Source: "26.1", Target: "26.7", SourceABI: "FreeBSD:14:amd64", TargetABI: "FreeBSD:15:amd64"},
}

// Hops returns a copy of the table.
func Hops() []Hop { return append([]Hop(nil), hops...) }

// HopTarget is the series a device on series is upgraded to; false for a series
// that is the source of no row (a pre-floor series, a business series, the target of
// the last hop) and for anything that is not a series name.
func HopTarget(series string) (string, bool) {
	for _, h := range hops {
		if h.Source == series {
			return h.Target, true
		}
	}
	return "", false
}

// HopSource is the series a device must be on to be upgraded to series; false for a
// series no row leads to.
func HopSource(series string) (string, bool) {
	for _, h := range hops {
		if h.Target == series {
			return h.Source, true
		}
	}
	return "", false
}

// HopBetween is the row from source to target.
func HopBetween(source, target string) (Hop, bool) {
	for _, h := range hops {
		if h.Source == source && h.Target == target {
			return h, true
		}
	}
	return Hop{}, false
}

// HopABIs are the ABIs of the hop that starts at source: where the device is, and
// where it lands.
func HopABIs(source string) (sourceABI, targetABI string, ok bool) {
	for _, h := range hops {
		if h.Source == source {
			return h.SourceABI, h.TargetABI, true
		}
	}
	return "", "", false
}
