package tasks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

const (
	// fieldSuggestionMaxEdit is how far a content key may be from a model
	// field for the refusal to suggest it.
	fieldSuggestionMaxEdit = 2
	// optionListCap bounds the options a message lists.
	optionListCap = 15
)

// fieldContract is how a snippet family's content maps onto an OPNsense
// entity model the device defines (opnapi.EntityModel): content may set any
// field of the model, and only those.
type fieldContract struct {
	// snippetType names the snippet type, whose ignored keys
	// (ignoredContentKeys) content may hold and are never applied.
	snippetType string
	// entity names the model in messages ("rule").
	entity      string
	codeUnknown string
	codeInvalid string
	// required are fields content must set: absent, null or empty refuses
	// the element.
	required map[string]bool
	// nameMapped are list fields that also take an option's label (a name),
	// sent as the option's key (the UUID OPNsense stores).
	nameMapped map[string]bool
	// caseFolded are list fields OPNsense changes the case of on save.
	caseFolded map[string]bool
	// lowerCased are plain fields OPNsense stores some values of trimmed and
	// lower-cased (opnsensePortFold), with those values: the row holding the
	// body's value so is a match when the value is one of them.
	lowerCased map[string]map[string]bool
	// unchecked are list fields whose options are checked elsewhere (RULE's
	// interface, by checkRuleInterfaces, with its own code).
	unchecked map[string]bool
	// newlineLists are fields whose list form joins with newlines rather than
	// commas. Their entries are free text, never checked against options.
	newlineLists map[string]bool
}

// skipped reports whether a content key, or a model field, is never applied:
// the element's identity, which is not part of the body, or a key its type
// ignores, whatever value it holds and whether or not the device's model has
// the field (a rule's sequence is placement's, its audit record is OPNsense's).
func (c fieldContract) skipped(key string) bool {
	return key == "uuid" || isIgnoredContentKey(c.snippetType, key)
}

// contentRefusal is a desired element this pass will not write, and why.
type contentRefusal struct {
	Code    string
	Message string
}

// build turns content into the body the entity's setter takes: every field the
// model lets content set, holding the content's value or, when content leaves
// the field out, the model's default. An element is what its content says, so
// leaving a field out resets it.
//
// It refuses the element when content names a field the model lacks (the
// setter would drop it and answer "saved", so a typo would change the device
// without a word), holds a value of the wrong JSON kind, leaves out a required
// field, gives a list field blanks and commas but no key, or names an option
// the device does not have. label names the element in messages; release
// names the device's OPNsense release, read only when a message needs it.
func (c fieldContract) build(content map[string]interface{}, model opnapi.EntityModel, label string, release func() string) (map[string]string, *contentRefusal) {
	if refusal := c.checkKeys(content, model, label, release); refusal != nil {
		return nil, refusal
	}

	body := make(map[string]string)
	var problems []string
	for _, name := range model.Names() {
		field, _ := model.Field(name)
		if c.skipped(name) || field.Nested {
			continue
		}

		raw, present := content[name]
		if !present || raw == nil {
			if c.required[name] {
				problems = append(problems, name+" is required")
				continue
			}
			body[name] = field.Default
			continue
		}

		value, problem := c.value(field, raw)
		if problem != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", name, problem))
			continue
		}
		if value == "" && c.required[name] {
			problems = append(problems, name+" is required")
			continue
		}
		body[name] = value
	}
	if len(problems) > 0 {
		return nil, &contentRefusal{
			Code:    c.codeInvalid,
			Message: fmt.Sprintf("%s: %s", label, strings.Join(problems, "; ")),
		}
	}
	return body, nil
}

// value converts one content value for its field.
func (c fieldContract) value(field opnapi.ModelField, raw interface{}) (string, string) {
	if c.newlineLists[field.Name] {
		if items, ok := raw.([]interface{}); ok {
			return joinListValue(items, "\n")
		}
		return opnsenseValue(raw, false, false)
	}

	value, problem := opnsenseValue(raw, field.IsBoolean(), field.List)
	if problem != "" || !field.List {
		return value, problem
	}
	tidied := tidyListValue(value)
	if tidied == "" && value != "" {
		return "", "holds no option key"
	}
	if c.unchecked[field.Name] {
		return tidied, ""
	}
	return c.optionValue(field, tidied)
}

// checkKeys refuses content naming a field the model does not have,
// suggesting the nearest field it does have, or one of the model's
// containers, which a flat setter body cannot set. A field one release has
// and another lacks is refused on the device that lacks it, with that
// device's release in the message, never dropped.
func (c fieldContract) checkKeys(content map[string]interface{}, model opnapi.EntityModel, label string, release func() string) *contentRefusal {
	var unknown, unsettable []string
	for key := range content {
		if c.skipped(key) {
			continue
		}
		switch field, ok := model.Field(key); {
		case !ok:
			unknown = append(unknown, key)
		case field.Nested:
			unsettable = append(unsettable, key)
		}
	}
	if len(unknown) == 0 && len(unsettable) == 0 {
		return nil
	}
	sort.Strings(unknown)
	sort.Strings(unsettable)

	var problems []string
	if len(unknown) > 0 {
		described := make([]string, 0, len(unknown))
		for _, key := range unknown {
			if near := c.nearestField(key, model); near != "" {
				described = append(described, fmt.Sprintf("%q (did you mean %q?)", key, near))
			} else {
				described = append(described, fmt.Sprintf("%q", key))
			}
		}
		problems = append(problems, fmt.Sprintf("%s not in this device's %s model (OPNsense %s)", fieldsSubject(described), c.entity, release()))
	}
	if len(unsettable) > 0 {
		quoted := make([]string, len(unsettable))
		for i, key := range unsettable {
			quoted[i] = fmt.Sprintf("%q", key)
		}
		problems = append(problems, fieldsSubject(quoted)+" not settable")
	}
	return &contentRefusal{
		Code:    c.codeUnknown,
		Message: fmt.Sprintf("%s: %s", label, strings.Join(problems, "; ")),
	}
}

// fieldsSubject is "field X is" for one described field, "fields X, Y are"
// for more.
func fieldsSubject(described []string) string {
	if len(described) == 1 {
		return "field " + described[0] + " is"
	}
	return "fields " + strings.Join(described, ", ") + " are"
}

// nearestField is the settable model field closest to key, within
// fieldSuggestionMaxEdit edits, or "" when none is that close. Ties go to the
// first name in sorted order.
func (c fieldContract) nearestField(key string, model opnapi.EntityModel) string {
	best, bestDistance := "", fieldSuggestionMaxEdit+1
	for _, name := range model.Names() {
		if field, _ := model.Field(name); c.skipped(name) || field.Nested {
			continue
		}
		if d := editDistance(strings.ToLower(key), strings.ToLower(name)); d < bestDistance {
			best, bestDistance = name, d
		}
	}
	return best
}

// optionValue checks a list field's value against the device's options and
// returns what to send. A name-mapped field may name an option by its label;
// it is sent as the option's key. Other fields take option keys, matched
// exactly except on a field OPNsense changes the case of.
func (c fieldContract) optionValue(field opnapi.ModelField, value string) (string, string) {
	if value == "" {
		return value, ""
	}

	keys := strings.Split(value, ",")
	var unknown []string
	for i, key := range keys {
		if _, ok := field.Options[key]; ok {
			continue
		}
		if c.nameMapped[field.Name] {
			if mapped, ok := optionKeyByLabel(field, key); ok {
				keys[i] = mapped
				continue
			}
		} else if c.caseFolded[field.Name] && optionKeyFold(field, key) {
			continue
		}
		unknown = append(unknown, key)
	}
	if len(unknown) == 0 {
		return strings.Join(keys, ","), ""
	}

	available := field.OptionKeys()
	if c.nameMapped[field.Name] {
		available = optionLabels(field)
	}
	return "", fmt.Sprintf("%s not on this device (available: %s)", quoteList(unknown), capList(available, optionListCap))
}

// rowMatches reports whether the device's row already holds every value of
// the body, so writing it would change nothing but the device's config
// history. A comma list is compared as written (OPNsense stores it as sent), a
// case-folded field without regard to case, a lower-cased one as written or,
// for one of the values OPNsense folds, trimmed and lower-cased, and a number
// in the row by its decimal form. A false "changed" costs one write, never a
// wrong rule, so anything else unexpected in the row counts as changed.
func (c fieldContract) rowMatches(body map[string]string, row map[string]interface{}) bool {
	for name, want := range body {
		var got string
		switch v := row[name].(type) {
		case string:
			got = v
		case float64:
			got = formatContentNumber(v)
		default:
			return false
		}
		if known := c.lowerCased[name]; known != nil {
			if folded := opnsensePortFold(want); known[folded] && got == folded {
				continue
			}
		}
		if c.caseFolded[name] {
			if !strings.EqualFold(got, want) {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// phpTrimSet is what PHP's trim() strips: no other white space, no NBSP.
const phpTrimSet = " \t\n\r\x00\x0B"

// opnsensePortFold is a value as PortField::setValue folds it: PHP's trim()
// and strtolower(), which change ASCII only. Go's TrimSpace would also strip a
// no-break space, and its ToLower maps the Kelvin sign to "k".
func opnsensePortFold(value string) string {
	folded := []byte(strings.Trim(value, phpTrimSet))
	for i, c := range folded {
		if c >= 'A' && c <= 'Z' {
			folded[i] = c + 'a' - 'A'
		}
	}
	return string(folded)
}

// portable turns a device row into snippet content: every field the model
// lets content set that differs from the model's default, and the always
// fields at any value. SYNC applies the default to whatever is left out, so
// the same element comes back. Name-mapped fields are given by label, and the
// description loses its template tags, which SYNC sets.
//
// The device's own UUID stays in the content: the control plane replaces it
// with a new managed UUID when it stores the pulled snippet, and only
// replaces a uuid that is there.
func (c fieldContract) portable(row map[string]interface{}, model opnapi.EntityModel, always map[string]bool) map[string]interface{} {
	content := map[string]interface{}{}
	if uuid, ok := row["uuid"].(string); ok {
		content["uuid"] = uuid
	}

	for _, name := range model.Names() {
		field, _ := model.Field(name)
		if c.skipped(name) || field.Nested {
			continue
		}
		value, ok := row[name].(string)
		if !ok {
			continue
		}
		switch {
		case name == "description":
			value = opnapi.StripTemplateTags(value)
		case c.nameMapped[name]:
			value = optionLabelsOf(field, value)
		}
		if always[name] || value != field.Default {
			content[name] = value
		}
	}
	return content
}

// optionLabelsOf names each key of a stored list value by its option's label;
// a key the device offers no option for stays as it is.
func optionLabelsOf(field opnapi.ModelField, value string) string {
	if value == "" {
		return ""
	}
	keys := strings.Split(value, ",")
	for i, key := range keys {
		if label, ok := field.Options[key]; ok && key != "" {
			keys[i] = label
		}
	}
	return strings.Join(keys, ",")
}

// withTemplateTags is the description a managed element carries: the
// content's, without any template tag it already holds (a pulled element
// does), followed by one tag per template that delivers it.
func withTemplateTags(description string, templates []string) string {
	desc := opnapi.StripTemplateTags(description)
	for _, t := range templates {
		desc += fmt.Sprintf(" [nd-template:%s]", t)
	}
	return strings.TrimSpace(desc)
}

// installedReleaseName names the device's OPNsense release for a message; a
// test replaces it.
var installedReleaseName = defaultInstalledReleaseName

func defaultInstalledReleaseName(ctx context.Context, client *opnapi.Client) string {
	release, err := client.InstalledRelease(ctx)
	if err != nil {
		return "release unknown"
	}
	return release.String()
}

// deviceRelease returns a lookup of the device's release that reads it the
// first time a message needs it, and only then.
func deviceRelease(ctx context.Context, client *opnapi.Client) func() string {
	var name string
	return func() string {
		if name == "" {
			name = installedReleaseName(ctx, client)
		}
		return name
	}
}

// validationFailure reports whether err is OPNsense refusing a write with
// field validations.
func validationFailure(err error) (*opnapi.ValidationFailedError, bool) {
	var refused *opnapi.ValidationFailedError
	if errors.As(err, &refused) {
		return refused, true
	}
	return nil, false
}

// contentText reads a content value as text, before or without the device's
// model: the checks that run first, and messages, need a few values early.
// Values the model check refuses read as "".
func contentText(content map[string]interface{}, key string) string {
	s, problem := opnsenseValue(content[key], false, false)
	if problem != "" {
		return ""
	}
	return s
}

// opnsenseValue converts one content value to the string form OPNsense's
// setters take, or says why it cannot. A value that is not a string is
// converted as OPNsense would have read it in a stored form:
//
//   - a boolean is "1" or "0" on a boolean field, and refused on any other (a
//     port of true would be sent as "1");
//   - a number is its decimal form ("443"); a fraction stays one, for OPNsense
//     to refuse on an integer field;
//   - a list of strings and numbers is comma-joined, OPNsense's multi-value
//     form, because a JSON array makes the setter answer HTTP 500;
//   - an object, or a list holding anything else, is refused.
//
// On a boolean field (boolField) the strings "true" and "false", in any case,
// are "1" and "0" too; any other string is sent as it is.
func opnsenseValue(v interface{}, boolField, listField bool) (string, string) {
	switch value := v.(type) {
	case nil:
		return "", ""
	case string:
		if boolField {
			switch strings.ToLower(value) {
			case "true":
				return "1", ""
			case "false":
				return "0", ""
			}
		}
		return value, ""
	case bool:
		switch {
		case boolField:
			return opnapi.BoolToOPNsense(value), ""
		case listField:
			return "", "takes the key of one of the device's options, not true or false"
		default:
			return "", "takes text or a number, not true or false"
		}
	case float64:
		return formatContentNumber(value), ""
	case []interface{}:
		return joinListValue(value, ",")
	default:
		return "", "must be a string, not an object"
	}
}

// joinListValue joins a list of strings and numbers with sep, or says why it
// cannot.
func joinListValue(items []interface{}, sep string) (string, string) {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		switch element := item.(type) {
		case string:
			parts = append(parts, element)
		case float64:
			parts = append(parts, formatContentNumber(element))
		default:
			return "", "a list may hold only strings and numbers"
		}
	}
	return strings.Join(parts, sep), ""
}

// formatContentNumber renders a JSON number in decimal: 443 is "443", and
// 1e3 is "1000".
func formatContentNumber(n float64) string {
	if n == math.Trunc(n) && math.Abs(n) < 1e15 {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'f', -1, 64)
}

// tidyListValue drops the blanks around and between the keys of a list
// field's value. No option key holds them, so "lan, wan" can only mean
// "lan,wan".
func tidyListValue(value string) string {
	var keys []string
	for _, key := range strings.Split(value, ",") {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}
	return strings.Join(keys, ",")
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

// optionKeyByLabel finds the option whose label is exactly name. OPNsense's
// "nothing selected" option is never a match.
func optionKeyByLabel(field opnapi.ModelField, name string) (string, bool) {
	for key, label := range field.Options {
		if key != "" && label == name {
			return key, true
		}
	}
	return "", false
}

func optionKeyFold(field opnapi.ModelField, key string) bool {
	for option := range field.Options {
		if strings.EqualFold(option, key) {
			return true
		}
	}
	return false
}

// optionLabels lists the labels of a field's options, sorted, without the
// "nothing selected" option.
func optionLabels(field opnapi.ModelField) []string {
	var labels []string
	for key, label := range field.Options {
		if key != "" {
			labels = append(labels, label)
		}
	}
	sort.Strings(labels)
	return labels
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return strings.Join(quoted, ", ")
}

// capList joins at most limit items, blanks left out, and says how many more
// there are.
func capList(items []string, limit int) string {
	var shown []string
	for _, item := range items {
		if item != "" {
			shown = append(shown, item)
		}
	}
	if len(shown) == 0 {
		return "none"
	}
	if len(shown) <= limit {
		return strings.Join(shown, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(shown[:limit], ", "), len(shown)-limit)
}
