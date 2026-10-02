package tasks

// TRUST_CA / TRUST_CERT: CAs and certificates synced into the OPNsense trust
// store through /api/trust/ca and /api/trust/cert.
//
// The family runs first in a SYNC: a service a later family touches may use a
// certificate this one renews. CAs are written before certificates, so a
// certificate can name its issuer, and certificates are removed before CAs, so
// a CA is not in use by a certificate leaving in the same pass.
//
// A certificate's private key is in the payload and in every trust read the
// device answers. None of it reaches a result, a task message or a log: items
// carry identifiers, codes and fixed text, and the opnapi trust client reduces
// what it reads to fingerprints before it returns.
//
// A device that does not use the family is not asked anything: with no trust
// item in the payload, no NetDefense CA or certificate in config.xml and no
// reload waiting, the family makes no API call at all.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Result codes of the trust family.
const (
	trustCodeNameCollision      = "NAME_COLLISION_UNMANAGED"
	trustCodeInUse              = "TRUST_IN_USE"
	trustCodeCARekeyed          = "TRUST_CA_REKEYED"
	trustCodeCADNConflict       = "TRUST_CA_DN_CONFLICT"
	trustCodeOPNsenseTooOld     = "TRUST_OPNSENSE_TOO_OLD"
	trustCodeIssuerMislinked    = "TRUST_ISSUER_MISLINKED"
	trustCodeContentUnsupported = "TRUST_CONTENT_UNSUPPORTED"
	trustCodeImportFailed       = "TRUST_IMPORT_FAILED"
	trustCodeReloadFailed       = "TRUST_RELOAD_FAILED"
	trustCodeReloadScheduled    = "TRUST_RELOAD_SCHEDULED"
	trustCodeConsumerUnknown    = "TRUST_CONSUMER_UNKNOWN"
	trustCodeRejectedDangerous  = "TRUST_REJECTED_DANGEROUS"
)

// Result item types of the trust family.
const (
	trustTypeCA     = "trust_ca"
	trustTypeCert   = "trust_cert"
	trustTypeReload = "trust_reload"
)

// trustUUIDPattern is a NetDefense-managed uuid: the managed prefix, version 4
// shape, lower-case hex.
var trustUUIDPattern = regexp.MustCompile(`^` + opnapi.NDAgentUUIDPrefix + `-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// trustContentKeys are the keys of the content of the two snippet types as the
// control plane resolves it: crt and key are PEM text.
var trustContentKeys = map[opnapi.TrustKind][]string{
	opnapi.TrustCA:   {"uuid", "name", "crt"},
	opnapi.TrustCert: {"uuid", "name", "crt", "key"},
}

// trustItem is one CA or certificate the payload asks for, validated, with its
// material re-encoded as the canonical PEM the agent posts.
type trustItem struct {
	Kind       opnapi.TrustKind
	UUID       string
	Name       string
	Cert       *x509.Certificate
	CertSHA256 string
	CertPEM    string
	KeyPEM     string
	KeySHA256  string
}

func (i trustItem) resultType() string {
	if i.Kind == opnapi.TrustCA {
		return trustTypeCA
	}
	return trustTypeCert
}

// trustContentError is content this agent cannot read. Reason is fixed text:
// it never quotes the content.
type trustContentError struct {
	Type        string
	SnippetName string
	Label       string
	Reason      string
}

func (e *trustContentError) message() string {
	return fmt.Sprintf("%s: %s: %s; no CA or certificate was changed", trustCodeContentUnsupported, e.Label, e.Reason)
}

// trustParseOutcome is the trust content of a payload. Err, when set, makes the
// whole family a no-op for this pass, deletes included: the agent cannot tell
// what the payload wants on the device.
type trustParseOutcome struct {
	CAs   []trustItem
	Certs []trustItem
	Err   *trustContentError
}

func (p trustParseOutcome) empty() bool {
	return len(p.CAs) == 0 && len(p.Certs) == 0
}

// parseAPITrustContent reads the TRUST_CA and TRUST_CERT snippets of a SYNC
// payload. It never fails the SYNC: content it cannot read is reported in Err.
func parseAPITrustContent(payload map[string]interface{}) trustParseOutcome {
	var out trustParseOutcome
	snippets, _ := payload["snippets"].([]interface{})
	seen := map[string]trustItem{}
	for idx, s := range snippets {
		snippet, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		var kind opnapi.TrustKind
		var resultType string
		switch snippet["config_type"] {
		case "TRUST_CA":
			kind, resultType = opnapi.TrustCA, trustTypeCA
		case "TRUST_CERT":
			kind, resultType = opnapi.TrustCert, trustTypeCert
		default:
			continue
		}
		snippetName, _ := snippet["snippet_name"].(string)
		label := snippetLabel(resultType, snippet, idx)
		content, _ := snippet["content"].(string)
		item, reason := parseTrustContent(kind, content)
		if reason == "" {
			if prev, dup := seen[item.UUID]; dup && !sameTrustItem(prev, item) {
				reason = "its uuid is used by another snippet with different content"
			}
		}
		if reason != "" {
			if out.Err == nil {
				out.Err = &trustContentError{Type: resultType, SnippetName: snippetName, Label: label, Reason: reason}
			}
			continue
		}
		if _, dup := seen[item.UUID]; dup {
			continue
		}
		seen[item.UUID] = item
		if kind == opnapi.TrustCA {
			out.CAs = append(out.CAs, item)
		} else {
			out.Certs = append(out.Certs, item)
		}
	}
	return out
}

func sameTrustItem(a, b trustItem) bool {
	return a.Kind == b.Kind && a.Name == b.Name && a.CertSHA256 == b.CertSHA256 && a.KeySHA256 == b.KeySHA256
}

// parseTrustContent decodes and validates one snippet's content. The reason
// it returns for content it refuses is fixed text.
func parseTrustContent(kind opnapi.TrustKind, content string) (trustItem, string) {
	item := trustItem{Kind: kind}
	keys := trustContentKeys[kind]
	fields, ok := strictStringObject(content, keys)
	if !ok {
		return item, "the content is not a JSON object of exactly " + strings.Join(keys, ", ") + ", each a string"
	}
	item.UUID, item.Name = fields["uuid"], fields["name"]
	crt, key := fields["crt"], fields["key"]

	if !trustUUIDPattern.MatchString(item.UUID) {
		return item, "uuid is not a NetDefense-managed UUID"
	}
	if !validTrustName(item.Name) {
		return item, "name is not 1-255 bytes on one line without ${, surrounding white space, or a control or format character"
	}

	certLabel, certDER, ok := singlePEMBlock(crt)
	if !ok || certLabel != "CERTIFICATE" {
		return item, "crt is not exactly one PEM CERTIFICATE block"
	}
	if !derIsCertificate(certDER) {
		return item, "the CERTIFICATE block of crt does not hold a certificate"
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return item, "crt does not parse as an X.509 certificate"
	}
	item.Cert = cert
	item.CertSHA256 = opnapi.CertFingerprint(cert)
	item.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	if kind == opnapi.TrustCA {
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return item, "crt is not a CA certificate (basicConstraints CA:TRUE)"
		}
		return item, ""
	}

	keyLabel, keyDER, ok := singlePEMBlock(key)
	if !ok {
		return item, "key is not exactly one PEM block"
	}
	if !derIsUnencryptedPrivateKey(keyDER) {
		return item, "key does not hold an unencrypted private key"
	}
	keyBlock := &pem.Block{Type: keyLabel, Bytes: keyDER}
	if _, err := opnapi.ParsePrivateKeyBlock(keyBlock); err != nil {
		return item, "key is not an unencrypted PEM private key"
	}
	item.KeyPEM = string(pem.EncodeToMemory(keyBlock))
	if _, err := tls.X509KeyPair([]byte(item.CertPEM), []byte(item.KeyPEM)); err != nil {
		return item, "key does not match the certificate"
	}
	item.KeySHA256 = opnapi.PrivateKeyFingerprint([]byte(item.KeyPEM))
	return item, ""
}

// strictStringObject decodes content that must be one JSON object holding
// exactly keys, spelled exactly so, each once, each a string, and nothing after
// it.
func strictStringObject(content string, keys []string) (map[string]string, bool) {
	dec := json.NewDecoder(strings.NewReader(content))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	fields := make(map[string]string, len(keys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := tok.(string)
		if _, dup := fields[key]; !allowed[key] || dup {
			return nil, false
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		fields[key] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	if len(fields) != len(keys) {
		return nil, false
	}
	return fields, true
}

// trustNameMaxBytes is OPNsense's limit on a description, which counts bytes.
const trustNameMaxBytes = 255

// validTrustName is a name OPNsense takes as the object's description: 1-255
// bytes of UTF-8 on one line, no surrounding white space, no control or format
// character, no variable left unresolved.
func validTrustName(name string) bool {
	if name == "" || len(name) > trustNameMaxBytes || !utf8.ValidString(name) ||
		strings.TrimSpace(name) != name || strings.Contains(name, "${") {
		return false
	}
	for _, r := range name {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return false
		}
	}
	return true
}

// pemOneBlockPattern is the whole of a PEM value: blank lines, one block whose
// armor lines start a line, a body of base64 lines and nothing else (no
// header, no blank line, no leading space), and white space after it. Lines
// end in LF or CRLF. The labels are compared after the match: RE2 has no
// backreference.
var pemOneBlockPattern = regexp.MustCompile(`\A(?:[ \t\r]*\n)*` +
	`-----BEGIN ([A-Z0-9]+(?: [A-Z0-9]+)*)-----\r?\n` +
	`((?:[A-Za-z0-9+/=]+\r?\n)+)` +
	`-----END ([A-Z0-9]+(?: [A-Z0-9]+)*)-----[ \t\r\n]*\z`)

// pemBase64Pattern is a body once its line breaks are gone.
var pemBase64Pattern = regexp.MustCompile(`\A[A-Za-z0-9+/]*={0,2}\z`)

// singlePEMBlock returns the label and DER of text when text is exactly one
// PEM block with only white space around it, and the DER is one SEQUENCE with
// nothing after it: a paste that lost a line fails here. Anything else (a
// second block, text after the block, headers) refuses the whole text, the
// rule the control plane applies to the same fields.
func singlePEMBlock(text string) (label string, der []byte, ok bool) {
	m := pemOneBlockPattern.FindStringSubmatch(text)
	if m == nil || m[1] != m[3] {
		return "", nil, false
	}
	body := strings.NewReplacer("\r", "", "\n", "").Replace(m[2])
	if len(body)%4 != 0 || !pemBase64Pattern.MatchString(body) {
		return "", nil, false
	}
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", nil, false
	}
	if _, ok := derSequenceItems(der); !ok {
		return "", nil, false
	}
	return m[1], der, true
}

// derSequenceItems returns the elements inside der when der is one SEQUENCE
// with nothing after it.
func derSequenceItems(der []byte) ([]asn1.RawValue, bool) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || !isUniversal(outer, asn1.TagSequence) || !outer.IsCompound {
		return nil, false
	}
	var items []asn1.RawValue
	for inner := outer.Bytes; len(inner) > 0; {
		var item asn1.RawValue
		next, err := asn1.Unmarshal(inner, &item)
		if err != nil {
			return nil, false
		}
		items = append(items, item)
		inner = next
	}
	return items, true
}

func isUniversal(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}

// derIsCertificate reports whether der has the outer shape of an X.509
// certificate: a SEQUENCE of the signed SEQUENCE, the algorithm SEQUENCE and
// the signature BIT STRING. A key or a public key relabelled CERTIFICATE does
// not.
func derIsCertificate(der []byte) bool {
	items, ok := derSequenceItems(der)
	return ok && len(items) == 3 &&
		isUniversal(items[0], asn1.TagSequence) && isUniversal(items[1], asn1.TagSequence) && isUniversal(items[2], asn1.TagBitString)
}

// derIsUnencryptedPrivateKey reports whether der opens like an unencrypted
// private key: every such format (PKCS#8, PKCS#1, SEC 1) starts with a one-byte
// version INTEGER, where a public key, a set of parameters or an encrypted
// PKCS#8 key starts with something else.
func derIsUnencryptedPrivateKey(der []byte) bool {
	items, ok := derSequenceItems(der)
	return ok && len(items) > 1 && isUniversal(items[0], asn1.TagInteger) && len(items[0].Bytes) == 1
}

// trustFamilyOutcome is what the trust family hands back to HandleSyncAPI: its
// result, and whether the web GUI's certificate was renewed, so the GUI must
// be restarted once the SYNC result has been sent.
type trustFamilyOutcome struct {
	Result        SyncAPIResult
	RestartWebGUI bool
}

// trustRun is one pass of the family.
type trustRun struct {
	ctx             context.Context
	client          *opnapi.Client
	rejectDangerous bool
	configXMLPath   string

	cas   []opnapi.TrustObject
	certs []opnapi.TrustObject

	config     *trustConfig
	configErr  error
	configRead bool

	// renewed are the refids whose material changed in place, by kind: this
	// pass's and those a previous pass left waiting for their reloads.
	renewedCAs   []renewedTrust
	renewedCerts []renewedTrust
	// left are the renewals whose reloads did not run or did not finish, kept
	// for the next pass.
	leftCAs   []renewedTrust
	leftCerts []renewedTrust
	// webGUIOwed is a web GUI restart a previous pass asked for that has not
	// started; webGUIRequested is whether this pass asks for one.
	webGUIOwed      bool
	webGUIRequested bool

	// changed is set once a write or a delete has been sent this pass, and
	// caWritten once a CA write has.
	changed   bool
	caWritten bool
	// payloadCAs are the CAs this pass asks for, desiredCAs their uuids.
	payloadCAs []trustItem
	desiredCAs map[string]bool

	// The device's OPNsense release, read before the first write.
	release     opnapi.ProductRelease
	releaseErr  error
	releaseRead bool

	result SyncAPIResult
}

type renewedTrust struct {
	RefID string `json:"refid"`
	Name  string `json:"name"`
}

// executeSyncTrust reconciles the device's NetDefense-managed CAs and
// certificates to the payload: create or update what it names, remove what it
// no longer names, and reload what uses a renewed one.
func executeSyncTrust(ctx context.Context, client *opnapi.Client, parsed trustParseOutcome, rejectDangerous bool, configXMLPath string) trustFamilyOutcome {
	log := logging.Named("SYNC_API")
	run := &trustRun{
		ctx:             ctx,
		client:          client,
		rejectDangerous: rejectDangerous,
		configXMLPath:   configXMLPath,
		result:          SyncAPIResult{Success: true},
	}

	if parsed.Err != nil {
		msg := parsed.Err.message()
		log.Warnw("Trust: content this agent cannot read; the trust family is a no-op this pass",
			"snippet", parsed.Err.Label)
		run.fail(SyncAPIItemResult{Type: parsed.Err.Type, Name: parsed.Err.SnippetName, Action: "unsupported", Status: "blocked", Code: trustCodeContentUnsupported, Error: msg})
		return trustFamilyOutcome{Result: run.result}
	}

	pending, err := loadTrustPending()
	if err != nil {
		log.Warnw("Trust: could not read the renewals waiting for their reloads", "error", err)
	}
	if parsed.empty() && pending.empty() && !trustConfigNeedsFamily(configXMLPath) {
		return trustFamilyOutcome{Result: run.result}
	}
	run.renewedCAs, run.renewedCerts, run.webGUIOwed = pending.CAs, pending.Certs, pending.WebGUI

	// The reloads run on every way out of reconcile: a renewal written before
	// a later step failed still reaches the services that use it.
	run.reconcile(parsed)
	restartWebGUI := run.reload()
	run.settlePending()

	log.Infow("Trust: family complete",
		"ca_count", len(parsed.CAs),
		"cert_count", len(parsed.Certs),
		"errors", len(run.result.Errors),
	)
	return trustFamilyOutcome{Result: run.result, RestartWebGUI: restartWebGUI}
}

// trustConfigNeedsFamily reports whether config.xml holds a CA or certificate
// NetDefense manages. One that cannot be read counts as holding one, so the
// family still removes what a payload no longer names.
func trustConfigNeedsFamily(path string) bool {
	holds, err := configHoldsManagedTrust(path)
	if err != nil {
		logging.Named("SYNC_API").Warnw("Trust: could not read the device configuration to see whether it holds NetDefense CAs or certificates; the trust family runs",
			"path", path, "error", err)
		return true
	}
	return holds
}

// reconcile makes the device's managed CAs and certificates match the payload.
func (r *trustRun) reconcile(parsed trustParseOutcome) {
	if !r.discover(parsed.empty()) {
		return
	}
	if parsed.empty() && !r.anyManaged() {
		return
	}

	r.payloadCAs = parsed.CAs
	r.desiredCAs = desiredUUIDs(parsed.CAs)
	for _, item := range parentsFirst(parsed.CAs) {
		r.upsert(item)
	}
	if r.caWritten && len(parsed.Certs) > 0 {
		// A CA write re-links every certificate on the device.
		if !r.refresh(opnapi.TrustCert, false) {
			return
		}
	}
	for _, item := range parsed.Certs {
		r.upsert(item)
	}

	desiredCAs := r.desiredCAs
	r.removeOrphans(opnapi.TrustCert, desiredUUIDs(parsed.Certs))
	if r.hasOrphans(opnapi.TrustCA, desiredCAs) && r.changed {
		// What was written or removed above changes which CAs are named as
		// issuers, and how many name them: OPNsense re-links every
		// certificate when a CA is written.
		if !r.refresh(opnapi.TrustCA, false) || !r.refresh(opnapi.TrustCert, false) {
			return
		}
	}
	r.removeOrphans(opnapi.TrustCA, desiredCAs)
}

// settlePending records what is still owed: the renewals whose reloads did not
// run or finish, and a web GUI restart until it has started.
func (r *trustRun) settlePending() {
	pending := trustPending{CAs: r.leftCAs, Certs: r.leftCerts, WebGUI: r.webGUIRequested}
	if err := saveTrustPending(pending); err != nil {
		logging.Named("SYNC_API").Warnw("Trust: could not record the renewals waiting for their reloads", "error", err)
	}
}

func desiredUUIDs(items []trustItem) map[string]bool {
	uuids := make(map[string]bool, len(items))
	for _, item := range items {
		uuids[item.UUID] = true
	}
	return uuids
}

// ok records a result item that is not a failure.
func (r *trustRun) ok(item SyncAPIItemResult) {
	r.result.Results = append(r.result.Results, item)
}

// fail records a failed item and fails the task with the same text.
func (r *trustRun) fail(item SyncAPIItemResult) {
	r.result.Results = append(r.result.Results, item)
	r.result.Errors = append(r.result.Errors, item.Error)
	r.result.Success = false
}

// discover reads both stores. A store that cannot be read stops the family:
// nothing can be compared or removed without it. With nothing to write, a
// store the device does not have (404) holds nothing of NetDefense's.
func (r *trustRun) discover(nothingToWrite bool) bool {
	return r.refresh(opnapi.TrustCA, nothingToWrite) && r.refresh(opnapi.TrustCert, nothingToWrite)
}

func (r *trustRun) refresh(kind opnapi.TrustKind, absentIsEmpty bool) bool {
	objects, err := r.client.ListTrust(r.ctx, kind)
	var apiErr *opnapi.TrustAPIError
	if err != nil && absentIsEmpty && errors.As(err, &apiErr) && apiErr.IsNotFound() {
		objects, err = nil, nil
	}
	if err != nil {
		resultType, what := trustTypeCA, "CAs"
		if kind == opnapi.TrustCert {
			resultType, what = trustTypeCert, "certificates"
		}
		logging.Named("SYNC_API").Errorw("Trust: could not list the device's trust store", "kind", string(kind), "error", err)
		r.fail(SyncAPIItemResult{Type: resultType, Action: "discover", Status: "error",
			Error: fmt.Sprintf("%s: could not list the device's %s (%v); no CA or certificate was changed after this point", resultType, what, err)})
		return false
	}
	if kind == opnapi.TrustCA {
		r.cas = objects
	} else {
		r.certs = objects
	}
	return true
}

// store puts what was read of one object in place of what the run held.
func (r *trustRun) store(kind opnapi.TrustKind, obj opnapi.TrustObject) {
	list := &r.certs
	if kind == opnapi.TrustCA {
		list = &r.cas
	}
	for i := range *list {
		if (*list)[i].UUID == obj.UUID {
			(*list)[i] = obj
			return
		}
	}
	*list = append(*list, obj)
}

func (r *trustRun) anyManaged() bool {
	for _, list := range [][]opnapi.TrustObject{r.cas, r.certs} {
		for _, obj := range list {
			if obj.IsManaged() {
				return true
			}
		}
	}
	return false
}

func (r *trustRun) live(kind opnapi.TrustKind) []opnapi.TrustObject {
	if kind == opnapi.TrustCA {
		return r.cas
	}
	return r.certs
}

func findTrust(objects []opnapi.TrustObject, uuid string) *opnapi.TrustObject {
	for i := range objects {
		if objects[i].UUID == uuid {
			return &objects[i]
		}
	}
	return nil
}

// upsert makes one CA or certificate on the device match the payload.
func (r *trustRun) upsert(item trustItem) {
	label := fmt.Sprintf("%s %q", item.resultType(), item.Name)
	// A copy: what the run holds is replaced by what is read back.
	var live *opnapi.TrustObject
	if found := findTrust(r.live(item.Kind), item.UUID); found != nil {
		before := *found
		live = &before
	}
	unchanged := SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "unchanged", Status: "success"}

	// The issuer checks run on every pass, written or not: OPNsense links
	// certificates to CAs by name and re-links them whenever a CA is
	// written, a hand-made one included, so a sync that changes nothing can
	// still find a certificate linked to a CA that did not issue it.
	expectedCARef := ""
	if item.Kind == opnapi.TrustCA {
		if other := r.caNameConflict(item); other != "" {
			r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "blocked", Status: "blocked", Code: trustCodeCADNConflict,
				Error: fmt.Sprintf("%s: %s: %s has the same subject name and a different key. OPNsense links a certificate to its CA by subject name only, so it cannot tell the two apart. Give a new CA a new subject name (for example ending in G2)",
					trustCodeCADNConflict, label, other)})
			return
		}
		if live != nil && r.matches(item, *live) && !r.caIssuerLost(item, *live) {
			r.ok(unchanged)
			return
		}
		// A CA whose issuer is on the device while OPNsense records none for
		// it (its issuer was deleted, or came after it) is written again:
		// OPNsense links a CA to its issuer only when the CA is imported.
	} else {
		link := r.opnsenseIssuer(item.Cert)
		if live != nil && r.matches(item, *live) {
			switch recorded := r.caByRef(live.CARef); {
			case recorded != nil && signs(recorded.Cert, item.Cert):
				r.ok(unchanged)
				return
			case recorded != nil:
				r.mislinked(item, label, *recorded, false)
				return
			case link == nil:
				// No CA on the device carries its issuer's name: nothing to link.
				r.ok(unchanged)
				return
			}
			// Its recorded issuer is gone: written again, OPNsense links it.
		}
		if link != nil && !signs(link.Cert, item.Cert) && (live == nil || live.CARef != link.RefID) {
			// The write would link it to a CA that did not issue it. One that
			// is linked to that CA already is written all the same, and is
			// reported after the write: its chain gets no worse, and the
			// certificate it replaces must not run out.
			r.mislinked(item, label, *link, false)
			return
		}
		if link != nil {
			expectedCARef = link.RefID
		}
	}

	// The write checks run in order and the first to refuse reports: those the
	// device's store decides, then the device's release, then the owner's
	// policy. A name is checked when the object would take it: on create and
	// on rename.
	if (live == nil || live.Descr != item.Name) && r.unmanagedNamed(item.Kind, item.Name) != nil {
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "blocked", Status: "blocked", Code: trustCodeNameCollision,
			Error: fmt.Sprintf("%s: %s: a %s with this name exists on the device that NetDefense does not manage; it is never adopted. Rename or delete it on the device, or rename the snippet",
				trustCodeNameCollision, label, trustNoun(item.Kind))})
		return
	}
	if item.Kind == opnapi.TrustCA && live != nil && live.Cert != nil &&
		(!bytes.Equal(live.Cert.RawSubject, item.Cert.RawSubject) || opnapi.PublicKeyFingerprint(live.Cert) != opnapi.PublicKeyFingerprint(item.Cert)) {
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "blocked", Status: "blocked", Code: trustCodeCARekeyed,
			Error: fmt.Sprintf("%s: %s: the certificate has a different subject or key than the CA on the device, and the certificates it issued would no longer chain to it. A CA rollover is a new CA with a new subject name (for example ending in G2), in a new snippet",
				trustCodeCARekeyed, label)})
		return
	}
	if why := r.tooOld(); why != "" {
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "blocked", Status: "blocked", Code: trustCodeOPNsenseTooOld,
			Error: fmt.Sprintf("%s: %s: %s, and certificate sync writes only to OPNsense %s or later; nothing was written",
				trustCodeOPNsenseTooOld, label, why, minimumSupportedRelease())})
		return
	}
	if r.rejectDangerous {
		fields := []string{"crt"}
		if item.Kind == opnapi.TrustCert {
			fields = append(fields, "key")
		}
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "rejected", Status: "blocked", Code: trustCodeRejectedDangerous,
			Error: dangerousSnippetRejectionMessage(item.resultType(), item.Name, fields)})
		return
	}

	action, verb := "created", "create"
	if live != nil {
		action, verb = "updated", "update"
	}
	var err error
	r.changed = true
	if item.Kind == opnapi.TrustCA {
		r.caWritten = true
		err = r.client.SetTrustCA(r.ctx, item.UUID, opnapi.TrustCAWrite{Descr: item.Name, CrtPEM: item.CertPEM})
	} else {
		err = r.client.SetTrustCert(r.ctx, item.UUID, opnapi.TrustCertWrite{Descr: item.Name, CrtPEM: item.CertPEM, KeyPEM: item.KeyPEM, CARef: expectedCARef})
	}
	if err != nil {
		logging.Named("SYNC_API").Errorw("Trust: write refused", "type", item.resultType(), "uuid", item.UUID, "error", err)
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: verb, Status: "error", Code: trustCodeImportFailed,
			Error: fmt.Sprintf("%s: %s: the firewall refused the %s (%v)", trustCodeImportFailed, label, verb, err)})
		r.recheck(item, live)
		return
	}

	stored, found, problem := r.readBack(item, live, expectedCARef)
	if found && item.Kind == opnapi.TrustCert && problem == "" {
		if recorded := r.caByRef(stored.CARef); recorded != nil && !signs(recorded.Cert, item.Cert) {
			r.noteRenewal(item, live, stored)
			r.mislinked(item, label, *recorded, true)
			return
		}
	}
	if problem != "" {
		r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: verb, Status: "error", Code: trustCodeImportFailed,
			Error: fmt.Sprintf("%s: %s: %s", trustCodeImportFailed, label, problem)})
		if found {
			r.noteRenewal(item, live, stored)
		} else {
			r.recheck(item, live)
		}
		return
	}
	r.noteRenewal(item, live, stored)
	r.ok(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: action, Status: "success"})
}

// recheck reads an object again after a write whose answer or read-back
// failed: the write may have landed all the same, and a renewal that did is
// reloaded like any other. When the object cannot be read either, a write that
// carried another certificate counts as a renewal: reloading what uses it costs
// a moment, missing a renewal leaves a service on the old certificate.
func (r *trustRun) recheck(item trustItem, before *opnapi.TrustObject) {
	if before == nil {
		return
	}
	stored, found, err := r.client.GetTrust(r.ctx, item.Kind, item.UUID)
	switch {
	case err != nil:
		if item.CertSHA256 != before.CertSHA256 {
			r.addRenewed(item.Kind, renewedTrust{RefID: before.RefID, Name: item.Name})
		}
	case found:
		r.store(item.Kind, stored)
		r.noteRenewal(item, before, stored)
	}
}

// noteRenewal records an in-place renewal: an object that was on the device
// before this pass and now holds another certificate.
func (r *trustRun) noteRenewal(item trustItem, before *opnapi.TrustObject, after opnapi.TrustObject) {
	if before == nil || after.CertSHA256 == "" || after.CertSHA256 == before.CertSHA256 {
		return
	}
	renewed := renewedTrust{RefID: after.RefID, Name: item.Name}
	if renewed.RefID == "" {
		renewed.RefID = before.RefID
	}
	r.addRenewed(item.Kind, renewed)
}

// addRenewed records a renewal and keeps it on disk until its reloads ran.
func (r *trustRun) addRenewed(kind opnapi.TrustKind, renewed renewedTrust) {
	if renewed.RefID == "" {
		return
	}
	list := &r.renewedCerts
	if kind == opnapi.TrustCA {
		list = &r.renewedCAs
	}
	for _, known := range *list {
		if known.RefID == renewed.RefID {
			return
		}
	}
	*list = append(*list, renewed)
	if err := saveTrustPending(trustPending{CAs: r.renewedCAs, Certs: r.renewedCerts, WebGUI: r.webGUIOwed}); err != nil {
		logging.Named("SYNC_API").Warnw("Trust: could not record a renewal waiting for its reloads", "error", err)
	}
}

// caNameConflict names another CA, on the device or in this pass, whose
// subject name is the item's and whose key is not; "" when there is none.
// OPNsense links certificates to CAs by subject name alone and picks the newest
// of a name, so two such CAs would hand each other's certificates around.
func (r *trustRun) caNameConflict(item trustItem) string {
	if item.Kind != opnapi.TrustCA {
		return ""
	}
	key := opnapi.PublicKeyFingerprint(item.Cert)
	for _, ca := range r.cas {
		if ca.UUID != item.UUID && ca.Cert != nil && sameSubject(ca.Cert, item.Cert) && opnapi.PublicKeyFingerprint(ca.Cert) != key {
			return fmt.Sprintf("the CA %q on the device", ca.Descr)
		}
	}
	for _, other := range r.payloadCAs {
		if other.UUID != item.UUID && sameSubject(other.Cert, item.Cert) && opnapi.PublicKeyFingerprint(other.Cert) != key {
			return fmt.Sprintf("the CA %q in this sync", other.Name)
		}
	}
	return ""
}

// sameSubject reports whether two certificates carry the same subject name,
// compared by its attributes whatever their encoding, as OPNsense compares.
func sameSubject(a, b *x509.Certificate) bool {
	return bytes.Equal(a.RawSubject, b.RawSubject) || a.Subject.String() == b.Subject.String()
}

// tooOld says why this device takes no trust writes, "" when it does: a
// release below the supported floor, or one that cannot be read. It is read
// once per pass, before the first write; removals do not ask.
func (r *trustRun) tooOld() string {
	if !r.releaseRead {
		r.releaseRead = true
		r.release, r.releaseErr = r.client.InstalledRelease(r.ctx)
	}
	switch {
	case r.releaseErr != nil:
		return "the OPNsense release of this device could not be read"
	case !r.release.AtLeast(opnapi.MinSupportedOPNsenseMajor, opnapi.MinSupportedOPNsenseMinor, opnapi.MinSupportedOPNsensePatch):
		return fmt.Sprintf("this device runs OPNsense %s", r.release.String())
	}
	return ""
}

// matches reports whether the object on the device already holds what the
// payload asks for: the same certificate and key (by DER fingerprint, never by
// PEM text) and the same name. A certificate's issuer is judged apart.
func (r *trustRun) matches(item trustItem, live opnapi.TrustObject) bool {
	if live.CertSHA256 != item.CertSHA256 || live.Descr != item.Name {
		return false
	}
	return item.Kind == opnapi.TrustCA || live.KeySHA256 == item.KeySHA256
}

// caByRef is the CA on the device with this refid, nil when there is none.
func (r *trustRun) caByRef(refid string) *opnapi.TrustObject {
	if refid == "" {
		return nil
	}
	for i := range r.cas {
		if r.cas[i].RefID == refid {
			return &r.cas[i]
		}
	}
	return nil
}

// caIssuerLost reports whether a CA that is not self-issued has lost its issuer
// link: OPNsense records none, or one that is gone, while a CA on the device
// issued it.
func (r *trustRun) caIssuerLost(item trustItem, live opnapi.TrustObject) bool {
	if bytes.Equal(item.Cert.RawIssuer, item.Cert.RawSubject) || r.caByRef(live.CARef) != nil {
		return false
	}
	for _, ca := range r.cas {
		if ca.UUID != item.UUID && signs(ca.Cert, item.Cert) {
			return true
		}
	}
	return false
}

// opnsenseIssuer is the CA OPNsense links cert to (Cert::linkCaRefs), nil when
// none qualifies. A CA qualifies when every value of its subject name occurs
// among the values of the certificate's issuer name, whatever attribute
// carries it (compare_issuer); the one with the most attribute types wins, then
// the newest refid. So a root "CN=Acme,O=Acme" qualifies for a certificate its
// intermediate "CN=Acme Issuing CA,O=Acme" issued.
func (r *trustRun) opnsenseIssuer(cert *x509.Certificate) *opnapi.TrustObject {
	issuer := opnsenseNameOf(cert.Issuer)
	var best *opnapi.TrustObject
	bestKey := ""
	for i := range r.cas {
		ca := &r.cas[i]
		if ca.Cert == nil {
			continue
		}
		subject := opnsenseNameOf(ca.Cert.Subject)
		if !subject.within(issuer) {
			continue
		}
		if key := fmt.Sprintf("%04d-%s", subject.types, ca.RefID); best == nil || key > bestKey {
			best, bestKey = ca, key
		}
	}
	return best
}

// opnsenseName is a name the way OPNsense compares names: one value per
// attribute type (a list for a type that occurs more than once), the types
// themselves ignored.
type opnsenseName struct {
	types  int
	values []string
}

func opnsenseNameOf(name pkix.Name) opnsenseName {
	byType := map[string][]string{}
	var order []string
	for _, atv := range name.Names {
		t := atv.Type.String()
		if _, seen := byType[t]; !seen {
			order = append(order, t)
		}
		byType[t] = append(byType[t], fmt.Sprint(atv.Value))
	}
	n := opnsenseName{types: len(order)}
	for _, t := range order {
		if vals := byType[t]; len(vals) == 1 {
			n.values = append(n.values, "s:"+vals[0])
		} else {
			list, _ := json.Marshal(vals)
			n.values = append(n.values, "a:"+string(list))
		}
	}
	return n
}

// within reports whether every value of n occurs among other's.
func (n opnsenseName) within(other opnsenseName) bool {
	have := make(map[string]bool, len(other.values))
	for _, v := range other.values {
		have[v] = true
	}
	for _, v := range n.values {
		if !have[v] {
			return false
		}
	}
	return true
}

// signs reports whether ca issued cert: cert's issuer is ca's subject and ca's
// key signed it. Go refuses to check SHA-1 and MD5 signatures; for those the
// issuer name alone decides.
func signs(ca, cert *x509.Certificate) bool {
	if ca == nil || cert == nil || !bytes.Equal(cert.RawIssuer, ca.RawSubject) {
		return false
	}
	err := cert.CheckSignatureFrom(ca)
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure)
}

// signedBy reports whether ca issued cert, which is not itself self-issued: a
// self-signed copy of a CA is not something the CA issued.
func signedBy(cert, ca *x509.Certificate) bool {
	if cert == nil || bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return signs(ca, cert)
}

// mislinked refuses a certificate OPNsense links, or would link, to a CA that
// did not issue it. The agent does not write an issuer against OPNsense's
// choice: OPNsense would link it the same way on the next write.
func (r *trustRun) mislinked(item trustItem, label string, ca opnapi.TrustObject, written bool) {
	done := "Nothing was written"
	if written {
		done = "The certificate was written"
	}
	r.fail(SyncAPIItemResult{Type: item.resultType(), UUID: item.UUID, Name: item.Name, Action: "blocked", Status: "blocked", Code: trustCodeIssuerMislinked,
		Error: fmt.Sprintf("%s: %s: OPNsense links it to the CA %q, which did not issue it: OPNsense picks a CA whose subject name values all occur in the certificate's issuer name. %s. Remove the CA %q from the device, or re-issue it with a subject name that does not overlap",
			trustCodeIssuerMislinked, label, ca.Descr, done, ca.Descr)})
}

// parentsFirst orders CAs so that one comes after the CA in the payload that
// issued it. OPNsense breaks ties between matching CAs by the newest refid, so
// a CA created after its issuer wins over it for the certificates it issued.
func parentsFirst(items []trustItem) []trustItem {
	placed := make([]bool, len(items))
	out := make([]trustItem, 0, len(items))
	for len(out) < len(items) {
		progress := false
		for i, item := range items {
			if placed[i] {
				continue
			}
			waiting := false
			for j, other := range items {
				if j != i && !placed[j] && signedBy(item.Cert, other.Cert) {
					waiting = true
					break
				}
			}
			if !waiting {
				placed[i], progress = true, true
				out = append(out, item)
			}
		}
		if !progress {
			// Two CAs that issued each other: the rest keeps payload order.
			for i, item := range items {
				if !placed[i] {
					placed[i] = true
					out = append(out, item)
				}
			}
		}
	}
	return out
}

// unmanagedNamed is an object of the kind, not NetDefense's, whose name is
// item's, compared the way a person would read them.
func (r *trustRun) unmanagedNamed(kind opnapi.TrustKind, name string) *opnapi.TrustObject {
	for _, obj := range r.live(kind) {
		if !obj.IsManaged() && strings.EqualFold(strings.TrimSpace(obj.Descr), strings.TrimSpace(name)) {
			o := obj
			return &o
		}
	}
	return nil
}

// readBack reads the object again after a write (get, not the whole store)
// and checks it holds what was sent: the certificate, the key, the name, the
// issuer, and on an update the refid it had, which is what keeps its bindings.
// found is whether the device holds the object at all.
func (r *trustRun) readBack(item trustItem, before *opnapi.TrustObject, expectedCARef string) (stored opnapi.TrustObject, found bool, problem string) {
	stored, found, err := r.client.GetTrust(r.ctx, item.Kind, item.UUID)
	if err != nil {
		return opnapi.TrustObject{}, false, fmt.Sprintf("the write was answered but the object could not be read back (%v)", err)
	}
	if !found {
		return opnapi.TrustObject{}, false, "the firewall answered the write but holds no object with this uuid"
	}
	r.store(item.Kind, stored)
	switch {
	case stored.CertSHA256 != item.CertSHA256:
		return stored, true, "the firewall stored a different certificate than the one sent"
	case stored.Descr != item.Name:
		return stored, true, "the firewall stored a different name than the one sent"
	case stored.RefID == "":
		return stored, true, "the firewall stored the object without a refid"
	case before != nil && before.RefID != "" && stored.RefID != before.RefID:
		return stored, true, "the firewall changed the object's refid, so services bound to it lost it"
	}
	if item.Kind == opnapi.TrustCert {
		if stored.KeySHA256 != item.KeySHA256 {
			return stored, true, "the firewall stored a different private key than the one sent"
		}
		if stored.CARef == "" && expectedCARef != "" {
			return stored, true, "the firewall recorded no issuer, though a CA on the device issued the certificate"
		}
		if stored.CARef != "" && r.caByRef(stored.CARef) == nil {
			return stored, true, "the firewall recorded an issuer that is not on the device"
		}
	}
	return stored, true, ""
}

func trustNoun(kind opnapi.TrustKind) string {
	if kind == opnapi.TrustCA {
		return "CA"
	}
	return "certificate"
}

// hasOrphans reports whether a managed object of the kind is not in desired.
func (r *trustRun) hasOrphans(kind opnapi.TrustKind, desired map[string]bool) bool {
	for _, obj := range r.live(kind) {
		if obj.IsManaged() && !desired[obj.UUID] {
			return true
		}
	}
	return false
}

// removeOrphans removes the managed objects of a kind the payload no longer
// names, unless something still uses them. OPNsense refuses to delete a
// certificate a setting names (references from other certificates and local
// accounts aside) and does not guard a CA at all, so the agent checks both.
func (r *trustRun) removeOrphans(kind opnapi.TrustKind, desired map[string]bool) {
	resultType := trustTypeCA
	if kind == opnapi.TrustCert {
		resultType = trustTypeCert
	}
	var orphans []opnapi.TrustObject
	for _, obj := range r.live(kind) {
		if obj.IsManaged() && !desired[obj.UUID] {
			orphans = append(orphans, obj)
		}
	}
	if kind == opnapi.TrustCA {
		// A CA goes before the CA that issued it, and the CAs are read again
		// after each delete, so a chain that leaves in one pass goes in one.
		orphans = childrenFirst(orphans)
	}
	for i, orphan := range orphans {
		found := findTrust(r.live(kind), orphan.UUID)
		if found == nil {
			continue
		}
		obj := *found
		label := fmt.Sprintf("%s %q", resultType, obj.Descr)
		users, known := r.usersOf(kind, obj)
		if !known {
			r.fail(SyncAPIItemResult{Type: resultType, UUID: obj.UUID, Name: obj.Descr, Action: "delete", Status: "error",
				Error: fmt.Sprintf("%s: not removed: the device configuration could not be read to check what uses it", label)})
			continue
		}
		if len(users) > 0 {
			r.fail(SyncAPIItemResult{Type: resultType, UUID: obj.UUID, Name: obj.Descr, Action: "retained", Status: "blocked", Code: trustCodeInUse,
				Error: fmt.Sprintf("%s: %s was not removed: it is still used by %s. Stop using it on the device, then sync again",
					trustCodeInUse, label, strings.Join(users, ", "))})
			continue
		}
		r.changed = true
		if err := r.client.DeleteTrust(r.ctx, kind, obj.UUID); err != nil {
			logging.Named("SYNC_API").Errorw("Trust: delete refused", "type", resultType, "uuid", obj.UUID, "error", err)
			r.fail(SyncAPIItemResult{Type: resultType, UUID: obj.UUID, Name: obj.Descr, Action: "delete", Status: "error",
				Error: fmt.Sprintf("%s: the firewall refused the delete (%v)", label, err)})
			continue
		}
		r.ok(SyncAPIItemResult{Type: resultType, UUID: obj.UUID, Name: obj.Descr, Action: "deleted", Status: "success"})
		if kind == opnapi.TrustCA && i < len(orphans)-1 && !r.refresh(opnapi.TrustCA, false) {
			return
		}
	}
}

// childrenFirst orders CAs so that one comes before the CA that issued it, or
// that OPNsense records as its issuer.
func childrenFirst(cas []opnapi.TrustObject) []opnapi.TrustObject {
	placed := make([]bool, len(cas))
	out := make([]opnapi.TrustObject, 0, len(cas))
	for len(out) < len(cas) {
		progress := false
		for i, ca := range cas {
			if placed[i] {
				continue
			}
			waiting := false
			for j, other := range cas {
				if j != i && !placed[j] && (signedBy(other.Cert, ca.Cert) || (ca.RefID != "" && other.CARef == ca.RefID)) {
					waiting = true
					break
				}
			}
			if !waiting {
				placed[i], progress = true, true
				out = append(out, ca)
			}
		}
		if !progress {
			for i, ca := range cas {
				if !placed[i] {
					placed[i] = true
					out = append(out, ca)
				}
			}
		}
	}
	return out
}

// usersOf names what still uses an object; known is false when the device
// configuration could not be read. A certificate is used when OPNsense says so
// or a service names it; a CA when a certificate or another CA names it as its
// issuer or was signed by it (OPNsense may have linked that one to another CA
// of the same name), or a service names it.
func (r *trustRun) usersOf(kind opnapi.TrustKind, obj opnapi.TrustObject) ([]string, bool) {
	var users []string
	seen := map[string]bool{}
	add := func(user string) {
		if !seen[user] {
			seen[user] = true
			users = append(users, user)
		}
	}
	// A copy of a CA (the same subject and key) that stays serves whatever
	// the CA serves: what it signed chains to the copy, and what names it is
	// linked to the copy once it is gone (OPNsense links every certificate
	// again at the next CA write, and the next pass writes a NetDefense
	// object whose issuer is gone). So only a service keeps it then.
	copyStays := kind == opnapi.TrustCA && r.copyStays(obj)
	if kind == opnapi.TrustCA && !copyStays {
		for _, cert := range r.certs {
			if (obj.RefID != "" && cert.CARef == obj.RefID) || signedBy(cert.Cert, obj.Cert) {
				add(fmt.Sprintf("certificate %q", cert.Descr))
			}
		}
		for _, ca := range r.cas {
			if ca.UUID != obj.UUID && ((obj.RefID != "" && ca.CARef == obj.RefID) || signedBy(ca.Cert, obj.Cert)) {
				add(fmt.Sprintf("CA %q", ca.Descr))
			}
		}
	}
	if obj.RefID != "" {
		cfg, err := r.deviceConfig()
		if err != nil {
			return nil, false
		}
		for _, c := range cfg.consumersOf(obj.RefID, false) {
			add(c.Label)
		}
	}
	if len(users) == 0 {
		switch {
		case kind == opnapi.TrustCA && obj.RefCount > 0 && !copyStays:
			users = append(users, fmt.Sprintf("%d object(s) that name it as their issuer", obj.RefCount))
		case kind == opnapi.TrustCert && obj.InUse:
			users = append(users, "a service or account on the device")
		}
	}
	return users, true
}

// copyStays reports whether another CA with obj's subject and key stays on
// the device: one NetDefense does not manage, or one the payload names.
func (r *trustRun) copyStays(obj opnapi.TrustObject) bool {
	if obj.Cert == nil {
		return false
	}
	key := opnapi.PublicKeyFingerprint(obj.Cert)
	for _, ca := range r.cas {
		if ca.UUID != obj.UUID && ca.Cert != nil && bytes.Equal(ca.Cert.RawSubject, obj.Cert.RawSubject) &&
			opnapi.PublicKeyFingerprint(ca.Cert) == key && (!ca.IsManaged() || r.desiredCAs[ca.UUID]) {
			return true
		}
	}
	return false
}

// deviceConfig reads config.xml once per pass, after the writes.
func (r *trustRun) deviceConfig() (*trustConfig, error) {
	if !r.configRead {
		r.configRead = true
		r.config, r.configErr = readTrustConfig(r.configXMLPath)
		if r.configErr != nil {
			logging.Named("SYNC_API").Errorw("Trust: could not read the device configuration", "path", r.configXMLPath, "error", r.configErr)
		}
	}
	return r.config, r.configErr
}
