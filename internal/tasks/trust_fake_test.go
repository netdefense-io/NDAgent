package tasks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// testCA is a CA of a test PKI: its certificate and key.
type testCA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM string
}

var testSerial int64 = 100

func nextSerial() *big.Int {
	testSerial++
	return big.NewInt(testSerial)
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func certPEMOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newTestCA makes a CA named cn, self-signed when parent is nil. key may be
// nil for a fresh one; passing a CA's key re-issues it (a renewal).
func newTestCA(t *testing.T, cn string, parent *testCA, key crypto.Signer) *testCA {
	t.Helper()
	if key == nil {
		key = newECKey(t)
	}
	template := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"NetDefense Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, certPEM: certPEMOf(der)}
}

// testLeaf is a server certificate and its key.
type testLeaf struct {
	cert    *x509.Certificate
	certPEM string
	keyPEM  string
}

// issue makes a server certificate for cn signed by ca, with an EC key in
// PKCS#8 or, with rsaKey, an RSA key in PKCS#1.
func (ca *testCA) issue(t *testing.T, cn string, rsaKey bool) testLeaf {
	t.Helper()
	var key crypto.Signer
	var keyBlock *pem.Block
	if rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	} else {
		k := newECKey(t)
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	template := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testLeaf{cert: cert, certPEM: certPEMOf(der), keyPEM: string(pem.EncodeToMemory(keyBlock))}
}

// trustSnippet renders one TRUST_* snippet of a SYNC payload.
func trustSnippet(configType, name string, content map[string]string) map[string]interface{} {
	raw, _ := json.Marshal(content)
	return map[string]interface{}{
		"config_type":  configType,
		"snippet_name": name,
		"content":      string(raw),
	}
}

func caSnippet(uuid, name string, ca *testCA) map[string]interface{} {
	return trustSnippet("TRUST_CA", name, map[string]string{"uuid": uuid, "name": name, "crt": ca.certPEM})
}

func certSnippet(uuid, name string, leaf testLeaf) map[string]interface{} {
	return trustSnippet("TRUST_CERT", name, map[string]string{"uuid": uuid, "name": name, "crt": leaf.certPEM, "key": leaf.keyPEM})
}

func trustPayload(snippets ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, len(snippets))
	for i, s := range snippets {
		list[i] = s
	}
	return map[string]interface{}{"snippets": list}
}

// fakeTrustObject is a row of the fake trust store.
type fakeTrustObject struct {
	uuid, refid, descr, caref string
	crtPEM, prvPEM            string
	inUse                     bool
}

// fakeTrust stands in for /api/trust/ca and /api/trust/cert. Rows carry what a
// 26.x search row and get carry, private keys included (prv, prv_payload), so
// the agent is tested against the answers it has to keep to itself. A set mints
// the refid on create and keeps it on update. It links issuers as OPNsense
// does (linkCaRefs): a cert set records the caref it was sent, then links the
// certificate to a CA by name; a CA set links every certificate again.
type fakeTrust struct {
	t      *testing.T
	mu     sync.Mutex
	cas    []*fakeTrustObject
	certs  []*fakeTrustObject
	writes []string
	bodies []map[string]interface{}
	nextID int

	// failSet, failGet and failDel answer the request for that uuid with the
	// status and body given; failSearch does the same for a kind's search.
	// applyFailedSet stores the write before answering with the failure.
	failSet        map[string]fakeFailure
	failGet        map[string]fakeFailure
	failDel        map[string]fakeFailure
	failSearch     map[opnapi.TrustKind]fakeFailure
	applyFailedSet bool
	// searchesBeforeFailing lets that many searches of a kind through before
	// failSearch applies.
	searchesBeforeFailing map[opnapi.TrustKind]int
	// requests counts every request the fake answered, searches its searches.
	requests int
	searches map[opnapi.TrustKind]int
	gets     int
	// storeOther makes a set for that uuid store this PEM instead of the one
	// sent, as a reissue would.
	storeOther map[string]string
	// keepCAref makes a cert set ignore the caref it was sent.
	keepCAref bool

	server *httptest.Server
	client *opnapi.Client
}

type fakeFailure struct {
	status int
	body   string
}

func newFakeTrust(t *testing.T) *fakeTrust {
	t.Helper()
	f := &fakeTrust{
		t:          t,
		nextID:     1000,
		failSet:    map[string]fakeFailure{},
		failGet:    map[string]fakeFailure{},
		failDel:    map[string]fakeFailure{},
		failSearch: map[opnapi.TrustKind]fakeFailure{},
		storeOther: map[string]string{},
		searches:   map[opnapi.TrustKind]int{},

		searchesBeforeFailing: map[opnapi.TrustKind]int{},
	}
	mux := http.NewServeMux()
	// The release is read from a version file the test writes; the API is
	// the last source, and this device does not answer it.
	mux.HandleFunc("/core/firmware/status", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	for _, kind := range []opnapi.TrustKind{opnapi.TrustCA, opnapi.TrustCert} {
		kind := kind
		mux.HandleFunc("/trust/"+string(kind)+"/search", func(w http.ResponseWriter, r *http.Request) { f.search(w, kind) })
		mux.HandleFunc("/trust/"+string(kind)+"/get/", func(w http.ResponseWriter, r *http.Request) { f.get(w, r, kind) })
		mux.HandleFunc("/trust/"+string(kind)+"/set/", func(w http.ResponseWriter, r *http.Request) { f.set(w, r, kind) })
		mux.HandleFunc("/trust/"+string(kind)+"/del/", func(w http.ResponseWriter, r *http.Request) { f.del(w, r, kind) })
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	f.client = opnapi.NewClient(f.server.URL, "key", "secret", true)
	useTrustRelease(t, "26.7.4")
	usePendingFile(t)
	return f
}

// useTrustRelease makes the device's OPNsense release read as version.
func useTrustRelease(t *testing.T, version string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(path, []byte(`{"product_version":"`+version+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opnapi.SetVersionFileForTest(path))
	t.Cleanup(opnapi.SetCommandOutputForTest(func(*exec.Cmd) ([]byte, error) { return nil, errors.New("opnsense-version is not available") }))
}

// usePendingFile keeps the renewals waiting for their reloads in a file of the
// test's own, and returns its path.
func usePendingFile(t *testing.T) string {
	t.Helper()
	prev := trustPendingPath
	trustPendingPath = filepath.Join(t.TempDir(), "trust-pending-reloads.json")
	t.Cleanup(func() { trustPendingPath = prev })
	return trustPendingPath
}

// requestCount is how many requests the fake answered.
func (f *fakeTrust) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// getCount is how many gets the fake answered.
func (f *fakeTrust) getCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets
}

// searchCount is how many searches of a kind the fake answered.
func (f *fakeTrust) searchCount(kind opnapi.TrustKind) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.searches[kind]
}

func (f *fakeTrust) list(kind opnapi.TrustKind) *[]*fakeTrustObject {
	if kind == opnapi.TrustCA {
		return &f.cas
	}
	return &f.certs
}

// add puts an object on the device before the run, with a refid of its own.
func (f *fakeTrust) add(kind opnapi.TrustKind, uuid, descr, crtPEM, prvPEM, caref string) *fakeTrustObject {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	obj := &fakeTrustObject{uuid: uuid, refid: fmt.Sprintf("66f0%09x", f.nextID), descr: descr, crtPEM: crtPEM, prvPEM: prvPEM, caref: caref}
	list := f.list(kind)
	*list = append(*list, obj)
	return obj
}

func (f *fakeTrust) find(kind opnapi.TrustKind, uuid string) *fakeTrustObject {
	for _, obj := range *f.list(kind) {
		if obj.uuid == uuid {
			return obj
		}
	}
	return nil
}

func (f *fakeTrust) search(w http.ResponseWriter, kind opnapi.TrustKind) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches[kind]++
	if fail, ok := f.failSearch[kind]; ok && f.searches[kind] > f.searchesBeforeFailing[kind] {
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	rows := []map[string]interface{}{}
	for _, obj := range *f.list(kind) {
		rows = append(rows, f.row(kind, obj, false))
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
}

// row renders an object as a search row or a get spells it; a get spells caref
// as an option list.
func (f *fakeTrust) row(kind opnapi.TrustKind, obj *fakeTrustObject, get bool) map[string]interface{} {
	row := map[string]interface{}{
		"refid":       obj.refid,
		"descr":       obj.descr,
		"caref":       obj.caref,
		"crt":         base64.StdEncoding.EncodeToString([]byte(obj.crtPEM)),
		"crt_payload": obj.crtPEM,
		"prv":         base64.StdEncoding.EncodeToString([]byte(obj.prvPEM)),
		"prv_payload": obj.prvPEM,
	}
	if get {
		options := map[string]interface{}{"": map[string]interface{}{"value": "none", "selected": 0}}
		for _, ca := range f.cas {
			selected := 0
			if ca.refid == obj.caref {
				selected = 1
			}
			options[ca.refid] = map[string]interface{}{"value": ca.descr, "selected": selected}
		}
		row["caref"] = options
	} else {
		row["uuid"] = obj.uuid
	}
	if kind == opnapi.TrustCA {
		count := 0
		for _, list := range [][]*fakeTrustObject{f.cas, f.certs} {
			for _, other := range list {
				if other != obj && other.caref == obj.refid {
					count++
				}
			}
		}
		row["refcount"] = fmt.Sprint(count)
	} else {
		row["in_use"] = map[bool]string{true: "1", false: "0"}[obj.inUse]
	}
	return row
}

func (f *fakeTrust) get(w http.ResponseWriter, r *http.Request, kind opnapi.TrustKind) {
	uuid := strings.TrimPrefix(r.URL.Path, "/trust/"+string(kind)+"/get/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if fail, ok := f.failGet[uuid]; ok {
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	obj := f.find(kind, uuid)
	if obj == nil {
		_, _ = w.Write([]byte("[]"))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{string(kind): f.row(kind, obj, true)})
}

// phpName is a name as openssl_x509_parse gives it to PHP, each value
// serialized as PHP's serialize() writes it: one entry per attribute type, a
// list for a type that occurs more than once.
func phpName(name pkix.Name) (types int, serialized []string) {
	byType := map[string][]string{}
	var order []string
	for _, atv := range name.Names {
		t := atv.Type.String()
		if _, seen := byType[t]; !seen {
			order = append(order, t)
		}
		byType[t] = append(byType[t], fmt.Sprint(atv.Value))
	}
	phpString := func(v string) string { return fmt.Sprintf("s:%d:%q;", len(v), v) }
	for _, t := range order {
		vals := byType[t]
		if len(vals) == 1 {
			serialized = append(serialized, phpString(vals[0]))
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "a:%d:{", len(vals))
		for i, v := range vals {
			fmt.Fprintf(&b, "i:%d;%s", i, phpString(v))
		}
		b.WriteString("}")
		serialized = append(serialized, b.String())
	}
	return len(order), serialized
}

// compareIssuer is OPNsense's compare_issuer: no value of the subject is
// missing from the issuer's values (array_diff), whatever attribute types
// carry them.
func compareIssuer(subject, issuer []string) bool {
	have := map[string]bool{}
	for _, v := range issuer {
		have[v] = true
	}
	for _, v := range subject {
		if !have[v] {
			return false
		}
	}
	return true
}

func parsedPEM(text string) *x509.Certificate {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// linkCaRefs links certificates to CAs as OPNsense's Cert::linkCaRefs does:
// every certificate, or the one with refid, gets the first CA whose subject
// values all occur in its issuer's, CAs with more subject attribute types
// first and, among those, the highest (newest) refid. It overwrites what was
// there, and leaves it when no CA matches.
func (f *fakeTrust) linkCaRefs(refid string) {
	type candidate struct {
		key     string
		subject []string
		refid   string
	}
	var candidates []candidate
	for _, ca := range f.cas {
		if cert := parsedPEM(ca.crtPEM); cert != nil {
			types, subject := phpName(cert.Subject)
			candidates = append(candidates, candidate{fmt.Sprintf("%04d-%s", types, ca.refid), subject, ca.refid})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].key > candidates[j].key })
	for _, c := range f.certs {
		if refid != "" && c.refid != refid {
			continue
		}
		cert := parsedPEM(c.crtPEM)
		if cert == nil {
			continue
		}
		_, issuer := phpName(cert.Issuer)
		for _, candidate := range candidates {
			if compareIssuer(candidate.subject, issuer) {
				c.caref = candidate.refid
				break
			}
		}
	}
}

// linkImportedCA does what a CA set with action "existing" does besides
// storing it: a CA that is not self-issued is linked to its issuer by name, a
// CA it issued is linked to it, and every certificate is linked again.
func (f *fakeTrust) linkImportedCA(obj *fakeTrustObject) {
	if cert := parsedPEM(obj.crtPEM); cert != nil && cert.Subject.String() != cert.Issuer.String() {
		_, issuer := phpName(cert.Issuer)
		for _, ca := range f.cas {
			other := parsedPEM(ca.crtPEM)
			if ca == obj || other == nil {
				continue
			}
			if _, subject := phpName(other.Subject); compareIssuer(subject, issuer) {
				obj.caref = ca.refid
			} else if other.Issuer.String() == cert.Subject.String() {
				ca.caref = obj.refid
			}
		}
	}
	f.linkCaRefs("")
}

// configXML writes a config.xml that holds the fake's store, as a device's
// does, and body after it.
func (f *fakeTrust) configXML(t *testing.T, body string) string {
	t.Helper()
	f.mu.Lock()
	var b strings.Builder
	for _, kind := range []opnapi.TrustKind{opnapi.TrustCA, opnapi.TrustCert} {
		for _, obj := range *f.list(kind) {
			fmt.Fprintf(&b, "<%s uuid=%q><refid>%s</refid><descr>%s</descr><caref>%s</caref></%s>\n", kind, obj.uuid, obj.refid, obj.descr, obj.caref, kind)
		}
	}
	f.mu.Unlock()
	return writeConfigXML(t, b.String()+body)
}

func (f *fakeTrust) set(w http.ResponseWriter, r *http.Request, kind opnapi.TrustKind) {
	uuid := strings.TrimPrefix(r.URL.Path, "/trust/"+string(kind)+"/set/")
	var body map[string]map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Errorf("set %s: body does not decode: %v", uuid, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "set "+string(kind)+" "+uuid)
	raw := map[string]interface{}{}
	for k, v := range body {
		raw[k] = v
	}
	f.bodies = append(f.bodies, raw)
	fail, failing := f.failSet[uuid]
	if failing && !f.applyFailedSet {
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	fields := body[string(kind)]
	if _, posted := fields["refid"]; posted {
		f.t.Errorf("set %s posted a refid", uuid)
	}
	wantAction := map[opnapi.TrustKind]string{opnapi.TrustCA: "existing", opnapi.TrustCert: "import"}[kind]
	if fields["action"] != wantAction {
		f.t.Errorf("set %s: action = %q, want %q", uuid, fields["action"], wantAction)
	}
	obj := f.find(kind, uuid)
	if obj == nil {
		f.nextID++
		obj = &fakeTrustObject{uuid: uuid, refid: fmt.Sprintf("66f0%09x", f.nextID)}
		list := f.list(kind)
		*list = append(*list, obj)
	}
	obj.descr = fields["descr"]
	obj.crtPEM = fields["crt_payload"]
	if other, ok := f.storeOther[uuid]; ok {
		obj.crtPEM = other
	}
	if kind == opnapi.TrustCert {
		obj.prvPEM = fields["prv_payload"]
		if !f.keepCAref {
			obj.caref = fields["caref"]
		}
		f.linkCaRefs(obj.refid)
	} else {
		f.linkImportedCA(obj)
	}
	if failing {
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
}

func (f *fakeTrust) del(w http.ResponseWriter, r *http.Request, kind opnapi.TrustKind) {
	uuid := strings.TrimPrefix(r.URL.Path, "/trust/"+string(kind)+"/del/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "del "+string(kind)+" "+uuid)
	if fail, ok := f.failDel[uuid]; ok {
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	list := f.list(kind)
	for i, obj := range *list {
		if obj.uuid == uuid {
			*list = append((*list)[:i], (*list)[i+1:]...)
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "deleted"})
			return
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"result": "not found"})
}

func (f *fakeTrust) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

// writeConfigXML writes a config.xml for the consumer scan.
func writeConfigXML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(`<?xml version="1.0"?>`+"\n<opnsense>\n"+body+"\n</opnsense>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRaw(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// recordConfigctl replaces the configctl runner, recording each invocation;
// fail names the invocations that fail.
func recordConfigctl(t *testing.T, fail ...string) *[]string {
	t.Helper()
	var calls []string
	var mu sync.Mutex
	prev := runConfigctlFunc
	runConfigctlFunc = func(_ context.Context, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		call := strings.Join(args, " ")
		calls = append(calls, call)
		for _, f := range fail {
			if f == call {
				return fmt.Errorf("configctl %s exited 1", call)
			}
		}
		return nil
	}
	t.Cleanup(func() { runConfigctlFunc = prev })
	return &calls
}

// Test UUIDs, managed and not.
const (
	uuidRootCA     = "221f3268-1111-4111-8111-000000000001"
	uuidInterCA    = "221f3268-1111-4111-8111-000000000002"
	uuidWildcard   = "221f3268-2222-4222-9222-000000000001"
	uuidHostCert   = "221f3268-2222-4222-9222-000000000002"
	uuidOrphanCert = "221f3268-2222-4222-9222-0000000000ff"
	uuidOrphanCA   = "221f3268-1111-4111-8111-0000000000ff"
	uuidHandMade   = "6f1c2a7e-4c3b-4f60-9d4e-0a8b1c2d3e4f"
)
