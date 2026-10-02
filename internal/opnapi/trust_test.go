package opnapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testCertAndKey(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// A row is read whichever way a release spells it: the PEM or only its
// base64, a reference as a value or as an option list, counts as strings or
// numbers.
func TestTrustObjectFromRow_Shapes(t *testing.T) {
	certPEM, keyPEM := testCertAndKey(t)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	payloadOnly := trustObjectFromRow(TrustCert, map[string]interface{}{
		"uuid": "221f3268-x", "refid": "r1", "descr": "d", "caref": "ca1",
		"crt_payload": certPEM, "prv_payload": keyPEM, "in_use": "1",
	})
	base64Only := trustObjectFromRow(TrustCert, map[string]interface{}{
		"uuid": "u", "refid": "r1", "descr": "d",
		"caref": map[string]interface{}{"": map[string]interface{}{"value": "none", "selected": float64(0)}, "ca1": map[string]interface{}{"value": "CA", "selected": float64(1)}},
		"crt":   b64(certPEM), "prv": b64(keyPEM), "in_use": float64(1),
	})
	for name, obj := range map[string]TrustObject{"PEM": payloadOnly, "base64": base64Only} {
		if obj.Cert == nil || obj.CertSHA256 == "" || obj.KeySHA256 == "" || obj.CARef != "ca1" || !obj.InUse {
			t.Errorf("%s row = %+v", name, obj)
		}
	}
	if payloadOnly.CertSHA256 != base64Only.CertSHA256 || payloadOnly.KeySHA256 != base64Only.KeySHA256 {
		t.Error("the two spellings read differently")
	}
	if !payloadOnly.IsManaged() || base64Only.IsManaged() {
		t.Error("ownership is the 221f3268- prefix")
	}

	ca := trustObjectFromRow(TrustCA, map[string]interface{}{"uuid": "u", "refcount": float64(2), "crt": "not base64!"})
	if ca.RefCount != 2 || ca.Cert != nil || ca.KeySHA256 != "" {
		t.Errorf("CA row = %+v", ca)
	}
}

func TestValidationFields_NamesOnly(t *testing.T) {
	got := validationFields(json.RawMessage(`{"cert.prv_payload":"-----BEGIN PRIVATE KEY-----","cert.descr":"x","<script>":"y","` + strings.Repeat("a", 80) + `":"z"}`))
	if want := []string{"cert.descr", "cert.prv_payload"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fields = %q, want %q", got, want)
	}
	if got := validationFields(json.RawMessage(`[]`)); len(got) != 0 {
		t.Errorf("a list of validations = %q", got)
	}
	if safeResult("failed") != "failed" || safeResult("-----BEGIN PRIVATE KEY-----") != "unexpected" {
		t.Error("safeResult keeps more than a result word")
	}
}

// What the set endpoints are sent: the action that keeps the material, the
// name, and never a refid.
func TestSetTrust_Bodies(t *testing.T) {
	var bodies []map[string]map[string]string
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]map[string]string
		_ = json.Unmarshal(raw, &body)
		bodies = append(bodies, body)
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"result":"saved"}`))
	}))
	defer server.Close()
	c := NewClient(server.URL, "k", "s", true)
	if err := c.SetTrustCA(context.Background(), "221f3268-a", TrustCAWrite{Descr: "Root", CrtPEM: "CA"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTrustCert(context.Background(), "221f3268-b", TrustCertWrite{Descr: "fw", CrtPEM: "C", KeyPEM: "K", CARef: "r"}); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/trust/ca/set/221f3268-a" || paths[1] != "/trust/cert/set/221f3268-b" {
		t.Fatalf("paths = %q", paths)
	}
	ca, cert := bodies[0]["ca"], bodies[1]["cert"]
	if ca["action"] != "existing" || ca["crt_payload"] != "CA" || ca["descr"] != "Root" || len(ca) != 3 {
		t.Errorf("CA body = %v", ca)
	}
	if cert["action"] != "import" || cert["crt_payload"] != "C" || cert["prv_payload"] != "K" || cert["caref"] != "r" || cert["descr"] != "fw" || len(cert) != 5 {
		t.Errorf("cert body = %v", cert)
	}
}

// A get by uuid is read as a search row is, its option-list caref included;
// OPNsense's empty list for an unknown uuid is "not found"; a refusal carries
// its status, never the body.
func TestGetTrust(t *testing.T) {
	certPEM, keyPEM := testCertAndKey(t)
	answers := map[string]struct {
		status int
		body   string
	}{
		"/trust/cert/get/c1": {200, `{"cert":{"refid":"66f0aaaaaaaa1","descr":"fw1","caref":{"":{"value":"none","selected":0},"66f0aaaaaaaa2":{"value":"Root","selected":1}},` +
			`"crt_payload":` + jsonString(certPEM) + `,"prv_payload":` + jsonString(keyPEM) + `,"in_use":"1"}}`},
		"/trust/ca/get/missing": {200, `[]`},
		"/trust/cert/get/fails": {500, `{"errorMessage":` + jsonString(keyPEM) + `}`},
		"/trust/cert/get/junk":  {200, `{"cert":` + jsonString(keyPEM)},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("%s %s, want GET", r.Method, r.URL.Path)
		}
		a := answers[r.URL.Path]
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}))
	defer server.Close()
	c := NewClient(server.URL, "k", "s", true)

	obj, found, err := c.GetTrust(context.Background(), TrustCert, "c1")
	if err != nil || !found {
		t.Fatalf("GetTrust = %v, %v", found, err)
	}
	if obj.UUID != "c1" || obj.RefID != "66f0aaaaaaaa1" || obj.Descr != "fw1" || obj.CARef != "66f0aaaaaaaa2" || !obj.InUse ||
		obj.CertSHA256 == "" || obj.KeySHA256 != PrivateKeyFingerprint([]byte(keyPEM)) {
		t.Errorf("obj = %+v", obj)
	}

	if _, found, err := c.GetTrust(context.Background(), TrustCA, "missing"); err != nil || found {
		t.Errorf("an unknown uuid: found %v, err %v", found, err)
	}
	for _, uuid := range []string{"fails", "junk"} {
		_, _, err := c.GetTrust(context.Background(), TrustCert, uuid)
		if err == nil {
			t.Fatalf("%s: no error", uuid)
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), keyPEM[40:70]) {
			t.Errorf("%s: the error quotes the answer: %v", uuid, err)
		}
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A transport error is reduced to its class: the text net/http gives some of
// them quotes what the device sent.
func TestErrorWithoutText_Classes(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY----- SECRET"
	for _, tc := range []struct {
		err  error
		want error
	}{
		{&json.SyntaxError{}, errTrustUnreadable},
		{context.Canceled, context.Canceled},
		{fmt.Errorf("request failed: %w", context.DeadlineExceeded), context.DeadlineExceeded},
		{&url.Error{Op: "Post", URL: "https://127.0.0.1/api/trust/cert/search", Err: timeoutError{}}, errTrustTimedOut},
		{&url.Error{Op: "Post", URL: "u", Err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}, errTrustRefused},
		{&url.Error{Op: "Post", URL: "u", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}, errTrustTLS},
		{&url.Error{Op: "Post", URL: "u", Err: io.ErrUnexpectedEOF}, errTrustClosed},
		{&url.Error{Op: "Post", URL: "u", Err: fmt.Errorf("malformed HTTP response %q", secret)}, errTrustFailed},
		{errors.New(secret), errTrustFailed},
	} {
		got := errorWithoutText(tc.err)
		if !errors.Is(got, tc.want) || strings.Contains(got.Error(), "SECRET") {
			t.Errorf("errorWithoutText(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// A device that answers with a malformed response quoting a key: the error the
// trust client returns does not carry it.
func TestListTrust_MalformedResponseIsNotQuoted(t *testing.T) {
	_, keyPEM := testCertAndKey(t)
	line := strings.SplitN(keyPEM, "\n", 3)[1]
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = io.WriteString(conn, "GARBAGE "+line+"\r\n\r\n")
			conn.Close()
		}
	}()
	c := NewClient("http://"+listener.Addr().String(), "k", "s", true)
	_, err = c.ListTrust(context.Background(), TrustCert)
	if err == nil {
		t.Fatal("a malformed response was accepted")
	}
	if strings.Contains(err.Error(), line[:20]) || strings.Contains(err.Error(), "GARBAGE") {
		t.Errorf("the error quotes the response: %v", err)
	}
}
