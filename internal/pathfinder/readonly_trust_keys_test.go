package pathfinder

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The certificate manager's API hands out private keys three ways: get/<uuid>
// and the rows of a search carry the key as prv (the PEM in base64) and
// prv_payload (the PEM), and generate_file/<uuid>/prv or pkcs12 sends it as a
// file. These tests take each way through the proxy with a real key, in both
// escapings PHP and Go give a JSON string, and require that a read-only client
// gets no part of it while a read-write client gets all of it.

// trustMaterial is a certificate and its key, as OPNsense stores them.
type trustMaterial struct {
	certPEM, certB64 string
	keyPEM, keyB64   string
}

func newTrustMaterial(t *testing.T) trustMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fw.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return trustMaterial{
		certPEM: certPEM, certB64: base64.StdEncoding.EncodeToString([]byte(certPEM)),
		keyPEM: keyPEM, keyB64: base64.StdEncoding.EncodeToString([]byte(keyPEM)),
	}
}

// keyPieces are the parts of the key a client must not get: the armour, every
// line of the PEM body, the stored base64 whole and a piece from inside it, each
// also as PHP escapes a slash.
func (m trustMaterial) keyPieces() []string {
	pieces := []string{"-----BEGIN PRIVATE KEY-----", m.keyB64, m.keyB64[40:80]}
	for _, line := range strings.Split(m.keyPEM, "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			pieces = append(pieces, line)
		}
	}
	for _, p := range pieces {
		if strings.Contains(p, "/") {
			pieces = append(pieces, strings.ReplaceAll(p, "/", `\/`))
		}
	}
	return pieces
}

// row is a certificate or CA as get and search answer with it.
func (m trustMaterial) row(descr string) map[string]any {
	return map[string]any{
		"refid":       "5f1e1a2b3c4d5",
		"descr":       descr,
		"crt":         m.certB64,
		"crt_payload": m.certPEM,
		"prv":         m.keyB64,
		"prv_payload": m.keyPEM,
		"commonname":  "fw.example.net",
	}
}

// trustKeyView is one view that answers with a key and the object in its answer
// that holds it.
type trustKeyView struct {
	name   string
	raw    string
	answer func(m trustMaterial) any
	object func(doc map[string]any) map[string]any
}

func trustKeyViews() []trustKeyView {
	inGet := func(field string) func(map[string]any) map[string]any {
		return func(doc map[string]any) map[string]any {
			obj, _ := doc[field].(map[string]any)
			return obj
		}
	}
	inRows := func(doc map[string]any) map[string]any {
		rows, _ := doc["rows"].([]any)
		if len(rows) != 1 {
			return nil
		}
		obj, _ := rows[0].(map[string]any)
		return obj
	}
	search := func(m trustMaterial, descr string) any {
		row := m.row(descr)
		row["uuid"] = certUUID
		return map[string]any{"rows": []any{row}, "rowCount": 1, "total": 1, "current": 1}
	}
	return []trustKeyView{
		{
			name:   "the get of a certificate",
			raw:    rawGet("/api/trust/cert/get/" + certUUID),
			answer: func(m trustMaterial) any { return map[string]any{"cert": m.row("Web GUI")} },
			object: inGet("cert"),
		},
		{
			name:   "the get of a CA",
			raw:    rawGet("/api/trust/ca/get/" + certUUID),
			answer: func(m trustMaterial) any { return map[string]any{"ca": m.row("Lab CA")} },
			object: inGet("ca"),
		},
		{
			name:   "the list of the certificates",
			raw:    rawRequest("POST", "/api/trust/cert/search", formMedia, "current=1&rowCount=7&searchPhrase="),
			answer: func(m trustMaterial) any { return search(m, "Web GUI") },
			object: inRows,
		},
		{
			name:   "the list of the CAs",
			raw:    rawRequest("POST", "/api/trust/ca/search", jsonMedia, `{"current":1,"rowCount":7,"searchPhrase":""}`),
			answer: func(m trustMaterial) any { return search(m, "Lab CA") },
			object: inRows,
		},
	}
}

// encodings are the two ways a JSON answer spells a slash.
var encodings = []struct {
	name   string
	encode func(t *testing.T, v any) string
}{
	{"as Go writes it", func(t *testing.T, v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}},
	{"as PHP writes it", func(t *testing.T, v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "/", `\/`)
	}},
}

// answerAfterTheBody answers with body once it has read the request's own, as
// OPNsense behind lighttpd does: lighttpd takes the whole request body before
// the controller runs. A stand-in that answered first would leave the client's
// transport still sending the body from the stream the proxy reads the next
// request from.
func answerAfterTheBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		jsonHandler(body)(w, r)
	}
}

func TestHandleStream_ReadOnlyBlanksTheKeyOfEveryCertificateView(t *testing.T) {
	m := newTrustMaterial(t)
	for _, view := range trustKeyViews() {
		for _, enc := range encodings {
			t.Run(view.name+" "+enc.name, func(t *testing.T) {
				body := enc.encode(t, view.answer(m))

				ex := exchangeWith(t, true, answerAfterTheBody(body), view.raw)
				if ex.resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d: %s", ex.resp.StatusCode, ex.body)
				}
				for _, piece := range m.keyPieces() {
					if bytes.Contains(ex.raw, []byte(piece)) {
						t.Errorf("%q of the key reached the client", piece)
					}
				}
				var doc map[string]any
				if err := json.Unmarshal([]byte(ex.body), &doc); err != nil {
					t.Fatalf("the cleaned answer is not JSON: %v", err)
				}
				obj := view.object(doc)
				if obj == nil {
					t.Fatalf("the object is gone from %s", ex.body)
				}
				for _, field := range []string{"prv", "prv_payload"} {
					if v, ok := obj[field]; !ok || v != "" {
						t.Errorf("%s = %v (present %v), want it blanked", field, v, ok)
					}
				}
				if obj["crt_payload"] != m.certPEM || obj["crt"] != m.certB64 {
					t.Errorf("the certificate is gone or changed: %v", obj)
				}

				// The key was in the answer: a read-write client gets it.
				ex = exchangeWith(t, false, answerAfterTheBody(body), view.raw)
				if err := json.Unmarshal([]byte(ex.body), &doc); err != nil {
					t.Fatalf("the answer is not JSON: %v", err)
				}
				if obj := view.object(doc); obj == nil || obj["prv_payload"] != m.keyPEM || obj["prv"] != m.keyB64 {
					t.Errorf("a read-write client did not get the key: %s", ex.body)
				}
			})
		}
	}
}

// generateFile stands in for generate_file, which answers a POST with a JSON
// document holding the file in field (payload, or payload_b64 for pkcs12),
// counting the requests that reach it.
func generateFile(field, file string, reached *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		answer, _ := json.Marshal(map[string]string{"status": "ok", "descr": "Web GUI", field: file})
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = w.Write(answer)
	}
}

// generate_file answers only a POST, but every method of the key files is
// refused without OPNsense seeing it. The certificate file itself is served.
func TestHandleStream_ReadOnlyRefusesTheKeyFiles(t *testing.T) {
	m := newTrustMaterial(t)
	var reached atomic.Int32
	files := map[string]http.HandlerFunc{
		"prv":    generateFile("payload", m.keyPEM, &reached),
		"pkcs12": generateFile("payload_b64", m.keyB64, &reached),
	}

	for _, module := range []string{"cert", "ca"} {
		for _, kind := range []string{"prv", "pkcs12"} {
			target := "/api/trust/" + module + "/generate_file/" + certUUID + "/" + kind
			for _, raw := range []string{
				rawRequest("POST", target, formMedia, ""),
				rawRequest("POST", target, jsonMedia, `{}`),
				rawGet(target),
			} {
				reached.Store(0)
				ex := exchangeWith(t, true, files[kind], raw)
				if ex.resp.StatusCode != refused {
					t.Errorf("%s: status = %d (%s), want %d", strings.SplitN(raw, "\r\n", 2)[0], ex.resp.StatusCode, ex.body, refused)
				}
				if reached.Load() != 0 {
					t.Errorf("%s: OPNsense was asked for the key file", strings.SplitN(raw, "\r\n", 2)[0])
				}
				for _, piece := range m.keyPieces() {
					if bytes.Contains(ex.raw, []byte(piece)) {
						t.Errorf("%s: %q of the key reached the client", strings.SplitN(raw, "\r\n", 2)[0], piece)
					}
				}
			}
		}
	}

	reached.Store(0)
	ex := exchangeWith(t, true, generateFile("payload", m.certPEM, &reached), rawRequest("POST", "/api/trust/cert/generate_file/"+certUUID+"/crt", formMedia, ""))
	var file struct{ Payload string }
	if err := json.Unmarshal([]byte(ex.body), &file); err != nil || ex.resp.StatusCode != http.StatusOK || reached.Load() != 1 || file.Payload != m.certPEM {
		t.Errorf("the certificate file: status %d, OPNsense reached %d times, body %q", ex.resp.StatusCode, reached.Load(), ex.body)
	}
}
