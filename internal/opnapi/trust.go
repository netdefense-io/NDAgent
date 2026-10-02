package opnapi

// trust.go — the certificate and CA store (/api/trust/ca and /api/trust/cert).
//
// Every read of these endpoints returns private keys: a search row and a get
// carry `prv` (base64 of the PEM) and `prv_payload` (the PEM) of every object
// that has one. Nothing here logs, returns or wraps a response body: a row is
// reduced to identifiers and fingerprints before it leaves this file, and an
// error carries a status code and field names, never text OPNsense wrote.

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// TrustKind is one of the two trust stores.
type TrustKind string

const (
	TrustCA   TrustKind = "ca"
	TrustCert TrustKind = "cert"
)

// TrustObject is a CA or certificate as the agent reads it: identifiers and
// fingerprints, never key material. CertSHA256 is the SHA-256 of the
// certificate's DER and KeySHA256 that of the stored private key's public key
// (SubjectPublicKeyInfo DER), both hex, empty when the field is absent or does
// not parse.
type TrustObject struct {
	UUID  string
	RefID string
	Descr string
	// CARef is the refid of the CA OPNsense recorded as the issuer.
	CARef string

	Cert       *x509.Certificate
	CertSHA256 string
	KeySHA256  string

	// InUse is OPNsense's own in-use flag of a certificate.
	InUse bool
	// RefCount is the number of objects that name a CA as their issuer.
	RefCount int
}

// IsManaged reports whether the object was created by the agent.
func (o TrustObject) IsManaged() bool {
	return strings.HasPrefix(o.UUID, NDAgentUUIDPrefix+"-")
}

// TrustAPIError is a failed trust request: the HTTP status, or the fields a
// "failed" answer named, and never the answer itself.
type TrustAPIError struct {
	Op         string
	StatusCode int
	Result     string
	Fields     []string
}

func (e *TrustAPIError) Error() string {
	switch {
	case e.StatusCode != 0:
		return fmt.Sprintf("%s: status %d", e.Op, e.StatusCode)
	case len(e.Fields) > 0:
		return fmt.Sprintf("%s: refused, fields %s", e.Op, strings.Join(e.Fields, ", "))
	case e.Result != "":
		return fmt.Sprintf("%s: result %q", e.Op, e.Result)
	default:
		return e.Op + ": unreadable answer"
	}
}

// IsNotFound reports whether the request was answered 404.
func (e *TrustAPIError) IsNotFound() bool {
	return e.StatusCode == 404
}

// trustError reduces an error of doRequest to one that carries no body.
func trustError(op string, err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return &TrustAPIError{Op: op, StatusCode: apiErr.StatusCode}
	}
	return fmt.Errorf("%s: %w", op, errorWithoutText(err))
}

// The classes of failure a trust error may name. Anything else is "request
// failed": the text of a transport error can quote what the device sent (a
// malformed response is reported with its bytes), so only these fixed words
// leave this file.
var (
	errTrustUnreadable = errors.New("unreadable answer")
	errTrustTimedOut   = errors.New("timed out")
	errTrustRefused    = errors.New("connection refused")
	errTrustTLS        = errors.New("TLS failure")
	errTrustClosed     = errors.New("connection closed")
	errTrustFailed     = errors.New("request failed")
)

// errorWithoutText reduces an error to its class.
func errorWithoutText(err error) error {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var netErr net.Error
	var verifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	switch {
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return errTrustUnreadable
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.As(err, &netErr) && netErr.Timeout():
		return errTrustTimedOut
	case errors.Is(err, syscall.ECONNREFUSED):
		return errTrustRefused
	case errors.As(err, &verifyErr), errors.As(err, &recordErr), errors.As(err, &alertErr),
		errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return errTrustTLS
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return errTrustClosed
	}
	return errTrustFailed
}

// trustSearchBody asks a grid for every row.
var trustSearchBody = map[string]interface{}{"current": 1, "rowCount": -1, "searchPhrase": ""}

// ListTrust returns every CA or every certificate on the device.
func (c *Client) ListTrust(ctx context.Context, kind TrustKind) ([]TrustObject, error) {
	var (
		body []byte
		err  error
	)
	op := "trust/" + string(kind) + "/search"
	switch kind {
	case TrustCA:
		body, err = c.doRequest(ctx, "POST", "/trust/ca/search", trustSearchBody)
	case TrustCert:
		body, err = c.doRequest(ctx, "POST", "/trust/cert/search", trustSearchBody)
	default:
		return nil, fmt.Errorf("unknown trust kind %q", kind)
	}
	if err != nil {
		return nil, trustError(op, err)
	}
	var resp struct {
		Rows []map[string]interface{} `json:"rows"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, trustError(op, err)
	}
	objects := make([]TrustObject, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		objects = append(objects, trustObjectFromRow(kind, row))
	}
	return objects, nil
}

// GetTrust reads one CA or certificate by uuid; found is false when the device
// holds none with that uuid, which OPNsense answers with an empty list. The
// answer is reduced as a search row is.
func (c *Client) GetTrust(ctx context.Context, kind TrustKind, uuid string) (obj TrustObject, found bool, err error) {
	op := "trust/" + string(kind) + "/get"
	var body []byte
	switch kind {
	case TrustCA:
		body, err = c.doRequest(ctx, "GET", "/trust/ca/get/"+uuid, nil)
	case TrustCert:
		body, err = c.doRequest(ctx, "GET", "/trust/cert/get/"+uuid, nil)
	default:
		return TrustObject{}, false, fmt.Errorf("unknown trust kind %q", kind)
	}
	if err != nil {
		return TrustObject{}, false, trustError(op, err)
	}
	var none []json.RawMessage
	if json.Unmarshal(body, &none) == nil && len(none) == 0 {
		return TrustObject{}, false, nil
	}
	var resp map[string]map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return TrustObject{}, false, trustError(op, err)
	}
	row, ok := resp[string(kind)]
	if !ok {
		return TrustObject{}, false, &TrustAPIError{Op: op}
	}
	obj = trustObjectFromRow(kind, row)
	obj.UUID = uuid
	return obj, true, nil
}

func trustObjectFromRow(kind TrustKind, row map[string]interface{}) TrustObject {
	obj := TrustObject{
		UUID:  trustField(row, "uuid"),
		RefID: trustField(row, "refid"),
		Descr: trustField(row, "descr"),
		CARef: trustRef(row, "caref"),
	}
	if cert := storedCertificate(trustField(row, "crt_payload"), trustField(row, "crt")); cert != nil {
		obj.Cert = cert
		obj.CertSHA256 = CertFingerprint(cert)
	}
	obj.KeySHA256 = storedKeyFingerprint(trustField(row, "prv_payload"), trustField(row, "prv"))
	switch kind {
	case TrustCert:
		obj.InUse = rowTruthy(row, "in_use")
	case TrustCA:
		obj.RefCount, _ = strconv.Atoi(trustField(row, "refcount"))
	}
	return obj
}

// trustField reads a string field of a row; a number reads as its integer.
func trustField(row map[string]interface{}, key string) string {
	return strings.TrimSpace(rowString(row, key))
}

// trustRef reads a reference field: the value itself, or the selected key of an
// option list, which is how a get spells it.
func trustRef(row map[string]interface{}, key string) string {
	if options, ok := row[key].(map[string]interface{}); ok {
		for value, option := range options {
			if opt, ok := option.(map[string]interface{}); ok && rowTruthy(opt, "selected") {
				return value
			}
		}
		return ""
	}
	return trustField(row, key)
}

// storedCertificate parses the certificate of a row: the PEM, or the base64 of
// the PEM that config.xml keeps.
func storedCertificate(payload, encoded string) *x509.Certificate {
	for _, text := range []string{payload, decodeBase64(encoded)} {
		if block := firstPEMBlock(text, "CERTIFICATE"); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert
			}
		}
	}
	return nil
}

// storedKeyFingerprint is the public key fingerprint of the private key of a
// row, "" when there is none that parses.
func storedKeyFingerprint(payload, encoded string) string {
	for _, text := range []string{payload, decodeBase64(encoded)} {
		if fp := PrivateKeyFingerprint([]byte(text)); fp != "" {
			return fp
		}
	}
	return ""
}

func decodeBase64(s string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(raw)
}

func firstPEMBlock(text, blockType string) *pem.Block {
	rest := []byte(text)
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == blockType {
			return block
		}
		rest = next
	}
}

// CertFingerprint is the hex SHA-256 of a certificate's DER.
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// PublicKeyFingerprint is the hex SHA-256 of a certificate's public key
// (SubjectPublicKeyInfo DER).
func PublicKeyFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// PrivateKeyFingerprint is the hex SHA-256 of the public key of the first
// private key in a PEM text, "" when there is none that parses.
func PrivateKeyFingerprint(pemText []byte) string {
	rest := pemText
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return ""
		}
		rest = next
		key, err := ParsePrivateKeyBlock(block)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		return hex.EncodeToString(sum[:])
	}
}

// ParsePrivateKeyBlock parses an unencrypted PKCS#8, PKCS#1 or SEC 1 private
// key block.
func ParsePrivateKeyBlock(block *pem.Block) (interface{}, error) {
	if len(block.Headers) != 0 {
		return nil, errors.New("encrypted or annotated key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, errors.New("not an unencrypted private key")
}

// TrustCAWrite is the set of a CA: an existing certificate, with no key.
type TrustCAWrite struct {
	Descr  string
	CrtPEM string
}

// TrustCertWrite is the set of a certificate: an import of a certificate and
// its key. CARef names the CA that issued it, "" for none on the device.
type TrustCertWrite struct {
	Descr  string
	CrtPEM string
	KeyPEM string
	CARef  string
}

// SetTrustCA creates or updates the CA with this uuid. The action is
// "existing": without it OPNsense saves a generated self-signed placeholder
// instead of the certificate. refid is never sent: OPNsense mints it on create
// and keeps it on update, which is what keeps every binding of the CA.
func (c *Client) SetTrustCA(ctx context.Context, uuid string, w TrustCAWrite) error {
	body := map[string]interface{}{"ca": map[string]string{
		"descr":       w.Descr,
		"action":      "existing",
		"crt_payload": w.CrtPEM,
	}}
	return c.trustSet(ctx, "trust/ca/set", "/trust/ca/set/"+uuid, body)
}

// SetTrustCert creates or updates the certificate with this uuid. The action
// is "import" with the certificate and the key: without it OPNsense reissues
// the certificate from the key it stores. refid is never sent, as for a CA.
func (c *Client) SetTrustCert(ctx context.Context, uuid string, w TrustCertWrite) error {
	body := map[string]interface{}{"cert": map[string]string{
		"descr":       w.Descr,
		"action":      "import",
		"crt_payload": w.CrtPEM,
		"prv_payload": w.KeyPEM,
		"caref":       w.CARef,
	}}
	return c.trustSet(ctx, "trust/cert/set", "/trust/cert/set/"+uuid, body)
}

func (c *Client) trustSet(ctx context.Context, op, path string, body interface{}) error {
	respBody, err := c.doRequest(ctx, "POST", path, body)
	if err != nil {
		return trustError(op, err)
	}
	var result struct {
		Result      string          `json:"result"`
		Validations json.RawMessage `json:"validations"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return trustError(op, err)
	}
	if result.Result != "saved" {
		return &TrustAPIError{Op: op, Result: safeResult(result.Result), Fields: validationFields(result.Validations)}
	}
	return nil
}

// DeleteTrust deletes the CA or certificate with this uuid. OPNsense rebuilds
// the system trust store after a CA delete.
func (c *Client) DeleteTrust(ctx context.Context, kind TrustKind, uuid string) error {
	var (
		respBody []byte
		err      error
	)
	op := "trust/" + string(kind) + "/del"
	switch kind {
	case TrustCA:
		respBody, err = c.doRequest(ctx, "POST", "/trust/ca/del/"+uuid, struct{}{})
	case TrustCert:
		respBody, err = c.doRequest(ctx, "POST", "/trust/cert/del/"+uuid, struct{}{})
	default:
		return fmt.Errorf("unknown trust kind %q", kind)
	}
	if err != nil {
		return trustError(op, err)
	}
	var result APIResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return trustError(op, err)
	}
	if result.Result != "deleted" {
		return &TrustAPIError{Op: op, Result: safeResult(result.Result)}
	}
	return nil
}

// fieldNamePattern is what a validation key looks like ("cert.crt_payload").
var fieldNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.]{1,64}$`)

// validationFields lists the field names of a validations object, in order,
// leaving out anything that is not a plain field name. The messages are never
// read.
func validationFields(raw json.RawMessage) []string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		if fieldNamePattern.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// safeResult keeps a result word ("failed") and drops anything longer.
func safeResult(result string) string {
	if fieldNamePattern.MatchString(result) && len(result) <= 16 {
		return result
	}
	return "unexpected"
}
