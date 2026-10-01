package pathfinder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// A read-only session reads every view an administrator reads, and OPNsense
// answers a view with the stored fields of its model: a grid sends every field of
// a row as stored (password hashes included), an edit dialog or a legacy form the
// plain text of every field that is not update-only. user-config-readonly limits
// writes, not reads, so the proxy blanks the named secret fields out of the
// responses of the routes below before the client sees them.
//
// The rules are exact: a route, and within it the JSON object keys (or positions)
// or the legacy page's form fields that hold a secret. Every other byte is
// forwarded as it arrived. A response of a scrubbed route that cannot be read as
// what it is (not JSON, not closed, too large, encoded) is withheld, never
// forwarded. A route that hands out key material outright is refused instead
// (handsOutPrivateMaterial). A grid's search is not held to the rule: the grid matches
// the phrase against the stored fields, secret included, before anything is blanked,
// so which rows come back can still say whether a phrase occurs in a secret. That is
// accepted (CLAUDE.md, TESTING.md). The list is what the audit described in TESTING.md
// found, and readonly_scrub_test.go pins it.

// maxScrubBytes bounds the body of a response that is rewritten. The proxy holds
// the whole body before it writes the first byte, so nothing half-cleaned can
// reach the client.
const maxScrubBytes = 8 << 20

// scrubRule says what the response to a group of routes is cleaned of.
type scrubRule struct {
	route  *regexp.Regexp  // matched against the canonical route
	except *regexp.Regexp  // routes inside it that carry no secret and are not JSON
	json   *jsonSecrets    // the secrets of a JSON response
	html   map[string]bool // the form fields of an HTML page whose value is blanked
}

// canonicalPattern spells a route pattern the way canonicalRoute spells a route:
// lower case, no underscores.
func canonicalPattern(pattern string) string {
	return strings.ReplaceAll(strings.ToLower(pattern), "_", "")
}

// scalars are fields that hold the secret as text, the way every model field
// does.
func scalars(names ...string) []jsonKey {
	keys := make([]jsonKey, len(names))
	for i, n := range names {
		keys[i] = jsonKey{name: n}
	}
	return keys
}

// lists are fields whose secret is a list of strings.
func lists(names ...string) []jsonKey {
	keys := make([]jsonKey, len(names))
	for i, n := range names {
		keys[i] = jsonKey{name: n, kinds: kindString | kindArray}
	}
	return keys
}

// dicts are fields that can carry the secret in an option list.
func dicts(names ...string) []jsonKey {
	keys := make([]jsonKey, len(names))
	for i, n := range names {
		keys[i] = jsonKey{name: n, kinds: kindString | kindObject}
	}
	return keys
}

// urls are fields whose value is a URL that can carry credentials.
func urls(names ...string) []jsonKey {
	keys := make([]jsonKey, len(names))
	for i, n := range names {
		keys[i] = jsonKey{name: n, userinfo: true}
	}
	return keys
}

// at is a position in a document: its keys from the root, with "*" for any key
// or index.
func at(segments ...string) jsonPath {
	return jsonPath{segments: segments}
}

// jsonRule names the routes /api/<route>[/...] and the keys blanked anywhere in
// their responses.
func jsonRule(route string, keys ...[]jsonKey) scrubRule {
	secrets := jsonSecrets{keys: map[string]jsonKey{}}
	for _, group := range keys {
		for _, k := range group {
			secrets.keys[k.name] = k
		}
	}
	return scrubRule{route: apiRoute(route), json: &secrets}
}

// jsonPathRule is jsonRule for secrets that only a position in the document
// names, because their key is a name other values carry.
func jsonPathRule(route string, paths ...jsonPath) scrubRule {
	return scrubRule{route: apiRoute(route), json: &jsonSecrets{paths: paths}}
}

func apiRoute(route string) *regexp.Regexp {
	return regexp.MustCompile(`^/api/(` + canonicalPattern(route) + `)(/|$)`)
}

// excluding leaves the routes out of the rule.
func (r scrubRule) excluding(routes string) scrubRule {
	r.except = apiRoute(routes)
	return r
}

// htmlRule names a legacy page and the <input> fields whose value it renders.
// Any path that begins with the page's name is the page: a spelling the web
// server resolves to the script is covered, and one it does not serves no
// secret.
func htmlRule(page string, inputs ...string) scrubRule {
	fields := map[string]bool{}
	for _, n := range inputs {
		fields[n] = true
	}
	return scrubRule{route: regexp.MustCompile(`^` + regexp.QuoteMeta(canonicalPattern("/"+page))), html: fields}
}

// scrubRules: a grid (searchBase) sends each field of a row as getValue(), the
// stored text, whatever columns the controller names; getBase and the inherited
// get action send getNodes(), which casts a field to a string, so update-only and
// API-key fields arrive empty. A key is named in both spellings where they differ:
// the dotted name of a grid row ("wpa.passphrase") and the nested one of a form.
var scrubRules = []scrubRule{
	// Users: the stored password hash and the API key lines (key|crypt secret)
	// arrive in every grid row; get returns the OTP seed, and again inside otp_uri.
	// download is a CSV that asRecordSet builds with the secret columns cast to
	// empty or left out.
	jsonRule(`auth/user`, scalars("password", "apikeys", "otp_seed", "otp_uri")).excluding(`auth/user/download`),

	// HA sync: the password for the peer's XMLRPC.
	jsonRule(`core/hasync`, scalars("password")),

	// Aliases: the password of a URL table's HTTP authentication, in every grid
	// row, in get and in the export (a JSON file of the whole model).
	jsonRule(`firewall/alias`, scalars("password")),

	// CARP virtual IPs: the VHID password.
	jsonRule(`interfaces/vip_settings`, scalars("password")),

	// Wireless clones: WEP keys, the WPA passphrase and the shared secrets of the
	// RADIUS servers.
	jsonRule(`interfaces/wireless_settings`, scalars(
		"keys", "wep.keys", "passphrase", "wpa.passphrase", "auth_server_shared_secret", "auth_server_shared_secret2")),

	// IPsec: the private key of a key pair and the secret of a pre-shared key. The
	// two controllers share one model, so get returns both.
	jsonRule(`ipsec/(key_pairs|pre_shared_keys)`, scalars("privateKey", "Key")),

	// IPsec security associations: the list comes from setkey -D, whose E: and A:
	// lines carry the keys of the live SAs, split into words.
	jsonRule(`ipsec/sad`, lists("m_enc", "m_auth")),

	// Kea: the TSIG secret of a subnet's dynamic DNS updates.
	// The reservation download is a CSV of the reservations alone.
	jsonRule(`kea/dhcpv[46]`, scalars("ddns_domain_key_secret")).excluding(`kea/dhcpv[46]/download_reservations`),

	// Monit: the SMTP and httpd passwords; httpdAllow takes user:password entries
	// next to hosts and networks, and mmonitUrl takes the collector's credentials
	// in the URL. The status page is monit's own report and repeats the
	// credentials it registers with M/Monit.
	jsonRule(`monit/settings`, scalars("password", "httpdPassword"), dicts("httpdAllow"), urls("mmonitUrl")),
	jsonRule(`monit/status`, scalars("password")),

	// OpenVPN: the password of a client instance, the secret of its tokens, and
	// the static keys (tls-auth, tls-crypt, secret), whose key is listed in the
	// static key grid.
	jsonRule(`openvpn/instances`, scalars("password", "auth-gen-token-secret", "key")),

	// Certificates and CAs: the private key, as stored and decoded.
	jsonRule(`trust/(ca|cert)`, scalars("prv", "prv_payload")),

	// WireGuard: the private keys of servers and clients, and the pre-shared key
	// of a peer.
	jsonRule(`wireguard/(client|server)`, scalars("privkey", "psk")),

	// Tailscale: the pre-auth key lives in a model of its own whose routes the
	// plugin's ACL does not grant; status reports the login URL of a node that
	// has not authenticated, which anyone holding it can complete.
	jsonRule(`tailscale/authentication`, scalars("preAuthKey")),
	jsonRule(`tailscale/status`, scalars("AuthURL")),

	// Intrusion detection: the values of the ruleset properties (the download
	// credentials of a rule set, such as an oinkcode) are stored under fileTags and
	// listed by name in properties. Their keys are names that option lists carry
	// too, so only the positions name them.
	jsonPathRule(`ids/settings`, at("ids", "fileTags", "tag", "*", "value"), at("properties", "*")),

	// Legacy pages render a stored secret as the value of a form field, escaped
	// with htmlspecialchars.
	htmlRule("interfaces.php",
		// DHCPv6 client key information, and on 26.1 the WEP keys, the WPA
		// passphrase and the RADIUS secrets of a wireless interface
		"adv_dhcp6_key_info_statement_secret",
		"key1", "key2", "key3", "key4", "passphrase", "auth_server_shared_secret", "auth_server_shared_secret2"),
	htmlRule("interfaces_ppps_edit.php", "password"),
	htmlRule("services_opendns.php", "password"),
	// ISC DHCP: the TSIG key of dynamic DNS updates and the OMAPI key
	htmlRule("services_dhcp.php", "ddnsdomainkey", "omapikey"),
	htmlRule("services_dhcpv6.php", "ddnsdomainkey"),
}

// scrubRuleFor returns the rule a read-only session's response to the request is
// cleaned by, or nil when there is none. The target was already classified by
// readOnlyRefusal; HEAD has no body to clean.
func scrubRuleFor(method, target string) *scrubRule {
	if method == http.MethodHead {
		return nil
	}
	path, ok := requestPath(target)
	if !ok {
		return nil
	}
	return scrubRuleForRoute(canonicalRoute(path))
}

// scrubRuleForRoute returns the rule whose routes include the canonical route.
func scrubRuleForRoute(route string) *scrubRule {
	for i := range scrubRules {
		rule := &scrubRules[i]
		if rule.route.MatchString(route) && (rule.except == nil || !rule.except.MatchString(route)) {
			return rule
		}
	}
	return nil
}

var (
	errScrubEncoded  = errors.New("the response is encoded and cannot be read")
	errScrubTooLarge = errors.New("the response is too large to be cleaned")
)

// withheldCause says, in a sentence a person reading the answer can act on, why a
// response was not forwarded. It names the cause and never quotes the response.
func withheldCause(err error) string {
	switch {
	case errors.Is(err, errScrubTooLarge):
		return fmt.Sprintf("the response is larger than %d MiB and cannot be cleaned of secrets", maxScrubBytes>>20)
	case errors.Is(err, errScrubEncoded):
		return "the response is encoded in a way the proxy cannot read, so it cannot be cleaned of secrets"
	case errors.Is(err, errNotJSON), errors.Is(err, errJSONTrailer):
		return "the response is not the JSON document this route answers with, so it cannot be cleaned of secrets"
	case errors.Is(err, errUnterminatedInput):
		return "the page has an input tag that is not closed, so it cannot be cleaned of secrets"
	}
	return "the response could not be read whole, so it cannot be cleaned of secrets"
}

// scrubResponse rewrites the body of resp by rule, whole and in memory, and
// returns the number of values it changed. On any error nothing has been written
// anywhere and resp is not to be forwarded. The original body is always closed.
//
// The request asked for an identity body (see HandleStream), so the transport has
// undone gzip already; a Content-Encoding that is still set is one it cannot undo.
func scrubResponse(resp *http.Response, rule *scrubRule) (int, error) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return 0, nil
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		resp.Body.Close()
		return 0, nil
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		resp.Body.Close()
		return 0, errScrubEncoded
	}
	if resp.ContentLength > maxScrubBytes {
		resp.Body.Close()
		return 0, errScrubTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScrubBytes+1))
	resp.Body.Close()
	if err != nil {
		return 0, fmt.Errorf("reading the response: %w", err)
	}
	if len(body) > maxScrubBytes {
		return 0, errScrubTooLarge
	}

	var cleaned []byte
	var changed int
	switch {
	case len(body) == 0:
		cleaned = body
	case rule.json != nil:
		cleaned, changed, err = scrubJSON(body, *rule.json)
	default:
		cleaned, changed, err = scrubHTMLInputs(body, rule.html)
	}
	if err != nil {
		return 0, err
	}

	if len(cleaned) == 0 {
		resp.Body = http.NoBody
	} else {
		resp.Body = io.NopCloser(bytes.NewReader(cleaned))
	}
	resp.ContentLength = int64(len(cleaned))
	resp.TransferEncoding = nil
	for _, h := range []string{"Content-Length", "Transfer-Encoding", "Content-Md5", "Digest"} {
		resp.Header.Del(h)
	}
	return changed, nil
}
