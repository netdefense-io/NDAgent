package pathfinder

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// scrubCase is one response of the audit: the request, the body OPNsense answers
// with (shaped after what the controller and the model field types produce), the
// secrets that must not reach the client and what must still be there.
type scrubCase struct {
	method  string
	target  string
	body    string
	secrets []string
	keeps   []string
}

const (
	hashSecret   = "$2y$11$SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSECR"
	seedSecret   = "SECRETOTPSEEDJBSWY3DP"
	keyLines     = "a2V5LVNFQ1JFVEtFWUlE|$6$SECRETSALT$SECRETCRYPTHASH\n"
	pemSecret    = "-----BEGIN PRIVATE KEY-----\\nSECRETPEMSECRETPEMSECRETPEM\\n-----END PRIVATE KEY-----\\n"
	pemB64Secret = "LS0tLS1CRUdJTiBTRUNSRVQgUEVN"
)

// scrubCases are the routes of the audit, spelled as the UI spells them.
var scrubCases = []scrubCase{
	// users
	{
		method: "POST", target: "/api/auth/user/search",
		body:    `{"rows":[{"uuid":"u1","name":"alice","scope":"user","descr":"Alice","email":"alice@example.com","password":"` + hashSecret + `","%password":"","apikeys":"` + strings.ReplaceAll(keyLines, "\n", "\\n") + `","%apikeys":"","otp_seed":"` + seedSecret + `","uid":"2001","is_admin":"0","shell_warning":"0"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{hashSecret, "SECRETSALT", "SECRETCRYPTHASH", seedSecret},
		keeps:   []string{`"name":"alice"`, `"email":"alice@example.com"`, `"rowCount":1`, `"uid":"2001"`},
	},
	{
		method: "GET", target: "/api/auth/user/get/u1",
		body:    `{"user":{"name":"alice","password":"","apikeys":"","otp_seed":"` + seedSecret + `","otp_uri":"otpauth://totp/alice@fw.example.com?secret=` + seedSecret + `&issuer=OPNsense","shell":{"":{"value":"","selected":1},"/bin/sh":{"value":"/bin/sh","selected":0}},"priv":{"page-all":{"value":"All pages","selected":1}}}}`,
		secrets: []string{seedSecret},
		keeps:   []string{`"name":"alice"`, `"/bin/sh":{"value":"/bin/sh","selected":0}`, `"page-all":{"value":"All pages","selected":1}`},
	},
	{
		method: "POST", target: "/api/auth/user/search_api_key",
		body:  `{"rows":[{"username":"alice","key":"a2V5LWlk","id":"YTJWNUxXbGs9"}],"rowCount":1,"total":1,"current":1}`,
		keeps: []string{`"key":"a2V5LWlk"`, `"username":"alice"`},
	},
	// HA
	{
		method: "GET", target: "/api/core/hasync/get",
		body:    `{"hasync":{"disablepreempt":"0","pfsyncinterface":{"lan":{"value":"LAN","selected":1}},"pfsyncpeerip":"192.168.1.2","synchronizetoip":"192.168.1.2","username":"root","password":"SECRET-HA-SYNC-PASSWORD","syncitems":{"aliases":{"value":"Aliases","selected":1}}}}`,
		secrets: []string{"SECRET-HA-SYNC-PASSWORD"},
		keeps:   []string{`"synchronizetoip":"192.168.1.2"`, `"username":"root"`, `"aliases":{"value":"Aliases","selected":1}`},
	},
	// aliases
	{
		method: "POST", target: "/api/firewall/alias/search_item",
		body:    `{"rows":[{"uuid":"a1","enabled":"1","name":"blocklist","type":"urltable","url":"https://lists.example.com/bad.txt","authtype":"basic","username":"fetcher","password":"SECRET-ALIAS-PASSWORD","updatefreq":"1","content":"","description":"bad hosts"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-ALIAS-PASSWORD"},
		keeps:   []string{`"name":"blocklist"`, `"username":"fetcher"`, `"url":"https://lists.example.com/bad.txt"`},
	},
	{
		method: "GET", target: "/api/firewall/alias/get_item/a1",
		body:    `{"alias":{"enabled":"1","name":"blocklist","type":{"urltable":{"value":"URL Table (IPs)","selected":1}},"authtype":{"basic":{"value":"Basic","selected":1}},"username":"fetcher","password":"SECRET-ALIAS-PASSWORD","content":{"password":{"selected":0,"value":"password","description":"an alias called password"},"lan_net":{"selected":0,"value":"lan_net"}}}}`,
		secrets: []string{"SECRET-ALIAS-PASSWORD"},
		keeps:   []string{`"username":"fetcher"`, `"password":{"selected":0,"value":"password","description":"an alias called password"}`, `"lan_net":{"selected":0,"value":"lan_net"}`},
	},
	{
		method: "GET", target: "/api/firewall/alias/export",
		body:    "{\n    \"aliases\": {\n        \"alias\": {\n            \"a1\": {\n                \"name\": \"blocklist\",\n                \"username\": \"fetcher\",\n                \"password\": \"SECRET-ALIAS-PASSWORD\",\n                \"proto\": \"\"\n            }\n        }\n    }\n}",
		secrets: []string{"SECRET-ALIAS-PASSWORD"},
		keeps:   []string{"\n    \"aliases\": {\n        \"alias\": {\n", `"name": "blocklist"`, `"password": ""`},
	},
	// CARP
	{
		method: "POST", target: "/api/interfaces/vip_settings/search_item",
		body:    `{"rows":[{"uuid":"v1","interface":"lan","mode":"carp","subnet":"192.168.1.1","subnet_bits":"24","vhid":"1","advbase":"1","advskew":"0","password":"SECRET-CARP-PASSWORD","descr":"LAN CARP"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-CARP-PASSWORD"},
		keeps:   []string{`"vhid":"1"`, `"mode":"carp"`},
	},
	{
		method: "GET", target: "/api/interfaces/vip_settings/get_item/v1",
		body:    `{"vip":{"interface":{"lan":{"value":"LAN","selected":1}},"mode":{"carp":{"value":"CARP","selected":1}},"vhid":"1","password":"SECRET-CARP-PASSWORD"}}`,
		secrets: []string{"SECRET-CARP-PASSWORD"},
		keeps:   []string{`"vhid":"1"`, `"carp":{"value":"CARP","selected":1}`},
	},
	// wireless clones: the grid names the nested fields with dots
	{
		method: "POST", target: "/api/interfaces/wireless_settings/search_item",
		body:    `{"rows":[{"uuid":"w1","if":"wlan0","mode":"hostap","wep.keys":"SECRET-WEP-KEYS","wpa.passphrase":"SECRET-WPA-PASSPHRASE","wpa.identity":"radius-user","auth_server_shared_secret":"SECRET-RADIUS-1","auth_server_shared_secret2":"SECRET-RADIUS-2","auth_server_addr":"192.0.2.10","descr":"guest wifi"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-WEP-KEYS", "SECRET-WPA-PASSPHRASE", "SECRET-RADIUS-1", "SECRET-RADIUS-2"},
		keeps:   []string{`"wpa.identity":"radius-user"`, `"auth_server_addr":"192.0.2.10"`, `"if":"wlan0"`},
	},
	{
		method: "GET", target: "/api/interfaces/wireless_settings/get_item/w1",
		body:    `{"wireless":{"if":{"em0":{"value":"em0","selected":1}},"wep":{"keys":"SECRET-WEP-KEYS"},"wpa":{"passphrase":"SECRET-WPA-PASSPHRASE","identity":"radius-user"},"auth_server_shared_secret":"SECRET-RADIUS-1","auth_server_shared_secret2":"SECRET-RADIUS-2"}}`,
		secrets: []string{"SECRET-WEP-KEYS", "SECRET-WPA-PASSPHRASE", "SECRET-RADIUS-1", "SECRET-RADIUS-2"},
		keeps:   []string{`"identity":"radius-user"`, `"em0":{"value":"em0","selected":1}`},
	},
	// IPsec
	{
		method: "POST", target: "/api/ipsec/key_pairs/search_item",
		body:    `{"rows":[{"uuid":"k1","keyType":"rsa","publicKey":"-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----","privateKey":"` + pemSecret + `","keySize":"2048","keyFingerprint":"aa:bb"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRETPEM"},
		keeps:   []string{`"keyFingerprint":"aa:bb"`, `"keySize":"2048"`, "PUBLIC"},
	},
	{
		method: "GET", target: "/api/ipsec/key_pairs/get_item/k1",
		body:    `{"keyPair":{"keyType":{"rsa":{"value":"RSA","selected":1}},"publicKey":"PUBLIC","privateKey":"` + pemSecret + `","keyFingerprint":"aa:bb"}}`,
		secrets: []string{"SECRETPEM"},
		keeps:   []string{`"keyFingerprint":"aa:bb"`, `"rsa":{"value":"RSA","selected":1}`},
	},
	{
		method: "POST", target: "/api/ipsec/pre_shared_keys/search_item",
		body:    `{"rows":[{"uuid":"p1","ident":"vpn-a","remote_ident":"vpn-b","keyType":"PSK","Key":"SECRET-IPSEC-PSK","description":"site a"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-IPSEC-PSK"},
		keeps:   []string{`"ident":"vpn-a"`, `"remote_ident":"vpn-b"`},
	},
	{
		method: "GET", target: "/api/ipsec/pre_shared_keys/get",
		body:    `{"ipsec":{"preSharedKeys":{"preSharedKey":{"p1":{"ident":"vpn-a","Key":"SECRET-IPSEC-PSK"}}},"keyPairs":{"keyPair":{"k1":{"privateKey":"` + pemSecret + `","keyFingerprint":"aa:bb"}}}}}`,
		secrets: []string{"SECRET-IPSEC-PSK", "SECRETPEM"},
		keeps:   []string{`"ident":"vpn-a"`, `"keyFingerprint":"aa:bb"`},
	},
	{
		method: "POST", target: "/api/ipsec/sad/search",
		body:    `{"rows":[{"id":"abc","src":"192.0.2.1","dst":"192.0.2.2","satype":"esp","spi":"c1a2b3d4","alg_enc":"rijndael-cbc","m_enc":["SECRETENC1","SECRETENC2"],"alg_auth":"hmac-sha256","m_auth":["SECRETAUTH1"],"bytes_current":1234}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRETENC1", "SECRETENC2", "SECRETAUTH1"},
		keeps:   []string{`"alg_enc":"rijndael-cbc"`, `"alg_auth":"hmac-sha256"`, `"spi":"c1a2b3d4"`, `"bytes_current":1234`},
	},
	// Kea
	{
		method: "POST", target: "/api/kea/dhcpv4/search_subnet",
		body:    `{"rows":[{"uuid":"s1","subnet":"192.168.1.0/24","ddns_domain_key_name":"ddns-key","ddns_domain_key_secret":"SECRET-TSIG4","ddns_domain_key_algorithm":"hmac-sha256","description":"lan"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-TSIG4"},
		keeps:   []string{`"subnet":"192.168.1.0/24"`, `"ddns_domain_key_name":"ddns-key"`},
	},
	{
		method: "GET", target: "/api/kea/dhcpv6/get_subnet/s1",
		body:    `{"subnet6":{"subnet":"2001:db8::/64","ddns_domain_key_name":"ddns-key","ddns_domain_key_secret":"SECRET-TSIG6","ddns_domain_key_algorithm":{"hmac-sha256":{"value":"HMAC-SHA256","selected":1}}}}`,
		secrets: []string{"SECRET-TSIG6"},
		keeps:   []string{`"subnet":"2001:db8::/64"`, `"hmac-sha256":{"value":"HMAC-SHA256","selected":1}`},
	},
	// Monit
	{
		method: "GET", target: "/api/monit/settings/get",
		body:    `{"monit":{"general":{"enabled":"1","mailserver":"smtp.example.com","port":"25","username":"mailer","password":"SECRET-SMTP-PASSWORD","httpdEnabled":"1","httpdUsername":"admin","httpdPassword":"SECRET-HTTPD-PASSWORD","httpdPort":"2812","httpdAllow":{"admin:SECRET-ALLOW-PASSWORD":{"value":"admin:SECRET-ALLOW-PASSWORD","selected":1},"192.168.1.0/24":{"value":"192.168.1.0/24","selected":1}},"mmonitUrl":"https://monit:SECRET-MMONIT-PASSWORD@mmonit.example.com:8443/collector","mmonitTimeout":"5"},"alert":{"a1":{"recipient":"ops@example.com"}}}}`,
		secrets: []string{"SECRET-SMTP-PASSWORD", "SECRET-HTTPD-PASSWORD", "SECRET-ALLOW-PASSWORD", "SECRET-MMONIT-PASSWORD"},
		keeps:   []string{`"mailserver":"smtp.example.com"`, `"username":"mailer"`, `"httpdUsername":"admin"`, `"mmonitUrl":"https://mmonit.example.com:8443/collector"`, `"recipient":"ops@example.com"`},
	},
	{
		method: "POST", target: "/api/monit/status/get/xml",
		body:    `{"result":"ok","status":{"server":{"version":"5.35","credentials":{"username":"monit","password":"SECRET-REGISTERED-PASSWORD"}},"service":[{"name":"root"}]}}`,
		secrets: []string{"SECRET-REGISTERED-PASSWORD"},
		keeps:   []string{`"version":"5.35"`, `"username":"monit"`, `"name":"root"`},
	},
	// OpenVPN
	{
		method: "POST", target: "/api/openvpn/instances/search",
		body:    `{"rows":[{"uuid":"o1","role":"client","description":"to hq","remote":"hq.example.com:1194","username":"vpnuser","password":"SECRET-OVPN-PASSWORD","auth-gen-token-secret":"SECRET-TOKEN-SECRET"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-OVPN-PASSWORD", "SECRET-TOKEN-SECRET"},
		keeps:   []string{`"username":"vpnuser"`, `"remote":"hq.example.com:1194"`},
	},
	{
		method: "GET", target: "/api/openvpn/instances/get/o1",
		body:    `{"instance":{"role":{"client":{"value":"Client","selected":1}},"username":"vpnuser","password":"SECRET-OVPN-PASSWORD","auth-gen-token-secret":"SECRET-TOKEN-SECRET","tls_key":{"sk1":{"value":"site key","selected":1}}}}`,
		secrets: []string{"SECRET-OVPN-PASSWORD", "SECRET-TOKEN-SECRET"},
		keeps:   []string{`"username":"vpnuser"`, `"sk1":{"value":"site key","selected":1}`},
	},
	{
		method: "POST", target: "/api/openvpn/instances/search_static_key",
		body:    `{"rows":[{"uuid":"sk1","mode":"crypt","key":"-----BEGIN OpenVPN Static key V1-----\nSECRETSTATICKEY\n-----END OpenVPN Static key V1-----","description":"site key"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRETSTATICKEY"},
		keeps:   []string{`"description":"site key"`, `"mode":"crypt"`},
	},
	{
		method: "GET", target: "/api/openvpn/instances/get_static_key/sk1",
		body:    `{"statickey":{"mode":{"crypt":{"value":"tls-crypt","selected":1}},"key":"-----BEGIN OpenVPN Static key V1-----\nSECRETSTATICKEY\n-----END OpenVPN Static key V1-----","description":"site key"}}`,
		secrets: []string{"SECRETSTATICKEY"},
		keeps:   []string{`"description":"site key"`, `"crypt":{"value":"tls-crypt","selected":1}`},
	},
	// certificates and CAs
	{
		method: "POST", target: "/api/trust/cert/search",
		body:    `{"rows":[{"uuid":"c1","refid":"5f1e1a2b3c4d5","descr":"Web GUI","caref":"","crt":"UFVCTElDQ1JU","csr":"","prv":"` + pemB64Secret + `","crt_payload":"-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----","prv_payload":"` + pemSecret + `","commonname":"fw.example.com","valid_to":"1893456000","in_use":"1"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRETPEM", pemB64Secret},
		keeps:   []string{`"descr":"Web GUI"`, `"commonname":"fw.example.com"`, `"in_use":"1"`, "PUBLIC", `"crt":"UFVCTElDQ1JU"`},
	},
	{
		method: "GET", target: "/api/trust/cert/get/c1",
		body:    `{"cert":{"refid":"5f1e1a2b3c4d5","descr":"Web GUI","caref":{"":{"value":"self-signed","selected":1}},"crt_payload":"PUBLIC","prv":"` + pemB64Secret + `","prv_payload":"` + pemSecret + `","action":{"reissue":{"value":"Reissue","selected":1}}}}`,
		secrets: []string{"SECRETPEM", pemB64Secret},
		keeps:   []string{`"descr":"Web GUI"`, `"crt_payload":"PUBLIC"`, `"reissue":{"value":"Reissue","selected":1}`},
	},
	{
		method: "POST", target: "/api/trust/ca/search",
		body:    `{"rows":[{"uuid":"ca1","refid":"5f1e1a2b3c4d6","descr":"Lab CA","crt_payload":"PUBLIC","prv":"` + pemB64Secret + `","prv_payload":"` + pemSecret + `"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRETPEM", pemB64Secret},
		keeps:   []string{`"descr":"Lab CA"`, `"crt_payload":"PUBLIC"`},
	},
	{
		method: "GET", target: "/api/trust/ca/get/ca1",
		body:    `{"ca":{"descr":"Lab CA","prv":"` + pemB64Secret + `","prv_payload":"` + pemSecret + `"}}`,
		secrets: []string{"SECRETPEM", pemB64Secret},
		keeps:   []string{`"descr":"Lab CA"`},
	},
	// WireGuard
	{
		method: "POST", target: "/api/wireguard/client/search_client",
		body:    `{"rows":[{"uuid":"g1","enabled":"1","name":"laptop","pubkey":"PUBKEYPUBKEY=","psk":"SECRET-WG-PSK","privkey":"SECRET-WG-CLIENT-PRIVKEY","tunneladdress":"10.10.0.2/32","serveraddress":"vpn.example.com","serverport":"51820"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-WG-PSK", "SECRET-WG-CLIENT-PRIVKEY"},
		keeps:   []string{`"pubkey":"PUBKEYPUBKEY="`, `"tunneladdress":"10.10.0.2/32"`, `"name":"laptop"`},
	},
	{
		method: "GET", target: "/api/wireguard/client/get_client/g1",
		body:    `{"client":{"enabled":"1","name":"laptop","pubkey":"PUBKEYPUBKEY=","psk":"SECRET-WG-PSK","privkey":"SECRET-WG-CLIENT-PRIVKEY","servers":{"s1":{"value":"wg0","selected":1}}}}`,
		secrets: []string{"SECRET-WG-PSK", "SECRET-WG-CLIENT-PRIVKEY"},
		keeps:   []string{`"pubkey":"PUBKEYPUBKEY="`, `"s1":{"value":"wg0","selected":1}`},
	},
	{
		method: "GET", target: "/api/wireguard/client/get",
		body:    `{"client":{"clients":{"client":{"g1":{"name":"laptop","psk":"SECRET-WG-PSK","privkey":"SECRET-WG-CLIENT-PRIVKEY"}}}}}`,
		secrets: []string{"SECRET-WG-PSK", "SECRET-WG-CLIENT-PRIVKEY"},
		keeps:   []string{`"name":"laptop"`},
	},
	{
		method: "POST", target: "/api/wireguard/server/search_server",
		body:    `{"rows":[{"uuid":"s1","enabled":"1","name":"wg0","pubkey":"SRVPUBKEY=","privkey":"SECRET-WG-SERVER-PRIVKEY","port":"51820","tunneladdress":"10.10.0.1/24"}],"rowCount":1,"total":1,"current":1}`,
		secrets: []string{"SECRET-WG-SERVER-PRIVKEY"},
		keeps:   []string{`"pubkey":"SRVPUBKEY="`, `"port":"51820"`},
	},
	{
		method: "GET", target: "/api/wireguard/server/get_server/s1",
		body:    `{"server":{"name":"wg0","pubkey":"SRVPUBKEY=","privkey":"SECRET-WG-SERVER-PRIVKEY","peers":{"g1":{"value":"laptop","selected":1}}}}`,
		secrets: []string{"SECRET-WG-SERVER-PRIVKEY"},
		keeps:   []string{`"pubkey":"SRVPUBKEY="`, `"g1":{"value":"laptop","selected":1}`},
	},
	// Tailscale
	{
		method: "GET", target: "/api/tailscale/authentication/get",
		body:    `{"authentication":{"loginServer":"https://controlplane.tailscale.com","preAuthKey":"tskey-auth-SECRETTAILSCALEKEY"}}`,
		secrets: []string{"SECRETTAILSCALEKEY"},
		keeps:   []string{`"loginServer":"https://controlplane.tailscale.com"`},
	},
	{
		method: "POST", target: "/api/tailscale/status/status",
		body:    `{"Version":"1.80.0","BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/SECRETLOGINURL","Self":{"HostName":"fw","PublicKey":"nodekey:abc"}}`,
		secrets: []string{"SECRETLOGINURL"},
		keeps:   []string{`"BackendState":"NeedsLogin"`, `"HostName":"fw"`, `"PublicKey":"nodekey:abc"`},
	},
	// intrusion detection
	{
		method: "GET", target: "/api/ids/settings/get",
		body:    `{"ids":{"general":{"enabled":"1","mode":{"ips":{"value":"IPS mode","selected":1}},"interfaces":{"wan":{"value":"WAN","selected":1}}},"fileTags":{"tag":{"t1":{"property":"oinkcode","value":"SECRET-OINKCODE"}}},"rules":{"rule":[]}}}`,
		secrets: []string{"SECRET-OINKCODE"},
		keeps:   []string{`"property":"oinkcode"`, `"ips":{"value":"IPS mode","selected":1}`, `"wan":{"value":"WAN","selected":1}`},
	},
	{
		method: "GET", target: "/api/ids/settings/get_rulesetproperties",
		body:    `{"properties":{"oinkcode":"SECRET-OINKCODE","token":"SECRET-RULESET-TOKEN"}}`,
		secrets: []string{"SECRET-OINKCODE", "SECRET-RULESET-TOKEN"},
		keeps:   []string{`"oinkcode":""`, `"token":""`},
	},
}

// scrubAndRead runs a synthetic response through scrubResponse.
func scrubAndRead(t *testing.T, rule *scrubRule, body string) (string, int) {
	t.Helper()
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json; charset=UTF-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	changed, err := scrubResponse(resp, rule)
	if err != nil {
		t.Fatalf("scrubResponse: %v", err)
	}
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != int64(len(out)) {
		t.Errorf("ContentLength = %d for a body of %d bytes", resp.ContentLength, len(out))
	}
	return string(out), changed
}

func TestScrubRules_EveryAuditedRouteIsCleaned(t *testing.T) {
	used := map[*scrubRule]bool{}
	for _, tt := range scrubCases {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			rule := scrubRuleFor(tt.method, tt.target)
			if rule == nil {
				t.Fatalf("no scrub rule for %s %s", tt.method, tt.target)
			}
			used[rule] = true
			if !json.Valid([]byte(tt.body)) {
				t.Fatalf("the fixture is not JSON: %s", tt.body)
			}
			for _, secret := range tt.secrets {
				if !strings.Contains(tt.body, secret) {
					t.Fatalf("the fixture does not carry %q, so the test proves nothing", secret)
				}
			}

			got, _ := scrubAndRead(t, rule, tt.body)
			if !json.Valid([]byte(got)) {
				t.Fatalf("the cleaned body is not JSON: %s", got)
			}
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("%q survived in %s", secret, got)
				}
			}
			if strings.Contains(got, "SECRET") {
				t.Errorf("a SECRET survived in %s", got)
			}
			for _, keep := range tt.keeps {
				if !strings.Contains(got, keep) {
					t.Errorf("%q is gone from %s", keep, got)
				}
			}
		})
	}

	// no rule may be left without a response of the audit to hold it to
	for i := range scrubRules {
		rule := &scrubRules[i]
		if rule.html == nil && !used[rule] {
			t.Errorf("the JSON rule for %s has no response in scrubCases", rule.route)
		}
	}
}

// The responses of the routes that carry no secret, or whose secret columns the
// server leaves out, are not touched, so their streams and their bytes stay as
// OPNsense wrote them.
func TestScrubRuleFor_LeavesEverythingElseAlone(t *testing.T) {
	for _, tt := range []struct{ method, target string }{
		// CSV exports whose secret columns are cast to empty or left out server-side
		{"GET", "/api/auth/user/download"},
		{"GET", "/api/kea/dhcpv4/download_reservations"},
		{"GET", "/api/kea/dhcpv6/download_reservations"},
		// nothing in them
		{"POST", "/api/auth/group/search"},
		{"GET", "/api/auth/group/get/g1"},
		{"POST", "/api/auth/priv/search"},
		{"POST", "/api/trust/crl/search"},
		{"POST", "/api/firewall/filter/search_rule"},
		{"POST", "/api/firewall/alias_util/list/lan_net"},
		{"GET", "/api/core/dashboard/get_dashboard"},
		{"GET", "/api/core/menu/tree"},
		{"POST", "/api/core/service/search"},
		{"GET", "/api/core/hasync_status/services"},
		{"GET", "/api/ipsec/connections/search_connection"},
		{"GET", "/api/ipsec/sessions/search_phase1"},
		{"POST", "/api/ipsec/leases/search"},
		{"POST", "/api/ipsec/spd/search"},
		{"POST", "/api/wireguard/service/show"},
		{"POST", "/api/openvpn/service/search_sessions"},
		{"POST", "/api/openvpn/export/providers"},
		{"POST", "/api/openvpn/client_overwrites/search"},
		{"POST", "/api/kea/leases4/search"},
		{"POST", "/api/syslog/settings/search_destinations"},
		{"POST", "/api/unbound/settings/search_host_override"},
		{"POST", "/api/dnsmasq/settings/search_host"},
		{"POST", "/api/interfaces/overview/interfaces_info"},
		{"POST", "/api/interfaces/vlan_settings/search_item"},
		{"POST", "/api/diagnostics/log/core/system/"},
		{"POST", "/api/diagnostics/firewall/query_states"},
		{"POST", "/api/diagnostics/packet_capture/search_jobs"},
		{"GET", "/api/ids/service/status"},
		{"GET", "/api/tailscale/settings/get"},
		{"GET", "/api/netdefense/service/status"},
		{"GET", "/ui/trust/cert"},
		{"GET", "/interfaces_ppps.php"},
		{"GET", "/system_general.php"},
		{"GET", "/index.php"},
		{"GET", "/"},
		// HEAD has no body
		{"HEAD", "/api/auth/user/get/u1"},
		{"HEAD", "/interfaces.php"},
	} {
		if rule := scrubRuleFor(tt.method, tt.target); rule != nil {
			t.Errorf("%s %s is scrubbed, but carries no secret", tt.method, tt.target)
		}
	}
}

// A route inside a scrubbed controller that carries no secret is read and
// written back unchanged, to the byte.
func TestScrubRules_ASecretFreeResponseComesBackIdentical(t *testing.T) {
	for _, tt := range []struct{ method, target, body string }{
		{"GET", "/api/trust/cert/raw_dump/c1", "{\n    \"text\": \"Certificate:\\n    Data:\\n        Version: 3 (0x2)\",\n    \"issuer\": {\"CN\": \"Lab CA\"}\n}"},
		{"GET", "/api/trust/cert/ca_list", `{"rows":[{"caref":"5f1e","descr":"Lab CA"}],"count":1}`},
		{"POST", "/api/firewall/alias/list_categories", `{"rows":[{"uuid":"x","name":"servers","color":"ff0000"}]}`},
		{"GET", "/api/wireguard/client/list_servers", `{"rows":[{"uuid":"s1","name":"wg0"}],"status":"ok"}`},
		{"POST", "/api/ids/settings/search_installed_rules", `{"rows":[{"sid":"2100498","msg":"GPL ATTACK_RESPONSE id check returned root","value":"kept"}],"total":1}`},
		{"POST", "/api/ipsec/sad/search", `{"rows":[],"rowCount":0,"total":0,"current":1}`},
		{"POST", "/api/auth/user/search", `{"rows":[],"rowCount":0,"total":0,"current":1}`},
	} {
		rule := scrubRuleFor(tt.method, tt.target)
		if rule == nil {
			t.Fatalf("no rule for %s", tt.target)
		}
		got, changed := scrubAndRead(t, rule, tt.body)
		if got != tt.body || changed != 0 {
			t.Errorf("%s: got %q (%d changes), want the body back untouched", tt.target, got, changed)
		}
	}
}

// A route is scrubbed however the router and the web server spell it.
func TestScrubRuleFor_Spellings(t *testing.T) {
	want := map[string]bool{}
	for _, tt := range scrubCases {
		want[tt.target] = true
	}
	variants := func(target string) []string {
		segs := strings.Split(strings.TrimPrefix(target, "/"), "/")
		api := strings.Join(segs, "/")
		out := []string{
			"/" + api + "/",
			"/" + api + "?current=1&rowCount=-1",
			"/" + strings.ToUpper(api),
			"//" + strings.ReplaceAll(api, "/", "//"),
			"/" + strings.ReplaceAll(api, "_", ""),
		}
		if len(segs) > 3 {
			// a camel-cased action: the router ignores case and underscores
			parts := strings.Split(segs[3], "_")
			for i := 1; i < len(parts); i++ {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
			out = append(out, "/"+strings.Join(segs[:3], "/")+"/"+strings.Join(parts, ""))
		}
		return out
	}
	for _, tt := range scrubCases {
		base := scrubRuleFor(tt.method, tt.target)
		for _, v := range variants(tt.target) {
			if got := scrubRuleFor(tt.method, v); got != base {
				t.Errorf("%s %s selects %p, want the rule of %s", tt.method, v, got, tt.target)
			}
		}
	}

	// percent-encoding decodes before the match, as lighttpd does for a legacy page
	for _, target := range []string{"/%69nterfaces.php", "/interfaces%2ephp", "//interfaces.php", "/interfaces.php/extra", "/Interfaces.php", "/interfaces.php?if=wan"} {
		if scrubRuleFor("GET", target) == nil {
			t.Errorf("GET %s is not scrubbed", target)
		}
	}
	// targets the read-only gate refuses never reach a rule
	for _, target := range []string{"/api/auth/user/../user/search", "/api/auth/user/search#x", "http://h/api/auth/user/search", "*", ""} {
		if rule := scrubRuleFor("GET", target); rule != nil {
			t.Errorf("GET %q selects a rule", target)
		}
	}
}

// Every route names one rule: a second match would hide a rule behind the first.
func TestScrubRules_AreDisjoint(t *testing.T) {
	var targets []string
	for _, tt := range scrubCases {
		targets = append(targets, tt.target)
	}
	targets = append(targets, "/interfaces.php", "/interfaces_ppps_edit.php", "/services_opendns.php", "/services_dhcp.php", "/services_dhcpv6.php")
	for _, target := range targets {
		path, _ := requestPath(target)
		route := canonicalRoute(path)
		var hits []string
		for i := range scrubRules {
			r := &scrubRules[i]
			if r.route.MatchString(route) && (r.except == nil || !r.except.MatchString(route)) {
				hits = append(hits, r.route.String())
			}
		}
		if len(hits) != 1 {
			t.Errorf("%s is matched by %d rules: %v", target, len(hits), hits)
		}
	}
}

// htmlCase is a legacy page, with the lines its template renders for the field.
type htmlCase struct {
	target  string
	page    string
	secrets []string
	keeps   []string
}

const pageHead = "<html><head><title>OPNsense</title></head><body>\n<form method=\"post\">\n"

var htmlCases = []htmlCase{
	{
		target: "/interfaces.php?if=wan",
		page: pageHead +
			`<input name="adv_dhcp6_key_info_statement_keyname" type="text" id="adv_dhcp6_key_info_statement_keyname" value="kname" />` + "\n" +
			`<input name="adv_dhcp6_key_info_statement_secret" type="text" id="adv_dhcp6_key_info_statement_secret" value="SECRET-DHCP6-KEY&amp;&quot;x" />` + "\n" +
			`<input name="adv_dhcp6_key_info_statement_expire" type="text" id="adv_dhcp6_key_info_statement_expire" value="never" />` + "\n</form></body></html>",
		secrets: []string{"SECRET-DHCP6-KEY"},
		keeps:   []string{`value="kname"`, `value="never"`, `id="adv_dhcp6_key_info_statement_secret" value="" />`},
	},
	{
		target: "/interfaces.php?if=opt1",
		page: pageHead +
			`<input name="key1" type="text" id="key1" value="SECRET-WEP1" />` + "\n" +
			`<input name="key2" type="text" id="key2" value="SECRET-WEP2" />` + "\n" +
			`<input name="key3" type="text" id="key3" value="SECRET-WEP3" />` + "\n" +
			`<input name="key4" type="text" id="key4" value="SECRET-WEP4" />` + "\n" +
			`<input name="passphrase" type="text" id="passphrase" value="SECRET-PASSPHRASE" />` + "\n" +
			`<input name="auth_server_addr" id="auth_server_addr" type="text" value="192.0.2.10" />` + "\n" +
			`<input name="auth_server_shared_secret" id="auth_server_shared_secret" type="text" value="SECRET-RADIUS1" />` + "\n" +
			`<input name="auth_server_shared_secret2" id="auth_server_shared_secret2" type="text" value="SECRET-RADIUS2" />` + "\n</form></body></html>",
		secrets: []string{"SECRET-WEP1", "SECRET-WEP2", "SECRET-WEP3", "SECRET-WEP4", "SECRET-PASSPHRASE", "SECRET-RADIUS1", "SECRET-RADIUS2"},
		keeps:   []string{`value="192.0.2.10"`},
	},
	{
		target: "/interfaces_ppps_edit.php?id=0",
		page: pageHead +
			`<input name="username" type="text" id="username" value="isp-user" />` + "\n" +
			`<input name="password" type="password" autocomplete="new-password" id="password" value="SECRET-PPP-PASSWORD" />` + "\n</form></body></html>",
		secrets: []string{"SECRET-PPP-PASSWORD"},
		keeps:   []string{`value="isp-user"`, `id="password" value="" />`},
	},
	{
		target: "/services_opendns.php",
		page: pageHead +
			`<input name="username" type="text" id="username" size="20" value="opendns-user" />` + "\n" +
			`<input name="password" type="password" autocomplete="new-password" id="password" size="20" value="SECRET-OPENDNS-PASSWORD" />` + "\n</form></body></html>",
		secrets: []string{"SECRET-OPENDNS-PASSWORD"},
		keeps:   []string{`value="opendns-user"`},
	},
	{
		target: "/services_dhcp.php?if=lan",
		page: pageHead +
			`<input name="ddnsdomainkeyname" type="text" value="ddns-key" />` + "\n" +
			`<input name="ddnsdomainkey" type="text" value="SECRET-DDNS-KEY=" />` + "\n" +
			`<input name="omapiport" type="text" id="omapiport" value="7911" /><br />` + "\n" +
			`<input name="omapikey" type="text" id="omapikey" value="SECRET-OMAPI-KEY" /><br />` + "\n</form></body></html>",
		secrets: []string{"SECRET-DDNS-KEY", "SECRET-OMAPI-KEY"},
		keeps:   []string{`value="ddns-key"`, `value="7911"`},
	},
	{
		target: "/services_dhcpv6.php?if=lan",
		page: pageHead +
			`<input name="ddnsdomainkeyname" type="text" id="ddnsdomainkeyname" size="20" value="ddns6-key" />` + "\n" +
			`<input name="ddnsdomainkey" type="text" id="ddnsdomainkey" size="20" value="SECRET-DDNS6-KEY=" />` + "\n</form></body></html>",
		secrets: []string{"SECRET-DDNS6-KEY"},
		keeps:   []string{`value="ddns6-key"`},
	},
}

func TestScrubRules_EveryLegacyPageIsCleaned(t *testing.T) {
	used := map[*scrubRule]bool{}
	for _, tt := range htmlCases {
		t.Run(tt.target, func(t *testing.T) {
			rule := scrubRuleFor("GET", tt.target)
			if rule == nil || rule.html == nil {
				t.Fatalf("no HTML rule for %s", tt.target)
			}
			used[rule] = true
			for _, secret := range tt.secrets {
				if !strings.Contains(tt.page, secret) {
					t.Fatalf("the fixture does not carry %q", secret)
				}
			}
			got, _ := scrubAndRead(t, rule, tt.page)
			if strings.Contains(got, "SECRET") {
				t.Errorf("a SECRET survived in %s", got)
			}
			for _, keep := range tt.keeps {
				if !strings.Contains(got, keep) {
					t.Errorf("%q is gone from %s", keep, got)
				}
			}
			if !strings.HasPrefix(got, pageHead) || !strings.HasSuffix(got, "</form></body></html>") {
				t.Errorf("the page around the fields changed: %s", got)
			}
		})
	}
	for i := range scrubRules {
		rule := &scrubRules[i]
		if rule.html != nil && !used[rule] {
			t.Errorf("the page rule for %s has no page in htmlCases", rule.route)
		}
	}
}
