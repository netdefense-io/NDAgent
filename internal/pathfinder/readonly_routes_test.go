package pathfinder

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// What readOnlyRefusal answers: 0 to forward, 405 for a request the read-only
// session must not make, 400 for a target it cannot classify.
const (
	forwarded = 0
	refused   = http.StatusMethodNotAllowed
	malformed = http.StatusBadRequest
)

func TestCanonicalRoute(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"plain", "/api/core/service/restart/openvpn", "/api/core/service/restart/openvpn"},
		{"case", "/api/Core/Service/RESTART", "/api/core/service/restart"},
		{"underscores", "/api/diagnostics/firewall/kill_states", "/api/diagnostics/firewall/killstates"},
		{"camel equals snake", "/api/diagnostics/firewall/killStates", "/api/diagnostics/firewall/killstates"},
		{"repeated slashes", "/api//core///service//restart", "/api/core/service/restart"},
		{"leading slashes", "//api/core/service/restart", "/api/core/service/restart"},
		{"trailing slash", "/api/core/service/restart/", "/api/core/service/restart"},
		{"a decoded question mark is part of its segment", "/api/core/service/restart?x=1", "/api/core/service/restart?x=1"},
		{"empty", "", ""},
		{"root", "/", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalRoute(tt.path); got != tt.want {
				t.Errorf("canonicalRoute(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestRequestPath(t *testing.T) {
	ok := []struct{ target, want string }{
		{"/api/core/service/restart/openvpn", "/api/core/service/restart/openvpn"},
		{"/interfaces.php?if=wan", "/interfaces.php"},
		{"/api/x?/../y", "/api/x"},
		{"/", "/"},
		{"//api//x", "//api//x"},
		{"/%69nterfaces.php", "/interfaces.php"},
		{"/api/x%2fy", "/api/x/y"},
		{"/api/x%3Fy", "/api/x?y"},
		{"/a%2eb/..c/.d/...", "/a.b/..c/.d/..."},
	}
	for _, tt := range ok {
		t.Run("ok "+tt.target, func(t *testing.T) {
			got, isOK := requestPath(tt.target)
			if !isOK || got != tt.want {
				t.Errorf("requestPath(%q) = %q, %v; want %q, true", tt.target, got, isOK, tt.want)
			}
		})
	}

	bad := []string{
		// not origin-form
		"", "x", "*", "127.0.0.1:443", "http://evil.example/x", "https://h/x", "http:@127.0.0.1:443/x", "mailto:x@y",
		// fragments
		"/x#y", "/x?a#b", "/#",
		// NUL
		"/x%00", "/%00", "/x%00.php",
		// dot segments, spelled every way lighttpd resolves them
		"/./interfaces.php", "/x/./y", "/x/../interfaces.php", "/..", "/x/..", "/x/.", "/api/../system_general.php",
		"/ui/../crash_reporter.php", "/%2e/interfaces.php", "/%2E%2E/interfaces.php", "/.%2e/x", "/%2e./x",
		"/x%2f..%2finterfaces.php", "/x%2F..%2Finterfaces.php", "/x/..%2finterfaces.php", "/x%3F/../interfaces.php",
		// invalid escapes
		"/%zz", "/%", "/%4",
	}
	for _, target := range bad {
		t.Run("bad "+target, func(t *testing.T) {
			if got, isOK := requestPath(target); isOK {
				t.Errorf("requestPath(%q) = %q, true; want a refusal", target, got)
			}
		})
	}
}

// assertRefusal fails for every target whose readOnlyRefusal result for the
// method, without a body, is not want.
func assertRefusal(t *testing.T, method string, want int, targets ...string) {
	t.Helper()
	for _, target := range targets {
		if got := readOnlyRefusal(method, target, false); got != want {
			t.Errorf("readOnlyRefusal(%q, %q) = %d, want %d", method, target, got, want)
		}
	}
}

// The log controller clears any module and scope with
// POST /api/diagnostics/log/<module>/<scope>/clear, and the read-only ACL
// grants the whole <module>/<scope>/* prefix. The router drops empty segments
// and takes the query apart, so the spellings below reach the same handler;
// the case variants of the action do not, but no client has a use for them.
func TestReadOnlyRoutes_LogClear(t *testing.T) {
	assertRefusal(t, "POST", refused,
		"/api/diagnostics/log/core/system/clear",
		"/api/diagnostics/log/core/audit/clear",
		"/api/diagnostics/log/core/boot/clear",
		"/api/diagnostics/log/core/configd/clear",
		"/api/diagnostics/log/core/lighttpd/clear",
		"/api/diagnostics/log/core/kea/clear",
		"/api/diagnostics/log/core/wireguard/clear",
		"/api/diagnostics/log/core/resolver/clear",
		"/api/diagnostics/log/core/dhcpd/clear",
		"/api/diagnostics/log/core/qemu-ga/clear",
		"/api/diagnostics/log/vendor/plugin/clear",
		"/api/diagnostics/log/core/system/clear/",
		"/api/diagnostics/log/core/system/clear//",
		"/api/diagnostics/log/core/system/clear/extra",
		"/api/diagnostics/log/core/system//clear",
		"/api/diagnostics/log//core//system//clear",
		"//api/diagnostics/log/core/system/clear",
		"/api/diagnostics/log/core/system/CLEAR",
		"/api/diagnostics/log/core/system/Clear",
		"/api/diagnostics/log/core/system/c_lear",
		"/api/diagnostics/log/core/system/clear?x=1",
		"/api/diagnostics/log/core/system/clear/?x=1&y=/z",
		"/api/diagnostics/log/core/system/clear?a=%23b",
	)
	assertRefusal(t, "POST", malformed,
		"/api/diagnostics/log/core/system/clear#frag",
		"/api/diagnostics/log/core/system/clear?a#b",
	)
	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		assertRefusal(t, method, refused, "/api/diagnostics/log/core/system/clear")
	}
}

func TestReadOnlyRoutes_LogViewsAreForwarded(t *testing.T) {
	assertRefusal(t, "POST", forwarded,
		"/api/diagnostics/log/core/system",
		"/api/diagnostics/log/core/system/",
		"/api/diagnostics/log/core/audit/",
		"/api/diagnostics/log/core/firewall/",
		"/api/diagnostics/log/core/resolver/",
		"/api/diagnostics/log/core/system/clearing",
		"/api/diagnostics/log/core/clear",
		"/api/diagnostics/log/core/clear/",
		"/api/diagnostics/log/clear/system",
		"/api/diagnostics/log/core/system/x/clear",
	)
	assertRefusal(t, "GET", forwarded,
		"/api/diagnostics/log/core/system/export",
		"/api/diagnostics/log/core/system/live",
		"/api/diagnostics/log/core/system/clear",
	)
}

// POST /api/interfaces/assignment/reconfigure applies the queued relink and
// delete and saves config.xml without asking user-config-readonly. OPNsense
// 26.7.4 dispatches these spellings to that action; its ACL refuses the ones
// with an empty segment inside the fixed prefix, but refusing them costs
// nothing.
func TestReadOnlyRoutes_InterfaceAssignmentReconfigure(t *testing.T) {
	assertRefusal(t, "POST", refused,
		"/api/interfaces/assignment/reconfigure",
		"/api/interfaces/assignment/reconfigure/",
		"/api/interfaces/assignment/reconfigure//",
		"/api/interfaces/assignment//reconfigure",
		"/api/interfaces//assignment//reconfigure",
		"//api/interfaces/assignment/reconfigure",
		"/api/interfaces/assignment/RECONFIGURE",
		"/api/interfaces/assignment/Reconfigure",
		"/api/interfaces/assignment/ReConFigure",
		"/api/interfaces/assignment/re_configure",
		"/api/interfaces/assignment/_reconfigure",
		"/api/interfaces/assignment/reconfigure_",
		"/api/interfaces/assignment/reconfigure?x=1",
		"/api/interfaces/assignment/reconfigure/?x=1",
		"/api/interfaces/assignment/reconfigure/extra",
	)
	assertRefusal(t, "POST", malformed, "/api/interfaces/assignment/reconfigure#frag")
	assertRefusal(t, "POST", forwarded,
		"/api/interfaces/assignment/searchItem",
		"/api/interfaces/assignment/search_item",
		"/api/interfaces/assignment/getItem/em0",
		"/api/interfaces/assignment/get_item",
		"/api/interfaces/assignment/pending",
		"/api/interfaces/overview/interfaces_info",
		"/api/interfaces/overview/getInterface",
		"/api/interfaces/vlan_settings/search_item",
	)
	assertRefusal(t, "GET", forwarded, "/api/interfaces/assignment/reconfigure")
}

// The state routes are spelled kill_states and flush_states in ACL.xml and by
// the UI; the ACL does not accept the camelCase names, and the router accepts
// any case and any underscores after the ACL's fixed prefix.
func TestReadOnlyRoutes_LifecycleSpellings(t *testing.T) {
	assertRefusal(t, "POST", refused,
		"/api/diagnostics/firewall/kill_states",
		"/api/diagnostics/firewall/kill_states/",
		"/api/diagnostics/firewall/kill_states?filter=x",
		"/api/diagnostics/firewall/flush_states",
		"/api/diagnostics/firewall/flush_sources",
		"/api/diagnostics/firewall/del_state/12345/0",
		"/api/diagnostics/firewall/killStates",
		"/api/diagnostics/firewall/KILL_STATES",
		"/api/core/service/restart/openvpn",
		"/api/core/service/RESTART/openvpn",
		"/api/core/service/Restart/openvpn",
		"/api/core/service//restart/openvpn",
		"/api/core/service/re_start/openvpn",
		"/api/core/service/_restart/openvpn",
		"/api/core/service/stop/openvpn",
		"/api/core/service/start/openvpn",
		"/api/openvpn/service/reconfigure",
		"/api/openvpn/service/restart_service",
		"/api/openvpn/service/restartService",
		"/api/unbound/service/reconfigure_general",
		"/api/trust/settings/reconfigure",
		"/api/firewall/filter/apply",
		"/api/firewall/filter/apply/1699999999",
		"/api/firewall/alias/reconfigure",
		"/api/firewall/filter/flush_inspect_cache",
	)
	// The same verbs in a parameter or in the middle of a name are not actions.
	assertRefusal(t, "POST", forwarded,
		"/api/firewall/alias/getAliasUUID/restart",
		"/api/firewall/alias/search_item?x=/reconfigure",
		"/api/core/service/search",
		"/api/core/service/status",
		"/api/core/system/status",
		"/api/firewall/filter/search_rule",
		"/api/kea/service/status",
		"/api/diagnostics/firewall/query_states",
		"/api/diagnostics/firewall/list_rule_ids",
		"/api/diagnostics/firewall/stats",
		"/api/diagnostics/firewall/log",
	)
}

// GET and HEAD reach every handler that answers them without acting, so they
// are forwarded; the handlers that act whatever the method are refused for
// all of them.
func TestReadOnlyRoutes_SafeMethods(t *testing.T) {
	assertRefusal(t, "GET", forwarded, "/interfaces.php")
	// A HEAD to a page or a route whose response is cleaned of secrets is refused: it
	// would give away the length of the response before the cleaning.
	assertRefusal(t, "HEAD", refused, "/interfaces.php", "/api/auth/user/get/u1", "/api/trust/cert/search")
	for _, method := range []string{"GET", "HEAD"} {
		assertRefusal(t, method, forwarded,
			"/api/core/service/restart/openvpn",
			"/api/diagnostics/firewall/kill_states",
			"/api/interfaces/assignment/reconfigure",
			"/api/diagnostics/log/core/system/clear",
			"/api/ipsec/connections/toggle",
			"/api/interfaces/vlan_settings/reconfigure",
			"/api/core/service/search",
			"/ui/interfaces/assignment",
			"/",
		)
		assertRefusal(t, method, refused,
			"/api/diagnostics/netflow/setconfig",
			"/api/diagnostics/netflow/set_config?x=1",
			"/api/firewall/alias_util/update_bogons",
			"/api/interfaces/overview/reload_interface",
			"/api/interfaces/overview/reload_interface/em0",
			"/api/interfaces/overview/reloadInterface/em0",
			"/api/tailscale/settings/reload",
			"/api/unbound/service/dnsbl",
			"/api/unbound/service/reconfigure_general",
			"/api/unbound/service/RECONFIGUREGENERAL",
			"/api/unbound/service//dnsbl",
		)
	}
}

// Three handlers act on the state they find, not on the request method, so a GET
// reaches them too:
//   - trust/ca/del runs `system trust configure` (unlink, rewrite and rehash of the
//     system trust store) after a delBase that deletes only on a POST, on every
//     release from 26.1.11 to stable/26.7 and master;
//   - routes/routes/setroute and interfaces/vip_settings/set_item write the
//     delete_route_<uuid>.todo and delete_vip_<uuid>.todo file the next apply acts
//     on, for a route or an address that exists, whether or not setBase saved
//     anything (it answers "failed" to a GET and they carry on).
//
// The audit's GET probe ran against a config with no routes and no addresses, where
// the conditions that lead to the write do not hold.
func TestReadOnlyRoutes_HandlersThatActWhateverTheMethod(t *testing.T) {
	routes := []string{
		"/api/trust/ca/del/" + certUUID,
		"/api/trust/ca/del",
		"/api/trust/ca/del/",
		"/api/trust/ca/DEL/" + certUUID,
		"/api/trust/ca/d_el/" + certUUID,
		"/api/trust/ca//del/" + certUUID + "/",
		"//api/trust/ca/del/" + certUUID,
		"/api/trust/ca/del/" + certUUID + "?x=1",
		"/api/trust/ca/del/" + certUUID + "," + certUUID,
		"/api/routes/routes/setroute/" + certUUID,
		"/api/routes/routes/set_route/" + certUUID,
		"/api/routes/routes/setRoute/" + certUUID,
		"/api/routes/routes/SETROUTE/" + certUUID,
		"/api/routes//routes/setroute/" + certUUID,
		"/api/interfaces/vip_settings/set_item/" + certUUID,
		"/api/interfaces/vip_settings/setItem/" + certUUID,
		"/api/interfaces/vip_settings/SET_ITEM/" + certUUID,
		"/api/interfaces/vip_settings/set_item",
		"/api/interfaces/vip_settings//set_item/" + certUUID,
		"/api/interfaces/vip_settings/set_item/" + certUUID + "?x=1",
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
		assertRefusal(t, method, refused, routes...)
	}

	// What their neighbours do on a GET stays as it was: the reads the pages load
	// with, and the deletes that only act on a POST. (A HEAD to a route whose
	// response is cleaned of secrets is refused: see the scrubber tests.)
	assertRefusal(t, "GET", forwarded,
		"/api/trust/ca/search",
		"/api/trust/ca/get/"+certUUID,
		"/api/trust/ca/raw_dump/"+certUUID,
		"/api/trust/ca/ca_info/x",
		"/api/trust/cert/del/"+certUUID,
		"/api/trust/ca/delx/"+certUUID,
		"/api/interfaces/vip_settings/del_item/"+certUUID,
		"/api/interfaces/vip_settings/get_item/"+certUUID,
		"/api/interfaces/vip_settings/search_item",
	)
	for _, method := range []string{"GET", "HEAD"} {
		assertRefusal(t, method, forwarded,
			"/api/routes/routes/del_route/"+certUUID,
			"/api/routes/routes/get_route/"+certUUID,
			"/api/routes/routes/search_route",
		)
	}
}

// ApiControllerBase fills $_POST from a JSON body whatever the method, and
// netflow setconfig acts on hasPost() alone, so a body on a request that
// should have none is refused outright.
func TestReadOnlyRoutes_BodyOnSafeMethods(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		for _, target := range []string{"/api/core/service/search", "/api/firewall/filter/search_rule", "/interfaces.php", "/"} {
			if got := readOnlyRefusal(method, target, true); got != malformed {
				t.Errorf("readOnlyRefusal(%q, %q, body) = %d, want %d", method, target, got, malformed)
			}
		}
		if got := readOnlyRefusal(method, "/api/diagnostics/netflow/setconfig", true); got != refused {
			t.Errorf("readOnlyRefusal(%q, netflow setconfig, body) = %d, want %d", method, got, refused)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if got := readOnlyRefusal(method, "/api/firewall/filter/search_rule", true); got != forwarded {
			t.Errorf("readOnlyRefusal(%q, search_rule, body) = %d, want %d", method, got, forwarded)
		}
	}
}

// A read-only session's page loads and grid loads use GET, HEAD and POST.
// Every other method is refused, netflow setconfig included, whichever the
// target.
func TestReadOnlyRoutes_OtherMethodsAreRefused(t *testing.T) {
	for _, method := range []string{"OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "LOCK", "get", "post", ""} {
		assertRefusal(t, method, refused,
			"/api/core/service/search",
			"/api/diagnostics/netflow/setconfig",
			"/api/core/service/restart/openvpn",
			"/interfaces.php",
			"/",
			"*",
		)
	}
}

// Everything outside /api/ is a legacy page or the UI shell. Their views are
// GETs; a POST applies, saves, uploads or deletes, and write_config() stops
// only the saves. lighttpd also runs index.php for / and any directory.
func TestReadOnlyRoutes_NonAPIRequests(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		assertRefusal(t, method, refused,
			"/interfaces.php",
			"/interfaces.php?if=wan",
			"/interfaces.php/",
			"/interfaces.php/x",
			"/interfaces.php;x",
			"/interfaces.php.bak",
			"//interfaces.php",
			"/%69nterfaces.php",
			"/interfaces%2ephp",
			"/crash_reporter.php",
			"/system_general.php",
			"/system_advanced_admin.php",
			"/firewall_nat_out.php",
			"/firewall_rules.php",
			"/system_gateway_groups.php",
			"/reporting_settings.php",
			"/services_dhcp.php",
			"/index.php",
			"/",
			"/?x=1",
			"//",
			"/ui/interfaces/assignment",
			"/ui/firewall/filter",
			"/widgets/index.html",
			"/api",
			"/apix/core/service/search",
		)
	}
	assertRefusal(t, "GET", forwarded, "/interfaces.php", "/interfaces.php?if=wan")
	assertRefusal(t, "HEAD", refused, "/interfaces.php", "/interfaces.php?if=wan", "/interfaces_ppps_edit.php?id=0")
	for _, method := range []string{"GET", "HEAD"} {
		assertRefusal(t, method, forwarded,
			"/crash_reporter.php",
			"/system_general.php",
			"/index.php",
			"/",
			"/?x=1",
			"/status_wireless.php?if=wlan0",
			"/ui/interfaces/assignment",
			"/widgets/index.html",
		)
	}
	// getserviceproviders.php is a POST lookup, not an action.
	assertRefusal(t, "POST", forwarded,
		"/getserviceproviders.php",
		"/getserviceproviders.php?country=BR",
		"/getserviceproviders.php/",
	)
	assertRefusal(t, "POST", refused, "/getserviceproviders.php.bak", "/x/getserviceproviders.php")
}

// lighttpd decodes the path and resolves dot segments before it picks the
// script, so a legacy page is reachable as /./interfaces.php,
// /x/../interfaces.php, /%2e/interfaces.php, /x%3F/../interfaces.php and
// /x%2f..%2finterfaces.php, and its authorisation follows the resolved
// SCRIPT_NAME. The router splits REQUEST_URI as received. Whatever the method,
// a target with a dot segment, a fragment, a NUL or a form other than a path
// is refused before either can read it.
func TestReadOnlyRoutes_TargetShapes(t *testing.T) {
	targets := []string{
		"/./interfaces.php",
		"/x/../interfaces.php",
		"/ui/../crash_reporter.php",
		"/api/../system_general.php",
		"/api/core/service/../service/restart/openvpn",
		"/%2e/interfaces.php",
		"/%2e%2e/interfaces.php",
		"/x%3F/../interfaces.php",
		"/x%2f..%2finterfaces.php",
		"/x/..%2finterfaces.php",
		"/../interfaces.php",
		"/interfaces.php/..",
		"/interfaces.php/.",
		"/interfaces.php#x",
		"/x#/../interfaces.php",
		"/api/core/service/restart#/x",
		"/api/x%00",
		"/interfaces.php%00.png",
		"/%zz",
		"http:@127.0.0.1:443/interfaces.php",
		"http://evil.example/x",
		"https://127.0.0.1/interfaces.php",
		"127.0.0.1:443",
		"*",
		"",
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "GET", "HEAD"} {
		assertRefusal(t, method, malformed, targets...)
	}
}

// core/dashboard/saveWidgets and restoreDefaults and core/menu/setFavorite
// save config past user-config-readonly on purpose, so the flag answers none of
// them, and each call cuts a config revision. Every method but GET and HEAD is
// refused, whichever spelling the router accepts.
func TestReadOnlyRoutes_DashboardAndFavoriteSavesAreRefused(t *testing.T) {
	saves := []string{
		"/api/core/dashboard/saveWidgets",
		"/api/core/dashboard/save_widgets",
		"/api/core/dashboard/SAVEWIDGETS",
		"/api/core/dashboard/Save_Widgets",
		"/api/core/dashboard/s_a_v_e_widgets",
		"/api/core/dashboard//save_widgets",
		"/api/core//dashboard/save_widgets/",
		"//api/core/dashboard/save_widgets",
		"/api/core/dashboard/save_widgets/x",
		"/api/core/dashboard/save_widgets?x=1",
		"/api/core/dashboard/restoreDefaults",
		"/api/core/dashboard/restore_defaults",
		"/api/core/dashboard/RESTOREDEFAULTS",
		"/api/core/dashboard/restore_defaults/",
		"/api/core/dashboard/restore_defaults?x=1",
		"/api/core/menu/setFavorite",
		"/api/core/menu/set_favorite",
		"/api/core/menu/SETFAVORITE",
		"/api/core/menu//set_favorite",
		"/api/core/menu/set_favorite/",
		"/api/core/menu/set_favorite?x=1",
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		assertRefusal(t, method, refused, saves...)
	}
	assertRefusal(t, "POST", malformed,
		"/api/core/dashboard/save_widgets#frag",
		"/api/core/dashboard/../dashboard/save_widgets",
		"/api/core/menu/set_favorite#frag",
	)

	// What the dashboard and the menu read keeps working.
	assertRefusal(t, "POST", forwarded,
		"/api/core/dashboard/get_dashboard",
		"/api/core/dashboard/getDashboard",
		"/api/core/dashboard/product_info_feed",
		"/api/core/dashboard/picture",
		"/api/core/menu/search",
		"/api/core/menu/tree",
	)
	for _, method := range []string{"GET", "HEAD"} {
		assertRefusal(t, method, forwarded,
			"/api/core/dashboard/get_dashboard",
			"/api/core/dashboard/save_widgets",
			"/api/core/menu/tree",
			"/api/core/menu/set_favorite",
		)
	}
}

const certUUID = "221f3268-0000-4000-8000-000000000001"

// trust/<cert|ca>/generate_file hands out the files of a certificate: crt and
// csr are public, prv is the private key and pkcs12 the key in a bundle. The
// controller reads the type as the second path parameter and answers only a
// POST, so every method is refused for any type but crt and csr.
func TestReadOnlyRoutes_PrivateKeyFilesAreRefused(t *testing.T) {
	var keys []string
	for _, module := range []string{"cert", "ca"} {
		base := "/api/trust/" + module
		keys = append(keys,
			base+"/generate_file/"+certUUID+"/prv",
			base+"/generateFile/"+certUUID+"/prv",
			base+"/GENERATE_FILE/"+certUUID+"/PRV",
			base+"/generate_file/"+certUUID+"/p_rv",
			base+"/generate_file/"+certUUID+"/pkcs12",
			base+"/generate_file/"+certUUID+"/PKCS12",
			base+"/generate_file/"+certUUID+"/pkcs_12",
			base+"/generate_file//"+certUUID+"//prv",
			base+"//generate_file/"+certUUID+"/prv/",
			base+"/generate_file/"+certUUID+"/prv/extra",
			base+"/generate_file/"+certUUID+"/prv?x=1",
			base+"/generate_file/"+certUUID+"/%70rv",
			base+"/generate_file/"+certUUID+"/p%72v",
			base+"/generate_file/"+certUUID+"/%70kcs12",
			// anything the controller does not recognise as crt or csr is refused
			// rather than trusted to be harmless
			base+"/generate_file/"+certUUID+"/key",
			base+"/generate_file/"+certUUID+"/crt/extra",
			base+"/generate_file/"+certUUID+"/csr/extra",
			base+"/generate_file/"+certUUID+"/crtx",
			base+"/generate_file/"+certUUID+"/crt/prv",
		)
	}
	keys = append(keys, "//api/trust/cert/generate_file/"+certUUID+"/prv")
	for _, method := range []string{"POST", "GET", "HEAD", "PUT", "PATCH", "DELETE"} {
		assertRefusal(t, method, refused, keys...)
	}
	assertRefusal(t, "POST", malformed,
		"/api/trust/cert/generate_file/"+certUUID+"/prv#frag",
		"/api/trust/cert/generate_file/"+certUUID+"/../prv",
		"/api/trust/cert/generate_file/"+certUUID+"/%2e%2e/prv",
	)

	var public []string
	for _, module := range []string{"cert", "ca"} {
		base := "/api/trust/" + module
		public = append(public,
			base+"/generate_file",
			base+"/generate_file/",
			base+"/generate_file/"+certUUID,
			base+"/generate_file/"+certUUID+"/crt",
			base+"/generate_file/"+certUUID+"/csr",
			base+"/generateFile/"+certUUID+"/crt",
			base+"/generate_file/"+certUUID+"/crt/",
			base+"/generate_file/"+certUUID+"/crt?x=1",
		)
	}
	for _, method := range []string{"POST", "GET"} {
		assertRefusal(t, method, forwarded, public...)
	}
	// The views the certificate pages load with, until the scrubber removes
	// their key fields.
	assertRefusal(t, "POST", forwarded,
		"/api/trust/cert/search",
		"/api/trust/cert/get/"+certUUID,
		"/api/trust/cert/raw_dump/"+certUUID,
		"/api/trust/cert/ca_info/x",
		"/api/trust/cert/ca_list",
		"/api/trust/ca/search",
		"/api/trust/ca/get/"+certUUID,
		"/api/trust/ca/raw_dump/"+certUUID,
		"/api/trust/crl/search",
	)
}

// ipsec/connections/swanctl returns the generated swanctl.conf, and its secrets
// section holds every pre-shared key. Every method is refused.
func TestReadOnlyRoutes_SwanctlConfIsRefused(t *testing.T) {
	routes := []string{
		"/api/ipsec/connections/swanctl",
		"/api/ipsec/connections/swanctl/",
		"/api/ipsec/connections/SWANCTL",
		"/api/ipsec/connections/swanc_tl",
		"/api/ipsec/connections//swanctl",
		"/api/ipsec//connections/swanctl?x=1",
		"//api/ipsec/connections/swanctl",
		"/api/ipsec/connections/swanctl/extra",
		"/api/ipsec/Connections/swanctl",
	}
	for _, method := range []string{"POST", "GET", "HEAD", "PUT", "PATCH", "DELETE"} {
		assertRefusal(t, method, refused, routes...)
	}
	assertRefusal(t, "POST", forwarded,
		"/api/ipsec/connections/search_connection",
		"/api/ipsec/connections/get_connection/x",
		"/api/ipsec/connections/is_enabled",
		"/api/ipsec/connections/searchLocal",
		"/api/ipsec/connections/get",
		"/api/ipsec/connections/swanctl_x",
		"/api/ipsec/pre_shared_keys/search_item",
		"/api/ipsec/key_pairs/search_item",
	)
}

// A read-only session's grid and list views, and the config writes that
// user-config-readonly already answers with its own message, are forwarded.
func TestReadOnlyRoutes_ReadRequestsAreForwarded(t *testing.T) {
	assertRefusal(t, "POST", forwarded,
		"/api/firewall/filter/searchRule",
		"/api/firewall/filter/search_rule",
		"/api/firewall/filter/get_rule/uuid",
		"/api/firewall/filter/list_categories",
		"/api/firewall/filter/download_rules",
		"/api/firewall/alias/search_item",
		"/api/firewall/alias/get_item/uuid",
		"/api/firewall/alias/list_categories",
		"/api/firewall/alias_util/aliases",
		"/api/firewall/alias_util/list/lan_net",
		"/api/firewall/d_nat/search_rule",
		"/api/firewall/source_nat/search_rule",
		"/api/firewall/category/search_item",
		"/api/interfaces/overview/interfaces_info",
		"/api/interfaces/overview/export",
		"/api/interfaces/vlan_settings/get_item/uuid",
		"/api/core/dashboard/get_dashboard",
		"/api/core/hasync_status/services",
		"/api/core/hasync_status/version",
		"/api/core/menu/search",
		"/api/diagnostics/interface/search_arp",
		"/api/diagnostics/interface/get_routes",
		"/api/diagnostics/firewall/pf_statistics/rules",
		"/api/diagnostics/firewall/query_pf_top",
		"/api/diagnostics/traffic/interface",
		"/api/diagnostics/systemhealth/get_system_health/system/-1/-1",
		"/api/diagnostics/networkinsight/timeserie/FlowInterfaceTotals",
		"/api/diagnostics/packet_capture/search_jobs",
		"/api/diagnostics/ping/search_jobs",
		"/api/kea/leases4/search",
		"/api/kea/dhcpv4/search_subnet",
		"/api/dnsmasq/leases/search",
		"/api/wireguard/server/search_server",
		"/api/wireguard/service/show",
		"/api/openvpn/instances/search",
		"/api/openvpn/service/search_sessions",
		"/api/openvpn/export/accounts/1",
		"/api/ipsec/sessions/search_phase1",
		"/api/ipsec/leases/search",
		"/api/unbound/settings/search_host_override",
		"/api/unbound/overview/search_queries",
		"/api/unbound/diagnostics/stats",
		"/api/trust/cert/search",
		"/api/trust/ca/raw_dump/uuid",
		"/api/auth/user/search",
		"/api/auth/group/search",
		"/api/ids/settings/search_installed_rules",
		"/api/ids/service/query_alerts",
		"/api/monit/settings/search_service",
		"/api/syslog/settings/search_destinations",
		"/api/routes/gateway/status",
		"/api/routing/settings/search_gateway",
		"/api/trafficshaper/settings/search_pipes",
		"/api/cron/settings/search_jobs",
		"/api/hostdiscovery/service/search",
		"/api/captiveportal/session/search",
		"/api/captiveportal/voucher/list_vouchers/provider/group",
		"/api/captiveportal/settings/search_zones",
		"/api/tailscale/status/status",
		"/api/tailscale/settings/get",
		"/api/qemuguestagent/service/status",
		"/api/netdefense/service/status",
		"/api/netdefense/service/agentStatus",
		"/api/netdefense/settings/getApiStatus",
		"/api/diagnostics/log/core/ndagent/",
		// config writes: refused by OPNsense itself while user-config-readonly is set
		"/api/firewall/filter/set_rule/uuid",
		"/api/firewall/filter/add_rule",
		"/api/firewall/filter/del_rule/uuid",
		"/api/firewall/filter/toggle_rule/uuid",
		"/api/firewall/alias/set_item/uuid",
		"/api/interfaces/assignment/del_item/em0",
		"/api/interfaces/vlan_settings/set_item/uuid",
	)
}

// Every route the audit found reachable through the read-only group's ACL
// whose handler acts before, or without, a user-config-readonly check on some
// supported release, spelled as the UI and ACL.xml spell them.
var auditedMutatingRoutes = []string{
	// captiveportal
	"/api/captiveportal/access/logoff",
	"/api/captiveportal/access/logon",
	"/api/captiveportal/service/del_template",
	"/api/captiveportal/service/reconfigure",
	"/api/captiveportal/service/restart",
	"/api/captiveportal/service/save_template",
	"/api/captiveportal/service/start",
	"/api/captiveportal/service/stop",
	"/api/captiveportal/session/connect",
	"/api/captiveportal/session/disconnect",
	"/api/captiveportal/template/save_template",
	"/api/captiveportal/voucher/drop_expired_vouchers",
	"/api/captiveportal/voucher/drop_voucher_group",
	"/api/captiveportal/voucher/expire_voucher",
	"/api/captiveportal/voucher/generate_vouchers",
	// core
	"/api/core/dashboard/restore_defaults",
	"/api/core/dashboard/save_widgets",
	"/api/core/hasync/reconfigure",
	"/api/core/hasync_status/restart",
	"/api/core/hasync_status/restart_all",
	"/api/core/hasync_status/start",
	"/api/core/hasync_status/stop",
	"/api/core/menu/set_favorite",
	"/api/core/service/restart",
	"/api/core/service/start",
	"/api/core/service/stop",
	"/api/core/system/dismiss_status",
	"/api/core/tunables/reconfigure",
	// cron
	"/api/cron/service/reconfigure",
	// dhcpv4
	"/api/dhcpv4/leases/del_lease",
	// dhcpv6
	"/api/dhcpv6/leases/del_lease",
	// dhcrelay
	"/api/dhcrelay/service/reconfigure",
	// diagnostics
	"/api/diagnostics/firewall/del_state",
	"/api/diagnostics/firewall/flush_sources",
	"/api/diagnostics/firewall/flush_states",
	"/api/diagnostics/firewall/kill_states",
	"/api/diagnostics/interface/carp_status",
	"/api/diagnostics/netflow/reconfigure",
	"/api/diagnostics/netflow/reset",
	"/api/diagnostics/netflow/setconfig",
	"/api/diagnostics/packet_capture/remove",
	"/api/diagnostics/packet_capture/start",
	"/api/diagnostics/packet_capture/stop",
	"/api/diagnostics/ping/remove",
	"/api/diagnostics/ping/start",
	"/api/diagnostics/ping/stop",
	"/api/diagnostics/systemhealth/del_rrd",
	"/api/diagnostics/systemhealth/reconfigure",
	// dnsmasq
	"/api/dnsmasq/service/reconfigure",
	"/api/dnsmasq/service/restart",
	"/api/dnsmasq/service/start",
	"/api/dnsmasq/service/stop",
	// firewall
	"/api/firewall/alias/reconfigure",
	"/api/firewall/alias/update",
	"/api/firewall/alias_util/add",
	"/api/firewall/alias_util/delete",
	"/api/firewall/alias_util/flush",
	"/api/firewall/alias_util/update_bogons",
	"/api/firewall/d_nat/apply",
	"/api/firewall/d_nat/cancel_rollback",
	"/api/firewall/d_nat/move_rule_before",
	"/api/firewall/d_nat/revert",
	"/api/firewall/d_nat/savepoint",
	"/api/firewall/d_nat/toggle_rule_log",
	"/api/firewall/filter/apply",
	"/api/firewall/filter/cancel_rollback",
	"/api/firewall/filter/move_rule_before",
	"/api/firewall/filter/revert",
	"/api/firewall/filter/savepoint",
	"/api/firewall/filter/toggle_rule_log",
	"/api/firewall/group/reconfigure",
	"/api/firewall/npt/apply",
	"/api/firewall/npt/cancel_rollback",
	"/api/firewall/npt/move_rule_before",
	"/api/firewall/npt/revert",
	"/api/firewall/npt/savepoint",
	"/api/firewall/npt/toggle_rule_log",
	"/api/firewall/one_to_one/apply",
	"/api/firewall/one_to_one/cancel_rollback",
	"/api/firewall/one_to_one/move_rule_before",
	"/api/firewall/one_to_one/revert",
	"/api/firewall/one_to_one/savepoint",
	"/api/firewall/one_to_one/toggle_rule_log",
	"/api/firewall/source_nat/apply",
	"/api/firewall/source_nat/cancel_rollback",
	"/api/firewall/source_nat/move_rule_before",
	"/api/firewall/source_nat/revert",
	"/api/firewall/source_nat/savepoint",
	"/api/firewall/source_nat/toggle_rule_log",
	// hostdiscovery
	"/api/hostdiscovery/service/reconfigure",
	"/api/hostdiscovery/service/restart",
	"/api/hostdiscovery/service/start",
	"/api/hostdiscovery/service/stop",
	// ids
	"/api/ids/service/drop_alert_log",
	"/api/ids/service/reconfigure",
	"/api/ids/service/reload_rules",
	"/api/ids/service/restart",
	"/api/ids/service/start",
	"/api/ids/service/stop",
	"/api/ids/service/update_rules",
	// interfaces
	"/api/interfaces/assignment/reconfigure",
	"/api/interfaces/bridge_settings/reconfigure",
	"/api/interfaces/gif_settings/reconfigure",
	"/api/interfaces/gre_settings/reconfigure",
	"/api/interfaces/lagg_settings/reconfigure",
	"/api/interfaces/loopback_settings/reconfigure",
	"/api/interfaces/neighbor_settings/reconfigure",
	"/api/interfaces/overview/reload_interface",
	"/api/interfaces/settings/reconfigure",
	"/api/interfaces/vip_settings/reconfigure",
	"/api/interfaces/vip_settings/set_item",
	"/api/interfaces/vlan_settings/reconfigure",
	"/api/interfaces/vxlan_settings/reconfigure",
	"/api/interfaces/wireless_settings/reconfigure",
	// ipsec
	"/api/ipsec/connections/toggle",
	"/api/ipsec/sad/delete",
	"/api/ipsec/service/reconfigure",
	"/api/ipsec/service/restart",
	"/api/ipsec/service/start",
	"/api/ipsec/service/stop",
	"/api/ipsec/sessions/connect",
	"/api/ipsec/sessions/disconnect",
	"/api/ipsec/spd/delete",
	// kea
	"/api/kea/leases4/del_lease",
	"/api/kea/leases6/del_lease",
	"/api/kea/service/reconfigure",
	"/api/kea/service/restart",
	"/api/kea/service/start",
	"/api/kea/service/stop",
	// monit
	"/api/monit/service/check",
	"/api/monit/service/reconfigure",
	"/api/monit/service/restart",
	"/api/monit/service/start",
	"/api/monit/service/stop",
	// openvpn
	"/api/openvpn/export/download",
	"/api/openvpn/export/store_presets",
	"/api/openvpn/service/kill_session",
	"/api/openvpn/service/reconfigure",
	"/api/openvpn/service/restart_service",
	"/api/openvpn/service/start_service",
	"/api/openvpn/service/stop_service",
	// routes
	"/api/routes/routes/reconfigure",
	"/api/routes/routes/setroute",
	// routing
	"/api/routing/group_settings/reconfigure",
	"/api/routing/settings/reconfigure",
	// syslog
	"/api/syslog/service/reconfigure",
	"/api/syslog/service/reset",
	"/api/syslog/service/restart",
	"/api/syslog/service/start",
	"/api/syslog/service/stop",
	// tailscale
	"/api/tailscale/settings/reload",
	// trafficshaper
	"/api/trafficshaper/service/flushreload",
	"/api/trafficshaper/service/reconfigure",
	// trust
	"/api/trust/ca/del",
	"/api/trust/crl/del",
	"/api/trust/crl/set",
	// unbound
	"/api/unbound/overview/reset",
	"/api/unbound/service/dnsbl",
	"/api/unbound/service/reconfigure",
	"/api/unbound/service/reconfigure_general",
	"/api/unbound/service/restart",
	"/api/unbound/service/start",
	"/api/unbound/service/stop",
	"/api/unbound/settings/update_blocklist",
	// wireguard
	"/api/wireguard/service/reconfigure",
	"/api/wireguard/service/restart",
	"/api/wireguard/service/start",
	"/api/wireguard/service/stop",
}

func TestReadOnlyRoutes_AuditedRoutesAreRefused(t *testing.T) {
	for _, route := range auditedMutatingRoutes {
		t.Run(route, func(t *testing.T) {
			assertRefusal(t, "POST", refused, route)
			assertRefusal(t, "POST", refused, route+"/", route+"?x=1", route+"/x/y", "/"+route, strings.ToUpper(route[:5])+strings.ToUpper(route[5:]))
		})
	}
}

// rawRequest renders one HTTP/1.1 request as it arrives on a webadmin stream.
func rawRequest(method, target, contentType, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n", method, target)
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return b.String()
}

// streamRequest is one request a client puts on a stream of its own and the
// status the read-only session must answer it with.
type streamRequest struct {
	raw  string
	want int
}

const jsonBody = `{"netflow":{"capture":{"targets":"192.0.2.1:2055"}}}`

// waitNeverHit holds for the window and fails as soon as any of the backends
// is hit. See assertSentinelNeverHitWithin for why the streams must stay open
// through it.
func waitNeverHit(t *testing.T, window time.Duration, backends ...*int32) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		for _, hits := range backends {
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Fatalf("a backend was hit %d time(s); a refused request must never be forwarded, and its target must never choose the host", got)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertRefusedOnStreams puts each request on a stream of its own, since a
// refusal ends the exchange, and checks that every one is answered with its
// status and nothing else, none reaches a backend, the proxy leaves the stream
// for the client to close (see endAfterReply), and the handler returns without
// an error once the client has closed it.
func assertRefusedOnStreams(t *testing.T, proxy *HTTPProxy, requests []streamRequest, backends ...*int32) {
	t.Helper()
	// Longer than everything below takes, so a CLOSE seen here is the proxy's
	// own and not the end of the linger.
	proxy.replyLinger = time.Minute

	type running struct {
		stream *Stream
		cap    *handleStreamCapture
		done   <-chan error
	}
	runs := make([]running, len(requests))
	for i, request := range requests {
		stream, cap := newHandleStreamTestStream()
		runs[i] = running{stream, cap, runHandleStream(proxy, stream)}
		stream.readBuf <- []byte(request.raw)
	}

	for i, request := range requests {
		resp := waitForHandleStreamResponse(t, runs[i].cap)
		if want := fmt.Sprintf("%d %s (read-only session)", request.want, http.StatusText(request.want)); resp.Status != want {
			t.Errorf("%q: status = %q, want %q", strings.SplitN(request.raw, "\r\n", 2)[0], resp.Status, want)
		}
	}

	waitNeverHit(t, 2*time.Second, backends...)

	for i, request := range requests {
		line := strings.SplitN(request.raw, "\r\n", 2)[0]
		if runs[i].cap.closeSent() {
			t.Errorf("%q: the proxy closed the stream right behind its reply; the client closes it once it has read the reply", line)
		}
		if extra := runs[i].cap.afterFirstResponse(); len(extra) != 0 {
			t.Errorf("%q: the stream carried more than the refusal: %q", line, extra)
		}
		closeHandleStreamTestStream(runs[i].stream)
		if err := waitHandleStreamDone(t, runs[i].done); err != nil {
			t.Errorf("%q: HandleStream returned %v after the refusal", line, err)
		}
	}
	for _, hits := range backends {
		if got := atomic.LoadInt32(hits); got != 0 {
			t.Fatalf("a backend was hit %d time(s) after HandleStream returned; a delayed/async forward slipped through", got)
		}
	}
}

// TestHandleStream_ReadOnlyRefusesBypassVariants_DoesNotForward drives the
// spellings and request shapes that reach a mutating handler, or a host, past
// a matcher that reads only the path as the client wrote it. Each must be
// answered 405 or 400 and none may reach a backend. The streams stay open for
// the confirmation window before they are closed (see TESTING.md).
func TestHandleStream_ReadOnlyRefusesBypassVariants_DoesNotForward(t *testing.T) {
	ts, hits := newSentinelBackend("acted")
	defer ts.Close()
	other, otherHits := newSentinelBackend("other host")
	defer other.Close()
	_, otherPort, err := net.SplitHostPort(strings.TrimPrefix(other.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	form := "application/x-www-form-urlencoded"
	requests := []streamRequest{
		// spellings the router and ACL accept
		{rawRequest("POST", "/api/diagnostics/log/core/system/clear?x=1", "", ""), refused},
		{rawRequest("POST", "/api/diagnostics/log/core/audit//clear/", "", ""), refused},
		{rawRequest("POST", "/api/interfaces/assignment/RECONFIGURE", "", ""), refused},
		{rawRequest("POST", "/api/interfaces/assignment//re_configure?x=1", "", ""), refused},
		{rawRequest("POST", "/api/core/service//restart/openvpn", "", ""), refused},
		{rawRequest("POST", "/api/diagnostics/firewall/kill_states", "", ""), refused},
		{rawRequest("GET", "/api/interfaces/overview/reload_interface/em0", "", ""), refused},
		// handlers that act before or without their own check
		{rawRequest("POST", "/api/core/system/dismiss_status", "application/json", `{"subject":"crashreporter"}`), refused},
		{rawRequest("POST", "/api/routes/routes/setroute/221f3268-0000-4000-8000-000000000000", "application/json", `{"route":{"network":"192.0.2.0/24"}}`), refused},
		{rawRequest("POST", "/api/interfaces/vip_settings/set_item/221f3268-0000-4000-8000-000000000000", "application/json", `{"vip":{"network":"192.0.2.1/32"}}`), refused},
		// the same handlers on a GET, which reaches them just the same
		{rawRequest("GET", "/api/trust/ca/del/"+certUUID, "", ""), refused},
		{rawRequest("HEAD", "/api/trust/ca/del/"+certUUID, "", ""), refused},
		{rawRequest("GET", "/api/trust/ca/DEL/"+certUUID, "", ""), refused},
		{rawRequest("POST", "/api/trust/ca/del/"+certUUID, "", ""), refused},
		{rawRequest("GET", "/api/routes/routes/setroute/"+certUUID, "", ""), refused},
		{rawRequest("GET", "/api/routes/routes/set_route/"+certUUID, "", ""), refused},
		{rawRequest("GET", "/api/interfaces/vip_settings/set_item/"+certUUID, "", ""), refused},
		{rawRequest("HEAD", "/api/interfaces/vip_settings/setItem/"+certUUID, "", ""), refused},
		// saves that OPNsense lets through user-config-readonly on purpose
		{rawRequest("POST", "/api/core/dashboard/save_widgets", "application/json", `{"widgets":[{"id":"memory"}]}`), refused},
		{rawRequest("POST", "/api/core/dashboard/saveWidgets", form, "widgets%5B0%5D%5Bid%5D=memory"), refused},
		{rawRequest("POST", "/api/core/dashboard/restore_defaults", "", ""), refused},
		{rawRequest("POST", "/api/core/menu/set_favorite", form, "menuUrl=%2Fui%2Ffirewall%2Ffilter&isFavorite=1"), refused},
		// routes that hand out private key material
		{rawRequest("POST", "/api/trust/cert/generate_file/"+certUUID+"/prv", "", ""), refused},
		{rawRequest("POST", "/api/trust/cert/generate_file/"+certUUID+"/pkcs12", "application/json", `{"password":"x"}`), refused},
		{rawRequest("POST", "/api/trust/cert/generate_file//"+certUUID+"//PKCS12", form, "password=x"), refused},
		{rawRequest("POST", "/api/trust/ca/generate_file/"+certUUID+"/prv", "", ""), refused},
		{rawRequest("GET", "/api/trust/ca/generate_file/"+certUUID+"/prv", "", ""), refused},
		{rawRequest("GET", "/api/ipsec/connections/swanctl", "", ""), refused},
		{rawRequest("POST", "/api/ipsec/connections/swanctl", "", ""), refused},
		// legacy pages and the UI shell
		{rawRequest("POST", "/interfaces.php?if=wan", form, "apply=1"), refused},
		{rawRequest("POST", "/", form, "usernamefld=root&passwordfld=x"), refused},
		{rawRequest("POST", "/?x=1", form, "usernamefld=root&passwordfld=x"), refused},
		{rawRequest("POST", "/index.php", form, "usernamefld=root&passwordfld=x"), refused},
		{rawRequest("POST", "/ui/interfaces/assignment", form, "x=1"), refused},
		// the same pages, spelled so that lighttpd resolves them to the script
		{rawRequest("POST", "/./interfaces.php", form, "apply=1"), malformed},
		{rawRequest("POST", "/x/../crash_reporter.php", form, "Submit=Delete"), malformed},
		{rawRequest("POST", "/ui/../crash_reporter.php", form, "Submit=Delete"), malformed},
		{rawRequest("POST", "/api/../system_general.php", form, "x=1"), malformed},
		{rawRequest("POST", "/%2e/interfaces.php", form, "apply=1"), malformed},
		{rawRequest("POST", "/%2e%2e/interfaces.php", form, "apply=1"), malformed},
		{rawRequest("POST", "/x%3F/../interfaces.php", form, "apply=1"), malformed},
		{rawRequest("POST", "/x%2f..%2finterfaces.php", form, "apply=1"), malformed},
		{rawRequest("POST", "/interfaces.php#x", form, "apply=1"), malformed},
		{rawRequest("POST", "/x#/../interfaces.php", form, "apply=1"), malformed},
		// a JSON body fills $_POST whatever the method
		{rawRequest("OPTIONS", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), refused},
		{rawRequest("GET", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), refused},
		{rawRequest("HEAD", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), refused},
		{rawRequest("PUT", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), refused},
		{rawRequest("PATCH", "/api/diagnostics/netflow/setconfig", "application/json", jsonBody), refused},
		{rawRequest("GET", "/api/core/service/search", "application/json", `{}`), malformed},
		{rawRequest("HEAD", "/interfaces.php", "application/json", `{}`), malformed},
		{"GET /api/core/service/search HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", malformed},
		{rawRequest("TRACE", "/api/core/service/search", "", ""), refused},
		{rawRequest("PROPFIND", "/api/core/service/search", "", ""), refused},
		// a request-target that carries a host of its own
		{fmt.Sprintf("POST http:@127.0.0.1:%s/interfaces.php HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", otherPort), malformed},
		{fmt.Sprintf("GET http:@127.0.0.1:%s/internal/admin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", otherPort), malformed},
		{fmt.Sprintf("GET http://127.0.0.1:%s/x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", otherPort), malformed},
		{"GET http://evil.example/x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", malformed},
		{"OPTIONS * HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", refused},
		{"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nContent-Length: 0\r\n\r\n", refused},
	}

	assertRefusedOnStreams(t, newHandleStreamTestProxy(t, ts, true), requests, hits, otherHits)
}

// newRecordingBackend stands in for local OPNsense and records what reaches it.
type recordedRequest struct{ method, uri, body string }

func newRecordingBackend() (*httptest.Server, func() []recordedRequest) {
	var mu sync.Mutex
	var got []recordedRequest
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recordedRequest{r.Method, r.RequestURI, string(body)})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("forwarded"))
	}))
	return ts, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), got...)
	}
}

// TestHandleStream_ReadOnlyForwardsWhatItDoesNotRefuse is the positive
// counterpart: page loads, the service-provider lookup and the grid and log
// loads that every read-only view depends on reach the backend, target and
// body unchanged.
func TestHandleStream_ReadOnlyForwardsWhatItDoesNotRefuse(t *testing.T) {
	ts, recorded := newRecordingBackend()
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)

	form := "application/x-www-form-urlencoded"
	requests := []recordedRequest{
		{"GET", "/interfaces.php?if=wan", ""},
		{"GET", "//interfaces.php", ""},
		{"GET", "/api/core/service/search?a=%2F&b=1", ""},
		{"GET", "/api/core/service/search?", ""},
		{"GET", "/api/diagnostics/log/core/system/", ""},
		{"POST", "/getserviceproviders.php", "country=BR"},
		{"POST", "/api/firewall/filter/search_rule?current=1&rowCount=-1", `{"searchPhrase":""}`},
		{"POST", "/api/diagnostics/log/core/system/", `{"current":1}`},
		{"POST", "/api/firewall/filter/get_rule/x%2Fy", ""},
	}
	for _, want := range requests {
		contentType := ""
		switch {
		case want.body == "":
		case strings.HasPrefix(want.body, "{"):
			contentType = "application/json"
		default:
			contentType = form
		}

		stream, cap := newHandleStreamTestStream()
		done := runHandleStream(proxy, stream)
		stream.readBuf <- []byte(rawRequest(want.method, want.uri, contentType, want.body))

		resp := waitForHandleStreamResponse(t, cap)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s %s: status = %d, want 200", want.method, want.uri, resp.StatusCode)
		}
		closeHandleStreamTestStream(stream)
		waitHandleStreamDone(t, done)
	}

	got := recorded()
	if len(got) != len(requests) {
		t.Fatalf("backend saw %d requests, want %d: %+v", len(got), len(requests), got)
	}
	for i, want := range requests {
		if got[i] != want {
			t.Errorf("backend request %d = %+v, want %+v", i, got[i], want)
		}
	}
}

// TestHandleStream_ReadOnlyForwardsLogSearch is the positive counterpart: the
// log grids load by POSTing to the log controller, which must still work.
func TestHandleStream_ReadOnlyForwardsLogSearch(t *testing.T) {
	const wantBody = "log-rows"
	ts, hits := newSentinelBackend(wantBody)
	defer ts.Close()

	proxy := newHandleStreamTestProxy(t, ts, true)
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)

	pushRawRequest(stream, "POST", "/api/diagnostics/log/core/system/")

	resp := waitForHandleStreamResponse(t, cap)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a log grid load must not be refused)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("sentinel backend hit count = %d, want 1", got)
	}

	closeHandleStreamTestStream(stream)
	waitHandleStreamDone(t, done)
}
