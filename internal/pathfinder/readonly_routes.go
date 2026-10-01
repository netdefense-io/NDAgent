package pathfinder

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// The read-only WebAdmin identity is granted (almost) every OPNsense page and
// relies on user-config-readonly to refuse config writes. That flag guards
// only the two config-save chokepoints, so readOnlyRefusal stops what gets
// past it:
//
//   - lifecycle actions that apply, restart, flush or kill something without
//     saving config (service and interface reconfigure, filter apply, state
//     flush, ...);
//   - handlers that delete data, save config or write files without checking
//     the flag, or that save config past it on purpose (the account's own
//     dashboard layout and menu favorites);
//   - every request other than GET and HEAD to anything but /api/, i.e. the
//     legacy pages, whose only non-config side effects are apply and delete
//     handlers;
//   - the routes that hand out private key material, which no read view needs,
//     and HEAD to the routes whose responses are cleaned of secrets (see
//     readonly_scrub.go), whose length it would give away;
//   - targets that lighttpd and OPNsense's router could read differently.
//
// The lists come from auditing every API controller of OPNsense 26.1 - 26.7
// and master (plus the ISC DHCP, Tailscale and QEMU guest agent plugins)
// against the ACL of the read-only group; TESTING.md in this directory says
// how to repeat it. Anything not listed relies on user-config-readonly.

// readOnlyRefusal returns the status a read-only session answers a request
// with instead of forwarding it, or 0 to forward it. target is the request
// target as received and hasBody tells whether the request carries a body.
//
// It is a denylist, not a method allowlist: OPNsense's grid and list views
// load by POSTing to search* endpoints, so an API request is forwarded unless
// a rule below names it.
func readOnlyRefusal(method, target string, hasBody bool) int {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return http.StatusMethodNotAllowed
	}
	path, ok := requestPath(target)
	if !ok {
		return http.StatusBadRequest
	}
	route := canonicalRoute(path)
	if anyMethodRoutePattern.MatchString(route) || handsOutPrivateMaterial(route) {
		return http.StatusMethodNotAllowed
	}
	if method == http.MethodGet || method == http.MethodHead {
		if hasBody {
			return http.StatusBadRequest
		}
		// A HEAD runs the handler and answers with the length of a body it does not
		// send, which is the length of the response before its secrets are blanked.
		if method == http.MethodHead && scrubRuleForRoute(route) != nil {
			return http.StatusMethodNotAllowed
		}
		return 0
	}
	if isMutatingRoute(route) {
		return http.StatusMethodNotAllowed
	}
	return 0
}

// requestPath returns the decoded path of an origin-form request target, or
// false for a target that lighttpd and the router could read differently: any
// other form, a fragment, a NUL, or a dot segment. lighttpd decodes the path
// and resolves dot segments before it picks the script, and a legacy page
// authorises on the resulting SCRIPT_NAME; the router splits REQUEST_URI as
// received and never decodes it. No browser sends these targets.
func requestPath(target string) (string, bool) {
	if !strings.HasPrefix(target, "/") || strings.Contains(target, "#") {
		return "", false
	}
	rawPath, _, _ := strings.Cut(target, "?")
	path, err := url.PathUnescape(rawPath)
	if err != nil || strings.Contains(path, "\x00") {
		return "", false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	return path, true
}

// canonicalRoute reduces a decoded path to the form OPNsense's MVC router
// dispatches on: empty segments dropped, every segment lower-cased with its
// underscores removed. The router ignores case and underscores in the action
// name and skips empty segments, so /api/core//service/RESTART/x and
// /api/core/service/re_start/x reach the same handler as
// /api/core/service/restart/x. The ACL, which is what limits the rest of the
// path, only matches the spelling in ACL.xml and a wildcard suffix, and leaves
// everything after its fixed prefix free.
func canonicalRoute(path string) string {
	var b strings.Builder
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			continue
		}
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(strings.ToLower(segment), "_", ""))
	}
	return b.String()
}

// isMutatingRoute reports whether a POST, PUT, PATCH or DELETE to a canonical
// route must be refused. Outside /api/ that is everything but the
// service-provider lookup, a page that POSTs to fetch data.
func isMutatingRoute(route string) bool {
	if !strings.HasPrefix(route, "/api/") {
		return !readOnlyPostPagePattern.MatchString(route)
	}
	return lifecycleRoutePattern.MatchString(route) ||
		mutatingRoutePattern.MatchString(route) ||
		logClearRoutePattern.MatchString(route)
}

// readOnlyPostPagePattern matches the pages outside /api/ that a read-only
// session may POST to.
var readOnlyPostPagePattern = regexp.MustCompile(`^/getserviceproviders\.php(/|$)`)

// lifecycleRoutePattern matches the action verbs OPNsense uses on every
// controller for runtime changes: /api/<module>/<controller>/<verb>[...].
// Upstream does not guard them with user-config-readonly and no read-only view
// depends on them. The verb is matched as a prefix so restartService,
// reconfigureGeneral, flushStates, killSession and updateRules are covered.
var lifecycleRoutePattern = regexp.MustCompile(
	`^/api/[^/]+/[^/]+/(start|stop|restart|reload|reconfigure|apply|revert|flush|reset|kill|update|remove)[a-z0-9]*(/|$)`)

// mutatingRoutes are the routes whose action name is not a lifecycle verb but
// which delete data, write files or write config before, or without, a
// user-config-readonly check on at least one supported OPNsense release.
// Several are guarded upstream on newer releases; they stay listed so the
// proxy does not depend on which release the device runs.
var mutatingRoutes = []string{
	// captive portal sessions, vouchers and templates
	`captiveportal/access/(logon|logoff)`,
	`captiveportal/session/(connect|disconnect)`,
	`captiveportal/voucher/(generatevouchers|expirevoucher|dropexpiredvouchers|dropvouchergroup)`,
	`captiveportal/(service|template)/(savetemplate|deltemplate)`,
	// the account's own dashboard layout and menu favorites: OPNsense saves them
	// past user-config-readonly on purpose, and each save still cuts a config
	// revision, prunes the oldest backups and fires the config-event hook
	`core/dashboard/(restoredefaults|savewidgets)`,
	`core/menu/setfavorite`,
	// crash dumps and the rules-error marker: dismissing deletes them, and the
	// handler's own read-only check lets a user through whose group has the page
	`core/system/dismissstatus`,
	// firewall states, CARP maintenance mode, RRD data
	`diagnostics/firewall/delstate`,
	`diagnostics/interface/carpstatus`,
	`diagnostics/systemhealth/delrrd`,
	// pf tables and rule ordering (26.1.0 lacks the guard on the second)
	`firewall/aliasutil/(add|delete)`,
	`firewall/[^/]+/(cancelrollback|moverulebefore|savepoint|togglerulelog)`,
	// alert log, IPsec, DHCP leases, monit, OpenVPN export presets, CRLs
	`ids/service/dropalertlog`,
	`ipsec/connections/toggle`,
	`ipsec/(sad|spd)/delete`,
	`ipsec/sessions/(connect|disconnect)`,
	`[^/]+/leases[46]?/dellease`,
	`monit/service/check`,
	`openvpn/export/(download|storepresets)`,
	`trust/crl/(set|del)`,
}

// mutatingRoutePattern matches /api/<mutatingRoutes>[/...].
var mutatingRoutePattern = regexp.MustCompile(
	`^/api/(` + strings.Join(mutatingRoutes, "|") + `)(/|$)`)

// logClearRoutePattern matches the log-clear action of the diagnostics log
// controller for any module and scope: /api/diagnostics/log/<module>/<scope>/clear.
// The controller dispatches on a wildcard, so the module and scope are the
// two path segments before the action.
var logClearRoutePattern = regexp.MustCompile(`^/api/diagnostics/log/[^/]+/[^/]+/clear(/|$)`)

// anyMethodRoutePattern matches the routes whose handler acts whatever the
// request method: four actions of OPNsense 26.1.0 and the os-tailscale
// settings reload act on a plain GET, and netflow setconfig acts on any method
// whose JSON body fills $_POST (it checks hasPost(), not isPost(), and
// 26.1.0 - 26.7.0 lack its throwReadOnly()).
//
// Three more act on the state they find and not on the method. The CA delete
// runs `system trust configure` (it rewrites and rehashes the system trust
// store) after a delBase that deletes only on a POST and saves only when it
// deleted something, so a GET, or a POST for a uuid that does not exist, gets
// there. The route and VIP edits write the delete_route_<uuid>.todo and
// delete_vip_<uuid>.todo file that the next apply acts on, for any route or
// address that exists, before the config guard or whatever setBase answered.
var anyMethodRoutePattern = regexp.MustCompile(`^/api/(` + strings.Join([]string{
	`diagnostics/netflow/setconfig`,
	`firewall/aliasutil/updatebogons`,
	`interfaces/overview/reloadinterface`,
	`interfaces/vipsettings/setitem`,
	`routes/routes/setroute`,
	`tailscale/settings/reload`,
	`trust/ca/del`,
	`unbound/service/(dnsbl|reconfiguregeneral)`,
}, "|") + `)(/|$)`)

// keyFileRoutePattern matches the file download of a certificate or a CA,
// /api/trust/<cert|ca>/generate_file/<uuid>/<type>. The type defaults to crt;
// crt and csr are public, prv is the private key and pkcs12 bundles it.
var keyFileRoutePattern = regexp.MustCompile(`^/api/trust/(cert|ca)/generatefile(/|$)`)

// publicFileRoutePattern matches the forms of keyFileRoutePattern whose type is
// crt or csr, or absent. The controller reads the type as the second parameter
// and compares it to its literal spelling, so only a route whose canonical type
// is one of those two can be served a public file; anything else, extra
// segments included, is refused.
var publicFileRoutePattern = regexp.MustCompile(`^/api/trust/(cert|ca)/generatefile(/[^/]+(/(crt|csr))?)?$`)

// exportRoutePattern matches the routes that return a configuration with its
// secrets in it, for any method: the generated swanctl.conf carries every
// IPsec pre-shared key.
var exportRoutePattern = regexp.MustCompile(`^/api/ipsec/connections/swanctl(/|$)`)

// handsOutPrivateMaterial reports whether a canonical route exports private
// key material. OpenVPN's client export (openvpn/export/download, which embeds
// the client key) is one of the named mutators, because it needs a POST.
func handsOutPrivateMaterial(route string) bool {
	if exportRoutePattern.MatchString(route) {
		return true
	}
	return keyFileRoutePattern.MatchString(route) && !publicFileRoutePattern.MatchString(route)
}
