package tasks

import (
	"fmt"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// Result codes of the RULE family. Consumers key on these together with the
// item status, never on the message text.
const (
	codeRuleFieldUnknown      = "RULE_FIELD_UNKNOWN"
	codeRuleValueInvalid      = "RULE_VALUE_INVALID"
	codeRuleRejectedByDevice  = "RULE_REJECTED_BY_DEVICE"
	codeRuleModelUnavailable  = "RULE_MODEL_UNAVAILABLE"
	codeRuleInterfaceNotFound = "INTERFACE_NOT_FOUND"
)

// ruleNameMappedFields hold a reference OPNsense stores as a UUID, and content
// may name it instead: a category, or the overload table's alias. The device's
// own option list maps the name, as OPNsense's rule export and import do.
var ruleNameMappedFields = map[string]bool{
	"categories": true,
	"overload":   true,
}

// rulePortNames are the port values OPNsense stores trimmed and lower-cased
// (PortField::setValue, opnsensePortFold): "any" and the well-known services,
// so "HTTPS" is saved as "https". Any other value is stored as written: two
// port aliases may differ only in case (the alias name's UniqueConstraint is
// case-sensitive). The list is the union across releases of
// PortField::$wellknownservices, refreshed at each point release; 26.7.5 added
// domain-s, ldaps, sip-tls and submissions. afs3-fileserver is listed although
// 26.7's ['any'] + array_keys(...) union drops it (both sit at index 0), which
// is harmless.
var rulePortNames = map[string]bool{
	"any": true, "afs3-fileserver": true, "aol": true, "auth": true, "avt-profile-1": true,
	"cvsup": true, "domain": true, "domain-s": true, "ftp": true, "hbci": true, "http": true,
	"https": true, "igmpv3lite": true, "imap": true, "imaps": true, "ipsec-msft": true,
	"ipsec-nat-t": true, "isakmp": true, "l2f": true, "ldap": true, "ldaps": true,
	"microsoft-ds": true, "ms-streaming": true, "ms-wbt-server": true, "msnp": true,
	"nat-stun-port": true, "netbios-dgm": true, "netbios-ns": true, "netbios-ssn": true,
	"nntp": true, "ntp": true, "openvpn": true, "pop3": true, "pop3s": true, "pptp": true,
	"radius": true, "radius-acct": true, "rfb": true, "sip": true, "sip-tls": true, "smtp": true,
	"snmp": true, "snmptrap": true, "ssh": true, "submission": true, "submissions": true,
	"telnet": true, "teredo": true, "tftp": true, "urd": true, "wins": true,
}

// ruleContract is the RULE family's field contract: any field of the device's
// filter rule model. The keys a rule never applies are RULE's ignored keys: a
// sequence in content loses to placement, sort_order and prio_group are
// computed from it, the audit record (26.7.5 and later) is OPNsense's, and the
// rest is what a pulled rule carried from the search grid. The action is
// required: the model's default is pass, so a rule that left it out would let
// traffic through by omission, and every rule the control plane generates
// names one. A protocol is stored upper-cased ("tcp" becomes "TCP", "any"
// stays "any"), a port named by rulePortNames lower-cased, and the interface
// has its own check, checkRuleInterfaces, with its own code.
var ruleContract = fieldContract{
	snippetType: "RULE",
	entity:      "rule",
	codeUnknown: codeRuleFieldUnknown,
	codeInvalid: codeRuleValueInvalid,
	required:    map[string]bool{"action": true},
	nameMapped:  ruleNameMappedFields,
	caseFolded:  map[string]bool{"protocol": true},
	lowerCased:  map[string]map[string]bool{"source_port": rulePortNames, "destination_port": rulePortNames},
	unchecked:   map[string]bool{"interface": true},
}

// ruleLabel names a rule in a message the way the user can find it: by its
// description and the snippet that carries it.
func ruleLabel(r APIRulePayload) string {
	name := fmt.Sprintf("%q", r.Description)
	if r.Description == "" {
		name = r.UUID
	}
	if r.SnippetName != "" {
		return fmt.Sprintf("Rule %s (snippet %q)", name, r.SnippetName)
	}
	return fmt.Sprintf("Rule %s (snippet at index %d)", name, r.SnippetIndex)
}

// buildRuleBody turns a desired rule's content into the body setRule takes:
// every field the device's rule model lets content set, holding the content's
// value or the model's default, so leaving "log" out turns logging off. The
// sequence is placement's and is added by the caller. See fieldContract.build
// for what refuses the rule.
func buildRuleBody(r APIRulePayload, model opnapi.EntityModel, release func() string) (map[string]string, *contentRefusal) {
	body, refusal := ruleContract.build(r.Content, model, ruleLabel(r), release)
	if refusal != nil {
		return nil, refusal
	}
	body["description"] = withTemplateTags(body["description"], r.Templates)
	return body, nil
}

// ruleRowMatches reports whether the device's rule already holds every value
// of the body.
func ruleRowMatches(body map[string]string, row map[string]interface{}) bool {
	return ruleContract.rowMatches(body, row)
}
