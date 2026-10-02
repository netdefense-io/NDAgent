package tasks

// Which services use a CA or a certificate. OPNsense has no API that lists
// them, so config.xml is read: every element whose text (or one item of a
// comma-separated list) is the object's refid names it. Three kinds of match
// are not consumers: an object's own <refid>, a local account's certificate
// (system.user), and the issuer link (<caref>) of a CA, certificate or CRL.

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// trustConsumer is one setting that names a CA or certificate.
type trustConsumer struct {
	// Kind is the reload unit that applies a changed certificate to it, ""
	// when there is none.
	Kind string
	// UUID is the MVC item that holds the setting; "" for a legacy setting.
	UUID string
	// Label names it for a person: the item's description, descr or name,
	// or the setting's path.
	Label string
	// Path is the setting's element path below the root.
	Path string
}

// trustConsumerKinds maps a setting's path, lower-cased, to its reload unit.
// A trailing "*" matches any one element.
var trustConsumerKinds = []struct {
	path []string
	kind string
}{
	{[]string{"system", "webgui", "ssl-certref"}, "webgui"},
	{[]string{"opnsense", "openvpn", "instances", "instance", "cert"}, "openvpn"},
	{[]string{"opnsense", "openvpn", "instances", "instance", "ca"}, "openvpn"},
	{[]string{"openvpn", "openvpn-server", "certref"}, "openvpn"},
	{[]string{"openvpn", "openvpn-server", "caref"}, "openvpn"},
	{[]string{"openvpn", "openvpn-client", "certref"}, "openvpn"},
	{[]string{"openvpn", "openvpn-client", "caref"}, "openvpn"},
	{[]string{"opnsense", "swanctl", "locals", "local", "certs"}, "ipsec"},
	{[]string{"opnsense", "swanctl", "remotes", "remote", "certs"}, "ipsec"},
	{[]string{"opnsense", "swanctl", "remotes", "remote", "cacerts"}, "ipsec"},
	{[]string{"ipsec", "phase1", "certref"}, "ipsec"},
	{[]string{"ipsec", "phase1", "caref"}, "ipsec"},
	{[]string{"opnsense", "syslog", "destinations", "destination", "certificate"}, "syslog"},
	{[]string{"opnsense", "captiveportal", "zones", "zone", "certificate"}, "captiveportal"},
}

// trustObjectElements are the top-level elements of the trust store itself.
var trustObjectElements = map[string]bool{"ca": true, "cert": true, "crl": true}

// xmlNode is an element of config.xml.
type xmlNode struct {
	name     string
	uuid     string
	text     string
	parent   *xmlNode
	children []*xmlNode
}

func (n *xmlNode) child(name string) *xmlNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// trustConfig is config.xml as the consumer scan reads it.
type trustConfig struct {
	root *xmlNode
	// issued maps a refid to the refids of the CAs and certificates that
	// name it as their issuer.
	issued map[string][]string
	// byRef indexes every element whose text names a refid.
	byRef map[string][]*xmlNode
}

// readTrustConfig parses config.xml.
func readTrustConfig(path string) (*trustConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	root, err := parseXMLTree(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return newTrustConfig(root), nil
}

func parseXMLTree(r io.Reader) (*xmlNode, error) {
	dec := xml.NewDecoder(r)
	var root, cur *xmlNode
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: t.Name.Local, parent: cur}
			for _, a := range t.Attr {
				if a.Name.Local == "uuid" {
					n.uuid = a.Value
				}
			}
			if cur == nil {
				if root != nil {
					return nil, fmt.Errorf("more than one root element")
				}
				root = n
			} else {
				cur.children = append(cur.children, n)
			}
			cur = n
			text.Reset()
		case xml.CharData:
			if cur != nil && len(cur.children) == 0 {
				text.Write(t)
			}
		case xml.EndElement:
			if cur == nil {
				return nil, fmt.Errorf("unbalanced element %s", t.Name.Local)
			}
			if len(cur.children) == 0 {
				cur.text = strings.TrimSpace(text.String())
			}
			text.Reset()
			cur = cur.parent
		}
	}
	if root == nil {
		return nil, fmt.Errorf("no root element")
	}
	return root, nil
}

func newTrustConfig(root *xmlNode) *trustConfig {
	cfg := &trustConfig{root: root, issued: map[string][]string{}, byRef: map[string][]*xmlNode{}}
	for _, obj := range root.children {
		if !trustObjectElements[obj.name] || obj.name == "crl" {
			continue
		}
		ref, issuer := obj.child("refid"), obj.child("caref")
		if ref != nil && ref.text != "" && issuer != nil && issuer.text != "" && issuer.text != ref.text {
			cfg.issued[issuer.text] = append(cfg.issued[issuer.text], ref.text)
		}
	}
	var walk func(n *xmlNode)
	walk = func(n *xmlNode) {
		if len(n.children) == 0 {
			if n.text != "" && !excludedTrustRef(n) {
				for _, token := range strings.Split(n.text, ",") {
					if token = strings.TrimSpace(token); token != "" {
						cfg.byRef[token] = append(cfg.byRef[token], n)
					}
				}
			}
			return
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)
	return cfg
}

// excludedTrustRef reports whether a matching element is one of the three
// that name an object without using it.
func excludedTrustRef(n *xmlNode) bool {
	if n.name == "refid" {
		return true
	}
	path := elementPath(n)
	if len(path) >= 2 && path[0] == "system" && path[1] == "user" {
		return true
	}
	if n.name == "caref" && len(path) == 2 && trustObjectElements[path[0]] {
		return true
	}
	return false
}

// elementPath is the lower-cased element names from below the root to n.
func elementPath(n *xmlNode) []string {
	var path []string
	for cur := n; cur != nil && cur.parent != nil; cur = cur.parent {
		path = append([]string{strings.ToLower(cur.name)}, path...)
	}
	return path
}

// consumersOf lists the settings that use the object with this refid. With
// issued set, it adds those of every CA and certificate the object issued,
// down the chain: what a CA's renewal reaches.
func (c *trustConfig) consumersOf(refid string, issued bool) []trustConsumer {
	refs := []string{refid}
	if issued {
		seen := map[string]bool{refid: true}
		for i := 0; i < len(refs); i++ {
			for _, child := range c.issued[refs[i]] {
				if !seen[child] {
					seen[child] = true
					refs = append(refs, child)
				}
			}
		}
	}
	// One consumer per owner and reload unit. An owner with a setting of a
	// known unit is that unit's consumer, whatever other of its fields name the
	// object, so a field met first cannot turn it into an unknown one.
	type found struct {
		consumer trustConsumer
		owner    *xmlNode
	}
	type key struct {
		owner *xmlNode
		kind  string
	}
	var all []found
	seen := map[key]bool{}
	known := map[*xmlNode]bool{}
	for _, ref := range refs {
		for _, n := range c.byRef[ref] {
			consumer, owner := describeTrustConsumer(n)
			k := key{owner, consumer.Kind}
			if seen[k] {
				continue
			}
			seen[k] = true
			if consumer.Kind != "" {
				known[owner] = true
			}
			all = append(all, found{consumer, owner})
		}
	}
	var out []trustConsumer
	for _, f := range all {
		if f.consumer.Kind == "" && known[f.owner] {
			continue
		}
		out = append(out, f.consumer)
	}
	return out
}

// configHoldsManagedTrust reports whether config.xml holds a CA or a
// certificate NetDefense manages: a top-level ca or cert element with a
// managed uuid. It stops at the first one.
func configHoldsManagedTrust(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("parse %s: %w", path, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && (t.Name.Local == "ca" || t.Name.Local == "cert") {
				for _, a := range t.Attr {
					if a.Name.Local == "uuid" && strings.HasPrefix(a.Value, opnapi.NDAgentUUIDPrefix+"-") {
						return true, nil
					}
				}
			}
		case xml.EndElement:
			depth--
		}
	}
}

// describeTrustConsumer describes the setting n, and returns the element that
// owns it: the MVC item (the nearest ancestor with a uuid), or else the
// element that holds the setting. One owner is one consumer, however many of
// its settings name the object.
func describeTrustConsumer(n *xmlNode) (trustConsumer, *xmlNode) {
	path := elementPath(n)
	consumer := trustConsumer{Kind: trustConsumerKind(path), Path: strings.Join(path, ".")}
	for owner := n.parent; owner != nil && owner.parent != nil; owner = owner.parent {
		if owner.uuid != "" {
			consumer.UUID = owner.uuid
			consumer.Label = describedAs(owner)
			if consumer.Label == "" {
				consumer.Label = strings.Join(elementPath(owner), ".") + " " + owner.uuid
			}
			return consumer, owner
		}
	}
	owner := n.parent
	if consumer.Kind == "webgui" {
		consumer.Label = "webgui"
		return consumer, owner
	}
	consumer.Label = strings.Join(elementPath(owner), ".")
	if consumer.Label == "" {
		consumer.Label = consumer.Path
	}
	if d := describedAs(owner); d != "" {
		consumer.Label = fmt.Sprintf("%s (%s)", consumer.Label, d)
	}
	return consumer, owner
}

// describedAs is the text a person knows an item by.
func describedAs(n *xmlNode) string {
	for _, field := range []string{"description", "descr", "name"} {
		if c := n.child(field); c != nil && c.text != "" {
			return c.text
		}
	}
	return ""
}

func trustConsumerKind(path []string) string {
	for _, k := range trustConsumerKinds {
		if len(k.path) != len(path) {
			continue
		}
		match := true
		for i := range path {
			if k.path[i] != "*" && k.path[i] != path[i] {
				match = false
				break
			}
		}
		if match {
			return k.kind
		}
	}
	return ""
}
