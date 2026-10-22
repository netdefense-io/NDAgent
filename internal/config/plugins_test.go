package config

import (
	"context"
	"reflect"
	"testing"
)

func TestReadRegisteredPlugins(t *testing.T) {
	cases := map[string]struct {
		xml  string
		want map[string]bool
	}{
		"listed": {
			"<?xml version=\"1.0\"?>\n<opnsense>\n  <system>\n    <firmware>\n      <plugins>os-acme-client,os-zabbix7-agent</plugins>\n      <type/>\n    </firmware>\n  </system>\n</opnsense>\n",
			map[string]bool{"os-acme-client": true, "os-zabbix7-agent": true},
		},
		"empty list": {
			"<opnsense><system><firmware><plugins/></firmware></system></opnsense>",
			map[string]bool{},
		},
		"no firmware section": {
			completeConfigXML,
			map[string]bool{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ReadRegisteredPlugins(context.Background(), writeConfigXMLFile(t, tc.xml))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestReadRegisteredPlugins_ACutShortFileIsAnError(t *testing.T) {
	setConfigXMLTiming(t, 2, configXMLLockWait)
	path := writeConfigXMLFile(t, "<opnsense><system><firmware><plugins>os-a")
	if got, err := ReadRegisteredPlugins(context.Background(), path); err == nil {
		t.Fatalf("got %v and no error: a list read from a file being written is not the list", got)
	}
}
