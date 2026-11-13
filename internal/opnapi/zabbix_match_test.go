package opnapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// zabbixGetShape renders body as /settings/get returns it: the debug level and,
// with asOptions, the lists as option maps; otherwise the lists as strings.
func zabbixGetShape(body ZabbixSettingsBody, asOptions bool) map[string]interface{} {
	options := func(csv string, all ...string) map[string]interface{} {
		out := map[string]interface{}{}
		for _, k := range all {
			out[k] = map[string]interface{}{"value": k, "selected": float64(0)}
		}
		// BaseSetField::getNodeData explodes the stored value, so an empty
		// list is one selected option with an empty key.
		for _, k := range strings.Split(csv, ",") {
			out[k] = map[string]interface{}{"value": k, "selected": float64(1)}
		}
		return out
	}
	list := func(csv string) interface{} {
		if asOptions {
			return options(csv)
		}
		return csv
	}
	m, tu, f := body.Settings.Main, body.Settings.Tuning, body.Settings.Features
	return map[string]interface{}{"zabbixagent": map[string]interface{}{
		"local": map[string]interface{}{"hostname": body.Local.Hostname},
		"settings": map[string]interface{}{
			"main": map[string]interface{}{
				"enabled": m.Enabled, "serverList": list(m.ServerList), "listenPort": m.ListenPort,
				"listenIP": list(m.ListenIP), "sourceIP": m.SourceIP, "listenBacklog": m.ListenBacklog,
				"syslogEnable": m.SyslogEnable, "logFileSize": m.LogFileSize,
				"debugLevel": options(m.DebugLevel, "val_0", "val_1", "val_2", "val_3", "val_4", "val_5"),
				"sudoRoot":   m.SudoRoot,
			},
			"tuning": map[string]interface{}{
				"startAgents": tu.StartAgents, "bufferSend": tu.BufferSend, "bufferSize": tu.BufferSize,
				"maxLinesPerSecond": tu.MaxLinesPerSecond, "timeout": tu.Timeout,
			},
			"features": map[string]interface{}{
				"enableActiveChecks": f.EnableActiveChecks, "activeCheckServers": list(f.ActiveCheckServers),
				"refreshActiveChecks": f.RefreshActiveChecks, "enableRemoteCommands": f.EnableRemoteCommands,
				"logRemoteCommands": f.LogRemoteCommands, "encryption": f.Encryption,
				"encryptionidentity": f.EncryptionIdentity, "encryptionpsk": f.EncryptionPSK,
			},
		},
	}}
}

func zabbixMatchBody() ZabbixSettingsBody {
	return BuildZabbixSettings(APIZabbixSettingsPayload{
		Hostname:           "fw1",
		Enabled:            true,
		ServerList:         []string{"10.0.0.2", "zabbix.example.com"},
		ListenIP:           []string{"10.0.0.1", "192.0.2.1"},
		ActiveCheckServers: []string{"10.0.0.2:10051"},
		DebugLevel:         "4",
		Encryption:         "1",
		EncryptionIdentity: "fw1-psk",
		EncryptionPSK:      "00112233445566778899aabbccddeeff",
	})
}

func TestZabbixSettingsMatch_TheStoredTreeMatches(t *testing.T) {
	body := zabbixMatchBody()
	for _, asOptions := range []bool{true, false} {
		if !ZabbixSettingsMatch(body, zabbixGetShape(body, asOptions)) {
			t.Errorf("lists as options %v: the device's own tree did not match", asOptions)
		}
	}

	empty := body
	empty.Settings.Features.ActiveCheckServers = ""
	if !ZabbixSettingsMatch(empty, zabbixGetShape(empty, true)) {
		t.Error("an empty list, which the get renders as one empty selected option, did not match")
	}

	reordered := body
	reordered.Settings.Main.ServerList = "zabbix.example.com,10.0.0.2"
	if !ZabbixSettingsMatch(body, zabbixGetShape(reordered, false)) {
		t.Error("a list in another order did not match")
	}

	upper := body
	upper.Settings.Main.ServerList = "10.0.0.2,Zabbix.Example.COM"
	if !ZabbixSettingsMatch(upper, zabbixGetShape(body, true)) {
		t.Error("the model lower-cases the server list, so a snippet in capitals must match what it stored")
	}
}

func TestZabbixSettingsMatch_EveryFieldCounts(t *testing.T) {
	body := zabbixMatchBody()
	raw, _ := json.Marshal(body)
	var flat struct {
		Local    map[string]string            `json:"local"`
		Settings map[string]map[string]string `json:"settings"`
	}
	if err := json.Unmarshal(raw, &flat); err != nil {
		t.Fatal(err)
	}
	count := 0
	mutate := func(name string, change func(*ZabbixSettingsBody)) {
		count++
		other := body
		change(&other)
		if ZabbixSettingsMatch(body, zabbixGetShape(other, true)) {
			t.Errorf("%s: a device that differs only there matched", name)
		}
	}
	mutate("hostname", func(b *ZabbixSettingsBody) { b.Local.Hostname = "other" })
	m := func(f func(*ZabbixMain)) func(*ZabbixSettingsBody) {
		return func(b *ZabbixSettingsBody) { f(&b.Settings.Main) }
	}
	tu := func(f func(*ZabbixTuning)) func(*ZabbixSettingsBody) {
		return func(b *ZabbixSettingsBody) { f(&b.Settings.Tuning) }
	}
	fe := func(f func(*ZabbixFeatures)) func(*ZabbixSettingsBody) {
		return func(b *ZabbixSettingsBody) { f(&b.Settings.Features) }
	}
	mutate("enabled", m(func(x *ZabbixMain) { x.Enabled = "0" }))
	mutate("serverList", m(func(x *ZabbixMain) { x.ServerList = "10.0.0.3,zabbix.example.com" }))
	mutate("listenPort", m(func(x *ZabbixMain) { x.ListenPort = "20050" }))
	mutate("listenIP", m(func(x *ZabbixMain) { x.ListenIP = "0.0.0.0" }))
	mutate("sourceIP", m(func(x *ZabbixMain) { x.SourceIP = "10.0.0.9" }))
	mutate("listenBacklog", m(func(x *ZabbixMain) { x.ListenBacklog = "7" }))
	mutate("syslogEnable", m(func(x *ZabbixMain) { x.SyslogEnable = "1" }))
	mutate("logFileSize", m(func(x *ZabbixMain) { x.LogFileSize = "5" }))
	mutate("debugLevel", m(func(x *ZabbixMain) { x.DebugLevel = "val_3" }))
	mutate("sudoRoot", m(func(x *ZabbixMain) { x.SudoRoot = "1" }))
	mutate("startAgents", tu(func(x *ZabbixTuning) { x.StartAgents = "9" }))
	mutate("bufferSend", tu(func(x *ZabbixTuning) { x.BufferSend = "9" }))
	mutate("bufferSize", tu(func(x *ZabbixTuning) { x.BufferSize = "9" }))
	mutate("maxLinesPerSecond", tu(func(x *ZabbixTuning) { x.MaxLinesPerSecond = "9" }))
	mutate("timeout", tu(func(x *ZabbixTuning) { x.Timeout = "9" }))
	mutate("enableActiveChecks", fe(func(x *ZabbixFeatures) { x.EnableActiveChecks = "0" }))
	mutate("activeCheckServers", fe(func(x *ZabbixFeatures) { x.ActiveCheckServers = "" }))
	mutate("refreshActiveChecks", fe(func(x *ZabbixFeatures) { x.RefreshActiveChecks = "60" }))
	mutate("enableRemoteCommands", fe(func(x *ZabbixFeatures) { x.EnableRemoteCommands = "1" }))
	mutate("logRemoteCommands", fe(func(x *ZabbixFeatures) { x.LogRemoteCommands = "1" }))
	mutate("encryption", fe(func(x *ZabbixFeatures) { x.Encryption = "0" }))
	mutate("encryptionidentity", fe(func(x *ZabbixFeatures) { x.EncryptionIdentity = "other" }))
	mutate("encryptionpsk", fe(func(x *ZabbixFeatures) { x.EncryptionPSK = "" }))

	shorter := body
	shorter.Settings.Main.ServerList = "10.0.0.2"
	if ZabbixSettingsMatch(body, zabbixGetShape(shorter, true)) {
		t.Error("serverList: a device with fewer servers matched")
	}

	want := len(flat.Local)
	for _, group := range flat.Settings {
		want += len(group)
	}
	if count != want {
		t.Errorf("%d fields mutated, the body has %d: a field was added without a case here", count, want)
	}
}

func TestZabbixSettingsMatch_AnUnreadableTreeIsDifferent(t *testing.T) {
	body := zabbixMatchBody()
	for name, raw := range map[string]map[string]interface{}{
		"empty":       {},
		"no wrapper":  zabbixGetShape(body, true)["zabbixagent"].(map[string]interface{}),
		"no features": {"zabbixagent": map[string]interface{}{"local": map[string]interface{}{"hostname": "fw1"}, "settings": map[string]interface{}{"main": map[string]interface{}{}, "tuning": map[string]interface{}{}}}},
	} {
		if ZabbixSettingsMatch(body, raw) {
			t.Errorf("%s: matched", name)
		}
	}
	numeric := zabbixGetShape(body, true)
	numeric["zabbixagent"].(map[string]interface{})["settings"].(map[string]interface{})["tuning"].(map[string]interface{})["timeout"] = float64(3)
	if ZabbixSettingsMatch(body, numeric) {
		t.Error("a value that is not a string matched")
	}
}

func TestZabbixRowMatches(t *testing.T) {
	up := ZabbixUserParameter{Enabled: "1", Key: "nd-cpu", Command: "sysctl -n hw.ncpu", AcceptParams: "0"}
	row := map[string]interface{}{"uuid": "u1", "enabled": "1", "key": "nd-cpu", "command": "sysctl -n hw.ncpu", "acceptParams": "0"}
	if !ZabbixUserParameterMatches(up, row) {
		t.Error("the row the write would leave did not match")
	}
	caseOnly := map[string]interface{}{}
	for k, v := range row {
		caseOnly[k] = v
	}
	caseOnly["command"] = "SYSCTL -n hw.ncpu"
	if ZabbixUserParameterMatches(up, caseOnly) {
		t.Error("a command that differs only in case matched: the model stores it as sent")
	}
	for _, key := range []string{"enabled", "key", "command", "acceptParams"} {
		other := map[string]interface{}{}
		for k, v := range row {
			other[k] = v
		}
		other[key] = "changed"
		if ZabbixUserParameterMatches(up, other) {
			t.Errorf("userparameter %s: a row that differs there matched", key)
		}
		delete(other, key)
		if ZabbixUserParameterMatches(up, other) {
			t.Errorf("userparameter %s: a row without it matched", key)
		}
	}

	alias := ZabbixAlias{Enabled: "1", Key: "nd-ping", SourceKey: "agent.ping", AcceptParams: "1"}
	aliasRow := map[string]interface{}{"uuid": "a1", "enabled": "1", "key": "nd-ping", "sourceKey": "agent.ping", "acceptParams": "1"}
	if !ZabbixAliasMatches(alias, aliasRow) {
		t.Error("the alias row the write would leave did not match")
	}
	for _, key := range []string{"enabled", "key", "sourceKey", "acceptParams"} {
		other := map[string]interface{}{}
		for k, v := range aliasRow {
			other[k] = v
		}
		other[key] = "changed"
		if ZabbixAliasMatches(alias, other) {
			t.Errorf("alias %s: a row that differs there matched", key)
		}
		delete(other, key)
		if ZabbixAliasMatches(alias, other) {
			t.Errorf("alias %s: a row without it matched", key)
		}
	}
}
