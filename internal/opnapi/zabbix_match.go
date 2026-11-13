package opnapi

import "strings"

// ZabbixUserParameterMatches reports whether a userparameter's search row
// already holds what the write would send, so the write can be skipped.
func ZabbixUserParameterMatches(want ZabbixUserParameter, row map[string]interface{}) bool {
	return holds(row, "enabled", want.Enabled) && holds(row, "key", want.Key) &&
		holds(row, "command", want.Command) && holds(row, "acceptParams", want.AcceptParams)
}

// ZabbixAliasMatches is ZabbixUserParameterMatches for an alias.
func ZabbixAliasMatches(want ZabbixAlias, row map[string]interface{}) bool {
	return holds(row, "enabled", want.Enabled) && holds(row, "key", want.Key) &&
		holds(row, "sourceKey", want.SourceKey) && holds(row, "acceptParams", want.AcceptParams)
}

// ZabbixSettingsMatch reports whether the settings /settings/get returned
// already hold every field of body, so the write can be skipped. Each field is
// compared with the value as the model stores it: the lists as sets, and the
// fields the model lower-cases (the two server lists, the addresses)
// lower-cased. A field that is missing, or in a shape this does not read,
// counts as different.
func ZabbixSettingsMatch(body ZabbixSettingsBody, raw map[string]interface{}) bool {
	za, _ := raw["zabbixagent"].(map[string]interface{})
	local, _ := za["local"].(map[string]interface{})
	settings, _ := za["settings"].(map[string]interface{})
	main, _ := settings["main"].(map[string]interface{})
	tuning, _ := settings["tuning"].(map[string]interface{})
	features, _ := settings["features"].(map[string]interface{})
	if local == nil || main == nil || tuning == nil || features == nil {
		return false
	}
	m, t, f := body.Settings.Main, body.Settings.Tuning, body.Settings.Features
	lower := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	plain := []struct {
		node      map[string]interface{}
		key, want string
	}{
		{local, "hostname", body.Local.Hostname},
		{main, "enabled", m.Enabled},
		{main, "listenPort", m.ListenPort},
		{main, "sourceIP", lower(m.SourceIP)},
		{main, "listenBacklog", m.ListenBacklog},
		{main, "syslogEnable", m.SyslogEnable},
		{main, "logFileSize", m.LogFileSize},
		{main, "sudoRoot", m.SudoRoot},
		{tuning, "startAgents", t.StartAgents},
		{tuning, "bufferSend", t.BufferSend},
		{tuning, "bufferSize", t.BufferSize},
		{tuning, "maxLinesPerSecond", t.MaxLinesPerSecond},
		{tuning, "timeout", t.Timeout},
		{features, "enableActiveChecks", f.EnableActiveChecks},
		{features, "refreshActiveChecks", f.RefreshActiveChecks},
		{features, "enableRemoteCommands", f.EnableRemoteCommands},
		{features, "logRemoteCommands", f.LogRemoteCommands},
		{features, "encryption", f.Encryption},
		{features, "encryptionidentity", f.EncryptionIdentity},
		{features, "encryptionpsk", f.EncryptionPSK},
	}
	for _, p := range plain {
		if !holds(p.node, p.key, p.want) {
			return false
		}
	}

	lists := []struct {
		node      map[string]interface{}
		key, want string
	}{
		{main, "serverList", strings.ToLower(m.ServerList)},
		{main, "listenIP", strings.ToLower(m.ListenIP)},
		{features, "activeCheckServers", strings.ToLower(f.ActiveCheckServers)},
	}
	for _, l := range lists {
		got, ok := storedSet(l.node[l.key])
		if !ok || !sameSet(got, csvSet(l.want)) {
			return false
		}
	}

	level, ok := storedSet(main["debugLevel"])
	return ok && len(level) == 1 && level[m.DebugLevel]
}

// holds reports whether row[key] is the string want. A value of any other type
// never matches, so the write goes ahead.
func holds(row map[string]interface{}, key, want string) bool {
	got, ok := row[key].(string)
	return ok && got == want
}

// storedSet reads a list or option field as /settings/get returns it: a
// comma-separated string, or a map of options in which the selected ones are
// set. An empty list field renders as one selected option with an empty key,
// which is no entry.
func storedSet(v interface{}) (map[string]bool, bool) {
	switch val := v.(type) {
	case string:
		return csvSet(val), true
	case map[string]interface{}:
		set := map[string]bool{}
		for key, opt := range val {
			o, ok := opt.(map[string]interface{})
			if !ok {
				return nil, false
			}
			if key == "" {
				continue
			}
			switch sel := o["selected"].(type) {
			case float64:
				if sel == 1 {
					set[key] = true
				}
			case string:
				if sel == "1" {
					set[key] = true
				}
			case bool:
				if sel {
					set[key] = true
				}
			}
		}
		return set, true
	}
	return nil, false
}

func csvSet(s string) map[string]bool {
	set := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		if item != "" {
			set[item] = true
		}
	}
	return set
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
