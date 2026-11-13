# ZabbixAgent.xml

A copy of the os-zabbix-agent plugin's settings model, from opnsense/plugins:
`net-mgmt/zabbix-agent/src/opnsense/mvc/app/models/OPNsense/ZabbixAgent/ZabbixAgent.xml`
at commit `110eaa13e847` (model version 1.2.4; the plugin was 1.17 there, and the model is unchanged
through 1.19).

`TestZabbixSettingsDefaultsAreTheModels` holds `zabbixSettingsDefaults` (internal/opnapi/zabbix.go)
to it, and `TestZabbixEntryDefaultsAreTheModels` the defaults of the userparameter and alias
conversions. A field a ZABBIX_SETTINGS, ZABBIX_USERPARAMETER or ZABBIX_ALIAS snippet leaves out
takes the default here.

To refresh it after a plugin release:

    gh api "repos/opnsense/plugins/contents/net-mgmt/zabbix-agent/src/opnsense/mvc/app/models/OPNsense/ZabbixAgent/ZabbixAgent.xml" \
      --jq .content | base64 -d > internal/opnapi/testdata/zabbix/ZabbixAgent.xml

Then run `go test ./internal/opnapi/ -run 'TestZabbix(Settings|Entry)DefaultsAreTheModels'`, update
the defaults until both pass, and update the commit and the versions above.
