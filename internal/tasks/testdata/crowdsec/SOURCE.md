# General.xml

A copy of the os-crowdsec plugin's settings model, from opnsense/plugins:
`security/crowdsec/src/opnsense/mvc/app/models/OPNsense/CrowdSec/General.xml`
at commit `5e83a9f93cf7` (model version 1.0.12; the plugin is 1.0.12 there).

`TestCrowdsecDefaultsAreTheModels` holds `crowdsecDefaults` (internal/tasks/sync_crowdsec.go) to
it: a key a CROWDSEC_SETTINGS snippet leaves out takes the default here.

To refresh it after a plugin release:

    gh api "repos/opnsense/plugins/contents/security/crowdsec/src/opnsense/mvc/app/models/OPNsense/CrowdSec/General.xml" \
      --jq .content | base64 -d > internal/tasks/testdata/crowdsec/General.xml

Then run `go test ./internal/tasks/ -run TestCrowdsecDefaultsAreTheModels`, update the defaults
until it passes, and update the commit and the version above.
