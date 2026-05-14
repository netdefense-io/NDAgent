// Copyright (C) 2026 NetDefense
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.

package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Plugin-side helper that clears the bootstrapToken field in the
// OPNsense Settings model and triggers a template reload so the next
// rendering of /usr/local/etc/ndagent.conf drops the
// `bootstrap_token=` line. See:
//   plugin/src/usr/local/opnsense/scripts/OPNsense/NetDefense/clear_rebind_token.php
const (
	clearRebindTokenScript = "/usr/local/opnsense/scripts/OPNsense/NetDefense/clear_rebind_token.php"
	phpInterpreter         = "/usr/local/bin/php"
)

// clearRebindTokenInConfigFunc is the indirection point for tests. The
// production wiring is clearRebindTokenInConfigDefault; tests swap it
// to avoid shelling out.
var clearRebindTokenInConfigFunc = clearRebindTokenInConfigDefault

// clearRebindTokenInConfig invokes the OPNsense plugin helper that
// clears the local bootstrapToken field from /conf/config.xml and
// reloads the ndagent.conf template. Idempotent on the helper side
// (no-op if the field is already empty).
//
// Called only after a successful registration whose ndagent.conf still
// carried `bootstrap_token=` — see lifecycle.go. The broker has already
// cleared its server-side hash at consumption time
// (NDBroker/src/routers/device_registration.py); this is the
// device-side housekeeping the operator used to be told to do
// manually.
func clearRebindTokenInConfig(ctx context.Context) error {
	return clearRebindTokenInConfigFunc(ctx)
}

func clearRebindTokenInConfigDefault(ctx context.Context) error {
	if _, err := os.Stat(clearRebindTokenScript); err != nil {
		// Older plugin builds that pre-date this helper, or the agent
		// is running standalone outside an OPNsense host (developer
		// laptop). Either way, there is no model state to clear.
		return fmt.Errorf("plugin helper not present at %s: %w", clearRebindTokenScript, err)
	}
	cmd := exec.CommandContext(ctx, phpInterpreter, clearRebindTokenScript, "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clear_rebind_token.php failed: %w; output: %s", err, string(out))
	}
	return nil
}
