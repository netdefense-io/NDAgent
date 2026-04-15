# NDAgent

NDAgent is the device-side daemon of the [NetDefense](https://netdefense.io/) platform. It runs on OPNsense firewalls, connects to the NetDefense central server over WebSocket, and synchronizes firewall configuration (aliases, rules, and related objects) with the platform.

This repository contains the open-source source code for:

- The **NDAgent** Go binary (`cmd/`, `internal/`, `pkg/`)
- The **OPNsense plugin** that packages the agent for installation on OPNsense (`plugin/`)

Production packages for OPNsense are published to the NetDefense package repository; see the [Releases](https://github.com/netdefense-io/NDAgent/releases) page for source snapshots that match each released version.

## Architecture

NDAgent runs as a service on an OPNsense device and operates in two phases:

1. **Registration phase (HTTP)** — polls the NetDefense server until the device is approved.
2. **WebSocket phase** — maintains a persistent connection to receive tasks (PING, SYNC, PULL, RESTART, etc.) and pushes results back.

Managed firewall objects (aliases, rules) are identified by a dedicated UUID prefix so the agent only touches objects it created and never interferes with manually configured entries.

### Package layout

```
cmd/ndagent/          Entry point (Cobra CLI)
internal/
  config/             Configuration loader (key=value files)
  core/               Lifecycle manager and shutdown coordination
  logging/            Zap-based logging (syslog + stdout)
  network/            WebSocket client, registration, heartbeat, dispatcher
  opnapi/             OPNsense REST API client (aliases, rules, interfaces)
  security/           Input validation
  tasks/              Task handlers (PING, SYNC, PULL, RESTART, ...)
  util/               Shared utilities
  xmlconfig/          Legacy OPNsense config.xml parsing
pkg/version/          Version info injected at build time via ldflags
plugin/               OPNsense plugin (MVC sources + package manifest)
```

## Requirements

- Go **1.24+**
- Production target: **FreeBSD 14 / amd64** (OPNsense 25.7+)
- For local development: macOS or Linux

## Building

```bash
# Build for the current OS/arch
make build

# Cross-compile for OPNsense (FreeBSD amd64)
make build-freebsd

# Cross-compile for macOS (amd64 + arm64)
make build-darwin

# Build every supported platform
make build-all

# With debug symbols
make build-debug
make build-freebsd-debug
```

Binaries are written to `bin/`.

## Testing

```bash
# Unit tests with race detector
make test

# Tests for a specific package
go test ./internal/config/...
```

Integration tests that target a live OPNsense instance are guarded by the `integration` build tag:

```bash
OPNSENSE_API_KEY="..." \
OPNSENSE_API_SECRET="..." \
OPNSENSE_API_URL="https://<host>/api" \
go test -tags=integration ./internal/opnapi/
```

## Configuration

NDAgent reads a `key=value` config file (default: `/usr/local/etc/ndagent.conf`).

Minimum required keys:

```ini
enabled=true
token=<organization-token>
device_uuid=<device-uuid>
```

For OPNsense API operations (SYNC / PULL):

```ini
api_key=<opnsense-api-key>
api_secret=<opnsense-api-secret>
opnsense_api_url=https://127.0.0.1/api
```

Example configuration templates are under `configs/`.

## OPNsense plugin

The `plugin/` directory contains the OPNsense plugin sources (`plugin/src/`) and the FreeBSD package manifest (`plugin/+MANIFEST`). The plugin installs the `ndagent` binary, its service definition, and the UI integration for OPNsense.

Prebuilt signed packages are distributed through the NetDefense package repository. Instructions for adding the repository to an OPNsense device are available at https://netdefense.io/.

## Releases

Each tagged release on this repository corresponds to a released version of NDAgent. The same tag is used for the OPNsense package published to the NetDefense repository. See the [Releases](https://github.com/netdefense-io/NDAgent/releases) page for changelogs.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full text.

## Contributing

Issues and pull requests are welcome. For questions or security reports, contact `info@netdefense.io`.
