# NDAgent

NDAgent is the on-firewall agent for **NetDefense for OPNsense**. It runs as a service on your OPNsense box, holds a persistent outbound connection to the NetDefense control plane, and executes a fixed set of signed commands — configuration sync, firmware updates, backups, and remote access sessions.

This repository contains the open-source source code for:

- The **NDAgent** Go binary (`cmd/`, `internal/`, `pkg/`)
- The **OPNsense plugin** that packages the agent for installation on OPNsense (`plugin/`)

Production packages for OPNsense are published to the NetDefense package repository; see the [Releases](https://github.com/netdefense-io/NDAgent/releases) page for source snapshots that match each released version.

## Trust model

This code is open source specifically so none of the following is a "trust me" claim — it's what's in this repository.

**Outbound-only.** NDAgent never opens a listening port. It dials out to the control plane over HTTPS/WSS and stays connected; there's nothing on the firewall for a scanner or an attacker on the network to find or connect to.

**Every command is signed, bound, and sequenced.** Commands from the control plane arrive as [COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc8152) envelopes signed with Ed25519 (`internal/signing/signing.go`). Each envelope binds the operation type, the target device UUID, a signed expiry, and a strictly-increasing per-device sequence number. The agent verifies the signature and every one of those bindings before a command is even parsed (`internal/network/dispatcher.go`):

- A device rejects a command addressed to a different device UUID.
- A replayed command — same or earlier sequence number — is a no-op, not a re-execution.
- A command that arrives after its signed expiry fails closed. It never fires late.

**The dispatch tier can't forge commands.** The relay service that fans commands out to devices holds no private signing key and independently re-verifies every envelope's signature before forwarding it. Compromising that tier doesn't get you the ability to mint commands — you'd still need the control plane's private key.

**A fixed vocabulary.** NDAgent understands exactly ten operations — `PING`, `SYNC`, `PULL`, `BACKUP`, `CONNECT`, `RESTART`, `REBOOT`, `SHUTDOWN`, `PLUGIN_INSTALL`, `FIRMWARE_UPGRADE` — each with its own typed payload and handler (`internal/tasks/register.go`). The task protocol carries no "run this shell command" operation.

Be clear about what that does and does not buy you, because the distinction is the whole point: **`CONNECT` opens a remote session, and a session reaches a shell.** A fixed vocabulary means the wire protocol can't be coerced into arbitrary instructions — it does not mean a caller holding a write-scoped credential is confined. Everything above protects the *channel*. None of it contains a compromised control plane or a stolen operator credential.

**What the device itself decides**, independent of the control plane:

- **The remote-access ceiling.** `remote_access_policy` (Services → NetDefense → Settings) caps what any remote session may be: `full`, `readonly` (web UI only — no shell, no SSH, no exec stream, whatever the caller asked for), or `disabled` (no session opens at all). The control plane may request a session at or below this ceiling and never above it. It cannot raise it: the value lives in the device's own configuration, and the agent's OPNsense API client has no writer for it, so a configuration sync can't change it either. Enforced twice — in the `CONNECT` handler before any relay is dialed (`internal/tasks/connect.go`), and again at the per-stream chokepoint every stream must traverse (`internal/pathfinder/proxy.go`).
- **Read-only sessions.** When a session is read-only — whether the caller asked for that or the device's ceiling imposed it — the local proxy refuses every service except the web UI, regardless of what's requested (`internal/pathfinder/proxy.go`).
- **Protected accounts.** `root`, the agent's own service account, and the read-only service account can never be created, modified, or deleted **by configuration sync**, whatever the control plane sends (`internal/opnapi/users_types.go`). Note the scope: this constrains the sync path, not someone who already has a shell.

**What none of this stops.** A credential with write access can open a remote session, and from a session, a shell. The ceiling above is the limit on that; the credential is the key — so scope the tokens you issue accordingly, especially for AI agents driving the MCP tools. And even with remote access disabled, a compromised control plane is not harmless: configuration sync can install packages, and package post-install scripts run as root. `reject_dangerous_snippets` (on by default) covers the privileged-user, SSH-key and Zabbix-command vectors, but not package installation.

**Re-keying requires a device-local step.** If a device's signing key ever needs to be re-bound (lost key material, suspected compromise), an operator issues a one-time token from the control plane that expires in 24 hours by default, and that token has to be applied in the device's own local configuration before a new key is accepted. The control plane can't rotate a device's trusted key by itself.

## Install

```sh
curl -sSL https://repo.netdefense.io/install.sh | sh
```

Installs the OPNsense plugin package from the NetDefense repository and walks through registration.

For headless/scripted provisioning (registers, provisions OPNsense API credentials, and enables the service in one step):

```sh
curl -sSL https://repo.netdefense.io/install.sh | sh -s -- --auto-setup=<org-registration-token>
```

Requirements: **FreeBSD 14 or FreeBSD 15 / amd64** — OPNsense 25.7 through 26.1 run FreeBSD 14, OPNsense 26.7+ runs FreeBSD 15. The Go binary is identical across environments — this repo builds it from source; the packages above are what's actually signed and shipped.

## What it talks to

NDAgent makes outbound HTTPS/WSS connections to the NetDefense control plane (`hub.netdefense.io` by default) and, only for remote-access sessions, to the relay service (`pathfinder.netdefense.io`). No inbound firewall rule is required or used.

## Open source vs. not

The agent and the OPNsense plugin in this repository are **Apache-2.0**. Every package published to the NetDefense repository corresponds to a tagged commit here — same source, not a paraphrase of it. This mirror is also self-contained enough to build on its own: `go build ./cmd/ndagent` compiles the agent from exactly the `cmd/`, `internal/`, `pkg/`, `go.mod`, and `go.sum` in this repository, nothing outside it required. The control plane it talks to (device management, policy, the web dashboard) is closed-source SaaS, with a free tier for personal, non-commercial use.

## Links

- [Security model](https://netdefense.io/security)
- [Docs](https://netdefense.io/docs)
- [NDCLI](https://github.com/netdefense-io/NDCLI) — the command-line client, also Apache-2.0
- [netdefense.io](https://netdefense.io)

## Architecture

NDAgent runs as a service on an OPNsense device and operates in two phases:

1. **Registration phase (HTTP)** — polls the NetDefense server until the device is approved.
2. **WebSocket phase** — maintains a persistent connection to receive signed tasks and pushes results back.

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
  pathfinder/         Remote-access tunnel client (CONNECT sessions)
  security/           Input validation
  signing/            COSE_Sign1 envelope build/verify (Ed25519)
  tasks/              Task handlers (PING, SYNC, PULL, RESTART, ...)
  util/               Shared utilities
  xmlconfig/          Legacy OPNsense config.xml parsing
pkg/version/          Version info injected at build time via ldflags
plugin/               OPNsense plugin (MVC sources + package manifest)
```

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

## Releases

Each tagged release on this repository corresponds to a released version of NDAgent. The same tag is used for the OPNsense package published to the NetDefense repository. See the [Releases](https://github.com/netdefense-io/NDAgent/releases) page for changelogs.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full text.

## Contributing

Issues and pull requests are welcome. For questions or security reports, contact `info@netdefense.io`.
