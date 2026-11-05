# Offline and live modes

Nexus SymBiote runs **offline by default**. Three commands can observe something
outside your local files, and only when you ask for **live mode** explicitly.

## Why

- **Inventory runs on untrusted input.** A scan reads repositories, model files and
  reports that an attacker may control. If collection could resolve a host name or
  open a connection, a crafted file could turn a scan into DNS or HTTP exfiltration
  from your CI runner. Offline-by-default removes that path.
- **Air-gapped and regulated environments need a statement they can rely on.**
  "This command makes no network connections and starts no processes" is enforced
  at run time and covered by tests rather than asserted only in documentation.
- **Some evidence only exists live.** The tools an MCP server actually serves, and
  the advisories published today, cannot be read from a checkout. Live mode makes
  those observations available without making them implicit.

## What

| | Offline (default) | Live (`--live` or `NEXUS_SYMBIOTE_MODE=live`) |
|---|---|---|
| Name resolution, network connections | Refused | Allowed for the three live commands only |
| Starting processes | Refused | Not guarded for the three live commands; only `verify-live` is designed to start processes (its pinned launchers) |
| `discover-mcp`, `advisories`, `verify-live` | Refused with exit 2 and a hint | Run |
| Every other command | Runs | Runs, **still offline** |

The three live commands, and what each one contacts:

| Command | What it reaches | Safeguards (in addition to live mode) |
|---|---|---|
| `discover-mcp` | The HTTPS MCP endpoint you name | Exact `--allowed-origin` match; HTTPS only; destination pinned to one public IP address (private, loopback, link-local, NAT64, 6to4 and Teredo addresses are refused); no proxies or redirects; bounded size and time; never calls a tool; the bearer token is read from `--token-env` and never written to evidence |
| `advisories` | `https://api.osv.dev/v1/query` | Same pinned HTTPS transport; exact `pkg:pypi`/`pkg:npm` package URLs only; at most 500 components and a 60-second total budget; no response text copied into the report |
| `verify-live` | The operator-pinned stdio launchers in `--launch-policy` | The policy file must live outside the project; each launcher is an absolute path with a SHA-256 pin; a private copy is executed with an empty environment (only `PATH`), no project arguments and no project working directory; 20-second deadline; never calls a tool |

**Mode selection.** A `--offline` or `--live` flag (placed before the command) wins;
otherwise `NEXUS_SYMBIOTE_MODE` decides; otherwise the mode is offline. An
unrecognized value such as `NEXUS_SYMBIOTE_MODE=LIVE` is an error (exit 2), not a
fallback, so a typo can neither enable live mode nor hide a request for it. Passing
both flags is also an error. A project's `.nexus-symbiote.yaml` can never select the
mode, because it is part of the checkout being inventoried.

## How

### Use it

```bash
nexus-symbiote scan . -o agentbom.json             # offline, the default
nexus-symbiote --offline scan . -o agentbom.json   # the same, stated explicitly

nexus-symbiote --live advisories agentbom.json -o advisories.json
nexus-symbiote --live discover-mcp https://mcp.example.com/mcp \
  --allowed-origin https://mcp.example.com --token-env MCP_TOKEN -o observed.json

export NEXUS_SYMBIOTE_MODE=live                    # for a CI job that runs live steps
nexus-symbiote advisories agentbom.json -o advisories.json
```

Mode flags go **before** the command. Running a live command offline exits with
status 2 and tells you how to enable live mode:

```text
$ nexus-symbiote advisories agentbom.json
Error: advisories is a live command: it queries the OSV vulnerability API (api.osv.dev)
over HTTPS. Commands run offline by default. Re-run with --live before the command
(nexus-symbiote --live advisories ...) or set NEXUS_SYMBIOTE_MODE=live.
```

The GitHub Action and the pre-commit hooks run `scan`, `validate` and `risk`, which
are always offline, so they need no configuration.

### How offline mode is enforced

For the duration of an offline command, the CLI replaces these Python entry points
with functions that raise `OfflineViolation`:

- `socket.socket` methods: `connect`, `connect_ex`, `listen`, `sendto`, `sendmsg`;
- name resolution: `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`,
  `gethostbyaddr` and `getnameinfo`, in both `socket` and `_socket`;
- `socket.create_connection` and `socket.create_server`;
- process creation: `subprocess`, `os.system`, `os.fork`, `os.forkpty`,
  `os.posix_spawn`, `os.posix_spawnp`, `os.execv`, `os.execve`, and
  `_posixsubprocess.fork_exec` together with the reference that `subprocess`
  keeps to it.

`OfflineViolation` derives from `BaseException`, so a collector's broad
`except Exception` cannot turn it into a recorded, soft failure. The command stops
with exit status 1 and asks you to report a defect; a scan stops before it writes
its inventory. The original functions are restored when the command ends.

The C socket type (`_socket.socket`, also named `socket.SocketType`) is immutable
and cannot be patched, so a CPython audit hook raises the same `OfflineViolation`
while an offline command runs. It refuses creating any socket other than a
Unix-domain socket. An internet socket therefore cannot be opened during the
command, and the name resolution that `connect`, `sendto` and `bind` perform for a
host-name address never starts on one. Creating Unix-domain sockets and socket
pairs is allowed, so asyncio's event loop and `send` and `recv` on a socket pair keep
working, but `connect`, `listen`, `sendto` and `sendmsg` are refused for every
socket family, Unix-domain included. When urllib3 is installed, the CLI imports
`urllib3.util.connection` before the guard starts: that import tries to bind an IPv6
socket to `::1` to detect IPv6 support, reaches no network, and would otherwise stop
Sigstore's offline verifier, which imports urllib3. The hook also refuses the
`socket.connect`, `socket.sendto` and `socket.sendmsg` events, the name resolution
events and the process creation events. CPython raises these events inside the C
implementations, so they also cover references to those functions captured before
the command started. `_posixsubprocess.fork_exec` raises no audit event: only its
two module attributes listed above are replaced, so another reference to it
captured earlier is not covered. An audit hook cannot be removed, so it stays
installed and is inert outside an offline command.

The test suite runs every static command through the CLI with this guard in place,
and checks that Sigstore's offline verifier (used for signature checks) loads its
embedded trust root without network access.

### Limits

The guard is a tripwire for this package and its Python dependencies, **not a
sandbox**. Native code that calls the operating system directly bypasses it, and
a process started by `verify-live` is not covered at all. A socket created before
the command started is not affected by the creation check: code that holds one can
still accept or use an existing connection, because `listen`, `accept`, `send` and
`recv` raise no audit event, and its `bind`, `connect` or `sendto` on a host-name
address still resolves the name before any refused event fires. A descriptor opened
earlier can also be wrapped during the command by declaring a Unix-domain family.
No code from the scanned project runs inside the process, so these limits concern
deliberate in-process evasion, not crafted input. Where you need a hard
boundary, add an operating-system control as well: a network namespace (for
example `unshare --net --map-root-user`), a container started with
`--network none`, or a deny-all egress policy. Run `verify-live` launchers under an
isolated identity with a restricted filesystem and egress, as described in the
[security model](security-model.md).

### Try it without network access

The repository contains a synthetic agent project at
[`examples/demo-agent`](../examples/demo-agent) and a recorded ShadowScan report.
From a checkout:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote import-shadowscan tests/fixtures/shadowscan/code-report-0.1.4.json \
  --report-only -o imported.aibom.json
```

See [`examples/README.md`](../examples/README.md) for the full walkthrough.
