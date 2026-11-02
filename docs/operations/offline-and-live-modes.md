# Offline and live modes

Every Nexus SymBiote command runs in one of two modes. **Offline**, the default,
guarantees that the run resolves no host name, opens no network connection and
starts no process. **Live** permits exactly three explicit observations: an HTTPS
`tools/list` session (`discover-mcp`), OSV advisory queries (`advisories`) and
operator-pinned stdio launchers (`verify-live`). Each of those three commands
also works offline from a saved export, the way a Nexus ShadowScan connector
reads an `input:` export instead of its live API.

| | Offline (default) | Live (`--live`) |
| --- | --- | --- |
| Static commands (`scan`, `validate`, `risk`, `diff`, `summary`, `blast-radius`, `vex`, `baseline`, `import-shadowscan`, `verify-artifact`, `verify-discovery`, `runtime`, `init`) | Same behavior; the guarantee is enforced | Same behavior; nothing live is added |
| `discover-mcp ENDPOINT` | Refused (exit 3) | One bounded HTTPS session to an allowed origin |
| `discover-mcp --input FILE` | Reads a saved `tools/list` result | Same |
| `advisories AIBOM` | Refused (exit 3) | Queries the OSV API over pinned HTTPS |
| `advisories AIBOM --input EXPORT` | Matches a saved OSV export | Same |
| `verify-live AIBOM --launch-policy POLICY` | Refused (exit 3) | Starts private copies of pinned launchers |
| `verify-live AIBOM --input FILE` | Compares recorded descriptors | Same |

## Choosing the mode

```bash
nexus-symbiote scan . -o agentbom.json                    # offline: the default
nexus-symbiote --offline scan . -o agentbom.json          # offline, stated explicitly
nexus-symbiote --live advisories agentbom.json            # live
NEXUS_SYMBIOTE_MODE=live nexus-symbiote advisories agentbom.json
```

The mode is resolved once, before the command reads any input:

1. `--offline` or `--live`, placed **before** the command name. Giving both is a
   usage error.
2. Otherwise `NEXUS_SYMBIOTE_MODE`, which must be exactly `offline` or `live`.
   Any other value, including an empty string, is a usage error rather than a
   silent fallback.
3. Otherwise offline.

A flag typed after the command is reported with the correct placement:

```
$ nexus-symbiote advisories agentbom.json --live
Error: No such option '--live'. (--offline and --live go before the command: nexus-symbiote --live <command> ...)
```

`.nexus-symbiote.yaml` has no mode key. The policy file is read from the checkout
being inventoried, which may be hostile, so nothing in it can enable network
access or process execution. The GitHub Action and the pre-commit hooks pin
`--offline` on every invocation.

## What offline mode guarantees

For the whole command, offline mode installs a guard in the Python process that
refuses:

| Refused | Python entry points |
| --- | --- |
| Name resolution | `socket.getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo` |
| Outbound and listening sockets | `socket.socket.connect`, `connect_ex`, `listen`, `sendto`, `sendmsg`; `socket.create_connection`, `create_server` |
| Process creation | `subprocess.Popen` (and with it `run`, `call`, `check_output`, asyncio subprocesses), `os.system`, `os.popen`, `os.fork`, `os.forkpty`, `os.posix_spawn`, `os.posix_spawnp`, `os.execv`, `os.execve`, `_posixsubprocess.fork_exec` |

The live HTTPS transport, the OSV client and the stdio launcher also check the
mode themselves before they act, so a refusal does not depend on the guard
alone. A refusal raises `OfflineViolation`, which derives from `BaseException`:
a collector's broad `except Exception` handler cannot turn it into a recorded,
soft failure. If a static command ever reached a refused operation, the run would
stop with exit 3 and a message asking for a defect report; the test suite runs
every static command under the guard to keep that from happening.

Local socket pairs and binding a loopback address stay available: asyncio needs
the former, and a dependency probes IPv6 support with the latter when it is
imported. Neither sends anything off the host.

The guard is a tripwire for this package and its Python dependencies. It is not a
sandbox. Native code that calls the operating system directly bypasses it, as
would a compromised dependency written to evade it. Where a hard boundary is
required, add operating-system controls: a network namespace (`unshare -n`), an
egress policy, seccomp, or a container without network access.

## Live observations

Live mode permits an operation; it never relaxes the operation's own controls.

| Command | Contacts or runs | Controls that still apply |
| --- | --- | --- |
| `discover-mcp ENDPOINT --allowed-origin ORIGIN` | One HTTPS origin, `initialize`, `notifications/initialized` and `tools/list` only | The origin must be listed exactly; HTTPS only; DNS answers must be public addresses and are pinned for the session; redirects, proxies and server-initiated requests are refused; byte, page, tool-count and time limits; tools are never called; a `--token-env` token is redacted from evidence |
| `advisories AIBOM` | `https://api.osv.dev/v1/query` through the same pinned transport | Only exact PyPI and npm package URLs are queried; response size and time limits; lookup failures and unresolved identities make the result incomplete (exit 3) |
| `verify-live AIBOM --launch-policy POLICY` | Private copies of launchers whose SHA-256 the operator pinned in a policy kept outside the project | No project arguments, environment or working directory; launcher bytes are copied and re-hashed before execution; the process group is killed after a bounded session; descriptors are compared, tools are never called |

A served descriptor that matches the inventory does not establish backend safety
or authorization. Run live observations from an isolated worker with a
restricted identity, filesystem and egress, and keep their evidence separate
from the static inventory.

## Offline counterparts: replaying a saved export

Each live command reads a saved export with `--input` and applies the same
validation it applies to live data. Nothing is contacted, so these work in
offline mode, in air-gapped review and in CI without egress. Evidence read from
an export keeps declared assurance: whoever saved the export observed it, not
this run.

### `discover-mcp --input`

The input is a `tools/list` result object, a JSON-RPC response carrying one, or a
JSON list of result pages in order. Any MCP client can save one; for example the
output of an MCP inspector's `tools/list` call. ENDPOINT is optional and only
labels the report.

```
$ nexus-symbiote discover-mcp https://tickets.example.com/mcp --input tools-list.json
{
  "endpoint": "https://tickets.example.com/mcp",
  "collector_id": "nexus-symbiote-mcp-export",
  "complete": true,
  "collection_mode": "offline",
  "input_digest": "sha256:f945e093...",
  "tools": [{"name": "create_ticket", "definition_hash": "sha256:cbc53310...", ...}, ...]
  ...
}
```

Each descriptor passes the checks live discovery applies (identity, text fields,
JSON Schema validity, annotation types) and gets the same full-descriptor digest.
An export whose last page still carries `nextCursor`, or has pages after the
final one, is incomplete (exit 3). `--allowed-origin` and `--token-env` are live
options and are rejected with `--input`.

### `advisories --input`

The input is what [osv.dev](https://osv.dev) publishes for offline use (an
ecosystem's `all.zip`, for example
`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`), a directory of
OSV JSON records, or a JSON file holding one record, a list of records, or a
`{"vulns": [...]}` response.

```bash
nexus-symbiote advisories agentbom.json --input PyPI-all.zip -o advisories.json
```

For every exact PyPI or npm package URL in the inventory, a record is a match when
an `affected` entry for that package lists the version in `versions`, or an
`ECOSYSTEM` or `SEMVER` range includes it, evaluated as the
[OSV schema](https://ossf.github.io/osv-schema/) specifies. PyPI versions are
compared with PEP 440 rules and npm versions with SemVer 2.0.0 precedence.
Withdrawn records are skipped and counted. An entry that cannot be evaluated (an
unparseable version, a `GIT`-only range with no version list, an entry with
neither) is reported as undetermined and makes the result incomplete instead of
clean. Components without an exact package URL, such as an npm dependency
declared as `^1.0.0`, are also reported, as the live command reports them.

Reading never follows a symbolic link and is bounded: 4 MiB per record, 64 MiB
for a single JSON file, 1,000,000 files and 4 GiB in total. For a whole
ecosystem, pass the archive rather than one large JSON file. An export is a point in
time: a version released after the export was taken can be affected by a range
the export lists, but only a newer export can show advisories published since.

### `verify-live --input` and `--save-descriptors`

The input maps exact server references to complete tool lists:

```json
{
  "format": "nexus-symbiote.recorded-tools/1",
  "servers": {
    "mcp-server:3f2a...": {"tools": [{"name": "weather", "description": "...", "inputSchema": {"type": "object"}}]}
  }
}
```

A live run writes this file with `--save-descriptors`, so an isolated worker can
observe the launchers and a reviewer can compare the result elsewhere, offline:

```bash
# On the isolated worker
nexus-symbiote --live verify-live agentbom.json --launch-policy /operator/launch-policy.json \
  --save-descriptors descriptors.json
# Anywhere, offline
nexus-symbiote verify-live agentbom.json --input descriptors.json --json-output
```

A server in the inventory that the recording does not cover makes the comparison
incomplete (exit 3). A file in another format, a duplicate tool name or a tool
without an `inputSchema` object is invalid input (exit 1). Changed, new or
missing tools are drift (exit 2). With `--record`, replayed descriptors enter
the unsigned candidate with declared assurance and the method
`recorded-tools-list-export`; descriptors observed live enter with observed
assurance and add a `live_operations` record.

## How the mode is recorded

Every inventory written by `scan`, `import-shadowscan`, `baseline` or
`verify-live --record` states how its evidence was collected, in
`metadata.completeness`:

| Field | Values |
| --- | --- |
| `collection_mode` | `offline`: every record came from files or saved exports. `live`: at least one record came from a live step in `live_operations`. |
| `offline_enforced` | `true` when the producing run enforced offline mode |
| `live_operations` | One entry per live step that contributed evidence: `command`, `kind` (`network` or `process`), `target` (a server reference or sanitized origin, never a credential) and `observed_at` |

CycloneDX and SPDX exports carry the same facts as the `nexus-symbiote:collectionMode`
and `nexus-symbiote:offlineEnforced` properties, and SARIF in
`runs[0].invocations[0].properties`. Reports of the live commands carry
`collection_mode` at the top level. Inventories written before these fields
existed have no value for them, which means unknown.

## Exit codes

Modes use the same [exit codes](../reference/exit-codes.md) as every command. A
live step refused in offline mode exits 3 and writes nothing. A conflicting or
invalid mode setting is a usage error and exits 1 before any input is read.
