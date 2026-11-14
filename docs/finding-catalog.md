# Finding catalog

A finding, or risk, is a security-relevant observation about one component: its
category, severity, detail and recommendation. Findings describe declarations in
the repository; they are not confirmed vulnerabilities. This page lists every
category this version emits, which collector raises it, what it means and what to
do about it. Use these names in `ignore_categories` and in
[suppressions](policy-reference.md#suppressions).

- [How findings affect the gates](#how-findings-affect-the-gates)
- [Categories](#categories)
- [Reports that are not findings](#reports-that-are-not-findings)
- [SARIF rules](#sarif-rules)

## How findings affect the gates

`risk`, and the scan gate of `scan`, `baseline` and the GitHub Action, weigh every
finding by severity: critical 10, high 7, medium 4, low 1 and info 0. The aggregate
score is that sum. It is not capped and it is not a percentage from 0 to 100, so it
grows with the number of findings. The gate fails when any of these holds, with the
built-in policy's values in parentheses:

- a finding is at or above `fail_on_severity` (`critical` for the CLI and a project
  policy; the GitHub Action passes `high` unless its `fail-on-severity` input says
  otherwise);
- the aggregate score, the sum of the weights, is at or above `fail_threshold` (50);
- an `invalid_safetensors` finding is present, whatever the score;
- coverage is incomplete or unknown;
- a repository scan found no agent manifest or supported local inventory evidence;
- a suppression has expired.

A finding left out by `ignore_categories` or an active suppression counts toward
none of these. The [policy reference](policy-reference.md) lists the settings that
change them; the [glossary](glossary.md#risk-level) explains the risk level that
`risk` prints beside the score.

## Categories

Collectors are named as `--scanner` names them. `risk` adds `invalid_safetensors`
itself, and adds `serialization_format` or `code_execution` when a model's recorded
fields call for one that its findings no longer carry, as in an edited inventory.

| Category | Severity | Raised by | Meaning | What to do |
| --- | --- | --- | --- | --- |
| `additional_directories` | low | `ide_agents` | Claude Code settings grant access to directories outside the project. | Review the directories and approve the exact value. |
| `attestation` | low | `ide_agents` | A VS Code extension the project recommends has no verified attestation of its identity or publisher. | Verify the installed extension's identity, publisher and artifact separately. |
| `authentication` | medium | `a2a` | An A2A agent card declares no nonempty authentication requirement, for itself or for a skill, or an A2A client declares no authentication method. | Declare the requirement, and verify separately that the endpoint enforces it. |
| `auto_approval` | medium | `mcp` | An MCP server's tools run without per-call approval: `alwaysAllow`, `autoApprove` or `trust: true`. | Require approval for tool calls with side effects. |
| `bidi_override` | critical | `prompt` | An instruction file contains bidirectional embedding, override or isolate characters, which can make text read differently from how it is processed. | Remove them. |
| `capability_scope` | high or medium | `mcp` | A tool in a configuration's `tools` array declares destructive or financial side effects (high), or is declared read-only but named for a destructive operation (medium). | Require human approval for destructive operations; verify the tool's effects before relying on `readOnlyHint`. |
| `code_execution` | critical | `model`, `risk` | A model configuration sets `trust_remote_code: true`, so loading the model runs code from its repository. | Audit that code, or use a model that does not need it. |
| `completeness` | medium or low | `mcp`, `a2a`, `rag`, `ide_agents` | Low: values that only the binding key binds, so their changes cannot raise a drift alert, or an A2A card that declares no skills. Medium: MCP identity fields withheld because credential values occur in them. | Set `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` for every scan and baseline ([source binding](verification-source-binding.md)); keep credentials out of names, hosts and package references. |
| `credential_helper` | medium | `ide_agents` | Claude Code settings declare `apiKeyHelper`, a command that runs to obtain credentials. | Review the command and approve its exact value. |
| `custom_code` | high | `model` | A model's configuration declares custom code (`auto_map` or `custom_pipelines`), which loading runs under `trust_remote_code`. | Review the declared modules before loading; their digests are recorded, so a change raises a drift alert. |
| `data_integrity` | high or medium | `rag` | A retrieval endpoint or connection without encryption (high), or a RAG source that declares no content filtering (medium). | Use authenticated encrypted transport; declare and review the ingestion and content controls. |
| `detection_method` | info | `a2a` | An A2A SDK reference was found in Python source; no deployment is established. | Add an explicit agent card or client configuration. |
| `directional_marks` | medium | `prompt` | An instruction file contains LRM, RLM or ALM marks, which are ordinary in right-to-left text but can reorder neutral characters. | Confirm that each mark belongs to right-to-left text. |
| `endpoint_identity` | high or medium | `mcp` | An MCP endpoint's host cannot be established from its URL (high), or the endpoint depends on the environment (medium). | Declare a literal `https://` URL whose host every URL parser reads the same way. |
| `hidden_markup` | high or low | `prompt` | An instruction file contains HTML or Markdown comments, which rendered views hide and agents read. Only their number and length are reported. High when a comment contains an imperative, a URL or a path under `~/`; `run` counts only when followed by a path, a script or executable file name, a shell (`sh`, `bash`, `zsh`, `dash`, `pwsh`, `powershell`) or a command that executes code, reads secrets or deletes files (`python`, `python3`, `py`, `node`, `deno`, `bun`, `ruby`, `perl`, `php`, `java`, `osascript`, `npx`, `uvx`, `pipx`, `pip`, `pip3`, `npm`, `pnpm`, `yarn`, `uv`, `poetry`, `cargo`, `go`, `brew`, `apt`, `apt-get`, `gem`, `sudo`, `doas`, `su`, `env`, `exec`, `eval`, `source`, `curl`, `wget`, `iwr`, `cat`, `cp`, `mv`, `rm`, `dd`, `chmod`, `chown`, `ssh`, `scp`, `nc`, `base64`, `xargs`, `docker` or `kubectl`, but not one joined by a hyphen to another word, as in `go-live`), also after punctuation or markup such as `:`, quotes, `(`, `**` or a code fence; or when followed by `this`, `these`, `it` or `the following` and one of those appears later in the same comment (`run the following command: ./x.sh`); or when one of those starts a command later in the same sentence, that is at the start of a line or list item (`-`, `*`, `+`, `1.`, `1)`), or after `:`, `;`, `&`, `|`, `then`, `command`, `commands` or `script`, with only whitespace, quotes, brackets, `*`, `_`, `>`, `-` or `$` between (`` run the command `rm -rf /` ``, `run as root: rm -rf /`, `run make test && rm -rf /`, `run tests, then cat .env`); a sentence ends at `.`, `!` or `?` before whitespace, except after a digit. `run them with python`, `Run make docs`, `run make test`, `dry-run`, `last run:`, `test run`, `re-run make` and `runtime` stay low. Otherwise low. | Read the comments in the raw file, and move notes out of agent instructions. |
| `hook_commands` | critical, high or medium | `ide_agents` | Claude Code or Cursor settings declare hook commands that run automatically on agent events. Critical when a command pipes a download or `base64 -d` output into `sh`, `bash`, `zsh` or `dash` (by name, by a path that ends in the shell, or through `env`), or passes PowerShell an encoded command among its own parameters, before any `-File <script>`, `-Command` or script path, which only a plain argument ends; high when a command contains a URL; otherwise medium. The command text is not recorded. | Review each hook and approve its exact value. Remove fetch-and-execute commands. |
| `instruction_layering` | low | `ide_agents` | An IDE agent reads instructions from two locations: `CLAUDE.md` and `.claude/CLAUDE.md`, or `.cursorrules` and `.cursor/rules`. | Document the loading order and who may change each file. |
| `invalid_safetensors` | high | `risk` | A model recorded as SafeTensors has no established structural safety: its header is malformed, over the inspection limit, or was not inspected. The risk gate fails at any score. | Replace the file with a SafeTensors file that validates, then collect again. |
| `invisible_characters` | high | `prompt` | An instruction file contains invisible format characters, variation selectors, blank fillers or the unassigned default-ignorable code points U+2065 and U+FFF0 to U+FFF8, other than bidirectional controls, directional marks and tag characters. | Remove them, or document why each one is there. |
| `launch_context` | high, medium or low | `mcp` | High: privileged mode, a container runtime socket or host root mount, disabled confinement, a host-level capability or a command-valued field. Medium: a host namespace, added capabilities, host devices, a broad host mount, or an option, variable or setting that loads local code. Low: a launch through a shell or wrapper. | Remove host-level privileges and code-loading options, or isolate the server; launch the executable directly. |
| `launcher_identity` | high | `mcp` | The launched package and its pin cannot be established: an unclassified runner, inline code, a nested launch, or a package from git without a full commit, from a URL or from a local path. The server is also a coverage gap. | Launch a registry package pinned to an exact version, or an image pinned by digest, in a form the collector classifies ([known limitations](known-limitations.md#mcp-servers-and-tools)). |
| `local_process` | medium | `mcp` | An MCP server runs as a local process whose executable the inventory does not verify. | Check the executable's integrity, for example with `verify-live` and a pinned launch policy. |
| `lockfile_resolution_mismatch` | high | `registry` | An npm lockfile record's tarball URL names another package or version than the record. | Regenerate the lockfile from the registry and review the change. |
| `lockfile_unread` | low | `registry` | A package may be resolved by `Pipfile.lock`, `pdm.lock`, `bun.lock` or `bun.lockb`, which the collector does not read. | Review that lockfile's record for the package. |
| `mcp_auto_approval` | medium | `ide_agents` | Claude Code settings set `enableAllProjectMcpServers`, which approves every server in `.mcp.json` without a prompt. | Approve servers one by one. |
| `missing_lockfile_integrity` | medium | `registry` | An npm lockfile record has no integrity value. | Regenerate the lockfile so that it records a `sha512` integrity value. |
| `mutable_image_tag` | medium | `mcp`, `registry` | A container image is pinned by a tag, which can be moved to other content, instead of a digest. | Pin the image by its SHA-256 digest. |
| `nonregistry_source` | high or medium | `registry` | An npm or PyPI package is declared from a git, URL or path source instead of a registry; high when that source can change, such as git without a full commit or plain `http://`. | Install it from a registry with an exact version and integrity evidence, or pin the source to a full commit. |
| `package_alias` | low | `registry` | An npm dependency installs a package under another name (`npm:` alias). | Check that the aliased package is the one the code expects. |
| `package_source` | medium | `mcp` | An MCP server resolves packages through a non-default registry or index, so name and version do not establish identity. | Review that registry or index, and pin an artifact digest or integrity hash. |
| `permission_scope` | high or medium | `ide_agents` | A project-level starting mode that skips permission prompts (high) or accepts edits without one (medium), unscoped tool allowances (medium), or Codex's `danger-full-access` sandbox (high) or `never` approval (medium). Effective approval stays unverified. | Keep the default or plan mode, scope allow rules to resources, and keep Codex's workspace-write sandbox with on-request approval. |
| `plugin_sources` | low | `ide_agents` | Claude Code settings enable plugins or register plugin marketplaces, which can add commands, agents, hooks and MCP servers. | Review each plugin and marketplace, and approve the exact value. |
| `prompt_size` | medium | `prompt` | An instruction file is larger than 50,000 bytes, which makes review for injected text harder. | Remove unnecessary content. |
| `rag_discovery` | info | `rag` | A vector store library is imported in Python code, or a vector store is named by environment variable names, without a declared configuration. | Document whether the deployment uses it. |
| `registry_origin` | low | `registry` | An npm lockfile record resolves the package from a registry other than the default one, or a project setting, such as `registry=` in `.npmrc` or `--index-url` in a requirements file, can send an npm or PyPI package to another registry or index, which leaves the package without a package URL; see [registry and index settings](registry-collector.md#registry-and-index-settings). | Confirm that the registry or index is intended and trusted for the package, and pin artifact digests or integrity hashes. |
| `serialization_format` | critical | `model`, `risk` | A model file's format or loader can execute code, such as a pickle-based format, or a chat template, embedded in a GGUF file or configured in the model's directory, reaches Python internals. | Convert the weights to SafeTensors; remove or replace the template ([model integrity](model-integrity.md)). |
| `serialization_format_unknown` | high | `model` | The safety of a model file's format or loader could not be established: a format without a structural validator, such as ONNX or GGUF, or a SafeTensors file that does not validate. | Validate the container and the loader that will read it before admission. |
| `shadowscan-heuristic` | the report's rating | `shadowscan` | An imported ShadowScan report rated the component. The rating is a heuristic, not a verified vulnerability. | Review the source evidence in the report. |
| `shadowscan-inventory-unmatched` | info | `shadowscan` | The ShadowScan report found no matching entry in the inventory it was given; authorization is not established. | Reconcile the report's scope with the finding. |
| `signing_status` | high | `model` | Not every weight file of a model is Sigstore-signed or digest-pinned in the operator's signer policy. | Pin the SHA-256 of every weight file, or sign each one with a Sigstore message signature, in a [signer policy](model-integrity.md#operator-signature-policy). |
| `tag_characters` | critical | `prompt` | An instruction file contains Unicode tag characters (U+E0000 to U+E007F) outside a flag emoji, a known way to hide prompt text, or unassigned default-ignorable code points of plane 14 (U+E0080 to U+E00FF, U+E01F0 to U+E0FFF), which can hide text the same way. | Remove them. |
| `transport_ambiguity` | low | `mcp` | An MCP server declares both a launch command and an endpoint. | Declare one of the two, and an explicit transport type. |
| `transport_security` | high or low | `mcp`, `a2a`, `rag` | An MCP or A2A endpoint without HTTPS, or an MCP endpoint URL that embeds credentials (high); a RAG locator whose transport is not shown to be encrypted (low). | Use authenticated HTTPS, and pass credentials in a header or an environment reference. |
| `version_pinning` | high, medium or low | `mcp`, `registry` | A package or image without an exact version or digest: an unpinned MCP launcher package or an image with neither digest nor release tag (high), a nonexact npm or PyPI declaration (medium), or a PyPI pin that applies only under environment markers (low). | Pin an exact version or digest, and keep integrity evidence such as lockfile hashes. |
| `transitive_resolution` | medium | `mcp` | `npx`, `npm exec`, `bunx`, `bun x`, `pnpm dlx`, `yarn dlx`, `uvx`, `uv tool run` or `pipx run` pins the top-level package to an exact version and still resolves that package's dependencies at launch. A project lockfile does not cover that install. | Vendor a lockfile-installed server, or launch an image by digest. |

[Known false-positive and false-negative classes](security-model.md#known-false-positive-and-false-negative-classes)
explains how some of these are classified, such as why a `.bin` file is critical and
which characters count as hidden.

## Reports that are not findings

- **Collection failures and coverage gaps** are coverage records, not findings: they
  have no category or severity, and they fail the gates through coverage. See the
  [glossary](glossary.md#coverage-gap).
- **`validate` issues** have categories of their own, such as `unpinned_version` or
  `weight_files_mismatch`, in `validate --json-output`. They decide the completeness
  and integrity checks, not the risk score.
- **Drift alerts** rate changes between two inventories. A finding added between
  them is one alert among others; [what the alerts mean](drift-gate.md#what-the-alerts-mean)
  rates every change `diff` reports.
- **`trace-diff` results** compare traces with an inventory and are not written into
  it: `risk` does not score them, and `ignore_categories` and suppressions do not
  apply to them. Undeclared and unidentified items fail the trace gate of `trace-diff`
  itself, and `--sarif` reports them under `runtime_undeclared`
  ([trace evidence](trace-evidence.md#exit-codes-and-the-gate)).
- **Risk classes, framework references and minimum-element statuses**, which `graph`,
  `crosswalk` and `minimum-elements` report, are views of an inventory's records and
  findings, not findings: no gate reads them except
  `minimum-elements --fail-under`, which gates on minimum-element coverage.

## SARIF rules

In SARIF output each finding's rule is `nexus_symbiote/<category>/<severity>`, so a
finding whose severity changes moves to another rule
([migration](fingerprint-migration.md#sarif-rule-identifiers)). Findings on
components imported from a ShadowScan report are left out of SARIF. Every category
on this page has a rule in the catalog that
[standard exports](standard-exports.md#sarif-for-github-code-scanning) lists, with
its title and taxonomy tags, and so has `runtime_undeclared`, the category under which
`trace-diff --sarif` writes a tool, model, agent or MCP endpoint that the agent's own
telemetry reports and the inventory does not declare, or whose identifier cannot be
read ([trace evidence](trace-evidence.md#sarif)). The
[framework crosswalk](framework-crosswalk.md) gives the rationale for each tag and the
category's EU AI Act and ISO/IEC 42001 references. A category outside the catalog,
such as one that an edited inventory records, gets a generic rule titled after the
category and tagged only `security`.
