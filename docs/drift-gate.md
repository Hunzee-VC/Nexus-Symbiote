# Gate drift in CI

`nexus-symbiote diff OLD NEW --fail-on-alert` compares a reviewed snapshot with a
new collection and exits 1 when anything it rates medium or higher changed. This
page says where the reviewed snapshot must come from, how to take both snapshots so
they compare, and what each alert means.

The gate compares what the inventory records. Content the collectors do not record,
such as Codex `config.toml` settings or instruction files under names the `prompt`
collector does not read, cannot alert. Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`,
neither can a changed MCP launch argument other than the launcher package, a changed
environment value, or an endpoint path changed on the same host; see
[source binding](verification-source-binding.md). The
[known limitations](../SECURITY.md#known-limitations-in-010) list those surfaces.

## The trust anchor is the baseline

A baseline is an unsigned JSON file. `diff` cannot tell a reviewed baseline from one
the change under review wrote, so the gate is only as strong as the place the
baseline comes from.

- **Keep the baseline out of the pull request's reach.** Read it from the protected
  base branch (for example `git show "$BASE_SHA:.nexus-symbiote/reviewed.json"`), or
  from an artifact store only maintainers can write. Never read it from the
  pull-request head: an author who changes `.mcp.json` can regenerate a baseline in
  the same commit, and the diff then passes.
- **Copy it outside the scanned checkout** before you compare, for example into
  `$RUNNER_TEMP`, and write the candidate there too. A file inside the checkout can
  be replaced by a symlink or by another file the author controls.
- **Decide who may change it.** Updating the baseline approves everything in it.
  Change it only in a reviewed pull request to the protected branch, and require
  code-owner review for that path.
- **Protect the gate itself.** On the `pull_request` event the workflow file comes
  from the pull request, so an author can edit `--fail-on-alert` away. Require the
  check through a repository ruleset or a required workflow, and require code-owner
  review of `.github/`.

## Take both snapshots the same way

Approve a baseline on a checkout of the protected base branch, and commit it there
through a reviewed pull request (or upload it to a store only maintainers can write):

```bash
nexus-symbiote baseline . --no-project-policy -o .nexus-symbiote/reviewed.json
```

The pull-request job then reads that baseline from the base commit, never from the
pull request, and compares it with a scan of the pull-request checkout:

```bash
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
nexus-symbiote scan . --no-project-policy -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

Taking both snapshots in the same job from the same checkout compares the pull
request with itself, and that gate can never fail.

- **Use the same policy for both.** `--no-project-policy` keeps a policy file in the
  checkout from narrowing either snapshot. `baseline` accepts it, and
  `--signature-policy`, like `scan`.
- **Use the same binding key for both.** Set one `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`
  of 32 or more characters for the baseline and every candidate scan. Without it, the
  values described above cannot alert; with a different key, every MCP and A2A
  binding changes and alerts. See [source binding](verification-source-binding.md).
- **Paths are root-relative.** Recorded paths are relative to the scan root, so a
  snapshot taken in `/Users/alice/agent` compares with one taken in
  `/home/runner/work/agent/agent`. Without a manifest `id`, the repository agent is
  `agent:repository:cdb4ee2aea69cc6a83331bbe`, named `repository`, wherever the
  checkout is. An
  [agent manifest](agent-manifest.md) `id` gives it a stable, named reference.
- **Upgrading from 0.1.0: re-create the baseline.** Snapshots written by 0.1.0
  record absolute paths and a path-derived agent reference. `diff` does not treat
  `/old/root/CLAUDE.md` and `CLAUDE.md` as the same location, because the old root
  is not recorded and guessing it could hide a file that really moved. It adds a
  note when one snapshot has absolute paths and the other relative ones. To migrate,
  check out the commit the old baseline was reviewed at, take a new baseline there
  with this release, and review `diff old.json new.json`: on the same commit it
  should show only how the evidence is recorded, not what it contains. Then adopt
  the new baseline through your usual review.
- **ShadowScan reports** are compared by normalized content; see
  [comparing discovery across reruns](shadowscan-integration.md#compare-discovery-across-reruns).

## What the alerts mean

Every alert names what changed. Security alerts are listed first in text output,
then notes, then the added, removed and modified components and relationships.
`--json-output` carries the same records.

| Change | Rating |
| --- | --- |
| Component added | medium |
| Component removed | high for MCP servers and clients, tools, models, instruction and skill files, guardrails, IDE agents and extensions, A2A clients and servers, and for any record that carried integrity evidence (file, content, definition or schema digest, exact package URL, version pin, lockfile integrity, static source binding); medium otherwise. Confirm it was deleted, not moved where no collector reads it |
| MCP endpoint, transport, launch command, launcher package or static source binding changed | critical |
| Tool definition, input schema, description or annotations changed | critical |
| Security field changed (for example capabilities, authorizations, claims, endpoints, A2A card URL, package URL, provider, source URI, signing identity or key reference, permission mode, version pin), a `*_ref` or `*_refs` field changed, declared autonomy level changed, trust tier or signing status downgraded, a digest removed or changed | high |
| Trust tier or signing status raised | medium: a snapshot is unsigned, so a raised label is a claim to review |
| Risk findings added | the highest added severity, at least medium |
| Risk findings removed; any other field changed, including snapshot metadata such as the producer's `tool_name` or `tool_vendor` | medium |
| Relationship added | medium; high for `invokes`, `delegates-to` and `acts-as-identity` |
| Relationship removed | medium; high for `uses-guardrail` and `approved-under` |
| Relationship kept but its assurance or conditions changed | high |
| Coverage regressed: a new scan failure, coverage gap or exclusion; a collector's status got worse or is no longer recorded; fewer collectors requested or completed; a different scope; more unobserved surfaces; lower coverage assurance; no completeness claim in the new snapshot; or a baseline without a completeness claim (such as a hand-made or supplied BOM) while the new snapshot records a scan failure, a coverage gap, a collector that did not complete or no collector at all, since nothing shows that gap predates the change | high, naming the collector or entries |
| ShadowScan: report content changed; report bytes changed without comparable content digests; source status worse; more unmapped entries; new projection limitations; a lossy format | high |
| The new snapshot has graph problems the baseline did not (dangling or mistyped references), or either snapshot uses a `spec_version` this release does not support | high |

A relationship to a component that was itself added or removed is listed but alerts
through that component, unless its own rating is high.

These are recorded but never alert: a changed list of scanned surfaces (the
components found there are compared separately, so an added source file is not
drift), a coverage improvement, a baseline without a completeness claim compared
with a snapshot whose coverage is complete, a different Nexus SymBiote release
(`tool_version`), a ShadowScan report regenerated with unchanged content, and
unmapped ShadowScan entries that moved within the report.

Notes describe the comparison, not a change, and are printed even when nothing
changed: gaps both snapshots share (the baseline was already incomplete, and changes
inside those gaps cannot be detected), graph problems in both, a baseline recorded
after the candidate (check the argument order, since swapped snapshots show
additions as removals), and snapshots that disagree on absolute paths.

## Exit status

`diff` exits 0 without `--fail-on-alert`, whatever it finds. With it, the command
exits 1 when it reports any security alert, and 0 otherwise. An unreadable or
invalid input is an error (exit 1).
