# Lockfile evidence

The registry collector reads direct AI-related dependencies from `package.json`
and, when present, their exact `node_modules/<name>` records in the npm lockfile's
`packages` map (npm lockfile versions 2 and 3, or a compatible map without a version
field). It retains the requested range, lockfile-declared version, sanitized origin,
record JSON pointer, validated SHA-256/384/512 SRI declaration, and the SHA-256 of
the exact lockfile bytes parsed. Local links and conflicting alias identities
remain unresolved. Unsupported or unreadable inputs remain visible in coverage.

`pnpm-lock.yaml` and `yarn.lock` (v1 and Berry) are read the same way when one of
them is the only npm lockfile in the project root: the root importer's or the
matching stanza's exact version, its SRI integrity and its tarball origin. With more
than one npm lockfile no lockfile evidence is bound, and the conflict is reported as
an exclusion. Workspace, link, file and git resolutions (and Yarn `patch:` and
`portal:` ones), aliases that name another package, and more than one resolution
for the same package are reported as exclusions too. A Yarn v1 `sha1-` integrity
value is a collection failure, and Yarn Berry `checksum` values are not recorded.

For Python, `uv.lock` or `poetry.lock` in the project root supplies the exact
version and the index origin of each AI package declared in `requirements*.txt` or
`pyproject.toml`, the lockfile record's position, and the SHA-256 of the lockfile.
Artifact digests in the lockfile are not recorded. With both lockfiles present, or
for a package with a local, git or URL source, no resolution is bound.

These are declared resolution claims with unknown trust. The collector does not
fetch packages, establish their presence, verify registry ownership or publisher
identity, or prove that package bytes match the lockfile. Raw download paths,
userinfo, tokens and signed URL parameters are omitted. A manifest without a
supported lock record does not establish a registry origin.
