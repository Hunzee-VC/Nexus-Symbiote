# Lockfile evidence

The registry collector reads direct AI-related dependencies from `package.json`
(`peerDependencies`, `dependencies`, `optionalDependencies` and `devDependencies`)
and, when present, their exact `node_modules/<name>` records in the `packages` map
of the lockfile npm installs from: `npm-shrinkwrap.json` when it exists, otherwise
`package-lock.json` (npm lockfile versions 2 and 3, or a compatible map without a
version field). An unreadable `npm-shrinkwrap.json` is a collection failure, never
replaced by `package-lock.json`. Which packages count as AI-related, and the
findings below, are described with the rest of the collector in
[the registry collector](registry-collector.md).

From a record the collector retains the requested range, the lockfile-declared
version, the sanitized origin of its `resolved` URL, the record's JSON pointer, a
validated SRI integrity value (one or several hashes, at least one of them SHA-256,
SHA-384 or SHA-512), and the SHA-256 of the exact lockfile bytes parsed. The package
URL names the registry with a `repository_url` qualifier when the record resolves
from a host other than `registry.npmjs.org` and `registry.yarnpkg.com`. A record is
checked before it is taken:

- A `resolved` value that is not an `https` URL with a host, or that holds white
  space, a control character, a backslash, a non-ASCII character or a percent sign
  in the host, is a collection failure. A WHATWG URL parser, which npm uses, can read
  such a value as another host than Python does.
- A version that is not an exact SemVer version, an integrity value that does not
  decode to its algorithm's length or has only SHA-1, and a version that differs
  from an exact version in `package.json` (which `npm ci` refuses) are collection
  failures.
- A missing integrity value, a registry other than the default, and a tarball URL
  that names another package or version are findings.
  A range in `package.json` is resolved, with no `version_pinning` finding, only by a
  record with a SHA-256 or stronger integrity value and a consistent tarball URL.
- Local links, and records whose `name` differs from the package `package.json`
  declares, remain unresolved coverage gaps. An `npm:` alias is resolved against the
  package it names.

`pnpm-lock.yaml` and `yarn.lock` (v1 and Berry) are read when one of them is the only
lockfile in the project root (`npm-shrinkwrap.json` and `package-lock.json` count as
npm's one): the root importer's or the matching stanza's exact version, its SRI
integrity and its tarball origin. Their records are checked as an npm record is: the
`resolved` or `tarball` URL, the exact version, an exact `package.json` version it
contradicts and the integrity value are collection failures as above (so a Yarn v1
`sha1-` value is one), and a tarball URL that names another package or version is a
finding. A missing integrity value and another registry are not findings for them,
and a range they resolve keeps its `version_pinning` finding. With the lockfiles of
more than one package manager no lockfile evidence is bound, and the conflict is
reported as an exclusion. Workspace, link, file and git resolutions (and Yarn
`patch:` and `portal:` ones), `npm:` aliases, which only npm's own records resolve,
and more than one resolution for the same package are reported as exclusions too.
Yarn Berry `checksum` values are not recorded.

For Python, `uv.lock` or `poetry.lock` in the project root supplies the exact
version and the index origin of each AI package declared in `requirements*.txt` or
`pyproject.toml`, the lockfile record's position, and the SHA-256 of the lockfile.
Artifact digests in the lockfile are not recorded. With both lockfiles present, for
a package with a local, git or URL source in the lockfile, or for one that a root
file declares from a URL, no resolution is bound.

These are declared resolution claims with unknown trust. The collector does not
fetch packages, establish their presence, verify registry ownership or publisher
identity, or prove that package bytes match the lockfile. Raw download paths,
userinfo, tokens and signed URL parameters are omitted. A manifest without a
supported lock record does not establish a registry origin. `bun.lock`, `bun.lockb`,
`Pipfile.lock` and `pdm.lock` are not read; when one exists, each package of its
ecosystem gets a low `lockfile_unread` finding.
