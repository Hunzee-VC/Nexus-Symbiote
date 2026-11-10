# npm lockfile evidence

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
validated SRI integrity value (SHA-1, SHA-256, SHA-384 or SHA-512, one or several),
and the SHA-256 of the exact lockfile bytes parsed. The package URL names the
registry with a `repository_url` qualifier when the record resolves from a host
other than `registry.npmjs.org`. A record is checked before it is taken:

- A `resolved` value that is not an `https` URL with a host, or that holds white
  space, a control character, a backslash, a non-ASCII character or a percent sign
  in the host, is a collection failure. A WHATWG URL parser, which npm uses, can read
  such a value as another host than Python does.
- A version that is not an exact SemVer version, an integrity value that does not
  decode to its algorithm's length, and a version that differs from an exact version
  in `package.json` (which `npm ci` refuses) are collection failures.
- A missing integrity value or one with only SHA-1, a registry other than the
  default, and a tarball URL that names another package or version are findings.
  A range in `package.json` is resolved, with no `version_pinning` finding, only by a
  record with a SHA-256 or stronger integrity value and a consistent tarball URL.
- Local links, and records whose `name` differs from the package `package.json`
  declares, remain unresolved coverage gaps. An `npm:` alias is resolved against the
  package it names.

These are declared resolution claims with unknown trust. The collector does not
fetch packages, establish their presence, verify registry ownership or publisher
identity, or prove that package bytes match the lockfile. Raw download paths,
userinfo, tokens and signed URL parameters are omitted. A manifest without a
supported lock record does not establish a registry origin. `yarn.lock`,
`pnpm-lock.yaml`, `bun.lock` and `bun.lockb` are not read; when one exists, each npm
package gets a low `lockfile_unread` finding.
