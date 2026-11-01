# npm lockfile evidence

The registry collector reads direct AI-related dependencies from `package.json`
and, when present, their exact `node_modules/<name>` records in the npm lockfile's
`packages` map (npm lockfile versions 2 and 3, or a compatible map without a version
field). It retains the requested range, lockfile-declared version, sanitized origin,
record JSON pointer, validated SHA-256/384/512 SRI declaration, and the SHA-256 of
the exact lockfile bytes parsed. Local links and conflicting alias identities
remain unresolved. Unsupported or unreadable inputs remain visible in coverage.

These are declared resolution claims with unknown trust. The collector does not
fetch packages, establish their presence, verify registry ownership or publisher
identity, or prove that package bytes match the lockfile. Raw download paths,
userinfo, tokens and signed URL parameters are omitted. A manifest without a
supported lock record does not establish a registry origin.
