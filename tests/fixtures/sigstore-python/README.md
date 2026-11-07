# sigstore-python fixture

`bundle_v3_github.whl.sigstore` is the sigstore-python test asset of the same
name, under the Apache License 2.0 in `LICENSE`. It is a Sigstore bundle in
which the GitHub Actions workflow
`https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2`,
with issuer `https://token.actions.githubusercontent.com`, signs
`rfc8785-0.1.2-py3-none-any.whl`.

`rfc8785-0.1.2-py3-none-any.whl.subject` holds the exact bytes of that wheel as
published on PyPI, SHA-256
`c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201`. The wheel
carries its own Apache License 2.0 text in `rfc8785-0.1.2.dist-info/LICENSE`.
The `.subject` suffix keeps the repository's `*.whl` ignore rule, which also
shapes the source distribution, from dropping it. The bundle binds the bytes,
not the file name.

Tests verify the pair offline against the production trust root embedded in
sigstore-python and fetch nothing. The wheel is never installed or imported:
the Action tests copy its bytes under a model file name to stand in for a
signed model, because the repository has no keyless-signed SafeTensors fixture.
Only SafeTensors has a bounded structural validator, so that stand-in still
leaves model integrity unknown for its format after its signature verifies.
