# Roadmap

Nexus SymBiote is alpha software at version 0.1.0 and is not yet published on
PyPI; `main` is the compatibility baseline. This roadmap is intent, not a
contract: nothing here has a date, and an item moves only when it keeps static
scans free of execution and network access and keeps failures closed.

## Now

- First PyPI release of 0.1.0 through a TestPyPI rehearsal, following the
  [release runbook](docs/operations/releasing.md) and the
  [release requirements](GOVERNANCE.md#releases). Until then, install from a
  reviewed checkout as the [README](README.md) describes.
- Run the first offline and live mode release in practice: offline is the
  default, the three live commands need `--live`, and each has an `--input`
  counterpart for saved exports. Gather operator feedback before 1.0 on the
  exit-code contract and the recorded-descriptor format.
- Community standards: code of conduct, support routing, governance, issue
  forms, Dependabot, CodeQL, and OpenSSF Scorecard. A Scorecard result
  measures repository practices; it is not a code review.

## Next

- Independent review of a release candidate: someone other than the maintainer
  examines an exact commit, and the release notes record who reviewed what.
  Until that exists, release notes say so.
- Exporter conformance work: keep the CycloneDX 1.7, SPDX 3.0.1, SARIF, and
  VEX exports validating against the pinned official schemas while preserving
  references, unknown states, and loss reports, and document what each format
  cannot carry.
- Wider scanner coverage: more evidence sources for the existing surfaces
  (MCP, models, prompts and skills, retrieval, packages, A2A, IDE agents),
  each with synthetic fixtures in the
  [regression corpus](benchmarks/README.md) and with gaps reported in
  coverage rather than hidden.

## Later

- Python 3.14, once every pinned dependency in `requirements-ci.lock`
  publishes wheels for it and the lock can be regenerated and reviewed.
- A second maintainer, which makes non-author review possible
  ([GOVERNANCE.md](GOVERNANCE.md#adding-a-maintainer)).

## Not planned

- A hosted scanning service.
- Safety, compliance, or certification claims. A scan is an inventory result,
  and a risk score summarizes findings under a policy.
- Executing project code, model loaders, or MCP launch commands during static
  collection, or any live operation that is not an explicit opt-in.
- Weakening fail-closed behavior, redaction, or coverage reporting to make a
  result look more complete.
