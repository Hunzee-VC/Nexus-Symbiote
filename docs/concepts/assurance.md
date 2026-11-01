# Assurance, claims and unknowns

Symbiote never asks "is this agent safe?". It asks, for each fact, *who says so, how, and with what evidence*.

## Claims
```json
{"value": "stdio", "state": "present", "assurance": "declared",
 "method": "config", "locator": ".mcp.json#/mcpServers/github/command",
 "collector": "collector:mcp-config@0.1.0", "evidence": []}
```
- **declared** — the owner, supplier or configuration says so.
- **observed** — a collector corroborated the deployed state within a stated window (live `tools/list`, a
  trace, a registry or provider API).
- **verified** — the evidence is authenticated against an explicit trust policy with a *constrained signer*
  and documented coverage.

`verified` is a high bar on purpose. A valid signature from a signer nobody constrained is recorded as
`signature-valid-unconstrained` and stays `observed`. Symbiote adopts this rule verbatim from Google's
k8s-aibom (Design 002), and the model enforces it: a `verified` claim without verified-constrained evidence
does not validate.

## Unknown is not absence
A claim whose state is `unknown` carries a reason — `not-collected`, `permission-denied`, `unreachable`,
`truncated`, `provider-undisclosed`, `timeout` — and the coverage statement records the surface that could not
be examined. `absent-verified` means a collector looked and found nothing. A failed registry query therefore
yields "unknown", never "not registered". Policy checks whose inputs are unknown report `indeterminate`; they
never pass silently.

## Importing other producers' confidence
k8s-aibom's per-attribute confidence maps as `declared → declared`, `inferred → observed (heuristic)`,
`unresolved → unknown`, and `verified → verified` only when a signer identity constraint is recorded in the
imported document; otherwise `observed` plus the fact `imported-verified-without-constraint`.
