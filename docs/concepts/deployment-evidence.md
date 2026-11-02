# Deployment-scoped authority claims

The optional `deployment_profile` on a native AgentBOM agent records the deployment ID, environment, optional tenant and workload identity, and a list of scoped authority claims. Existing documents without a profile remain valid. This profile does not discover permissions or enforce access.

Each authority claim separates **kind** (`declared`, `effective`, or `observed`) from the producer's **claim state** (`declared`, `observed`, `verified`, `unknown`, or `not-applicable`). A known claim identifies a principal, action and resource and cites at least one evidence record. An unknown claim requires a reason and contains no permission assertion; it does not mean the principal has no permissions. A not-applicable claim likewise is not a negative inventory assertion. Use explicit scopes, rather than assuming a resource or audience.

Evidence records state their source, collector, and collection time. A producer-reported verified record must include its subject's SHA-256 digest, verifier, verification policy and verification time. These constraints check *record structure only*. Importing a record with `verification_status: verified` or a claim with `state: verified` does not verify a signature, prove that the verifier is trusted, establish freshness, or authorize a call. Consumers must verify evidence and its subject under their own trust and freshness policy. No secrets, raw credentials, token-bearing URLs, or private prompt content should be placed in provenance identifiers.

The native JSON representation preserves these fields. Current CycloneDX and SPDX exporters do not preserve this profile; consumers must retain the native BOM until explicit mappings and conversion-loss reports are implemented. The BOM schema and generated standalone `schemas/deployment-profile-1.0.schema.json` validate field shape; cross-field semantics are additionally enforced by the Python model.

```json
{
  "deployment_id": "agent-a:production:v3",
  "environment": "production",
  "tenant": "tenant-1",
  "workload_identity": "workload:agent-a",
  "authority": [
    {
      "kind": "effective",
      "state": "unknown",
      "unknown_reason": "identity collector lacked permission",
      "evidence": []
    }
  ]
}
```
