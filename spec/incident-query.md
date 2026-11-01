# Query a revoked descriptor

Use the exact tool-definition digest, tenant and time window. Supply a complete deployed companion and its matching in-toto DSSE envelope. The deployment authority's trusted public key is an operator input. Repeat the two file options in matching order for additional deployments.

```sh
symbiote incident query --tenant acme --descriptor "$TOOL_DIGEST" \
  --from 2026-11-01T00:00:00Z --until 2026-11-01T01:00:00Z \
  --companion deployed.json --envelope deployed.dsse --deployment-key deploy.pub \
  --policy-key policy.pub --observer-key observer.pub --observation event.dsse \
  --revocation trust.dsse --trust-key trust.pub --report-key report.key
```

The trust-status statement must commit to this tenant's entries and identify the revoked descriptor. The query clips the window to the signed revocation and validity intervals. With no revocation input, the query simply searches for the supplied descriptor.

A deployment row requires a signed deployed snapshot, a tenant-bound workload, a served descriptor and runtime relationship evidence. The effective-grant column requires a co-signature from a distinct policy authority, a bounded grant for this tool, and a credential for this workload. Restrictions and required approvals remain in the output. A separately signed tool-execution event supplies the completed or failed outcome. An approval receipt alone supplies no execution evidence.

An empty result or missing observer leaves status unknown. Reports cover only supplied snapshots, signing keys and time intervals. Treat storage, freshness policy, and the assignment of tenant authority to each public key as deployment configuration. The optional report key signs the generated JSON using DSSE with media type `application/vnd.symbiote.incident-report.v1+json`.

To trace a publisher, replace `--descriptor` with `--publisher ID --issuer ISSUER --provenance-key KEY`. A separate provenance authority must co-sign the exact snapshot. A matching record must carry the expected signer, a verified outcome, a signature-bundle digest and a resolved digest equal to the deployed server artifact. A matching display name is insufficient. Use `--artifact SHA256` to query an immutable server digest. The corresponding trust-status subjects are `publisher-identity` and `server-identity`.
