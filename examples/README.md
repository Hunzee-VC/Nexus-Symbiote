# Examples

Minimal fixtures for demonstrating the collectors.

## Collector demo

From a reviewed checkout of the repository:

```bash
nexus-symbiote scan examples --no-project-policy --report-only -o demo-agentbom.json
nexus-symbiote summary demo-agentbom.json
```

This exercises the eight built-in collectors (`shadowscan`, `mcp`, `model`, `prompt`, `rag`, `registry`, `a2a`, `ide_agents`) against the files in this directory. A completed search may report zero matches for some collectors; that is expected and is recorded as coverage information rather than a failure.

Record a ~60 s asciinema of the above commands and link it from the root README once the v0.1.0 tag exists.
