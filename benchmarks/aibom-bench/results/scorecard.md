# AIBOM-Bench 1.0.0 scorecard

Seed `20261118`, corpus digest `e771ea4d7f519c31`. Ranked by grade (after gates), then score. Domain columns are percentages; Score is the weighted total out of 100; Risk findings is the share of finding points earned across all domains.

| Rank | Tool | Version | Grade | Score | In-scope | Risk findings | mcp | tooldefs | skills | agents | models | data | packages | standards | safety | Gates |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | Nexus SymBiote | 0.2.0 (a13b622) | C | 65.3 | 65.3 | 44 | 82 | 47 | 72 | 39 | 55 | 0 | 91 | 77 | 100 | – |
| 2 | agent-bom | 0.115.4 | D | 51.2 | 51.2 | 36 | 72 | 0 | 66 | 22 | 55 | 0 | 91 | 69 | 67 | – |
| 3 | Cisco AI BOM | 1.10.1 | F (was D) | 50.3 | 47.7 | 0 | 59 | 40 | 28 | 28 | 43 | 25 | 91 | 78 | 67 | X02→F, X03→C |
| 4 | AIROM | 0.4.7 | F | 39.4 | 60.8 | 19 | 0 | 13 | 3 | 11 | 66 | 58 | 91 | 89 | 53 | – |
| 5 | OWASP cdxgen | 12.9.2 | F | 35.0 | 38.0 | 14 | 49 | 13 | 31 | 11 | 41 | 0 | 91 | 72 | 17 | X09→F |
| 6 | Trusera ai-bom | 3.6.0 | F | 34.5 | 33.9 | 0 | 41 | 27 | 0 | 0 | 29 | 0 | 36 | 52 | 92 | X03→C |
| 7 | aibom-scanner (saasvista) | 1.3.5 | F | 29.8 | 38.5 | 14 | 77 | 0 | 0 | 6 | 3 | 0 | 91 | 17 | 78 | – |
| 8 | AIsbom | 1.7.0 | F | 27.7 | 60.1 | 22 | 0 | 0 | 0 | 0 | 59 | 0 | 54 | 73 | 53 | – |
| 9 | Anchore Syft | 1.57.2 | F | 25.1 | 52.9 | 0 | 0 | 0 | 0 | 0 | 36 | 0 | 91 | 63 | 58 | – |
| 10 | AIBoMGen CLI | 0.3.0 | F | 11.7 | 29.3 | 0 | 0 | 0 | 9 | 0 | 17 | 0 | 0 | 65 | 0 | – |
| – | OWASP AIBOM Generator | main@2026-10-17 | N/R | – | – | – | – | – | – | – | – | – | – | – | – | not run |

- **Positive control (executes every payload)** (calibration, not ranked): grade F, gates ['X01', 'X02', 'X03', 'X09', 'X07'], failed safety checks ['X01', 'X02', 'X03', 'X04', 'X09', 'X07', 'X08'], probes that did not fire [].
- **agent-bom**: Scans with the documented --model-files, --model-provenance and --dataset-cards discovery, with the checkout as working directory (agent-bom only scans model files under safe roots such as the working directory).
- **Cisco AI BOM**: v1.10.1 refuses to run without an LLM. The LLM endpoint is pointed at an unreachable port, so the tool reports its deterministic detections, each marked pending_agent_review, and no LLM enrichment; those unconfirmed candidates are graded as detections. Installed with the documented agentic, analysis, security and llm-openai extras and run with --atr-enrichment. Its intended LLM-assisted results may differ; treat its grade as provisional. With the documented `security` extra, `analyze` hands each discovered MCP config to cisco-ai-mcp-scanner, which starts every declared stdio server to enumerate its tools; in the benchmark it ran `sh -c touch …` from s09b's .mcp.json (X02) and `npx -y …` / `docker run …` from s04. A base install without that extra does not start servers (observed in an earlier run of this benchmark).
- **OWASP cdxgen**: Runs the README's AI-BOM command ('Generate and audit an AI-BOM from the current repository'). The benchmark run adds the documented --no-install-deps; the plain invocation keeps cdxgen's default of installing project dependencies.
- **AIBoMGen CLI**: Reads model metadata from the Hugging Face Hub, which the sandbox cannot reach; only model IDs it detects in code are reported.
- **OWASP AIBOM Generator** not run: Takes a Hugging Face model ID and reads metadata from the live Hugging Face Hub API; it has no mode for scanning a local repository or local model files, and the Hub is unreachable from the benchmark sandbox by design.
