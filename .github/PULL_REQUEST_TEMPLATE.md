## Summary

<!-- Explain the concrete problem, resulting behavior, and validation. -->

## Related issues

<!-- For example: Closes #123. Write "None" if there is no issue. -->

## Roadmap and decisions

<!-- Name the ROADMAP.md item this change implements and any recorded decision it relies on or
would change (docs/decisions.md says where each kind is recorded). Check that no open pull request
already implements the same item. Write "None" for a fix or chore outside the roadmap. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Security fix (see SECURITY.md for reporting guidelines)
- [ ] Refactoring (no functional changes)

## Checklist

`make check` runs the offline subset of the required CI checks. See [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-Symbiote/blob/main/CONTRIBUTING.md).

- [ ] Tests cover the new or changed behavior
- [ ] New tests take __ s in total without coverage (`python -m pytest --durations=0`; at most 60 s, or the suite's own documented budget; see CONTRIBUTING.md)
- [ ] `ruff check src tests scripts` passes
- [ ] `ruff format --check src tests scripts` passes
- [ ] `mypy src/nexus_symbiote scripts` passes
- [ ] Workflow, repository hygiene and lock checks pass (`make workflow-check hygiene lock-check`)
- [ ] Dependency changes: locks regenerated with `make lock`, and the "Dependency health" run is green
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated under Unreleased
- [ ] Labelled with at least one type and one area label ([label guide](https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/labels.md))

## Review record

<!-- A behavior- or security-changing pull request stays open for at least 24 hours: opened __ UTC, merge not before __ UTC. -->

<!-- Who reviewed the full rendered diff after Verified CI finished, and when. Name any AI
assistance used to write or review the change and whether its review ran outside the session
that wrote it. See "AI-assisted contributions" in CONTRIBUTING.md. -->

### Security-sensitive changes

- [ ] Trust boundary and abuse case stated
- [ ] Regression test fails on the vulnerable behavior
- [ ] Security regression corpus reviewed (`benchmarks/manifest.json`, run with `scripts/benchmark_security.py`)
- [ ] No new network access, executable discovery, or credential collection without design and tests

## Limitations

<!-- Describe what this change does not cover or what it assumes. -->
