## Summary

<!-- Explain the concrete problem, resulting behavior, and validation. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Security fix (see SECURITY.md for reporting guidelines)
- [ ] Refactoring (no functional changes)

## Checklist

- [ ] Tests cover the new or changed behavior
- [ ] `ruff check src tests scripts` passes
- [ ] `ruff format --check src tests scripts` passes
- [ ] `mypy src/nexus_symbiote` passes
- [ ] Workflow and repository hygiene checks pass (`make workflow-check hygiene`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated under Unreleased

### Security-sensitive changes

- [ ] Trust boundary and abuse case stated
- [ ] Regression test fails on the vulnerable behavior
- [ ] Security regression corpus reviewed (`scripts/benchmark_security.py`)
- [ ] No new network access, executable discovery, or credential collection without design and tests

## Limitations

<!-- Describe what this change does not cover or what it assumes. -->
