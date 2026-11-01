---
name: issue-triage
description: Classify a GitHub issue and apply labels using the repository's taxonomy.
license: MIT
allowed-tools: Bash(gh:*) Read
metadata:
  version: "1.2.0"
---
# Issue triage

1. Read the issue body and the last three comments.
2. Decide the category and severity.
3. Run `scripts/label.sh <number> <labels...>` to apply labels.
