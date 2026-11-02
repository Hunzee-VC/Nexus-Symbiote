"""Agent dependency updates: plan, patch and pull request (``spec/monitoring.md`` §4).

:func:`plan_updates` turns dependency intelligence into at most one proposal per dependency;
:func:`locate_edits` finds the minimal textual edit in the declaring configuration file; :func:`render_diff`
and :func:`apply_proposals` show and write those edits; :func:`open_pull_request` opens a draft pull request
with ``git`` and ``gh``.
"""

from __future__ import annotations

from symbiote.update.patch import PatchError, apply_proposals, locate_edits, render_diff
from symbiote.update.plan import plan_updates
from symbiote.update.pr import PullRequestError, branch_name, open_pull_request, render_pr_body
from symbiote.update.types import FileEdit, UpdateKind, UpdatePolicy, UpdateProposal

__all__ = [
    "FileEdit",
    "PatchError",
    "PullRequestError",
    "UpdateKind",
    "UpdatePolicy",
    "UpdateProposal",
    "apply_proposals",
    "branch_name",
    "locate_edits",
    "open_pull_request",
    "plan_updates",
    "render_diff",
    "render_pr_body",
]
