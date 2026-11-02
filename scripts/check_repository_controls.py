"""Fail publication closed unless GitHub reports enforced required CI checks.

Only read repository branch metadata. Administrative configuration is a separate
operator action; a checked-in policy file does not protect a GitHub branch.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

REQUIRED_CHECKS = frozenset({"Verified CI"})
MAX_RESPONSE_BYTES = 1024 * 1024


def evaluate(metadata: Any, required: frozenset[str] = REQUIRED_CHECKS) -> list[str]:
    """Require positively reported protection; missing or malformed data fails."""
    if not isinstance(metadata, dict) or metadata.get("protected") is not True:
        return ["branch protection is not positively reported as enabled"]
    protection = metadata.get("protection")
    if not isinstance(protection, dict) or protection.get("enabled") is not True:
        return ["branch protection metadata is unavailable or disabled"]
    status = protection.get("required_status_checks")
    if not isinstance(status, dict):
        return ["required status-check metadata is unavailable"]
    errors = []
    if status.get("enforcement_level") != "everyone":
        errors.append("required checks must apply to administrators as well as contributors")
    contexts = status.get("contexts", [])
    checks = status.get("checks", [])
    if (
        not isinstance(contexts, list)
        or any(not isinstance(c, str) for c in contexts)
        or not isinstance(checks, list)
        or any(not isinstance(c, dict) or not isinstance(c.get("context"), str) for c in checks)
    ):
        return [*errors, "required status-check metadata is malformed"]
    present = set(contexts) | {c["context"] for c in checks}
    missing = required - present
    if missing:
        errors.append("missing enforced required checks: " + ", ".join(sorted(missing)))
    return errors


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        # Never forward an authentication header to a redirect destination.
        return None


def fetch_branch(repo: str, branch: str, token: str) -> Any:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None:
        raise ValueError("repository must be owner/name")
    if not branch or any(ord(c) < 32 for c in branch):
        raise ValueError("branch name is invalid")
    if not token or any(c in token for c in "\r\n"):
        raise ValueError("a GitHub token with repository contents-read access is required")
    request = Request(
        f"https://api.github.com/repos/{repo}/branches/{quote(branch, safe='')}",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "nexus-symbiote-repository-controls",
        },
    )
    with build_opener(_NoRedirect()).open(request, timeout=15) as response:  # noqa: S310 - fixed HTTPS API origin
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub branch response exceeds the size limit")
    return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--branch", default="main")
    args = parser.parse_args()
    try:
        metadata = fetch_branch(
            args.repo, args.branch, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
        )
        errors = evaluate(metadata)
    except (HTTPError, URLError, OSError, ValueError, RecursionError):
        # Do not include response bodies, headers or credential-bearing error text.
        print(
            "Repository controls could not be verified from GitHub; publication is blocked.",
            file=sys.stderr,
        )
        return 2
    for error in errors:
        print("Repository controls: " + error, file=sys.stderr)
    if errors:
        return 1
    print("Repository controls verified: protected branch and required CI checks are enforced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
