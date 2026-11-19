"""Enforce an out-of-tree, optionally DSSE-signed operator policy on a checkout (`R1.0.0-2`).

In pull-request CI, the target checkout controls `.nexus-symbiote.yaml` and every file inside
the working tree. This gate verifies that `--operator-policy` (and any `--operator-policy-key`
or `--baseline`) resides outside the target checkout and every enclosing git working tree
*without* copying it into a temporary path, verifies its DSSE attestation when supplied or
required, clamps any checkout `.nexus-symbiote.yaml` to a non-weakening floor, and runs
collection, completeness/integrity reconciliation, risk scoring, and optional baseline diffing.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, cast

import click
from click.testing import CliRunner
from pydantic import ValidationError

from nexus_symbiote import attestation
from nexus_symbiote.attestation_cli import _load_trusted_public
from nexus_symbiote.cli import main as cli_main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.policy import (
    DEFAULT_WARN_THRESHOLD,
    MAX_POLICY_YAML_NODES,
    Policy,
    PolicyError,
    RiskPolicy,
    ValidatePolicy,
    load_policy,
    parse_yaml_mapping,
)
from nexus_symbiote.runtime import key_id
from nexus_symbiote.runtime_cli import (
    _check_key_placement,
    _identity,
    _InputTooLargeError,
    _KeyFileError,
    _read,
    _working_trees,
)
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_OPERATOR_POLICY_BYTES = 1024 * 1024
_SEVERITY_STRICTNESS: dict[str, int] = {
    "none": 0,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}
_ASSURANCE_STRICTNESS: dict[str, int] = {"declared": 0, "observed": 1, "verified": 2}


def _verify_outside_checkout(
    target: Path, untrusted_roots: tuple[Path, ...], *, label: str
) -> None:
    try:
        resolved_roots = [p.resolve() for p in untrusted_roots]
        search_starts = [
            *(p if p.is_dir() else p.parent for p in resolved_roots),
            Path.cwd().resolve(),
        ]
        trees = _working_trees(search_starts)
        forbidden_dirs = [
            *trees,
            *(p for p in resolved_roots if p.is_dir() and p not in trees),
        ]
        forbidden_ids = {_identity(d) for d in forbidden_dirs}
        resolved_target = target.resolve()
        ancestor_ids = {_identity(parent) for parent in resolved_target.parents}
        if any(resolved_target.is_relative_to(d) for d in forbidden_dirs) or bool(
            ancestor_ids & forbidden_ids
        ):
            raise click.UsageError(
                f"{label} must lie outside the target checkout and every git working tree "
                "that holds the checkout or the current directory"
            )
        if os.stat(resolved_target).st_nlink != 1:
            raise click.UsageError(f"{label} must not have multiple hard links")
    except click.UsageError:
        raise
    except (OSError, RuntimeError):
        raise click.UsageError(f"{label} cannot be inspected safely") from None


def clamp_operator_floor(operator_policy: Policy, project_policy: Policy | None) -> Policy:
    """Combine operator and checkout policies so the checkout can only tighten controls."""
    if project_policy is None:
        return operator_policy

    op_r, pr_r = operator_policy.risk, project_policy.risk
    fail_threshold = min(op_r.fail_threshold, pr_r.fail_threshold)
    warn_threshold = min(
        op_r.warn_threshold, pr_r.warn_threshold, fail_threshold, DEFAULT_WARN_THRESHOLD
    )
    fail_on_severity = (
        pr_r.fail_on_severity
        if _SEVERITY_STRICTNESS[pr_r.fail_on_severity] > _SEVERITY_STRICTNESS[op_r.fail_on_severity]
        else op_r.fail_on_severity
    )
    allowed_ignored = set(op_r.ignore_categories)
    ignore_categories = [c for c in pr_r.ignore_categories if c in allowed_ignored]

    op_v, pr_v = operator_policy.validation, project_policy.validation
    min_assurance = (
        pr_v.minimum_assurance_level
        if _ASSURANCE_STRICTNESS[pr_v.minimum_assurance_level]
        > _ASSURANCE_STRICTNESS[op_v.minimum_assurance_level]
        else op_v.minimum_assurance_level
    )

    return Policy(
        version="1.0",
        scan=operator_policy.scan,
        risk=RiskPolicy(
            fail_threshold=fail_threshold,
            warn_threshold=warn_threshold,
            ignore_categories=ignore_categories,
            fail_on_severity=fail_on_severity,
            suppressions=list(op_r.suppressions),
        ),
        validate=ValidatePolicy(
            require_completeness=op_v.require_completeness or pr_v.require_completeness,
            require_integrity=op_v.require_integrity or pr_v.require_integrity,
            minimum_assurance_level=min_assurance,
            require_discovery_signature=(
                op_v.require_discovery_signature or pr_v.require_discovery_signature
            ),
        ),
        output=operator_policy.output,
    )


def _cli_supports_operator_policy() -> bool:
    scan_cmd = cli_main.commands.get("scan")
    if scan_cmd is None:
        return False
    return any("--operator-policy" in param.opts for param in scan_cmd.params)


def run_staged_gate(
    project_dir: Path,
    operator_policy_source: Path,
    *,
    baseline_source: Path | None = None,
    attestation_source: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
    require_signed: bool = False,
) -> tuple[int, str]:
    """Verify operator policy placement/attestation in-place and run repository gates."""
    try:
        if not project_dir.is_dir():
            raise click.UsageError("--project must name an existing directory")
        if require_signed and (attestation_source is None or not trusted_keys):
            raise click.UsageError(
                "--require-signed-operator-policy requires --operator-policy-attestation "
                "and at least one --operator-policy-key"
            )
        if attestation_source is not None and not trusted_keys:
            raise click.UsageError(
                "--operator-policy-attestation requires at least one --operator-policy-key"
            )
        if trusted_keys and attestation_source is None:
            raise click.UsageError("--operator-policy-key requires --operator-policy-attestation")

        untrusted = (
            (project_dir, baseline_source) if baseline_source is not None else (project_dir,)
        )
        _verify_outside_checkout(operator_policy_source, untrusted, label="--operator-policy")
        if baseline_source is not None:
            _verify_outside_checkout(baseline_source, (project_dir,), label="--baseline")

        if attestation_source is not None:
            _verify_outside_checkout(
                attestation_source, untrusted, label="--operator-policy-attestation"
            )
            _check_key_placement(
                trusted_keys,
                (project_dir, operator_policy_source, attestation_source),
                option="--operator-policy-key",
                holders="PROJECT, OPERATOR_POLICY, ATTESTATION",
            )

        raw_policy = _read(operator_policy_source, MAX_OPERATOR_POLICY_BYTES)
        if attestation_source is not None:
            ring: dict[str, Ed25519PublicKey] = {}
            for key_path in trusted_keys:
                pub = cast("Ed25519PublicKey", _load_trusted_public(key_path))
                ring[key_id(pub)] = pub
            raw_env = _read(attestation_source, attestation.MAX_ENVELOPE_BYTES)
            attestation.verify_attestation(
                attestation.parse_envelope(raw_env),
                raw_policy,
                trusted_keys=ring,
                purpose="reviewed",
                threshold=1,
                match="bytes",
            )

        operator_policy = Policy.model_validate(
            parse_yaml_mapping(raw_policy.decode("utf-8"), max_nodes=MAX_POLICY_YAML_NODES)
        )
        policy_digest = "sha256:" + hashlib.sha256(raw_policy).hexdigest()
    except click.UsageError as exc:
        return 2, f"Error: {exc.format_message()}\n"
    except (PolicyError, ValidationError, UnicodeDecodeError) as exc:
        return 2, f"Error: invalid operator policy ({type(exc).__name__})\n"
    except (_KeyFileError, _InputTooLargeError, OSError) as exc:
        return 2, f"Error: operator policy input rejected ({exc or type(exc).__name__})\n"
    except attestation.AttestationError as exc:
        return 1, f"Error: operator policy attestation verification failed ({exc.reason})\n"

    cli_policy_args: list[str] = []
    scan_extra_args: list[str] = []
    if _cli_supports_operator_policy():
        cli_policy_args.extend(["--operator-policy", str(operator_policy_source)])
        if attestation_source is not None:
            cli_policy_args.extend(["--operator-policy-attestation", str(attestation_source)])
        for key_path in trusted_keys:
            cli_policy_args.extend(["--operator-policy-key", str(key_path)])
        if require_signed:
            cli_policy_args.append("--require-signed-operator-policy")
    else:
        # Ignore untrusted checkout .nexus-symbiote.yaml during collection so a PR cannot
        # hide files via scan.exclude_paths, disable collectors via scan.scanners, or
        # trigger the CI weakened-project-policy abort before operator clamping runs.
        scan_extra_args.append("--no-project-policy")
        for scanner_name in operator_policy.scan.scanners:
            scan_extra_args.extend(["--scanner", scanner_name])

    with tempfile.TemporaryDirectory(prefix="nsb-staged-out-") as out_root:
        candidate_bom = Path(out_root) / "candidate-aibom.json"
        runner = CliRunner()
        scan_res = runner.invoke(
            cli_main,
            [
                "scan",
                str(project_dir),
                "-o",
                str(candidate_bom),
                "--report-only",
                *cli_policy_args,
                *scan_extra_args,
            ],
        )
        if scan_res.exit_code != 0 or not candidate_bom.is_file():
            return scan_res.exit_code or 1, scan_res.output

        bom = AIBOM.load(candidate_bom)
        resolved_project = project_dir.resolve()
        try:
            project_policy = load_policy(resolved_project)
        except PolicyError as exc:
            return 1, scan_res.output + f"Error: invalid checkout policy ({exc})\n"

        effective = clamp_operator_floor(operator_policy, project_policy)
        lines = [scan_res.output, f"Policy: operator:{policy_digest}\n"]

        if effective.validation.require_completeness:
            c_rep = CompletenessValidator().validate_against_project(
                bom, resolved_project, exclude_paths=effective.scan.exclude_paths
            )
            if not c_rep.is_complete:
                lines.append("Error: completeness validation failed under operator policy\n")
                return 1, "".join(lines)
        if effective.validation.require_integrity:
            i_rep = IntegrityValidator().validate(
                bom, resolved_project, exclude_paths=effective.scan.exclude_paths
            )
            if i_rep.status == "fail":
                lines.append("Error: integrity validation failed under operator policy\n")
                return 1, "".join(lines)

        scorer = RiskScorer(
            fail_threshold=effective.risk.fail_threshold,
            warn_threshold=effective.risk.warn_threshold,
            ignore_categories=effective.risk.ignore_categories,
            fail_on_severity=effective.risk.fail_on_severity,
            suppressions=effective.risk.suppressions,
        )
        passed, risk_report = scorer.passes_gate(bom)
        if not passed:
            reasons = "; ".join(risk_report.gate_reasons) or "risk gate failed"
            lines.append(f"Error: operator risk gate failed: {reasons}\n")
            return 1, "".join(lines)

        if _cli_supports_operator_policy():
            risk_res = runner.invoke(
                cli_main,
                ["risk", str(candidate_bom), "--project", str(project_dir), *cli_policy_args],
            )
            lines.append(risk_res.output)
            if risk_res.exit_code != 0:
                return risk_res.exit_code, "".join(lines)

        if baseline_source is not None:
            diff_res = runner.invoke(
                cli_main,
                ["diff", str(baseline_source), str(candidate_bom), "--fail-on-alert"],
            )
            lines.append(diff_res.output)
            if diff_res.exit_code != 0:
                return diff_res.exit_code, "".join(lines)

        return 0, "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True, help="Target checkout directory")
    parser.add_argument(
        "--operator-policy",
        type=Path,
        required=True,
        help="Trusted operator policy file outside the checkout and its git working tree",
    )
    parser.add_argument(
        "--operator-policy-attestation",
        type=Path,
        default=None,
        help="Reviewed DSSE attestation envelope over --operator-policy",
    )
    parser.add_argument(
        "--operator-policy-key",
        type=Path,
        action="append",
        default=[],
        help="Trusted Ed25519 public key PEM for --operator-policy-attestation (repeatable)",
    )
    parser.add_argument(
        "--require-signed-operator-policy",
        action="store_true",
        help="Fail closed unless --operator-policy carries a verified DSSE attestation",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional reviewed baseline AIBOM outside the checkout",
    )
    args = parser.parse_args(argv)
    code, output = run_staged_gate(
        args.project,
        args.operator_policy,
        baseline_source=args.baseline,
        attestation_source=args.operator_policy_attestation,
        trusted_keys=tuple(args.operator_policy_key),
        require_signed=args.require_signed_operator_policy,
    )
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
