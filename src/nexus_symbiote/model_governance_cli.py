"""CLI commands for model governance policy (Item 30) and dual-axis completeness scoring (Item 31)."""

from __future__ import annotations

import json
from pathlib import Path

import click

from nexus_symbiote.completeness_score import score_aibom_completeness
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.model_policy import (
    ModelGovernancePolicy,
    ModelPolicyError,
    evaluate_model_policy,
    load_model_policy,
    load_retirement_catalog,
)
from nexus_symbiote.utils.terminal import (
    json_text,
    neutralize,
    refuse_dash_output,
    write_cli_output,
)

_EXISTING_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
_EXISTING_DIR = click.Path(exists=True, file_okay=False, path_type=Path)


def _load_aibom(path: Path) -> AIBOM:
    try:
        return AIBOM.load(path)
    except (NativeFormatError, OSError, ValueError, TypeError, RecursionError) as exc:
        raise click.ClickException(f"Invalid native AIBOM file: {neutralize(exc)}") from exc


def _emit_json(text: str, output: Path | None) -> None:
    if output:
        refuse_dash_output(output)
        write_cli_output(output, text + "\n")
    else:
        click.echo(json_text(text))


def register_model_governance_commands(main: click.Group) -> None:
    @main.command("model-policy")
    @click.argument("aibom_path", type=_EXISTING_FILE)
    @click.option(
        "--policy",
        "policy_path",
        type=_EXISTING_FILE,
        help="Operator-owned model policy YAML/JSON.",
    )
    @click.option(
        "--policy-attestation", type=_EXISTING_FILE, help="Reviewed DSSE attestation for --policy."
    )
    @click.option(
        "--retirement-catalog",
        type=_EXISTING_FILE,
        help="Offline AIROM model retirement catalog JSON.",
    )
    @click.option(
        "--catalog-attestation",
        type=_EXISTING_FILE,
        help="Reviewed DSSE attestation for --retirement-catalog.",
    )
    @click.option(
        "--trusted-key",
        "trusted_keys",
        multiple=True,
        type=_EXISTING_FILE,
        help="Ed25519 pubkey PEM.",
    )
    @click.option(
        "--allow-unsigned-policy",
        is_flag=True,
        default=False,
        help="Allow unattested policy or catalog.",
    )
    @click.option("--project-root", type=_EXISTING_DIR, help="Scanned project root.")
    @click.option(
        "-o", "--output", type=click.Path(path_type=Path), help="Write report JSON to file."
    )
    def model_policy(
        aibom_path: Path,
        policy_path: Path | None,
        policy_attestation: Path | None,
        retirement_catalog: Path | None,
        catalog_attestation: Path | None,
        trusted_keys: tuple[Path, ...],
        allow_unsigned_policy: bool,
        project_root: Path | None,
        output: Path | None,
    ) -> None:
        """Evaluate models in an AgentBOM against pinning, license, trust_remote_code, and AIROM retirement policy.

        Dated provider snapshots (e.g. gpt-4o-2024-08-06) and cryptographic digests pass pinning;
        floating aliases fail closed. Operator policy and retirement catalogs require Ed25519 DSSE
        attestation by default unless --allow-unsigned-policy is passed. Exits 1 on violations.
        """
        if policy_attestation is not None and policy_path is None:
            raise click.UsageError("--policy-attestation requires --policy")
        if catalog_attestation is not None and retirement_catalog is None:
            raise click.UsageError("--catalog-attestation requires --retirement-catalog")

        bom = _load_aibom(aibom_path)
        try:
            if policy_path is not None:
                policy, pol_sha, pol_att = load_model_policy(
                    policy_path,
                    project_root=project_root,
                    inventory_path=aibom_path,
                    attestation_path=policy_attestation,
                    trusted_key_paths=trusted_keys,
                    allow_unsigned=allow_unsigned_policy,
                )
            else:
                policy, pol_sha, pol_att = ModelGovernancePolicy(), "default", False

            catalog, cat_sha, cat_att = None, None, False
            if retirement_catalog is not None:
                catalog, cat_sha, cat_att = load_retirement_catalog(
                    retirement_catalog,
                    project_root=project_root,
                    inventory_path=aibom_path,
                    attestation_path=catalog_attestation,
                    trusted_key_paths=trusted_keys,
                    allow_unsigned=allow_unsigned_policy,
                )
        except (ModelPolicyError, OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc

        report = evaluate_model_policy(
            bom,
            policy,
            policy_sha256=pol_sha,
            policy_attested=pol_att,
            catalog=catalog,
            catalog_sha256=cat_sha,
            catalog_attested=cat_att,
        )
        _emit_json(json.dumps(report.to_dict(), indent=2, sort_keys=True, allow_nan=False), output)
        if not report.passed:
            raise click.exceptions.Exit(1)

    @main.command("completeness-score")
    @click.argument("aibom_path", type=_EXISTING_FILE)
    @click.option(
        "--min-structure",
        type=click.FloatRange(0.0, 100.0),
        default=None,
        help="Exit 1 when overall structure_score is below this threshold (0-100).",
    )
    @click.option(
        "--min-completeness",
        type=click.FloatRange(0.0, 100.0),
        default=None,
        help="Exit 1 when overall completeness_score is below this threshold (0-100).",
    )
    @click.option(
        "-o", "--output", type=click.Path(path_type=Path), help="Write report JSON to file."
    )
    def completeness_score(
        aibom_path: Path,
        min_structure: float | None,
        min_completeness: float | None,
        output: Path | None,
    ) -> None:
        """Compute dual-axis structure_score vs completeness_score for an AgentBOM offline.

        Reports separate 0-100 structure and completeness scores plus a per-component
        missing_fields checklist so valid-but-undocumented inventories are exposed clearly.
        """
        bom = _load_aibom(aibom_path)
        report = score_aibom_completeness(bom)
        _emit_json(json.dumps(report.to_dict(), indent=2, sort_keys=True, allow_nan=False), output)
        failed = (min_structure is not None and report.structure_score < min_structure) or (
            min_completeness is not None and report.completeness_score < min_completeness
        )
        if failed:
            raise click.exceptions.Exit(1)
