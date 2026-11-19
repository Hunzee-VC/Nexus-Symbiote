"""Stage operator policy and optional baseline outside the checkout (`R1.0.0-2`).

In pull-request CI, the target checkout controls `.nexus-symbiote.yaml` and any files inside
the workspace. This helper copies trusted operator policy (and optional signer policy or
reviewed baseline) into an operator-owned directory *outside* every git working tree and
invokes the Nexus SymBiote gates (`scan --check` or `scan` + `risk` + optional `diff`) so
any checkout-side attempt to weaken thresholds or suppress findings is clamped or fails closed.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main as cli_main


def run_staged_gate(
    project_dir: Path,
    operator_policy_source: Path,
    *,
    baseline_source: Path | None = None,
    attestation_source: Path | None = None,
    trusted_keys: tuple[Path, ...] = (),
) -> tuple[int, str]:
    """Copy policy artifacts into an isolated directory outside ``project_dir`` and run gates."""
    with tempfile.TemporaryDirectory(prefix="nsb-staged-policy-") as staged_root:
        staged = Path(staged_root)
        staged_policy = staged / "operator-policy.yaml"
        shutil.copyfile(operator_policy_source, staged_policy)
        staged_policy.chmod(0o600)

        policy_args = ["--operator-policy", str(staged_policy)]
        if attestation_source is not None:
            staged_att = staged / "operator-policy.dsse.json"
            shutil.copyfile(attestation_source, staged_att)
            staged_att.chmod(0o600)
            policy_args.extend(["--operator-policy-attestation", str(staged_att)])
        for idx, key_path in enumerate(trusted_keys):
            staged_key = staged / f"trusted-key-{idx}.pub"
            shutil.copyfile(key_path, staged_key)
            staged_key.chmod(0o600)
            policy_args.extend(["--operator-policy-key", str(staged_key)])

        runner = CliRunner()
        bom_out = staged / "candidate-aibom.json"
        scan_res = runner.invoke(
            cli_main,
            ["scan", str(project_dir), "-o", str(bom_out), "--report-only", *policy_args],
        )
        if scan_res.exit_code != 0 or not bom_out.is_file():
            return scan_res.exit_code or 1, scan_res.output

        risk_res = runner.invoke(
            cli_main,
            ["risk", str(bom_out), "--project", str(project_dir), *policy_args],
        )
        combined_out = scan_res.output + risk_res.output
        if risk_res.exit_code != 0:
            return risk_res.exit_code, combined_out

        if baseline_source is not None:
            staged_base = staged / "reviewed-baseline.json"
            shutil.copyfile(baseline_source, staged_base)
            staged_base.chmod(0o600)
            diff_res = runner.invoke(
                cli_main,
                ["diff", str(staged_base), str(bom_out), "--fail-on-alert"],
            )
            combined_out += diff_res.output
            if diff_res.exit_code != 0:
                return diff_res.exit_code, combined_out

        return 0, combined_out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True, help="Target checkout directory")
    parser.add_argument(
        "--operator-policy", type=Path, required=True, help="Trusted operator policy source file"
    )
    parser.add_argument("--baseline", type=Path, default=None, help="Optional reviewed baseline")
    args = parser.parse_args(argv)
    code, output = run_staged_gate(
        args.project, args.operator_policy, baseline_source=args.baseline
    )
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
