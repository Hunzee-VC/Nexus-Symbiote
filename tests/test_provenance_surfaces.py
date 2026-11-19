"""Tests for provenance_surfaces.py and provenance_cli.py (R1.1-4, R1.3-5, R1.3-6, R1.4-2)."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import A2AServerComponent, ModelComponent
from nexus_symbiote.provenance_surfaces import (
    inspect_gguf_general_keys,
    inspect_pickle_globals,
    inspect_provenance_surfaces,
)


def _gguf_bytes(kvs: list[tuple[str, int, bytes]]) -> bytes:
    header = b"GGUF" + struct.pack("<IQQ", 3, 0, len(kvs))
    body = bytearray()
    for key, kind, val_bytes in kvs:
        k_raw = key.encode("utf-8")
        body += struct.pack("<Q", len(k_raw)) + k_raw + struct.pack("<I", kind) + val_bytes
    return header + bytes(body)


def _gguf_str(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def test_pickle_safe_and_unsafe_globals_and_opcodes() -> None:
    # Safe torch global via GLOBAL ('c') and STACK_GLOBAL (0x93)
    safe_stream = (
        b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00"
        b"ctorch._utils\n_rebuild_tensor_v2\nq\x00"
        b"\x8c\x0bcollections\x94\x8c\x0bOrderedDict\x94\x93"
        b"K\x01M\x02\x00J\x01\x00\x00\x00G?\xf0\x00\x00\x00\x00\x00\x00"
        b"\x8a\x01\x01\x8b\x01\x00\x00\x00\x01"
        b"C\x02abB\x02\x00\x00\x00cd"
        b"N(]})\x88\x89\x8fR0."
    )
    evidences, truncated = inspect_pickle_globals(safe_stream)
    assert not truncated
    assert len(evidences) == 2
    assert all(e.allowed for e in evidences)
    assert evidences[0].global_name == "torch._utils._rebuild_tensor_v2"
    assert evidences[1].global_name == "collections.OrderedDict"

    # Disallowed os.system via GLOBAL and subprocess.Popen via STACK_GLOBAL + EXT1
    unsafe_stream = (
        b"\x80\x02cos\nsystem\n"
        b"U\x0asubprocessr\x01\x00\x00\x00"
        b"T\x05\x00\x00\x00Popenj\x01\x00\x00\x00h\x00"
        b"\x8d\x0a\x00\x00\x00subprocess\x8e\x05\x00\x00\x00\x00\x00\x00\x00Popen\x93"
        b"\x82\x07\x83\x08\x00\x84\x09\x00\x00\x00"
        b"I1\nF1.5\nS'mod'\np0\nVattr\ng0\ni__main__\nEvil\nP1\nQ."
    )
    ev2, trunc2 = inspect_pickle_globals(unsafe_stream)
    assert not trunc2
    names = [e.global_name for e in ev2]
    assert "os.system" in names
    assert "subprocess.Popen" in names
    assert "copyreg.extension_7" in names
    assert "__main__.Evil" in names
    os_ev = next(e for e in ev2 if e.global_name == "os.system")
    assert not os_ev.allowed
    assert os_ev.opcode == "GLOBAL"
    assert os_ev.byte_offset == 2


def test_pickle_truncation_and_malformed_branches() -> None:
    _, trunc_budget = inspect_pickle_globals(b"N0N0N0.", max_opcodes=2)
    assert trunc_budget
    for bad in (
        b"\x80",
        b"\x95\x01\x02",
        b"cos\n",
        b"\x93",
        b"\x82",
        b"\x8c\x05abc",
        b"\x8d\x01\x00",
        b"\x8d\x05\x00\x00\x00a",
        b"\x8e\x01\x00",
        b"\x8e\x05\x00\x00\x00\x00\x00\x00\x00a",
        b"U\x05a",
        b"T\x01",
        b"T\xff\xff\xff\xff",
        b"S'unterminated",
        b"q",
        b"r\x01",
        b"pnotint\n",
        b"p",
        b"h",
        b"j\x01",
        b"gnotint\n",
        b"g",
        b"K",
        b"M\x01",
        b"J\x01",
        b"G\x01",
        b"\x8a",
        b"\x8a\x05a",
        b"\x8b\x01",
        b"\x8b\xff\xff\xff\xff",
        b"C",
        b"C\x04a",
        b"B\x01",
        b"B\x04\x00\x00\x00a",
        b"I123",
        b"\xff",
    ):
        _, trunc = inspect_pickle_globals(bad)
        assert trunc


def test_gguf_general_keys_allowlist_and_malformed() -> None:
    gguf_raw = _gguf_bytes(
        [
            ("general.architecture", 8, _gguf_str("llama")),
            ("general.license", 8, _gguf_str("apache-2.0")),
            ("general.quantization_version", 4, struct.pack("<I", 2)),
            ("general.tags", 9, struct.pack("<IQ", 8, 1) + _gguf_str("chat")),
            ("general.languages", 9, struct.pack("<IQ", 4, 2) + struct.pack("<II", 1, 2)),
            ("general.backdoor_hook", 8, _gguf_str("evil")),
        ]
    )
    keys, lic, malformed = inspect_gguf_general_keys(gguf_raw)
    assert not malformed
    assert lic == "apache-2.0"
    disallowed = [k for k in keys if not k.allowed]
    assert len(disallowed) == 1
    assert disallowed[0].key == "general.backdoor_hook"
    assert disallowed[0].byte_offset > 0

    for bad_gguf in (
        b"NOTG",
        b"GGUF" + struct.pack("<IQQ", 1, 0, 0),
        b"GGUF" + struct.pack("<IQQ", 3, 0, 5000),
        b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + b"\x01",
        _gguf_bytes([("general.x", 99, b"")]),
        _gguf_bytes([("general.x", 4, b"\x01")]),
        _gguf_bytes([("general.x", 9, b"\x01")]),
        _gguf_bytes([("general.x", 9, struct.pack("<IQ", 4, 999999))]),
        _gguf_bytes([("general.x", 9, struct.pack("<IQ", 4, 2) + b"\x01")]),
    ):
        _, _, m = inspect_gguf_general_keys(bad_gguf)
        assert m


def test_end_to_end_provenance_surfaces_and_cli(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()

    # 1. Pickle files (one safe, one unsafe with os.system, one credential-named skipped)
    models_dir = project / "models"
    models_dir.mkdir()
    (models_dir / "safe.pt").write_bytes(b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\n)R.")
    (models_dir / "backdoor.pkl").write_bytes(b"\x80\x02cos\nsystem\n(S'id'\ntR.")
    (models_dir / "api_key_weights.pkl").write_bytes(b"\x80\x02cos\nsystem\n.")

    # 2. GGUF model with disallowed general.* key
    (models_dir / "custom.gguf").write_bytes(
        _gguf_bytes(
            [
                ("general.architecture", 8, _gguf_str("llama")),
                ("general.license", 8, _gguf_str("mit")),
                ("general.custom_loader_hook", 8, _gguf_str("run")),
            ]
        )
    )

    # 3. Alias indirection: Modelfile, LiteLLM, k8s/vllm.yaml, configs/mlflow.yaml
    (project / "Modelfile").write_text("FROM llama3:latest\n", encoding="utf-8")
    (project / "litellm_config.yaml").write_text(
        "model_list:\n"
        "  - model_name: prod-llm\n"
        "    litellm_params:\n"
        "      model: openai/gpt-4o\n"
        "  - model_name: prod-llm\n"
        "    litellm_params:\n"
        "      model: anthropic/claude-3-5-sonnet-20241022\n",
        encoding="utf-8",
    )
    k8s_dir = project / "k8s"
    k8s_dir.mkdir()
    (k8s_dir / "vllm.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: vllm\n"
        "          args:\n"
        "            - --model=meta-llama/Llama-3-8B\n"
        "            - --served-model-name=chat-default\n",
        encoding="utf-8",
    )
    configs_dir = project / "configs"
    configs_dir.mkdir()
    (configs_dir / "mlflow.yaml").write_text(
        "model_uri: models:/fraud-detector/Production\n"
        "pinned_model:\n"
        "  registry_uri: hf://meta-llama/Llama-3-8B\n"
        "  revision: 0123456789abcdef0123456789abcdef01234567\n",
        encoding="utf-8",
    )

    # 4. Guardrails, Promptfoo, MemoryStore, and PII data reaching exposed agent
    (project / "guardrails.yaml").write_text(
        "version: '1.0'\n"
        "guardrail_type: input-filter\n"
        "rails:\n"
        "  input:\n"
        "    flows:\n"
        "      - self check input\n"
        "memory_stores:\n"
        "  - name: shared-episodic\n"
        "    store_type: episodic\n"
        "    write_authority: public\n"
        "    tenant_isolated: false\n"
        "    encryption_at_rest: true\n"
        "exposed: true\n"
        "name: support-agent\n"
        "data:\n"
        "  - name: customer-records\n"
        "    classification: pii\n"
        "rag_sources:\n"
        "  - name: billing-vectors\n"
        "    classification: confidential\n",
        encoding="utf-8",
    )
    (project / "promptfooconfig.yaml").write_text(
        "prompts:\n  - 'Hello {{name}}'\nproviders:\n  - openai:gpt-4o\ntests:\n  - vars:\n      name: world\n",
        encoding="utf-8",
    )

    # 5. Training lineage: .dvc (one matching, one mismatching), training.yaml with pin 1c4513b2
    data_dir = project / "data"
    data_dir.mkdir()
    train_bytes = b'{"prompt": "hi", "completion": "hello"}\n'
    (data_dir / "train.jsonl").write_bytes(train_bytes)
    train_md5 = hashlib.md5(train_bytes, usedforsecurity=False).hexdigest()
    (data_dir / "train.jsonl.dvc").write_text(
        f"outs:\n  - md5: {train_md5}\n    path: train.jsonl\n",
        encoding="utf-8",
    )
    (data_dir / "tampered.jsonl").write_bytes(b"tampered")
    (data_dir / "tampered.jsonl.dvc").write_text(
        "outs:\n  - md5: 00000000000000000000000000000000\n    path: tampered.jsonl\n",
        encoding="utf-8",
    )
    (project / "training.yaml").write_text(
        "run_id: finetune-v1\n"
        "dataset: corp/instruct-set\n"
        "dataset_revision: 1c4513b2\n"
        "base_model: meta-llama/Llama-3-8B\n"
        "output_model: corp/llama3-finetuned\n",
        encoding="utf-8",
    )

    # External claims: CR-2, CR-4 (unpinned corp/instruct-set + conflicting base_model), CR-9, CR-10
    claims_file = tmp_path / "claims.json"
    claims_file.write_text(
        json.dumps(
            {
                "claims": [
                    {
                        "cr": "CR-10",
                        "model_path": "models/safe.pt",
                        "loader_call": "AutoModel.from_pretrained",
                        "trust_remote_code": True,
                        "file": "app/loader.py",
                        "line": 42,
                    },
                    {
                        "cr": "CR-2",
                        "alias": "claim-alias",
                        "target": "gpt-4o-mini:latest",
                        "file": "app/router.py",
                    },
                    {
                        "cr": "CR-4",
                        "dataset": "corp/instruct-set",
                        "revision": "main",
                        "base_model": "mistralai/Mistral-7B",
                        "target_model": "corp/llama3-finetuned",
                        "registry_uri": "runs:/abc123def/model",
                        "file": "train.py",
                    },
                    {
                        "cr": "CR-9",
                        "bom_ref": "guard.bedrock-guardrail",
                        "guardrail_type": "classifier",
                        "file": "infra/bedrock.tf",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    # External in-toto / SLSA lineage attestation
    att_file = tmp_path / "lineage.intoto.json"
    att_file.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "corp/attested-model",
                        "digest": {"sha256": "a" * 64},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "run_id": "slsa-train-1",
                    "materials": [
                        {
                            "uri": "hf://datasets/corp/clean-data",
                            "digest": {"sha256": "b" * 64},
                        },
                        {
                            "uri": "meta-llama/Llama-3-8B-Base",
                            "kind": "base_model",
                            "digest": {"sha256": "c" * 64},
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    # Existing inventory with an A2A server and a model component
    base_bom = AIBOM()
    base_bom.add_component(
        A2AServerComponent(
            bom_ref="a2a:public",
            name="public-a2a",
            endpoint_url="https://agent.example/a2a",
        )
    )
    base_bom.add_component(
        ModelComponent(
            bom_ref="model:existing",
            name="existing",
            requested_alias="existing-alias",
            resolved_revision="gpt-4-0613",
            assurance_level=AssuranceLevel.OBSERVED,
        )
    )
    inv_path = tmp_path / "base.aibom.json"
    base_bom.save(inv_path)

    doc, enriched = inspect_provenance_surfaces(
        inventory_path=inv_path,
        project_root=project,
        claim_paths=(claims_file,),
        attestation_paths=(att_file,),
        fail_on="high",
    )

    categories = {f["category"] for f in doc["findings"]}
    assert "pickle_unsafe_global" in categories
    assert "gguf_unrecognized_general_key" in categories
    assert "loader_trust_remote_code" in categories
    assert "model_alias_mutable" in categories
    assert "model_alias_retargeted" in categories
    assert "floating_registry_reference" in categories
    assert "memory_store_unisolated" in categories
    assert "pii_data_reaches_exposed_agent" in categories
    assert "floating_dataset_revision" in categories
    assert "lineage_unpinned" in categories
    assert "lineage_conflict" in categories
    assert any("api_key_weights.pkl" in g for g in doc["unread_gaps"])

    # Guardrail ground-truth IDs guard.config, eval.promptfoo, and guard.bedrock-guardrail
    guard_refs = {g["bom_ref"] for g in doc["guardrails"]}
    assert {"guard.config", "eval.promptfoo", "guard.bedrock-guardrail"} <= guard_refs
    assert enriched.get_component("guard.config") is not None
    assert enriched.get_component("eval.promptfoo") is not None

    # Attested model and dataset stay at DECLARED assurance
    attested_model = enriched.get_component("model:corp/attested-model")
    assert attested_model is not None
    assert attested_model.assurance_level == AssuranceLevel.DECLARED

    # Verify CLI invocation with JSON output, report output, and bom output
    out_report = tmp_path / "report.json"
    out_bom = tmp_path / "enriched.aibom.json"
    runner = CliRunner()
    res = runner.invoke(
        main,
        [
            "inspect-provenance",
            "--inventory",
            str(inv_path),
            "--project",
            str(project),
            "--claims",
            str(claims_file),
            "--attestation",
            str(att_file),
            "-o",
            str(out_report),
            "--bom-output",
            str(out_bom),
            "--json-output",
            "--fail-on",
            "high",
        ],
    )
    assert res.exit_code == 1
    parsed_stdout = json.loads(res.stdout)
    assert parsed_stdout["format"] == "nexus-symbiote/provenance-surfaces/v1"
    assert out_report.is_file()
    assert out_bom.is_file()

    # Text summary mode with --fail-on none
    res_text = runner.invoke(
        main,
        [
            "inspect-provenance",
            "--project",
            str(project),
            "--fail-on",
            "none",
        ],
    )
    assert res_text.exit_code == 0
    assert "Provenance inspection:" in res_text.stdout
    assert "Provenance gate: not applied" in res_text.stdout


def test_cli_error_handling_and_confinement(tmp_path: Path) -> None:
    runner = CliRunner()
    # No inputs provided
    res_empty = runner.invoke(main, ["inspect-provenance"])
    assert res_empty.exit_code != 0

    project = tmp_path / "clean_proj"
    project.mkdir()
    # Passing gate in text mode
    res_pass = runner.invoke(
        main, ["inspect-provenance", "--project", str(project), "--fail-on", "high"]
    )
    assert res_pass.exit_code == 0
    assert "Provenance gate passed:" in res_pass.stdout

    # Output inside --project refused
    res_inside = runner.invoke(
        main,
        [
            "inspect-provenance",
            "--project",
            str(project),
            "-o",
            str(project / "out.json"),
        ],
    )
    assert res_inside.exit_code != 0

    # Overwriting input refused
    claims = tmp_path / "c.json"
    claims.write_text("[]", encoding="utf-8")
    res_overwrite = runner.invoke(
        main,
        ["inspect-provenance", "--claims", str(claims), "-o", str(claims)],
    )
    assert res_overwrite.exit_code != 0

    # Same file for -o and --bom-output refused
    same_out = tmp_path / "same.json"
    res_same = runner.invoke(
        main,
        [
            "inspect-provenance",
            "--claims",
            str(claims),
            "-o",
            str(same_out),
            "--bom-output",
            str(same_out),
        ],
    )
    assert res_same.exit_code != 0

    # Malformed claims JSON refused
    bad_claims = tmp_path / "bad.json"
    bad_claims.write_text("{not-json", encoding="utf-8")
    res_bad = runner.invoke(main, ["inspect-provenance", "--claims", str(bad_claims)])
    assert res_bad.exit_code != 0

    # Invalid native inventory refused
    bad_inv = tmp_path / "bad_inv.json"
    bad_inv.write_text('{"metadata": {"spec_version": "9.9.9"}}', encoding="utf-8")
    res_bad_inv = runner.invoke(main, ["inspect-provenance", "--inventory", str(bad_inv)])
    assert res_bad_inv.exit_code != 0

    # Symlink project root refused
    sym_proj = tmp_path / "sym_proj"
    sym_proj.symlink_to(project)
    res_sym = runner.invoke(main, ["inspect-provenance", "--project", str(sym_proj)])
    assert res_sym.exit_code != 0

    # Failing gate in text summary mode + output outside project without --project
    fail_claims = tmp_path / "fail_claims.json"
    fail_claims.write_text(
        json.dumps([{"cr": "CR-10", "model_path": "m.bin", "trust_remote_code": True}]),
        encoding="utf-8",
    )
    out_only = tmp_path / "out_only.json"
    res_fail_text = runner.invoke(
        main, ["inspect-provenance", "--claims", str(fail_claims), "-o", str(out_only)]
    )
    assert res_fail_text.exit_code == 1
    assert "Provenance gate failed:" in res_fail_text.stdout

    # Non-dict/non-list JSON claim file refused
    prim_claims = tmp_path / "prim.json"
    prim_claims.write_text("123", encoding="utf-8")
    res_prim = runner.invoke(main, ["inspect-provenance", "--claims", str(prim_claims)])
    assert res_prim.exit_code != 0


def test_provenance_edge_cases_and_error_branches(tmp_path: Path) -> None:
    # GGUF non-general key, truncated general string value, and oversized string length
    gguf_mix = _gguf_bytes(
        [
            ("llama.context_length", 4, struct.pack("<I", 4096)),
            ("general.architecture", 8, _gguf_str("llama")),
        ]
    )
    keys, lic, malformed = inspect_gguf_general_keys(gguf_mix)
    assert not malformed
    assert lic is None
    assert len(keys) == 1

    # GGUF truncated inside general.* string value and string length > size
    bad_key_len = b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 99) + b"abc"
    assert inspect_gguf_general_keys(bad_key_len)[2] is True
    bad_val_str = (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 1)
        + _gguf_str("general.name")
        + struct.pack("<IQ", 8, 99)
        + b"x"
    )
    assert inspect_gguf_general_keys(bad_val_str)[2] is True

    # Project with custom.modelfile, vLLM --model= and --served-model-name, duplicate memory store,
    # DVC with sha256 and empty outs, symlink to credential file, broken symlink (collection failure),
    # and conflicting pinned dataset digests.
    proj = tmp_path / "edge_proj"
    proj.mkdir()
    (proj / "custom.modelfile").write_text("FROM llama3:8b\n# comment\n", encoding="utf-8")
    (proj / "secret.pem").write_text("PRIVATE KEY", encoding="utf-8")
    (proj / "linked_cfg.yaml").symlink_to("secret.pem")
    (proj / "broken_link.yaml").symlink_to("does_not_exist.yaml")
    (proj / "empty.dvc").write_text("meta: 1\n", encoding="utf-8")
    data_file = proj / "sub" / "corpus.jsonl"
    data_file.parent.mkdir()
    data_file.write_bytes(b'{"a":1}\n')
    sha_hex = hashlib.sha256(b'{"a":1}\n').hexdigest()
    (proj / "sub" / "corpus.jsonl.dvc").write_text(
        f"outs:\n  - path: ''\n  - path: corpus.jsonl\n    sha256: {sha_hex}\n",
        encoding="utf-8",
    )
    (proj / "vllm_list.yaml").write_text(
        "services:\n"
        "  - command: ['vllm', '--model=meta-llama/Llama-3-8B', '--served-model-name', 'chat-alias']\n"
        "  - registry_uri: 'oci://registry.example.com/models/base@sha256:" + ("b" * 64) + "'\n"
        "memory: {name: shared-mem, store_type: vector, tenant_isolated: true}\n",
        encoding="utf-8",
    )
    (proj / "guard1.yaml").write_text(
        "guardrails:\n  - input\nmemory_stores:\n  - name: shared-mem\n",
        encoding="utf-8",
    )
    (proj / "guard2.yaml").write_text("rails:\n  - output\n", encoding="utf-8")

    # Pre-existing inventory with alias + conflicting dataset pins in claims
    inv = AIBOM()
    inv.add_component(
        ModelComponent(
            bom_ref="model:alias:chat-alias",
            name="chat-alias",
            model_type="alias",
            requested_alias="chat-alias",
            resolved_revision="other-target",
        )
    )
    inv_file = tmp_path / "pre_inv.json"
    inv_file.write_text(inv.to_native_json(), encoding="utf-8")

    claims_file = tmp_path / "edge_claims.json"
    claims_file.write_text(
        json.dumps(
            [
                {"cr": "CR-10", "model_path": "", "trust_remote_code": False},
                {"cr": "CR-10", "model_path": "safe.safetensors", "trust_remote_code": False},
                {
                    "cr": "CR-4",
                    "dataset": "corpus.jsonl",
                    "revision": "sha256:" + ("c" * 64),
                },
                {"cr": "CR-9", "bom_ref": "guard.config"},
            ]
        ),
        encoding="utf-8",
    )

    doc, _ = inspect_provenance_surfaces(
        inventory_path=inv_file,
        project_root=proj,
        claim_paths=(claims_file,),
        fail_on="high",
    )
    cats = {f["category"] for f in doc["findings"]}
    assert "lineage_conflict" in cats
    assert "model_alias_retargeted" in cats
    assert any(" confined collection failure" in r for r in doc["gate"]["reasons"])
