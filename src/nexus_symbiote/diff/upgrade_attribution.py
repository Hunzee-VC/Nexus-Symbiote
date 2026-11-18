"""Static attribution of expected format and fingerprint transitions across tool upgrades.

When an operator upgrades Nexus SymBiote across a documented profile change (for example
``0.1.0 -> 0.2.0`` or ``0.2.0 -> 0.3.0``) and passes ``diff --expect-upgrade FROM_VERSION``,
alerts caused *exclusively* by the documented serializer/profile transitions of that upgrade
are moved from ``security_alerts`` into ``tool_upgrade_changes``. Any component modification
that mixes an upgrade transition with genuine supply-chain drift (changed command, endpoint,
tool description, permissions, etc.) remains in ``security_alerts`` and fails the gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UpgradeRule:
    """Known profile or schema transitions introduced after ``from_version``."""

    from_version: str
    detail_patterns: tuple[re.Pattern[str], ...]
    requires_profile_bump_for_binding: bool = True


_PROFILE_BUMP_RE = re.compile(
    r"^properties\.static_(?:config_hash_profile|value_binding_profile) (?:changed|added)\.$"
)

SUPPORTED_UPGRADE_VERSIONS: dict[str, UpgradeRule] = {
    "0.1.0": UpgradeRule(
        from_version="0.1.0",
        detail_patterns=(
            _PROFILE_BUMP_RE,
            re.compile(r"^properties\.static_config_hash (?:changed|added)\.$"),
            re.compile(
                r"^MCP server static source binding changed: launcher, arguments, "
                r"environment, endpoint or declared tools differ, or the binding key "
                r"changed\. Review before execution\.$"
            ),
            re.compile(
                r"^Tool fingerprint versions are unknown or incompatible; "
                r"re-collect and re-approve\.$"
            ),
            re.compile(
                r"^Changed security fields: "
                r"(?:(?:definition_hash_version|tokenizer_hash|chat_template_hash)(?:, )?)+\.$"
            ),
            re.compile(r"^Risk finding category changed: transport_security -> local_process\.$"),
        ),
    ),
    "0.2.0": UpgradeRule(
        from_version="0.2.0",
        detail_patterns=(
            _PROFILE_BUMP_RE,
            re.compile(r"^properties\.static_config_hash (?:changed|added)\.$"),
            re.compile(
                r"^MCP server static source binding changed: launcher, arguments, "
                r"environment, endpoint or declared tools differ, or the binding key "
                r"changed\. Review before execution\.$"
            ),
            re.compile(
                r"^Tool fingerprint versions are unknown or incompatible; "
                r"re-collect and re-approve\.$"
            ),
            re.compile(
                r"^Changed security fields: "
                r"(?:(?:definition_hash_version|serialization_evidence)(?:, )?)+\.$"
            ),
            re.compile(r"^properties\.(?:name_neutralized|serialization_evidence) added\.$"),
        ),
    ),
}

_METADATA_UPGRADE_RE = re.compile(
    r"^(?:Native AIBOM format version|Tool version|The (?:baseline|candidate) snapshot uses a spec_version)\b"
)


def _all_details_expected(details: list[str], rule: UpgradeRule) -> bool:
    if not details:
        return False
    has_profile_bump = any(_PROFILE_BUMP_RE.match(d) for d in details)
    for detail in details:
        if (
            (
                detail.startswith("MCP server static source binding changed:")
                or detail.startswith("properties.static_config_hash ")
            )
            and rule.requires_profile_bump_for_binding
            and not has_profile_bump
        ):
            # Without a profile version transition on the same component, a static_config_hash
            # change is genuine configuration drift and must never be attributed to an upgrade.
            return False
        if not any(pattern.match(detail) for pattern in rule.detail_patterns):
            return False
    return True


def attribute_expected_upgrade(diff_document: dict[str, Any], from_version: str) -> dict[str, Any]:
    """Partition ``security_alerts`` into active alerts vs expected tool-upgrade transitions."""
    rule = SUPPORTED_UPGRADE_VERSIONS.get(from_version)
    if rule is None:
        supported = ", ".join(sorted(SUPPORTED_UPGRADE_VERSIONS))
        raise ValueError(
            f"Unsupported --expect-upgrade version {from_version!r}; supported: {supported}"
        )
    raw_alerts = diff_document.get("security_alerts")
    if not isinstance(raw_alerts, list):
        return {
            **diff_document,
            "expected_upgrade_from": from_version,
            "tool_upgrade_changes": [],
        }

    modified_by_ref: dict[str, list[str]] = {}
    for mod in diff_document.get("components_modified") or []:
        if isinstance(mod, dict) and isinstance(mod.get("bom_ref"), str):
            raw_details = mod.get("details")
            if isinstance(raw_details, list):
                modified_by_ref[mod["bom_ref"]] = [str(item) for item in raw_details]

    kept: list[dict[str, Any]] = []
    attributed: list[dict[str, Any]] = []
    for entry in raw_alerts:
        if not isinstance(entry, dict):
            continue
        comp_ref = str(entry.get("component", ""))
        alert_text = str(entry.get("alert") or entry.get("message") or "")
        is_expected = False
        if comp_ref == "metadata" and _METADATA_UPGRADE_RE.search(alert_text):
            is_expected = True
        elif comp_ref in modified_by_ref and (
            alert_text.startswith(("Medium change in ", "High change in ", "Critical change in "))
        ):
            is_expected = _all_details_expected(modified_by_ref[comp_ref], rule)
        if is_expected:
            attributed.append({**entry, "attributed_to_upgrade": from_version})
        else:
            kept.append(entry)
    return {
        **diff_document,
        "security_alerts": kept,
        "expected_upgrade_from": from_version,
        "tool_upgrade_changes": attributed,
    }
