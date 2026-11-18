"""Findings on the text of a tool description, which a model reads as instructions.

The hidden-content checks are those of instruction files. ``tool_description_instructions``
is by shape: it reports a description in which at least two of three marks occur, each of
them ordinary alone. The text itself is never recorded in a finding.
"""

from __future__ import annotations

import re
from collections import Counter

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.credential_files import _CREDENTIAL_NAMES, credential_shaped
from nexus_symbiote.scanners.prompt import detect_hidden_markup, detect_invisible_characters
from nexus_symbiote.utils.terminal import neutralize

CATEGORY = "tool_description_instructions"

# An element named for priority, for the system role or for concealment: markup that
# describes nothing about a tool and addresses whoever reads the description as a prompt.
# It counts with its closing tag, which a placeholder such as `<secret>` in a usage line
# does not have.
_MODEL_TAG = re.compile(
    r"<(/?)(important|critical|system(?:[-_](?:prompt|reminder|instructions?|message))?"
    r"|instructions?|secret|hidden)>",
    re.IGNORECASE,
)
# A clause ends at ``;``, and at ``.``, ``!`` or ``?`` before white space, so the dots of
# a path do not end one. Each alternative reads a bounded stretch of one clause, so a
# megabyte description costs linear time.
_IN_CLAUSE = r"(?:[^.!?;]|[.!?](?=\S))"
_NEGATION = (
    r"(?:do\s++not|don['\u2019]?t|never|must\s++not|should\s++not|not\s++to"
    r"|no\s++need\s++to|avoid|without)"
)
_DISCLOSURE = (
    r"(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?"
    r"|reveal(?:ing)?|disclos(?:e|ing)|show(?:ing)?)"
)
_USER = r"\b(?:end[- ])?users?\b"
_CONCEALMENT = re.compile(
    rf"\b{_NEGATION}\s++(?:ever\s++|even\s++)?{_DISCLOSURE}\b{_IN_CLAUSE}{{0,80}}?{_USER}"
    rf"|\b(?:hide|conceal|withhold|keep)\b{_IN_CLAUSE}{{0,60}}?\bfrom\s++(?:the\s++)?{_USER}"
    rf"|\bwithout\s++(?:the\s++)?{_USER}(?:['\u2019]s)?\s++(?:knowing|knowledge|noticing)\b",
    re.IGNORECASE,
)
_PATH = re.compile(r"[\w.~/\\-]+")
_MARKS = (
    ("element addressed to the model", "elements addressed to the model"),
    ("directive to keep something from the user", "directives to keep something from the user"),
    ("reference to a credential location", "references to a credential location"),
)


def _model_elements(description: str) -> int:
    opened: Counter[str] = Counter()
    closed: Counter[str] = Counter()
    for slash, name in _MODEL_TAG.findall(description):
        (closed if slash else opened)[name.lower()] += 1
    return sum(min(count, closed[name]) for name, count in opened.items())


def _credential_location(token: str) -> bool:
    """Whether a path names where credentials are kept: under ``.ssh``, ``.aws/credentials``,
    a name the collectors take to hold credentials, such as ``.netrc`` or ``id_rsa``, or a
    ``.env`` file that is not a template."""
    parts = token.lower().replace("\\", "/").rstrip(".").split("/")
    name = parts[-1]
    return (
        ".ssh" in parts
        or name in _CREDENTIAL_NAMES
        or parts[-2:] == [".aws", "credentials"]
        or ((name == ".env" or name.startswith(".env.")) and credential_shaped(name))
    )


def instruction_marks(description: str) -> tuple[int, int, int]:
    """How often each mark occurs: an element addressed to the model, a directive to keep
    something from the user, and a reference to a credential location."""
    return (
        _model_elements(description),
        len(_CONCEALMENT.findall(description)),
        sum(_credential_location(token) for token in _PATH.findall(description)),
    )


def tool_description_risks(description: str, tool: str) -> list[RiskAssessment]:
    """The findings of one tool's description; ``tool`` is the name findings show.

    Hidden characters and comments are rated as in an instruction file. A description
    that carries at least two of the three marks is high: by shape, so never critical.
    """
    shown = f"description of tool {tool}"
    risks = [
        *detect_invisible_characters(description, shown),
        *detect_hidden_markup(description, shown),
    ]
    counts = instruction_marks(description)
    found = [
        f"{count} {names[count > 1]}" for count, names in zip(counts, _MARKS, strict=True) if count
    ]
    if len(found) >= 2:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=CATEGORY,
                detail=(
                    f"The description of tool '{neutralize(tool)}' combines "
                    f"{', '.join(found[:-1])} and {found[-1]}. A model reads a tool "
                    "description as instructions; each of these is ordinary alone, and "
                    "together they are the shape of text written to steer the model. The "
                    "text is not quoted here."
                ),
                recommendation=(
                    "Read the description where the tool is declared, remove what does not "
                    "describe the tool, and do not use the server until it is gone."
                ),
            )
        )
    return risks
