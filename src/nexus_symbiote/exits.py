"""Process exit codes shared by every nexus-symbiote command.

====  ==============================================================
Exit  Meaning
====  ==============================================================
0     Complete for the requested scope and within policy
1     Usage, configuration, input or output failure; no usable result
2     Complete evidence, but a policy gate or a verification failed
3     Incomplete collection or observation, or a live step refused
      because offline mode is in effect
====  ==============================================================
"""

from __future__ import annotations

import click

OK = 0
FAILURE = 1
GATE = 2
INCOMPLETE = 3


class GateFailed(click.ClickException):
    """Complete evidence that does not satisfy a gate or a verification."""

    exit_code = GATE


class Incomplete(click.ClickException):
    """Collection or observation that did not complete, or was refused offline."""

    exit_code = INCOMPLETE
