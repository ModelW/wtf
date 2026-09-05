"""Process exit codes for ``compliance check``.

The codes form a contract with CI: a pipeline can branch on the numeric
value (e.g. tolerate ``STALE_ATTESTATION`` on a nightly job but fail on
``FINDINGS``), so they are frozen here rather than scattered as literals.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit status of ``compliance check``, from best to worst."""

    CLEAN = 0
    """Everything declared, no open findings."""

    FINDINGS = 1
    """Open findings or gate failures. Not reachable yet (later milestone)."""

    STALE_ATTESTATION = 2
    """An attestation is out of date. Not reachable yet (later milestone)."""

    DECLARATION_ERROR = 3
    """The declarations themselves are wrong: missing/malformed manifest,
    image without a compliance folder under ``--strict``, nothing declared
    under ``--strict``, ..."""

    TOOL_ERROR = 4
    """model-wtf itself crashed; the result says nothing about the repo."""
