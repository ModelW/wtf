"""Identifier conventions shared by every kind of compliance file.

Ids are never written inside files: the file name *is* the id. Element
ids are the one case where the stable id (``http:POST:/back/api/me/``)
contains characters that are unsafe or ambiguous in a file name, so they
are projected onto a dotted, path-safe form.
"""

from __future__ import annotations

import re

_SEPARATORS = re.compile(r"[:/]+")


def element_path_id(stable_id: str) -> str:
    """Project a stable element id onto its file-name form.

    ``http:POST:/back/api/me/`` becomes ``http.POST.back.api.me``: every
    run of ``:`` or ``/`` is a separator, leading/trailing separators are
    dropped. The projection is lossy on purpose (a dotted id is still
    readable by a human browsing the folder); callers that need the
    stable id read it from the element's ``.gen.yaml`` facts.
    """
    return ".".join(part for part in _SEPARATORS.split(stable_id) if part)


def id_from_path(file_name: str) -> str:
    """Strip the ``.yaml`` / ``.gen.yaml`` suffix to get the declared id."""
    if file_name.endswith(".gen.yaml"):
        return file_name[: -len(".gen.yaml")]
    if file_name.endswith(".yaml"):
        return file_name[: -len(".yaml")]
    return file_name


def split_checkpoint(checkpoint: str) -> tuple[str, str]:
    """Split ``RULE@element-stable-id`` into ``(rule, element)``.

    Raises
    ------
    ValueError
        When there is no ``@`` or one side is empty.
    """
    rule, sep, element = checkpoint.partition("@")
    if not sep or not rule or not element:
        msg = f"checkpoint must look like RULE@element, got {checkpoint!r}"
        raise ValueError(msg)
    return rule, element
