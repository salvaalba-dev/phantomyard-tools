"""
Loads an org.yaml, validates its shape (shape_validator, section 5.2 of
the spec) and returns a typed OrgSpec (model.OrgSpec.from_dict).

The *business* validation (cycles in escalation_matrix, cross-references,
size budgets) lives in phantomorg.validator, not here: this module only
guarantees "this is a well-formed org.yaml".
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import OrgSpec
from .shape_validator import ShapeError, validate_shape


class OrgSpecError(Exception):
    """Load or shape-validation error of org.yaml."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    PyYAML's default behavior keeps the *last* value of a duplicated key
    silently — for a hand-edited org.yaml that is silent spec data loss
    (e.g. a pasted duplicate ``roles:`` block drops the first one).
    """

    def construct_mapping(self, node, deep=False):
        mapping = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping.add(key)
        return super().construct_mapping(node, deep=deep)


def load_org_yaml(path: str | Path) -> OrgSpec:
    """Load a UTF-8 model without accepting ambiguous mapping keys."""
    try:
        payload = Path(path).read_bytes()
    except OSError as error:
        raise OrgSpecError(f"org.yaml could not be read/parsed: {error}") from error
    return load_org_bytes(payload)


def load_org_bytes(payload: bytes) -> OrgSpec:
    """Parse an exact UTF-8 snapshot; do not reopen a mutable candidate path."""
    if not isinstance(payload, bytes):
        raise TypeError("organization payload must be bytes")
    try:
        raw = yaml.load(payload.decode("utf-8"), Loader=_UniqueKeyLoader)  # nosec B506
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError) as error:
        raise OrgSpecError(f"org.yaml could not be read/parsed: {error}") from error
    try:
        validate_shape(raw)
    except ShapeError as error:
        raise OrgSpecError(
            f"org.yaml does not conform to the expected shape: {error}"
        ) from error
    try:
        return OrgSpec.from_dict(raw)
    except Exception as error:
        raise OrgSpecError(f"org.yaml could not be typed: {error}") from error
