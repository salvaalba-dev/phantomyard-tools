"""Normalize meeting context using a trusted channel envelope and PhantomOrg.

Sender fields must come from the authenticated runtime envelope, never message
text. This module supplies defaults only; it does not authorize access or delivery.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

import yaml


class RequestContextError(ValueError):
    """The caller must ask the requester to resolve missing or ambiguous data."""


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1000
        or any(unicodedata.category(c).startswith("C") for c in value)
    ):
        raise RequestContextError(f"invalid {label}")
    return value.strip()


def _words(value: str) -> str:
    plain = "".join(
        c
        for c in unicodedata.normalize("NFKD", value.casefold())
        if not unicodedata.combining(c)
    )
    return " ".join(re.findall(r"[a-z0-9]+", plain))


def _rows(org: dict, section: str) -> list[dict]:
    rows = org.get(section, [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise RequestContextError(f"invalid PhantomOrg {section}")
    ids = [_text(row.get("id"), f"{section} id") for row in rows]
    if not all(ids) or len(ids) != len(set(ids)) or ids != [row["id"] for row in rows]:
        raise RequestContextError(f"ambiguous PhantomOrg {section}")
    return rows


def resolve_request(
    org: dict,
    *,
    title: str,
    requester: str = "",
    department: str = "",
    sender_channel: str = "",
    sender_id: str = "",
) -> tuple[str, str]:
    """Return requester and department; explicit fields override defaults.

    Exact department ids/names in the title and the requester's own role's
    department are defaults. Visibility scopes and supervising personas are
    never used to invent a destination. Conflicting defaults require a question.
    """
    if not isinstance(org, dict):
        raise RequestContextError("invalid PhantomOrg model")
    title = _text(title, "title")
    requester = _text(requester, "requester")
    department = _text(department, "department")
    sender_id = _text(sender_id, "sender identity")
    sender_channel = _text(sender_channel, "sender channel")
    departments = _rows(org, "departments")
    by_department = {row["id"]: row for row in departments}
    roles = {row["id"]: row for row in _rows(org, "roles")}
    humans = _rows(org, "humans")
    actors = _rows(org, "actors")
    members = humans + actors

    member = None
    if requester:
        # An explicitly different requester must not inherit the sender's scope.
        matches = [m for m in members if requester in (m["id"], m.get("name"))]
        if len(matches) > 1:
            raise RequestContextError("ambiguous requester; ask for a unique id")
        member = matches[0] if matches else None
    else:
        fields = {"telegram": "telegram_user_id", "nostr": "npub", "email": "email"}
        field = fields.get(sender_channel)
        if not field or not sender_id:
            raise RequestContextError(
                "ask for the requester: verified channel identity missing"
            )
        candidates = humans if sender_channel == "telegram" else members
        matches = [
            m
            for m in candidates
            if m.get(field) is not None
            and not isinstance(m[field], bool)
            and str(m[field]) == sender_id
        ]
        if len(matches) > 1:
            raise RequestContextError(
                "ask for the requester: channel identity is ambiguous"
            )
        if matches:
            member = matches[0]
            requester = member["id"]
        else:
            # The runtime can authenticate a human not yet registered in org.yaml.
            # Retain their qualified identity; never invent a role or department.
            formats = {
                "telegram": r"[1-9][0-9]*",
                "nostr": r"npub1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}",
                "email": r"[^\s@]+@[^\s@]+\.[^\s@]+",
            }
            if not re.fullmatch(formats[sender_channel], sender_id):
                raise RequestContextError(
                    "ask for the requester: invalid channel identity"
                )
            requester = f"{sender_channel}:{sender_id}"

    if department:
        if department not in by_department:
            raise RequestContextError(
                "unknown explicit department; ask for a valid destination"
            )
        return requester, department

    role_id = member.get("role") if member else None
    if role_id is not None:
        role_id = _text(role_id, "requester role")
    role = roles.get(role_id)
    scope = role.get("department") if role else None
    if scope is not None:
        scope = _text(scope, "role department")
    if scope is not None and scope not in by_department:
        raise RequestContextError("requester role references an unknown department")
    title_words = f" {_words(title)} "
    matches = {
        row["id"]
        for row in departments
        if any(
            alias and f" {alias} " in title_words
            for alias in (
                _words(row["id"]),
                _words(_text(row.get("name", ""), "department name")),
            )
        )
    }
    if len(matches) > 1:
        raise RequestContextError(
            "title names multiple departments; ask for the destination"
        )
    title_department = next(iter(matches), None)
    if title_department and scope and title_department != scope:
        raise RequestContextError(
            "title and requester department conflict; ask for the destination"
        )
    resolved = title_department or scope
    if not resolved:
        raise RequestContextError(
            "ask for the department: no unambiguous title or requester scope"
        )
    return requester, resolved


def main() -> int:
    """Emit two validated lines for the generated bash invitation tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True)
    for name in ("title", "requester", "department", "sender-channel", "sender-id"):
        parser.add_argument("--" + name, default="")
    args = parser.parse_args()
    try:
        org = yaml.safe_load(Path(args.org).read_text(encoding="utf-8"))
        requester, department = resolve_request(
            org,
            title=args.title,
            requester=args.requester,
            department=args.department,
            sender_channel=args.sender_channel,
            sender_id=args.sender_id,
        )
        # The bash protocol uses LF, including when tests run under Git Bash.
        fields = (_text(requester, "requester"), _text(department, "department"))
        sys.stdout.buffer.write(("\n".join(fields) + "\n").encode("utf-8"))
        return 0
    except RequestContextError as exc:
        print(f"error: meeting context unresolved: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, yaml.YAMLError):
        # Do not print raw org data, paths, or sender identifiers on failure.
        print(
            "error: meeting context unresolved; ask the requester to clarify identity or department",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
