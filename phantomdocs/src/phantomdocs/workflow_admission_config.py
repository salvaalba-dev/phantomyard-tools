"""Experimental root-controlled configuration for the local admission host.

This file does not activate a service. Deployment must protect the listener,
private ledger and all policy writers before it can be considered for use.
"""

import json
import os

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

import yaml

from phantomdocs.access import validate_org_schema
from phantomdocs.workflow_protected_paths import open_protected_file, protected_parent
from phantomdocs.workflows import validate_contract

MAX_BYTES = 4 * 1024 * 1024
_PATHS = {
    "identity_map",
    "ledger_path",
    "policy_lock",
    "org_path",
    "installation_path",
    "socket_path",
    "store_path",
}
_FIELDS = _PATHS | {"processor_config_path", "processor_state_path", "server_uid"}


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate organization field")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration field")
        result[key] = value
    return result


def _read_protected(path):
    """Read bounded content from an existing root-owned, protected file."""
    with protected_parent(path) as (directory, name):
        fd = open_protected_file(directory, name)
        try:
            before = os.fstat(fd)
            with os.fdopen(fd, "rb", closefd=False) as source:
                payload = source.read(MAX_BYTES + 1)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        not payload
        or len(payload) > MAX_BYTES
        or tuple(getattr(before, x) for x in fields)
        != tuple(getattr(after, x) for x in fields)
    ):
        raise ValueError("invalid or changed protected file")
    return payload


def _json(path):
    try:
        return json.loads(
            _read_protected(path).decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid protected JSON") from exc


def load_config(path):
    value = _json(path)
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("invalid admission configuration")
    if type(value["server_uid"]) is not int or value["server_uid"] < 0:
        raise ValueError("invalid server identity")
    _fields = _PATHS | {
        field
        for field in ("processor_config_path", "processor_state_path")
        if value[field] is not None
    }
    if (
        value["processor_state_path"] is not None
        and value["processor_config_path"] is None
    ):
        raise ValueError("processor state requires a processor config")
    for field in _fields:
        candidate = value[field]
        if (
            not isinstance(candidate, str)
            or not candidate.startswith("/")
            or "\x00" in candidate
            or any(part in ("", ".", "..") for part in candidate[1:].split("/"))
        ):
            raise ValueError("unsafe admission path")
    return value


def load_processor(config_path, state_path):
    """Use the same precedence and source labels as the native resolver."""
    actor = None
    if state_path is not None:
        state = _json(state_path)
        if not isinstance(state, dict):
            raise ValueError("invalid processor state")
        if "default_persona" in state:
            actor = state["default_persona"]
            if not isinstance(actor, str) or not actor.strip():
                raise ValueError("invalid processor state default persona")
            return actor, "phantombot-state"
    try:
        config = tomllib.loads(_read_protected(config_path).decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("invalid processor configuration") from exc
    actor = config.get("default_persona")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("default processor is missing or invalid")
    return actor, "phantombot-config"


def load_installation(path):
    value = _json(path)
    validate_contract(value, "installation")
    return value


def load_policy(path):
    try:
        loader = _UniqueLoader(_read_protected(path))
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(value, dict):
            raise TypeError("invalid organization")
        validate_org_schema(value)
        return value
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("invalid protected organization") from exc
