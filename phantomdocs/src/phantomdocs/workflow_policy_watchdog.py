"""Report source/copy drift without publishing or repairing policy files."""

import argparse
import hashlib
import json

from .workflow_bridge_policy import _read_policy
from .workflow_policy_commit import inspect_committed_locked, receipt
from .workflow_policy_fanout import destinations
from .workflow_policy_guard import policy_guard


def check(*, source, destination, lock_path, require_committed=False):
    """MD5 is a drift indicator only; it is never an authorization digest."""
    paths = destinations(source, destination, lock_path)
    with policy_guard(lock_path, exclusive=False):
        payload = _read_policy(source)
        expected = hashlib.md5(payload, usedforsecurity=False).hexdigest()
        copies = [
            {
                "destination": path,
                "md5": hashlib.md5(
                    _read_policy(path), usedforsecurity=False
                ).hexdigest(),
            }
            for path in paths
        ]
        if _read_policy(source) != payload:
            raise ValueError("source changed during drift check")
        for item in copies:
            item["matches"] = item["md5"] == expected
        committed_matches = not require_committed or inspect_committed_locked(
            lock_path, source
        ) == receipt(source, payload)
        return {
            "status": "ok"
            if committed_matches and all(c["matches"] for c in copies)
            else "drift",
            **({"committed_matches": committed_matches} if require_committed else {}),
            "source_md5": expected,
            "destinations": copies,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True, action="append")
    parser.add_argument("--policy-lock", required=True)
    args = parser.parse_args()
    try:
        result = check(
            source=args.source, destination=args.destination, lock_path=args.policy_lock
        )
    except (OSError, ValueError, RuntimeError):
        print(json.dumps({"status": "unavailable"}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
