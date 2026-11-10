"""Read one matrix through the local agent's Workspace tool, without secrets."""

import argparse
import os
import sys

from .view_matrix_drive import read_workspace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--limit", type=int, required=True)
    args = parser.parse_args()
    if os.name != "posix":
        raise SystemExit("Unix identity required")
    try:
        content = read_workspace(
            args.ref, args.limit, workspace=args.workspace, expected_uid=args.uid
        )
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()
    except (OSError, ValueError, TimeoutError):
        raise SystemExit("matrix unavailable") from None


if __name__ == "__main__":
    main()
