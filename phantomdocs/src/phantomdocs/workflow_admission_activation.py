"""Experimental systemd socket activation for local admission and search.

This host does not process requests, register documents, move Drive objects,
or configure policy synchronization. It must not be deployed until every
writer of the active policy cooperates with its lock and the end-to-end trust
boundaries have been verified on Linux.
"""

import argparse
import os
import socket
import stat
import sys

from phantomdocs.workflow_admission_config import load_config
from phantomdocs.workflow_admission_service import serve_configured_once
from phantomdocs.workflow_protected_paths import protected_parent


def validated_systemd_socket(expected_path, *, environ=None):
    """Duplicate systemd's sole Unix listener after checking its identity."""
    if sys.platform != "linux":
        raise ValueError("socket activation requires Linux")
    env = os.environ if environ is None else environ
    if env.get("LISTEN_PID") != str(os.getpid()) or env.get("LISTEN_FDS") != "1":
        raise ValueError("one systemd-activated listener is required")
    with protected_parent(expected_path) as (directory, name):
        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(entry.st_mode)
            or entry.st_uid != 0
            or entry.st_mode & 0o002
        ):
            raise ValueError("activation socket is not protected")
    listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (
            listener.family != socket.AF_UNIX
            or listener.type & 0xF != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or listener.getsockname() != expected_path
        ):
            raise ValueError("unexpected activation listener")
        return listener
    except BaseException:
        listener.close()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    path = config["socket_path"]
    with validated_systemd_socket(path) as listener:
        while True:
            serve_configured_once(listener, args.config, expected_socket=path)


if __name__ == "__main__":
    main()
