"""Compose the matrix route into one explicitly pinned PhantomView revision."""

import ast
import hashlib

SOURCE_SHA256 = "ecbe853eb1b14bc0da8a3dfdd879461daabbcad9c24fa9d951b8a534e3e69ef4"
ANCHOR = "        elif method == 'GET' and parsed.path.startswith('/api/resource/'):\n"


def patch_http(source):
    """Return inactive candidate bytes; never alter the installed reader."""
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
    ):
        raise ValueError("unsupported reader revision")
    text = source.decode("utf-8")
    if text.count(ANCHOR) != 1:
        raise ValueError("reader composition changed")
    text = text.replace(
        ANCHOR,
        "        elif method == 'GET' and parsed.path.startswith('/api/matrix/'):\n"
        "            from phantomdocs.view_matrix_http import dispatch as matrix_dispatch\n"
        "            matrix_dispatch(handler, backend, parsed.path)\n" + ANCHOR,
        1,
    )
    ast.parse(text)
    return text.encode("utf-8")
