"""Compose dynamic read-only projection loading into pinned viewer sources."""

import ast
import hashlib

_DIGESTS = {
    "reader_launch.py": "23b2c4b45ea25c3b8979b3708201443d8476e23192e32c9f613aeb13d599469f",
    "identified_reader.py": "a91a3a20627010dce7ecba5b885337f06b0f3ccab06e9ba60796ba0cd67231f8",
}
_OLD = "from projection_review import PublishedProjection\n"
_NEW = (
    "import projection_review as _projection_review\n"
    "from phantomdocs.view_projection_dynamic import dynamic_projection_class\n"
    "PublishedProjection = dynamic_projection_class(_projection_review)\n"
)


def patch_projection_consumer(name, source):
    """Return candidate bytes only for reviewed exact consumer revisions."""
    if (
        name not in _DIGESTS
        or not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != _DIGESTS[name]
    ):
        raise ValueError("Unsupported viewer source revision")
    text = source.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")
    if normalized.count(_OLD) != 1:
        raise ValueError("Viewer projection import changed")
    candidate = normalized.replace(_OLD, _NEW, 1)
    ast.parse(candidate)
    return candidate.replace("\n", newline).encode("utf-8")
