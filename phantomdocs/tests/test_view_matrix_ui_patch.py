import hashlib

import pytest

from phantomdocs import view_matrix_ui_patch as patcher


def test_pinned_ui_adds_escaped_matrix_view(monkeypatch):
    source = (patcher.ANCHOR + patcher.NOTICE + "\n" + patcher.SCRIPT_ANCHOR).encode()
    monkeypatch.setattr(patcher, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    result = patcher.patch_ui(source)
    assert b"/api/matrix/current" in result
    assert b"pre.textContent=data.content" in result
    with pytest.raises(ValueError):
        patcher.patch_ui(source + b"different")
