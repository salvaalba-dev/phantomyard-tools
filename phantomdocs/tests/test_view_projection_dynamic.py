import copy
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_view_projection_revalidate import inputs

from phantomdocs.view_projection_dynamic import dynamic_projection_class
from phantomdocs.view_projection_dynamic_patch import patch_projection_consumer


def test_dynamic_view_retains_approvals_and_rejects_policy_race():
    bundle, draft, policy, categories, _, org_id = inputs()
    revision = "a" * 64
    bundle["revision"] = revision
    org = {
        "organization": {"id": org_id},
        "policies": {"security_categories": categories},
    }

    class Base:
        def __init__(self):
            self.root = Path("/synthetic")
            self.org_loader = lambda: org
            self.snapshot_loader = dict

        def active(self):
            return "strict administrative approval"

    class Directory:
        def __init__(self, _org):
            self.scope = SimpleNamespace(policy={"view_access": policy})
            self.authority_revision = "current-authority"

    def read(path):
        return {"revision": revision} if path.name == "active.json" else bundle

    def fingerprint(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    review = SimpleNamespace(
        PublishedProjection=Base,
        root_path=lambda path: path,
        read_json=read,
        HEX=re.compile(r"[0-9a-f]{64}"),
        validate=lambda value: value,
        HumanDirectory=Directory,
        prepare_like=lambda *_: draft,
        ProjectionCatalog=lambda value: value,
        revision=fingerprint,
    )
    view = dynamic_projection_class(review)()
    assert view.active() == "strict administrative approval"
    assert [r["id"] for r in view._visible()[2]["resources"]] == ["old"]
    changed = copy.deepcopy(org)
    changed["organization"]["id"] = "changed"
    states = iter([org, changed])
    view.org_loader = lambda: next(states)
    with pytest.raises(ValueError, match="changed"):
        view._visible()


def test_composer_refuses_unpinned_source(monkeypatch):
    source = b"from projection_review import PublishedProjection\n"
    monkeypatch.setattr(
        "phantomdocs.view_projection_dynamic_patch._DIGESTS",
        {"reader_launch.py": hashlib.sha256(source).hexdigest()},
    )
    assert b"dynamic_projection_class" in patch_projection_consumer(
        "reader_launch.py", source
    )
    with pytest.raises(ValueError):
        patch_projection_consumer("reader_launch.py", source + b"# changed\n")
