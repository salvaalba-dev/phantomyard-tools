"""Complete English PhantomOrg model used only in synthetic publication tests."""

from pathlib import Path

import yaml


def model():
    path = (
        Path(__file__).resolve().parents[2]
        / "phantomorg/tests/fixtures/source-publication-org.yaml"
    )
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def snapshots():
    before = model()
    after = model()
    after["actors"][0]["actor_exceptions"] = []
    return yaml.safe_dump(before).encode(), yaml.safe_dump(after).encode()
