"""Explicit order configuration must survive validation and regeneration."""

from pathlib import Path

import pytest
import yaml

from phantommeet.apply import _persona_context, apply_manifest
from phantommeet.manifest import ManifestError, load_manifest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example-org.yaml"


@pytest.mark.parametrize("writer", [None, "writer --flag", [], [""], [42], ["a\nb"]])
def test_invalid_adapter_rejected(tmp_path: Path, writer: object) -> None:
    manifest = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    manifest["invite"]["order_writer"] = writer
    source = tmp_path / "manifest.yaml"
    source.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    with pytest.raises(ManifestError, match="order_writer"):
        load_manifest(source)


@pytest.mark.parametrize("language", ["en", "es"])
def test_reapply_preserves_adapter_and_owned_sections(
    tmp_path: Path, language: str
) -> None:
    manifest = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    manifest["language"] = language
    manifest["invite"]["order_writer"] = ["python3", "/opt/example/meeting-order.py"]
    source = tmp_path / "manifest.yaml"
    source.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    target = tmp_path / "personas"
    for persona in manifest["roles"]:
        (target / persona).mkdir(parents=True)
    assert not apply_manifest(source, target).errors
    tool = target / "maria" / "tools" / "meeting-invite.sh"
    before = tool.read_bytes()
    kb = target / "maria" / "kb" / "procedures" / "Meetings.md"
    with kb.open("a", encoding="utf-8") as stream:
        stream.write("\nOperator-owned note.\n")
    assert not apply_manifest(source, target).errors
    assert tool.read_bytes() == before
    assert "ORDER_WRITER=(python3 /opt/example/meeting-order.py )" in tool.read_text(
        encoding="utf-8"
    )
    assert "Operator-owned note." in kb.read_text(encoding="utf-8")
    assert "--department" in kb.read_text(encoding="utf-8")
    assert (
        _persona_context("maria", load_manifest(source))["invite"]["order_writer"]
        == manifest["invite"]["order_writer"]
    )
