import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "contrib/matrix-overlay"
spec = importlib.util.spec_from_file_location("matrix_launcher", HERE / "launcher.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, "protected", lambda *args, **kwargs: None)
    monkeypatch.setattr(launcher, "protected_package", lambda *args: None)
    monkeypatch.setattr(launcher, "protected_config", lambda *args: None)
    monkeypatch.setattr(launcher, "protected_file", lambda meta: True)
    monkeypatch.setattr(launcher, "isolated_python", lambda: True)
    base = tmp_path / "runtime"
    package = base / "phantomdocs"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    host = b"baseline host\n"
    guard = b'VALUE = "old guard"\n'
    payload = (
        b"from . import workflow_policy_guard\n"
        b"def main():\n"
        b'    assert workflow_policy_guard.VALUE == "old guard"\n'
        b"    raise SystemExit(23)\n"
    )
    (package / "view_matrix_host.py").write_bytes(host)
    (package / "workflow_policy_guard.py").write_bytes(guard)
    source = tmp_path / "overlay.py"
    source.write_bytes(payload)
    monkeypatch.setattr(sys, "prefix", str(base))
    monkeypatch.syspath_prepend(str(base))
    for key in list(sys.modules):
        if key == "phantomdocs" or key.startswith("phantomdocs."):
            monkeypatch.delitem(sys.modules, key, raising=False)
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    config = tmp_path / "config"
    config.touch(mode=0o600)
    config.chmod(0o600)
    return (
        base,
        package,
        source,
        str(config),
        digest(host),
        digest(guard),
        digest(payload),
    )


def test_executes_overlay_with_original_package_and_guard(runtime):
    with pytest.raises(SystemExit) as result:
        launcher.run(*runtime)
    assert result.value.code == 23
    assert (
        Path(sys.modules["phantomdocs.workflow_policy_guard"].__file__)
        == runtime[1] / "workflow_policy_guard.py"
    )


@pytest.mark.parametrize("index", [4, 5, 6])
def test_rejects_hash_mismatch_before_loading_package(runtime, index):
    args = list(runtime)
    args[index] = "0" * 64
    with pytest.raises(ValueError, match="integrity"):
        launcher.run(*args)
    assert "phantomdocs" not in sys.modules


def test_rejects_wrong_interpreter(runtime, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "wrong"))
    with pytest.raises(ValueError, match="interpreter"):
        launcher.run(*runtime)


def test_payload_and_launcher_pin_match_current_source():
    source = HERE.parents[1] / "src/phantomdocs/view_matrix_host.py"
    assert (HERE / "view_matrix_host.py").read_bytes() == source.read_bytes()
    assert digest(source.read_bytes()) == launcher.PAYLOAD_SHA256
