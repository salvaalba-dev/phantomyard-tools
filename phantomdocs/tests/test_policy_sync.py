import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phantomdocs.workflow_policy_sync import synchronize


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "requires root on Linux")
class ProtectedSyncTests(unittest.TestCase):
    def test_posix_acl_survives_policy_replacement(self):
        setfacl, getfacl = shutil.which("setfacl"), shutil.which("getfacl")
        if not setfacl or not getfacl:
            self.skipTest("POSIX ACL tools are not installed")
        with tempfile.TemporaryDirectory(dir="/root") as root:
            src, dst, lock = (Path(root) / name for name in ("src", "dst", "lock"))
            lock.touch(mode=0o600)
            src.write_text("version: 1\nnew: true\n")
            dst.write_text("version: 1\nold: true\n")
            subprocess.run([setfacl, "-m", "u:65534:r--", str(dst)], check=True)
            original = subprocess.check_output([getfacl, "-cpn", str(dst)])
            synchronize(str(src), str(dst), str(lock))
            self.assertEqual(
                subprocess.check_output([getfacl, "-cpn", str(dst)]), original
            )
            self.assertEqual(dst.read_text(), "version: 1\nnew: true\n")

    def test_extended_attributes_survive_policy_replacement(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            src, dst, lock = (Path(root) / name for name in ("src", "dst", "lock"))
            lock.touch(mode=0o600)
            src.write_text("version: 1\nnew: true\n")
            dst.write_text("version: 1\nold: true\n")
            try:
                os.setxattr(dst, "user.synthetic-policy-test", b"preserved")
            except OSError as exc:
                self.skipTest(f"test filesystem does not support user xattrs: {exc}")
            synchronize(str(src), str(dst), str(lock))
            self.assertEqual(
                os.getxattr(dst, "user.synthetic-policy-test"), b"preserved"
            )
            self.assertEqual(dst.read_text(), "version: 1\nnew: true\n")

    def test_valid_update_and_rejection_preserve_permissions(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            src, dst, lock = (Path(root) / name for name in ("src", "dst", "lock"))
            lock.touch(mode=0o600)
            src.write_text("version: 1\nnew: true\n")
            dst.write_text("version: 1\nold: true\n")
            dst.chmod(0o640)
            synchronize(str(src), str(dst), str(lock))
            self.assertEqual(dst.read_text(), "version: 1\nnew: true\n")
            self.assertEqual(dst.stat().st_mode & 0o777, 0o640)
            src.write_text("version: 9\n")
            with self.assertRaises(ValueError):
                synchronize(str(src), str(dst), str(lock))
            self.assertEqual(dst.read_text(), "version: 1\nnew: true\n")

    def test_symlink_source_cannot_replace_destination(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            src, dst, lock = (Path(root) / name for name in ("src", "dst", "lock"))
            lock.touch(mode=0o600)
            dst.write_text("version: 1\nold: true\n")
            src.symlink_to(dst)
            with self.assertRaises(OSError):
                synchronize(str(src), str(dst), str(lock))
            self.assertEqual(dst.read_text(), "version: 1\nold: true\n")

    def test_destination_changed_during_validation_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            src, dst, lock = (Path(root) / name for name in ("src", "dst", "lock"))
            lock.touch(mode=0o600)
            src.write_text("version: 1\nnew: true\n")
            dst.write_text("version: 1\nold: true\n")
            real_write = os.write
            changed = []

            def race(fd, data):
                if not changed:
                    dst.write_text("version: 1\nthird: true\n")
                    changed.append(True)
                return real_write(fd, data)

            with patch("phantomdocs.workflow_policy_sync.os.write", side_effect=race):  # noqa: SIM117
                with self.assertRaisesRegex(ValueError, "changed during"):
                    synchronize(str(src), str(dst), str(lock))
            self.assertEqual(dst.read_text(), "version: 1\nthird: true\n")
