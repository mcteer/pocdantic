"""Private regression storage must refuse unsafe permissions and immutable overwrites."""

from uuid import uuid4

import pytest

from scripts.security_regression.models import RegressionError
from scripts.security_regression.store import Store


def test_immutable_and_busy(tmp_path):
    """A second reader cannot acquire a live run or overwrite its first artifact."""
    store = Store(tmp_path)
    run = str(uuid4())
    with store.create(run) as writer:
        writer.write("manifest.json", {"sentinel": 1})
        with pytest.raises(RegressionError, match="run_busy"):
            with store.open(run):
                pass
        with pytest.raises(RegressionError):
            writer.write("manifest.json", {})


@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_existing_root_is_not_repaired(tmp_path, mode):
    """An unsafe directory must be rejected before inherited helpers chmod it."""
    root = tmp_path / ".local"
    root.mkdir(mode=mode)
    root.chmod(mode)
    with pytest.raises(RegressionError, match="unsafe_path"):
        Store(tmp_path)
    assert root.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize("damage", ["mode", "symlink", "hardlink", "inode", "traversal"])
def test_file_and_directory_identities(tmp_path, damage):
    """Unsafe entry types and directory replacement are rejected without repairing them."""
    import os

    store = Store(tmp_path)
    identifier = str(uuid4())
    with store.create(identifier) as writer:
        writer.write("record.json", {"synthetic": 1})
        path = writer.path / "record.json"
        if damage == "mode":
            path.chmod(0o644)
        elif damage == "symlink":
            path.unlink()
            path.symlink_to(tmp_path / "missing")
        elif damage == "hardlink":
            os.link(path, writer.path / "copy.json")
        elif damage == "inode":
            old = writer.path.with_name(str(uuid4()))
            writer.path.rename(old)
            writer.path.mkdir(mode=0o700)
        with pytest.raises(RegressionError, match="unsafe_path"):
            writer.read("../record.json" if damage == "traversal" else "record.json")
