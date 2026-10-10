import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_privacy.py"


@pytest.mark.parametrize(
    "name",
    [
        "design/private.txt",
        "config/context.json",
        "specs/003-feature/closeout.json",
        "docs/adr/closeout.md",
        "config/manifest.json",
        ".local/validation/run.json",
        "specs/002-feature/report.json",
        "config/review-00000000-0000-4000-8000-000000000002.json",
        "specs/002-feature/source-00000000-0000-4000-8000-000000000002.raw",
        ".env.local",
        "specs/001-feature/evidence/private.json",
        "notes.md",
        "chat/app.py",
        "chat/static/index.html",
    ],
)
def test_private_or_non_harness_files_rejected_even_when_force_added(tmp_path, name):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("private local material")
    subprocess.run(["git", "add", "-f", name], cwd=tmp_path, check=True, capture_output=True)
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True)
    assert result.returncode != 0
    assert name.encode() in result.stderr


@pytest.mark.parametrize(
    "name",
    [
        "src/agent/main.py",
        "specs/001-feature/spec.md",
        "docs/adr/0001-decision.md",
        ".specify/memory/constitution.md",
    ],
)
def test_staged_credential_detected_after_worktree_cleaned(tmp_path, name):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    credential = "private-credential-sentinel-value"
    (tmp_path / ".env.local").write_text("VERIFY_CLIENT_SECRET=" + credential)
    target = tmp_path / name
    target.parent.mkdir(parents=True)
    target.write_text("VALUE = '" + credential + "'")
    subprocess.run(["git", "add", name], cwd=tmp_path, check=True, capture_output=True)
    target.write_text("VALUE = None")
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True)
    assert result.returncode != 0
    assert credential.encode() not in result.stderr


@pytest.mark.parametrize(
    "copied",
    [
        "postgresql://admin:private%40database%3Apassword@db.example.invalid:5432/postgres",
        "private@database:password",
        "db.example.invalid",
    ],
)
def test_database_uri_and_decoded_components_rejected(tmp_path, copied):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    uri = "postgresql://admin:private%40database%3Apassword@db.example.invalid:5432/postgres"
    (tmp_path / ".env.local").write_text("SUPABASE_DB_URI=" + uri)
    (tmp_path / "README.md").write_text(copied)
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True, capture_output=True)
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True)
    assert result.returncode != 0
    assert copied.encode() not in result.stderr


def test_chat_frontend_is_forbidden_in_distribution_paths():
    import importlib.util

    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec = importlib.util.spec_from_file_location("privacy_guard", SCRIPT)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        assert guard.forbidden("PoCdantic-0.1.0/chat/app.py")
        assert guard.forbidden("chat/static/index.html")
        assert guard.forbidden("PoCdantic-0.1.0/specs/002-feature/report.json")
        assert guard.forbidden("agent/validation/review-00000000-0000-4000-8000-000000000002.json")
    finally:
        sys.path.pop(0)


@pytest.mark.parametrize("name", ["index.html", "app.js", "style.css"])
def test_workspace_assets_have_exact_publication_allowlist(name):
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        from publish_policy import publishable

        assert publishable("src/agent/workspace/static/" + name)
        assert not publishable("src/agent/workspace/static/storage.json")
        assert not publishable("src/agent/workspace/static/extra.html")
        assert not publishable("src/agent/workspace/static/trace.zip")
    finally:
        sys.path.pop(0)
