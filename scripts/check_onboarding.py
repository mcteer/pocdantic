#!/usr/bin/env python3
"""Fixed synthetic onboarding checks with bounded child ownership and sanitized output.

No supplied command, live deployment setting or provider effect is admitted. Installed
mode checks the actual artifact import location and never installs or downloads packages.
"""

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "offline": ("tests/test_offline_entrypoints.py",),
    "guided": (
        "tests/test_setup_recipes.py",
        "tests/test_setup_guidance.py",
        "tests/test_project_boundary.py",
        "tests/test_model_configuration.py",
        "tests/test_setup_walkthrough.py",
        "tests/test_setup_commands.py",
    ),
}


def parser() -> argparse.ArgumentParser:
    """Admit only three reviewed cases; callers cannot supply executable text."""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--case", choices=("offline", "guided", "installed"), required=True)
    return result


def run_child(arguments: list[str], *, cwd: Path, env: dict[str, str], deadline: float) -> int:
    """Own a fixed child process group until completion or bounded termination/drain.

    Output is discarded, never persisted or dumped on failure. Cancellation and timeout
    terminate the entire group so nested entry points cannot outlive their check owner.
    """
    child = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        return child.wait(timeout=max(0.001, deadline - time.monotonic()))
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        raise


INSTALLED_PROBE = r"""
from pathlib import Path
from agent.settings import Settings
from agent.model_config import descriptor, selected_model
from agent.setup.guidance import guide
from agent.setup.prerequisites import package_present
for provider, prefix, package, key in (
    ('google', 'google-gla', 'google.genai', 'GOOGLE_API_KEY'),
    ('openai', 'openai-chat', 'openai', 'OPENAI_API_KEY'),
    ('openai', 'openai-responses', 'openai', 'OPENAI_API_KEY'),
    ('anthropic', 'anthropic', 'anthropic', 'ANTHROPIC_API_KEY'),
):
    path = Path('.env.local')
    path.write_text('MODEL=' + prefix + ':synthetic\n' + key + '=synthetic-canary\n')
    settings = Settings()
    assert getattr(settings, key.lower()).get_secret_value() == 'synthetic-canary'
    assert 'synthetic-canary' not in repr(settings)
    result = guide(settings, project=Path.cwd())
    assert result.exit_code == 2 and result.state == 'needs-input'
    assert 'synthetic-canary' not in result.model_dump_json()
    if package_present(package):
        assert selected_model(settings).model_name == 'synthetic'
    else:
        names = {name for finding in result.findings for name in finding.setting_names}
        assert provider.upper() + '_EXTRA' in names
    path.unlink()
assert not Path('.local').exists()
import json
import subprocess
import sys
repo = Path('root-fixture')
repo.mkdir()
subprocess.run(['git', 'init', '-q', str(repo)], check=True, timeout=5)
nested = repo / 'nested'
nested.mkdir()
(nested / '.env.local').write_text('TIMEOUT_SECONDS=synthetic-private-canary\n')
result = subprocess.run(
    [str(Path(sys.executable).parent / 'agent'), 'setup', 'guide',
     '--recipe', 'workspace-read', '--format', 'json'],
    cwd=nested, capture_output=True, text=True, timeout=30,
)
assert result.returncode == 2 and len(result.stdout.encode()) <= 32768
report = json.loads(result.stdout)
assert report['findings'][0]['id'] == 'root-invalid'
assert 'synthetic-private-canary' not in result.stdout + result.stderr
assert not (repo / '.local').exists() and not (nested / '.local').exists()
"""


def installed(env: dict[str, str], temporary: Path, deadline: float) -> int:
    """Prove installed imports/resources and aliases from outside source and PYTHONPATH."""
    from importlib.resources import files
    from shutil import which

    if which("git") is None:
        return 2
    import agent

    location = Path(agent.__file__).resolve()
    if location.is_relative_to(ROOT / "src"):
        return 2
    for resource in (
        "default_agents.json",
        "validation/default_suites.json",
        "workspace/static/app.js",
    ):
        if not files("agent").joinpath(resource).is_file():
            return 1
    import zipfile

    # Install verification is performed on the artifact environment, not editable source.
    if zipfile.is_zipfile(location):
        return 2
    for alias in ("agent", "pocdantic"):
        executable = Path(sys.executable).parent / alias
        for arguments in (
            ["--help"],
            ["demo"],
            ["setup", "guide", "--recipe", "offline", "--format", "json"],
            ["setup", "check", "--recipe", "offline"],
        ):
            if run_child(
                [str(executable), *arguments],
                cwd=temporary,
                env=env,
                deadline=min(deadline, time.monotonic() + 30),
            ):
                return 1
    return (
        0
        if run_child(
            [sys.executable, "-c", INSTALLED_PROBE], cwd=temporary, env=env, deadline=deadline
        )
        == 0
        else 1
    )


def main() -> int:
    """Run a fixed case; exits distinguish software pass/failure/unavailable/interruption."""
    args = parser().parse_args()
    deadline = time.monotonic() + 180
    # Remove ambient deployment inputs while retaining interpreter/tool discovery.
    allowed = ("PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL", "UV_CACHE_DIR")
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    code = 1
    try:
        with tempfile.TemporaryDirectory(prefix="onboarding-") as directory:
            temporary = Path(directory)
            guard = temporary / "guard"
            guard.mkdir()
            (guard / "sitecustomize.py").write_text(
                "import socket\n"
                'def denied(*args, **kwargs):\n    raise RuntimeError("network_denied")\n'
                "socket.socket.connect = denied\nsocket.create_connection = denied\n"
            )
            env["PYTHONPATH"] = str(guard)
            if args.case == "installed":
                code = installed(env, temporary, deadline)
            elif importlib.util.find_spec("pytest") is None:
                code = 2
            else:
                code = run_child(
                    [sys.executable, "-m", "pytest", "-q", *CASES[args.case]],
                    cwd=ROOT,
                    env=env,
                    deadline=deadline,
                )
                code = 0 if code == 0 else 1
    except KeyboardInterrupt:
        code = 130
    except ImportError:
        code = 2
    except (OSError, subprocess.TimeoutExpired):
        code = 1
    print(json.dumps({"case": args.case, "scope": "synthetic", "exit_code": code}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
