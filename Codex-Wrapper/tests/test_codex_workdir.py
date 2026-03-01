from pathlib import Path

from app import codex


def test_codex_workdir_fallback_when_not_writable(monkeypatch, tmp_path):
    """Fallback to a writable directory when configured workdir lacks permissions."""

    requested = tmp_path / "readonly"
    requested.mkdir()

    original_verify = codex._verify_directory_write_access

    def fake_verify(directory: Path) -> None:
        if directory == requested:
            raise PermissionError("read-only")
        original_verify(directory)

    monkeypatch.setattr(
        codex, "_verify_directory_write_access", fake_verify, raising=False
    )
    monkeypatch.setattr(
        codex.settings, "codex_workdir", str(requested), raising=False
    )
    monkeypatch.setattr(codex, "_WORKDIR_PATH", None, raising=False)
    monkeypatch.setattr(codex, "_WORKDIR_NEEDS_SKIP_GIT_CHECK", False, raising=False)

    codex._ensure_workdir_exists()

    resolved = Path(codex.settings.codex_workdir)
    assert resolved != requested
    assert codex._WORKDIR_PATH == resolved
    probe = resolved / "fallback-probe.txt"
    with open(probe, "w", encoding="utf-8") as handle:
        handle.write("ok")
    probe.unlink()


def test_skip_git_repo_flag_added_when_workdir_not_repo(monkeypatch, tmp_path):
    """Ensure CLI command opts out of Git repo check if workdir lacks .git."""

    requested = tmp_path / "readonly"
    requested.mkdir()
    fallback_root = tmp_path / "fallback"
    fallback_root.mkdir()

    original_verify = codex._verify_directory_write_access

    def fake_verify(directory: Path) -> None:
        if directory == requested:
            raise PermissionError("read-only")
        original_verify(directory)

    monkeypatch.setattr(
        codex, "_verify_directory_write_access", fake_verify, raising=False
    )
    monkeypatch.setattr(codex, "_resolve_codex_executable", lambda: "codex-bin")
    monkeypatch.setattr(
        codex.settings, "codex_workdir", str(requested), raising=False
    )
    monkeypatch.setattr(codex, "_WORKDIR_PATH", None, raising=False)
    monkeypatch.setattr(codex, "_WORKDIR_NEEDS_SKIP_GIT_CHECK", False, raising=False)
    monkeypatch.setattr(
        codex.tempfile, "gettempdir", lambda: str(fallback_root), raising=False
    )

    cmd = codex._build_cmd_and_env("prompt")

    resolved = Path(codex.settings.codex_workdir)
    assert resolved.is_dir()
    assert "--skip-git-repo-check" in cmd


def test_codex_home_fallback_when_default_not_writable(monkeypatch, tmp_path):
    """Fallback to a writable CODEX_HOME when default locations are read-only."""

    default_home = tmp_path / "default-home"
    default_home.mkdir()
    workspace_home = tmp_path / "workspace-home"
    workspace_home.mkdir()
    fallback_root = tmp_path / "fallback-root"
    fallback_root.mkdir()

    original_verify = codex._verify_directory_write_access

    def fake_verify(directory: Path) -> None:
        if directory in (default_home, workspace_home / ".codex"):
            raise PermissionError("read-only")
        original_verify(directory)

    monkeypatch.setenv("CODEX_HOME", str(default_home))
    monkeypatch.setattr(codex.settings, "codex_config_dir", None, raising=False)
    monkeypatch.setattr(codex.settings, "codex_workdir", str(workspace_home), raising=False)
    monkeypatch.setattr(codex.tempfile, "gettempdir", lambda: str(fallback_root), raising=False)
    monkeypatch.setattr(codex, "_verify_directory_write_access", fake_verify, raising=False)

    env = codex._build_codex_env()

    expected_home = fallback_root / "codex"
    assert env["CODEX_HOME"] == str(expected_home)
    assert codex.settings.codex_config_dir == str(expected_home)
