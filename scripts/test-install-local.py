#!/usr/bin/env python3
"""Isolated, no-build regression tests for the current-user release installer."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent
PUBLIC_SCRIPTS = (
    "install-local.sh",
    "setup-system-dns.sh",
    "setup-clamav.sh",
    "cleanup-system.sh",
    "install-firewall.sh",
)
PUBLIC_PACKAGING = (
    "epimetheus-blue.desktop",
    "blue-firewall.service",
    "com.epimetheus.blue.firewall.policy",
    "blue-watch.service",
    "blue-dns.service",
    "blue-guard.service",
    "blue-guard.timer",
    "blue-feeds.service",
    "blue-feeds.timer",
    "blue-net.service",
    "blue-net.timer",
    "blue-reputation.service",
    "blue-reputation.timer",
)
FILE_TOOLS = (
    "bash", "dirname", "grep", "mktemp", "cat", "chmod", "mv", "readlink",
    "ln", "mkdir", "cp", "date", "install", "sed",
)
STUB_TOOLS = (
    "systemctl", "update-desktop-database", "cargo", "sudo", "pkexec",
    "nmcli", "nft", "pacman", "setcap", "curl", "wget",
)


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def tree_bytes(root):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


class Sandbox:
    def __init__(self, base, home_name):
        self.project = base / "project"
        self.home = base / home_name
        self.tools = base / "path"
        self.log = base / "commands.jsonl"
        self.child = None
        self.bindir = self.home / ".local/bin"
        self.blue = self.bindir / "blue"
        self.appdir = self.home / ".local/share/epimetheus-blue"
        self.extension = self.appdir / "browser-extension"
        self.previous = self.appdir / "browser-extension.previous"
        self.native_host = self.bindir / "blue-native-host"
        self.dns_active = self.home / ".local/share/blue/system-dns-backup/active"
        self.new_bytes = Path("/usr/bin/true").read_bytes()
        self.old_bytes = Path("/usr/bin/sleep").read_bytes()

        # Copy only installer inputs, never a working tree, real profile or DB.
        for filename in PUBLIC_SCRIPTS:
            destination = self.project / "scripts" / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / "scripts" / filename, destination)
        for filename in PUBLIC_PACKAGING:
            destination = self.project / "packaging" / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / "packaging" / filename, destination)
        extension_id = self.project / "browser-extension/EXTENSION_ID"
        extension_id.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / "browser-extension/EXTENSION_ID", extension_id)
        self.extension_id = extension_id.read_text().strip()
        write(self.project / "browser-extension/release.txt", b"new extension one\n")
        write(self.extension / "obsolete.js", b"old extension; retain for rollback\n")
        write(self.extension / "release.txt", b"old extension\n")
        for filename in ("blue", "blue-firewall-helper"):
            destination = self.project / "target/release" / filename
            write(destination, self.new_bytes)
            destination.chmod(0o755)
        write(self.blue, self.old_bytes)
        self.blue.chmod(0o755)

        self.protected = (
            self.home / ".config/chromium/Default",
            self.home / ".config/chromium/Local State",
            self.home / ".config/BraveSoftware/Brave-Browser/Default",
            self.home / ".config/BraveSoftware/Brave-Browser/Local State",
            self.home / ".config/blue",
            self.home / ".local/share/blue",
            self.home / ".local/state/blue",
        )
        for browser in ("chromium", "BraveSoftware/Brave-Browser"):
            profile = self.home / ".config" / browser
            write(profile / "Default/Preferences", b'{"fixture":"keep preferences"}\n')
            write(profile / "Default/Extensions/keep.txt", b"existing browser extension\n")
            write(profile / "Local State", b'{"fixture":"keep local state"}\n')
        write(self.home / ".config/blue/config.toml", b"# keep user settings\n")
        write(self.home / ".local/share/blue/state.sqlite3", b"fixture state, not a real DB\n")
        write(self.home / ".local/share/blue/trust.json", b'{"fixture":"keep trust"}\n')
        write(self.home / ".local/state/blue/history.log", b"keep history\n")

        self.tools.mkdir()
        for tool in FILE_TOOLS:
            (self.tools / tool).symlink_to(Path("/usr/bin") / tool)
        stub = f"#!{sys.executable}\n" + """import json
import os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['INSTALL_TEST_LOG'], 'a') as log:
    log.write(json.dumps({'command': name, 'args': args}) + '\\n')
if name == 'systemctl' and args == ['--user', 'daemon-reload']:
    sys.exit(0)
if name == 'update-desktop-database':
    sys.exit(0)
sys.exit(97)  # Never call a real service, build, network or privilege command.
"""
        for tool in STUB_TOOLS:
            destination = self.tools / tool
            destination.write_text(stub)
            destination.chmod(0o755)
        temporary = base / "tmp"
        temporary.mkdir()
        # Do not inherit real XDG directories, D-Bus, shell hooks or credentials.
        self.env = {
            "HOME": str(self.home),
            "XDG_DATA_HOME": str(self.home / ".local/share"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".local/state"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "PATH": str(self.tools),
            "TMPDIR": str(temporary),
            "INSTALL_TEST_LOG": str(self.log),
            "LANG": "C",
            "LC_ALL": "C",
        }

    def start_old(self):
        self.old_inode = self.blue.stat().st_ino
        self.child = subprocess.Popen(
            [str(self.blue), "300"], env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def stop_old(self):
        if self.child is not None:
            try:
                if self.child.poll() is None:
                    self.child.terminate()
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)

    def install(self):
        return subprocess.run(
            ["/usr/bin/bash", str(self.project / "scripts/install-local.sh"), "--from-binary"],
            cwd=self.project, env=self.env, capture_output=True, text=True, timeout=20,
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def snapshot(self):
        snapshot = {}
        for root in self.protected:
            paths = [root] if root.is_file() or root.is_symlink() else sorted(root.rglob("*"))
            for path in paths:
                if path.is_symlink():
                    snapshot[str(path.relative_to(self.home))] = ("symlink", os.readlink(path))
                elif path.is_file():
                    metadata = path.stat()
                    snapshot[str(path.relative_to(self.home))] = (
                        "file", path.read_bytes(), stat.S_IMODE(metadata.st_mode), metadata.st_mtime_ns,
                    )
        return snapshot


@contextmanager
def sandbox(home_name="home"):
    with tempfile.TemporaryDirectory(prefix="blue-install-test-", dir="/tmp/opencode") as temporary:
        fixture = Sandbox(Path(temporary), home_name)
        try:
            yield fixture
        finally:
            fixture.stop_old()  # Reap the old executable before removing its sandbox.


@unittest.skipIf(os.geteuid() == 0, "installer must run as a non-root desktop user")
class InstallLocalTests(unittest.TestCase):
    def assert_old_alive(self, fixture):
        self.assertIsNone(fixture.child.poll())
        self.assertEqual(os.stat(f"/proc/{fixture.child.pid}/exe").st_ino, fixture.old_inode)

    def assert_safe_native_host(self, fixture):
        self.assertTrue(fixture.native_host.is_symlink())
        self.assertEqual(os.readlink(fixture.native_host), "blue")
        self.assertEqual(fixture.native_host.resolve(), fixture.blue.resolve())
        for browser in ("chromium", "BraveSoftware/Brave-Browser"):
            directory = fixture.home / ".config" / browser / "NativeMessagingHosts"
            manifest_path = directory / "com.epimetheus.blue.json"
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["name"], "com.epimetheus.blue")
            self.assertEqual(manifest["type"], "stdio")
            self.assertEqual(manifest["path"], str(fixture.native_host))
            self.assertTrue(Path(manifest["path"]).is_absolute())
            self.assertEqual(manifest["allowed_origins"], [f"chrome-extension://{fixture.extension_id}/"])
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o644)
            self.assertEqual(list(directory.glob(".com.epimetheus.blue.json.*")), [])

    def assert_only_safe_calls(self, fixture, installations=1):
        expected = [
            {"command": "systemctl", "args": ["--user", "daemon-reload"]},
            {"command": "update-desktop-database", "args": [str(fixture.home / ".local/share/applications")]},
        ] * installations
        # This excludes enable/start/restart (and all build/privilege commands),
        # even when an installer masks a stub's nonzero exit status.
        self.assertEqual(fixture.calls(), expected)

    def test_atomic_live_replacement_preserves_profiles_state_and_extension_rollback(self):
        with sandbox() as fixture:
            before = fixture.snapshot()
            old_extension = tree_bytes(fixture.extension)
            fixture.start_old()
            self.assert_old_alive(fixture)
            result = fixture.install()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_old_alive(fixture)
            self.assertNotEqual(fixture.blue.stat().st_ino, fixture.old_inode)
            self.assertEqual(fixture.blue.read_bytes(), fixture.new_bytes)
            self.assertEqual(stat.S_IMODE(fixture.blue.stat().st_mode), 0o755)
            helper = fixture.appdir / "firewall-install/target/release/blue-firewall-helper"
            self.assertEqual(helper.read_bytes(), fixture.new_bytes)
            self.assertEqual(list(fixture.bindir.glob(".blue-install.*")), [])
            self.assert_safe_native_host(fixture)
            self.assert_only_safe_calls(fixture)
            self.assertEqual(fixture.snapshot(), before)
            self.assertEqual(tree_bytes(fixture.previous), old_extension)
            self.assertFalse((fixture.extension / "obsolete.js").exists())
            installed_extension = tree_bytes(fixture.extension)

            # Reinstall accepts only the suite's existing relative native-host
            # link and retains both the last release and the older rollback copy.
            write(fixture.project / "browser-extension/release.txt", b"new extension two\n")
            result = fixture.install()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_old_alive(fixture)
            self.assertEqual(fixture.blue.read_bytes(), fixture.new_bytes)
            self.assert_safe_native_host(fixture)
            self.assert_only_safe_calls(fixture, installations=2)
            self.assertEqual(fixture.snapshot(), before)
            self.assertEqual(tree_bytes(fixture.previous), installed_extension)
            archives = list(fixture.appdir.glob("browser-extension.previous.*"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(tree_bytes(archives[0]), old_extension)
            self.assertEqual((fixture.extension / "release.txt").read_bytes(), b"new extension two\n")
            self.assertEqual(list(fixture.appdir.glob("browser-extension.new.*")), [])

    def test_native_manifest_escapes_home_path_without_broadening_origin(self):
        with sandbox('home "quoted" \\ path') as fixture:
            before = fixture.snapshot()
            result = fixture.install()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_safe_native_host(fixture)
            self.assert_only_safe_calls(fixture)
            self.assertEqual(fixture.snapshot(), before)

    def test_unrelated_native_host_paths_are_not_replaced(self):
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind), sandbox() as fixture:
                if kind == "file":
                    write(fixture.native_host, b"unrelated native host\n")
                else:
                    write(fixture.bindir / "unrelated-host", b"unrelated native host\n")
                    fixture.native_host.symlink_to("unrelated-host")
                before = fixture.snapshot()
                old_extension = tree_bytes(fixture.extension)
                fixture.start_old()
                result = fixture.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing to replace", result.stderr)
                self.assert_old_alive(fixture)
                if kind == "symlink":
                    self.assertTrue(fixture.native_host.is_symlink())
                    self.assertEqual(os.readlink(fixture.native_host), "unrelated-host")
                else:
                    self.assertFalse(fixture.native_host.is_symlink())
                self.assertEqual(fixture.native_host.read_bytes(), b"unrelated native host\n")
                self.assertEqual(fixture.snapshot(), before)
                self.assertEqual(tree_bytes(fixture.extension), old_extension)
                self.assertEqual(fixture.calls(), [])
                # Host conflict checking currently follows the atomic binary
                # swap: there is no claim that an entire installation rolls back.
                self.assertEqual(fixture.blue.read_bytes(), fixture.new_bytes)

    def test_active_dns_state_blocks_replacement_including_dangling_symlink(self):
        for kind in ("file", "dangling_symlink"):
            with self.subTest(kind=kind), sandbox() as fixture:
                fixture.dns_active.parent.mkdir(parents=True, exist_ok=True)
                if kind == "file":
                    write(fixture.dns_active, b"retain DNS rollback evidence\n")
                else:
                    fixture.dns_active.symlink_to("missing-rollback-evidence")
                before = fixture.snapshot()
                old_extension = tree_bytes(fixture.extension)
                fixture.start_old()
                result = fixture.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("system DNS routing is active", result.stderr)
                self.assert_old_alive(fixture)
                self.assertEqual(fixture.blue.stat().st_ino, fixture.old_inode)
                self.assertEqual(fixture.blue.read_bytes(), fixture.old_bytes)
                self.assertFalse(fixture.native_host.exists())
                self.assertEqual(fixture.snapshot(), before)
                self.assertEqual(tree_bytes(fixture.extension), old_extension)
                self.assertEqual(fixture.calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
