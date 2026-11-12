"""Offline integration tests: no requests leave the test fixture."""
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        tools = self.root / "tools"
        tools.mkdir()
        # Only the downloader is replaced. Hashing, extraction and installation
        # run through the real host tools against a synthetic release archive.
        curl = tools / "curl"
        curl.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, shutil, sys\n"
            "args=sys.argv[1:]\n"
            "url=next(x for x in args if x.startswith('https://'))\n"
            "assert url.startswith('https://github.com/example/masktext/releases/')\n"
            "shutil.copyfile(pathlib.Path(os.environ['FIXTURES'])/url.rsplit('/',1)[1], args[args.index('-o')+1])\n"
        )
        curl.chmod(0o755)
        machine = platform.machine()
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
        system = "darwin" if platform.system() == "Darwin" else "linux"
        name = f"masktext_{system}_{arch}.tar.gz"
        archive = self.root / name
        content = b"#!/bin/sh\nprintf 'fixture-version\\n'\n"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("masktext")
            info.mode = 0o755
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        self.sums = self.root / "SHA256SUMS"
        self.sums.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {name}\n")
        self.dest = self.root / "destination with spaces"
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                        FIXTURES=str(self.root), MASKTEXT_INSTALL_DIR=str(self.dest))

    def install(self, *args):
        return subprocess.run(["sh", str(INSTALLER), *args], env=self.env,
                              text=True, capture_output=True)

    def test_install_and_upgrade(self):
        for _ in range(2):
            result = self.install("example/masktext", "v0.1.0")
            self.assertEqual(result.returncode, 0, result.stderr)
            binary = self.dest / "masktext"
            self.assertEqual(subprocess.check_output([binary], text=True), "fixture-version\n")
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            self.assertFalse(list(self.dest.glob(".masktext-install.*")))

    def test_bad_checksum_keeps_existing_binary(self):
        self.dest.mkdir()
        binary = self.dest / "masktext"
        binary.write_text("original")
        self.sums.write_text(self.sums.read_text().replace(self.sums.read_text()[:64], "0" * 64))
        result = self.install("example/masktext", "v0.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(binary.read_text(), "original")

    def test_invalid_repository_and_version(self):
        for args in [("bad",), ("owner/../repo",), ("owner/repo", "v0/evil")]:
            self.assertNotEqual(self.install(*args).returncode, 0)


if __name__ == "__main__":
    unittest.main()
