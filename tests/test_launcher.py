"""Exercise the standalone script without a checkout in its working directory."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
if not BASH and os.name == "nt":
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    BASH = str(git_bash) if git_bash.exists() else None


@unittest.skipUnless(BASH, "Bash is required to exercise the packaged entry point")
class LauncherTests(unittest.TestCase):
    def test_process_substitution_with_stdin_and_no_checkout(self):
        with tempfile.TemporaryDirectory(prefix="nodequality space ") as directory:
            shutil.copyfile(ROOT / "NodeQuality.sh", Path(directory) / "standalone.sh")
            result = subprocess.run(
                [BASH, "-c", 'bash <(cat standalone.sh) --json --no-dnsbl'],
                input="127.0.0.1\n", cwd=directory, encoding="utf-8", capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stderr)
        bundle = json.loads(result.stdout)
        self.assertEqual(bundle["reports"][0]["target_ip"], "127.0.0.1")
        self.assertEqual(bundle["reports"][0]["status"], "not_applicable")
        self.assertIn("直接回车", result.stderr)

    def test_quoted_argument_cannot_execute_shell_code(self):
        with tempfile.TemporaryDirectory(prefix="nodequality space ") as directory:
            shutil.copyfile(ROOT / "NodeQuality.sh", Path(directory) / "standalone.sh")
            result = subprocess.run([BASH, "standalone.sh", "-i", "1.1.1.1;touch injected"],
                                    cwd=directory, encoding="utf-8", capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((Path(directory) / "injected").exists())
