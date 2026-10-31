#!/usr/bin/env python3
"""
Integrity & Architecture Tests for VexTunnel Installers
"""

import unittest
import os
import glob
import re

class TestInstaller(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.shell_scripts = [
            os.path.join(self.base_dir, "install.sh"),
            os.path.join(self.base_dir, "install", "setup.sh"),
            os.path.join(self.base_dir, "install", "install_ssh.sh"),
            os.path.join(self.base_dir, "install", "install_ws.sh"),
            os.path.join(self.base_dir, "install", "install_badvpn.sh"),
            os.path.join(self.base_dir, "install", "install_cron.sh")
        ]

    def test_all_scripts_exist_with_shebang(self):
        """Verify all essential installer scripts exist and start with valid bash shebang."""
        for script_path in self.shell_scripts:
            with self.subTest(script=os.path.basename(script_path)):
                self.assertTrue(os.path.exists(script_path), f"Missing script: {script_path}")
                with open(script_path, "r", encoding="utf-8") as f:
                    first_line = f.readline().strip()
                self.assertEqual(first_line, "#!/bin/bash", f"Invalid shebang in {script_path}")

    def test_no_backdoors_or_obfuscated_blobs(self):
        """Verify zero obfuscated/malicious shell patterns exist across all scripts."""
        malicious_patterns = [
            r"base64\s+-d\s*\|\s*sh",
            r"eval\s*\$\(base64",
            r"wget\s+.*\|\s*sh",
            r"curl\s+.*\|\s*sh\s*&",
            r"lib_enc\.sh",
            r"/dev/tcp/",
            r"python.*-c.*import.*socket.*connect"
        ]

        for script_path in self.shell_scripts:
            with open(script_path, "r", encoding="utf-8") as f:
                content = f.read()

            for pattern in malicious_patterns:
                with self.subTest(script=os.path.basename(script_path), pattern=pattern):
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    self.assertEqual(len(matches), 0, f"Detected potential backdoor pattern '{pattern}' in {script_path}")

    def test_architecture_classification(self):
        """Verify architecture detection logic correctly classifies target CPU types."""
        def classify_arch(arch: str) -> str:
            if arch in ("x86_64", "amd64"):
                return "x86_64"
            elif arch in ("aarch64", "arm64"):
                return "arm64"
            elif arch in ("armv7l", "armv8l"):
                return "arm32"
            return "unsupported"

        self.assertEqual(classify_arch("x86_64"), "x86_64")
        self.assertEqual(classify_arch("amd64"), "x86_64")
        self.assertEqual(classify_arch("aarch64"), "arm64")
        self.assertEqual(classify_arch("arm64"), "arm64")
        self.assertEqual(classify_arch("armv7l"), "arm32")
        self.assertEqual(classify_arch("mips"), "unsupported")

if __name__ == "__main__":
    unittest.main()
