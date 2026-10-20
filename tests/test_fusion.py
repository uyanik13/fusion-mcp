import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fusion  # noqa: E402

VALID = "import adsk.core\n\ndef run(_context: str):\n    print('ok')\n"


class LintTests(unittest.TestCase):
    def test_clean_script(self):
        rep = fusion.lint(VALID)
        self.assertEqual(rep, {"errors": [], "destructive": [], "warnings": []})

    def test_missing_entry_point(self):
        self.assertTrue(fusion.lint("print('x')")["errors"])

    def test_forbidden_import(self):
        self.assertTrue(fusion.lint("import os\n" + VALID)["errors"])

    def test_forbidden_call(self):
        src = "def run(_context: str):\n    eval('1')\n"
        self.assertTrue(fusion.lint(src)["errors"])

    def test_indirect_attribute_access(self):
        src = "def run(_context: str):\n    getattr(object, '__subclasses__')\n"
        self.assertTrue(fusion.lint(src)["errors"])

    def test_destructive_call(self):
        src = "def run(_context: str):\n    x.deleteMe()\n"
        rep = fusion.lint(src)
        self.assertFalse(rep["errors"])
        self.assertTrue(rep["destructive"])

    def test_syntax_error(self):
        self.assertTrue(fusion.lint("def run(:")["errors"])

    def test_size_limit(self):
        src = VALID + "#" * fusion.MAX_SCRIPT_BYTES
        self.assertTrue(fusion.lint(src)["errors"])


class UrlTests(unittest.TestCase):
    def test_local_urls_allowed(self):
        fusion.check_url("http://127.0.0.1:27182/mcp")
        fusion.check_url("http://localhost:27182/mcp")

    def test_remote_url_rejected(self):
        with self.assertRaises(fusion.FusionError):
            fusion.check_url("http://example.com/mcp")

    def test_invalid_scheme_rejected(self):
        with self.assertRaises(fusion.FusionError):
            fusion.check_url("file:///etc/passwd")


class WriteGateTests(unittest.TestCase):
    class Args:
        write = False
        doc = None
        any_doc = False

    def test_write_requires_flag(self):
        with self.assertRaises(fusion.FusionError):
            fusion.require_write(self.Args(), "run")

    def test_write_requires_target_document(self):
        args = self.Args()
        args.write = True
        with self.assertRaises(fusion.FusionError):
            fusion.require_write(args, "run")

    def test_write_allowed_with_doc(self):
        args = self.Args()
        args.write, args.doc = True, "My Design"
        fusion.require_write(args, "run")


class ParserTests(unittest.TestCase):
    def test_help_builds(self):
        self.assertIsNotNone(fusion.build_parser())

    def test_builtin_scripts_are_valid_and_clean(self):
        for name, (_, src) in fusion.SNIPPETS.items():
            with self.subTest(name=name):
                self.assertEqual(fusion.lint(src), {"errors": [], "destructive": [], "warnings": []})


if __name__ == "__main__":
    unittest.main()
