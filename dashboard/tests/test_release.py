import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import build
from scripts import check_release


class PrivateBuildTests(unittest.TestCase):
    def test_report_requires_explicit_private_output(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "ghqr.json"
            report.write_text('{"organizations":{}}', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                build.main([str(report)])
            self.assertEqual(result.exception.code, 2)

    def test_private_build_cannot_overwrite_application_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "app"
            root.mkdir()
            report = Path(folder) / "report.json"
            report.write_text('{"organizations":{}}', encoding="utf-8")
            for name in ("ghqr-dashboard.html", "other.html", str(Path("src") / "index.html")):
                output = root / name
                output.parent.mkdir(exist_ok=True)
                output.write_text("unchanged", encoding="utf-8")
                with self.subTest(name=name), mock.patch.object(build, "ROOT", root), self.assertRaises(SystemExit):
                    build.build(report, output)
                self.assertEqual(output.read_text(encoding="utf-8"), "unchanged")

    def test_private_build_outside_application_still_works(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.json"
            report.write_text('{"organizations":{}}', encoding="utf-8")
            output = Path(folder) / "private.html"
            build.build(report, output)
            page = output.read_text(encoding="utf-8")
            self.assertIn('data-source="report.json"', page)
            self.assertIn('{"organizations":{}}', page)

    def test_private_output_cannot_escape_dashboard_into_repository(self):
        with tempfile.TemporaryDirectory() as folder:
            repository = Path(folder)
            (repository / ".git").mkdir()
            app = repository / "dashboard"
            app.mkdir()
            output = repository / "private.html"
            output.write_text("unchanged", encoding="utf-8")
            with mock.patch.object(build, "ROOT", app), self.assertRaises(SystemExit):
                build.require_private_output(output)
            self.assertEqual(output.read_text(encoding="utf-8"), "unchanged")

    def test_private_pdf_cannot_delete_or_overwrite_application_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "report.pdf"
            output.write_bytes(b"unchanged")
            with mock.patch.object(build, "ROOT", root), self.assertRaises(SystemExit):
                build.export_pdf(root / "private.html", output, "unused-browser", "dark")
            self.assertEqual(output.read_bytes(), b"unchanged")


class PublicContentTests(unittest.TestCase):
    def test_data_files_and_disguised_reports_are_rejected(self):
        for name, content in (
            ("report.json", b"{}"),
            ("export.csv", b"column\nvalue"),
            ("report.pdf", b"private"),
            ("backup.zip", b"private"),
            ("notes.txt", b'{"organizations":{}}'),
            ("private-dashboard.html", b"<html></html>"),
        ):
            with self.subTest(name=name), self.assertRaises(check_release.ReleaseCheckError):
                check_release.check_content(name, content)

    def test_personal_data_checks_do_not_echo_the_value(self):
        email = "synthetic-person" + "@" + "example.invalid"
        personal_path = "C:" + chr(92) + "Users" + chr(92) + "synthetic-person"
        for value in (email, personal_path):
            with self.subTest(value=value), self.assertRaises(check_release.ReleaseCheckError) as result:
                check_release.check_content("notes.txt", value.encode("utf-8"))
            self.assertNotIn(value, str(result.exception))

    def test_private_terms_cover_content_and_filenames(self):
        for name, content in (("notes.txt", b"Synthetic private label"), ("synthetic-private.html", b"blank")):
            with self.subTest(name=name), self.assertRaises(check_release.ReleaseCheckError):
                check_release.check_content(name, content, ("synthetic private label", "synthetic-private"))

    def test_generic_source_and_public_entrypoints_are_allowed(self):
        for name in ("build.py", "ghqr-dashboard.html", str(Path("src") / "index.html")):
            with self.subTest(name=name):
                check_release.check_content(name, b"generic application source")

    def test_stale_distributable_fails_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "ghqr-dashboard.html"
            artifact.write_bytes(b"stale")

            def fake_build(command, **kwargs):
                Path(command[-1]).write_bytes(b"fresh")

            with mock.patch.object(check_release, "run", side_effect=fake_build), self.assertRaises(check_release.ReleaseCheckError):
                check_release.check_blank_build(root)
            self.assertEqual(artifact.read_bytes(), b"stale")


class GitBoundaryTests(unittest.TestCase):
    def initialize(self, root):
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        (root / ".gitattributes").write_text("* text=auto eol=lf\n", encoding="utf-8")
        self.stage(root, ".gitattributes")

    def stage(self, root, name):
        subprocess.run(["git", "-C", str(root), "add", "--", name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_staged_content_must_match_the_tested_working_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.initialize(root)
            (root / "notes.txt").write_text("staged\n", encoding="utf-8")
            self.stage(root, "notes.txt")
            (root / "notes.txt").write_text("different\n", encoding="utf-8")
            with self.assertRaisesRegex(check_release.ReleaseCheckError, "Index differs"):
                check_release.check_git(root, ())

    def test_staged_report_is_rejected_even_if_removed_from_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.initialize(root)
            report = root / "report.json"
            report.write_text("{}", encoding="utf-8")
            self.stage(root, "report.json")
            report.unlink()
            with self.assertRaisesRegex(check_release.ReleaseCheckError, "report/export/credential"):
                check_release.check_git(root, ())

    def test_untracked_test_code_must_be_staged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.initialize(root)
            (root / "extra.py").write_text("print('synthetic')\n", encoding="utf-8")
            with self.assertRaisesRegex(check_release.ReleaseCheckError, "Untracked"):
                check_release.check_git(root, ())

    def test_line_ending_normalization_does_not_change_tested_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.initialize(root)
            source = root / "example.py"
            source.write_bytes(b"print('synthetic')\n")
            self.stage(root, "example.py")
            source.write_bytes(b"print('synthetic')\r\n")
            self.assertTrue(check_release.check_git(root, ()))

    def test_nested_dashboard_scopes_content_checks_to_its_own_index(self):
        with tempfile.TemporaryDirectory() as folder:
            repository = Path(folder)
            self.initialize(repository)
            (repository / "LICENSE").write_text("Contact " + "synthetic-person" + "@" + "example.invalid\n", encoding="utf-8")
            self.stage(repository, "LICENSE")
            (repository / "unrelated.txt").write_text("untracked repository file\n", encoding="utf-8")
            app = repository / "dashboard"
            app.mkdir()
            (app / "example.py").write_text("print('synthetic')\n", encoding="utf-8")
            self.stage(repository, "dashboard")
            staged = check_release.check_git(app, ())
            self.assertIn(b"example.py", staged)
            self.assertNotIn(b"LICENSE", staged)
            (app / "extra.py").write_text("print('untracked')\n", encoding="utf-8")
            with self.assertRaisesRegex(check_release.ReleaseCheckError, "Untracked"):
                check_release.check_git(app, ())


if __name__ == "__main__":
    unittest.main()
