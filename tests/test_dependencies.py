from __future__ import annotations

import concurrent.futures
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

import loki
from tests.helpers import temporary_root, write_file


class ManifestDependencyTests(unittest.TestCase):
    def test_parses_every_supported_manifest(self) -> None:
        with temporary_root() as root:
            write_file(
                root,
                "package.json",
                '{"dependencies":{"npm-prod":"1"},"devDependencies":{"npm-dev":"1"}}',
            )
            write_file(
                root,
                "pyproject.toml",
                '[project]\ndependencies=["Py-Prod>=1",4]\n',
            )
            write_file(
                root, "requirements-dev.txt", "# comment\n-r base.txt\nPy-Dev==1\n"
            )
            write_file(
                root,
                "go.mod",
                "module example\nrequire example.com/one v1.0.0\n"
                "require (\n example.com/Two v2.0.0\n)\n",
            )
            write_file(
                root, "Cargo.toml", '[dependencies]\nserde="1"\nlocal={path="x"}\n'
            )
            write_file(
                root, "mix.exs", 'def deps, do: [{:jason, "~> 1.0"}, {:plug, ">= 0"}]'
            )
            self.assertEqual(
                [
                    ("crates", "local"),
                    ("crates", "serde"),
                    ("go", "example.com/Two"),
                    ("go", "example.com/one"),
                    ("hex", "jason"),
                    ("hex", "plug"),
                    ("npm", "npm-dev"),
                    ("npm", "npm-prod"),
                    ("pypi", "py-dev"),
                    ("pypi", "py-prod"),
                ],
                loki.manifest_dependencies(root),
            )

    def test_invalid_manifests_are_ignored(self) -> None:
        with temporary_root() as root:
            for name in ("package.json", "pyproject.toml", "Cargo.toml"):
                write_file(root, name, "{")
            write_file(root, "go.mod", "require (\ninvalid\n")
            write_file(root, "mix.exs", "not deps")
            self.assertEqual([], loki.manifest_dependencies(root))

    def test_absent_and_non_mapping_manifest_sections_are_ignored(self) -> None:
        with temporary_root() as root:
            self.assertEqual([], loki.manifest_dependencies(root))
            write_file(root, "package.json", "[]")
            write_file(root, "pyproject.toml", "project = []")
            write_file(root, "Cargo.toml", "dependencies = []")
            self.assertEqual([], loki.manifest_dependencies(root))

    def test_empty_present_manifest_files_cover_no_dependency_paths(self) -> None:
        with temporary_root() as root:
            write_file(root, "package.json", "{}")
            write_file(root, "pyproject.toml", "")
            write_file(root, "go.mod", "module example\n")
            write_file(root, "Cargo.toml", "")
            write_file(root, "mix.exs", "def deps, do: []")
            self.assertEqual([], loki.manifest_dependencies(root))

    def test_non_string_package_and_cargo_keys_are_ignored(self) -> None:
        with (
            temporary_root() as root,
            patch.object(
                loki.json,
                "loads",
                return_value={"dependencies": {4: "one"}, "devDependencies": []},
            ),
            patch.object(
                loki.tomllib,
                "loads",
                side_effect=[
                    {"project": {"dependencies": []}},
                    {"dependencies": {4: "one"}},
                ],
            ),
        ):
            write_file(root, "package.json", "{}")
            write_file(root, "pyproject.toml", "")
            write_file(root, "Cargo.toml", "")
            self.assertEqual([], loki.manifest_dependencies(root))

    def test_unreadable_manifests_are_ignored(self) -> None:
        with temporary_root() as root:
            paths = [
                write_file(root, "package.json", "{}"),
                write_file(root, "pyproject.toml", ""),
                write_file(root, "requirements.txt", "x"),
                write_file(root, "go.mod", ""),
                write_file(root, "Cargo.toml", ""),
                write_file(root, "mix.exs", ""),
            ]
            original = loki.Path.read_text

            def unreadable(path, *args, **kwargs):
                if path in paths:
                    raise OSError("denied")
                return original(path, *args, **kwargs)

            with patch.object(loki.Path, "read_text", unreadable):
                self.assertEqual([], loki.manifest_dependencies(root))


class RegistryTests(unittest.TestCase):
    def test_go_proxy_name_and_registry_urls(self) -> None:
        self.assertEqual(
            "github.com/!azure/!s!d!k", loki.go_proxy_name("github.com/Azure/SDK")
        )
        expected = {
            ("npm", "@scope/pkg"): "https://registry.npmjs.org/%40scope%2Fpkg",
            ("pypi", "pkg name"): "https://pypi.org/pypi/pkg%20name/json",
            ("crates", "pkg name"): "https://crates.io/api/v1/crates/pkg%20name",
            (
                "go",
                "github.com/Azure/SDK",
            ): "https://proxy.golang.org/github.com/%21azure/%21s%21d%21k/@latest",
            ("hex", "pkg name"): "https://hex.pm/api/packages/pkg%20name",
        }
        for item, url in expected.items():
            with self.subTest(item=item):
                self.assertEqual(url, loki.registry_url(*item))

    def test_dependency_violation_handles_registry_results(self) -> None:
        item = ("npm", "pkg")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(urllib.request, "urlopen", return_value=response):
            self.assertIsNone(loki.dependency_violation(item))

        for error in (
            urllib.error.HTTPError("url", 404, "missing", {}, None),
            urllib.error.HTTPError("url", 429, "limited", {}, None),
            urllib.error.HTTPError("url", 500, "bad", {}, None),
            urllib.error.URLError("offline"),
            OSError("offline"),
        ):
            with (
                self.subTest(error=error),
                patch.object(urllib.request, "urlopen", side_effect=error),
            ):
                finding = loki.dependency_violation(item)
                self.assertIn(
                    "package not found"
                    if isinstance(error, urllib.error.HTTPError) and error.code == 404
                    else "registry check unavailable",
                    finding or "",
                )

    def test_slopsquatting_filters_private_prefixes_and_clean_results(self) -> None:
        dependencies = [
            ("npm", "@private/pkg"),
            ("npm", "bad"),
            ("pypi", "good"),
        ]
        with (
            temporary_root() as root,
            patch.object(loki, "manifest_dependencies", return_value=dependencies),
            patch.object(
                concurrent.futures,
                "ThreadPoolExecutor",
            ) as executor_type,
        ):
            executor = executor_type.return_value.__enter__.return_value
            executor.map.return_value = ["missing bad", None]
            self.assertEqual(
                ["missing bad"],
                loki.slopsquatting_violations(
                    root, {"private_packages": ["@private/", 4]}
                ),
            )
        executor_type.assert_called_once_with(max_workers=8)
        executor.map.assert_called_once_with(
            loki.dependency_violation, [("npm", "bad"), ("pypi", "good")]
        )

    def test_slopsquatting_ignores_invalid_private_config(self) -> None:
        dependencies = [("npm", "pkg")]
        with (
            temporary_root() as root,
            patch.object(loki, "manifest_dependencies", return_value=dependencies),
            patch.object(
                concurrent.futures,
                "ThreadPoolExecutor",
            ) as executor_type,
        ):
            executor = executor_type.return_value.__enter__.return_value
            executor.map.return_value = [None]
            self.assertEqual(
                [], loki.slopsquatting_violations(root, {"private_packages": "pkg"})
            )
        executor.map.assert_called_once_with(loki.dependency_violation, dependencies)


if __name__ == "__main__":
    unittest.main()
