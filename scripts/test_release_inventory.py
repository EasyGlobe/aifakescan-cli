import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from release_inventory import TARGETS, copy_go_license, runtime_modules, write_inventory


class ReleaseInventoryTests(unittest.TestCase):
    def test_missing_license_aborts_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, out = root / "module", root / "out"
            source.mkdir()
            out.mkdir()
            with self.assertRaisesRegex(RuntimeError, "license missing"):
                write_inventory([{"Path": "example.test/runtime", "Dir": str(source)}], out)
            self.assertFalse((out / "sbom.spdx.json").exists())

    def test_empty_license_aborts_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, out = root / "module", root / "out"
            source.mkdir()
            out.mkdir()
            (source / "LICENSE").touch()
            with self.assertRaisesRegex(RuntimeError, "license is empty"):
                write_inventory([{"Path": "example.test/runtime", "Dir": str(source)}], out)

    def test_download_precedes_all_target_runtime_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            seen = []
            def download(command, **kwargs):
                self.assertEqual(command, ["go", "mod", "download"])
                seen.append("download")
            def discover(command, **kwargs):
                self.assertEqual(seen[0], "download")
                self.assertEqual(command, ["go", "list", "-deps", "-json", "./cmd/aifakescan"])
                env = kwargs["env"]
                seen.append((env["GOOS"], env["GOARCH"]))
                return json.dumps({"Module": {"Path": "runtime/" + env["GOOS"], "Version": "v1.0.0", "Dir": str(root)}})
            with mock.patch("release_inventory.subprocess.run", side_effect=download), mock.patch("release_inventory.subprocess.check_output", side_effect=discover):
                modules = runtime_modules(root, {})
            self.assertEqual(seen[1:], list(TARGETS))
            self.assertEqual([m["Path"] for m in modules], ["runtime/darwin", "runtime/linux", "runtime/windows"])

    @unittest.skipUnless(os.environ.get("AIFAKESCAN_TEST_EMPTY_MODULE_CACHE") == "1", "opt-in network test with a fresh Go module cache")
    def test_empty_cache_includes_all_platform_runtime_licenses(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="aifakescan-empty-cache-") as temporary:
            temporary = pathlib.Path(temporary)
            module_cache = temporary / "modules"
            self.assertFalse(module_cache.exists())
            env = dict(os.environ, GOMODCACHE=str(module_cache), GOPATH=str(temporary / "gopath"))
            modules = runtime_modules(root, env)
            expected = {"github.com/EasyGlobe/aifakescan-cli", "github.com/zalando/go-keyring", "al.essio.dev/pkg/shellescape", "github.com/danieljoos/wincred", "github.com/godbus/dbus/v5", "golang.org/x/sys"}
            self.assertEqual({m["Path"] for m in modules}, expected)
            out = temporary / "output"
            out.mkdir()
            licenses = write_inventory(modules, out)
            self.assertEqual(len(list(licenses.iterdir())), len(expected))
            copy_go_license(licenses, env)
            self.assertTrue((licenses / "go-standard-library-LICENSE").stat().st_size > 0)
            sbom = json.loads((out / "sbom.spdx.json").read_text())
            self.assertEqual({p["name"] for p in sbom["packages"]}, expected)
            self.assertNotIn(str(temporary), (out / "sbom.spdx.json").read_text())


if __name__ == "__main__":
    unittest.main()
