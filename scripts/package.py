#!/usr/bin/env python3
"""Build public client archives and a resolved-module SPDX dependency inventory."""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import zipfile

from release_inventory import TARGETS, copy_go_license, runtime_modules, write_inventory

root = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(os.environ.get("RELEASE_OUTPUT_DIR", str(root / "dist")))
if out.exists() and any(out.iterdir()):
    raise SystemExit("release output directory must be empty; use RELEASE_OUTPUT_DIR for a fresh directory")
out.mkdir(parents=True, exist_ok=True)
version = os.environ.get("RELEASE_TAG", "v0.1.0-beta.1")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", version):
    raise SystemExit("invalid release tag")
modules = runtime_modules(root, dict(os.environ))
licenses = write_inventory(modules, out)
copy_go_license(licenses, dict(os.environ))
for target_os, arch in TARGETS:
    name = f"aifakescan-{version}-{target_os}-{arch}"
    stage = out / name
    stage.mkdir(exist_ok=True)
    binary = stage / ("aifakescan.exe" if target_os == "windows" else "aifakescan")
    env = dict(os.environ, GOOS=target_os, GOARCH=arch, CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(binary), "./cmd/aifakescan"], cwd=root, env=env, check=True)
    for doc in ["README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]:
        shutil.copyfile(root / doc, stage / doc)
    shutil.copytree(licenses, stage / "dependency-licenses", dirs_exist_ok=True)
    shutil.copyfile(out / "sbom.spdx.json", stage / "sbom.spdx.json")
    if target_os == "windows":
        with zipfile.ZipFile(out / (name + ".zip"), "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(out))
    else:
        with tarfile.open(out / (name + ".tar.gz"), "w:gz") as archive:
            def public_metadata(info):
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                return info
            archive.add(stage, arcname=name, filter=public_metadata)
    shutil.rmtree(stage)
shutil.rmtree(licenses)
assets = sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
(out / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in assets))
print("Built public archives, module inventory, dependency licenses and SHA256SUMS")
