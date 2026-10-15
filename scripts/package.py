#!/usr/bin/env python3
"""Build public client archives and a resolved-module SPDX dependency inventory."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import uuid
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
out = root / "dist"
out.mkdir(exist_ok=True)
version = os.environ.get("RELEASE_TAG", "v0.1.0-beta")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", version):
    raise SystemExit("invalid release tag")
modules_raw = subprocess.check_output(["go", "list", "-m", "-json", "all"], cwd=root, text=True)
decoder = json.JSONDecoder()
modules = []
while modules_raw.strip():
    modules_raw = modules_raw.lstrip()
    module, end = decoder.raw_decode(modules_raw)
    modules.append(module)
    modules_raw = modules_raw[end:]
packages = []
licenses = out / "dependency-licenses"
licenses.mkdir(exist_ok=True)
for index, module in enumerate(modules):
    path = module["Path"]
    entry = {
        "name": path, "SPDXID": f"SPDXRef-module-{index}",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if module.get("Version"):
        entry["versionInfo"] = module["Version"]
        entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:golang/{path}@{module['Version']}"}]
    packages.append(entry)
    source = pathlib.Path(module.get("Dir", "/nonexistent"))
    for license_file in source.glob("*LICENSE*"):
        if license_file.is_file():
            shutil.copyfile(license_file, licenses / (f"module-{index}-" + license_file.name))
sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "aifakescan-cli-module-inventory", "documentNamespace": "https://aifakescan.com/spdx/" + str(uuid.uuid4()), "creationInfo": {"creators": ["Tool: aifakescan-cli-package-script"], "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, "packages": packages, "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]} for p in packages]}
(out / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
for target_os, arch in [("darwin", "arm64"), ("darwin", "amd64"), ("linux", "arm64"), ("linux", "amd64"), ("windows", "arm64"), ("windows", "amd64")]:
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
