"""Runtime-module inventory for all supported public release targets."""
import datetime
import json
import pathlib
import shutil
import subprocess
import uuid

TARGETS = (("darwin", "arm64"), ("darwin", "amd64"),
           ("linux", "arm64"), ("linux", "amd64"),
           ("windows", "arm64"), ("windows", "amd64"))


def json_stream(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        yield value
        raw = raw[end:]


def runtime_modules(root, env):
    # Download every required module before reading Dir or license files. A
    # Linux-only test run does not populate macOS/Windows dependency sources.
    subprocess.run(["go", "mod", "download"], cwd=root, env=env, check=True)
    modules = {}
    for target_os, arch in TARGETS:
        target_env = dict(env, GOOS=target_os, GOARCH=arch, CGO_ENABLED="0")
        raw = subprocess.check_output(
            ["go", "list", "-deps", "-json", "./cmd/aifakescan"],
            cwd=root, env=target_env, text=True)
        for package in json_stream(raw):
            module = package.get("Module")
            if not module:
                continue  # Go standard-library packages are not modules.
            if module.get("Replace"):
                raise RuntimeError("release inventory rejects replaced modules")
            if not module.get("Dir") or not pathlib.Path(module["Dir"]).is_dir():
                raise RuntimeError("runtime module source unavailable: " + module["Path"])
            previous = modules.get(module["Path"])
            if previous and previous.get("Version") != module.get("Version"):
                raise RuntimeError("conflicting runtime module versions")
            modules[module["Path"]] = module
    if not modules:
        raise RuntimeError("runtime module inventory is empty")
    return [modules[name] for name in sorted(modules)]


def write_inventory(modules, out):
    licenses = out / "dependency-licenses"
    licenses.mkdir()
    packages = []
    for index, module in enumerate(modules):
        source = pathlib.Path(module["Dir"])
        license_files = sorted(p for p in source.glob("*LICENSE*") if p.is_file())
        if not license_files:
            raise RuntimeError("runtime module license missing: " + module["Path"])
        for license_file in license_files:
            if license_file.stat().st_size == 0:
                raise RuntimeError("runtime module license is empty: " + module["Path"])
            shutil.copyfile(license_file, licenses / (f"module-{index}-" + license_file.name))
        entry = {
            "name": module["Path"], "SPDXID": f"SPDXRef-module-{index}",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if module.get("Version"):
            entry["versionInfo"] = module["Version"]
            entry["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                "referenceLocator": f"pkg:golang/{module['Path']}@{module['Version']}"}]
        packages.append(entry)
    sbom = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "aifakescan-cli-runtime-module-inventory",
        "documentNamespace": "https://aifakescan.com/spdx/" + str(uuid.uuid4()),
        "creationInfo": {
            "creators": ["Tool: aifakescan-cli-package-script"],
            "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]} for p in packages],
    }
    (out / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
    return licenses


def copy_go_license(licenses, env):
    goroot = pathlib.Path(subprocess.check_output(
        ["go", "env", "GOROOT"], env=env, text=True).strip())
    license_file = goroot / "LICENSE"
    if not license_file.is_file() or not license_file.stat().st_size:
        raise RuntimeError("Go standard library license unavailable")
    shutil.copyfile(license_file, licenses / "go-standard-library-LICENSE")
