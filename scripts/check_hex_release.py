"""Compare the inspected uploads with Hex's public, immutable release bytes."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request


def refuse(message):
    raise SystemExit(f"::error::{message}")


def fetch(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "hex-release-readback", "Cache-Control": "no-cache"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                refuse(f"Registry lookup failed (HTTP {response.status}): {url}")
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        refuse(f"Registry lookup failed (HTTP {error.code}): {url}")
    except (OSError, http.client.HTTPException):
        refuse(f"Registry lookup failed: {url}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compare(url, path, label):
    served = fetch(url)
    if served is None:
        return False
    expected = path.read_bytes()
    if served != expected:
        refuse(
            f"{label} differs from the inspected archive; refusing replacement "
            f"(expected SHA-256 {digest(expected)}, served {digest(served)})"
        )
    print(f"{label} read-back matches SHA-256 {digest(expected)}")
    return True


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("name", "prepare", "read-back"):
        refuse("usage: check_hex_release.py name|prepare|read-back")
    mode = sys.argv[1]
    package, version = os.environ["PACKAGE"], os.environ["VERSION"]
    if not re.fullmatch(r"[a-z][a-z0-9_]*", package) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version
    ):
        refuse("Invalid release identity")
    package_url = f"https://hex.pm/api/packages/{package}"
    # Also repeat the name refusal before any upload and during the final read-back.
    if fetch(package_url) is None:
        refuse(
            f"{package} has never been published to Hex.pm: "
            "this workflow publishes new versions of existing packages only. "
            "A first publication is the owner's decision."
        )
    if mode == "name":
        return

    metadata = fetch(f"{package_url}/releases/{version}")
    release = None if metadata is None else json.loads(metadata)
    if release is not None:
        if release.get("retirement") is not None:
            refuse(f"{package} {version} is retired; refusing publication")
        checksum = release.get("checksum", "")
        expected = digest(Path(os.environ["PACKAGE_ARCHIVE"]).read_bytes())
        if not isinstance(checksum, str) or checksum.lower() != expected:
            refuse(f"{package} {version} registry outer checksum differs from the archive")

    package_served = compare(
        f"https://repo.hex.pm/tarballs/{package}-{version}.tar",
        Path(os.environ["PACKAGE_ARCHIVE"]),
        "Package",
    )
    docs_served = compare(
        f"https://repo.hex.pm/docs/{package}-{version}.tar.gz",
        Path(os.environ["DOCS_ARCHIVE"]),
        "Documentation",
    )
    # Metadata that advertises an upload is never permission to overwrite it while
    # its CDN object is unavailable. A later dispatch can retry the read-back.
    if release is not None and not package_served:
        refuse("Hex lists this release but does not serve its archive; retry this commit")
    if release is not None and release.get("has_docs") and not docs_served:
        refuse("Hex lists these docs but does not serve their archive; retry this commit")
    if release is None and (package_served or docs_served):
        refuse("Hex release metadata and served archives disagree; retry this commit")

    if mode == "prepare":
        with open(os.environ["GITHUB_ENV"], "a") as output:
            output.write(f"PUBLISH_PACKAGE={str(not package_served).lower()}\n")
            output.write(f"PUBLISH_DOCS={str(not docs_served).lower()}\n")
        return
    held = os.environ.get("PUBLICATION_HELD") == "true"
    if held or not (release is not None and package_served and docs_served):
        refuse(
            "Publication is held or not yet served: approve any held uploads on Hex, "
            "then dispatch publish.yml again on this same commit. "
            "Both package and documentation must match before tagging."
        )
    print(f"Hex serves both inspected uploads for {package} {version}")


if __name__ == "__main__":
    main()
