"""Download the Nuclei binary into backend/bin/ (it is git-ignored, ~40 MB zip).

Run after cloning if you want deep scans:

    python scripts/install_nuclei.py

Then fetch templates once:

    backend/bin/nuclei -update-templates
"""

from __future__ import annotations

import io
import os
import platform
import zipfile

import httpx

API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"


def asset_name_fragment() -> str:
    system = platform.system().lower()  # windows | linux | darwin
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    osname = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system, system)
    return f"{osname}_{arch}"


def main() -> None:
    bin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin")
    os.makedirs(bin_dir, exist_ok=True)

    frag = asset_name_fragment()
    print(f"Looking up latest Nuclei release for {frag} …")
    data = httpx.get(API, timeout=30, follow_redirects=True).json()
    asset = next((a for a in data.get("assets", [])
                  if frag in a["name"] and a["name"].endswith(".zip")), None)
    if not asset:
        raise SystemExit(f"No Nuclei asset found for {frag}")

    print(f"Downloading {asset['name']} ({asset['size'] // 1_000_000} MB) …")
    content = httpx.get(asset["browser_download_url"], timeout=300, follow_redirects=True).content
    exe = "nuclei.exe" if platform.system().lower() == "windows" else "nuclei"
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        z.extract(exe, bin_dir)
    path = os.path.join(bin_dir, exe)
    if platform.system().lower() != "windows":
        os.chmod(path, 0o755)
    print(f"Installed: {path}")
    print("Next: run 'bin/nuclei -update-templates' to fetch templates.")


if __name__ == "__main__":
    main()
