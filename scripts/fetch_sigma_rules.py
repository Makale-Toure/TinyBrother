"""Download the SigmaHQ Windows rules into rules/sigma/.

Usage: python scripts/fetch_sigma_rules.py
"""

from __future__ import annotations

import io
import shutil
import urllib.request
import zipfile
from pathlib import Path

URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
DEST = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def main() -> None:
    print(f"Downloading {URL} ...")
    with urllib.request.urlopen(URL) as resp:
        data = resp.read()
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            parts = name.split("/")
            # sigma-master/rules/windows/<...>.yml
            if len(parts) > 3 and parts[1] == "rules" and parts[2] == "windows" and name.endswith(".yml"):
                target = DEST / "/".join(parts[3:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                count += 1
    print(f"Saved {count} Windows rules to {DEST}")


if __name__ == "__main__":
    main()
