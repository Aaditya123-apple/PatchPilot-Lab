"""Download the public benchmark datasets into bench/data/.

  * SecurityEval  - https://github.com/s2e-lab/SecurityEval  (121 vulnerable Python samples, 69 CWEs)
  * Bandit        - https://github.com/PyCQA/bandit           (labelled example files used by Bandit's own tests)

Usage: python -m bench.fetch_datasets
"""

from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
SOURCES = {
    "SecurityEval-main": "https://codeload.github.com/s2e-lab/SecurityEval/zip/refs/heads/main",
    "bandit-main": "https://codeload.github.com/PyCQA/bandit/zip/refs/heads/main",
}


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for folder, url in SOURCES.items():
        if (DATA / folder).exists():
            print(f"{folder}: already present")
            continue
        print(f"{folder}: downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https URL
            payload = resp.read()
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            for member in zf.namelist():
                target = (DATA / member).resolve()
                if not str(target).startswith(str(DATA.resolve())):
                    raise RuntimeError(f"Refusing to extract outside {DATA}: {member}")
            zf.extractall(DATA)
        print(f"{folder}: done")


if __name__ == "__main__":
    main()
