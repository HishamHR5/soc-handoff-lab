"""Download public datasets to data/raw/, with SHA-256 checks.

SHA-256: data/checksums.json holds the expected hash of each file. If a file has no hash
yet, the first download records it (trust on first use) and prints it; commit the file so
that later downloads are checked. A file with a wrong hash is deleted and the download fails.

AIT-LDS v2 is too large (7-27 GB per scenario) for an automatic download. MANUAL_STEPS
says what to do.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..config import DATA


@dataclass(frozen=True)
class Source:
    url: str
    dest: str  # path under data/raw/
    license: str


SOURCES = {
    "loghub_openssh": Source(
        "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
        "loghub/OpenSSH_2k.log",
        "LogHub (logpai/loghub): free for research or academic work; cite the LogHub paper "
        "(Zhu et al., ISSRE 2023). No attack labels."),
    "loghub_apache": Source(
        "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log",
        "loghub/Apache_2k.log",
        "LogHub (logpai/loghub): free for research or academic work; cite the LogHub paper. "
        "This is an Apache ERROR log. No attack labels."),
}

MANUAL_STEPS = {
    "guide": """Microsoft GUIDE (test file only) - MANUAL DOWNLOAD WITH A KAGGLE ACCOUNT
Dataset: Microsoft/microsoft-security-incident-prediction (Kaggle). Paper: Freitas et al.,
WWW Companion 2025, doi:10.1145/3701716.3715209. License on Kaggle: "other" - read the terms
on the dataset page before you use the data.
1. Make a Kaggle API token (kaggle.com -> Settings -> API). The Kaggle CLI reads it from
   ~/.kaggle/ (never put it in this project).
2. pip install kaggle   (in a separate environment)
3. kaggle datasets download Microsoft/microsoft-security-incident-prediction \\
       -f GUIDE_Test.csv -p data/raw/guide
4. The file is 1,087,963,831 bytes; check it:  shasum -a 256 data/raw/guide/GUIDE_Test.csv
   (the expected SHA-256 is in data/checksums.json, key guide/GUIDE_Test.csv).
5. Use it in an experiment (clean runs only, GUIDE has no attacker fields):
     dataset: {source: guide, n: 20}     # 20 incidents per label (TP, BP, FP)
""",
    "aitlds": """AIT Log Data Set V2.0 (AIT-LDS v2) - MANUAL DOWNLOAD
License: CC BY-NC-SA 4.0 (non-commercial; cite Landauer et al. 2022, arXiv:2203.08580).
1. Open https://zenodo.org/records/5789064
2. Download ONE scenario zip. Sizes: russellmitchell.zip 7.1 GB (smallest), santos.zip 10.0 GB,
   fox.zip 15.8 GB, harrison.zip 16.8 GB, wardbeck.zip 17.2 GB, shaw.zip 17.6 GB,
   wheeler.zip 19.6 GB, wilson.zip 26.5 GB.
3. Check the zip with the MD5 that Zenodo shows next to the file:  md5 <file>.zip
4. Unzip it to data/raw/aitlds/<scenario>/  (you must see gather/ and labels/ in it).
5. Find the log files:  find data/raw/aitlds/<scenario>/gather -name 'auth.log' -o -name '*access*.log'
6. Put the paths in the dataset block of your experiment file, for example:
     dataset:
       source: aitlds
       root: data/raw/aitlds/<scenario>
       year: 2022            # the auth.log lines have no year; use the year of the scenario
       files:
         - {path: gather/<host>/logs/auth.log, kind: auth}
         - {path: gather/<host>/logs/apache2/<name>-access.log, kind: apache_access}
""",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_checksums(path: Path) -> dict[str, str]:
    return json.loads(path.read_text()) if path.exists() else {}


def download(name: str, raw_dir: Path = DATA / "raw", checksums_file: Path = DATA / "checksums.json",
             client: httpx.Client | None = None, url: str | None = None) -> tuple[Path, str]:
    """Download one source. Return (path, status). status: verified | recorded | present."""
    source = SOURCES[name]
    dest = raw_dir / source.dest
    sums = load_checksums(checksums_file)
    expected = sums.get(source.dest)
    if dest.exists() and expected and sha256_of(dest) == expected:
        return dest, "present"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    own_client = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True)
    try:
        with client.stream("GET", url or source.url) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_bytes():
                    f.write(chunk)
    finally:
        if own_client:
            client.close()
    digest = sha256_of(tmp)
    if expected and digest != expected:
        tmp.unlink()
        raise ValueError(f"SHA-256 mismatch for {source.dest}: expected {expected}, got {digest}")
    tmp.replace(dest)
    if expected:
        return dest, "verified"
    sums[source.dest] = digest
    checksums_file.write_text(json.dumps(dict(sorted(sums.items())), indent=2) + "\n")
    return dest, "recorded"
