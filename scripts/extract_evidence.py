"""Safely extract the password-protected CyberDefenders lab archive.

Handles WinZip-AES (what CyberDefenders uses) via pyzipper. Extraction only --
it writes files to disk and lists them; it never opens or executes any content.

    python -P scripts/extract_evidence.py <zip_path> <out_dir> [password]
"""
import sys
from pathlib import Path

import pyzipper

PASSWORD = "cyberdefenders.org"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    zip_path = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    pwd = (sys.argv[3] if len(sys.argv) > 3 else PASSWORD).encode()

    out_dir.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(pwd)
        names = zf.namelist()
        print(f"archive contains {len(names)} entries:")
        for n in names:
            info = zf.getinfo(n)
            print(f"  {n}  ({info.file_size} bytes)")
        zf.extractall(out_dir)
    print(f"\nextracted -> {out_dir}")
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(out_dir)}  ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
