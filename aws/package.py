"""Package a release candidate for the AWS pipeline.

    python aws/package.py app          -> aws/dist/release.zip  (the vulnerable service)
    python aws/package.py app_secure   -> aws/dist/release.zip  (the fixed service)

The zip holds the pipeline tooling, both service folders (the unit tests use them) and a
one-line TARGET file naming the folder being released. Paths are written with forward
slashes so the archive unpacks correctly on the Linux build hosts.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = ("pipeline", "app", "app_secure", "tests", "samples", "aws/requirements-aws.txt",
           "requirements.txt", "policy.yaml")
SKIP_PARTS = {"__pycache__", ".pytest_cache"}
SKIP_SUFFIXES = {".pyc", ".db"}
SKIP_PREFIXES = ("ai_triage_",)  # cached model answers are local rehearsal aids, not release content
TARGETS = ("app", "app_secure")


def files_to_package() -> list[Path]:
    found = []
    for entry in INCLUDE:
        path = ROOT / entry
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            found.extend(
                p for p in sorted(path.rglob("*"))
                if p.is_file()
                and not SKIP_PARTS.intersection(p.parts)
                and p.suffix not in SKIP_SUFFIXES
                and not p.name.startswith(SKIP_PREFIXES)
            )
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in TARGETS:
        print(f"usage: python aws/package.py {{{'|'.join(TARGETS)}}}")
        return 2
    target = argv[1]
    dist = ROOT / "aws" / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / "release.zip"
    files = files_to_package()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, path.relative_to(ROOT).as_posix())
        bundle.writestr("TARGET", target + "\n")
    print(f"{archive}  ({len(files) + 1} files, releasing '{target}')")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
