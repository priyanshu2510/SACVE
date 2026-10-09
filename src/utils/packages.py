"""Package-name helpers shared by context assembly and reachability analysis."""

from __future__ import annotations

import re

# Distribution name -> import name for pip packages whose top-level module differs.
_PIP_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "python-dateutil": ("dateutil",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "protobuf": ("google.protobuf",),
    "python-jose": ("jose",),
    "pyjwt": ("jwt",),
    "msgpack-python": ("msgpack",),
    "attrs": ("attr", "attrs"),
    "setuptools": ("setuptools", "pkg_resources"),
}


def normalise_pip_name(name: str) -> str:
    """PEP 503 normalisation (``Foo_Bar.baz`` -> ``foo-bar-baz``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def import_names(ecosystem: str, package: str) -> list[str]:
    """Candidate module / import names for a package (best effort, ordered most-likely first)."""
    if ecosystem == "pip":
        norm = normalise_pip_name(package)
        names = [*_PIP_IMPORT_ALIASES.get(norm, ()), norm.replace("-", "_")]
        return list(dict.fromkeys(names))
    if ecosystem == "maven":
        group = package.split(":", 1)[0]
        return [group]
    return [package]


def declared_in_manifest(manifest_text: str, package: str) -> bool:
    """True if ``package`` is named directly in a pip manifest (requirements / pyproject / setup)."""
    parts = [re.escape(p) for p in re.split(r"[-_.]+", package) if p]
    if not parts:
        return False
    pattern = r"[-_.]+".join(parts)
    uncommented = re.sub(r"(?m)#.*$", "", manifest_text)  # a commented-out requirement is not a declaration
    return bool(re.search(rf"(?im)(?:^|[\s\"',\[])({pattern})(?=$|[\s<>=!~\[;\"',])", uncommented))
