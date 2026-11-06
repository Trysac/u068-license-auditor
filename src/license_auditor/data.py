"""Bundled license data.

Sources: https://spdx.org/licenses (SPDX license list) and https://pypi.org/classifiers
(trove classifiers). Checked on 2026-11-05. Only the entries below are known; every
other well-formed identifier is kept verbatim by the parser.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

LICENSE_IDS: tuple[str, ...] = (
    "0BSD",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "EPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
)

EXCEPTION_IDS: tuple[str, ...] = ("Classpath-exception-2.0", "LLVM-exception")

_DEPRECATED = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
}

_FREE_TEXT = {
    "MIT License": "MIT",
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
}

CLASSIFIER_PREFIX = "License :: OSI Approved :: "

_CLASSIFIER_SUFFIXES = {
    "MIT License": "MIT",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
}

_CLASSIFIERS = {CLASSIFIER_PREFIX + k: v for k, v in _CLASSIFIER_SUFFIXES.items()}

DEPRECATED_IDS: Mapping[str, str] = MappingProxyType(_DEPRECATED)
FREE_TEXT_ALIASES: Mapping[str, str] = MappingProxyType(_FREE_TEXT)
CLASSIFIER_LICENSES: Mapping[str, str] = MappingProxyType(_CLASSIFIERS)

_LICENSES_LOWER = {value.lower(): value for value in LICENSE_IDS}
_EXCEPTIONS_LOWER = {value.lower(): value for value in EXCEPTION_IDS}
_DEPRECATED_LOWER = {key.lower(): value for key, value in _DEPRECATED.items()}
_ALIASES_FOLDED = {key.casefold(): value for key, value in _FREE_TEXT.items()}


def canonical_license_id(raw: str, plus: bool) -> tuple[str, bool]:
    """Return the canonical id and the or-later flag for ``raw`` (with ``+`` already removed).

    Known ids match case-insensitively and get canonical casing. Deprecated ids mean
    ``-only``, and with ``+`` they mean ``-or-later``. Other ids are returned verbatim.
    """
    key = raw.lower()
    base = _DEPRECATED_LOWER.get(key)
    if base is not None:
        if plus:
            return base.removesuffix("-only") + "-or-later", False
        return base, False
    return _LICENSES_LOWER.get(key, raw), plus


def canonical_exception_id(raw: str) -> str:
    """Return the canonical casing of a known license exception id, else ``raw``."""
    return _EXCEPTIONS_LOWER.get(raw.lower(), raw)


def alias_license(text: str) -> str | None:
    """Return the SPDX id for a known free-text license name, else ``None``."""
    return _ALIASES_FOLDED.get(" ".join(text.split()).casefold())


def classifier_license(classifier: str) -> str | None:
    """Return the SPDX id for an unambiguous trove classifier, else ``None``."""
    return CLASSIFIER_LICENSES.get(classifier)
