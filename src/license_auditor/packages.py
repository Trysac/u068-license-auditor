"""Package inventory: installed distributions and JSON inventory files."""

from __future__ import annotations

import importlib.metadata
import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageMetadata
from pathlib import Path

from .data import CLASSIFIER_PREFIX, classifier_license
from .errors import ErrorCode, LicenseAuditError, LicenseExpressionError
from .expression import And, LicenseExpr, parse_expression, parse_license_text

logger = logging.getLogger(__name__)

MAX_INVENTORY_BYTES = 10 * 1024 * 1024
MAX_INVENTORY_ENTRIES = 100_000
MAX_LICENSE_FIELD = 200
MAX_NAME_LENGTH = 200
CLASSIFIER_SOURCE = "classifiers:"

_SEPARATORS = re.compile("[-_.]+")
_LICENSE_CLASSIFIER = "License ::"


def normalize_name(name: str) -> str:
    """Return ``name`` normalised per PEP 503."""
    return _SEPARATORS.sub("-", name).lower()


def safe_text(text: str, limit: int = 200) -> str:
    """Return ``text`` cut to ``limit`` characters, non-printable ones replaced."""
    return "".join(char if char.isprintable() else "?" for char in text[:limit])


@dataclass(frozen=True)
class Package:
    """A package and its license data.

    ``name`` is normalised per PEP 503 on construction. ``license`` is the license text or
    expression (``None`` when unknown). ``source`` records where the license came from;
    values starting with ``classifiers:`` carry the package's License classifiers.
    """

    name: str
    version: str
    license: str | None = None
    source: str = "inventory"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_name(self.name))


def read_text_limited(path: Path, limit: int, code: ErrorCode, label: str) -> str:
    """Read a UTF-8 file of at most ``limit`` bytes.

    Raises:
        LicenseAuditError: ``too_large`` above the limit, otherwise ``code`` if unreadable.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise LicenseAuditError(code, f"cannot read {label}") from exc
    if len(data) > limit:
        raise LicenseAuditError("too_large", f"{label} is larger than {limit} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LicenseAuditError(code, f"{label} is not valid UTF-8") from exc


def _classifier_text(classifier: str, overrides: Mapping[str, str] | None) -> str | None:
    if overrides:
        for key in (classifier, classifier.removeprefix(CLASSIFIER_PREFIX)):
            if key in overrides:
                return overrides[key]
    return classifier_license(classifier)


def resolve_classifiers(
    classifiers: Sequence[str],
    overrides: Mapping[str, str] | None = None,
) -> LicenseExpr | None:
    """Map License classifiers to one expression (several are combined with AND).

    Returns ``None`` when there is no classifier or any of them is ambiguous.
    """
    exprs: list[LicenseExpr] = []
    for classifier in classifiers:
        text = _classifier_text(classifier, overrides)
        if text is None:
            return None
        try:
            exprs.append(parse_license_text(text))
        except LicenseExpressionError:
            return None
    if not exprs:
        return None
    return exprs[0] if len(exprs) == 1 else And(tuple(exprs))


def _header(meta: PackageMetadata, key: str) -> str | None:
    if key not in meta:
        return None
    value = meta[key]
    return value.strip() if isinstance(value, str) else None


def _looks_like_id(text: str) -> bool:
    if len(text) > MAX_LICENSE_FIELD or "\n" in text:
        return False
    return text.casefold() != "unknown"


def _license_classifiers(meta: PackageMetadata) -> list[str]:
    values = meta.get_all("Classifier") or []
    found = {value.strip() for value in values if isinstance(value, str)}
    return sorted(v for v in found if v.startswith(_LICENSE_CLASSIFIER) and "|" not in v)


def _license_from_metadata(meta: PackageMetadata) -> tuple[str | None, str]:
    expression = _header(meta, "License-Expression")
    if expression:
        try:
            return str(parse_expression(expression)), "license-expression"
        except LicenseExpressionError:
            logger.debug("ignoring unparseable License-Expression")
    text = _header(meta, "License")
    if text and _looks_like_id(text):
        try:
            return str(parse_license_text(text)), "license"
        except LicenseExpressionError:
            logger.debug("License field is free text")
    classifiers = _license_classifiers(meta)
    if classifiers:
        expr = resolve_classifiers(classifiers)
        license_text = str(expr) if expr is not None else None
        return license_text, CLASSIFIER_SOURCE + "|".join(classifiers)
    return None, "none"


def _from_distribution(dist: importlib.metadata.Distribution) -> Package | None:
    meta = dist.metadata
    if meta is None:
        return None
    name = _header(meta, "Name")
    if not name:
        logger.debug("skipping distribution without a name")
        return None
    version = _header(meta, "Version") or ""
    license_text, source = _license_from_metadata(meta)
    return Package(name, version, license_text, source)


def collect_installed(paths: Sequence[str] | None = None) -> list[Package]:
    """Collect installed distributions and their licenses, sorted by name.

    The license is taken from the PEP 639 ``License-Expression`` field, else a ``License``
    field that is an expression or a known free-text name (a field over 200 characters is
    text, not an id), else the mapped License classifiers (several combine with AND), else
    ``None``. When the same name appears on several paths the first one wins.

    Raises:
        LicenseAuditError: ``too_large`` if more than 100000 distributions are found.
    """
    if paths is None:
        dists = importlib.metadata.distributions()
    else:
        dists = importlib.metadata.distributions(path=list(paths))
    found: dict[str, Package] = {}
    for dist in dists:
        package = _from_distribution(dist)
        if package is None or package.name in found:
            continue
        found[package.name] = package
        if len(found) > MAX_INVENTORY_ENTRIES:
            raise LicenseAuditError("too_large", "too many installed distributions")
    return sorted(found.values(), key=lambda item: (item.name, item.version))


def _inventory_entry(index: int, item: object) -> Package:
    if not isinstance(item, dict):
        raise LicenseAuditError("invalid_inventory", f"entry {index} must be an object")
    name = item.get("name")
    version = item.get("version")
    license_text = item.get("license")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_LENGTH:
        raise LicenseAuditError("invalid_inventory", f"entry {index} has an invalid name")
    if not isinstance(version, str):
        raise LicenseAuditError("invalid_inventory", f"entry {index} has an invalid version")
    if license_text is not None and not isinstance(license_text, str):
        raise LicenseAuditError("invalid_inventory", f"entry {index} has an invalid license")
    if license_text is not None and not license_text.strip():
        license_text = None
    return Package(name, version, license_text, "inventory")


def load_inventory(path: Path) -> list[Package]:
    """Read a JSON list of ``{name, version, license}`` objects.

    Limits: 10 MiB and 100000 entries.

    Raises:
        LicenseAuditError: ``invalid_inventory`` for unreadable or malformed input,
            ``too_large`` above the limits.
    """
    text = read_text_limited(path, MAX_INVENTORY_BYTES, "invalid_inventory", "inventory")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise LicenseAuditError("invalid_inventory", "inventory is not valid JSON") from exc
    if not isinstance(data, list):
        raise LicenseAuditError("invalid_inventory", "inventory must be a JSON list")
    if len(data) > MAX_INVENTORY_ENTRIES:
        raise LicenseAuditError("too_large", "inventory has too many entries")
    packages = [_inventory_entry(index, item) for index, item in enumerate(data)]
    return sorted(packages, key=lambda item: (item.name, item.version))
