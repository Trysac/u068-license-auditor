"""Policy model and the audit engine."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import islice
from typing import Literal

from .errors import LicenseAuditError, LicenseExpressionError, clip
from .expression import And, LicenseExpr, Term, With, parse_expression, parse_license_text
from .packages import CLASSIFIER_SOURCE, Package, normalize_name, resolve_classifiers, safe_text

MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_ENTRIES = 10_000
MAX_REASON_LENGTH = 500
MAX_AUDIT_PACKAGES = 100_000

Status = Literal["allowed", "denied", "unknown", "exception"]

_POLICY_KEYS = frozenset({"allow", "deny", "exceptions", "unknown", "classifier_overrides"})
_STATUS_ORDER = ("allowed", "denied", "unknown", "exception")


def _normalize_entries(entries: object, field_name: str) -> list[str]:
    if not isinstance(entries, list | tuple):
        raise LicenseAuditError("invalid_policy", f"{field_name} must be a list")
    if len(entries) > MAX_POLICY_ENTRIES:
        raise LicenseAuditError("too_large", f"{field_name} has too many entries")
    result: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            raise LicenseAuditError("invalid_policy", f"{field_name} entries must be strings")
        try:
            expr = parse_expression(entry)
        except LicenseExpressionError as exc:
            raise LicenseAuditError(
                "invalid_policy",
                f"invalid {field_name} entry: {exc.message}",
            ) from exc
        if not isinstance(expr, Term | With):
            raise LicenseAuditError(
                "invalid_policy",
                f"{field_name} entries must be an id or a WITH compound",
            )
        text = str(expr)
        if text not in result:
            result.append(text)
    return result


def _normalize_exceptions(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise LicenseAuditError("invalid_policy", "exceptions must be an object")
    if len(value) > MAX_POLICY_ENTRIES:
        raise LicenseAuditError("too_large", "exceptions has too many entries")
    result: dict[str, str] = {}
    for name, reason in value.items():
        if not isinstance(name, str) or not name.strip():
            raise LicenseAuditError("invalid_policy", "exception names must be strings")
        if not isinstance(reason, str) or not reason.strip():
            raise LicenseAuditError("invalid_policy", "exception reasons must be text")
        if len(reason) > MAX_REASON_LENGTH:
            raise LicenseAuditError("invalid_policy", "exception reason is too long")
        result[normalize_name(name)] = reason
    return result


def _normalize_overrides(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise LicenseAuditError("invalid_policy", "classifier_overrides must be an object")
    if len(value) > MAX_POLICY_ENTRIES:
        raise LicenseAuditError("too_large", "classifier_overrides has too many entries")
    result: dict[str, str] = {}
    for classifier, text in value.items():
        if not isinstance(classifier, str) or not isinstance(text, str):
            raise LicenseAuditError("invalid_policy", "classifier_overrides must map text")
        if not classifier.strip():
            raise LicenseAuditError("invalid_policy", "classifier names must not be empty")
        try:
            result[classifier] = str(parse_license_text(text))
        except LicenseExpressionError as exc:
            raise LicenseAuditError(
                "invalid_policy",
                f"invalid classifier override: {exc.message}",
            ) from exc
    return result


@dataclass(frozen=True)
class Policy:
    """An allowlist policy.

    ``allow`` and ``deny`` hold license ids or ``WITH`` compounds (normalised on
    construction); an id listed in both raises ``invalid_policy``. ``exceptions`` maps a
    package name to the reason it is accepted. ``unknown`` decides whether packages without
    usable license data fail the check. ``classifier_overrides`` maps a License classifier
    (full text or the part after ``License :: OSI Approved :: ``) to an SPDX expression.
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    exceptions: dict[str, str] = field(default_factory=dict)
    unknown: Literal["fail", "warn"] = "fail"
    classifier_overrides: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        allow = _normalize_entries(self.allow, "allow")
        deny = _normalize_entries(self.deny, "deny")
        both = sorted(set(allow) & set(deny))
        if both:
            raise LicenseAuditError(
                "invalid_policy",
                f"{clip(both[0])!r} is listed in both allow and deny",
            )
        if self.unknown not in ("fail", "warn"):
            raise LicenseAuditError("invalid_policy", "unknown must be 'fail' or 'warn'")
        object.__setattr__(self, "allow", allow)
        object.__setattr__(self, "deny", deny)
        object.__setattr__(self, "exceptions", _normalize_exceptions(self.exceptions))
        overrides = _normalize_overrides(self.classifier_overrides)
        object.__setattr__(self, "classifier_overrides", overrides)

    @classmethod
    def from_json(cls, text: str) -> Policy:
        """Build a policy from JSON text (at most 1 MiB).

        Raises:
            LicenseAuditError: ``invalid_policy`` for malformed or inconsistent policies,
                ``too_large`` above the size limits.
        """
        if not isinstance(text, str):
            raise LicenseAuditError("invalid_policy", "policy must be a JSON string")
        if len(text.encode("utf-8", "surrogatepass")) > MAX_POLICY_BYTES:
            raise LicenseAuditError("too_large", f"policy is larger than {MAX_POLICY_BYTES} bytes")
        try:
            data = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise LicenseAuditError("invalid_policy", "policy is not valid JSON") from exc
        if not isinstance(data, dict):
            raise LicenseAuditError("invalid_policy", "policy must be a JSON object")
        extra = sorted(set(data) - _POLICY_KEYS)
        if extra:
            raise LicenseAuditError(
                "invalid_policy",
                f"unknown policy key {clip(extra[0])!r}",
            )
        return cls(
            allow=data.get("allow", []),
            deny=data.get("deny", []),
            exceptions=data.get("exceptions", {}),
            unknown=data.get("unknown", "fail"),
            classifier_overrides=data.get("classifier_overrides", {}),
        )


@dataclass(frozen=True)
class Result:
    """The audit outcome of one package."""

    package: Package
    status: Status
    reason: str


def _format_result(result: Result) -> str:
    package = result.package
    name = safe_text(package.name)
    version = safe_text(package.version)
    license_text = safe_text(package.license or "no license")
    reason = safe_text(result.reason)
    return f"{result.status.upper()} {name} {version} ({license_text}): {reason}"


@dataclass(frozen=True)
class AuditReport:
    """The results of an audit."""

    results: list[Result]
    unknown: Literal["fail", "warn"] = "fail"

    def _ordered(self) -> list[Result]:
        return sorted(self.results, key=lambda r: (r.package.name, r.package.version))

    def counts(self) -> dict[str, int]:
        """Return the number of results per status."""
        counts = dict.fromkeys(_STATUS_ORDER, 0)
        for result in self.results:
            counts[result.status] += 1
        return counts

    @property
    def ok(self) -> bool:
        """``False`` if any package is denied, or unknown while unknown is ``fail``."""
        counts = self.counts()
        if counts["denied"]:
            return False
        return not (counts["unknown"] and self.unknown == "fail")

    def to_text(self) -> str:
        """Render a plain-text report ordered by package name."""
        lines = [_format_result(result) for result in self._ordered()]
        counts = self.counts()
        summary = ", ".join(f"{counts[key]} {key}" for key in _STATUS_ORDER)
        lines.append(f"Summary: {summary}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """Render JSON with sorted keys and indent 2, results ordered by package name."""
        payload: dict[str, object] = {
            "results": [
                {
                    "license": result.package.license,
                    "name": result.package.name,
                    "reason": result.reason,
                    "status": result.status,
                    "version": result.package.version,
                }
                for result in self._ordered()
            ],
            "summary": self.counts(),
        }
        return json.dumps(payload, sort_keys=True, indent=2)


def _keys(leaf: Term | With) -> list[str]:
    if isinstance(leaf, With):
        return [str(leaf), *_keys(leaf.term)]
    return [str(leaf), leaf.id] if leaf.or_later else [str(leaf)]


def _term_allowed(term: Term, allow: frozenset[str], deny: frozenset[str]) -> bool:
    keys = _keys(term)
    if any(key in deny for key in keys):
        return False
    return any(key in allow for key in keys)


def _allowed(expr: LicenseExpr, allow: frozenset[str], deny: frozenset[str]) -> bool:
    if isinstance(expr, Term):
        return _term_allowed(expr, allow, deny)
    if isinstance(expr, With):
        compound = str(expr)
        if compound in deny:
            return False
        return compound in allow or _term_allowed(expr.term, allow, deny)
    if isinstance(expr, And):
        return all(_allowed(item, allow, deny) for item in expr.operands)
    return any(_allowed(item, allow, deny) for item in expr.operands)


def _leaves(expr: LicenseExpr) -> Iterator[Term | With]:
    if isinstance(expr, Term | With):
        yield expr
    else:
        for item in expr.operands:
            yield from _leaves(item)


def _resolve(package: Package, policy: Policy) -> tuple[LicenseExpr | None, str]:
    if package.source.startswith(CLASSIFIER_SOURCE):
        names = package.source[len(CLASSIFIER_SOURCE) :].split("|")
        expr = resolve_classifiers([name for name in names if name], policy.classifier_overrides)
        if expr is None:
            return None, "ambiguous classifier"
        return expr, ""
    if package.license is None or not package.license.strip():
        return None, "no license data"
    try:
        return parse_license_text(package.license), ""
    except LicenseExpressionError:
        return None, "unparseable license expression"


def _audit_one(
    package: Package,
    policy: Policy,
    allow: frozenset[str],
    deny: frozenset[str],
) -> Result:
    excused = policy.exceptions.get(package.name)
    if excused is not None:
        return Result(package, "exception", excused)
    expr, problem = _resolve(package, policy)
    if expr is None:
        return Result(package, "unknown", problem)
    if _allowed(expr, allow, deny):
        return Result(package, "allowed", "allowed by policy")
    denied = any(key in deny for leaf in _leaves(expr) for key in _keys(leaf))
    return Result(package, "denied", "in deny list" if denied else "not in allow list")


def audit(packages: Iterable[Package], policy: Policy) -> AuditReport:
    """Evaluate ``packages`` against ``policy``.

    A term is allowed only if it is in ``allow`` and not in ``deny``. ``X WITH E`` is allowed
    if the compound is allowed, or ``X`` is allowed and the compound is not denied. ``X+`` is
    allowed if ``X+`` or ``X`` is allowed. ``AND`` needs every operand, ``OR`` one. Packages
    under ``exceptions`` get status ``exception``; packages without usable license data are
    ``unknown``.

    Raises:
        LicenseAuditError: ``too_large`` if more than 100000 packages are given.
    """
    items = list(islice(packages, MAX_AUDIT_PACKAGES + 1))
    if len(items) > MAX_AUDIT_PACKAGES:
        raise LicenseAuditError("too_large", "too many packages to audit")
    allow = frozenset(policy.allow)
    deny = frozenset(policy.deny)
    results = [_audit_one(item, policy, allow, deny) for item in items]
    results.sort(key=lambda result: (result.package.name, result.package.version))
    return AuditReport(results=results, unknown=policy.unknown)
