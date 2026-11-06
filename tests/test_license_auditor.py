"""Tests for the license_auditor public API and command-line interface."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from license_auditor import (
    And,
    AuditReport,
    LicenseAuditError,
    LicenseExpressionError,
    Or,
    Package,
    Policy,
    Result,
    Term,
    With,
    audit,
    collect_installed,
    load_inventory,
    parse_expression,
)
from license_auditor.__main__ import main
from license_auditor.data import alias_license
from license_auditor.expression import parse_license_text

MIT_CLASSIFIER = "License :: OSI Approved :: MIT License"
ISC_CLASSIFIER = "License :: OSI Approved :: ISC License (ISCL)"
BSD_CLASSIFIER = "License :: OSI Approved :: BSD License"
APACHE_CLASSIFIER = "License :: OSI Approved :: Apache Software License"
COMPOUND = "GPL-2.0-only WITH Classpath-exception-2.0"

GOLDEN = "\n".join(
    [
        "{",
        '  "results": [',
        "    {",
        '      "license": "Apache-2.0",',
        '      "name": "alpha",',
        '      "reason": "not in allow list",',
        '      "status": "denied",',
        '      "version": "1.0"',
        "    },",
        "    {",
        '      "license": "MIT",',
        '      "name": "zeta",',
        '      "reason": "allowed by policy",',
        '      "status": "allowed",',
        '      "version": "2.0"',
        "    }",
        "  ],",
        '  "summary": {',
        '    "allowed": 1,',
        '    "denied": 1,',
        '    "exception": 0,',
        '    "unknown": 0',
        "  }",
        "}",
        "",
    ]
)


def make_dist(root: Path, name: str, version: str = "1.0", *headers: str) -> None:
    dist = root / f"{name}-{version}.dist-info"
    dist.mkdir()
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}", *headers]
    (dist / "METADATA").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def pkg(license_text: str | None, name: str = "demo") -> Package:
    return Package(name, "1.0", license_text, "inventory")


def verdict(expression: str, allow: list[str], deny: list[str] | None = None) -> Result:
    policy = Policy(allow=allow, deny=deny or [])
    return audit([pkg(expression)], policy).results[0]


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- expression parser -------------------------------------------------------------


def test_lowercase_id_is_canonicalised() -> None:
    assert str(parse_expression("mit")) == "MIT"


def test_plus_on_deprecated_id_reads_or_later() -> None:
    assert str(parse_expression("GPL-2.0+")) == "GPL-2.0-or-later"
    assert str(parse_expression("lgpl-2.1+")) == "LGPL-2.1-or-later"


def test_deprecated_id_reads_only() -> None:
    assert str(parse_expression("GPL-3.0")) == "GPL-3.0-only"
    assert str(parse_expression("AGPL-3.0")) == "AGPL-3.0-only"


def test_plus_on_other_ids_is_kept() -> None:
    assert parse_expression("MIT+") == Term("MIT", True)
    assert str(parse_expression("Foo-1.0+")) == "Foo-1.0+"


def test_operator_adjacent_to_parenthesis_parses() -> None:
    expr = parse_expression("MIT OR(Apache-2.0)")
    assert expr == Or((Term("MIT"), Term("Apache-2.0")))


def test_license_ref_parses() -> None:
    assert parse_expression("LicenseRef-acme.1") == Term("LicenseRef-acme.1")


def test_precedence_and_over_or() -> None:
    expr = parse_expression("MIT OR Apache-2.0 AND BSD-3-Clause")
    assert expr == Or((Term("MIT"), And((Term("Apache-2.0"), Term("BSD-3-Clause")))))


def test_parentheses_round_trip() -> None:
    text = "(MIT OR Apache-2.0) AND BSD-3-Clause"
    expr = parse_expression(text)
    assert isinstance(expr, And)
    assert str(expr) == text


def test_with_expression_canonicalises_exception() -> None:
    expr = parse_expression("GPL-2.0 WITH classpath-exception-2.0")
    assert expr == With(Term("GPL-2.0-only"), "Classpath-exception-2.0")
    assert str(expr) == COMPOUND


def test_nesting_of_32_parses() -> None:
    assert parse_expression("(" * 32 + "MIT" + ")" * 32) == Term("MIT")


def test_dangling_operator_reports_position() -> None:
    with pytest.raises(LicenseExpressionError) as info:
        parse_expression("MIT AND OR")
    assert info.value.code == "invalid_expression"
    assert info.value.position == 9


BAD_EXPRESSIONS = [
    "MIT and Apache-2.0",
    "MIT, Apache-2.0",
    "A" * 1001,
    "(" * 33 + "MIT" + ")" * 33,
    "",
    "   ",
    "(MIT",
    "MIT)",
    "()",
    "MIT AND",
    "MIT WITH",
    "(MIT) WITH Classpath-exception-2.0",
    "MIT WITH A WITH B",
    "MIT WITH Foo+",
    "MIT WITH AND",
    "LicenseRef-",
    "LicenseRef-a_b",
    "MIT OR OR ISC",
    "+",
    "MIT (ISC)",
    "and",
    "MIT\u00a0OR ISC",
    "MIT AND (ISC OR) ",
    "MIT AND (",
]


@pytest.mark.parametrize("text", BAD_EXPRESSIONS)
def test_invalid_expressions_raise(text: str) -> None:
    with pytest.raises(LicenseExpressionError) as info:
        parse_expression(text)
    assert info.value.code == "invalid_expression"
    assert info.value.position >= 1
    assert len(info.value.message) <= 200


def test_non_string_expression_raises() -> None:
    with pytest.raises(LicenseExpressionError):
        parse_expression(5)  # type: ignore[arg-type]


def test_long_garbage_word_message_is_short() -> None:
    with pytest.raises(LicenseExpressionError) as info:
        parse_expression("!" * 500)
    assert len(info.value.message) <= 200
    assert str(info.value) == info.value.message


def test_base_error_truncates_message() -> None:
    error = LicenseAuditError("too_large", "x" * 500)
    assert error.code == "too_large"
    assert len(error.message) == 200


# --- data and free text ------------------------------------------------------------


def test_free_text_aliases() -> None:
    assert alias_license("MIT License") == "MIT"
    assert alias_license("Apache 2.0") == "Apache-2.0"
    assert alias_license("apache  license 2.0") == "Apache-2.0"
    assert alias_license("Some License") is None
    assert str(parse_license_text("Apache License 2.0")) == "Apache-2.0"
    assert str(parse_license_text("ISC")) == "ISC"


# --- evaluation --------------------------------------------------------------------


def test_mit_is_allowed_and_apache_is_denied() -> None:
    assert verdict("mit", ["MIT"]).status == "allowed"
    result = verdict("Apache-2.0", ["MIT"])
    assert (result.status, result.reason) == ("denied", "not in allow list")


def test_or_and_and_semantics() -> None:
    assert verdict("MIT OR GPL-3.0-only", ["MIT"]).status == "allowed"
    assert verdict("MIT AND GPL-3.0-only", ["MIT"]).status == "denied"


def test_parentheses_are_respected() -> None:
    expr = "(MIT OR Apache-2.0) AND BSD-3-Clause"
    assert verdict(expr, ["MIT", "BSD-3-Clause"]).status == "allowed"
    assert verdict(expr, ["Apache-2.0", "BSD-3-Clause"]).status == "allowed"
    assert verdict(expr, ["MIT", "Apache-2.0"]).status == "denied"
    assert verdict("MIT OR Apache-2.0 AND BSD-3-Clause", ["MIT"]).status == "allowed"


def test_or_later_semantics() -> None:
    assert verdict("GPL-2.0+", ["GPL-2.0-or-later"]).status == "allowed"
    assert verdict("GPL-2.0+", ["GPL-2.0-only"]).status == "denied"
    assert verdict("MIT+", ["MIT"]).status == "allowed"
    assert verdict("MIT+", ["MIT+"]).status == "allowed"
    assert verdict("MIT+", ["MIT"], ["MIT+"]).status == "denied"


def test_with_allowed_by_compound_or_by_base() -> None:
    assert verdict(COMPOUND, [COMPOUND]).status == "allowed"
    assert verdict(COMPOUND, ["GPL-2.0-only"]).status == "allowed"


def test_with_denied_cases() -> None:
    result = verdict(COMPOUND, ["MIT"], ["GPL-2.0-only"])
    assert (result.status, result.reason) == ("denied", "in deny list")
    assert verdict(COMPOUND, ["GPL-2.0-only"], [COMPOUND]).status == "denied"
    assert verdict(COMPOUND, [COMPOUND], ["GPL-2.0-only"]).status == "allowed"
    assert verdict(COMPOUND, ["MIT"]).status == "denied"


def test_deny_reason_inside_compound_expression() -> None:
    result = verdict("GPL-3.0-only AND MIT", ["MIT"], ["GPL-3.0-only"])
    assert (result.status, result.reason) == ("denied", "in deny list")


def test_unbundled_id_is_verbatim_and_exact() -> None:
    assert verdict("Foo-1.0", ["Foo-1.0"]).status == "allowed"
    assert verdict("Foo-1.0", ["MIT"]).status == "denied"
    assert verdict("foo-1.0", ["Foo-1.0"]).status == "denied"


def test_neighbouring_ids_do_not_match() -> None:
    assert verdict("MIT-0", ["MIT"]).status == "denied"
    assert verdict("MITX", ["MIT"]).status == "denied"
    assert verdict("LicenseRef-acme.1", ["LicenseRef-acme.1"]).status == "allowed"


def test_license_text_aliases_are_audited() -> None:
    assert verdict("Apache License 2.0", ["Apache-2.0"]).status == "allowed"


def test_missing_and_unparseable_licenses_are_unknown() -> None:
    policy = Policy(allow=["MIT"])
    results = audit([pkg(None, "a"), pkg("  ", "b"), pkg("not a license!", "c")], policy).results
    assert [r.status for r in results] == ["unknown", "unknown", "unknown"]
    assert [r.reason for r in results] == [
        "no license data",
        "no license data",
        "unparseable license expression",
    ]


def test_exceptions_override_everything() -> None:
    policy = Policy(allow=[], exceptions={"foo.bar": "approved by legal"})
    package = Package("Foo_Bar", "1.0", "GPL-3.0-only", "inventory")
    result = audit([package], policy).results[0]
    assert (result.status, result.reason) == ("exception", "approved by legal")
    unlicensed = Package("foo-bar", "1.0", None, "none")
    assert audit([unlicensed], policy).results[0].status == "exception"


def test_audit_accepts_generators_and_sorts() -> None:
    packages = (pkg("MIT", name) for name in ["b", "a"])
    report = audit(packages, Policy(allow=["MIT"]))
    assert isinstance(report, AuditReport)
    assert [r.package.name for r in report.results] == ["a", "b"]


def test_audit_rejects_too_many_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("license_auditor.policy.MAX_AUDIT_PACKAGES", 1)
    with pytest.raises(LicenseAuditError) as info:
        audit([pkg("MIT", "a"), pkg("MIT", "b")], Policy())
    assert info.value.code == "too_large"


def test_package_is_frozen_and_normalised() -> None:
    package = Package("Foo_Bar", "1.0")
    assert package.name == "foo-bar"
    with pytest.raises(AttributeError):
        package.name = "x"  # type: ignore[misc]


# --- reports -----------------------------------------------------------------------


def test_text_report() -> None:
    packages = [pkg("MIT", "b"), pkg("ISC", "a")]
    packages = [Package("b", "2", "MIT", "inventory"), Package("a", "1", "ISC", "inventory")]
    report = audit(packages, Policy(allow=["MIT"]))
    assert report.to_text().splitlines() == [
        "DENIED a 1 (ISC): not in allow list",
        "ALLOWED b 2 (MIT): allowed by policy",
        "Summary: 1 allowed, 1 denied, 0 unknown, 0 exception",
    ]


def test_text_report_strips_control_characters() -> None:
    report = audit([pkg("MIT\x1b[0m")], Policy(allow=["MIT"]))
    assert "\x1b" not in report.to_text()


def test_report_ok_depends_on_unknown_mode() -> None:
    unknown = pkg(None)
    assert not audit([unknown], Policy(unknown="fail")).ok
    assert audit([unknown], Policy(unknown="warn")).ok
    assert not audit([pkg("MIT")], Policy(allow=["ISC"], unknown="warn")).ok
    assert audit([pkg("MIT")], Policy(allow=["MIT"])).ok
    assert audit([], Policy()).to_text() == "Summary: 0 allowed, 0 denied, 0 unknown, 0 exception"


# --- policy ------------------------------------------------------------------------


def test_policy_from_json_normalises() -> None:
    policy = Policy.from_json('{"allow": ["mit", "GPL-3.0"], "unknown": "warn"}')
    assert policy.allow == ["MIT", "GPL-3.0-only"]
    assert policy.unknown == "warn"
    assert Policy.from_json("{}").unknown == "fail"


def test_policy_with_mit_in_allow_and_deny_is_invalid() -> None:
    with pytest.raises(LicenseAuditError) as info:
        Policy.from_json('{"allow": ["MIT"], "deny": ["MIT"]}')
    assert info.value.code == "invalid_policy"
    with pytest.raises(LicenseAuditError):
        Policy(allow=["MIT"], deny=["mit"])


BAD_POLICIES = [
    "not json",
    "[]",
    '{"unexpected": 1}',
    '{"allow": "MIT"}',
    '{"allow": [1]}',
    '{"allow": ["MIT,"]}',
    '{"allow": ["MIT AND ISC"]}',
    '{"unknown": "maybe"}',
    '{"exceptions": []}',
    '{"exceptions": {"a": 1}}',
    '{"exceptions": {"a": ""}}',
    '{"exceptions": {"": "reason"}}',
    '{"exceptions": {"a": "' + "r" * 501 + '"}}',
    '{"classifier_overrides": []}',
    '{"classifier_overrides": {"X": "not valid("}}',
    '{"classifier_overrides": {"X": 1}}',
    '{"classifier_overrides": {" ": "MIT"}}',
    "[" * 100000,
]


@pytest.mark.parametrize("text", BAD_POLICIES)
def test_invalid_policies(text: str) -> None:
    with pytest.raises(LicenseAuditError) as info:
        Policy.from_json(text)
    assert info.value.code == "invalid_policy"


def test_policy_from_json_requires_text() -> None:
    with pytest.raises(LicenseAuditError) as info:
        Policy.from_json(5)  # type: ignore[arg-type]
    assert info.value.code == "invalid_policy"


def test_policy_size_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("license_auditor.policy.MAX_POLICY_ENTRIES", 1)
    for text in (
        '{"allow": ["MIT", "ISC"]}',
        '{"exceptions": {"a": "r", "b": "r"}}',
        '{"classifier_overrides": {"a": "MIT", "b": "MIT"}}',
    ):
        with pytest.raises(LicenseAuditError) as info:
            Policy.from_json(text)
        assert info.value.code == "too_large"
    monkeypatch.setattr("license_auditor.policy.MAX_POLICY_BYTES", 10)
    with pytest.raises(LicenseAuditError) as info:
        Policy.from_json('{"allow": []}')
    assert info.value.code == "too_large"


# --- installed distributions -------------------------------------------------------


def test_collect_installed_reads_pep_639_expression(tmp_path: Path) -> None:
    make_dist(tmp_path, "Foo_Bar", "1.0", "License-Expression: mit")
    found = collect_installed([str(tmp_path)])
    assert found == [Package("foo-bar", "1.0", "MIT", "license-expression")]


def test_collect_installed_sorts_by_name(tmp_path: Path) -> None:
    make_dist(tmp_path, "zeta", "1.0", "License-Expression: MIT")
    make_dist(tmp_path, "Alpha", "2.0", "License-Expression: ISC")
    assert [p.name for p in collect_installed([str(tmp_path)])] == ["alpha", "zeta"]


def test_license_field_variants(tmp_path: Path) -> None:
    make_dist(tmp_path, "apache", "1.0", "License: Apache 2.0")
    make_dist(tmp_path, "bsd", "1.0", "License: BSD")
    make_dist(tmp_path, "unknown", "1.0", "License: UNKNOWN")
    make_dist(tmp_path, "prose", "1.0", "License: GNU General Public License")
    make_dist(tmp_path, "long", "1.0", "License: " + "x" * 201)
    make_dist(tmp_path, "multi", "1.0", "License: MIT", " more text")
    found = {p.name: p for p in collect_installed([str(tmp_path)])}
    assert found["apache"].license == "Apache-2.0"
    assert found["apache"].source == "license"
    assert found["bsd"].license == "BSD"
    assert found["unknown"].license is None
    assert found["prose"].license is None
    assert found["long"].license is None
    assert found["multi"].license is None
    assert found["long"].source == "none"


def test_invalid_expression_header_falls_back(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0", "License-Expression: MIT and", "License: ISC")
    assert collect_installed([str(tmp_path)])[0].license == "ISC"


def test_classifier_maps_to_mit(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0", f"Classifier: {MIT_CLASSIFIER}")
    package = collect_installed([str(tmp_path)])[0]
    assert package.license == "MIT"
    assert audit([package], Policy(allow=["MIT"])).results[0].status == "allowed"


def test_ambiguous_classifier_is_unknown_unless_overridden(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0", f"Classifier: {APACHE_CLASSIFIER}")
    package = collect_installed([str(tmp_path)])[0]
    assert package.license is None
    result = audit([package], Policy(allow=["Apache-2.0"])).results[0]
    assert (result.status, result.reason) == ("unknown", "ambiguous classifier")
    overrides = {APACHE_CLASSIFIER: "Apache-2.0"}
    policy = Policy(allow=["Apache-2.0"], classifier_overrides=overrides)
    assert audit([package], policy).results[0].status == "allowed"
    suffix = {"Apache Software License": "Apache-2.0"}
    policy = Policy(allow=["Apache-2.0"], classifier_overrides=suffix)
    assert audit([package], policy).results[0].status == "allowed"


def test_bsd_classifier_is_ambiguous(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0", f"Classifier: {BSD_CLASSIFIER}")
    package = collect_installed([str(tmp_path)])[0]
    assert package.license is None
    assert audit([package], Policy(allow=["BSD-3-Clause"])).results[0].reason == (
        "ambiguous classifier"
    )


def test_several_classifiers_combine_with_and(tmp_path: Path) -> None:
    make_dist(
        tmp_path,
        "pkg",
        "1.0",
        f"Classifier: {MIT_CLASSIFIER}",
        f"Classifier: {ISC_CLASSIFIER}",
        "Classifier: Programming Language :: Python :: 3",
    )
    package = collect_installed([str(tmp_path)])[0]
    assert package.license == "ISC AND MIT"
    assert audit([package], Policy(allow=["MIT"])).results[0].status == "denied"
    assert audit([package], Policy(allow=["MIT", "ISC"])).results[0].status == "allowed"


def test_mixed_classifiers_need_every_one_resolved(tmp_path: Path) -> None:
    make_dist(
        tmp_path,
        "pkg",
        "1.0",
        f"Classifier: {MIT_CLASSIFIER}",
        f"Classifier: {BSD_CLASSIFIER}",
    )
    package = collect_installed([str(tmp_path)])[0]
    assert package.license is None
    allow = ["MIT", "BSD-3-Clause"]
    assert audit([package], Policy(allow=allow)).results[0].status == "unknown"
    overrides = {"BSD License": "BSD-3-Clause"}
    policy = Policy(allow=allow, classifier_overrides=overrides)
    assert audit([package], policy).results[0].status == "allowed"


def test_override_can_replace_builtin_mapping(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0", f"Classifier: {MIT_CLASSIFIER}")
    package = collect_installed([str(tmp_path)])[0]
    policy = Policy(allow=["ISC"], classifier_overrides={MIT_CLASSIFIER: "ISC"})
    assert audit([package], policy).results[0].status == "allowed"


def test_distribution_without_license_is_unknown(tmp_path: Path) -> None:
    make_dist(tmp_path, "pkg", "1.0")
    package = collect_installed([str(tmp_path)])[0]
    assert (package.license, package.source) == (None, "none")
    assert audit([package], Policy()).results[0].reason == "no license data"


def test_distribution_without_name_is_skipped(tmp_path: Path) -> None:
    dist = tmp_path / "ghost-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.4\nVersion: 1.0\n", encoding="utf-8")
    assert collect_installed([str(tmp_path)]) == []


def test_first_path_wins_for_duplicate_names(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    make_dist(first, "pkg", "1.0", "License-Expression: MIT")
    make_dist(second, "pkg", "2.0", "License-Expression: ISC")
    found = collect_installed([str(first), str(second)])
    assert [(p.version, p.license) for p in found] == [("1.0", "MIT")]


def test_collect_installed_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_dist(tmp_path, "a", "1.0")
    make_dist(tmp_path, "b", "1.0")
    monkeypatch.setattr("license_auditor.packages.MAX_INVENTORY_ENTRIES", 1)
    with pytest.raises(LicenseAuditError) as info:
        collect_installed([str(tmp_path)])
    assert info.value.code == "too_large"


def test_collect_installed_defaults() -> None:
    assert collect_installed([]) == []
    assert all(isinstance(p, Package) for p in collect_installed())


# --- inventory files ---------------------------------------------------------------


def test_load_inventory(tmp_path: Path) -> None:
    entries = [
        {"name": "Zeta_Pkg", "version": "2", "license": "MIT"},
        {"name": "alpha", "version": "1", "license": "  "},
    ]
    path = tmp_path / "inventory.json"
    write(path, json.dumps(entries))
    assert load_inventory(path) == [
        Package("alpha", "1", None, "inventory"),
        Package("zeta-pkg", "2", "MIT", "inventory"),
    ]


BAD_INVENTORIES = [
    "not json",
    "{}",
    "[1]",
    '[{"version": "1"}]',
    '[{"name": "a"}]',
    '[{"name": " ", "version": "1"}]',
    '[{"name": "a", "version": 1}]',
    '[{"name": "a", "version": "1", "license": 5}]',
    '[{"name": "' + "a" * 201 + '", "version": "1"}]',
    "[" * 100000,
]


@pytest.mark.parametrize("text", BAD_INVENTORIES)
def test_invalid_inventories(tmp_path: Path, text: str) -> None:
    path = tmp_path / "inventory.json"
    write(path, text)
    with pytest.raises(LicenseAuditError) as info:
        load_inventory(path)
    assert info.value.code == "invalid_inventory"


def test_unreadable_inventories(tmp_path: Path) -> None:
    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe")
    for path in (tmp_path / "missing.json", tmp_path, binary):
        with pytest.raises(LicenseAuditError) as info:
            load_inventory(path)
        assert info.value.code == "invalid_inventory"


def test_inventory_size_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "inventory.json"
    write(path, '[{"name": "a", "version": "1"}, {"name": "b", "version": "1"}]')
    monkeypatch.setattr("license_auditor.packages.MAX_INVENTORY_ENTRIES", 1)
    with pytest.raises(LicenseAuditError) as info:
        load_inventory(path)
    assert info.value.code == "too_large"
    monkeypatch.setattr("license_auditor.packages.MAX_INVENTORY_BYTES", 10)
    with pytest.raises(LicenseAuditError) as info:
        load_inventory(path)
    assert info.value.code == "too_large"


# --- command line ------------------------------------------------------------------


def golden_inputs(tmp_path: Path) -> tuple[str, str]:
    entries = [
        {"name": "Zeta", "version": "2.0", "license": "MIT"},
        {"name": "alpha", "version": "1.0", "license": "Apache-2.0"},
    ]
    policy = write(tmp_path / "policy.json", '{"allow": ["MIT"]}')
    inventory = write(tmp_path / "inventory.json", json.dumps(entries))
    return policy, inventory


def test_check_json_is_byte_exact(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy, inventory = golden_inputs(tmp_path)
    flag = "--format json"  # golden output for '--format json'
    argv = ["check", "--policy", policy, "--inventory", inventory, *flag.split()]
    code, out, _ = run(argv, capsys)
    assert code == 1
    assert out == GOLDEN


def test_check_exits_1_on_denied_in_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy, inventory = golden_inputs(tmp_path)
    code, out, _ = run(["check", "--policy", policy, "--inventory", inventory], capsys)
    assert code == 1
    assert "DENIED alpha 1.0 (Apache-2.0): not in allow list" in out


def test_check_exits_0_when_all_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = write(tmp_path / "policy.json", '{"allow": ["MIT"]}')
    inventory = write(
        tmp_path / "inventory.json", '[{"name": "a", "version": "1", "license": "MIT"}]'
    )
    code, out, _ = run(["check", "--policy", policy, "--inventory", inventory], capsys)
    assert code == 0
    assert "ALLOWED a 1 (MIT): allowed by policy" in out


@pytest.mark.parametrize(("mode", "expected"), [("fail", 1), ("warn", 0)])
def test_unknown_mode_controls_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, expected: int
) -> None:
    policy = write(tmp_path / "policy.json", json.dumps({"allow": ["MIT"], "unknown": mode}))
    inventory = write(tmp_path / "inventory.json", '[{"name": "a", "version": "1"}]')
    code, out, _ = run(["check", "--policy", policy, "--inventory", inventory], capsys)
    assert code == expected
    assert "UNKNOWN a 1 (no license): no license data" in out


def test_check_exits_2_for_conflicting_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = write(tmp_path / "policy.json", '{"allow": ["MIT"], "deny": ["MIT"]}')
    inventory = write(tmp_path / "inventory.json", "[]")
    code, _, err = run(["check", "--policy", policy, "--inventory", inventory], capsys)
    assert code == 2
    assert "invalid_policy" in err


def test_check_exits_2_for_input_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = write(tmp_path / "policy.json", "{}")
    bad = write(tmp_path / "bad.json", "nope")
    code, _, err = run(["check", "--policy", policy, "--inventory", bad], capsys)
    assert (code, "invalid_inventory" in err) == (2, True)
    code, _, err = run(["check", "--policy", str(tmp_path / "none.json")], capsys)
    assert (code, "invalid_policy" in err) == (2, True)
    monkeypatch.setattr("license_auditor.__main__.MAX_POLICY_BYTES", 1)
    code, _, err = run(["check", "--policy", policy], capsys)
    assert (code, "too_large" in err) == (2, True)


def test_usage_errors_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert run([], capsys)[0] == 2
    assert run(["check"], capsys)[0] == 2
    assert run(["list", "--format", "xml"], capsys)[0] == 2
    assert run(["--help"], capsys)[0] == 0


def test_list_text_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    entries = [{"name": "B_x", "version": "1", "license": "mit"}, {"name": "a", "version": "2"}]
    inventory = write(tmp_path / "inventory.json", json.dumps(entries))
    code, out, _ = run(["list", "--inventory", inventory], capsys)
    assert (code, out) == (0, "a 2 -\nb-x 1 mit\n")
    code, out, _ = run(["list", "--inventory", inventory, "--format", "json"], capsys)
    assert code == 0
    assert json.loads(out) == {
        "packages": [
            {"license": None, "name": "a", "version": "2"},
            {"license": "mit", "name": "b-x", "version": "1"},
        ]
    }


def test_list_defaults_to_installed_packages(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "license_auditor.__main__.collect_installed",
        lambda: [Package("a", "1", "MIT", "license")],
    )
    assert run(["list"], capsys) == (0, "a 1 MIT\n", "")


def test_list_reports_inventory_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(["list", "--inventory", str(tmp_path / "none.json")], capsys)
    assert (code, "invalid_inventory" in err) == (2, True)


# --- logging -----------------------------------------------------------------------


def test_package_logger_has_null_handler() -> None:
    handlers = logging.getLogger("license_auditor").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)
