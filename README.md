# license-auditor

[![PyPI version](https://img.shields.io/pypi/v/trysac-license-auditor)](https://pypi.org/project/trysac-license-auditor/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-license-auditor)](LICENSE)
[![CI](https://github.com/Trysac/u068-license-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u068-license-auditor/actions/workflows/ci.yml)

Audit dependency licenses against an allowlist policy with SPDX license expressions, PEP 639 metadata and conservative classifier mapping.

## Problem

Teams discover a copyleft or unknown license in their dependencies only during a customer's legal review. Python metadata stores licenses inconsistently (License-Expression, free text, classifiers), and naive checks misread ambiguous classifiers as specific licenses. This library normalises licenses to SPDX identifiers, evaluates AND, OR and WITH expressions against an allowlist, and reports violations so CI can fail.

**Disclaimer:** this tool is not legal advice. It checks declared metadata against your policy only.

## Install

```sh
pip install trysac-license-auditor
# or
uv add trysac-license-auditor
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from license_auditor import Package, Policy, audit

policy = Policy.from_json('{"allow": ["MIT", "Apache-2.0"]}')
packages = [Package("demo", "1.0", "MIT OR GPL-3.0-only", "inventory")]
report = audit(packages, policy)
print(report.to_text())
print("ok" if report.ok else "violations")
```

### Public API

- `Package(name, version, license, source)`: frozen; `name` is normalised per PEP 503.
- `collect_installed(paths=None) -> list[Package]`: reads installed distributions; license taken from PEP 639 `License-Expression`, else a `License` field that is an expression or known free text, else mapped classifiers (several combine with AND), else `None`.
- `load_inventory(path) -> list[Package]`: reads a JSON list of `{name, version, license}`.
- `parse_expression(text) -> LicenseExpr`: parses an SPDX 2.3 Annex D expression. Precedence is WITH, then AND, then OR.
- `Policy.from_json(text) -> Policy`: keys `allow`, `deny`, `exceptions` (package to reason), `unknown` (`fail` or `warn`), `classifier_overrides`.
- `audit(packages, policy) -> AuditReport`: results have status `allowed`, `denied`, `unknown` or `exception`. `to_text()` and `to_json()` order results by package name.
- Errors: `LicenseAuditError` with `code` in `invalid_expression`, `invalid_policy`, `invalid_inventory`, `too_large`; `LicenseExpressionError` adds `position` (1-based).

### Limits

- Expressions: at most 1000 characters and nesting depth 32.
- Inventory file: at most 10 MiB and 100000 entries.
- Policy file: at most 1 MiB.
- A License field longer than 200 characters is treated as text, not as an identifier.
- More than 100000 installed distributions raise `too_large`.
- Only the bundled SPDX and classifier data is known; other well-formed identifiers are kept verbatim and match policy entries exactly.
- Classifiers such as `BSD License` or `Apache Software License` are unknown unless `classifier_overrides` maps them.

### CLI

```sh
license-auditor check --policy policy.json [--inventory inventory.json] [--format json]
license-auditor list [--inventory inventory.json] [--format json]
```

Exit codes: `0` all packages pass, `1` any denied package (or unknown when `unknown` is `fail`), `2` usage or input error (for example an invalid policy).

### Policy format

```json
{
  "allow": ["MIT", "Apache-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"],
  "deny": ["GPL-3.0-only"],
  "exceptions": {"some-package": "reviewed by legal on 2026-01-10"},
  "unknown": "fail",
  "classifier_overrides": {
    "License :: OSI Approved :: BSD License": "BSD-3-Clause"
  }
}
```

An id listed in both `allow` and `deny` is an invalid policy.

### Why not pip-licenses?

The specification does not name a best-known alternative, so this section is omitted.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
