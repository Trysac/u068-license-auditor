# Architecture

## Purpose

`trysac-license-auditor` is a small, dependency-free Python library (import name `license_auditor`) that audits dependency licenses against an allowlist policy using SPDX expressions, PEP 639 metadata and conservative classifier mapping.

## Shape

```text
caller code --> license_auditor (public API in __init__.py)
                    |
                    +-- expression.py   SPDX expression parser
                    +-- policy.py      Policy model and audit engine
                    +-- packages.py    Package model, installed-distribution and inventory readers
                    +-- data.py        bundled SPDX ids, exceptions and classifier mapping
                    +-- errors.py      typed errors with stable codes
                    +-- __main__.py    CLI (check and list)
```

- **Public API**: the names listed in `__all__` of `src/license_auditor/__init__.py`: `And`, `AuditReport`, `LicenseAuditError`, `LicenseExpr`, `LicenseExpressionError`, `Or`, `Package`, `Policy`, `Result`, `Term`, `With`, `audit`, `collect_installed`, `load_inventory`, `parse_expression`, and `__version__`.
- **Errors**: invalid input raises `LicenseAuditError` (or its subclass `LicenseExpressionError`) carrying a stable `code`.
- **Side effects**: `collect_installed` and `load_inventory` read the filesystem; the CLI writes to stdout and stderr. Logging goes through `logging.getLogger(__name__)` with a NullHandler.

## Quality contract

The gates are described in [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
