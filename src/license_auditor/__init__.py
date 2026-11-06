"""Audit dependency licenses against an allowlist policy.

Supports SPDX license expressions, PEP 639 metadata and conservative
classifier mapping.
"""

from __future__ import annotations

import logging

from .errors import LicenseAuditError, LicenseExpressionError
from .expression import And, LicenseExpr, Or, Term, With, parse_expression
from .packages import Package, collect_installed, load_inventory
from .policy import AuditReport, Policy, Result, audit

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "And",
    "AuditReport",
    "LicenseAuditError",
    "LicenseExpr",
    "LicenseExpressionError",
    "Or",
    "Package",
    "Policy",
    "Result",
    "Term",
    "With",
    "__version__",
    "audit",
    "collect_installed",
    "load_inventory",
    "parse_expression",
]

__version__ = "0.1.0"
