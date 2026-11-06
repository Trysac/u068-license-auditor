# Evaluate SPDX expressions against an allowlist with conservative license normalisation

Status: accepted (generated, pending human review)

## Context

Python package metadata records licenses inconsistently: PEP 639 License-Expression, free-text License fields and trove classifiers, several of which (for example BSD License or Apache Software License) do not identify one license. Naive checks misread them and let copyleft or unknown licenses reach customers. Teams need a CI gate that normalises to SPDX, understands AND, OR and WITH, and fails on violations without network access or legal interpretation.

## Decision

Use only the standard library. Parse SPDX 2.3 Annex D with a small recursive-descent parser that enforces length (1000), depth (32) and uppercase operators, reporting 1-based offsets via LicenseExpressionError. Bundle a small, dated data module (known ids, exceptions, deprecated aliases, free-text names, unambiguous classifiers); other well-formed ids are kept verbatim and matched exactly. Evaluate with an allowlist: a term is allowed only if allowed and not denied, WITH and + have explicit rules, AND needs every operand and OR one. Classifiers are mapped only when unambiguous; the classifiers are carried in Package.source so policy classifier_overrides can resolve them at audit time. Packages without usable data are 'unknown' and policy decides whether that fails. Every untrusted input (expressions, policy JSON, inventory JSON) has a named size limit and raises a typed LicenseAuditError with a stable code.

## Consequences

Results are deterministic and offline, and ambiguous data is never silently treated as a specific license. The bundled data is deliberately small, so unlisted SPDX ids are only matched by exact policy entries and must be maintained by hand. Encoding classifiers in Package.source keeps the four-field Package API but couples audit to that source format. The tool is not legal advice.
