# Security notes

## Threat model

`trysac-license-auditor` has no network access and no runtime dependencies. It does read files: policy files (at most 1 MiB), inventory files (at most 10 MiB and 100000 entries) and installed distribution metadata.

Defended:

- **Oversized input**: expressions above 1000 characters or nesting depth 32, policies above 1 MiB, inventories above 10 MiB or 100000 entries, and more than 100000 distributions are rejected with explicit errors (`invalid_expression` or `too_large`).
- **Malformed input**: invalid JSON, non-UTF-8 files, wrong types and inconsistent policies (an id in both `allow` and `deny`) raise `invalid_policy` or `invalid_inventory`; the CLI exits 2.
- **Terminal injection**: names, versions and licenses printed by the CLI are passed through a sanitiser that replaces non-printable characters and truncates long values.
- **Code execution**: no `eval`, `exec` or pickle deserialisation is used.

Not defended:

- **Declared metadata is trusted**: the tool checks what packages declare, not what their source code contains. Misdeclared licenses are not detected.
- **Unknown classifiers are not guessed**: ambiguous classifiers are reported as `unknown`; a package whose license is mislabelled as a known id will be accepted.
- **Filesystem attacks**: `collect_installed` reads whatever distributions the Python environment exposes; the library does not sandbox that access.
- **Legal correctness**: the output is not legal advice.

## Publishing

Releases are published to PyPI with trusted publishing (OIDC) when available, never with a long-lived token stored in the repository.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
