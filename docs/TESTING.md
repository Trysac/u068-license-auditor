# Testing

## Running

```sh
uv run pytest --cov=license_auditor   # tests with coverage report
uv run python scripts/check.py      # every gate, as CI runs it
```

## Policy

- Branch coverage of `src/license_auditor` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import license_auditor`) and assert return values, raised exceptions and their codes.
- Tests are intended to be deterministic: no network and no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each module. Shared fixtures go in `tests/conftest.py`.

Covered behaviour from the specification: SPDX expression parsing and error positions, PEP 503 name normalisation, fake `.dist-info` directories collected from `tmp_path`, policy validation, allow and deny evaluation including WITH compounds, exit codes 0, 1 and 2, and the byte-exact JSON golden output.
