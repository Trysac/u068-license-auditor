# Stack

## Used

| Tool | Why |
|---|---|
| Python >= 3.10 | Minimum version of the package; uses postponed annotations and dataclasses. |
| uv | Environment and build management on Windows and Linux. |
| hatchling | Standards-based build backend; no setup.py. |
| ruff | Lint and format in one tool. |
| mypy (strict) | Type checking; the package ships `py.typed`. |
| pytest + pytest-cov | Test runner with coverage. |
| gitleaks | Secret scanning locally and in CI. |
| GitHub Actions + Dependabot | CI wrapper over the local gates; dependency updates. |

## Discarded

| Tool | Why not |
|---|---|
| Poetry | uv covers the same needs with standard dependency groups. |
| black + isort + flake8 | Replaced by ruff. |
| tox / nox | The OS matrix lives in CI; locally `scripts/check.py` is used. |
| Shell scripts for gates | Not portable to Windows; the gates are a Python script. |
