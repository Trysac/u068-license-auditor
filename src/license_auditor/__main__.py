"""Command-line interface: ``license-auditor check`` and ``license-auditor list``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import LicenseAuditError
from .packages import Package, collect_installed, load_inventory, read_text_limited, safe_text
from .policy import MAX_POLICY_BYTES, Policy, audit


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--inventory",
        metavar="FILE",
        help="JSON inventory to use instead of the installed packages",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="license-auditor",
        description="Audit dependency licenses against an allowlist policy.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="audit packages against a policy")
    check.add_argument("--policy", required=True, metavar="FILE", help="policy JSON file")
    _add_common(check)
    listing = commands.add_parser("list", help="list packages and their licenses")
    _add_common(listing)
    return parser


def _load_packages(inventory: str | None) -> list[Package]:
    if inventory:
        return load_inventory(Path(inventory))
    return collect_installed()


def _render_packages(packages: list[Package], fmt: str) -> str:
    if fmt == "json":
        entries = [{"license": p.license, "name": p.name, "version": p.version} for p in packages]
        return json.dumps({"packages": entries}, sort_keys=True, indent=2)
    lines = [
        f"{safe_text(p.name)} {safe_text(p.version)} {safe_text(p.license or '-')}"
        for p in packages
    ]
    return "\n".join(lines)


def _emit(text: str) -> None:
    sys.stdout.write(text + "\n")


def _run(args: argparse.Namespace) -> int:
    if args.command == "check":
        policy_text = read_text_limited(
            Path(args.policy),
            MAX_POLICY_BYTES,
            "invalid_policy",
            "policy file",
        )
        policy = Policy.from_json(policy_text)
        report = audit(_load_packages(args.inventory), policy)
        _emit(report.to_json() if args.format == "json" else report.to_text())
        return 0 if report.ok else 1
    _emit(_render_packages(_load_packages(args.inventory), args.format))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return the exit code.

    Exit codes: 0 success, 1 a denied package (or unknown with ``unknown: fail``), 2 usage
    or input errors.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return _run(args)
    except LicenseAuditError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
