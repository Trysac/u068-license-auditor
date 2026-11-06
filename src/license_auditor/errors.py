"""Typed errors raised by the library."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["invalid_expression", "invalid_policy", "invalid_inventory", "too_large"]

MAX_MESSAGE_LENGTH = 200


def clip(text: str, limit: int = 60) -> str:
    """Return ``text`` shortened to ``limit`` characters for use in messages."""
    return text if len(text) <= limit else text[:limit] + "..."


class LicenseAuditError(Exception):
    """Base class of every error raised by this library.

    Attributes:
        code: Stable machine-readable error code.
        message: Human-readable message, at most 200 characters.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        text = message[:MAX_MESSAGE_LENGTH]
        super().__init__(text)
        self.code: ErrorCode = code
        self.message = text


class LicenseExpressionError(LicenseAuditError):
    """A license expression is malformed.

    Attributes:
        position: 1-based offset of the offending token in the expression.
    """

    def __init__(self, position: int, message: str) -> None:
        super().__init__("invalid_expression", message)
        self.position = position
