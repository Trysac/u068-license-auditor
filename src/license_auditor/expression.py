"""Parser for SPDX license expressions (SPDX specification 2.3, Annex D).

A simple expression is a license id, an id followed by ``+``, or ``LicenseRef-`` plus
``[A-Za-z0-9.-]+``. Compound expressions use ``WITH``, ``AND``, ``OR`` and parentheses;
``WITH`` binds tighter than ``AND``, which binds tighter than ``OR``. Operators must be
uppercase and delimited by whitespace or parentheses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeAlias

from .data import alias_license, canonical_exception_id, canonical_license_id
from .errors import LicenseExpressionError, clip

MAX_EXPRESSION_LENGTH = 1000
MAX_DEPTH = 32

_WHITESPACE = " \t\r\n"
_ID_RE = re.compile("[A-Za-z0-9.-]+[+]?")
_EXCEPTION_RE = re.compile("[A-Za-z0-9.-]+")
_REF_RE = re.compile("LicenseRef-[A-Za-z0-9.-]+")
_OPERATORS = frozenset({"AND", "OR", "WITH"})


@dataclass(frozen=True)
class Term:
    """A license id, optionally with the ``+`` (or later) suffix."""

    id: str
    or_later: bool = False

    def __str__(self) -> str:
        return f"{self.id}+" if self.or_later else self.id


@dataclass(frozen=True)
class With:
    """A license id combined with a license exception."""

    term: Term
    exception: str

    def __str__(self) -> str:
        return f"{self.term} WITH {self.exception}"


@dataclass(frozen=True)
class And:
    """All operands apply."""

    operands: tuple[LicenseExpr, ...]

    def __str__(self) -> str:
        parts = [f"({op})" if isinstance(op, Or) else str(op) for op in self.operands]
        return " AND ".join(parts)


@dataclass(frozen=True)
class Or:
    """One of the operands applies."""

    operands: tuple[LicenseExpr, ...]

    def __str__(self) -> str:
        return " OR ".join(str(op) for op in self.operands)


LicenseExpr: TypeAlias = Term | With | And | Or


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    pos: int


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in _WHITESPACE:
            index += 1
        elif char in "()":
            tokens.append(_Token(char, char, index + 1))
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in _WHITESPACE + "()":
                index += 1
            tokens.append(_Token("word", text[start:index], start + 1))
    return tokens


class _Parser:
    def __init__(self, text: str) -> None:
        self._text = text
        self._tokens = _tokenize(text)
        self._index = 0

    def parse(self) -> LicenseExpr:
        if not self._tokens:
            raise LicenseExpressionError(1, "empty expression")
        expr = self._parse_or(0)
        if self._index < len(self._tokens):
            token = self._tokens[self._index]
            if token.kind == ")":
                raise LicenseExpressionError(token.pos, "unbalanced ')'")
            hint = "expected AND, OR or WITH"
            if token.text.upper() in _OPERATORS:
                hint += "; operators must be uppercase"
            raise LicenseExpressionError(token.pos, hint)
        return expr

    def _peek_word(self, word: str) -> bool:
        if self._index >= len(self._tokens):
            return False
        token = self._tokens[self._index]
        return token.kind == "word" and token.text == word

    def _next(self, expected: str) -> _Token:
        if self._index >= len(self._tokens):
            raise LicenseExpressionError(
                len(self._text) + 1,
                f"unexpected end of expression, expected {expected}",
            )
        token = self._tokens[self._index]
        self._index += 1
        return token

    def _parse_or(self, depth: int) -> LicenseExpr:
        operands = [self._parse_and(depth)]
        while self._peek_word("OR"):
            self._index += 1
            operands.append(self._parse_and(depth))
        return operands[0] if len(operands) == 1 else Or(tuple(operands))

    def _parse_and(self, depth: int) -> LicenseExpr:
        operands = [self._parse_with(depth)]
        while self._peek_word("AND"):
            self._index += 1
            operands.append(self._parse_with(depth))
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def _parse_with(self, depth: int) -> LicenseExpr:
        left = self._parse_primary(depth)
        if not self._peek_word("WITH"):
            return left
        with_token = self._tokens[self._index]
        previous = self._tokens[self._index - 1]
        if not isinstance(left, Term) or previous.kind == ")":
            raise LicenseExpressionError(with_token.pos, "WITH needs a license id on its left")
        self._index += 1
        exception = self._next("an exception id")
        valid = exception.kind == "word" and _EXCEPTION_RE.fullmatch(exception.text)
        if not valid or exception.text.upper() in _OPERATORS:
            raise LicenseExpressionError(exception.pos, "invalid exception id")
        return With(left, canonical_exception_id(exception.text))

    def _parse_primary(self, depth: int) -> LicenseExpr:
        token = self._next("a license id or '('")
        if token.kind == "(":
            if depth + 1 > MAX_DEPTH:
                raise LicenseExpressionError(token.pos, f"nesting deeper than {MAX_DEPTH}")
            inner = self._parse_or(depth + 1)
            closing = self._next("')'")
            if closing.kind != ")":
                raise LicenseExpressionError(closing.pos, "expected ')'")
            return inner
        if token.kind == ")":
            raise LicenseExpressionError(token.pos, "unexpected ')'")
        return self._term(token)

    def _term(self, token: _Token) -> Term:
        text = token.text
        if text in _OPERATORS:
            raise LicenseExpressionError(token.pos, f"unexpected operator {text}")
        if text.upper() in _OPERATORS:
            raise LicenseExpressionError(token.pos, "operators must be uppercase")
        if text.startswith("LicenseRef-"):
            if not _REF_RE.fullmatch(text):
                raise LicenseExpressionError(
                    token.pos,
                    f"invalid license reference {clip(text)!r}",
                )
            return Term(text)
        if not _ID_RE.fullmatch(text):
            raise LicenseExpressionError(token.pos, f"invalid license id {clip(text)!r}")
        plus = text.endswith("+")
        license_id, or_later = canonical_license_id(text[:-1] if plus else text, plus)
        return Term(license_id, or_later)


def parse_expression(text: str) -> LicenseExpr:
    """Parse an SPDX license expression.

    Known ids are canonicalised (case-insensitive match, deprecated ids mapped, ``+`` on a
    deprecated GPL family id becomes ``-or-later``); other well-formed ids are kept verbatim.

    Raises:
        LicenseExpressionError: if the text is longer than 1000 characters, nested deeper
            than 32 levels or not a valid expression. ``position`` is the 1-based offset.
    """
    if not isinstance(text, str):
        raise LicenseExpressionError(1, "expression must be a string")
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise LicenseExpressionError(
            1,
            f"expression longer than {MAX_EXPRESSION_LENGTH} characters",
        )
    return _Parser(text).parse()


def parse_license_text(text: str) -> LicenseExpr:
    """Parse a license field: a known free-text name or an SPDX expression."""
    alias = alias_license(text)
    if alias is not None:
        return Term(alias)
    return parse_expression(text)
