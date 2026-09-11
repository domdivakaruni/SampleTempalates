"""Read-only Cypher statement gate.

``check_readonly`` is the first of the three defensive layers in front of the agent's ``run_cypher`` tool
(gate -> engine opened ``read_only=True`` -> per-query timeout). It is deliberately conservative: a query
that is refused here can be rewritten by the caller, while a write or an unbounded traversal that slips
through could damage the database or stall the API.

Rules (all case-insensitive; string literals, backtick identifiers and comments are masked before scanning,
so ``WHERE n.title CONTAINS 'CREATE'`` passes):

* exactly one statement (a trailing ``;`` is tolerated);
* the statement starts with a read clause (``MATCH``, ``OPTIONAL MATCH``, ``WITH``, ``UNWIND``, ``RETURN``);
* no write / DDL / procedure / file / transaction keyword anywhere (``CREATE MERGE SET DELETE REMOVE DROP
  ALTER COPY LOAD INSTALL ATTACH DETACH CALL IMPORT EXPORT BEGIN COMMIT`` plus a few engine extras such as
  ``FOREACH``, ``CHECKPOINT``, ``USE``, ``GRANT``); property accesses like ``n.set`` are fine;
* every variable-length pattern has an explicit upper bound ``<= max_var_length`` (``[*]``, ``[*2..]`` and
  ``[*1..9]`` are refused; Kuzu's ``[e* SHORTEST 1..3]`` and Neo4j quantified paths ``{1,3}`` are handled);
* the final ``LIMIT`` is clamped to ``row_limit`` (or injected when missing); ``LIMIT $param`` is refused
  because the gate cannot see parameter values.

The normalized statement (comments stripped, trailing ``;`` removed, ``LIMIT`` clamped) is returned.
"""
from __future__ import annotations

import re

from throughline.graph.store import QueryRejected

FORBIDDEN_KEYWORDS: frozenset[str] = frozenset(
    {
        # required by the contract
        "CREATE", "MERGE", "SET", "DELETE", "REMOVE", "DROP", "ALTER", "COPY", "LOAD", "INSTALL", "ATTACH", "DETACH",
        "CALL", "IMPORT", "EXPORT", "BEGIN", "COMMIT",
        # engine-specific extras that also write, read files or change session state
        "FOREACH", "CHECKPOINT", "ROLLBACK", "USE", "GRANT", "REVOKE", "DENY", "SHOW", "TERMINATE", "PROJECT",
        "TRUNCATE", "COMMENT", "PROFILE", "EXPLAIN", "MACRO", "SEQUENCE", "EXTENSION",
    }
)
READ_CLAUSES: frozenset[str] = frozenset({"MATCH", "OPTIONAL", "WITH", "UNWIND", "RETURN"})

_FORBIDDEN_RE = re.compile(
    r"(?<![\w.$`])(" + "|".join(sorted(FORBIDDEN_KEYWORDS)) + r")(?![\w])",
    re.IGNORECASE,
)
_FIRST_WORD_RE = re.compile(r"^\s*([A-Za-z_]+)")
# `[` optional variable, optional `:TYPE|TYPE2` (Neo4j `:!TYPE` and `:A|:B` spellings tolerated), then `*`
_VARLEN_RE = re.compile(r"\[\s*(?:[A-Za-z_]\w*)?\s*(?::\s*!?\s*`?\w+`?(?:\s*\|\s*:?\s*!?\s*`?\w+`?)*)?\s*\*")
_VARLEN_BOUNDS_RE = re.compile(
    r"\s*(?:ALL\s+)?(?:W?SHORTEST\s*(?:\([^)]*\))?\s*)?(?:ALL\s+)?(\d+)?\s*(\.\.)?\s*(\d+)?",
    re.IGNORECASE,
)
_QPP_BRACES_RE = re.compile(r"\)\s*\{\s*(\d*)\s*(,?)\s*(\d*)\s*\}")
_QPP_SYMBOL_RE = re.compile(r"\)\s*([+*])")
_LIMIT_RE = re.compile(r"(?<![\w.$])LIMIT\b", re.IGNORECASE)
_RETURN_RE = re.compile(r"(?<![\w.$])RETURN\b", re.IGNORECASE)
_LIMIT_VALUE_RE = re.compile(r"LIMIT\s+(\S+)(.*)$", re.IGNORECASE | re.DOTALL)


def _strip_comments_and_mask(query: str) -> tuple[str, str]:
    """Return ``(clean, masked)``: ``clean`` is the query without comments, ``masked`` is ``clean`` with the
    contents of string literals and backtick identifiers replaced by spaces (same length, positions align)."""
    clean: list[str] = []
    masked: list[str] = []
    i, n = 0, len(query)
    while i < n:
        ch = query[i]
        nxt = query[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            j = query.find("\n", i)
            i = n if j < 0 else j  # keep the newline itself
            continue
        if ch == "/" and nxt == "*":
            j = query.find("*/", i + 2)
            if j < 0:
                raise QueryRejected("unterminated block comment")
            clean.append(" ")
            masked.append(" ")
            i = j + 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            j = i + 1
            while j < n:
                if query[j] == "\\" and quote != "`":
                    j += 2
                    continue
                if query[j] == quote:
                    break
                j += 1
            if j >= n:
                raise QueryRejected(f"unterminated {'string literal' if quote != '`' else 'backtick identifier'}")
            literal = query[i : j + 1]
            clean.append(literal)
            masked.append(quote + " " * (len(literal) - 2) + quote)
            i = j + 1
            continue
        clean.append(ch)
        masked.append(ch)
        i += 1
    return "".join(clean), "".join(masked)




def _closes_pattern_group(masked: str, close_idx: int) -> bool:
    """True when the ``)`` at ``close_idx`` closes a parenthesised *path pattern* such as ``((a)-[]->(b))``
    (Neo4j quantified path patterns), as opposed to an arithmetic or function group like ``(a+b)``."""
    depth = 0
    for i in range(close_idx, -1, -1):
        ch = masked[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                inner = masked[i + 1 : close_idx]
                return "-[" in inner or "]-" in inner or "->" in inner or "<-" in inner or "--" in inner
    return False


def _check_var_length(masked: str, max_var_length: int) -> None:
    for m in _VARLEN_RE.finditer(masked):
        tail = masked[m.end() :]
        b = _VARLEN_BOUNDS_RE.match(tail)
        lower, dots, upper = (b.group(1), b.group(2), b.group(3)) if b else (None, None, None)
        if dots is None and lower is None:
            raise QueryRejected(f"variable-length pattern without bounds is not allowed; use *1..{max_var_length}")
        if dots is None:  # exact length `*n`
            if int(lower) > max_var_length:  # type: ignore[arg-type]
                raise QueryRejected(f"variable-length pattern *{lower} exceeds the maximum of {max_var_length} hops")
            continue
        if upper is None:
            raise QueryRejected(f"variable-length pattern needs an upper bound <= {max_var_length} (got *{lower or ''}..)")
        if int(upper) > max_var_length:
            raise QueryRejected(f"variable-length upper bound {upper} exceeds the maximum of {max_var_length} hops")
        if lower is not None and int(lower) > int(upper):
            raise QueryRejected(f"variable-length lower bound {lower} is greater than the upper bound {upper}")
    for m in _QPP_BRACES_RE.finditer(masked):
        if not _closes_pattern_group(masked, m.start()):
            continue
        lower, comma, upper = m.group(1), m.group(2), m.group(3)
        if not comma:
            bound = lower or upper
            if bound and int(bound) > max_var_length:
                raise QueryRejected(f"path quantifier {{{bound}}} exceeds the maximum of {max_var_length} hops")
            continue
        if not upper:
            raise QueryRejected(f"path quantifier without an upper bound is not allowed; use {{1,{max_var_length}}}")
        if int(upper) > max_var_length:
            raise QueryRejected(f"path quantifier upper bound {upper} exceeds the maximum of {max_var_length} hops")
    for m in _QPP_SYMBOL_RE.finditer(masked):
        if _closes_pattern_group(masked, m.start()):
            raise QueryRejected(f"unbounded path quantifiers (+, *) are not allowed; use {{1,{max_var_length}}}")


def _apply_row_limit(clean: str, masked: str, row_limit: int) -> str:
    limits = list(_LIMIT_RE.finditer(masked))
    returns = list(_RETURN_RE.finditer(masked))
    if limits and returns and limits[-1].start() > returns[-1].start():
        last = limits[-1]
        value_match = _LIMIT_VALUE_RE.match(masked, last.start())
        if value_match is None:
            raise QueryRejected("LIMIT must be followed by an integer literal")
        token = value_match.group(1).rstrip(";")
        if not token.isdigit() or value_match.group(2).strip():
            raise QueryRejected("LIMIT must be a single integer literal at the end of the query (parameters and expressions are not allowed)")
        if int(token) > row_limit:
            start = value_match.start(1)
            return clean[:start] + str(row_limit) + clean[start + len(token) :]
        return clean
    if not returns:
        return clean  # let the engine report the missing RETURN
    return f"{clean.rstrip()} LIMIT {row_limit}"


def check_readonly(query: str, max_var_length: int = 5, row_limit: int = 200) -> str:
    """Validate ``query`` against the read-only rules and return the normalized statement.

    Raises ``QueryRejected`` with a message the caller (or an LLM agent) can act on.
    """
    if not isinstance(query, str) or not query.strip():
        raise QueryRejected("empty query")
    if max_var_length < 1:
        raise ValueError("max_var_length must be >= 1")
    if row_limit < 1:
        raise ValueError("row_limit must be >= 1")

    clean, masked = _strip_comments_and_mask(query)
    clean, masked = clean.strip(), masked.strip()
    while masked.endswith(";"):
        clean, masked = clean[:-1].rstrip(), masked[:-1].rstrip()
    if not masked:
        raise QueryRejected("empty query")
    if ";" in masked:
        raise QueryRejected("multiple statements are not allowed")

    first = _FIRST_WORD_RE.match(masked)
    if first is None or first.group(1).upper() not in READ_CLAUSES:
        raise QueryRejected("query must start with MATCH, OPTIONAL MATCH, WITH, UNWIND or RETURN")

    forbidden = _FORBIDDEN_RE.search(masked)
    if forbidden:
        raise QueryRejected(f"keyword {forbidden.group(1).upper()} is not allowed in read-only queries")

    _check_var_length(masked, max_var_length)
    return _apply_row_limit(clean, masked, row_limit)
