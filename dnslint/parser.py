"""Parse a subset of BIND-style zone file syntax into records.

This does not implement the full RFC 1035 master file grammar -- there is
no support yet for $INCLUDE, and comment stripping doesn't know about
quoted TXT rdata. It covers the record styles that the vast majority of
hand-written zone files actually use, including parenthesized records
that continue across several lines, which is enough to build useful
checks on top of.
"""

from dataclasses import dataclass, field
from typing import List, Optional

KNOWN_TYPES = {
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA",
}
KNOWN_CLASSES = {"IN", "CH", "HS"}


@dataclass
class Record:
    line: int
    name: str
    ttl: Optional[int]
    rclass: Optional[str]
    rtype: str
    rtype_raw: str
    rdata: str


@dataclass
class Finding:
    line: int
    level: str  # "error" or "warning"
    rule: str
    message: str


@dataclass
class ParseResult:
    records: List[Record] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    default_ttl: Optional[int] = None


def _strip_comment(raw: str) -> str:
    # Naive: doesn't know about quoted TXT rdata, so a ';' inside a quoted
    # string will be treated as a comment start. Good enough for v1.
    idx = raw.find(";")
    return raw[:idx] if idx != -1 else raw


def _logical_lines(text: str, findings: List[Finding]):
    """Yield (start_line, has_leading_ws, code) for each logical record.

    A record wrapped in parentheses spans multiple physical lines; this
    joins them into one so the rest of the parser can keep treating a
    record as a single whitespace-separated token stream. The parens
    themselves are dropped rather than tokenized.
    """
    paren_depth = 0
    parts: List[str] = []
    start_line = 0
    leading_ws = False

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        code = _strip_comment(raw_line.rstrip("\n"))
        if paren_depth == 0:
            if not code.strip():
                continue
            start_line = line_no
            leading_ws = code[0] in (" ", "\t")

        paren_depth += code.count("(") - code.count(")")
        parts.append(code.replace("(", " ").replace(")", " "))

        if paren_depth <= 0:
            if paren_depth < 0:
                findings.append(Finding(
                    line_no, "error", "unbalanced-parens",
                    "found ')' with no matching '('"))
            paren_depth = 0
            yield start_line, leading_ws, " ".join(parts)
            parts = []

    if parts:
        findings.append(Finding(
            start_line, "error", "unbalanced-parens",
            "record has '(' with no matching ')' before end of file"))
        yield start_line, leading_ws, " ".join(parts)


def parse_zone(text: str) -> ParseResult:
    result = ParseResult()
    current_name: Optional[str] = None

    for line_no, has_leading_ws, code in _logical_lines(text, result.findings):
        tokens = code.split()
        if not tokens:
            continue
        directive = tokens[0].upper()

        if directive == "$ORIGIN":
            if len(tokens) < 2:
                result.findings.append(Finding(line_no, "error", "bad-directive",
                                                "$ORIGIN with no argument"))
                continue
            if not tokens[1].endswith("."):
                result.findings.append(Finding(
                    line_no, "error", "missing-trailing-dot",
                    f"$ORIGIN value '{tokens[1]}' should end with '.'"))
            continue

        if directive == "$TTL":
            if len(tokens) < 2 or not tokens[1].isdigit():
                result.findings.append(Finding(line_no, "error", "bad-directive",
                                                "$TTL requires a numeric argument"))
                continue
            result.default_ttl = int(tokens[1])
            continue

        if directive == "$INCLUDE":
            result.findings.append(Finding(
                line_no, "warning", "unsupported-directive",
                "$INCLUDE is not followed; the included file was not linted"))
            continue

        idx = 0
        if has_leading_ws:
            if current_name is None:
                result.findings.append(Finding(
                    line_no, "error", "missing-owner",
                    "record has no owner name and none precedes it"))
                continue
            name = current_name
        else:
            name = tokens[0]
            idx = 1
            current_name = name

        ttl: Optional[int] = None
        rclass: Optional[str] = None
        while idx < len(tokens) and len(tokens[idx:]) > 1:
            tok = tokens[idx]
            if tok.isdigit() and ttl is None:
                ttl = int(tok)
                idx += 1
                continue
            if tok.upper() in KNOWN_CLASSES and rclass is None:
                rclass = tok.upper()
                idx += 1
                continue
            break

        if idx >= len(tokens):
            result.findings.append(Finding(line_no, "error", "malformed-record",
                                            "record is missing a type and data"))
            continue

        rtype_raw = tokens[idx]
        rtype = rtype_raw.upper()
        idx += 1
        rdata = " ".join(tokens[idx:])
        if not rdata:
            result.findings.append(Finding(line_no, "error", "malformed-record",
                                            f"{rtype} record has no data"))
            continue

        result.records.append(Record(line_no, name, ttl, rclass, rtype, rtype_raw, rdata))

    return result
