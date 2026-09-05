"""Parse a subset of BIND-style zone file syntax into records.

This does not implement the full RFC 1035 master file grammar -- there is
no support yet for parenthesized multi-line records or $INCLUDE. It covers
the single-line record style that the vast majority of hand-written zone
files actually use, which is enough to build useful checks on top of.
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


def parse_zone(text: str) -> ParseResult:
    result = ParseResult()
    current_name: Optional[str] = None

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        code = _strip_comment(raw_line.rstrip("\n"))
        if not code.strip():
            continue

        has_leading_ws = code[0] in (" ", "\t")
        tokens = code.split()
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
