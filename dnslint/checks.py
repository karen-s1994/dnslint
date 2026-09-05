"""Checks that run over a parsed zone.

Some checks catch things that are unconditionally broken (a zone with two
SOA records will not load; a name with a CNAME and another record type is
invalid per RFC 1034) -- those always report as errors. Others are
heuristics or style preferences (a bare-looking name missing its trailing
dot, an unusually short TTL, lowercase record types) -- those are errors
by default and get downgraded or skipped under --lenient.
"""

from typing import List, Optional

from .parser import Finding, KNOWN_TYPES, Record


def _looks_like_missing_dot(token: str) -> bool:
    """Two or more dots in a bare name almost always means the author
    meant a full domain name. Without the trailing dot, BIND silently
    appends $ORIGIN to it instead, which is rarely what was intended."""
    if token in ("@", "*"):
        return False
    if token.endswith("."):
        return False
    return token.count(".") >= 2


def check_trailing_dots(records: List[Record], lenient: bool) -> List[Finding]:
    level = "warning" if lenient else "error"
    findings = []
    for rec in records:
        if _looks_like_missing_dot(rec.name):
            findings.append(Finding(
                rec.line, level, "missing-trailing-dot",
                f"owner name '{rec.name}' looks like a full domain but has no trailing dot"))

        parts = rec.rdata.split()
        target: Optional[str] = None
        if rec.rtype in ("CNAME", "NS", "PTR") and parts:
            target = parts[0]
        elif rec.rtype == "MX" and len(parts) >= 2 and parts[0].isdigit():
            target = parts[1]

        if target and _looks_like_missing_dot(target):
            findings.append(Finding(
                rec.line, level, "missing-trailing-dot",
                f"{rec.rtype} target '{target}' looks like a full domain but has no trailing dot"))
    return findings


def check_ttl_present(records: List[Record], default_ttl: Optional[int], lenient: bool) -> List[Finding]:
    if lenient:
        return []
    findings = []
    last_ttl = default_ttl
    for rec in records:
        if rec.ttl is not None:
            last_ttl = rec.ttl
            continue
        if last_ttl is None:
            findings.append(Finding(
                rec.line, "error", "ttl-missing",
                f"{rec.rtype} record for '{rec.name}' has no TTL and no $TTL directive precedes it"))
    return findings


def check_ttl_range(records: List[Record], lenient: bool) -> List[Finding]:
    if lenient:
        return []
    findings = []
    for rec in records:
        if rec.ttl is None:
            continue
        if rec.ttl < 300:
            findings.append(Finding(
                rec.line, "warning", "ttl-too-short",
                f"TTL {rec.ttl} is under 5 minutes; that's a lot of query load unless this record changes often"))
        elif rec.ttl > 604800:
            findings.append(Finding(
                rec.line, "warning", "ttl-too-long",
                f"TTL {rec.ttl} is over 7 days; changes to this record will take a long time to propagate"))
    return findings


def check_type_case(records: List[Record], lenient: bool) -> List[Finding]:
    if lenient:
        return []
    findings = []
    for rec in records:
        if rec.rtype_raw != rec.rtype_raw.upper():
            findings.append(Finding(
                rec.line, "warning", "lowercase-type",
                f"record type '{rec.rtype_raw}' should be written in uppercase ('{rec.rtype}')"))
    return findings


def check_unknown_type(records: List[Record], lenient: bool) -> List[Finding]:
    findings = []
    for rec in records:
        if rec.rtype not in KNOWN_TYPES:
            level = "warning" if lenient else "error"
            findings.append(Finding(
                rec.line, level, "unknown-type",
                f"'{rec.rtype}' is not a record type this linter recognizes"))
    return findings


def check_duplicate_soa(records: List[Record], lenient: bool) -> List[Finding]:
    findings = []
    first_soa_line = None
    for rec in records:
        if rec.rtype != "SOA":
            continue
        if first_soa_line is not None:
            findings.append(Finding(
                rec.line, "error", "duplicate-soa",
                f"second SOA record in zone (first was on line {first_soa_line})"))
        else:
            first_soa_line = rec.line
    return findings


def check_cname_conflicts(records: List[Record], lenient: bool) -> List[Finding]:
    findings = []
    types_by_name = {}
    cname_line_by_name = {}
    for rec in records:
        types_by_name.setdefault(rec.name, set()).add(rec.rtype)
        if rec.rtype == "CNAME" and rec.name not in cname_line_by_name:
            cname_line_by_name[rec.name] = rec.line

    for rec in records:
        if rec.rtype == "CNAME":
            continue
        types = types_by_name.get(rec.name, set())
        if "CNAME" in types:
            findings.append(Finding(
                rec.line, "error", "cname-conflict",
                f"'{rec.name}' has a CNAME record and cannot have other record types "
                f"(CNAME is on line {cname_line_by_name[rec.name]})"))
    return findings


def run_checks(parse_result, lenient: bool) -> List[Finding]:
    records = parse_result.records
    findings = list(parse_result.findings)
    findings += check_trailing_dots(records, lenient)
    findings += check_ttl_present(records, parse_result.default_ttl, lenient)
    findings += check_ttl_range(records, lenient)
    findings += check_type_case(records, lenient)
    findings += check_unknown_type(records, lenient)
    findings += check_duplicate_soa(records, lenient)
    findings += check_cname_conflicts(records, lenient)
    findings.sort(key=lambda f: f.line)
    return findings
