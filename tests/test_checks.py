import os
import unittest

from dnslint.checks import (
    check_cname_conflicts,
    check_duplicate_soa,
    check_trailing_dots,
    check_ttl_present,
    check_ttl_range,
    check_type_case,
    check_unknown_type,
    run_checks,
)
from dnslint.parser import Record, parse_zone

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return fh.read()


def rec(line=1, name="www", ttl=None, rclass="IN", rtype="A", rdata="192.0.2.10"):
    return Record(line, name, ttl, rclass, rtype, rtype.lower() if rtype else rtype, rdata)


class TrailingDotTests(unittest.TestCase):
    def test_owner_name_missing_dot_is_an_error_by_default(self):
        records = [rec(name="www.example.com", rtype="A", rdata="192.0.2.10")]
        findings = check_trailing_dots(records, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "error")

    def test_owner_name_missing_dot_is_a_warning_when_lenient(self):
        records = [rec(name="www.example.com", rtype="A", rdata="192.0.2.10")]
        findings = check_trailing_dots(records, lenient=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "warning")

    def test_at_and_wildcard_owners_are_never_flagged(self):
        records = [
            rec(name="@", rtype="NS", rdata="ns1.example.com."),
            rec(name="*", rtype="A", rdata="192.0.2.10"),
        ]
        self.assertEqual(check_trailing_dots(records, lenient=False), [])

    def test_cname_target_missing_dot_is_flagged(self):
        records = [rec(rtype="CNAME", rdata="www.example.com")]
        findings = check_trailing_dots(records, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertIn("CNAME target", findings[0].message)

    def test_mx_target_missing_dot_is_flagged(self):
        records = [rec(rtype="MX", rdata="10 mail.example.com")]
        findings = check_trailing_dots(records, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertIn("MX target", findings[0].message)

    def test_properly_dotted_names_are_not_flagged(self):
        records = [
            rec(name="www", rtype="A", rdata="192.0.2.10"),
            rec(rtype="CNAME", rdata="www.example.com."),
        ]
        self.assertEqual(check_trailing_dots(records, lenient=False), [])


class TtlPresentTests(unittest.TestCase):
    def test_missing_ttl_with_no_default_is_an_error(self):
        records = [rec(ttl=None)]
        findings = check_ttl_present(records, default_ttl=None, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "ttl-missing")

    def test_default_ttl_covers_records_without_one(self):
        records = [rec(ttl=None)]
        findings = check_ttl_present(records, default_ttl=3600, lenient=False)
        self.assertEqual(findings, [])

    def test_skipped_entirely_when_lenient(self):
        records = [rec(ttl=None)]
        findings = check_ttl_present(records, default_ttl=None, lenient=True)
        self.assertEqual(findings, [])


class TtlRangeTests(unittest.TestCase):
    def test_short_ttl_is_a_warning(self):
        findings = check_ttl_range([rec(ttl=60)], lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "ttl-too-short")

    def test_long_ttl_is_a_warning(self):
        findings = check_ttl_range([rec(ttl=1_000_000)], lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "ttl-too-long")

    def test_skipped_entirely_when_lenient(self):
        self.assertEqual(check_ttl_range([rec(ttl=60)], lenient=True), [])


class TypeCaseTests(unittest.TestCase):
    def test_lowercase_type_is_a_warning(self):
        record = Record(1, "www", None, "IN", "TXT", "txt", '"hello"')
        findings = check_type_case([record], lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "lowercase-type")

    def test_skipped_entirely_when_lenient(self):
        record = Record(1, "www", None, "IN", "TXT", "txt", '"hello"')
        self.assertEqual(check_type_case([record], lenient=True), [])


class UnknownTypeTests(unittest.TestCase):
    def test_unknown_type_is_an_error_by_default(self):
        findings = check_unknown_type([rec(rtype="LOC")], lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "error")

    def test_unknown_type_is_a_warning_when_lenient(self):
        findings = check_unknown_type([rec(rtype="LOC")], lenient=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "warning")


class DuplicateSoaTests(unittest.TestCase):
    def test_second_soa_is_flagged(self):
        records = [
            rec(line=4, rtype="SOA", rdata="a b 1 2 3 4 5"),
            rec(line=5, rtype="SOA", rdata="a b 2 2 3 4 5"),
        ]
        findings = check_duplicate_soa(records, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 5)
        self.assertIn("line 4", findings[0].message)


class CnameConflictTests(unittest.TestCase):
    def test_other_record_at_cname_name_is_flagged(self):
        records = [
            rec(line=1, name="ftp", rtype="CNAME", rdata="www.example.com."),
            rec(line=2, name="ftp", rtype="A", rdata="192.0.2.11"),
        ]
        findings = check_cname_conflicts(records, lenient=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)

    def test_cname_alone_is_not_flagged(self):
        records = [rec(name="ftp", rtype="CNAME", rdata="www.example.com.")]
        self.assertEqual(check_cname_conflicts(records, lenient=False), [])


class RunChecksIntegrationTests(unittest.TestCase):
    def test_broken_zone_default(self):
        parse_result = parse_zone(load_fixture("broken.zone"))
        findings = run_checks(parse_result, lenient=False)
        rules = [(f.line, f.level, f.rule) for f in findings]
        self.assertEqual(rules, [
            (5, "error", "duplicate-soa"),
            (9, "error", "missing-trailing-dot"),
            (11, "error", "cname-conflict"),
            (12, "warning", "lowercase-type"),
        ])

    def test_broken_zone_lenient(self):
        parse_result = parse_zone(load_fixture("broken.zone"))
        findings = run_checks(parse_result, lenient=True)
        rules = [(f.line, f.level, f.rule) for f in findings]
        self.assertEqual(rules, [
            (5, "error", "duplicate-soa"),
            (9, "warning", "missing-trailing-dot"),
            (11, "error", "cname-conflict"),
        ])

    def test_clean_zone_has_no_findings(self):
        parse_result = parse_zone(load_fixture("clean.zone"))
        self.assertEqual(run_checks(parse_result, lenient=False), [])
        self.assertEqual(run_checks(parse_result, lenient=True), [])


if __name__ == "__main__":
    unittest.main()
