import os
import unittest

from dnslint.parser import parse_zone

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return fh.read()


class ParseCleanZoneTests(unittest.TestCase):
    def setUp(self):
        self.result = parse_zone(load_fixture("clean.zone"))

    def test_no_parser_level_findings(self):
        self.assertEqual(self.result.findings, [])

    def test_default_ttl_picked_up_from_directive(self):
        self.assertEqual(self.result.default_ttl, 3600)

    def test_record_count(self):
        self.assertEqual(len(self.result.records), 6)

    def test_soa_record_fields(self):
        soa = self.result.records[0]
        self.assertEqual(soa.line, 4)
        self.assertEqual(soa.name, "@")
        self.assertEqual(soa.rclass, "IN")
        self.assertEqual(soa.rtype, "SOA")
        self.assertEqual(
            soa.rdata,
            "ns1.example.com. hostmaster.example.com. 2024031501 7200 3600 1209600 3600",
        )

    def test_mx_record_fields(self):
        mx = self.result.records[4]
        self.assertEqual(mx.line, 9)
        self.assertEqual(mx.name, "mail")
        self.assertEqual(mx.rtype, "MX")
        self.assertEqual(mx.rdata, "10 mail.example.com.")


class IncludeDirectiveTests(unittest.TestCase):
    def test_include_is_recognized_but_not_followed(self):
        result = parse_zone(load_fixture("include.zone"))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.level, "warning")
        self.assertEqual(finding.rule, "unsupported-directive")


class OwnerNameInheritanceTests(unittest.TestCase):
    def test_leading_whitespace_reuses_previous_owner(self):
        text = "www     IN  A     192.0.2.10\n        IN  A     192.0.2.11\n"
        result = parse_zone(text)
        self.assertEqual(result.findings, [])
        self.assertEqual([r.name for r in result.records], ["www", "www"])
        self.assertEqual(result.records[1].rdata, "192.0.2.11")

    def test_missing_owner_with_no_preceding_record_is_an_error(self):
        text = "        IN  A     192.0.2.10\n"
        result = parse_zone(text)
        self.assertEqual(result.records, [])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule, "missing-owner")


class TtlAndClassOrderingTests(unittest.TestCase):
    def test_ttl_before_class(self):
        result = parse_zone("www 300 IN A 192.0.2.10\n")
        rec = result.records[0]
        self.assertEqual(rec.ttl, 300)
        self.assertEqual(rec.rclass, "IN")
        self.assertEqual(rec.rtype, "A")
        self.assertEqual(rec.rdata, "192.0.2.10")

    def test_class_before_ttl(self):
        result = parse_zone("www IN 300 A 192.0.2.10\n")
        rec = result.records[0]
        self.assertEqual(rec.ttl, 300)
        self.assertEqual(rec.rclass, "IN")
        self.assertEqual(rec.rtype, "A")
        self.assertEqual(rec.rdata, "192.0.2.10")


class ParenthesizedRecordTests(unittest.TestCase):
    def test_multiline_soa_joins_into_one_record(self):
        text = (
            "@   IN  SOA ns1.example.com. hostmaster.example.com. (\n"
            "                2024031501 ; serial\n"
            "                7200       ; refresh\n"
            "                3600       ; retry\n"
            "                1209600    ; expire\n"
            "                3600 )     ; minimum\n"
        )
        result = parse_zone(text)
        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.records), 1)
        rec = result.records[0]
        self.assertEqual(rec.line, 1)
        self.assertEqual(rec.rtype, "SOA")
        self.assertEqual(
            rec.rdata,
            "ns1.example.com. hostmaster.example.com. 2024031501 7200 3600 1209600 3600",
        )

    def test_unclosed_paren_reports_error_and_still_yields_record(self):
        text = "@ IN SOA ns1.example.com. hostmaster.example.com. (\n    2024031501\n"
        result = parse_zone(text)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.rule, "unbalanced-parens")
        self.assertEqual(len(result.records), 1)

    def test_stray_close_paren_reports_error(self):
        result = parse_zone("www IN A 192.0.2.10 )\n")
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.rule, "unbalanced-parens")
        self.assertIn("no matching '('", finding.message)
        self.assertEqual(result.records[0].rdata, "192.0.2.10")


class QuotedRdataTests(unittest.TestCase):
    def test_semicolon_and_parens_inside_quotes_are_data_not_syntax(self):
        text = 'txt1    IN  TXT   "hello ; not a comment (and not a paren)"\n'
        result = parse_zone(text)
        self.assertEqual(result.findings, [])
        rec = result.records[0]
        self.assertEqual(rec.rtype, "TXT")
        self.assertEqual(rec.rdata, '"hello ; not a comment (and not a paren)"')


class DirectiveValidationTests(unittest.TestCase):
    def test_ttl_directive_requires_numeric_argument(self):
        result = parse_zone("$TTL abc\n")
        self.assertIsNone(result.default_ttl)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule, "bad-directive")

    def test_origin_without_trailing_dot_is_flagged(self):
        result = parse_zone("$ORIGIN example.com\n")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule, "missing-trailing-dot")


if __name__ == "__main__":
    unittest.main()
