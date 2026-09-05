import argparse
import sys
from typing import List, Optional

from .checks import run_checks
from .parser import parse_zone


def lint_file(path: str, lenient: bool):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    parse_result = parse_zone(text)
    return run_checks(parse_result, lenient)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnslint",
        description="Lint DNS zone files for common mistakes.",
    )
    parser.add_argument("zonefiles", nargs="+", help="path to one or more zone files")
    parser.add_argument(
        "--lenient", action="store_true",
        help="downgrade or skip stylistic checks instead of treating them as errors",
    )
    args = parser.parse_args(argv)

    had_error = False
    for path in args.zonefiles:
        try:
            findings = lint_file(path, args.lenient)
        except OSError as exc:
            print(f"{path}: could not read file: {exc}", file=sys.stderr)
            had_error = True
            continue

        for finding in findings:
            print(f"{path}:{finding.line}: {finding.level}: {finding.rule}: {finding.message}")
            if finding.level == "error":
                had_error = True

    return 1 if had_error else 0


if __name__ == "__main__":
    sys.exit(main())
