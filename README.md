# dnslint

A linter for BIND-style DNS zone files. It reads a zone file and reports
findings with line numbers, the way a normal linter would for source code.

Zone files are hand-edited far more often than they should be, and the
mistakes they hide are the kind that DNS itself won't complain about until
something breaks in production: a forgotten trailing dot that silently
turns `mail.example.com` into `mail.example.com.example.com`, a second SOA
record that makes some resolvers reject the whole zone, a `CNAME` sitting
next to an `A` record for the same name (which RFC 1034 forbids, and which
behaves inconsistently across servers when it happens anyway).

## Usage

```
$ dnslint example.com.zone
```

Given this zone file:

```
$ORIGIN example.com.
$TTL 3600

@       IN  SOA   ns1.example.com. hostmaster.example.com. 2024031501 7200 3600 1209600 3600
@       IN  NS    ns1.example.com.
@       IN  NS    ns2.example.com.

www     IN  A     192.0.2.10
mail    IN  MX    10 mail.example.com
ftp     IN  CNAME www.example.com.
ftp     IN  A     192.0.2.11
```

running `dnslint example.com.zone` reports:

```
example.com.zone:9: error: missing-trailing-dot: MX target 'mail.example.com' looks like a full domain but has no trailing dot
example.com.zone:11: error: cname-conflict: 'ftp' has a CNAME record and cannot have other record types (CNAME is on line 10)
```

The exit code is non-zero whenever at least one `error`-level finding was
reported, so it can be dropped into CI as-is.

## Strict by default, with an escape hatch

By default dnslint treats anything that's likely to cause a real problem
as an `error`, including things a name server would technically still
load: a missing trailing dot that changes what a name actually resolves
to, a record with no TTL and no `$TTL` directive in scope, an unusually
short or long TTL, or a lowercase record type.

Pass `--lenient` to relax the checks that are heuristic or stylistic
rather than strictly incorrect:

```
$ dnslint --lenient example.com.zone
```

Under `--lenient`, TTL-range and type-casing checks are skipped entirely,
missing-TTL is no longer flagged, and a missing trailing dot is reported
as a `warning` instead of an `error`. Checks for things that are simply
broken regardless of style -- duplicate `SOA` records and `CNAME`
conflicts -- always report as errors, `--lenient` or not.

## What it doesn't do yet

- No support for `$INCLUDE` (the directive is recognized but the included
  file is not linted).

## Requirements

Python 3.9 or later. No third-party dependencies.

## Running the tests

Tests use only the standard library `unittest` module and live under `tests/`,
with sample zone files under `tests/fixtures/`:

```
$ python -m unittest discover
```
