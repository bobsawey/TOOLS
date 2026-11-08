#!/usr/bin/env python3
"""Read-only eMudhra incident audit for Arch, CachyOS and explicit filesystem scopes."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import sys

try:
    import cryptography
    from scanner import Scanner
    import system_checks
except ImportError:
    sys.exit('Missing dependency: install python-cryptography with pacman, or use the documented venv.')

HERE = Path(__file__).resolve().parent
DEFAULT_PATHS = ('/etc', '/usr', '/opt', '/home', '/root', '/srv', '/var/lib', '/var/cache')


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', action='append', help='Scan only these files/directories (repeatable); otherwise scan standard system/app locations.')
    parser.add_argument('--exclude', action='append', default=[], help='Exclude path and descendants; recorded as a gap when encountered.')
    parser.add_argument('--system', action='store_true', help='Also inspect this running host when --path is supplied (on by default without --path).')
    parser.add_argument('--archives', action='store_true', help='Inspect bounded ZIP/JAR/wheel and tar members without extracting them.')
    parser.add_argument('--max-file-mib', type=positive, default=128)
    parser.add_argument('--max-total-mib', type=positive, default=16384)
    parser.add_argument('--max-archive-mib', type=positive, default=256)
    parser.add_argument('--max-members', type=positive, default=10000)
    parser.add_argument('--format', choices=('text', 'json'), default='text', help='Report to stdout; no report files are created by the scanner.')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    indicators = json.loads((HERE / 'indicators.json').read_text())
    scanner = Scanner(indicators, max_file=args.max_file_mib << 20,
                      max_total=args.max_total_mib << 20, archives=args.archives,
                      max_archive=args.max_archive_mib << 20, max_members=args.max_members,
                      exclusions=args.exclude)
    host = args.system or not args.path
    paths = args.path if args.path else [x for x in DEFAULT_PATHS if Path(x).exists()]
    if (date.today() - date.fromisoformat(indicators['reviewed_on'])).days > 30:
        scanner.gap('indicators.json', 'Incident indicators last reviewed over 30 days ago; run check_indicators.py and review upstream changes.')
    print('Scanning read-only; reports may include sensitive local paths. No outbound requests.', file=sys.stderr)
    inventory = {}
    if host:
        if os.geteuid() != 0:
            scanner.gap('privileges', 'Not running as root; other users and restricted stores may be unreadable.')
        system_checks.effective_trust(scanner)
        inventory = system_checks.host_inventory(scanner)
    scanner.walk(paths)
    # These inspect discovered databases, even for a detached filesystem scan.
    system_checks.nss(scanner)
    system_checks.java(scanner)
    scanner.verify_issuers()
    report = scanner.report()
    report.update(schema_version=1, generated_at=datetime.now(timezone.utc).isoformat(),
                  indicator_review_date=indicators['reviewed_on'],
                  indicator_sources=indicators['sources'],
                  tool_versions={'python': sys.version.split()[0], 'cryptography': cryptography.__version__},
                  scope={'paths': [str(Path(p).absolute()) for p in paths],
                         'excluded': args.exclude, 'host_checks': host, 'archives': args.archives,
                         'max_file_mib': args.max_file_mib, 'max_total_mib': args.max_total_mib,
                         'max_archive_mib': args.max_archive_mib, 'max_members': args.max_members},
                  inventory=inventory)
    if args.format == 'json':
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print('eMudhra audit: ' + report['status'])
        print(f"Indicators reviewed {indicators['reviewed_on']}; {len(scanner.certs)} unique certificates.")
        for finding in scanner.findings:
            # Escape control characters from filenames, aliases, and archive entries.
            print(f"[{finding['severity'].upper()}] {finding['code']} {json.dumps(finding['source'])}")
            print('  ' + finding['evidence'])
            if 'root' in finding:
                print('  Root: ' + finding['root'])
        for gap in scanner.gaps:
            print(f"[GAP] {json.dumps(gap['source'])}: {gap['reason']}")
        print(f"{len(scanner.findings)} findings; {len(scanner.gaps)} coverage gaps.")
        print('No findings means only no matching evidence within the reported scope. See README.md for remediation and limits.')
    # Findings take precedence, but gaps always remain in the report.
    return 1 if scanner.findings else (2 if scanner.gaps else 0)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('Interrupted: scan incomplete; no complete report produced.', file=sys.stderr)
        raise SystemExit(130)
