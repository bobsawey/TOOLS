#!/usr/bin/env python3
"""Compare packaged incident hashes with upstream Go. Never update rules silently."""
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

URL = 'https://raw.githubusercontent.com/golang/go/master/src/crypto/x509/verify.go'


def parse_upstream(text):
    match = re.search(r'var distrustedSPKIHashes = map\[string\]struct\{\}\{(.*?)\n\}', text, re.S)
    if not match:
        raise ValueError('Upstream blocklist format changed; manual review required.')
    hashes = set(re.findall(r'"([0-9a-f]{64})":\s*\{\}', match[1]))
    if len(hashes) < 8:
        raise ValueError('Unexpectedly short upstream blocklist; manual review required.')
    return hashes


def main():
    local = json.loads(Path(__file__).with_name('indicators.json').read_text())
    try:
        with urllib.request.urlopen(URL, timeout=30) as response:
            if response.url != URL:
                raise ValueError('Unexpected redirect; manual review required.')
            data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('Upstream response exceeds limit.')
        upstream = parse_upstream(data.decode('utf-8'))
    except (OSError, ValueError) as exc:
        print(f'Unable to verify indicator freshness: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2
    shipped = {x['sha256'] for x in local['compromised_spki']}
    print(json.dumps({'source': URL, 'retrieved_sha256': hashlib.sha256(data).hexdigest(),
                      'match': upstream == shipped, 'upstream_only': sorted(upstream - shipped),
                      'local_only': sorted(shipped - upstream),
                      'note': 'This checks the intermediate key list only. Review root paths and vendor guidance separately; no local files were changed.'}, indent=2))
    return 0 if upstream == shipped else 1


if __name__ == '__main__':
    raise SystemExit(main())
