"""Offline certificate discovery and evidence collection. Never executes scanned files."""
from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import tarfile
import zipfile
from collections import Counter
from functools import lru_cache

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)
DER_START = re.compile(rb"\x30[\x30-\x7f\x81-\x84]")
CERT_SUFFIXES = {'.pem', '.crt', '.cer', '.der', '.p7b', '.p7c', '.p12', '.pfx', '.jks', '.keystore'}
ARCHIVE_SUFFIXES = ('.zip', '.jar', '.war', '.ear', '.whl', '.egg', '.tar', '.tar.gz', '.tgz', '.tar.xz', '.tar.bz2')
OPAQUE_SUFFIXES = ('.zst', '.7z', '.rar', '.squashfs', '.appimage', '.qcow2', '.iso')
# Virtual filesystems, not general user directories. Explicit --path can scan mounts.
VIRTUAL = ('/proc', '/sys', '/dev', '/run')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sequence(data, offset=0):
    """Return bounds of a definite-length DER SEQUENCE; never allocate from its length."""
    if offset + 2 > len(data) or data[offset] != 0x30:
        return None
    length = data[offset + 1]
    head = offset + 2
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4 or head + count > len(data) or data[head] == 0:
            return None
        length = int.from_bytes(data[head:head + count], 'big')
        head += count
        if length < 128:
            return None
    end = head + length
    return (head, end) if end <= len(data) else None


@lru_cache(maxsize=32)
def scalar_four_point(curve_type):
    return ec.derive_private_key(4, curve_type()).public_key().public_numbers()


class Scanner:
    def __init__(self, indicators, *, max_file=128 << 20, max_total=16 << 30,
                 archives=False, max_archive=256 << 20, max_members=10000,
                 max_candidates=50000, exclusions=()):
        self.indicators = indicators
        self.bad = {x['sha256']: x for x in indicators['compromised_spki']}
        self.roots = {x['spki_sha256']: x for x in indicators['risk_roots']}
        self.max_file, self.max_total = max_file, max_total
        self.archives, self.max_archive = archives, max_archive
        self.max_members, self.max_candidates = max_members, max_candidates
        self.exclusions = tuple(Path(x).absolute() for x in exclusions)
        self.findings, self.gaps = [], []
        self.stats = Counter()
        self.seen_files, self.seen_findings, self.seen_gaps = set(), set(), set()
        self.nss_databases = []
        self.jks_stores = []
        self.certs = {}  # public certificates only, for direct issuer verification
        self.weak_certs = {}
        self.total_exhausted = False

    def gap(self, source, reason):
        key = (str(source), reason)
        if key not in self.seen_gaps:
            self.seen_gaps.add(key)
            self.gaps.append({'source': str(source), 'reason': reason})

    def finding(self, code, severity, source, evidence, **details):
        key = (code, str(source), json.dumps(details, sort_keys=True))
        if key not in self.seen_findings:
            self.seen_findings.add(key)
            self.findings.append(dict(code=code, severity=severity, source=str(source),
                                      evidence=evidence, **details))

    def key(self, key, source, context, cert_hash=None):
        digest = sha256(spki(key))
        details = dict(spki_sha256=digest, context=context)
        if cert_hash:
            details['cert_sha256'] = cert_hash
        weak = False
        if digest in self.bad:
            weak = True
            self.finding('COMPROMISED_EMUDHRA_KEY', 'critical', source,
                         'Exact public-key match to Go X.509 eMudhra blocklist.',
                         known_subject=self.bad[digest]['subject'], **details)
        if isinstance(key, ec.EllipticCurvePublicKey):
            try:
                if key.public_numbers() == scalar_four_point(type(key.curve)):
                    weak = True
                    self.finding('EC_PRIVATE_SCALAR_4', 'critical', source,
                                 'Public point equals 4 times the curve generator.',
                                 curve=key.curve.name, **details)
            except (ValueError, UnsupportedAlgorithm):
                self.gap(source, 'Unable to evaluate scalar 4 on this EC curve.')
        if digest in self.roots:
            active = context in ('effective-system-tls', 'nss-trusted-tls')
            self.finding('AFFECTED_TRUST_PATH_ROOT', 'high' if active else 'warning', source,
                         'Root public key can anchor an affected chain. Presence alone does '
                         'not prove a client accepts that chain; intermediate blocking may apply.',
                         root=self.roots[digest]['name'], **details)
        return weak

    def certificate(self, cert, source, context):
        der = cert.public_bytes(serialization.Encoding.DER)
        digest = sha256(der)
        self.stats['certificate_occurrences'] += 1
        if digest not in self.certs:
            self.certs[digest] = (cert, [])
        location = (str(source), context)
        if location not in self.certs[digest][1]:
            self.certs[digest][1].append(location)
        if self.key(cert.public_key(), source, context, digest):
            self.weak_certs[digest] = cert

    def der_object(self, data, source, context):
        for loader, kind in ((x509.load_der_x509_certificate, 'cert'),
                             (serialization.load_der_public_key, 'public')):
            try:
                obj = loader(data)
                if kind == 'cert':
                    # Some parsers permit trailing data: require an exact object.
                    if obj.public_bytes(serialization.Encoding.DER) != data:
                        return False
                    self.certificate(obj, source, context)
                else:
                    if spki(obj) != data:
                        return False
                    self.key(obj, source, context)
                    self.stats['public_keys'] += 1
                return True
            except (ValueError, TypeError, UnsupportedAlgorithm):
                continue
        return False

    def content(self, data, source, context='file-presence', depth=0):
        """Read bounded bytes, including embedded PEM and DER in binaries/configuration."""
        suffix = Path(str(source).split('!')[-1]).suffix.lower()
        matched = 0
        pem_ranges = []
        for match in PEM.finditer(data):
            label, body = match[1], match[2]
            pem_ranges.append(match.span())
            loc = f'{source}:pem@{match.start()}'
            try:
                raw = base64.b64decode(re.sub(rb'\s', b'', body), validate=True)
                if label == b'TRUSTED CERTIFICATE':
                    bounds = sequence(raw)
                    raw = raw[:bounds[1]] if bounds else raw
                if label in (b'CERTIFICATE', b'TRUSTED CERTIFICATE', b'PUBLIC KEY'):
                    if self.der_object(raw, loc, context):
                        matched += 1
                    else:
                        self.gap(loc, 'Unparseable certificate/public-key PEM block.')
                elif label in (b'PKCS7', b'CMS'):
                    certs = pkcs7.load_der_pkcs7_certificates(raw)
                    for c in certs:
                        self.certificate(c, loc, context)
                    matched += len(certs)
                elif b'PRIVATE KEY' in label:
                    try:
                        private = serialization.load_pem_private_key(match[0], password=None)
                        self.key(private.public_key(), loc, context)
                        matched += 1
                    except (ValueError, TypeError, UnsupportedAlgorithm):
                        self.gap(loc, 'Encrypted or unsupported private key; no password attempted.')
            except (ValueError, TypeError, UnsupportedAlgorithm):
                self.gap(loc, 'Unsupported or malformed PEM object.')

        # Concatenated/embedded DER: parse only plausible ASN.1 sequence prefixes.
        attempts = 0
        next_offset = 0
        for match in DER_START.finditer(data):
            offset = match.start()
            if offset < next_offset:
                continue
            bounds = sequence(data, offset)
            if not bounds:
                continue
            head, end = bounds
            if not 64 <= end - offset <= 65536 or data[head:head + 1] != b'\x30':
                continue
            attempts += 1
            if attempts > self.max_candidates:
                self.gap(source, 'DER candidate limit reached; remainder not parsed.')
                break
            if self.der_object(data[offset:end], f'{source}:der@{offset}', context):
                matched += 1
                next_offset = end

        if suffix in ('.p7b', '.p7c') and not matched:
            try:
                certs = pkcs7.load_der_pkcs7_certificates(data)
                for c in certs:
                    self.certificate(c, source, context)
                matched += len(certs)
            except (ValueError, UnsupportedAlgorithm):
                self.gap(source, 'Unsupported PKCS#7 container.')
        if suffix in ('.p12', '.pfx'):
            try:
                private, cert, extra = pkcs12.load_key_and_certificates(data, None)
                for c in ([cert] if cert else []) + list(extra):
                    self.certificate(c, source, context)
                    matched += 1
                if private:
                    self.key(private.public_key(), source, context)
            except (ValueError, UnsupportedAlgorithm):
                self.gap(source, 'Encrypted or unsupported PKCS#12; no password attempted.')
        if suffix == '.key' and not pem_ranges:
            try:
                private = serialization.load_der_private_key(data, None)
                self.key(private.public_key(), source, context)
                matched += 1
            except (ValueError, TypeError, UnsupportedAlgorithm):
                self.gap(source, 'Unparsed .key file (may be encrypted or a different key format).')
        if suffix in CERT_SUFFIXES - {'.p12', '.pfx', '.jks', '.keystore'} and not matched:
            self.gap(source, 'No supported certificate/public key parsed from certificate-named file.')

        # Match actual risky curl options, not arbitrary mentions in source code.
        if Path(str(source)).name in ('.curlrc', 'curlrc'):
            for line in data.decode('utf-8', errors='replace').splitlines():
                if re.match(r'^\s*(?:--)?(?:insecure|proxy-insecure)(?:\s|=|$)', line) or line.strip() == '-k':
                    self.finding('TLS_VERIFICATION_DISABLED', 'high', source,
                                 'curl configuration enables insecure TLS verification.')
                    break

        compression = None
        if data.startswith(b'\x28\xb5\x2f\xfd'):
            compression = 'zstd'
        elif data.startswith(b'\x1f\x8b'):
            compression = 'gzip'
        elif data.startswith(b'\xfd7zXZ\x00'):
            compression = 'xz'
        elif data.startswith(b'BZh'):
            compression = 'bzip2'
        if compression:
            if self.archives and depth < 3:
                self.compressed(data, source, context, depth, compression)
            else:
                self.gap(source, 'Compressed contents not expanded (enable --archives; nesting limit 3).')
        elif (str(source).lower().endswith(ARCHIVE_SUFFIXES)
              or data.startswith(b'PK\x03\x04') or data[257:262] == b'ustar'):
            if self.archives and depth < 3:
                self.archive(data, source, context, depth)
            else:
                self.gap(source, 'Archive contents not expanded (enable --archives; nesting limit 3).')
        elif str(source).lower().endswith(OPAQUE_SUFFIXES):
            self.gap(source, 'Opaque image/compression unsupported; scan an unpacked or mounted filesystem.')

    def compressed(self, data, source, context, depth, kind):
        try:
            if kind == 'zstd':
                try:
                    import zstandard
                except ImportError:
                    self.gap(source, 'Zstandard support missing; install python-zstandard or scan unpacked files.')
                    return
                limit = min(self.max_archive, self.max_total - self.stats['bytes_read'])
                declared = zstandard.frame_content_size(data)
                if declared > limit:
                    self.gap(source, 'Zstandard frame exceeds archive or total byte limit.')
                    return
                payload = zstandard.ZstdDecompressor(max_window_size=32768).decompress(
                    data, max_output_size=max(1, limit + 1), allow_extra_data=False)
                if declared < 0:
                    self.gap(source, 'Zstandard unknown-length frame decoded; trailing concatenated frames cannot be ruled out by this decoder.')
                stream = io.BytesIO(payload)
            elif kind == 'gzip':
                stream = gzip.GzipFile(fileobj=io.BytesIO(data))
            elif kind == 'xz':
                # LZMAFile has no decoder memory limit; use LZMADecompressor instead.
                decoder = lzma.LZMADecompressor(memlimit=64 << 20)
                limit = min(self.max_archive, self.max_total - self.stats['bytes_read'])
                payload = decoder.decompress(data, max_length=limit + 1)
                if not decoder.eof:
                    self.gap(source, 'XZ stream truncated or expansion/memory limit reached.')
                    return
                if decoder.unused_data.strip(b'\x00'):
                    self.gap(source, 'Concatenated XZ streams not completely inspected.')
                stream = io.BytesIO(payload)
            else:
                stream = bz2.BZ2File(io.BytesIO(data))
            limit = min(self.max_archive, self.max_total - self.stats['bytes_read'])
            with stream:
                payload = stream.read(max(0, limit) + 1)
            if len(payload) > limit:
                self.gap(source, 'Compressed expansion exceeds archive or total byte limit.')
                return
            self.stats['bytes_read'] += len(payload)
            self.stats['compressed_streams'] += 1
            # Magic detection on the next call also handles tar streams without a suffix.
            name = re.sub(r'\.(?:gz|xz|bz2|zst|tgz)$', '', str(source), flags=re.I)
            self.content(payload, name + '!decompressed', context, depth + 1)
        except (OSError, EOFError, ValueError, lzma.LZMAError) as exc:
            self.gap(source, f'Cannot decompress {kind}: {type(exc).__name__}.')
        except Exception as exc:
            if type(exc).__module__ == 'zstandard.backend_c':
                self.gap(source, 'Zstandard decoder rejected the stream or its window size.')
            else:
                raise

    def archive(self, data, source, context, depth):
        """Stream members in memory; never extract paths or follow archive links."""
        expanded = 0
        count = 0

        def member(name, size, opener):
            nonlocal expanded, count
            count += 1
            if count > self.max_members or expanded + size > self.max_archive:
                raise OverflowError('Archive member/expanded-byte limit reached.')
            if size > self.max_file or self.stats['bytes_read'] + size > self.max_total:
                self.gap(f'{source}!{name}', 'Member exceeds file or total byte limit.')
                return
            with opener() as stream:
                payload = stream.read(min(self.max_file, self.max_archive - expanded) + 1)
            if len(payload) > self.max_file or expanded + len(payload) > self.max_archive:
                raise OverflowError('Expanded member exceeds byte limit.')
            expanded += len(payload)
            self.stats['bytes_read'] += len(payload)
            self.stats['archive_members'] += 1
            self.content(payload, f'{source}!{name}', context, depth + 1)

        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                # Bound the central directory before ZipFile allocates ZipInfo objects.
                end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
                if end < 0 or end + 22 > len(data):
                    raise ValueError('Invalid ZIP end record')
                advertised = int.from_bytes(data[end + 10:end + 12], 'little')
                directory_size = int.from_bytes(data[end + 12:end + 16], 'little')
                if (advertised > self.max_members or directory_size > self.max_members * 4096
                        or data.count(b'PK\x01\x02') > self.max_members):
                    raise OverflowError('ZIP central directory limit')
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for entry in archive.infolist():
                        if entry.is_dir():
                            continue
                        if entry.flag_bits & 1:
                            self.gap(f'{source}!{entry.filename}', 'Encrypted ZIP member.')
                            continue
                        member(entry.filename, entry.file_size, lambda: archive.open(entry))
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode='r|*') as archive:
                    for entry in archive:
                        if entry.isfile():
                            member(entry.name, entry.size, lambda: archive.extractfile(entry))
                        elif not entry.isdir():
                            self.gap(f'{source}!{entry.name}', 'Archive link or special member not followed.')
        except (OSError, ValueError, EOFError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, OverflowError) as exc:
            self.gap(source, f'Archive incomplete: {type(exc).__name__}.')

    def excluded(self, path):
        return any(path == x or x in path.parents for x in self.exclusions)

    def file(self, path):
        try:
            resolved = path.resolve(strict=True)
            if self.excluded(resolved):
                self.gap(path, 'Excluded by --exclude (resolved target).')
                return
            if any(str(resolved) == p or str(resolved).startswith(p + '/') for p in VIRTUAL):
                self.gap(path, 'Virtual filesystem target skipped.')
                return
            fd = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode):
                    self.gap(path, 'Nonregular file skipped.')
                    return
                inode = (st.st_dev, st.st_ino)
                if inode in self.seen_files:
                    self.stats['aliases_skipped'] += 1
                    return
                self.seen_files.add(inode)
                if path.name == 'cert9.db':
                    self.nss_databases.append(resolved)
                if path.name == 'cert8.db':
                    self.gap(path, 'Legacy NSS DBM database requires manual export.')
                if path.suffix.lower() in ('.jks', '.keystore') or path.name == 'cacerts':
                    self.jks_stores.append(resolved)
                if st.st_size > self.max_file:
                    self.gap(path, 'File size exceeds --max-file-mib.')
                    return
                if self.stats['bytes_read'] + st.st_size > self.max_total:
                    self.total_exhausted = True
                    self.gap(path, 'Total byte budget reached; scan incomplete.')
                    return
                data = stream.read(self.max_file + 1)
                if len(data) > self.max_file:
                    self.gap(path, 'File grew beyond --max-file-mib during scan.')
                    return
                self.stats['bytes_read'] += len(data)
                self.stats['files_read'] += 1
                self.content(data, str(path))
                after = os.fstat(stream.fileno())
                if (st.st_size, st.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    self.gap(path, 'File changed during scan; repeat on a stable filesystem.')
        except (OSError, RuntimeError, ValueError) as exc:
            self.gap(path, f'Cannot read file: {type(exc).__name__}.')

    def walk(self, paths):
        for root in paths:
            root = Path(root).absolute()
            if self.excluded(root):
                self.gap(root, 'Excluded by --exclude.')
                continue
            if not root.is_dir():
                self.file(root)
                continue
            for directory, dirs, files in os.walk(root, followlinks=False,
                                                  onerror=lambda e: self.gap(e.filename, 'Directory unreadable.')):
                current = Path(directory)
                if any(str(current) == p or str(current).startswith(p + '/') for p in VIRTUAL):
                    dirs[:] = []
                    continue
                for name in list(dirs):
                    p = current / name
                    if self.excluded(p) or p.is_symlink():
                        dirs.remove(name)
                        self.gap(p, 'Directory excluded or symlink not traversed; select target explicitly if needed.')
                for name in files:
                    p = current / name
                    if self.excluded(p):
                        self.gap(p, 'Excluded by --exclude.')
                        continue
                    self.file(p)
                    if self.total_exhausted:
                        self.gap(root, 'Traversal stopped at total byte budget.')
                        return

    def verify_issuers(self):
        """Confirm direct signatures; issuer names alone never establish a relationship."""
        for digest, (cert, locations) in self.certs.items():
            for issuer_digest, issuer in self.weak_certs.items():
                if digest == issuer_digest or cert.issuer != issuer.subject:
                    continue
                try:
                    cert.verify_directly_issued_by(issuer)
                except (ValueError, TypeError, UnsupportedAlgorithm, InvalidSignature):
                    continue
                for source, context in locations:
                    self.finding('SIGNED_BY_COMPROMISED_KEY', 'critical', source,
                                 'Direct certificate signature verified against a discovered compromised key. '
                                 'This is not proof of malicious issuance or runtime trust.',
                                 cert_sha256=digest, issuer_cert_sha256=issuer_digest, context=context)

    def report(self):
        return {'findings': self.findings, 'coverage_gaps': self.gaps,
                'statistics': {**dict(self.stats), 'unique_certificates': len(self.certs)},
                'status': 'findings' if self.findings else ('incomplete' if self.gaps else 'no-findings-in-scope'),
                'limitations': [
                    'This is an incident-specific inventory, not proof that a machine or all TLS clients are safe.',
                    'Presence is not active trust. Browser blocklists, CT, revocation and application policy can differ.',
                    'Encrypted stores, custom encodings, compressed images, remote/hardware stores and cached in-memory trust need separate validation.',
                    'Filesystem bytes cannot prove the absence of past exploitation or malicious executables.',
                    'Only direct signatures to compromised certificates discovered in this scan are checked.',
                ]}
