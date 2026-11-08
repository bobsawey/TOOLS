import io
import gzip
import lzma
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from scanner import Scanner, sha256, spki
from check_indicators import parse_upstream
import system_checks

HERE = Path(__file__).resolve().parent
INDICATORS = json.loads((HERE.parent / 'indicators.json').read_text())


def certificate(key=None, *, issuer=None, signer=None, name='Synthetic audit fixture'):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(signer or key, hashes.SHA256()))


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


class ScannerTests(unittest.TestCase):
    def scanner(self, **kwargs):
        return Scanner(INDICATORS, **kwargs)

    def codes(self, scanner):
        return {f['code'] for f in scanner.findings}

    def weak(self):
        return certificate(ec.derive_private_key(4, ec.SECP384R1()))

    def test_real_compromised_fixtures_match_all_eight(self):
        s = self.scanner()
        for path in (HERE / 'fixtures').glob('EM-*.pem'):
            s.content(path.read_bytes(), str(path))
        actual = {f['spki_sha256'] for f in s.findings if f['code'] == 'COMPROMISED_EMUDHRA_KEY'}
        self.assertEqual(actual, {r['sha256'] for r in INDICATORS['compromised_spki']})

    def test_weak_curve_4_all_common_curves_and_renamed_subject(self):
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
            with self.subTest(curve=curve.name):
                s = self.scanner()
                s.content(pem(certificate(ec.derive_private_key(4, curve), name='unrelated name')), 'bundle')
                self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))

    def test_regular_key_is_not_flagged_even_with_emudhra_name(self):
        s = self.scanner()
        s.content(pem(certificate(name='eMudhra')), 'normal.pem')
        self.assertEqual(s.findings, [])
        self.assertEqual(s.gaps, [])

    def test_root_keys_have_context_specific_severity(self):
        for root in ('emSign_ECC_Root_CA_-_G3.pem', 'AAA_Certificate_Services.pem'):
            data = (HERE / 'fixtures' / root).read_bytes()
            for context, severity in [('file-presence', 'warning'), ('effective-system-tls', 'high')]:
                s = self.scanner()
                s.content(data, root, context)
                self.assertEqual(s.findings[0]['severity'], severity)
                self.assertEqual(s.findings[0]['code'], 'AFFECTED_TRUST_PATH_ROOT')
                self.assertNotIn('EC_PRIVATE_SCALAR_4', self.codes(s))

    def test_binary_embedded_der_and_public_key(self):
        s = self.scanner()
        cert = self.weak()
        s.content(b'\x7fELF' + bytes(101) + cert.public_bytes(serialization.Encoding.DER) + bytes(11), 'program')
        s.content(b'header' + spki(cert.public_key()) + b'end', 'library.so')
        self.assertEqual(sum(f['code'] == 'EC_PRIVATE_SCALAR_4' for f in s.findings), 2)

    def test_bundle_scans_all_certificates(self):
        s = self.scanner()
        s.content(pem(certificate()) + pem(self.weak()) + pem(certificate()), 'ca-bundle.pem')
        self.assertEqual(len(s.certs), 3)
        self.assertIn('COMPROMISED_EMUDHRA_KEY', self.codes(s))

    def test_corrupt_pem_and_huge_der_length_do_not_crash(self):
        s = self.scanner()
        s.content(b'-----BEGIN CERTIFICATE-----\n!not-base64\n-----END CERTIFICATE-----', 'broken.pem')
        s.content(b'\x30\x84\xff\xff\xff\xff\x30' + bytes(100), 'hostile')
        self.assertTrue(s.gaps)
        self.assertEqual(s.findings, [])

    def test_public_key_pem(self):
        s = self.scanner()
        data = self.weak().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        s.content(data, 'pub.pem')
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))

    def test_private_key_never_serialized_to_report(self):
        s = self.scanner()
        key = ec.derive_private_key(4, ec.SECP256R1())
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        s.content(data, 'local.key')
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))
        self.assertNotIn(data.decode(), json.dumps(s.report()))
        self.assertNotIn('BEGIN PRIVATE KEY', json.dumps(s.report()))

    def test_encrypted_private_key_is_gap(self):
        key = ec.generate_private_key(ec.SECP256R1())
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.BestAvailableEncryption(b'test-password'))
        s = self.scanner()
        s.content(data, 'encrypted.key')
        self.assertTrue(s.gaps)

    def test_pkcs12_empty_and_encrypted(self):
        key = ec.derive_private_key(4, ec.SECP384R1())
        cert = certificate(key)
        for encryption, expected in [(serialization.NoEncryption(), True),
                                     (serialization.BestAvailableEncryption(b'password'), False)]:
            s = self.scanner()
            s.content(pkcs12.serialize_key_and_certificates(b'test', key, cert, None, encryption), 'store.p12')
            self.assertEqual('EC_PRIVATE_SCALAR_4' in self.codes(s), expected)
            if not expected:
                self.assertTrue(s.gaps)

    def test_direct_issuer_signature_not_name_only(self):
        key = ec.derive_private_key(4, ec.SECP256R1())
        issuer = certificate(key)
        good = certificate(issuer=issuer, signer=key)
        impostor = certificate(issuer=issuer, signer=ec.generate_private_key(ec.SECP256R1()))
        s = self.scanner()
        for cert, source in [(issuer, 'issuer'), (good, 'valid'), (impostor, 'invalid')]:
            s.content(pem(cert), source)
        s.verify_issuers()
        findings = [f for f in s.findings if f['code'] == 'SIGNED_BY_COMPROMISED_KEY']
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]['source'].startswith('valid:'))

    def zip(self, name, data):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, data)
        return output.getvalue()

    def test_zip_member_cannot_traverse_filesystem(self):
        s = self.scanner(archives=True)
        s.content(self.zip('../../outside.pem', pem(self.weak())), 'application.jar')
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))
        self.assertEqual(s.stats['archive_members'], 1)

    def test_archives_disabled_are_coverage_gaps(self):
        s = self.scanner()
        s.content(self.zip('ca.pem', pem(self.weak())), 'application.whl')
        self.assertTrue(s.gaps)
        self.assertEqual(s.stats['archive_members'], 0)

    def test_zip_expansion_limit(self):
        s = self.scanner(archives=True, max_archive=100)
        s.content(self.zip('huge', bytes(100000)), 'bomb.zip')
        self.assertTrue(s.gaps)
        self.assertEqual(s.stats['archive_members'], 0)

    def test_nested_archive_depth_limit(self):
        data = pem(self.weak())
        for name in ('cert.pem', 'a.zip', 'b.zip', 'c.zip', 'd.zip'):
            data = self.zip(name, data)
        s = self.scanner(archives=True)
        s.content(data, 'outer.zip')
        self.assertTrue(any('nesting' in g['reason'] for g in s.gaps))

    def test_tar_and_link_handling(self):
        output = io.BytesIO()
        data = pem(self.weak())
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            info = tarfile.TarInfo('cert.pem'); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo('link'); link.type = tarfile.SYMTYPE; link.linkname = '/etc/shadow'
            archive.addfile(link)
        s = self.scanner(archives=True)
        s.content(output.getvalue(), 'bundle.tar.gz')
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))
        self.assertTrue(any('link' in g['reason'] for g in s.gaps))

    def test_magic_compression_without_filename(self):
        for compressor in (gzip.compress, lzma.compress):
            s = self.scanner(archives=True)
            s.content(compressor(pem(self.weak())), 'opaque-blob')
            self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))

    def test_compressed_expansion_and_truncation(self):
        s = self.scanner(archives=True, max_archive=10)
        s.content(gzip.compress(bytes(1000)), 'bomb.gz')
        s.content(lzma.compress(bytes(1000))[:-10], 'broken.xz')
        self.assertEqual(len(s.gaps), 2)

    def test_zstandard_arch_package(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest('zstandard not installed')
        output = io.BytesIO()
        data = pem(self.weak())
        with tarfile.open(fileobj=output, mode='w') as archive:
            info = tarfile.TarInfo('usr/share/app/cert.pem'); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        s = self.scanner(archives=True)
        s.content(zstandard.ZstdCompressor().compress(output.getvalue()), 'package.pkg.tar.zst')
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(s))
        self.assertFalse(s.gaps)
        broken = self.scanner(archives=True)
        broken.content(b'\x28\xb5\x2f\xfdgarbage', 'broken.zst')
        self.assertTrue(broken.gaps)
        truncated = self.scanner(archives=True)
        truncated.content(zstandard.ZstdCompressor().compress(output.getvalue())[:-3], 'truncated.zst')
        self.assertTrue(truncated.gaps)
        unknown = self.scanner(archives=True)
        unknown.content(zstandard.ZstdCompressor(write_content_size=False).compress(output.getvalue()), 'unknown.zst')
        self.assertTrue(unknown.gaps)
        self.assertIn('EC_PRIVATE_SCALAR_4', self.codes(unknown))

    def test_zip_member_count_limit(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for i in range(3):
                archive.writestr(str(i), b'x')
        s = self.scanner(archives=True, max_members=2)
        s.content(output.getvalue(), 'too-many.zip')
        self.assertTrue(s.gaps)
        self.assertEqual(s.stats['archive_members'], 0)

    def test_file_budget_symlinks_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cert.pem').write_bytes(pem(self.weak()))
            (root / 'alias').symlink_to(root / 'cert.pem')
            os.mkfifo(root / 'pipe')
            s = self.scanner()
            s.walk([root])
            self.assertEqual(s.stats['files_read'], 1)
            self.assertEqual(s.stats['aliases_skipped'], 1)
            self.assertTrue(any('Nonregular' in g['reason'] for g in s.gaps))
            limited = self.scanner(max_total=10)
            limited.walk([root / 'cert.pem'])
            self.assertTrue(limited.gaps)
            self.assertEqual(limited.stats['files_read'], 0)

    def test_oversized_file_and_unreadable_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large'
            path.write_bytes(bytes(20))
            s = self.scanner(max_file=10)
            s.walk([path, path.with_name('missing')])
            self.assertEqual(len(s.gaps), 2)

    def test_explicit_exclusions_and_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'inner').mkdir()
            (root / 'inner' / 'weak.pem').write_bytes(pem(self.weak()))
            (root / 'alias').symlink_to(root / 'inner', target_is_directory=True)
            s = self.scanner(exclusions=[root / 'inner'])
            s.walk([root])
            self.assertEqual(s.findings, [])
            self.assertEqual(len(s.gaps), 2)

    def test_curl_config_ignores_comments(self):
        s = self.scanner()
        s.content(b'# insecure\n# -k\n', '/home/a/.curlrc')
        self.assertEqual(s.findings, [])
        s.content(b'insecure\n', '/home/b/.curlrc')
        self.assertIn('TLS_VERIFICATION_DISABLED', self.codes(s))

    def test_pacman_and_missing_helpers_are_explicit(self):
        s = self.scanner()
        with patch('system_checks.binary', return_value=None):
            system_checks.effective_trust(s)
        self.assertTrue(any('p11-kit' in g['reason'] for g in s.gaps))

    def test_upstream_parser_rejects_layout_change_or_short_list(self):
        for text in ('404 not found', 'var distrustedSPKIHashes = map[string]struct{}{\n}'):
            with self.assertRaises(ValueError):
                parse_upstream(text)
        body = '\n'.join('"' + item['sha256'] + '": {},' for item in INDICATORS['compromised_spki'])
        self.assertEqual(len(parse_upstream('var distrustedSPKIHashes = map[string]struct{}{\n' + body + '\n}')), 8)

    def test_cli_exit_codes_json_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data, expected in [('clean.pem', pem(certificate()), 0),
                                         ('weak.pem', pem(self.weak()), 1), ('broken.pem', b'bad', 2)]:
                path = root / name
                path.write_bytes(data)
                before = (path.read_bytes(), path.stat().st_mtime_ns)
                result = subprocess.run([sys.executable, str(HERE.parent / 'emudhra_audit.py'),
                                         '--path', str(path), '--format', 'json'], capture_output=True, check=False)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                report = json.loads(result.stdout)
                self.assertEqual(report['scope']['host_checks'], False)
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    @unittest.skipUnless(system_checks.binary('certutil'), 'NSS certutil unavailable')
    def test_nss_actual_public_database_trust_flags_and_no_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = 'sql:' + directory
            certutil = system_checks.binary('certutil')
            subprocess.run([certutil, '-N', '-d', db, '--empty-password'], check=True, capture_output=True)
            cert = HERE / 'fixtures' / 'AAA_Certificate_Services.pem'
            subprocess.run([certutil, '-A', '-d', db, '-n', 'Audit root', '-t', 'C,,', '-i', str(cert)], check=True, capture_output=True)
            before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
            s = self.scanner()
            s.nss_databases.append(root / 'cert9.db')
            system_checks.nss(s)
            self.assertTrue(any(f['context'] == 'nss-trusted-tls' and f['severity'] == 'high' for f in s.findings), s.gaps)
            after = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
            self.assertEqual(before, after)

    @unittest.skipUnless(system_checks.binary('keytool'), 'Java keytool unavailable')
    def test_java_actual_store_no_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / 'cacerts'
            subprocess.run([system_checks.binary('keytool'), '-importcert', '-noprompt',
                            '-keystore', str(store), '-storepass', 'changeit', '-alias', 'audit-root',
                            '-file', str(HERE / 'fixtures' / 'AAA_Certificate_Services.pem')],
                           check=True, capture_output=True)
            before = store.read_bytes()
            s = self.scanner()
            s.jks_stores = [store]
            system_checks.java(s)
            self.assertTrue(any(f['code'] == 'AFFECTED_TRUST_PATH_ROOT' for f in s.findings), s.gaps)
            self.assertEqual(before, store.read_bytes())


if __name__ == '__main__':
    unittest.main()
