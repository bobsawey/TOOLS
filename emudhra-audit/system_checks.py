"""Optional read-only adapters for the running host's trust stores and packages."""
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

CA_VARIABLES = ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                'NODE_EXTRA_CA_CERTS', 'AWS_CA_BUNDLE', 'GIT_SSL_CAINFO', 'PIP_CERT',
                'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH')


def binary(name):
    # Never resolve helpers from an application directory or a user-controlled PATH.
    for directory in ('/usr/bin', '/bin'):
        path = Path(directory) / name
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def run(scanner, args, source, timeout=30):
    env = os.environ.copy()
    env.update(LC_ALL='C', LANG='C')
    # Do not pass Java launcher flags capable of loading agents from a scanned store.
    for name in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'):
        env.pop(name, None)
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env, stdin=subprocess.DEVNULL, check=False)
        if result.returncode:
            scanner.gap(source, f'{Path(args[0]).name} failed (exit {result.returncode}).')
            return None
        if len(result.stdout) > scanner.max_file:
            scanner.gap(source, 'Helper output exceeds scan byte limit.')
            return None
        return result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        scanner.gap(source, f'Helper unavailable: {type(exc).__name__}.')
        return None


def effective_trust(scanner):
    trust = binary('trust')
    if not trust:
        scanner.gap('system TLS trust', 'p11-kit trust command missing; effective anchors not exported.')
        return
    with tempfile.TemporaryDirectory(prefix='emudhra-trust-') as directory:
        bundle = Path(directory) / 'anchors.pem'
        output = run(scanner, [trust, 'extract', '--filter=ca-anchors', '--purpose=server-auth',
                               '--format=pem-bundle', str(bundle)], 'system TLS trust')
        if output is not None and bundle.exists():
            if bundle.stat().st_size > scanner.max_file:
                scanner.gap('system TLS trust', 'Export exceeds file size limit.')
            else:
                scanner.content(bundle.read_bytes(), 'p11-kit:effective-server-auth', 'effective-system-tls')
                scanner.stats['effective_trust_exports'] += 1
        elif output is not None:
            scanner.gap('system TLS trust', 'Export did not create an anchor bundle.')


def nss(scanner):
    certutil = binary('certutil')
    for db in scanner.nss_databases:
        if not certutil:
            scanner.gap(db, 'certutil missing; NSS trust flags not inspected.')
            continue
        # Use private temporary storage; never load the profile's module configuration.
        with tempfile.TemporaryDirectory(prefix='emudhra-nss-') as directory:
            database = 'sql:' + directory
            if run(scanner, [certutil, '-N', '-d', database, '--empty-password'], str(db)) is None:
                continue
            try:
                # Do not open the source with SQLite: even mode=ro can create WAL/SHM
                # sidecars. Copy the DB and WAL and let NSS recover only the copy.
                # NSS authenticates trust records using key4.db. Substituting an empty
                # key DB silently drops trust flags, so preserve it in the snapshot.
                sources = [db, db.with_name(db.name + '-wal'),
                           db.with_name('key4.db'), db.with_name('key4.db-wal')]
                snapshots = {}
                for source in sources:
                    try:
                        fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                    except FileNotFoundError:
                        if source == db:
                            raise
                        snapshots[source] = None
                        continue
                    with os.fdopen(fd, 'rb') as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode) or before.st_size > scanner.max_file:
                            raise ValueError('NSS source is nonregular or oversized')
                        data = stream.read(scanner.max_file + 1)
                        if len(data) > scanner.max_file:
                            raise ValueError('NSS source grew beyond limit')
                        snapshots[source] = (before.st_ino, before.st_size, before.st_mtime_ns)
                        (Path(directory) / source.name).write_bytes(data)
                for source, snapshot in snapshots.items():
                    try:
                        current = source.stat()
                        observed = (current.st_ino, current.st_size, current.st_mtime_ns)
                    except FileNotFoundError:
                        observed = None
                    if observed != snapshot:
                        raise ValueError('NSS changed while copied; close application and retry')
            except (OSError, ValueError) as exc:
                scanner.gap(db, f'NSS snapshot failed: {type(exc).__name__}.')
                continue
            listing = run(scanner, [certutil, '-L', '-d', database], str(db))
            if listing is None:
                continue
            entries = []
            for line in listing.decode('utf-8', errors='replace').splitlines():
                match = re.match(r'^(.*?)\s+([A-Za-z]*,[A-Za-z]*,[A-Za-z]*)\s*$', line)
                if match:
                    entries.append((match[1].strip(), match[2].split(',')[0]))
            for nickname, flags in entries[:scanner.max_members]:
                data = run(scanner, [certutil, '-L', '-d', database, '-n', nickname, '-a'], str(db))
                if data:
                    context = 'nss-trusted-tls' if 'C' in flags else 'nss-stored'
                    scanner.content(data, f'{db}:nickname={nickname}', context)
            if len(entries) > scanner.max_members:
                scanner.gap(db, 'NSS certificate count limit reached.')
            scanner.stats['nss_databases_checked'] += 1
            scanner.gap(db, 'NSS profile certificates inspected; external modules, locked trust records and browser built-in policies need runtime verification.')


def java(scanner):
    keytool = binary('keytool')
    for store in scanner.jks_stores:
        if not keytool:
            scanner.gap(store, 'keytool missing; only embedded certificates scanned, store trust not inspected.')
            continue
        # No guessing at personal passwords. changeit is the documented stock cacerts password.
        if store.name != 'cacerts':
            scanner.gap(store, 'Custom Java store: export public certificates with keytool and scan the export.')
            continue
        data = run(scanner, [keytool, '-list', '-rfc', '-keystore', str(store),
                             '-storepass', 'changeit'], str(store))
        if data is not None:
            scanner.content(data, f'{store}:keytool-export', 'java-store-presence')
            scanner.stats['java_stores_checked'] += 1


def host_inventory(scanner):
    inventory = {'environment_ca_paths': [], 'packages': [], 'processes_using_deleted_files': []}
    for name in CA_VARIABLES:
        value = os.environ.get(name)
        if value:
            # Values are used as paths, never executed. No full environment or secret dump.
            for item in value.split(os.pathsep):
                if not item:
                    continue
                path = Path(item).expanduser()
                inventory['environment_ca_paths'].append({'variable': name, 'path': str(path)})
                scanner.walk([path])
    for name, value in (('NODE_TLS_REJECT_UNAUTHORIZED', '0'), ('GIT_SSL_NO_VERIFY', 'true')):
        if os.environ.get(name, '').lower() == value:
            scanner.finding('TLS_VERIFICATION_DISABLED', 'high', f'environment:{name}',
                            'Current process environment disables TLS certificate verification.')
    pacman = binary('pacman')
    if pacman:
        data = run(scanner, [pacman, '-Q'], 'pacman installed package inventory')
        if data is not None:
            for line in data.decode(errors='replace').splitlines():
                parts = line.split(' ', 1)
                if len(parts) == 2 and re.search(r'^(ca-certificates|openssl|p11-kit|nss|curl|wget|python.*certifi|nodejs|go$|jdk|jre|firefox|chromium|brave|electron|cachyos)', parts[0]):
                    inventory['packages'].append({'name': parts[0], 'version': parts[1]})
    else:
        scanner.gap('pacman', 'Not installed: Arch/CachyOS package inventory unavailable on this host.')
    try:
        pids = [p for p in Path('/proc').iterdir() if p.name.isdigit()]
        denied = 0
        for pid in pids:
            try:
                target = os.readlink(pid / 'exe')
                if target.endswith(' (deleted)'):
                    inventory['processes_using_deleted_files'].append({'pid': int(pid.name), 'executable': target})
            except PermissionError:
                denied += 1
            except (FileNotFoundError, ProcessLookupError, OSError):
                pass
        if denied:
            scanner.gap('/proc/*/exe', f'{denied} process executables unreadable.')
        if inventory['processes_using_deleted_files']:
            scanner.gap('running processes', 'Deleted executables still running; restart affected applications after upgrades.')
    except OSError:
        scanner.gap('/proc', 'Process inventory unavailable.')
    return inventory
