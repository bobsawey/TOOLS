# eMudhra audit for Arch Linux and CachyOS

A read-only, offline-by-default scanner for the October 2026 eMudhra intermediate
CA incident. It searches system trust, application bundles, configuration files,
and binaries, and reports evidence and coverage gaps. It does **not** certify
that an entire installation is safe or that it has never been attacked.

The incident is broader than a single private key equal to `4`. The rules match
all **eight compromised intermediate public keys** in Go's upstream X.509
blocklist, independently of certificate subject, filename, expiry or reissuance.
The scanner also checks whether any supported EC public key equals `4 × G`.
The affected `EM OV TLS CA - G3C` key is a P-384 key with that value.

Both **emSign ECC Root CA - G3** and **AAA Certificate Services** are relevant
trust paths. Their own private keys are not being labeled compromised. Finding
one in a file is a review item; finding one among effective system TLS anchors
is a higher priority potential exposure. A client with an appropriate
intermediate blocklist can still reject the affected chains.

## Install and run

Use current signed Arch/CachyOS packages through your configured, trusted
repositories. Perform a full upgrade; partial Arch upgrades are unsupported.
These installation commands change packages; the scanner itself does not.

```bash
sudo pacman -Syu --needed python python-cryptography python-zstandard openssl p11-kit nss
cd /path/to/TOOLS/emudhra-audit
python3 check_indicators.py
sudo python3 emudhra_audit.py --archives
```

If you use Java, install/use the appropriate maintained JDK for your application
so `/usr/bin/keytool` is available. The scanner does not require Java otherwise.
`nss` supplies NSS `certutil`. No downloaded scripts are executed, no AUR helper
is required, and no application binaries under inspection are launched.

The default paths are `/etc`, `/usr`, `/opt`, `/home`, `/root`, `/srv`, `/var/lib`
and `/var/cache` when present. These cover typical system, browser, Python venv,
Node/Electron, Java and Flatpak locations. Root permissions allow inspection of
other users' and service accounts' stores. Run an additional scan as each
relevant user or service identity to capture its CA environment overrides:
`sudo` often removes those variables. Only the current process environment is
inspected, not every running service's environment.

For a report with restrictive permissions, create it **outside the scan scope**:

```bash
umask 077
sudo python3 emudhra_audit.py --archives --format json > /tmp/audit-report.json
rc=$?
printf 'Audit exit status: %s\n' "$rc"
```

Do not pipe the scanner into a command that hides its exit status. Reports can
contain local usernames, paths, archive entry names and certificate aliases.
Private key bytes and secret environment values are never written to reports.

Target specific locations or an offline mounted installation:

```bash
python3 emudhra_audit.py --path /path/to/project/.venv --archives
sudo python3 emudhra_audit.py --path /mnt/arch --archives --format json > /tmp/offline-audit.json
python3 emudhra_audit.py --path /etc/ssl/certs/ca-certificates.crt
```

`--path` is repeatable and replaces the default scope. It disables checks of the
running host unless `--system` is explicitly added. NSS/Java adapters still
inspect discovered stores using the **host's** installed tools; target binaries
are never executed. Boot into the target installation and run the default scan
to inspect that installation's effective p11-kit trust and package inventory.

## What gets checked

| Check | Evidence and limits |
| --- | --- |
| Compromised intermediate | Exact SHA-256 of DER SubjectPublicKeyInfo matches one of eight upstream entries. Detects renamed and reissued certificates using the same key. |
| Scalar `4` | EC public point equals `4 × G`, using the installed cryptography/OpenSSL implementation. This is not a general weak-key search; other incident keys are covered by their exact hashes. |
| Relevant roots | Root public-key identity, not a substring search. Includes the AAA cross-signing path. Root presence does not prove active acceptance. |
| Directly issued certificates | Verifies a certificate's direct signature against compromised CA certificates discovered in this scan. Does not merely match issuer names and is not a full chain/trust validator. |
| System TLS trust | p11-kit `trust extract --filter=ca-anchors --purpose=server-auth` exports effective anchors to a temporary bundle. Other clients can have different trust policies. |
| Bundles and binaries | PEM and plausible DER certificates/SPKIs anywhere within a bounded file, including embedded PEM in scripts and DER in ELF files. Does not execute files or infer runtime policy from a package name. |
| NSS profiles | Copies `cert9.db`, `key4.db` and available WAL files into a private temporary directory. NSS uses the key DB to authenticate trust records. Reads public certs/trust flags with `certutil`; original databases are not opened for writing. Does not copy/load profile PKCS#11 module configuration or request passwords. |
| Java | Scans embedded certificates in JKS/PKCS#12; exports stock `cacerts` with `keytool -list -rfc` and the standard `changeit` password. Custom/encrypted stores require an owner-provided public export. |
| PKCS#7 / PKCS#12 | Extracts public certificates from supported containers. PKCS#12 with no password is supported; encrypted stores are gaps. |
| Local private keys | Reads supported unencrypted PEM and `.key` DER objects only to check the public key; never reports private material. Encrypted keys are gaps. |
| Archives | With `--archives`, scans ZIP/JAR/WAR/wheel/egg, tar and gzip/xz/bzip2/Zstandard content in memory, including Arch `.pkg.tar.zst` caches. Magic detection also recognizes common streams without a filename suffix. No paths are extracted; archive links are not followed. |
| Runtime/config context | Recognized CA environment paths, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY=true`, and active insecure options in `.curlrc`/`curlrc`. Arbitrary program configuration syntax is not interpreted. |
| Packages/processes | Relevant installed versions from read-only `pacman -Q`; reports processes still using deleted executables. This is inventory, not an online vulnerability feed or proof that a patched process restarted. |

Temporary NSS copies can contain private-key database material; they are held
under a mode-0700 directory and removed on normal completion. No private keys
are exported. Avoid interrupting the process with SIGKILL; inspect and remove
its `emudhra-nss-*` temporary directory if a crash leaves one behind. Close a
browser before scanning its profile for the most reliable snapshot. Live
database changes, primary passwords, hardware tokens and external NSS modules
need separate checks. Read operations may update filesystem access timestamps.

## Reading results

| Exit status | Meaning |
| --- | --- |
| `0` | No matching findings and no recorded gaps **within the requested scope**. General limitations still apply. |
| `1` | Findings exist, including potential trust-path exposure. Read the evidence and any accompanying gaps. |
| `2` | No findings, but inspection is incomplete; also used for invalid arguments. |
| `130` | Interrupted; no complete report. |

`COMPROMISED_EMUDHRA_KEY` and `EC_PRIVATE_SCALAR_4` confirm a key identity, not
active exploitation. `SIGNED_BY_COMPROMISED_KEY` confirms a direct signature,
not malicious issuance. `AFFECTED_TRUST_PATH_ROOT` is potential exposure:
`warning` for a stored/bundled certificate, `high` for an exported effective
system or NSS TLS trust anchor. Blocklist files and this tool's public test
fixtures may produce expected findings. Investigate each source's purpose.

Unreadable directories, encrypted stores, oversize files, missing adapters,
unexpanded archives, untraversed directory symlinks and explicit exclusions are
reported as gaps. A permission failure, missing dependency or failed helper
never becomes a reassuring clean result. JSON contains the full scope, resource
limits, source references, inventory, findings, gaps and limitations.

Default limits are 128 MiB per file, 16 GiB file input plus expanded stream/member
bytes, 256 MiB expansion per archive, 10,000 members per archive, three archive
levels and 50,000 plausible DER candidates per file. Helper outputs and temporary
database snapshots have separate per-file bounds. Zstandard frames with unknown
declared size are scanned but carry a gap because trailing frames cannot always
be ruled out; concatenated XZ streams likewise need an unpacked scan. Increase limits for your
installation, e.g. `--max-file-mib 512 --max-total-mib 65536`. Exclude unrelated
data with repeatable `--exclude /absolute/path`. Directory symlinks are not
traversed; file symlinks resolve to regular files and inode aliases are scanned
once. Virtual filesystems are excluded. Select separate mounted filesystems
explicitly; avoid concurrently modifying a filesystem during an audit.

Opaque AppImages, SquashFS, encrypted disks, unmounted container storage,
proprietary formats, base64/hex without PEM framing, custom
trust-anchor encodings, HSMs, remote stores and in-memory trust are outside the
parser's guarantees. Mount or unpack images with the appropriate maintained
tool, then scan their contents. An image with unrecognized framing/compression
may not be identifiable as an archive. Statically embedded certificate fragments
can also evade DER/SPKI parsing. Absence of a finding cannot prove that every
application rejects the compromised chains.

## Responding to findings

1. Update the entire Arch/CachyOS system through trusted repositories, including
   CA packages, NSS, browsers, language runtimes and affected applications.
   Update/rebuild bundled Python environments, Electron/Node distributions,
   statically linked applications, containers and Flatpaks independently.
2. For a compromised intermediate or matching key, determine why the file is
   present and whether the application trusts or uses it. Follow the vendor's
   incident guidance. A public test fixture or historical certificate is not
   evidence of a host compromise.
3. For a relevant root, establish the actual client's trust and intermediate
   blocking behavior. A current browser's CT/revocation protection does not
   establish that a CLI, code-signing verifier or another TLS library is safe.
   Do not assume updating the system CA bundle updates a bundled trust store.
4. If vendor guidance requires an emergency distrust workaround, use that
   application's supported trust-management mechanism, preserve a rollback,
   and account for both root paths. The scanner deliberately makes no trust
   edits: removing a broadly used root can break unrelated legitimate chains.
5. Restart affected processes, then scan again. Resolve gaps with owners of
   encrypted stores and hardware-backed applications. For behavioral assurance,
   use a controlled TLS test for each actual client, with a working trusted
   positive control and a known affected negative control. A generic connection
   failure or DNS timeout is not evidence of secure rejection.

`check_indicators.py` is the only command that makes an outbound request. It
fetches the current Go X.509 blocklist over verified HTTPS, compares hashes,
and reports drift without changing files. The bundled review date is
**2026-11-08**; scans flag a review older than 30 days. A successful comparison
checks the key list only, not every vendor advisory or mitigation release.
Review new upstream information before editing `indicators.json`; do not
silently trust a changed or unavailable feed. No arbitrary "latest" package
version floor is embedded in this tool.

## Sources and verification

- [Go's authoritative blocklist, pinned revision](https://github.com/golang/go/blob/edcdd30e39ef493fa031cd582a5705500b09a762/src/crypto/x509/verify.go)
  and [Go issue 82345](https://github.com/golang/go/issues/82345).
- [Incident disclosure](https://emudhra.we-have-a-problem.com/) and
  [Mozilla incident 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).
  These two sites were inaccessible under the implementation environment's
  network policy; their contents were not independently fetched here.
- [Mozilla's public certdata mirror](https://raw.githubusercontent.com/mozilla/gecko-dev/master/security/nss/lib/ckfw/builtins/certdata.txt)
  supplies the two root identities. It can lag current NSS distrust policy;
  its presence is not a statement of current browser trust.
- [Incident tracking with both trust paths](https://github.com/platform-mesh/platform-mesh/issues/469).
  Third-party version claims are not used as detection rules.

`indicators.json` records SHA-256 checksums of the retrieved upstream sources.
The Go source checksum was independently checked against its pinned revision.
Tests include seven public intermediate certificates and the eighth public
key from [this public certificate mirror at a pinned commit](https://github.com/Henryisnotavailable/eMudhra-CA-Compromise/tree/496dd5f9da740f8f984a61d65bf1d900287fd5be/public_certs).
Every fixture's SPKI is checked against the authoritative Go list. The mirror
is not treated as an independent source of trust; no scripts or private keys
from that repository are included. Public fixtures are deliberately detectable.

## Development

Python 3.10+ and a maintained `cryptography` release (minimum API version 42).
For a non-Arch test environment, use a local venv if dependencies are missing:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Or use `python3 -m unittest discover -s tests -v` with distro dependencies.
The suite covers real incident keys, root paths, direct signatures, a normal
certificate, malformed inputs, private-key redaction, encryption, embedded
binary certificates, archives and limits, exit statuses, and NSS integration
when `certutil` is present. The Linux development host is Debian; an actual
Arch/CachyOS installation and its live applications must still be audited there.

Licensed under the repository's Apache-2.0 license.
