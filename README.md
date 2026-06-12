# Linux Vulnerability Checker

A dependency-free Linux security audit tool based on the KISA Critical Information Infrastructure Technical Vulnerability Assessment criteria (U-01~U-72) and CIS Benchmark. Designed to run directly on a target server without installing additional runtime packages.

## Status

- KISA 2021 Unix/Linux U-01~U-72 implemented
- CIS/STIG-based extension checks EX01~EX06 implemented
- Plain-text result output implemented
- Python 3 JSON/HTML report generation implemented
- Check ID registry added: `checks/check_registry.tsv`
- Local validation complete: `bash -n`, `shellcheck`, `bats`, Python compile, registry consistency, parser sample
- Remaining validation: actual root-privilege scans on Rocky Linux 8/9, RHEL 8/9, Ubuntu 20.04/22.04

## Supported Targets

- CentOS 7
- Rocky Linux 8/9
- RHEL 8/9
- Ubuntu 20.04/22.04

Written to Bash 4.2+ to accommodate the default Bash on CentOS 7. This is a Linux-only scanner; on macOS, only unit tests and static validation are supported. Real scans must be run as root on a Linux server.

## Requirements

Runtime:

- Bash 4.2+
- Standard GNU/Linux utilities: `awk`, `grep`, `sed`, `stat`, `find`, `ps`, `sysctl`, etc.
- root privileges
- Python 3 (optional): automatically generates JSON/HTML reports when present

Python packages:

- No external pip packages required
- `requirements.txt` exists solely to document that there are no runtime pip dependencies

Development tools:

- `shellcheck`: Bash static analysis
- `bats-core`: Bash unit tests

macOS development setup example:

```bash
brew install shellcheck bats-core
```

## Quick Start

```bash
sudo ./vuln-checker.sh
```

Results are written under `results/`:

```text
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.txt
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.json
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.html
```

If Python 3 is not available, only the plain-text report is generated.

## Output Labels

| Label | Meaning | Counted in score |
|-------|---------|-----------------|
| `[안전]` (Safe) | Passes automated check criteria | Yes |
| `[취약]` (Vulnerable) | Fails automated check criteria | Yes |
| `[권장]` (Recommended) | Requires manual review or policy decision | No |
| `[정보]` (Info) | Informational data only | No |
| `[PASS]` | Not applicable (not installed, file absent, etc.) | No |

Score is calculated from `[안전]` and `[취약]` counts only. `[권장]`, `[정보]`, and `[PASS]` are excluded from scoring.

## Project Layout

```text
vuln-checker/
├── vuln-checker.sh
├── lib/
│   ├── common.sh
│   ├── os_detect.sh
│   └── output.sh
├── checks/
│   ├── U01_account.sh
│   ├── U02_files.sh
│   ├── U03_services.sh
│   ├── U04_web.sh
│   ├── U05_patch.sh
│   ├── U06_log.sh
│   ├── EX01_ssh.sh
│   ├── EX02_kernel.sh
│   ├── EX03_audit.sh
│   ├── EX04_sudo.sh
│   ├── EX05_filesystem.sh
│   ├── EX06_integrity.sh
│   └── check_registry.tsv
├── report/
│   └── generate_report.py
├── tests/
│   └── test_common.bats
└── requirements.txt
```

## Check Coverage

KISA modules:

| Module | Coverage |
|--------|----------|
| `U01_account.sh` | U-01~U-04, U-44~U-53, U-66 |
| `U02_files.sh` | U-05~U-18, U-54~U-57 |
| `U03_services.sh` | U-19~U-34, U-58~U-65 |
| `U04_web.sh` | U-35~U-41 |
| `U05_patch.sh` | U-42 |
| `U06_log.sh` | U-43, U-67~U-72 |

Extension modules:

| Module | Coverage |
|--------|----------|
| `EX01_ssh.sh` | SSH hardening (EX-SSH-01~15) |
| `EX02_kernel.sh` | sysctl, SELinux/AppArmor, IPv6, kernel modules, firewall |
| `EX03_audit.sh` | auditd service and audit rules |
| `EX04_sudo.sh` | sudo config, package integrity, unnecessary services |
| `EX05_filesystem.sh` | mount options, bootloader, core dump, umask, time sync, password history |
| `EX06_integrity.sh` | AIDE/Tripwire, FIPS, package signing, account DB integrity |

`checks/check_registry.tsv` is the canonical registry for check IDs, standards, severity, module ownership, and auto/manual classification.

## Design Notes

- `set -uo pipefail` is used. `set -e` is intentionally omitted because many checks depend on non-zero return codes as normal control flow (e.g., `is_service_active`).
- `result_safe`, `result_vuln`, and `result_warn` must not be called inside a pipeline. Subshell execution would lose counter updates. Use `while ... done < <(...)` or `for` loops instead.
- `check_file_attr` emits one verdict per file and compares permissions via maximum-allowed bitmask, not exact string equality. A stricter actual permission (e.g., 640 vs. limit 644) is treated as safe.
- SSH effective configuration is read via `sshd -T` first, falling back to `/etc/ssh/sshd_config` parsing to correctly handle `Include` directives and OpenSSH defaults.
- All long-running `find` and package-manager commands are wrapped with `run_with_timeout` so that a slow filesystem or repository does not stall the entire scan.

## Validation

Run local validation:

```bash
bash -n vuln-checker.sh lib/*.sh checks/*.sh
python3 -m py_compile report/generate_report.py
shellcheck vuln-checker.sh lib/*.sh checks/*.sh
bats tests/test_common.bats
```

Registry consistency:

```bash
# Check for duplicate IDs
awk -F '\t' 'NR>1 { if (seen[$1]++) print $1 }' checks/check_registry.tsv

# Check for check_header IDs not registered in the registry
comm -23 \
  <(grep -oh 'check_header "[^"]*' checks/*.sh | sed 's/.*check_header "//' | sort -u) \
  <(awk -F '\t' 'NR>1 {print $1}' checks/check_registry.tsv | sort -u)
```

Expected local validation results:

| Check | Result |
|-------|--------|
| `bash -n` | pass |
| `python3 -m py_compile` | pass |
| `shellcheck` | pass |
| `bats` | 30 tests pass; root-only sysctl tests skipped when not root |
| Registry duplicate check | pass |
| Check header registry coverage | pass |

## Known Limits

- Actual vulnerability scanning requires Linux and root privileges.
- macOS is supported only for development-time validation (syntax checks, unit tests).
- Package update checks depend on repository metadata freshness and network/cache availability.
- Some checks intentionally return `[권장]` (Recommended) because the correct answer depends on the server's role or local security policy rather than a fixed threshold.

## Next Work

- Run full scans on Rocky Linux 8/9, RHEL 8/9, Ubuntu 20.04/22.04.
- Add fixture-based regression tests for `sshd_config`, PAM, Apache config, audit rules, and package manager output.
- Split JSON/HTML report scores into separate KISA and EX extension score groups.
- Add CI workflow covering shellcheck, bats, report parser sample, and registry consistency.
