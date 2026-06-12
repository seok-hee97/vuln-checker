# Linux Vulnerability Checker

KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준과 CIS Benchmark를 참고해 만든 Linux 취약점 자동 점검 도구입니다. 타겟 서버에 추가 런타임 패키지를 설치하지 않고 실행하는 것을 우선합니다.

## Status

- KISA 2021 Unix/Linux U-01~U-72 구현
- CIS/STIG 기반 확장 점검 EX01~EX06 구현
- 텍스트 결과 출력 구현
- Python 3 기반 JSON/HTML 리포트 생성 구현
- 항목 ID registry 추가: `checks/check_registry.tsv`
- 로컬 검증 완료: `bash -n`, `shellcheck`, `bats`, Python compile, registry consistency, parser sample
- 남은 검증: Rocky Linux 8/9, RHEL 8/9, Ubuntu 20.04/22.04 실제 root 실행

## Supported Targets

- CentOS 7
- Rocky Linux 8/9
- RHEL 8/9
- Ubuntu 20.04/22.04

CentOS 7 기본 Bash를 고려해 Bash 4.2+ 기준으로 작성합니다. Linux 대상 스크립트이므로 macOS에서는 단위 테스트와 정적 검증만 수행하고, 실제 스캔은 Linux 서버에서 root 권한으로 실행해야 합니다.

## Requirements

Runtime:

- Bash 4.2+
- GNU/Linux 기본 명령어: `awk`, `grep`, `sed`, `stat`, `find`, `ps`, `sysctl` 등
- root 권한
- Python 3 선택 사항: 있으면 JSON/HTML 리포트를 자동 생성

Python packages:

- 외부 pip 패키지 없음
- `requirements.txt`는 런타임 pip 의존성이 없음을 명시하기 위해 비워두지 않고 주석만 둡니다.

Development tools:

- `shellcheck`: Bash 정적 분석
- `bats-core`: Bash 단위 테스트

macOS 개발 환경 예시:

```bash
brew install shellcheck bats-core
```

## Quick Start

```bash
sudo ./vuln-checker.sh
```

결과는 `results/` 아래에 생성됩니다.

```text
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.txt
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.json
<hostname>_scan_YYYY-MM-DD__HH-MM-SS.html
```

Python 3이 없으면 텍스트 리포트만 생성됩니다.

## Output Labels

- `[안전]`: 자동 점검 기준 통과
- `[취약]`: 자동 점검 기준 미달
- `[권장]`: 환경 의존성이 있어 수동 확인 또는 정책 판단 필요
- `[정보]`: 단순 수집 정보
- `[PASS]`: 미설치, 파일 없음 등으로 해당 없음

점수 계산은 `[안전]`과 `[취약]`만 사용합니다. `[권장]`, `[정보]`, `[PASS]`는 점수에서 제외합니다.

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

- `U01_account.sh`: U-01~U-04, U-44~U-53, U-66
- `U02_files.sh`: U-05~U-18, U-54~U-57
- `U03_services.sh`: U-19~U-34, U-58~U-65
- `U04_web.sh`: U-35~U-41
- `U05_patch.sh`: U-42
- `U06_log.sh`: U-43, U-67~U-72

Extension modules:

- `EX01_ssh.sh`: SSH hardening
- `EX02_kernel.sh`: sysctl, SELinux/AppArmor, IPv6, firewall
- `EX03_audit.sh`: auditd and audit rules
- `EX04_sudo.sh`: sudo, package integrity, unnecessary services
- `EX05_filesystem.sh`: mount options, boot, umask, time sync, password history
- `EX06_integrity.sh`: AIDE/Tripwire, FIPS, package signing, account DB integrity

`checks/check_registry.tsv` is the canonical registry for check IDs, standards, severity, module ownership, and auto/manual classification.

## Design Notes

- `set -uo pipefail` is used. `set -e` is intentionally avoided because many checks rely on non-zero command status as normal control flow.
- `result_safe`, `result_vuln`, and `result_warn` must not be called in a pipeline because subshell execution would lose counter updates.
- `check_file_attr` emits one verdict per file and compares permissions by maximum allowed bitmask, not exact string equality.
- SSH effective configuration uses `sshd -T` first, then falls back to `/etc/ssh/sshd_config` parsing.
- Long-running package update checks use timeout handling and fall back to `[권장]` on timeout or repository query failure.

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
awk -F '\t' 'NR>1 { if (seen[$1]++) print $1 }' checks/check_registry.tsv
comm -23 \
  <(rg -o 'check_header "[^"]+' checks/*.sh | sed 's/.*check_header "//' | sort -u) \
  <(awk -F '\t' 'NR>1 {print $1}' checks/check_registry.tsv | sort -u)
```

Expected current local validation result:

- `bash -n`: pass
- `python3 -m py_compile`: pass
- `shellcheck`: pass
- `bats`: 30 tests pass, root-only sysctl tests skipped when not root
- registry duplicate check: pass
- check header registry coverage: pass

## Known Limits

- Actual vulnerability scan requires Linux and root privileges.
- macOS is supported only for development validation.
- Package update checks depend on repository metadata quality and network/cache state.
- Some checks intentionally return `[권장]` because the correct answer depends on service role or local policy.

## Next Work

- Run full scans on Rocky Linux 8/9, RHEL 8/9, Ubuntu 20.04/22.04.
- Add fixture-based tests for `sshd_config`, PAM, Apache, audit rules, and package manager output.
- Split JSON/HTML scores into KISA and EX extension score groups.
- Add CI workflow for shellcheck, bats, parser sample, and registry consistency.
