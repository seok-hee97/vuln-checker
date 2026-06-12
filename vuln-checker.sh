#!/bin/bash
# Linux Vulnerability Checker
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 (U-01~U-72)
# + CIS Benchmark Extension (EX01~EX06)
#
# 지원 OS: CentOS 7 / Rocky 8,9 / RHEL 8,9 / Ubuntu 20.04, 22.04
# 실행 조건: root 권한 필요
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# ── 라이브러리 로드 ─────────────────────────────────────────────────────────────
# shellcheck source=lib/os_detect.sh
source "${SCRIPT_DIR}/lib/os_detect.sh"
# shellcheck source=lib/output.sh
source "${SCRIPT_DIR}/lib/output.sh"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ── root 권한 확인 ──────────────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    printf '[ERROR] root 권한으로 실행하세요: sudo %s\n' "${0}" >&2
    exit 1
fi

# ── 결과 파일 경로 설정 ─────────────────────────────────────────────────────────
RESULT_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULT_DIR}"
CF="${RESULT_DIR}/$(hostname -s 2>/dev/null || hostname)_scan_$(date +%F__%H-%M-%S).txt"
: > "${CF}"

# ── 전역 카운터 ─────────────────────────────────────────────────────────────────
# source된 모듈이 직접 참조 — export 불필요
# 주의: result_safe/vuln/warn 을 파이프(|) 안에서 호출하면 subshell로
#       인해 카운터가 갱신되지 않음. for/while < <(...) 패턴을 사용할 것.
TOTAL=0
SAFE=0
VULN=0
WARN=0

# ── 배너 + 시스템 정보 ─────────────────────────────────────────────────────────
print_banner
collect_sysinfo

# ── 점검 모듈 순서대로 실행 ────────────────────────────────────────────────────
# 파일이 없는 모듈은 조용히 건너뜀 (선택적 모듈 지원)
MODULES=(
    U01_account    # 계정 관리       U-01~U-04, U-44~U-53, U-66
    U02_files      # 파일 관리       U-05~U-18, U-54~U-57 (hosts.lpd, xinetd.d 포함)
    U03_services   # 서비스 관리     U-19~U-34, U-58~U-65
    U04_web        # 웹 서비스       U-35~U-41
    U05_patch      # 패치 관리       U-42
    U06_log        # 로그 관리       U-43, U-67~U-72
    EX01_ssh       # SSH 하드닝      (CIS Benchmark EX-SSH-01~15)
    EX02_kernel    # 커널/방화벽     (CIS Benchmark EX-KRN-01~09d)
    EX03_audit     # 감사 로그       (CIS Benchmark EX-AUD-01~09)
    EX04_sudo      # sudo/패키지     (CIS Benchmark EX-SUD/PKG/SVC)
    EX05_filesystem # 파일시스템 하드닝 (CIS Benchmark EX-FS-01~11)
    EX06_integrity  # 시스템 무결성   (AIDE/FIPS/패키지서명 EX-INT-01~05)
)

for _mod in "${MODULES[@]}"; do
    _mod_path="${SCRIPT_DIR}/checks/${_mod}.sh"
    if [[ -f "${_mod_path}" ]]; then
        # shellcheck disable=SC1090
        source "${_mod_path}"
    else
        result_warn "점검 모듈 파일 없음: ${_mod}.sh — 해당 항목 건너뜀"
    fi
done
unset _mod _mod_path

# ── 최종 요약 출력 ──────────────────────────────────────────────────────────────
print_summary

# ── JSON/HTML 리포트 생성 (python3 있을 때만) ───────────────────────────────────
if command -v python3 &>/dev/null; then
    _json_path="${CF%.txt}.json"
    python3 "${SCRIPT_DIR}/report/generate_report.py" "${CF}" "${_json_path}"
    unset _json_path
fi
