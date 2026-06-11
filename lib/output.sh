#!/bin/bash
# 출력 헬퍼 모듈
#
# 판정 레이블:
#   [안전] — 점검 기준 충족         (SAFE++, TOTAL++)
#   [취약] — 취약점 발견             (VULN++, TOTAL++)
#   [권장] — 수동 점검/조치 권고     (WARN++, 점수 제외)
#   [정보] — 단순 수집 정보          (카운터 없음)
#   [PASS] — 해당 없음/미설치        (카운터 없음)
#
# 주의: result_safe/vuln/warn 을 파이프(|) 안에서 호출하지 말 것.
#       subshell에서 실행되면 TOTAL/SAFE/VULN/WARN이 부모로 전파되지 않음.
#       반드시 for/while < <(...) 또는 직접 루프를 사용할 것.

# ── 색상 코드 (터미널 출력 시만 적용) ──────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED='\033[0;31m'
    C_GREEN='\033[0;32m'
    C_YELLOW='\033[1;33m'
    C_BLUE='\033[0;34m'
    C_BOLD='\033[1m'
    C_RESET='\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''; C_RESET=''
fi

# ── 내부 출력 함수 ─────────────────────────────────────────────────────────────
# _log      : 색상 없이 터미널 + 결과파일 동시 출력
# _log_file : 결과파일 전용 (plain text)
# _log_tty  : 터미널 전용 (ANSI 색상 허용)
_log()      { printf '%s\n' "$*" | tee -a "${CF}"; }
_log_file() { printf '%s\n' "$*" >> "${CF}"; }
_log_tty()  { printf '%b\n' "$*"; }

# ── 판정 결과 함수 ─────────────────────────────────────────────────────────────
# 결과파일에는 plain text, 터미널에는 색상 출력 (ANSI 코드가 파일에 오염되지 않음)
result_safe() {
    ((SAFE++)); ((TOTAL++))
    _log_file "    ==> [안전] $*"
    _log_tty  "    ==> ${C_GREEN}[안전]${C_RESET} $*"
}

result_vuln() {
    ((VULN++)); ((TOTAL++))
    _log_file "    ==> [취약] $*"
    _log_tty  "    ==> ${C_RED}[취약]${C_RESET} $*"
}

result_warn() {
    ((WARN++))
    _log_file "    ==> [권장] $*"
    _log_tty  "    ==> ${C_YELLOW}[권장]${C_RESET} $*"
}

result_info() {
    _log_file "    ==> [정보] $*"
    _log_tty  "    ==> ${C_BLUE}[정보]${C_RESET} $*"
}

result_pass() {
    _log_file "    ==> [PASS] $*"
    _log_tty  "    ==> [PASS] $*"
}

# ── 구조 출력 함수 ─────────────────────────────────────────────────────────────
section_header() {
    _log ""
    _log "$(printf '=%.0s' {1..70})"
    _log_tty "${C_BOLD}  $*${C_RESET}"
    _log_file "  $*"
    _log "$(printf '=%.0s' {1..70})"
}

check_header() {
    local id="$1"; shift
    _log ""
    _log_tty "${C_BOLD}  [${id}] $*${C_RESET}"
    _log_file "  [${id}] $*"
    _log "  $(printf -- '-%.0s' {1..66})"
}

# ── 배너 출력 ──────────────────────────────────────────────────────────────────
print_banner() {
    local banner
    banner='======================================================================'$'\n'
    banner+='  Linux Vulnerability Checker  v2.0'$'\n'
    banner+='  KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준 (U-01~U-72)'$'\n'
    banner+='  + CIS Benchmark Extension (EX01~EX06)'$'\n'
    banner+='  대상 OS: CentOS 7 / Rocky 8,9 / RHEL 8,9 / Ubuntu 20.04, 22.04'$'\n'
    banner+='======================================================================'

    _log "${banner}"
    _log "  시작 시각 : $(date '+%Y-%m-%d %H:%M:%S')"
    _log "  호스트명  : $(hostname -f 2>/dev/null || hostname)"
    _log "  OS        : ${OS_ID} ${OS_VER} (${OS_FAMILY} 계열)"
    _log "  커널      : $(uname -r)"
    _log ""
}

# ── 시스템 정보 수집 ────────────────────────────────────────────────────────────
collect_sysinfo() {
    section_header "시스템 정보"
    result_info "OS       : ${OS_ID} ${OS_VER}"
    result_info "Family   : ${OS_FAMILY} / PKG: ${PKG_MGR}"
    result_info "Kernel   : $(uname -r)"
    result_info "Hostname : $(hostname -f 2>/dev/null || hostname)"
    result_info "Uptime   : $(uptime -p 2>/dev/null || uptime)"
    result_info "SELinux  : ${SELINUX_SUPPORTED} / Systemd: ${SYSTEMD_AVAILABLE}"
    result_info "PAM Auth : ${PAM_AUTH_FILE}"
    result_info "PAM Pass : ${PAM_PASS_FILE}"

    if command -v ip &>/dev/null; then
        while IFS= read -r _line; do
            result_info "Network  : ${_line}"
        done < <(ip addr show 2>/dev/null | grep "inet ")
        unset _line
    fi
}

# ── 최종 요약 출력 ──────────────────────────────────────────────────────────────
print_summary() {
    local score=0
    if [[ "${TOTAL}" -gt 0 ]]; then
        score=$(( SAFE * 100 / TOTAL ))
    fi

    local score_color="${C_RED}"
    [[ "${score}" -ge 50 ]] && score_color="${C_YELLOW}"
    [[ "${score}" -ge 80 ]] && score_color="${C_GREEN}"

    _log ""
    _log "$(printf '=%.0s' {1..70})"
    _log "  점검 완료  $(date '+%Y-%m-%d %H:%M:%S')"
    _log "$(printf -- '-%.0s' {1..70})"
    _log "  전체 판정 항목 : ${TOTAL}"
    _log "  [안전]         : ${SAFE}"
    _log "  [취약]         : ${VULN}"
    _log "  [권장]         : ${WARN} (점수 미반영)"
    _log_file "  보안 점수      : ${score}/100"
    _log_tty  "  보안 점수      : ${score_color}${score}/100${C_RESET}"
    _log "  결과 파일      : ${CF}"
    _log "$(printf '=%.0s' {1..70})"
}
