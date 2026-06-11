#!/bin/bash
# sudo 설정 / 패키지 무결성 / 불필요한 서비스 점검 모듈
# CIS Benchmark 기반
section_header "sudo / 패키지 무결성 / 불필요한 서비스 (CIS Benchmark)"

# ── EX-SUD-01: sudoers NOPASSWD 설정 점검 ──────────────────────────────────────
check_header "EX-SUD-01" "NOPASSWD sudo 설정 점검"
_nopasswd=$(grep -rh "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | grep -v "^#" | grep -v "^$" || true)
if [[ -z "${_nopasswd}" ]]; then
    result_safe "NOPASSWD sudo 설정이 없습니다"
else
    result_warn "NOPASSWD sudo 설정 발견 — 의도된 설정인지 수동 확인 필요:"
    while IFS= read -r _line; do
        result_info "  ${_line}"
    done <<< "${_nopasswd}"
fi
unset _nopasswd _line

# ── EX-SUD-02: sudoers 파일 권한 ───────────────────────────────────────────────
check_header "EX-SUD-02" "sudoers 파일 소유자·권한"
check_file_attr "/etc/sudoers" "root" "440|400"

# sudoers.d/ 디렉터리 내 파일들
if [[ -d /etc/sudoers.d ]]; then
    while IFS= read -r _sf; do
        check_file_attr "${_sf}" "root" "440|400"
    done < <(find /etc/sudoers.d -type f 2>/dev/null)
    unset _sf
fi

# ── EX-SUD-03: sudo 명령 로깅 ──────────────────────────────────────────────────
check_header "EX-SUD-03" "sudo 명령 실행 로깅 설정"
if grep -rqE "^[[:space:]]*Defaults.*logfile|^[[:space:]]*Defaults.*syslog" \
    /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    result_safe "sudo 명령 로깅 설정이 있습니다"
else
    result_warn "sudo 명령 로깅 미설정 — /etc/sudoers 에 'Defaults logfile=/var/log/sudo.log' 추가 권장"
fi

# ── EX-PKG-01: RPM 패키지 무결성 검사 ──────────────────────────────────────────
check_header "EX-PKG-01" "패키지 무결성 검사"
if command -v rpm &>/dev/null; then
    result_info "RPM 패키지 무결성 검사 중... (수분 소요 가능)"
    _tampered_file="${RESULT_DIR}/tampered_packages.txt"
    # MD5 불일치만 출력 (..5......)
    rpm -Va --nosignature 2>/dev/null | grep -E "^\.\.[5]" > "${_tampered_file}" || true
    _tampered_cnt=$(wc -l < "${_tampered_file}")
    if [[ "${_tampered_cnt}" -eq 0 ]]; then
        result_safe "변조된 시스템 파일이 탐지되지 않았습니다"
    else
        result_vuln "변조 의심 파일 ${_tampered_cnt}개 발견 — 즉시 확인 필요: ${_tampered_file}"
    fi
    unset _tampered_file _tampered_cnt
elif command -v dpkg &>/dev/null; then
    result_info "dpkg 무결성 검사 중..."
    _tampered_file="${RESULT_DIR}/tampered_packages.txt"
    dpkg --verify 2>/dev/null | grep -v "^$" > "${_tampered_file}" || true
    _tampered_cnt=$(wc -l < "${_tampered_file}")
    if [[ "${_tampered_cnt}" -eq 0 ]]; then
        result_safe "변조된 dpkg 패키지 파일이 탐지되지 않았습니다"
    else
        result_vuln "변조 의심 파일 ${_tampered_cnt}개 발견: ${_tampered_file}"
    fi
    unset _tampered_file _tampered_cnt
else
    result_pass "rpm/dpkg 를 찾을 수 없습니다 — 패키지 무결성 수동 확인 필요"
fi

# ── EX-SVC-01: 불필요한 서비스 실행 여부 ───────────────────────────────────────
check_header "EX-SVC-01" "불필요한 서비스 실행 여부 점검"
declare -A _risky_svcs=(
    ["avahi-daemon"]="mDNS/Bonjour 자동 탐색 서비스 — 인터넷 노출 서버에서는 비활성화"
    ["cups"]="프린터 서비스 — 서버에서는 불필요"
    ["bluetooth"]="블루투스 — 서버에서는 불필요"
    ["postfix"]="메일 서버 — 불필요한 경우 비활성화"
    ["telnet"]="Telnet — 평문 전송 (SSH로 대체 필요)"
    ["rsh"]="rsh — 평문 전송, 인증 취약"
    ["rlogin"]="rlogin — 평문 전송, 인증 취약"
    ["ypbind"]="NIS 클라이언트 — 보안 취약"
    ["ypserv"]="NIS 서버 — 보안 취약"
)

_risky_found=false
for _svc in "${!_risky_svcs[@]}"; do
    if is_service_active "${_svc}" 2>/dev/null; then
        result_warn "${_svc} 서비스가 실행 중 — ${_risky_svcs[${_svc}]}"
        _risky_found=true
    fi
done
${_risky_found} || result_safe "점검 대상 불필요한 서비스(avahi/cups/bluetooth/telnet 등)가 실행되지 않고 있습니다"
result_info "불필요한 서비스 점검 완료"
unset _risky_svcs _svc _risky_found

# ── EX-SVC-02: 실행 중인 서비스 목록 저장 ──────────────────────────────────────
check_header "EX-SVC-02" "현재 실행 중인 서비스 목록"
_svc_file="${RESULT_DIR}/running_services.txt"
if ${SYSTEMD_AVAILABLE}; then
    systemctl list-units --type=service --state=running --no-pager 2>/dev/null \
        > "${_svc_file}" || true
    _svc_cnt=$(grep -c "\.service" "${_svc_file}" 2>/dev/null || echo 0)
    result_info "실행 중인 서비스 ${_svc_cnt}개 — 목록 저장됨: ${_svc_file}"
    result_warn "실행 중인 서비스 목록을 검토하여 불필요한 서비스 비활성화 권장"
fi
unset _svc_file _svc_cnt
