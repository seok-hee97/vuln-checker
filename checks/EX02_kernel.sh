#!/bin/bash
# 커널 보안 파라미터 / SELinux / AppArmor / 방화벽 점검 모듈
# CIS Benchmark 기반
section_header "커널 보안 / SELinux / 방화벽 (CIS Benchmark)"

# ── EX-KRN-01~06: sysctl 보안 파라미터 ─────────────────────────────────────────
check_header "EX-KRN-01~06" "커널 보안 파라미터 (sysctl)"
check_sysctl "net.ipv4.ip_forward"                  "0" "IP 포워딩 비활성화 (라우터가 아닌 경우)"
check_sysctl "net.ipv4.conf.all.accept_redirects"   "0" "ICMP redirect 수신 금지"
check_sysctl "net.ipv4.conf.default.accept_redirects" "0" "ICMP redirect 수신 금지 (default)"
check_sysctl "net.ipv4.conf.all.send_redirects"     "0" "ICMP redirect 송신 금지"
check_sysctl "net.ipv4.conf.all.accept_source_route" "0" "소스 라우팅 패킷 거부"
check_sysctl "net.ipv4.conf.all.rp_filter"          "1" "IP Spoofing 방어 (역방향 경로 필터링)"
check_sysctl "net.ipv4.tcp_syncookies"              "1" "SYN Flood 방어 (SYN Cookie)"
check_sysctl "kernel.randomize_va_space"            "2" "ASLR 전체 활성화"

# ── EX-KRN-07: 네트워크 추가 파라미터 ─────────────────────────────────────────
check_header "EX-KRN-07" "네트워크 보안 파라미터 (추가)"
check_sysctl "net.ipv4.conf.all.log_martians"        "1" "스푸핑 의심 패킷 로깅"
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts"  "1" "브로드캐스트 ICMP echo 무시"
check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1" "잘못된 ICMP 에러 응답 무시"
check_sysctl "kernel.dmesg_restrict"                "1" "일반 사용자 dmesg 접근 제한"
check_sysctl "fs.suid_dumpable"                     "0" "SetUID 프로그램 코어 덤프 비활성화"

# ── EX-KRN-08: SELinux 상태 (RHEL 계열) ────────────────────────────────────────
check_header "EX-KRN-08" "SELinux / AppArmor 상태"
if ${SELINUX_SUPPORTED}; then
    if command -v getenforce &>/dev/null; then
        _se_status=$(getenforce 2>/dev/null || echo "Unknown")
        case "${_se_status}" in
            Enforcing)
                result_safe "SELinux = Enforcing (강제 모드 — 최적 상태)"
                ;;
            Permissive)
                result_warn "SELinux = Permissive (허용 모드) — Enforcing 으로 전환 권장"
                result_info "전환 명령: setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config"
                ;;
            Disabled)
                result_vuln "SELinux = Disabled — 활성화 필요 (/etc/selinux/config SELINUX=enforcing)"
                ;;
            *)
                result_warn "SELinux 상태를 확인할 수 없습니다: ${_se_status}"
                ;;
        esac
        unset _se_status
    else
        result_warn "getenforce 명령을 찾을 수 없습니다"
    fi
else
    # Debian 계열 — AppArmor 확인
    if command -v aa-status &>/dev/null || command -v apparmor_status &>/dev/null; then
        _aa_cmd=$(command -v aa-status 2>/dev/null || command -v apparmor_status)
        _aa=$(${_aa_cmd} 2>/dev/null | head -3 || true)
        if echo "${_aa}" | grep -q "profiles are in enforce mode"; then
            result_safe "AppArmor — enforce 프로파일이 있습니다"
        else
            result_warn "AppArmor 상태 수동 확인 필요: ${_aa_cmd}"
        fi
        unset _aa_cmd _aa
    else
        result_warn "SELinux/AppArmor 상태 확인 불가 — MAC(강제 접근 제어) 설정 권장"
    fi
fi

# ── EX-KRN-08b: IPv6 비활성화 확인 (서버 불필요 시) ────────────────────────────
check_header "EX-KRN-08b" "IPv6 비활성화 여부 확인"
_ipv6_disabled=false
# 커널 파라미터 확인
_ipv6_all=$(sysctl_val "net.ipv6.conf.all.disable_ipv6" 2>/dev/null || echo "")
_ipv6_def=$(sysctl_val "net.ipv6.conf.default.disable_ipv6" 2>/dev/null || echo "")
result_info "net.ipv6.conf.all.disable_ipv6     = ${_ipv6_all:-확인불가}"
result_info "net.ipv6.conf.default.disable_ipv6 = ${_ipv6_def:-확인불가}"

if [[ "${_ipv6_all:-}" == "1" && "${_ipv6_def:-}" == "1" ]]; then
    result_safe "IPv6 커널 레벨에서 비활성화됨"
    _ipv6_disabled=true
else
    # IPv6 인터페이스가 실제로 있는지 확인
    if ip -6 addr show 2>/dev/null | grep -q "inet6 " && \
       ip -6 addr show 2>/dev/null | grep -v "::1" | grep -q "inet6 "; then
        result_warn "IPv6 활성화 상태 — IPv6가 불필요하면 비활성화 권장 (net.ipv6.conf.all.disable_ipv6=1)"
    else
        result_info "IPv6 활성화되어 있으나 실제 IPv6 주소 없음 — 운영 정책에 따라 비활성화 검토"
    fi
fi
unset _ipv6_all _ipv6_def _ipv6_disabled

# ── EX-KRN-08c: 불필요한 네트워크 프로토콜 모듈 비활성화 ───────────────────────
check_header "EX-KRN-08c" "불필요한 네트워크 프로토콜 모듈 비활성화 (CIS)"
_proto_bad=()
_proto_blocked=0
_proto_total=0
for _proto in dccp sctp rds tipc; do
    ((_proto_total++))
    _loaded=false
    _blacklisted=false
    lsmod 2>/dev/null | grep -qE "^${_proto}[[:space:]]" && _loaded=true
    grep -rqE "install[[:space:]]+${_proto}[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+${_proto}" \
            /etc/modprobe.d/ 2>/dev/null && _blacklisted=true

    if ${_loaded}; then
        _proto_bad+=("${_proto}")
        result_info "${_proto} — 현재 로드됨 (비활성화 필요)"
    elif ${_blacklisted}; then
        result_info "${_proto} — modprobe 비활성화 설정됨 (미로드)"
        ((_proto_blocked++))
    else
        result_info "${_proto} — 미로드, 블랙리스트 미설정 (설정 권장)"
    fi
done

if [[ "${#_proto_bad[@]}" -gt 0 ]]; then
    result_vuln "불필요한 네트워크 프로토콜 로드됨: ${_proto_bad[*]} — /etc/modprobe.d/에 'install <proto> /bin/false' 권장"
elif [[ "${_proto_blocked}" -eq "${_proto_total}" ]]; then
    result_safe "불필요한 네트워크 프로토콜(dccp/sctp/rds/tipc) 모두 미로드 및 비활성화 설정됨"
elif [[ "${_proto_blocked}" -gt 0 ]]; then
    result_warn "불필요한 네트워크 프로토콜 일부(${_proto_blocked}/${_proto_total}) 차단 설정됨 — 나머지도 modprobe 비활성화 권장"
else
    result_warn "불필요한 네트워크 프로토콜이 로드되지 않았으나 modprobe 비활성화 미설정 — 영구 차단 설정 권장"
fi
unset _proto_bad _proto _loaded _blacklisted _proto_blocked _proto_total

# ── EX-KRN-08d: 무선 인터페이스 비활성화 (서버) ────────────────────────────────
check_header "EX-KRN-08d" "무선 인터페이스 비활성화 (서버 환경)"
_wifi_found=false
if command -v nmcli &>/dev/null; then
    _wifi_devs=$(nmcli device 2>/dev/null | grep -iE "wifi|wlan" | awk '{print $1}' || true)
    if [[ -n "${_wifi_devs:-}" ]]; then
        result_warn "무선 인터페이스 발견 — 서버에서는 비활성화 권장: ${_wifi_devs}"
        _wifi_found=true
    fi
fi
if ! ${_wifi_found}; then
    if ip link show 2>/dev/null | grep -qiE "wlan[0-9]|wlp[0-9]|wlo[0-9]"; then
        result_warn "무선 인터페이스(wlan/wlp) 발견 — 서버에서는 비활성화 권장"
        _wifi_found=true
    fi
fi
${_wifi_found} || result_safe "무선 인터페이스가 없거나 비활성화되어 있습니다"
unset _wifi_found _wifi_devs

# ── EX-KRN-09: 방화벽 활성화 상태 ─────────────────────────────────────────────
check_header "EX-KRN-09" "방화벽 활성화 상태"
_fw_active=false

# firewalld (RHEL 계열)
if is_service_active "firewalld" 2>/dev/null; then
    result_safe "firewalld 방화벽이 활성화되어 있습니다"
    _zones=$(firewall-cmd --get-active-zones 2>/dev/null | grep -v "^  " | head -3 || true)
    result_info "활성 존: ${_zones:-확인불가}"
    _fw_active=true
    unset _zones
fi

# ufw (Ubuntu)
if ! ${_fw_active} && command -v ufw &>/dev/null; then
    _ufw=$(ufw status 2>/dev/null | head -1 || true)
    if echo "${_ufw}" | grep -q "active"; then
        result_safe "ufw 방화벽이 활성화되어 있습니다"
        _fw_active=true
    else
        result_vuln "ufw가 설치되어 있으나 비활성화 상태입니다 — 활성화 필요: ufw enable"
        _fw_active=true
    fi
    unset _ufw
fi

# iptables 폴백
if ! ${_fw_active}; then
    if command -v iptables &>/dev/null; then
        _rule_cnt=$(iptables -L -n 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT)" || echo 0)
        if [[ "${_rule_cnt}" -gt 0 ]]; then
            result_warn "iptables 규칙 ${_rule_cnt}개 존재 — 방화벽 설정 수동 검토 필요"
        else
            result_vuln "방화벽 규칙이 없습니다 — firewalld 또는 ufw 활성화 필요"
        fi
        unset _rule_cnt
    else
        result_vuln "방화벽(firewalld/ufw/iptables)을 찾을 수 없습니다"
    fi
fi
unset _fw_active
