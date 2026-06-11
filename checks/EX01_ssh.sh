#!/bin/bash
# SSH 하드닝 점검 모듈 (CIS Benchmark 기반)
# KISA U-58에서 다루지 않은 심화 SSH 보안 설정
section_header "SSH 하드닝 (CIS Benchmark)"

_sshd_conf="/etc/ssh/sshd_config"
if [[ ! -f "${_sshd_conf}" ]]; then
    result_pass "SSH 서버가 설치되어 있지 않습니다 (EX-SSH 전체 건너뜀)"
    unset _sshd_conf
    return
fi

# ── EX-SSH-01: root 직접 로그인 금지 ───────────────────────────────────────────
check_header "EX-SSH-01" "PermitRootLogin (root 직접 로그인 금지)"
_val=$(sshd_config_val "PermitRootLogin")
case "${_val:-}" in
    no|prohibit-password) result_safe "PermitRootLogin = ${_val}" ;;
    "")                   result_safe "PermitRootLogin 미설정 (OpenSSH 7.0+ 기본: prohibit-password)" ;;
    *)                    result_vuln "PermitRootLogin = ${_val} — 'no' 또는 'prohibit-password' 권장" ;;
esac
unset _val

# ── EX-SSH-02: 패스워드 인증 비활성화 ──────────────────────────────────────────
check_header "EX-SSH-02" "PasswordAuthentication (키 기반 인증 강제)"
_val=$(sshd_config_val "PasswordAuthentication")
if [[ "${_val:-}" == "no" ]]; then
    result_safe "PasswordAuthentication = no (키 기반 인증만 허용)"
else
    result_warn "PasswordAuthentication = ${_val:-yes(기본)} — 키 기반 인증으로 전환 권장"
fi
unset _val

# ── EX-SSH-03: 최대 인증 시도 횟수 ────────────────────────────────────────────
check_header "EX-SSH-03" "MaxAuthTries (최대 인증 시도 횟수)"
_val=$(sshd_config_val "MaxAuthTries")
if [[ -n "${_val:-}" && "${_val}" -le 4 ]]; then
    result_safe "MaxAuthTries = ${_val} (기준: 4 이하)"
else
    result_vuln "MaxAuthTries = ${_val:-미설정(기본 6)} — 4 이하로 설정 필요"
fi
unset _val

# ── EX-SSH-04: 빈 패스워드 금지 ───────────────────────────────────────────────
check_header "EX-SSH-04" "PermitEmptyPasswords (빈 패스워드 금지)"
_val=$(sshd_config_val "PermitEmptyPasswords")
if [[ -z "${_val:-}" || "${_val}" == "no" ]]; then
    result_safe "PermitEmptyPasswords = no (기본값 또는 명시 설정)"
else
    result_vuln "PermitEmptyPasswords = ${_val} — 빈 패스워드 허용은 심각한 취약점, 즉시 no 설정 필요"
fi
unset _val

# ── EX-SSH-05: X11 포워딩 비활성화 ─────────────────────────────────────────────
check_header "EX-SSH-05" "X11Forwarding (X11 포워딩 비활성화)"
_val=$(sshd_config_val "X11Forwarding")
if [[ "${_val:-}" == "no" ]]; then
    result_safe "X11Forwarding = no"
else
    result_warn "X11Forwarding = ${_val:-yes(기본)} — 불필요한 경우 no 설정 권장"
fi
unset _val

# ── EX-SSH-06: SSH 접속 타임아웃 설정 ─────────────────────────────────────────
check_header "EX-SSH-06" "ClientAliveInterval / ClientAliveCountMax (유휴 세션 차단)"
_interval=$(sshd_config_val "ClientAliveInterval")
_maxcount=$(sshd_config_val "ClientAliveCountMax")

if [[ -n "${_interval:-}" && "${_interval}" -le 300 && "${_interval}" -gt 0 ]]; then
    result_safe "ClientAliveInterval = ${_interval}초 (기준: 300초 이하)"
else
    result_warn "ClientAliveInterval = ${_interval:-미설정(0=무제한)} — 300초 이하 설정 권장"
fi
result_info "ClientAliveCountMax = ${_maxcount:-미설정(기본 3)}"
unset _interval _maxcount

# ── EX-SSH-07: 사용자/그룹 접근 제한 ──────────────────────────────────────────
check_header "EX-SSH-07" "AllowUsers / AllowGroups (SSH 접속 허용 계정 제한)"
_allow_users=$(sshd_config_val "AllowUsers")
_allow_groups=$(sshd_config_val "AllowGroups")
_deny_users=$(sshd_config_val "DenyUsers")

if [[ -n "${_allow_users:-}" || -n "${_allow_groups:-}" ]]; then
    result_safe "SSH 접속 허용 계정/그룹 제한이 설정되어 있습니다"
    result_info "AllowUsers : ${_allow_users:-미설정}"
    result_info "AllowGroups: ${_allow_groups:-미설정}"
else
    result_warn "AllowUsers/AllowGroups 미설정 — SSH 접속 계정 화이트리스트 설정 권장"
fi
result_info "DenyUsers: ${_deny_users:-미설정}"
unset _allow_users _allow_groups _deny_users

# ── EX-SSH-08: 약한 암호화 알고리즘 점검 ───────────────────────────────────────
check_header "EX-SSH-08" "약한 Cipher/MAC 알고리즘 사용 여부"
_ciphers=$(sshd_config_val "Ciphers")
_macs=$(sshd_config_val "MACs")

if [[ -n "${_ciphers:-}" ]]; then
    result_info "설정된 Ciphers: ${_ciphers}"
    _weak_c=$(echo "${_ciphers}" | grep -oE "3des-cbc|arcfour[^ ,]*|blowfish-cbc|cast128-cbc" || true)
    if [[ -n "${_weak_c}" ]]; then
        result_vuln "약한 Cipher 알고리즘 사용 중: ${_weak_c}"
    else
        result_safe "설정된 Cipher에 취약 알고리즘이 없습니다"
    fi
    unset _weak_c
else
    result_info "Ciphers 미설정 (OpenSSH 기본값 사용) — 최신 버전의 기본값은 안전합니다"
fi

if [[ -n "${_macs:-}" ]]; then
    result_info "설정된 MACs: ${_macs}"
    _weak_m=$(echo "${_macs}" | grep -oE "hmac-md5[^ ,]*|hmac-sha1\b" || true)
    if [[ -n "${_weak_m}" ]]; then
        result_warn "약한 MAC 알고리즘 설정됨: ${_weak_m}"
    else
        result_safe "설정된 MAC에 취약 알고리즘이 없습니다"
    fi
    unset _weak_m
fi
unset _ciphers _macs

# ── EX-SSH-09: sshd_config 파일 권한 ───────────────────────────────────────────
check_header "EX-SSH-09" "sshd_config 파일 소유자·권한"
check_file_attr "${_sshd_conf}" "root" "600|644"

# ── EX-SSH-10: LoginGraceTime (로그인 대기 시간 제한) ───────────────────────────
check_header "EX-SSH-10" "LoginGraceTime (인증 완료 전 접속 유지 시간)"
_val=$(sshd_config_val "LoginGraceTime")
if [[ -n "${_val:-}" && "${_val}" -le 60 && "${_val}" -gt 0 ]]; then
    result_safe "LoginGraceTime = ${_val}초 (기준: 60초 이하)"
else
    result_warn "LoginGraceTime = ${_val:-미설정(기본 120초)} — 60초 이하 설정 권장"
fi
unset _val

# ── EX-SSH-11: Banner (접속 전 경고 배너) ──────────────────────────────────────
check_header "EX-SSH-11" "SSH 접속 전 경고 배너 (Banner)"
_val=$(sshd_config_val "Banner")
if [[ -n "${_val:-}" && "${_val}" != "none" ]]; then
    if [[ -f "${_val}" && -s "${_val}" ]]; then
        result_safe "SSH Banner = ${_val} (내용 설정됨)"
    else
        result_warn "SSH Banner = ${_val} (파일이 없거나 비어 있음)"
    fi
else
    result_warn "SSH Banner 미설정 — /etc/issue.net 파일로 경고 배너 설정 권장 (Banner /etc/issue.net)"
fi
unset _val

# ── EX-SSH-12: UsePAM (PAM 인증 활성화) ────────────────────────────────────────
check_header "EX-SSH-12" "UsePAM (PAM 인증 사용)"
_val=$(sshd_config_val "UsePAM")
if [[ -z "${_val:-}" || "${_val}" == "yes" ]]; then
    result_safe "UsePAM = ${_val:-yes(기본)} — PAM 인증 활성화"
else
    result_vuln "UsePAM = ${_val} — PAM 인증 비활성화 시 계정 잠금 정책이 적용되지 않음 (yes 설정 필요)"
fi
unset _val

# ── EX-SSH-13: IgnoreRhosts (.rhosts 무시) ─────────────────────────────────────
check_header "EX-SSH-13" "IgnoreRhosts (.rhosts 인증 무시)"
_val=$(sshd_config_val "IgnoreRhosts")
if [[ -z "${_val:-}" || "${_val}" == "yes" ]]; then
    result_safe "IgnoreRhosts = ${_val:-yes(기본)} — .rhosts 파일 무시"
else
    result_vuln "IgnoreRhosts = ${_val} — .rhosts 기반 인증 허용됨 (yes 설정 필요)"
fi
unset _val

# ── EX-SSH-14: HostbasedAuthentication (호스트 기반 인증 금지) ─────────────────
check_header "EX-SSH-14" "HostbasedAuthentication (호스트 기반 인증 비활성화)"
_val=$(sshd_config_val "HostbasedAuthentication")
if [[ -z "${_val:-}" || "${_val}" == "no" ]]; then
    result_safe "HostbasedAuthentication = ${_val:-no(기본)} — 호스트 기반 인증 비활성화"
else
    result_vuln "HostbasedAuthentication = ${_val} — 호스트 기반 인증 허용됨 (no 설정 필요)"
fi
unset _val

# ── EX-SSH-15: PrintLastLog (마지막 로그인 정보 출력) ──────────────────────────
check_header "EX-SSH-15" "PrintLastLog (이전 로그인 정보 표시)"
_val=$(sshd_config_val "PrintLastLog")
if [[ -z "${_val:-}" || "${_val}" == "yes" ]]; then
    result_safe "PrintLastLog = ${_val:-yes(기본)} — 마지막 로그인 시간·IP 표시 활성화"
else
    result_warn "PrintLastLog = ${_val} — 마지막 로그인 정보 미표시 (yes 설정 권장)"
fi
unset _val

unset _sshd_conf
