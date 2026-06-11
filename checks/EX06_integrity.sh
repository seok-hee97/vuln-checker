#!/bin/bash
# 시스템 무결성 점검 모듈
# AIDE / FIPS / 패키지 서명 검증 / 기타 DISA STIG 항목
section_header "시스템 무결성 (AIDE / FIPS / 패키지 서명)"

# ── EX-INT-01: AIDE 파일 무결성 모니터링 설치 및 설정 ─────────────────────────
check_header "EX-INT-01" "AIDE 파일 무결성 모니터링 설치 및 설정"
if command -v aide &>/dev/null; then
    _aide_ver=$(aide --version 2>/dev/null | head -1 || true)
    result_safe "AIDE 설치됨: ${_aide_ver:-버전 확인 불가}"

    # aide.conf 또는 aide.db 존재 확인
    _aide_conf=""
    for _f in /etc/aide.conf /etc/aide/aide.conf; do
        [[ -f "${_f}" ]] && { _aide_conf="${_f}"; break; }
    done

    if [[ -n "${_aide_conf}" ]]; then
        result_safe "AIDE 설정 파일: ${_aide_conf}"
    else
        result_warn "AIDE 설정 파일을 찾을 수 없습니다"
    fi

    # 데이터베이스 존재 확인
    _aide_db=""
    for _f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz \
              /etc/aide/aide.db /etc/aide/aide.db.gz; do
        [[ -f "${_f}" ]] && { _aide_db="${_f}"; break; }
    done

    if [[ -n "${_aide_db}" ]]; then
        _aide_db_date=$(stat -c "%y" "${_aide_db}" 2>/dev/null | cut -d' ' -f1 || true)
        result_safe "AIDE 데이터베이스 존재: ${_aide_db} (생성일: ${_aide_db_date:-확인불가})"
    else
        result_warn "AIDE 데이터베이스가 없습니다 — 초기화 필요: aide --init"
    fi

    # cron 설정으로 정기 실행 여부 확인
    _aide_cron=$(grep -rh "aide" /etc/cron* /var/spool/cron/ 2>/dev/null | grep -v "^#" | head -3 || true)
    if [[ -n "${_aide_cron}" ]]; then
        result_safe "AIDE 정기 실행(cron) 설정됨"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_aide_cron}"
    else
        result_warn "AIDE cron 정기 실행 미설정 — crontab에 일일 검사 추가 권장"
        result_info "예시: 0 5 * * * /usr/sbin/aide --check 2>&1 | mail -s 'AIDE Report' root"
    fi
    unset _aide_ver _aide_conf _aide_db _aide_db_date _aide_cron _line _f

elif command -v tripwire &>/dev/null; then
    result_safe "Tripwire 파일 무결성 모니터링 설치됨"
    result_warn "Tripwire 상세 설정 수동 확인 필요"
else
    result_vuln "파일 무결성 모니터링 도구(AIDE/Tripwire)가 설치되어 있지 않습니다"
    result_info "설치: yum install aide -y 또는 apt install aide -y"
    result_info "초기화: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
fi

# ── EX-INT-02: FIPS 140-2 모드 활성화 여부 ─────────────────────────────────────
check_header "EX-INT-02" "FIPS 140-2 암호화 모드 활성화 여부"
_fips_enabled=false

# 커널 파라미터 확인
if [[ -f /proc/sys/crypto/fips_enabled ]]; then
    _fips_val=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "0")
    result_info "/proc/sys/crypto/fips_enabled = ${_fips_val}"
    if [[ "${_fips_val}" == "1" ]]; then
        result_safe "FIPS 140-2 모드 활성화됨"
        _fips_enabled=true
    else
        result_info "FIPS 140-2 비활성화 — 정부/금융 규제 환경에서는 활성화 필요"
    fi
    unset _fips_val
fi

# GRUB 커널 파라미터 확인
if grep -qE "fips=1" /proc/cmdline 2>/dev/null; then
    result_safe "부팅 파라미터에 fips=1 설정됨"
    _fips_enabled=true
fi

# OpenSSL FIPS 모드 확인
if command -v openssl &>/dev/null; then
    _ssl_fips=$(openssl version -a 2>/dev/null | grep -i fips || true)
    if [[ -n "${_ssl_fips}" ]]; then
        result_info "OpenSSL FIPS: ${_ssl_fips}"
    fi
    unset _ssl_fips
fi

${_fips_enabled} || result_info "FIPS 140-2 미활성화 — 일반 환경에서는 선택 사항"
unset _fips_enabled

# ── EX-INT-03: 패키지 서명 검증 및 GPG 키 설정 ─────────────────────────────────
check_header "EX-INT-03" "패키지 서명 검증 및 GPG 키 설정"
if [[ "${OS_FAMILY}" == "rhel" ]]; then
    # RPM GPG 키 가져오기 여부
    _gpg_keys=$(rpm -q gpg-pubkey 2>/dev/null | wc -l || echo 0)
    if [[ "${_gpg_keys}" -gt 0 ]]; then
        result_safe "RPM GPG 공개키 ${_gpg_keys}개 등록됨"
    else
        result_warn "RPM GPG 공개키가 등록되지 않았습니다 — 패키지 서명 검증 불가"
    fi
    unset _gpg_keys

    # yum/dnf gpgcheck 설정 확인
    _gpgcheck=$(grep -rE "^[[:space:]]*gpgcheck[[:space:]]*=" \
        /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null \
        | grep -v "^#" | tail -1 || true)
    result_info "gpgcheck 설정: ${_gpgcheck:-미설정}"
    if echo "${_gpgcheck:-}" | grep -q "gpgcheck=1"; then
        result_safe "패키지 GPG 서명 검증(gpgcheck=1) 활성화됨"
    else
        result_warn "gpgcheck=1 설정 권장 (/etc/yum.conf 또는 /etc/dnf/dnf.conf)"
    fi
    unset _gpgcheck

    # repo 파일에서 gpgcheck=0 사용 여부 확인
    _insecure_repos=$(grep -rh "^gpgcheck[[:space:]]*=[[:space:]]*0" /etc/yum.repos.d/ 2>/dev/null | wc -l || echo 0)
    if [[ "${_insecure_repos}" -gt 0 ]]; then
        result_warn "gpgcheck=0 인 저장소가 ${_insecure_repos}개 있습니다 — 개별 확인 필요"
    else
        result_safe "모든 YUM/DNF 저장소에 gpgcheck=0 없음"
    fi
    unset _insecure_repos

elif [[ "${OS_FAMILY}" == "debian" ]]; then
    # APT GPG 키 확인
    _apt_keys=$(apt-key list 2>/dev/null | grep -c "^pub" || \
                gpg --no-default-keyring --keyring /etc/apt/trusted.gpg --list-keys 2>/dev/null | grep -c "^pub" || \
                find /etc/apt/trusted.gpg.d/ -name "*.gpg" 2>/dev/null | wc -l || echo 0)
    result_info "APT GPG 키 수: ${_apt_keys}"

    # AllowUnauthenticated 설정 확인
    _unauth=$(grep -rh "AllowUnauthenticated" /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null \
        | grep -v "^#" | grep -c "true" || echo 0)
    if [[ "${_unauth}" -gt 0 ]]; then
        result_vuln "APT AllowUnauthenticated=true 설정 발견 — 서명되지 않은 패키지 설치 허용됨 (즉시 제거 필요)"
    else
        result_safe "APT AllowUnauthenticated 설정 없음 — 패키지 서명 검증 활성화됨"
    fi
    unset _apt_keys _unauth
else
    result_info "패키지 관리자를 인식할 수 없습니다 (OS_FAMILY=${OS_FAMILY})"
fi

# ── EX-INT-04: /etc/passwd, /etc/shadow 무결성 (getpwent 일관성) ───────────────
check_header "EX-INT-04" "/etc/passwd, /etc/shadow 무결성 (pwck/grpck)"
if command -v pwck &>/dev/null; then
    _pwck_out=$(pwck -r </dev/null 2>&1 | grep -v "^$" | head -10 || true)
    if [[ -z "${_pwck_out}" ]]; then
        result_safe "pwck 점검 — /etc/passwd, /etc/shadow 일관성 문제 없음"
    else
        result_warn "pwck 점검 경고 발견:"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_pwck_out}"
    fi
    unset _pwck_out _line
fi

if command -v grpck &>/dev/null; then
    _grpck_out=$(grpck -r </dev/null 2>&1 | grep -v "^$" | head -10 || true)
    if [[ -z "${_grpck_out}" ]]; then
        result_safe "grpck 점검 — /etc/group, /etc/gshadow 일관성 문제 없음"
    else
        result_warn "grpck 점검 경고 발견:"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_grpck_out}"
    fi
    unset _grpck_out _line
fi

# ── EX-INT-05: /etc/passwd 잠금/만료된 계정 패스워드 해시 확인 ─────────────────
check_header "EX-INT-05" "서비스 계정 패스워드 항목 검증"
_svc_with_passwd=false
while IFS=: read -r _user _pw _uid _gid _ _ _shell; do
    # 시스템 계정(UID < 1000) 중 실제 해시가 있는 계정 확인
    [[ "${_uid}" -ge 1000 ]] && continue
    [[ "${_user}" == "root" ]] && continue
    # x가 아닌 실제 해시 또는 빈 값이면 취약
    if [[ "${_pw}" != "x" && "${_pw}" != "*" && "${_pw}" != "!" && -n "${_pw}" ]]; then
        result_vuln "/etc/passwd — 서비스 계정 '${_user}'에 패스워드 해시 직접 저장됨 (shadow 미사용)"
        _svc_with_passwd=true
    fi
done < /etc/passwd
${_svc_with_passwd} || result_safe "모든 서비스 계정이 shadow 패스워드를 사용하고 있습니다"
unset _svc_with_passwd _user _pw _uid _gid _shell
