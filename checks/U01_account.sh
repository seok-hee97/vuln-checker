#!/bin/bash
# 계정 관리 점검 모듈
# KISA U-01~U-04, U-44~U-53
section_header "계정 관리 (U-01 ~ U-04, U-44 ~ U-53)"

# ── U-01: root 계정 원격 접속 제한 ─────────────────────────────────────────────
check_header "U-01" "root 계정 원격 접속 제한"

# SSH PermitRootLogin 확인 (핵심 점검)
if [[ -f /etc/ssh/sshd_config ]]; then
    _prl=$(sshd_config_val "PermitRootLogin")
    case "${_prl:-}" in
        no|prohibit-password)
            result_safe "SSH PermitRootLogin = ${_prl}"
            ;;
        "")
            # OpenSSH 7.0+ 기본값은 prohibit-password 이므로 명시 없으면 안전
            result_safe "SSH PermitRootLogin 미설정 (OpenSSH 7.0+ 기본: prohibit-password)"
            ;;
        *)
            result_vuln "SSH PermitRootLogin = ${_prl} — 'no' 또는 'prohibit-password'로 변경 필요"
            ;;
    esac
    unset _prl
else
    result_pass "SSH 서버가 설치되어 있지 않습니다"
fi

# securetty pts 항목 확인 (콘솔/시리얼 직접 로그인 경로)
if [[ -f /etc/securetty ]]; then
    if grep -qE "^pts/" /etc/securetty 2>/dev/null; then
        result_vuln "/etc/securetty — pts 계열 항목이 허용되어 있습니다 (원격 root 로그인 가능)"
    else
        result_safe "/etc/securetty — pts 계열 원격 로그인 미허용"
    fi
else
    result_info "/etc/securetty 없음 — systemd/PAM 기반 시스템은 SSH 설정으로 제어"
fi

# ── U-02: 패스워드 복합성 설정 ─────────────────────────────────────────────────
check_header "U-02" "패스워드 복합성 설정"
if [[ -f /etc/security/pwquality.conf ]]; then
    _minlen=$(grep -E "^[[:space:]]*minlen[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _minclass=$(grep -E "^[[:space:]]*minclass[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _dcredit=$(grep -E "^[[:space:]]*dcredit[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _ucredit=$(grep -E "^[[:space:]]*ucredit[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _lcredit=$(grep -E "^[[:space:]]*lcredit[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _ocredit=$(grep -E "^[[:space:]]*ocredit[[:space:]]*=" /etc/security/pwquality.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)

    result_info "pwquality.conf minlen   : ${_minlen:-미설정}"
    result_info "pwquality.conf minclass : ${_minclass:-미설정}"
    result_info "pwquality.conf dcredit  : ${_dcredit:-미설정} (숫자, -1 이하=필수)"
    result_info "pwquality.conf ucredit  : ${_ucredit:-미설정} (대문자, -1 이하=필수)"
    result_info "pwquality.conf lcredit  : ${_lcredit:-미설정} (소문자, -1 이하=필수)"
    result_info "pwquality.conf ocredit  : ${_ocredit:-미설정} (특수문자, -1 이하=필수)"

    # 최소 길이 판정
    if [[ -n "${_minlen:-}" && "${_minlen}" -ge 8 ]]; then
        result_safe "최소 패스워드 길이 ${_minlen}자 이상 (기준: 8자 이상)"
    else
        result_vuln "최소 패스워드 길이 ${_minlen:-미설정} — 8자 이상 설정 필요 (/etc/security/pwquality.conf)"
    fi

    # 문자 클래스 판정: minclass >= 3 또는 각 credit이 음수(필수)로 설정된 경우를 안전으로 판정
    _class_ok=false
    if [[ -n "${_minclass:-}" && "${_minclass}" -ge 3 ]]; then
        result_safe "minclass = ${_minclass} — 최소 ${_minclass}개 문자 종류 필수"
        _class_ok=true
    fi
    if ! ${_class_ok}; then
        # credit 방식으로 각 종류 필수 설정 여부 확인
        _required_classes=0
        [[ -n "${_dcredit:-}" && "${_dcredit}" -lt 0 ]] && ((_required_classes++))
        [[ -n "${_ucredit:-}" && "${_ucredit}" -lt 0 ]] && ((_required_classes++))
        [[ -n "${_lcredit:-}" && "${_lcredit}" -lt 0 ]] && ((_required_classes++))
        [[ -n "${_ocredit:-}" && "${_ocredit}" -lt 0 ]] && ((_required_classes++))
        if [[ "${_required_classes}" -ge 3 ]]; then
            result_safe "credit 방식: ${_required_classes}개 문자 클래스 필수 설정됨"
            _class_ok=true
        fi
    fi
    ${_class_ok} || result_warn "문자 종류 복합성 미설정 — minclass=3 또는 dcredit/ucredit/lcredit/ocredit 설정 권장"
    unset _minlen _minclass _dcredit _ucredit _lcredit _ocredit _class_ok _required_classes
else
    # 구버전 폴백: /etc/login.defs PASS_MIN_LEN
    _minlen=$(login_defs_val "PASS_MIN_LEN")
    result_info "pwquality.conf 없음 — login.defs PASS_MIN_LEN: ${_minlen:-미설정}"
    if [[ -n "${_minlen:-}" && "${_minlen}" -ge 8 ]]; then
        result_safe "PASS_MIN_LEN = ${_minlen} (기준: 8자 이상)"
    else
        result_vuln "PASS_MIN_LEN = ${_minlen:-미설정} — 8자 이상 설정 필요 (/etc/login.defs)"
    fi
    unset _minlen
fi

# ── U-03: 계정 잠금 임계값 설정 ────────────────────────────────────────────────
check_header "U-03" "계정 잠금 임계값 설정"
# PAM_AUTH_FILE 은 os_detect.sh 에서 OS별로 분기되어 설정됨
# RHEL 계열: /etc/pam.d/password-auth / Ubuntu: /etc/pam.d/common-auth
_deny=""

# RHEL 8+ faillock.conf 방식 먼저 확인 (PAM 모듈 설정 파일)
if [[ -f /etc/security/faillock.conf ]]; then
    _deny=$(grep -E "^[[:space:]]*deny[[:space:]]*=" /etc/security/faillock.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    result_info "faillock.conf deny 설정: ${_deny:-미설정}"
fi

# PAM 파일에서 직접 옵션으로 설정된 경우
if [[ -z "${_deny:-}" && -f "${PAM_AUTH_FILE}" ]]; then
    _deny=$(pam_val "${PAM_AUTH_FILE}" "pam_faillock|pam_tally2" "deny")
fi

if [[ -n "${_deny:-}" ]]; then
    if [[ "${_deny}" -le 5 ]]; then
        result_safe "로그인 실패 잠금 임계값 : ${_deny}회 (기준: 5회 이하)"
    else
        result_vuln "로그인 실패 잠금 임계값 : ${_deny}회 — 5회 이하로 설정 필요"
    fi
else
    result_vuln "계정 잠금 정책 미설정 — pam_faillock(RHEL) 또는 pam_tally2(구버전) 설정 필요"
fi

# 잠금 해제 시간 (unlock_time) 추가 확인
_unlock=""
[[ -f /etc/security/faillock.conf ]] && \
    _unlock=$(grep -E "^[[:space:]]*unlock_time[[:space:]]*=" /etc/security/faillock.conf \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
[[ -z "${_unlock:-}" && -f "${PAM_AUTH_FILE}" ]] && \
    _unlock=$(pam_val "${PAM_AUTH_FILE}" "pam_faillock|pam_tally2" "unlock_time")
result_info "unlock_time: ${_unlock:-미설정} (0=관리자 수동해제, 기타=자동해제 초)"
result_info "참조 파일: ${PAM_AUTH_FILE}"
unset _deny _unlock

# ── U-04: 패스워드 파일 보호 ───────────────────────────────────────────────────
# 파일 소유자·권한은 U-07/U-08 에서 별도 점검
check_header "U-04" "패스워드 파일 보호 (Shadow 패스워드 사용 여부)"
_root_pw=$(awk -F: '$1=="root"{print $2}' /etc/passwd 2>/dev/null || true)
if [[ "${_root_pw:-}" == "x" ]]; then
    result_safe "Shadow 패스워드 시스템 사용 중 (/etc/passwd 에 해시 없음)"
else
    result_vuln "Shadow 패스워드 미사용 — /etc/passwd 에 패스워드 해시 직접 저장됨 (즉시 조치 필요)"
fi
unset _root_pw

# ── U-66: 패스워드 해시 알고리즘 점검 (SHA-512) ────────────────────────────────
check_header "U-66" "패스워드 해시 알고리즘 (SHA-512 적용 여부)"
# login.defs ENCRYPT_METHOD 확인
_enc_method=$(login_defs_val "ENCRYPT_METHOD")
result_info "login.defs ENCRYPT_METHOD: ${_enc_method:-미설정}"
if [[ "${_enc_method:-}" == "SHA512" ]]; then
    result_safe "패스워드 해시 알고리즘 SHA-512 설정됨"
else
    result_vuln "ENCRYPT_METHOD = ${_enc_method:-미설정} — SHA512 설정 권장 (/etc/login.defs)"
fi

# PAM pam_unix.so sha512 옵션 확인
if [[ -f "${PAM_PASS_FILE}" ]]; then
    if grep -qE "pam_unix\.so.*sha512" "${PAM_PASS_FILE}" 2>/dev/null; then
        result_safe "PAM pam_unix.so sha512 옵션 설정됨 (${PAM_PASS_FILE})"
    else
        result_warn "PAM pam_unix.so sha512 옵션 미설정 — 설정 권장 (${PAM_PASS_FILE})"
    fi
fi

# 실제 /etc/shadow 해시 방식 확인 (root 계정 기준)
_shadow_hash=$(awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null | cut -c1-3 || true)
case "${_shadow_hash:-}" in
    '$6$') result_safe "root 계정 해시 형식: SHA-512 (\$6\$)" ;;
    '$y$') result_safe "root 계정 해시 형식: yescrypt (\$y\$) — 강력한 최신 해시" ;;
    '$2'*) result_safe "root 계정 해시 형식: bcrypt (\$2y\$/\$2b\$) — 강력한 해시" ;;
    '$5$') result_warn "root 계정 해시 형식: SHA-256 (\$5\$) — SHA-512 전환 권장" ;;
    '$1$') result_vuln "root 계정 해시 형식: MD5 (\$1\$) — 즉시 SHA-512로 전환 필요" ;;
    'x'|'*'|'!'*) result_info "root 계정 잠금 상태 또는 패스워드 없음" ;;
    '') result_info "root 계정 해시 형식 확인 불가 (shadow 읽기 권한 필요)" ;;
    *) result_warn "root 계정 해시 형식 알 수 없음: '${_shadow_hash}' — 수동 확인 필요" ;;
esac
unset _enc_method _shadow_hash

# ── U-44: 패스워드 최대 사용기간 ───────────────────────────────────────────────
check_header "U-44" "패스워드 최대 사용기간 설정"
_max=$(login_defs_val "PASS_MAX_DAYS")
if [[ -n "${_max:-}" && "${_max}" -le 90 ]]; then
    result_safe "PASS_MAX_DAYS = ${_max}일 (기준: 90일 이하)"
else
    result_vuln "PASS_MAX_DAYS = ${_max:-미설정} — 90일 이하로 설정 필요 (/etc/login.defs)"
fi
unset _max

# ── PASS_WARN_AGE: 패스워드 만료 경고 기간 설정 ────────────────────────────────
check_header "U-44-warn" "패스워드 만료 경고 기간 (PASS_WARN_AGE)"
_warn_age=$(login_defs_val "PASS_WARN_AGE")
if [[ -n "${_warn_age:-}" && "${_warn_age}" -ge 7 ]]; then
    result_safe "PASS_WARN_AGE = ${_warn_age}일 (기준: 7일 이상)"
else
    result_vuln "PASS_WARN_AGE = ${_warn_age:-미설정} — 7일 이상 설정 권장 (/etc/login.defs)"
fi
unset _warn_age

# ── U-45: 패스워드 최소 사용기간 ───────────────────────────────────────────────
check_header "U-45" "패스워드 최소 사용기간 설정"
_min=$(login_defs_val "PASS_MIN_DAYS")
if [[ -n "${_min:-}" && "${_min}" -ge 1 ]]; then
    result_safe "PASS_MIN_DAYS = ${_min}일 (기준: 1일 이상)"
else
    result_vuln "PASS_MIN_DAYS = ${_min:-미설정} — 1일 이상으로 설정 필요 (/etc/login.defs)"
fi
unset _min

# ── U-46: 불필요한 계정 제거 ───────────────────────────────────────────────────
check_header "U-46" "불필요한 계정 제거 (한 번도 로그인하지 않은 일반 계정)"
_inactive_found=false
while IFS=: read -r _u _ _uid _ _ _ _shell; do
    [[ "${_uid}" -lt 1000 ]] && continue
    [[ "${_shell}" == */nologin || "${_shell}" == */false ]] && continue
    if lastlog -u "${_u}" 2>/dev/null | tail -1 | grep -q "\*\*Never"; then
        if ! ${_inactive_found}; then
            result_warn "미사용 계정 발견 — 업무 필요성 확인 후 제거 검토:"
            _inactive_found=true
        fi
        result_info "  미사용: ${_u} (Shell: ${_shell})"
    fi
done < /etc/passwd

${_inactive_found} || result_safe "한 번도 로그인하지 않은 일반 계정이 없습니다"
unset _inactive_found _u _uid _shell

# ── U-47: 관리자 그룹 최소 계정 ────────────────────────────────────────────────
check_header "U-47" "관리자 그룹(wheel/sudo) 최소 계정 유지"
_admins=$(grep -E "^(wheel|sudo):" /etc/group 2>/dev/null | awk -F: '{print $4}')
result_info "관리자 그룹 멤버: ${_admins:-없음}"
result_warn "관리자 그룹 멤버가 업무 상 최소한인지 수동 확인 필요"
unset _admins

# ── U-48: 계정 없는 GID 금지 ───────────────────────────────────────────────────
check_header "U-48" "계정 없는 GID 금지"
_orphan_found=false
while IFS=: read -r _gname _ _gid _; do
    # 시스템 GID 범위는 OS마다 다르므로 모두 검사
    if ! awk -F: -v g="${_gid}" '$4==g{found=1}END{exit !found}' /etc/passwd 2>/dev/null; then
        if ! ${_orphan_found}; then
            result_warn "계정이 없는 GID 발견 (확인 필요):"
            _orphan_found=true
        fi
        result_info "  GID ${_gid} (그룹: ${_gname}) — 해당 그룹을 기본 그룹으로 사용하는 계정 없음"
    fi
done < /etc/group

${_orphan_found} || result_safe "계정이 없는 GID가 존재하지 않습니다"
unset _orphan_found _gname _gid

# ── U-49: 동일 UID 금지 ────────────────────────────────────────────────────────
check_header "U-49" "동일 UID 금지"
_dup=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d || true)
if [[ -z "${_dup}" ]]; then
    result_safe "중복 UID가 없습니다"
else
    result_vuln "중복 UID 발견 — 즉시 정리 필요: ${_dup}"
fi
unset _dup

# ── U-50: 서비스 계정 로그인 Shell 점검 ────────────────────────────────────────
check_header "U-50" "서비스 계정 로그인 Shell 점검"
_bad=""
_bad=$(awk -F: '$3>0 && $3<1000 && ($7=="/bin/bash" || $7=="/bin/sh") {printf "%s(%s) ", $1, $7}' \
    /etc/passwd 2>/dev/null || true)
if [[ -z "${_bad}" ]]; then
    result_safe "로그인 가능한 Shell을 가진 서비스 계정이 없습니다"
else
    result_vuln "서비스 계정에 로그인 Shell 설정됨 — /sbin/nologin 으로 변경 권장: ${_bad}"
fi
unset _bad

# ── U-51: Session Timeout (TMOUT) 설정 ─────────────────────────────────────────
check_header "U-51" "Session Timeout (TMOUT) 설정"
_tmout=$(grep -rh "^[[:space:]]*TMOUT[[:space:]]*=" \
    /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc 2>/dev/null \
    | grep -oE '=[0-9]+' | sed 's/=//' | sort -n | head -1)
if [[ -n "${_tmout:-}" && "${_tmout}" -le 600 ]]; then
    result_safe "TMOUT = ${_tmout}초 (기준: 600초 이하)"
else
    result_vuln "TMOUT = ${_tmout:-미설정} — 600초 이하로 설정 필요 (/etc/profile.d/ 권장)"
fi
unset _tmout

# ── U-52: root 외 UID 0 계정 금지 ──────────────────────────────────────────────
check_header "U-52" "root 외 UID 0 계정 금지"
_uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null || true)
if [[ -z "${_uid0}" ]]; then
    result_safe "root 외 UID 0 계정이 없습니다"
else
    result_vuln "root 외 UID 0 계정 발견 — 즉시 삭제 필요: ${_uid0}"
fi
unset _uid0

# ── U-53: su 명령 wheel 그룹 제한 ──────────────────────────────────────────────
check_header "U-53" "su 명령 wheel 그룹 제한 (pam_wheel)"
if [[ -f /etc/pam.d/su ]]; then
    if grep -E "^[^#]*pam_wheel" /etc/pam.d/su &>/dev/null; then
        result_safe "su 명령이 wheel 그룹으로 제한되어 있습니다 (/etc/pam.d/su)"
    else
        result_vuln "su 명령 wheel 그룹 제한 미설정 — pam_wheel.so 모듈 추가 필요"
    fi
else
    result_pass "/etc/pam.d/su 파일이 없습니다"
fi
