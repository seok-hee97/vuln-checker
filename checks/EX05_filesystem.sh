#!/bin/bash
# 파일시스템 하드닝 점검 모듈
# CIS Benchmark Section 1: 파일시스템 구성, 부트, 인증 강화
section_header "파일시스템 하드닝 (CIS Benchmark)"

# ── EX-FS-01: /tmp 파티션 마운트 옵션 ─────────────────────────────────────────
check_header "EX-FS-01" "/tmp 마운트 옵션 (nodev, nosuid, noexec)"
_tmp_opts=$(findmnt -n -o OPTIONS /tmp 2>/dev/null || grep -E "[[:space:]]/tmp[[:space:]]" /proc/mounts 2>/dev/null | awk '{print $4}' || true)
if [[ -n "${_tmp_opts:-}" ]]; then
    result_info "/tmp 마운트 옵션: ${_tmp_opts}"
    _missing_opts=()
    for _opt in nodev nosuid noexec; do
        echo "${_tmp_opts}" | grep -q "${_opt}" || _missing_opts+=("${_opt}")
    done
    if [[ "${#_missing_opts[@]}" -eq 0 ]]; then
        result_safe "/tmp — nodev, nosuid, noexec 모두 설정됨"
    else
        result_vuln "/tmp — 마운트 옵션 누락: ${_missing_opts[*]} (/etc/fstab 수정 필요)"
    fi
    unset _missing_opts _opt
else
    result_warn "/tmp 가 별도 파티션이 아닙니다 — 독립 파티션으로 분리 및 nodev/nosuid/noexec 설정 권장"
fi
unset _tmp_opts

# ── EX-FS-02: /var/tmp 마운트 옵션 ────────────────────────────────────────────
check_header "EX-FS-02" "/var/tmp 마운트 옵션 (nodev, nosuid, noexec)"
_vtmp_opts=$(findmnt -n -o OPTIONS /var/tmp 2>/dev/null || grep -E "[[:space:]]/var/tmp[[:space:]]" /proc/mounts 2>/dev/null | awk '{print $4}' || true)
if [[ -n "${_vtmp_opts:-}" ]]; then
    result_info "/var/tmp 마운트 옵션: ${_vtmp_opts}"
    _missing_opts=()
    for _opt in nodev nosuid noexec; do
        echo "${_vtmp_opts}" | grep -q "${_opt}" || _missing_opts+=("${_opt}")
    done
    if [[ "${#_missing_opts[@]}" -eq 0 ]]; then
        result_safe "/var/tmp — nodev, nosuid, noexec 모두 설정됨"
    else
        result_warn "/var/tmp — 마운트 옵션 누락: ${_missing_opts[*]}"
    fi
    unset _missing_opts _opt
else
    result_warn "/var/tmp 가 별도 파티션이 아닙니다 — nodev/nosuid/noexec 설정 권장"
fi
unset _vtmp_opts

# ── EX-FS-03: /dev/shm 마운트 옵션 ────────────────────────────────────────────
check_header "EX-FS-03" "/dev/shm 마운트 옵션 (nodev, nosuid, noexec)"
_shm_opts=$(findmnt -n -o OPTIONS /dev/shm 2>/dev/null || grep -E "[[:space:]]/dev/shm[[:space:]]" /proc/mounts 2>/dev/null | awk '{print $4}' || true)
if [[ -n "${_shm_opts:-}" ]]; then
    result_info "/dev/shm 마운트 옵션: ${_shm_opts}"
    _missing_opts=()
    for _opt in nodev nosuid noexec; do
        echo "${_shm_opts}" | grep -q "${_opt}" || _missing_opts+=("${_opt}")
    done
    if [[ "${#_missing_opts[@]}" -eq 0 ]]; then
        result_safe "/dev/shm — nodev, nosuid, noexec 모두 설정됨"
    else
        result_warn "/dev/shm — 마운트 옵션 누락: ${_missing_opts[*]}"
    fi
    unset _missing_opts _opt
else
    result_warn "/dev/shm 마운트 옵션을 확인할 수 없습니다"
fi
unset _shm_opts

# ── EX-FS-04: /home 파티션 마운트 옵션 ────────────────────────────────────────
check_header "EX-FS-04" "/home 마운트 옵션 (별도 파티션 + nodev)"
_home_opts=$(findmnt -n -o OPTIONS /home 2>/dev/null || grep -E "[[:space:]]/home[[:space:]]" /proc/mounts 2>/dev/null | awk '{print $4}' || true)
if [[ -n "${_home_opts:-}" ]]; then
    result_info "/home 마운트 옵션: ${_home_opts}"
    if echo "${_home_opts}" | grep -q "nodev"; then
        result_safe "/home — nodev 설정됨"
    else
        result_warn "/home — nodev 미설정 (사용자 디렉터리의 device 파일 생성 방지 권장)"
    fi
else
    result_warn "/home 이 별도 파티션이 아닙니다 — 독립 파티션 분리 권장"
fi
unset _home_opts

# ── EX-FS-05: 불필요한 파일시스템 모듈 비활성화 ────────────────────────────────
check_header "EX-FS-05" "불필요한 파일시스템 모듈 비활성화 (CIS)"
_fs_modules=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat)
_fs_loaded=()
_fs_blocked=()
for _mod in "${_fs_modules[@]}"; do
    if lsmod 2>/dev/null | grep -qE "^${_mod}[[:space:]]"; then
        _fs_loaded+=("${_mod}")
    fi
    if grep -rqE "install[[:space:]]+${_mod}[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+${_mod}" \
            /etc/modprobe.d/ 2>/dev/null; then
        _fs_blocked+=("${_mod}")
    fi
done

if [[ "${#_fs_loaded[@]}" -eq 0 ]]; then
    result_safe "불필요한 파일시스템 모듈이 로드되지 않음"
else
    result_warn "다음 파일시스템 모듈이 로드됨 (필요성 확인): ${_fs_loaded[*]}"
fi

if [[ "${#_fs_blocked[@]}" -gt 0 ]]; then
    result_safe "modprobe 비활성화 설정된 모듈: ${_fs_blocked[*]}"
else
    result_info "modprobe 비활성화 미설정 — /etc/modprobe.d/disable-fs.conf 에 불필요 모듈 비활성화 권장"
fi
unset _fs_modules _fs_loaded _fs_blocked _mod

# ── EX-FS-06: GRUB 부트로더 패스워드 설정 ─────────────────────────────────────
check_header "EX-FS-06" "부트로더(GRUB) 패스워드 설정"
_grub_conf=""
for _f in /boot/grub2/grub.cfg /boot/grub/grub.cfg /etc/grub.d/40_custom; do
    [[ -f "${_f}" ]] && { _grub_conf="${_f}"; break; }
done

if [[ -n "${_grub_conf}" ]]; then
    if grep -qiE "password_pbkdf2|set superusers" "${_grub_conf}" 2>/dev/null; then
        result_safe "GRUB 부트로더 패스워드 설정됨 (${_grub_conf})"
    else
        # /etc/grub.d/ 전체 확인
        if grep -rlE "password_pbkdf2|set superusers" /etc/grub.d/ 2>/dev/null | grep -q .; then
            result_safe "GRUB 부트로더 패스워드 설정됨 (/etc/grub.d/)"
        else
            result_warn "GRUB 부트로더 패스워드 미설정 — 물리 접근 시 단일 사용자 모드 진입 위험"
            result_info "설정: grub2-setpassword 또는 /etc/grub.d/40_custom 에 password_pbkdf2 추가"
        fi
    fi
else
    result_info "GRUB 설정 파일을 찾을 수 없습니다"
fi
unset _grub_conf _f

# ── EX-FS-07: 단일 사용자 모드(Single User Mode) 인증 설정 ─────────────────────
check_header "EX-FS-07" "단일 사용자 모드 인증 필요 설정"
_su_mode_ok=false

# systemd 기반 시스템
if ${SYSTEMD_AVAILABLE}; then
    for _unit in /usr/lib/systemd/system/rescue.service /lib/systemd/system/rescue.service; do
        if [[ -f "${_unit}" ]]; then
            if grep -qE "ExecStart.*sulogin|ExecStart.*systemd-sulogin" "${_unit}" 2>/dev/null; then
                result_safe "단일 사용자 모드(rescue.service)에 인증 설정됨 (sulogin)"
                _su_mode_ok=true
            fi
            break
        fi
    done
    for _unit in /usr/lib/systemd/system/emergency.service /lib/systemd/system/emergency.service; do
        if [[ -f "${_unit}" ]]; then
            if grep -qE "ExecStart.*sulogin|ExecStart.*systemd-sulogin" "${_unit}" 2>/dev/null; then
                result_safe "비상 모드(emergency.service)에 인증 설정됨"
                _su_mode_ok=true
            fi
            break
        fi
    done
fi

# /etc/inittab 기반 (구버전 SysV)
if [[ -f /etc/inittab ]]; then
    if grep -qE "^~~:S:respawn:/sbin/sulogin" /etc/inittab 2>/dev/null; then
        result_safe "단일 사용자 모드 인증 설정됨 (/etc/inittab)"
        _su_mode_ok=true
    fi
fi

${_su_mode_ok} || result_warn "단일 사용자 모드 인증 설정 확인 필요 — 물리 접근 시 root 패스워드 없이 진입 가능 위험"
unset _su_mode_ok _unit

# ── EX-FS-08: 코어 덤프 제한 ──────────────────────────────────────────────────
check_header "EX-FS-08" "코어 덤프 제한 (/etc/security/limits.conf)"
_core_ok=false

# /etc/security/limits.conf 확인
if [[ -f /etc/security/limits.conf ]]; then
    if grep -Ev "^#|^$" /etc/security/limits.conf 2>/dev/null \
            | grep -qE "\*[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]+0"; then
        result_safe "/etc/security/limits.conf — core 덤프 hard/soft 0 설정됨"
        _core_ok=true
    fi
fi

# /etc/security/limits.d/ 확인
if ! ${_core_ok}; then
    for _lf in /etc/security/limits.d/*.conf; do
        [[ -f "${_lf}" ]] || continue
        if grep -Ev "^#|^$" "${_lf}" 2>/dev/null \
                | grep -qE "\*[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]+0"; then
            result_safe "${_lf} — core 덤프 0 설정됨"
            _core_ok=true
            break
        fi
    done
fi

# sysctl fs.suid_dumpable 확인 (이미 EX-KRN-07에서 확인하지만 재확인)
_suid_dump=$(sysctl_val "fs.suid_dumpable" 2>/dev/null || echo "")
result_info "fs.suid_dumpable = ${_suid_dump:-확인불가} (0 권장: SetUID 프로그램 코어 덤프 방지)"

${_core_ok} || result_warn "코어 덤프 제한 미설정 — /etc/security/limits.conf 에 '* hard core 0' 추가 권장"
unset _core_ok _lf _suid_dump

# ── EX-FS-09: umask 설정 ──────────────────────────────────────────────────────
check_header "EX-FS-09" "시스템 기본 umask 설정 (027 또는 022)"
_umask_val=""
_umask_file=""
for _f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
    [[ -f "${_f}" ]] || continue
    # grep -P 대신 grep -oE + sed 로 POSIX 호환 추출
    _u=$(grep -Ev "^#|^$" "${_f}" 2>/dev/null \
         | grep -oE "umask[[:space:]]+[0-9]+" | sed 's/umask[[:space:]]*//' | tail -1 || true)
    if [[ -n "${_u}" ]]; then
        _umask_val="${_u}"
        _umask_file="${_f}"
        break
    fi
done

# /etc/profile.d/ 확인
if [[ -z "${_umask_val}" ]]; then
    for _f in /etc/profile.d/*.sh; do
        [[ -f "${_f}" ]] || continue
        _u=$(grep -Ev "^#|^$" "${_f}" 2>/dev/null \
             | grep -oE "umask[[:space:]]+[0-9]+" | sed 's/umask[[:space:]]*//' | tail -1 || true)
        if [[ -n "${_u}" ]]; then
            _umask_val="${_u}"
            _umask_file="${_f}"
            break
        fi
    done
fi

# login.defs UMASK
_ldf_umask=$(login_defs_val "UMASK")
result_info "login.defs UMASK: ${_ldf_umask:-미설정}"

if [[ -n "${_umask_val}" ]]; then
    result_info "umask = ${_umask_val} (파일: ${_umask_file})"
    case "${_umask_val}" in
        027|077|0027|0077) result_safe "umask = ${_umask_val} — 그룹/기타 쓰기 금지 (권장 기준 충족)" ;;
        022|0022)          result_info "umask = ${_umask_val} — 표준 설정, 027로 강화 권장" ;;
        000|002|*)         result_warn "umask = ${_umask_val} — 너무 개방적, 022 또는 027 설정 권장" ;;
    esac
else
    result_warn "시스템 umask 설정을 찾을 수 없습니다 — /etc/profile 또는 /etc/bashrc 에 umask 027 추가 권장"
fi
unset _umask_val _umask_file _ldf_umask _u _f

# ── EX-FS-10: NTP/chrony 시간 동기화 설정 ─────────────────────────────────────
check_header "EX-FS-10" "NTP/chrony 시간 동기화 설정"
_ntp_ok=false

# chronyd (RHEL 8+, 현대 배포판 기본)
if is_service_active "chronyd" 2>/dev/null; then
    result_safe "chronyd 서비스 실행 중"
    _ntp_ok=true
    if [[ -f /etc/chrony.conf ]]; then
        _ntp_servers=$(grep -E "^(server|pool)" /etc/chrony.conf 2>/dev/null | head -3 || true)
        if [[ -n "${_ntp_servers}" ]]; then
            result_safe "chrony NTP 서버 설정됨"
            while IFS= read -r _line; do
                result_info "  ${_line}"
            done <<< "${_ntp_servers}"
        else
            result_warn "chrony.conf — NTP 서버(server/pool) 설정이 없습니다"
        fi
        unset _ntp_servers _line
    fi
fi

# ntpd (구형 배포판)
if ! ${_ntp_ok} && is_service_active "ntpd" 2>/dev/null; then
    result_safe "ntpd 서비스 실행 중"
    _ntp_ok=true
    if [[ -f /etc/ntp.conf ]]; then
        _ntp_servers=$(grep -E "^(server|pool)" /etc/ntp.conf 2>/dev/null | head -3 || true)
        [[ -n "${_ntp_servers}" ]] && result_safe "ntp.conf — NTP 서버 설정됨" \
            || result_warn "ntp.conf — NTP 서버 설정이 없습니다"
        unset _ntp_servers
    fi
fi

# systemd-timesyncd (Ubuntu 기본)
if ! ${_ntp_ok} && is_service_active "systemd-timesyncd" 2>/dev/null; then
    result_safe "systemd-timesyncd 시간 동기화 서비스 실행 중"
    _ntp_ok=true
fi

${_ntp_ok} || result_warn "시간 동기화 서비스(chronyd/ntpd/timesyncd)가 실행되지 않습니다 — 로그 신뢰성과 보안 이벤트 상관관계 분석에 필수"

# 현재 시간 동기화 상태
if command -v timedatectl &>/dev/null; then
    _tdc=$(timedatectl 2>/dev/null | grep -E "NTP|synchronized" | head -2 || true)
    while IFS= read -r _line; do
        result_info "  ${_line}"
    done <<< "${_tdc}"
    unset _tdc _line
fi
unset _ntp_ok

# ── EX-FS-11: PAM 패스워드 히스토리 (pam_pwhistory) ───────────────────────────
check_header "EX-FS-11" "PAM 패스워드 히스토리 설정 (pam_pwhistory)"
_pwhistory_set=false

for _pf in "${PAM_PASS_FILE}" /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -f "${_pf}" ]] || continue
    if grep -Ev "^#|^$" "${_pf}" 2>/dev/null | grep -q "pam_pwhistory"; then
        _remember=$(grep -Ev "^#|^$" "${_pf}" 2>/dev/null \
            | grep "pam_pwhistory" | grep -oE "remember=[0-9]+" | sed 's/remember=//' | tail -1 || true)
        result_info "${_pf} — pam_pwhistory remember=${_remember:-미설정}"
        if [[ -n "${_remember:-}" && "${_remember}" -ge 5 ]]; then
            result_safe "패스워드 히스토리 ${_remember}회 이상 기억 설정됨"
        else
            result_warn "pam_pwhistory remember=${_remember:-미설정} — 5회 이상 권장"
        fi
        _pwhistory_set=true
        break
    fi
done

${_pwhistory_set} || result_warn "PAM 패스워드 히스토리(pam_pwhistory) 미설정 — 이전 패스워드 재사용 방지 권장"
result_info "설정 예: password required pam_pwhistory.so remember=5 use_authtok"
unset _pwhistory_set _pf _remember
