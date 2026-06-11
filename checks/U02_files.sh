#!/bin/bash
# 파일 및 디렉터리 관리 점검 모듈
# KISA U-05~U-18, U-54~U-57
section_header "파일 및 디렉터리 관리 (U-05 ~ U-18, U-54 ~ U-57)"

# ── U-05: root 홈·PATH 디렉터리 권한 ───────────────────────────────────────────
check_header "U-05" "root 홈 디렉터리 및 PATH 설정"
_root_home=$(awk -F: '$1=="root"{print $6}' /etc/passwd 2>/dev/null || echo "/root")
_perm=$(file_perm_octal "${_root_home}" 2>/dev/null)
result_info "root 홈 디렉터리: ${_root_home} (권한: ${_perm:-확인불가})"
case "${_perm:-}" in
    700|550) result_safe "root 홈 디렉터리 권한 ${_perm} — 적절" ;;
    "")      result_warn "root 홈 디렉터리 권한을 확인할 수 없습니다" ;;
    *)       result_vuln "root 홈 디렉터리 권한 ${_perm} — 700 또는 550 권장" ;;
esac

# PATH에 현재 디렉터리(.) 포함 여부
if [[ ":${PATH}:" == *":."* ]]; then
    result_vuln "PATH에 현재 디렉터리(.)가 포함되어 있습니다 — 명령어 치환 공격 가능"
else
    result_safe "PATH에 현재 디렉터리(.)가 포함되어 있지 않습니다"
fi
unset _root_home _perm

# ── U-06: 소유자 없는 파일·디렉터리 점검 ──────────────────────────────────────
check_header "U-06" "소유자 없는 파일·디렉터리 점검"
_noowner_file="${RESULT_DIR}/noowner_files.txt"
find / \( -nouser -o -nogroup \) -xdev 2>/dev/null > "${_noowner_file}" || true
_count=$(wc -l < "${_noowner_file}")
if [[ "${_count}" -eq 0 ]]; then
    result_safe "소유자/그룹 없는 파일이 없습니다"
else
    result_vuln "소유자/그룹 없는 파일 ${_count}개 발견 — 확인 필요: ${_noowner_file}"
fi
unset _noowner_file _count

# ── U-07: /etc/passwd 소유자·권한 ──────────────────────────────────────────────
check_header "U-07" "/etc/passwd 소유자·권한"
check_file_attr "/etc/passwd" "root" "644|444"

# ── U-08: /etc/shadow 소유자·권한 ──────────────────────────────────────────────
check_header "U-08" "/etc/shadow 소유자·권한"
check_file_attr "/etc/shadow" "root" "000|400|640"

# ── U-09: /etc/hosts 소유자·권한 ───────────────────────────────────────────────
check_header "U-09" "/etc/hosts 소유자·권한"
check_file_attr "/etc/hosts" "root" "600|644"

# ── U-10: /etc/inetd.conf 및 /etc/xinetd.conf 소유자·권한 ──────────────────────
check_header "U-10" "inetd.conf / xinetd.conf 소유자·권한"
_found=false
for _f in /etc/inetd.conf /etc/xinetd.conf; do
    if [[ -f "${_f}" ]]; then
        check_file_attr "${_f}" "root" "600"
        _found=true
    fi
done
${_found} || result_pass "/etc/inetd.conf, /etc/xinetd.conf 파일이 없습니다 (xinetd 미사용)"
unset _found _f

# /etc/xinetd.d/ 디렉터리 내 파일 전수 권한 점검
if [[ -d /etc/xinetd.d ]]; then
    _xinetd_found=false
    while IFS= read -r _xf; do
        check_file_attr "${_xf}" "root" "600"
        _xinetd_found=true
    done < <(find /etc/xinetd.d -maxdepth 1 -type f 2>/dev/null)
    ${_xinetd_found} || result_pass "/etc/xinetd.d/ 디렉터리가 비어 있습니다"
    unset _xinetd_found _xf
fi

# ── U-11: /etc/syslog.conf 또는 /etc/rsyslog.conf 소유자·권한 ───────────────────
check_header "U-11" "syslog.conf / rsyslog.conf 소유자·권한"
_found=false
for _f in /etc/syslog.conf /etc/rsyslog.conf; do
    if [[ -f "${_f}" ]]; then
        check_file_attr "${_f}" "root" "644|640"
        _found=true
    fi
done
${_found} || result_pass "syslog.conf, rsyslog.conf 파일이 없습니다"
unset _found _f

# ── U-12: /etc/services 소유자·권한 ────────────────────────────────────────────
check_header "U-12" "/etc/services 소유자·권한"
check_file_attr "/etc/services" "root" "644"

# ── U-13: SetUID/SetGID 설정 파일 점검 ─────────────────────────────────────────
check_header "U-13" "SetUID, SetGID 설정 파일 점검"
_suid_file="${RESULT_DIR}/setuid_files.txt"
_sgid_file="${RESULT_DIR}/setgid_files.txt"
find / -user root -perm -4000 -xdev 2>/dev/null > "${_suid_file}" || true
find / -user root -perm -2000 -xdev 2>/dev/null > "${_sgid_file}" || true
_suid_cnt=$(wc -l < "${_suid_file}")
_sgid_cnt=$(wc -l < "${_sgid_file}")
result_warn "SetUID 파일 ${_suid_cnt}개 — 목록 저장됨: ${_suid_file} (수동 검토 필요)"
result_warn "SetGID 파일 ${_sgid_cnt}개 — 목록 저장됨: ${_sgid_file} (수동 검토 필요)"
result_info "허용 예시: /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su 등"
unset _suid_file _sgid_file _suid_cnt _sgid_cnt

# ── U-14: 사용자/시스템 시작 파일 및 환경변수 파일 소유자·권한 ─────────────────
check_header "U-14" "사용자·시스템 시작 파일 및 환경변수 파일 소유자·권한"
# 시스템 프로파일
for _f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
    [[ -f "${_f}" ]] && check_file_attr "${_f}" "root" "644"
done

# 각 사용자 홈디렉터리의 .bashrc, .profile, .bash_profile
_bad_startup=false
while IFS=: read -r _user _ _uid _ _ _home _; do
    [[ ! -d "${_home}" ]] && continue
    for _rc in .bash_profile .bashrc .profile .bash_login; do
        _rcpath="${_home}/${_rc}"
        [[ ! -f "${_rcpath}" ]] && continue
        _owner=$(file_owner "${_rcpath}")
        if [[ "${_owner}" != "${_user}" && "${_owner}" != "root" ]]; then
            result_vuln "${_rcpath} 소유자 이상: ${_owner} (기대: ${_user} 또는 root)"
            _bad_startup=true
        fi
    done
done < /etc/passwd
${_bad_startup} || result_safe "사용자 시작 파일 소유자가 모두 적절합니다"
unset _bad_startup _user _uid _home _rc _rcpath _owner _f

# ── U-15: World Writable 파일 점검 ─────────────────────────────────────────────
check_header "U-15" "World Writable 파일 점검"
_ww_file="${RESULT_DIR}/world_writable.txt"
find / -perm -002 \( ! -type l \) -xdev 2>/dev/null \
    | grep -vE "^/(proc|sys|dev)" > "${_ww_file}" || true
_ww_cnt=$(wc -l < "${_ww_file}")
if [[ "${_ww_cnt}" -eq 0 ]]; then
    result_safe "World Writable 파일이 없습니다"
else
    result_warn "World Writable 파일 ${_ww_cnt}개 — 목록 저장됨: ${_ww_file} (수동 검토 필요)"
fi
unset _ww_file _ww_cnt

# ── U-16: /dev 에 존재하지 않는 device 파일 점검 ───────────────────────────────
check_header "U-16" "/dev 에 major/minor 없는 비정상 device 파일 점검"
_dev_file="${RESULT_DIR}/dev_nodev.txt"
find /dev -not -type d -not -type l \
    \( ! -type b \) \( ! -type c \) \( ! -type p \) \( ! -type s \) \
    2>/dev/null > "${_dev_file}" || true
_dev_cnt=$(wc -l < "${_dev_file}")
if [[ "${_dev_cnt}" -eq 0 ]]; then
    result_safe "/dev 에 비정상 파일이 없습니다"
else
    result_warn "/dev 에 비정상 파일 ${_dev_cnt}개 — 확인 필요: ${_dev_file}"
fi
unset _dev_file _dev_cnt

# ── U-17: .rhosts, hosts.equiv 사용 금지 ───────────────────────────────────────
check_header "U-17" ".rhosts 및 hosts.equiv 사용 금지"
_rhosts_found=false
# /etc/hosts.equiv
if [[ -f /etc/hosts.equiv ]]; then
    result_vuln "/etc/hosts.equiv 파일이 존재합니다 — 삭제 필요 (r 계열 명령 무인증 허용)"
    _rhosts_found=true
fi
# 각 사용자 홈디렉터리의 .rhosts
while IFS=: read -r _user _ _uid _ _ _home _; do
    _rh="${_home}/.rhosts"
    if [[ -f "${_rh}" ]]; then
        result_vuln "${_rh} 파일이 존재합니다 — 삭제 필요"
        _rhosts_found=true
    fi
done < /etc/passwd
${_rhosts_found} || result_safe ".rhosts 및 hosts.equiv 파일이 없습니다"
unset _rhosts_found _user _uid _home _rh

# ── U-18: 접속 IP 및 포트 제한 ─────────────────────────────────────────────────
check_header "U-18" "접속 IP 및 포트 제한 (/etc/hosts.allow, /etc/hosts.deny)"
if [[ -f /etc/hosts.allow ]] || [[ -f /etc/hosts.deny ]]; then
    _allow_entries=$(grep -vc "^#\|^$" /etc/hosts.allow 2>/dev/null || echo 0)
    _deny_entries=$(grep -vc "^#\|^$" /etc/hosts.deny 2>/dev/null || echo 0)
    result_info "/etc/hosts.allow 유효 항목: ${_allow_entries}개"
    result_info "/etc/hosts.deny  유효 항목: ${_deny_entries}개"
    if [[ "${_deny_entries}" -gt 0 || "${_allow_entries}" -gt 0 ]]; then
        result_safe "TCP Wrapper 접근 제어 설정이 있습니다 — 내용 수동 확인 권장"
    else
        result_warn "TCP Wrapper 파일은 존재하나 유효한 규칙이 없습니다"
    fi
    unset _allow_entries _deny_entries
else
    result_warn "/etc/hosts.allow, /etc/hosts.deny 파일이 없습니다 — 방화벽 설정으로 대체 확인 필요"
fi

# ── hosts.lpd 파일 소유자·권한 (KISA 2021 U-30 상당) ───────────────────────────
check_header "U-18-lpd" "hosts.lpd 파일 소유자·권한"
if [[ -f /etc/hosts.lpd ]]; then
    check_file_attr "/etc/hosts.lpd" "root" "600|640"
    # 내용도 점검 — '+' 항목은 모든 호스트 허용으로 취약
    if grep -qE "^\+" /etc/hosts.lpd 2>/dev/null; then
        result_vuln "/etc/hosts.lpd — '+' 항목이 있어 모든 호스트에 LPD 프린터 접근 허용됨 (제거 필요)"
    fi
else
    result_pass "/etc/hosts.lpd 파일이 없습니다 (LPD 미사용)"
fi

# ── U-54: 홈디렉터리 소유자 및 권한 ────────────────────────────────────────────
check_header "U-54" "홈디렉터리 소유자 및 권한"
_bad_home=false
while IFS=: read -r _user _ _uid _ _ _home _; do
    [[ "${_uid}" -lt 1000 && "${_user}" != "root" ]] && continue
    [[ ! -d "${_home}" ]] && continue
    _owner=$(file_owner "${_home}")
    _perm=$(file_perm_octal "${_home}")
    if [[ "${_owner}" != "${_user}" ]]; then
        result_vuln "홈디렉터리 소유자 불일치: ${_home} (현재: ${_owner}, 기대: ${_user})"
        _bad_home=true
    fi
    # other write 비트(002) 검사
    if [[ $(( 0${_perm} & 002 )) -ne 0 ]]; then
        result_vuln "홈디렉터리에 other 쓰기 권한 존재: ${_home} (권한: ${_perm})"
        _bad_home=true
    fi
done < /etc/passwd
${_bad_home} || result_safe "모든 홈디렉터리의 소유자·권한이 적절합니다"
unset _bad_home _user _uid _home _owner _perm

# ── U-55: 홈디렉터리 존재 여부 ─────────────────────────────────────────────────
check_header "U-55" "홈디렉터리 실제 존재 여부 확인"
_missing_home=false
while IFS=: read -r _user _ _uid _ _ _home _shell; do
    [[ "${_uid}" -lt 1000 ]] && continue
    [[ "${_shell}" == */nologin || "${_shell}" == */false ]] && continue
    if [[ ! -d "${_home}" ]]; then
        result_vuln "홈디렉터리 없음: ${_user} → ${_home} (디렉터리 생성 필요)"
        _missing_home=true
    fi
done < /etc/passwd
${_missing_home} || result_safe "모든 일반 계정의 홈디렉터리가 존재합니다"
unset _missing_home _user _uid _home _shell

# ── U-56: 숨겨진 파일·디렉터리 검사 ───────────────────────────────────────────
check_header "U-56" "숨겨진 파일·디렉터리 검사"
_hidden_file="${RESULT_DIR}/hidden_files.txt"
find / -name ".*" \
    \( -not -path "/proc/*" \) \
    \( -not -path "/sys/*" \) \
    \( -not -path "*/.git/*" \) \
    \( -not -path "*/.git" \) \
    -xdev 2>/dev/null > "${_hidden_file}" || true
_hidden_cnt=$(wc -l < "${_hidden_file}")
result_warn "숨겨진 파일/디렉터리 ${_hidden_cnt}개 — 목록 저장됨: ${_hidden_file} (수동 검토 필요)"
result_info "점검 기준: 사용자 홈 외부의 숨김 파일, 의심스러운 위치의 .sh/.py 파일 확인"
unset _hidden_file _hidden_cnt

# ── U-57: .netrc 파일 사용 금지 ────────────────────────────────────────────────
check_header "U-57" ".netrc 파일 사용 금지"
_netrc=$(find / -name ".netrc" -xdev 2>/dev/null | head -20 || true)
if [[ -z "${_netrc}" ]]; then
    result_safe ".netrc 파일이 없습니다"
else
    result_vuln ".netrc 파일 발견 — 평문 자격증명 저장 위험, 즉시 삭제 필요:"
    while IFS= read -r _nf; do
        result_info "  ${_nf}"
    done <<< "${_netrc}"
fi
unset _netrc _nf
