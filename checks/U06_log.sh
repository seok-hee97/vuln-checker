#!/bin/bash
# 로그 관리 점검 모듈
# KISA U-43, U-67~U-72
section_header "로그 관리 (U-43, U-67 ~ U-72)"

check_header "U-43" "로그 관리 정책 및 설정 점검"

# ── 로깅 데몬 확인 ─────────────────────────────────────────────────────────────
_log_daemon=""
if is_service_active "rsyslog" 2>/dev/null; then
    _log_daemon="rsyslog"
elif is_service_active "syslog" 2>/dev/null; then
    _log_daemon="syslog"
elif is_service_active "syslog-ng" 2>/dev/null; then
    _log_daemon="syslog-ng"
fi

if [[ -n "${_log_daemon}" ]]; then
    result_safe "로그 데몬 실행 중: ${_log_daemon}"
else
    result_vuln "로그 데몬(rsyslog/syslog/syslog-ng)이 실행되지 않고 있습니다"
fi
unset _log_daemon

# ── 로그 설정 파일 존재 확인 ───────────────────────────────────────────────────
_log_conf=""
for _f in /etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf; do
    if [[ -f "${_f}" ]]; then
        _log_conf="${_f}"
        break
    fi
done

if [[ -n "${_log_conf}" ]]; then
    result_safe "로그 설정 파일 존재: ${_log_conf}"
    result_info "${_log_conf} — 소유자: $(file_owner "${_log_conf}"), 권한: $(file_perm_octal "${_log_conf}") (권한 점검은 U-11 에서 수행)"

    # 원격 로그 서버 설정 확인
    _remote_log=$(grep -E "^[[:space:]]*(\*\.\*|auth|kern|daemon)[[:space:]]*@" \
        "${_log_conf}" 2>/dev/null | grep -v "^#" | head -3 || true)
    if [[ -n "${_remote_log}" ]]; then
        result_safe "원격 로그 서버로 전송 설정이 있습니다:"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_remote_log}"
    else
        result_warn "원격 로그 서버 설정이 없습니다 — 중요 시스템은 원격 로그 서버 구성 권장"
    fi
    unset _remote_log _line
else
    result_vuln "로그 설정 파일이 없습니다 (rsyslog.conf/syslog.conf)"
fi
unset _log_conf _f

# ── 주요 로그 파일 존재 및 권한 확인 ──────────────────────────────────────────
_log_files_checked=false

# RHEL 계열
for _lf in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do
    [[ -f "${_lf}" ]] && { check_file_attr "${_lf}" "root" "600|640"; _log_files_checked=true; }
done

# Debian 계열
for _lf in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/daemon.log; do
    [[ -f "${_lf}" ]] && { check_file_attr "${_lf}" "root" "640|600"; _log_files_checked=true; }
done

${_log_files_checked} || result_warn "주요 로그 파일을 찾을 수 없습니다"
unset _log_files_checked _lf

# ── 로그 로테이션 설정 확인 ────────────────────────────────────────────────────
if [[ -f /etc/logrotate.conf ]]; then
    result_safe "/etc/logrotate.conf — 로그 로테이션 설정 존재"
    _rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]" /etc/logrotate.conf \
        | awk '{print $2}' | tail -1)
    result_info "기본 rotate 횟수: ${_rotate:-미설정}주/회"
    if [[ -n "${_rotate:-}" && "${_rotate}" -ge 12 ]]; then
        result_safe "로그 보관 기간 ${_rotate}회 이상 (권장: 12회/1년 이상)"
    else
        result_warn "로그 보관 기간 ${_rotate:-미설정} — 12회 이상(약 3개월) 설정 권장"
    fi
    unset _rotate
else
    result_warn "/etc/logrotate.conf 파일이 없습니다"
fi

# ── wtmp, btmp, lastlog 존재 확인 ─────────────────────────────────────────────
check_header "U-43-extra" "로그인 기록 파일 존재 여부"
for _lf in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
    if [[ -f "${_lf}" ]]; then
        result_safe "${_lf} — 존재합니다"
    else
        result_warn "${_lf} — 파일이 없습니다"
    fi
done
unset _lf

# ── journald (systemd) 로그 확인 ───────────────────────────────────────────────
if ${SYSTEMD_AVAILABLE} && command -v journalctl &>/dev/null; then
    _jsize=$(journalctl --disk-usage 2>/dev/null | awk '{print $7, $8}' || true)
    result_info "systemd journal 크기: ${_jsize:-확인불가}"

    # persistent 저장 여부
    if [[ -d /var/log/journal ]]; then
        result_safe "systemd journal — persistent 모드 (디스크 저장)"
    else
        result_warn "systemd journal — volatile 모드 (재부팅 시 삭제). persistent 권장"
        result_info "persistent 설정: mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal"
    fi
    unset _jsize
fi

# ── U-67: 시스템 로깅 기능 활성화 (주요 facility 로깅 여부 상세 확인) ────────────
check_header "U-67" "시스템 로깅 설정 상세 (주요 facility 로깅 여부)"
_log_conf_detail=""
for _f in /etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf; do
    [[ -f "${_f}" ]] && { _log_conf_detail="${_f}"; break; }
done

if [[ -n "${_log_conf_detail}" ]]; then
    # 보안 이벤트 로깅 여부 (auth, authpriv)
    if grep -Ev "^#|^$" "${_log_conf_detail}" 2>/dev/null \
            | grep -qE "(auth|authpriv|security)\.(notice|warn|info|\*)" ; then
        result_safe "인증/보안 이벤트(auth/authpriv) 로깅 설정됨"
    else
        result_warn "인증/보안 이벤트(auth/authpriv) 로깅 설정 확인 필요"
    fi

    # 커널 로깅 여부 (kern)
    if grep -Ev "^#|^$" "${_log_conf_detail}" 2>/dev/null | grep -qE "kern\.(notice|warn|err|\*)"; then
        result_safe "커널 이벤트(kern) 로깅 설정됨"
    else
        result_warn "커널 이벤트(kern) 로깅 설정 확인 필요"
    fi

    # 크리티컬 이벤트 (*.crit, *.emerg) 로깅 확인
    if grep -Ev "^#|^$" "${_log_conf_detail}" 2>/dev/null | grep -qE "\*\.(crit|emerg|alert)"; then
        result_safe "크리티컬/긴급 이벤트 로깅 설정됨"
    else
        result_warn "크리티컬/긴급 이벤트 로깅 설정 확인 필요 (*.crit, *.emerg 권장)"
    fi
else
    result_vuln "로그 설정 파일이 없어 상세 분석 불가"
fi
unset _log_conf_detail _f

# ── U-68: 원격 로그 서버 설정 확인 ────────────────────────────────────────────
check_header "U-68" "원격 로그 서버 전송 설정"
_remote_found=false
for _f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf; do
    [[ -f "${_f}" ]] || continue
    _r=$(grep -Ev "^#|^$" "${_f}" 2>/dev/null \
         | grep -E "@[0-9a-zA-Z]|@@[0-9a-zA-Z]|\*\.\*.*@@" | head -3 || true)
    if [[ -n "${_r}" ]]; then
        _remote_found=true
        result_safe "원격 로그 서버 전송 설정 발견: ${_f}"
        while IFS= read -r _rl; do
            result_info "  ${_rl}"
        done <<< "${_r}"
    fi
    unset _r
done

${_remote_found} || result_warn "원격 로그 서버 전송 설정이 없습니다 — 중요 시스템은 중앙 로그 서버 구성 강력 권장"
unset _remote_found _f _rl

# ── U-69: 로그 파일 접근 권한 설정 (wtmp, btmp, lastlog) ──────────────────────
check_header "U-69" "로그 파일 접근 권한 설정 (wtmp, btmp, lastlog)"
for _lf in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
    if [[ -f "${_lf}" ]]; then
        _perm=$(file_perm_octal "${_lf}")
        _owner=$(file_owner "${_lf}")
        result_info "${_lf} — 소유자: ${_owner}, 권한: ${_perm}"
        _ok=true
        [[ "${_owner}" != "root" ]] && { result_vuln "${_lf} — 소유자가 root가 아닙니다 (현재: ${_owner})"; _ok=false; }
        # 644 이하 (other write 없어야 함)
        if [[ $(( 0${_perm} & 002 )) -ne 0 ]]; then
            result_vuln "${_lf} — other 쓰기 권한이 있습니다 (권한: ${_perm})"
            _ok=false
        fi
        ${_ok} && result_safe "${_lf} — 소유자·권한 적절"
        unset _ok
    else
        result_warn "${_lf} — 파일이 없습니다 (로그인 기록 미보존)"
    fi
    unset _perm _owner
done
unset _lf

# ── U-70: 로그온/로그오프 기록 유지 설정 ───────────────────────────────────────
check_header "U-70" "로그온/로그오프 기록 유지 (last, lastlog)"
# lastlog 활성화 여부 — /etc/login.defs LASTLOG_ENAB
_lastlog_enab=$(login_defs_val "LASTLOG_ENAB")
if [[ "${_lastlog_enab:-}" == "yes" || "${_lastlog_enab:-}" == "YES" || -z "${_lastlog_enab:-}" ]]; then
    result_safe "LASTLOG_ENAB = ${_lastlog_enab:-yes(기본)} — 마지막 로그인 기록 활성화"
else
    result_vuln "LASTLOG_ENAB = ${_lastlog_enab} — 마지막 로그인 기록 비활성화 (yes 설정 필요)"
fi
unset _lastlog_enab

# wtmp 내용 확인 (last 명령으로 최근 로그인 기록 있는지)
if command -v last &>/dev/null; then
    _last_cnt=$(last -n 5 2>/dev/null | wc -l || echo 0)
    if [[ "${_last_cnt}" -gt 1 ]]; then
        result_safe "로그인 기록이 유지되고 있습니다 (wtmp — 최근 기록 ${_last_cnt}줄)"
    else
        result_warn "로그인 기록이 비어 있습니다 (wtmp) — 시스템 초기화 여부 확인 필요"
    fi
    unset _last_cnt
fi

# ── U-71: sudo 명령 로그 설정 ──────────────────────────────────────────────────
check_header "U-71" "sudo 명령 로그 설정"
if grep -rqE "^[[:space:]]*Defaults.*logfile|^[[:space:]]*Defaults.*log_output|^[[:space:]]*Defaults.*syslog" \
        /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    _sudo_log=$(grep -rh "Defaults.*log" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -v "^#" | head -3 || true)
    result_safe "sudo 명령 로깅 설정이 있습니다"
    while IFS= read -r _sl; do
        result_info "  ${_sl}"
    done <<< "${_sudo_log}"
    unset _sudo_log _sl
else
    result_warn "sudo 명령 로그 미설정 — /etc/sudoers 에 'Defaults logfile=/var/log/sudo.log' 추가 권장"
fi

# syslog sudo 로깅 여부 (rsyslog)
if grep -rqE "sudo" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
    result_safe "rsyslog에 sudo 로그 설정이 있습니다"
fi

# ── U-72: 이벤트 로그 관리 (로그 보존 주기, logrotate 상세) ─────────────────────
check_header "U-72" "이벤트 로그 관리 (보존 주기 및 logrotate 설정)"
if [[ -f /etc/logrotate.conf ]]; then
    _rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]" /etc/logrotate.conf \
        | awk '{print $2}' | tail -1)
    _compress=$(grep -E "^[[:space:]]*compress" /etc/logrotate.conf | grep -v "^#" | head -1 || true)
    _dateext=$(grep -E "^[[:space:]]*dateext" /etc/logrotate.conf | grep -v "^#" | head -1 || true)

    result_info "기본 rotate 횟수: ${_rotate:-미설정}"
    result_info "compress: ${_compress:-미설정}"
    result_info "dateext: ${_dateext:-미설정}"

    # 보관 기간 판정 (주 단위 rotate 기준 12주=약 3개월)
    if [[ -n "${_rotate:-}" && "${_rotate}" -ge 12 ]]; then
        result_safe "로그 보관 횟수 ${_rotate}회 — 3개월 이상 보관 (권장 기준 충족)"
    elif [[ -n "${_rotate:-}" && "${_rotate}" -ge 4 ]]; then
        result_warn "로그 보관 횟수 ${_rotate}회 — 1개월 이상, 3개월 미만 (12회 이상 권장)"
    else
        result_vuln "로그 보관 횟수 ${_rotate:-미설정} — 설정 부족 (12회 이상 권장)"
    fi

    [[ -n "${_compress:-}" ]] && result_safe "로그 압축 설정됨 (compress)"
    [[ -n "${_dateext:-}" ]] && result_safe "날짜 기반 로그 파일명 설정됨 (dateext)"
    unset _rotate _compress _dateext
else
    result_vuln "/etc/logrotate.conf 파일이 없습니다 — 로그 관리 정책 미설정"
fi

# logrotate.d 설정 수 확인
_lr_d_cnt=$(find /etc/logrotate.d -type f 2>/dev/null | wc -l || echo 0)
result_info "/etc/logrotate.d/ 개별 설정 파일 수: ${_lr_d_cnt}개"
unset _lr_d_cnt

