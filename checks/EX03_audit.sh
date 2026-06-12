#!/bin/bash
# 감사 로그 (auditd) 점검 모듈
# CIS Benchmark 기반
section_header "감사 로그 auditd (CIS Benchmark)"

# ── EX-AUD-01: auditd 서비스 실행 여부 ─────────────────────────────────────────
check_header "EX-AUD-01" "auditd 서비스 실행 여부"
_auditd_running=false
if is_service_active "auditd" 2>/dev/null; then
    result_safe "auditd 서비스가 실행 중입니다"
    _auditd_running=true
else
    result_vuln "auditd 서비스가 실행되지 않고 있습니다 — systemctl enable --now auditd"
fi

# ── EX-AUD-02: 감사 규칙 파일 존재 여부 ────────────────────────────────────────
# 파일 기반 점검 — auditd 실행 상태와 무관하게 수행
check_header "EX-AUD-02" "감사 규칙 파일 및 주요 파일 감사 여부"
_audit_rules=""
for _f in /etc/audit/rules.d/audit.rules /etc/audit/rules.d/50-hardening.rules \
          /etc/audit/audit.rules; do
    if [[ -f "${_f}" ]]; then
        _audit_rules="${_f}"
        break
    fi
done

if [[ -z "${_audit_rules}" ]]; then
    result_vuln "감사 규칙 파일이 없습니다 (/etc/audit/rules.d/ 또는 /etc/audit/audit.rules)"
else
    result_safe "감사 규칙 파일: ${_audit_rules}"

    # 중요 파일에 대한 감사 규칙 확인
    declare -A _audit_targets=(
        ["/etc/passwd"]="계정 파일 변경 감사"
        ["/etc/shadow"]="패스워드 파일 변경 감사"
        ["/etc/sudoers"]="sudoers 변경 감사"
        ["/etc/ssh/sshd_config"]="SSH 설정 변경 감사"
        ["/var/log"]="로그 디렉터리 접근 감사"
    )
    for _target in "${!_audit_targets[@]}"; do
        if grep -q "${_target}" "${_audit_rules}" 2>/dev/null; then
            result_safe "${_target} — 감사 규칙 있음 (${_audit_targets[${_target}]})"
        else
            result_warn "${_target} — 감사 규칙 없음 (${_audit_targets[${_target}]} 권장)"
        fi
    done
    unset _audit_targets _target
fi
unset _audit_rules _f

# ── EX-AUD-03: auditd 설정 파일 점검 ───────────────────────────────────────────
# 파일 기반 점검 — auditd 실행 상태와 무관하게 수행
check_header "EX-AUD-03" "auditd 설정 (로그 크기, 가득 찼을 때 동작)"
_auditd_conf="/etc/audit/auditd.conf"
if [[ -f "${_auditd_conf}" ]]; then
    check_file_attr "${_auditd_conf}" "root" "640|600"

    _max_log=$(grep -E "^[[:space:]]*max_log_file[[:space:]]*=" "${_auditd_conf}" \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _action=$(grep -E "^[[:space:]]*space_left_action[[:space:]]*=" "${_auditd_conf}" \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    _disk_action=$(grep -E "^[[:space:]]*disk_full_action[[:space:]]*=" "${_auditd_conf}" \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)

    result_info "max_log_file        : ${_max_log:-미설정}MB"
    result_info "space_left_action   : ${_action:-미설정}"
    result_info "disk_full_action    : ${_disk_action:-미설정}"

    if [[ "${_action:-}" == "SYSLOG" || "${_action:-}" == "EMAIL" || "${_action:-}" == "EXEC" ]]; then
        result_safe "space_left_action = ${_action} — 공간 부족 시 알림 설정됨"
    else
        result_warn "space_left_action = ${_action:-미설정} — SYSLOG 또는 EMAIL 설정 권장"
    fi

    if [[ "${_disk_action:-}" == "SYSLOG" || "${_disk_action:-}" == "HALT" ]]; then
        result_safe "disk_full_action = ${_disk_action} — 디스크 가득 찼을 때 처리 설정됨"
    else
        result_warn "disk_full_action = ${_disk_action:-미설정} — SYSLOG 또는 HALT 설정 권장"
    fi
    unset _max_log _action _disk_action
else
    result_warn "/etc/audit/auditd.conf 파일이 없습니다"
fi
unset _auditd_conf

# ── EX-AUD-04: 현재 로드된 감사 규칙 수 확인 ───────────────────────────────────
# 런타임 점검 — auditd 실행 중일 때만 수행
check_header "EX-AUD-04" "현재 로드된 감사 규칙 수"
if ! ${_auditd_running}; then
    result_warn "auditd 미실행으로 로드된 규칙을 확인할 수 없습니다 — auditd 활성화 후 재점검 필요"
elif command -v auditctl &>/dev/null; then
    _rule_cnt=$(auditctl -l 2>/dev/null | grep -vc "^List\|^No rules" || echo 0)
    if [[ "${_rule_cnt}" -gt 0 ]]; then
        result_safe "로드된 감사 규칙 ${_rule_cnt}개"
    else
        result_warn "로드된 감사 규칙이 없습니다 — auditctl -l 로 확인 후 규칙 추가 필요"
    fi
    unset _rule_cnt
else
    result_warn "auditctl 명령을 찾을 수 없습니다"
fi

# ── 감사 규칙 내용 점검 (EX-AUD-05~09) ─────────────────────────────────────────
# 규칙 파일과 런타임 모두 합산 (auditd 미실행 시 파일 기반만 점검)
_all_rules=""
for _rf in /etc/audit/rules.d/*.rules /etc/audit/audit.rules; do
    [[ -f "${_rf}" ]] && _all_rules+=$(cat "${_rf}" 2>/dev/null || true)
done
if ${_auditd_running} && command -v auditctl &>/dev/null; then
    _all_rules+=$(auditctl -l 2>/dev/null || true)
fi

if [[ -z "${_all_rules}" && ! ${_auditd_running} ]]; then
    result_warn "auditd 미실행 + 규칙 파일 없음 — EX-AUD-05~09 점검 생략"
    unset _all_rules _rf _auditd_running
    return
fi

${_auditd_running} || result_info "auditd 미실행 — 이하 규칙 점검은 설정 파일 기반으로만 수행됨 (런타임 비활성 상태)"

# ── EX-AUD-05: 권한 상승 명령 감사 (sudo, su, newgrp, chsh) ────────────────────
check_header "EX-AUD-05" "권한 상승 명령 감사 규칙 (sudo, su, newgrp)"
_priv_missing=()
for _cmd in /usr/bin/sudo /usr/bin/su /usr/bin/newgrp /usr/bin/chsh; do
    if ! echo "${_all_rules}" | grep -q "${_cmd}"; then
        _priv_missing+=("${_cmd##*/}")
    fi
done
if [[ "${#_priv_missing[@]}" -eq 0 ]]; then
    result_safe "권한 상승 명령(sudo/su/newgrp/chsh) 감사 규칙 모두 있음"
else
    result_warn "다음 권한 상승 명령에 감사 규칙 없음: ${_priv_missing[*]}"
    result_info "예시: -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_esc"
fi
unset _priv_missing _cmd

# ── EX-AUD-06: 파일 삭제 감사 (unlink, rename, rmdir) ─────────────────────────
check_header "EX-AUD-06" "파일 삭제 감사 규칙 (unlink, rename, rmdir 시스템콜)"
if echo "${_all_rules}" | grep -qE "unlink|rename|rmdir"; then
    result_safe "파일 삭제 관련 시스템콜 감사 규칙 있음"
elif echo "${_all_rules}" | grep -q "delete"; then
    result_safe "파일 삭제 감사 규칙 있음 (-k delete)"
else
    result_warn "파일 삭제 감사 규칙 없음"
    result_info "예시: -a always,exit -F arch=b64 -S unlinkat,rename,rmdir -F auid>=1000 -k delete"
fi

# ── EX-AUD-07: 네트워크 환경 변경 감사 (sethostname, setdomainname) ────────────
check_header "EX-AUD-07" "네트워크 환경 변경 감사 (sethostname, setdomainname)"
if echo "${_all_rules}" | grep -qE "sethostname|setdomainname|system-locale"; then
    result_safe "네트워크 환경 변경 감사 규칙 있음"
else
    result_warn "네트워크 환경 변경 감사 규칙 없음"
    result_info "예시: -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
fi

# ── EX-AUD-08: 커널 모듈 로딩/언로딩 감사 ──────────────────────────────────────
check_header "EX-AUD-08" "커널 모듈 로딩·언로딩 감사 (insmod, rmmod, modprobe)"
if echo "${_all_rules}" | grep -qE "init_module|delete_module|kernel-module|modules"; then
    result_safe "커널 모듈 로딩/언로딩 감사 규칙 있음"
else
    result_warn "커널 모듈 감사 규칙 없음"
    result_info "예시: -a always,exit -F arch=b64 -S init_module,delete_module -k kernel-module"
fi

# ── EX-AUD-09: 시간 변경 감사 (settimeofday, clock_settime) ────────────────────
check_header "EX-AUD-09" "시스템 시간 변경 감사 (settimeofday, clock_settime)"
if echo "${_all_rules}" | grep -qE "settimeofday|clock_settime|adjtimex|time-change"; then
    result_safe "시스템 시간 변경 감사 규칙 있음"
else
    result_warn "시스템 시간 변경 감사 규칙 없음"
    result_info "예시: -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change"
fi

unset _all_rules _rf _auditd_running
