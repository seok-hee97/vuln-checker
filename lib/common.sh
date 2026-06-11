#!/bin/bash
# 공통 점검 헬퍼 함수 모듈
# 모든 checks/ 모듈에서 사용하는 재사용 가능한 유틸리티 함수 모음

# ── 파일 속성 조회 ─────────────────────────────────────────────────────────────
file_exists()     { [[ -e "$1" ]] && echo 1 || echo 0; }
file_owner()      { stat -c "%U" "$1" 2>/dev/null || ls -ld "$1" 2>/dev/null | awk '{print $3}'; }
file_group()      { stat -c "%G" "$1" 2>/dev/null || ls -ld "$1" 2>/dev/null | awk '{print $4}'; }
file_perm_octal() { stat -c "%a" "$1" 2>/dev/null; }
file_perm_sym()   { stat -c "%A" "$1" 2>/dev/null; }

# ── 파일 소유자·권한 통합 점검 ────────────────────────────────────────────────
# 파일 1개당 판정은 1개 (TOTAL +1) — 소유자와 권한 이슈를 하나의 결과로 통합
#
# Usage: check_file_attr <path> <expected_owner> <expected_perms>
#   path           : 점검할 파일/디렉터리 경로
#   expected_owner : 기대 소유자 (예: "root")
#   expected_perms : 기대 권한(8진수). 복수 허용은 "|" 구분자 (예: "600|640")
#
# 파일이 존재하지 않으면 result_pass 처리 (해당 없음, TOTAL 미증가)
check_file_attr() {
    local path="$1" expected_owner="$2" expected_perms="$3"

    if [[ ! -e "${path}" ]]; then
        result_pass "${path} — 파일 없음 (해당 없음)"
        return
    fi

    local owner perm_oct
    owner=$(file_owner "${path}")
    perm_oct=$(file_perm_octal "${path}")
    result_info "${path} — 소유자: ${owner}, 권한: ${perm_oct}"

    local issues=()

    # 소유자 검사
    if [[ "${owner}" != "${expected_owner}" ]]; then
        issues+=("소유자 '${owner}' (기대: '${expected_owner}')")
    fi

    # 권한 검사 ("|" 구분 복수 허용값 지원)
    local matched=false
    local _p
    IFS='|' read -ra _perm_list <<< "${expected_perms}"
    for _p in "${_perm_list[@]}"; do
        [[ "${perm_oct}" == "${_p}" ]] && { matched=true; break; }
    done
    unset _perm_list _p

    ${matched} || issues+=("권한 '${perm_oct}' (기대: '${expected_perms}')")

    if [[ "${#issues[@]}" -eq 0 ]]; then
        result_safe "${path} — 소유자·권한 적절"
    else
        local _msg
        printf -v _msg '%s; ' "${issues[@]}"
        result_vuln "${path} — ${_msg%; }"
        unset _msg
    fi
    unset issues
}

# ── 프로세스 점검 ─────────────────────────────────────────────────────────────
# 반환: 0=실행 중, 1=실행 안 함
is_process_running() {
    ps aux 2>/dev/null | grep -v grep | grep -q "$1"
}

# ── 서비스 활성화 점검 ────────────────────────────────────────────────────────
# systemctl 우선, 없으면 service 폴백
# 반환: 0=active, non-zero=inactive/not found
is_service_active() {
    local svc="$1"
    if ${SYSTEMD_AVAILABLE}; then
        systemctl is-active --quiet "${svc}" 2>/dev/null
    else
        service "${svc}" status &>/dev/null 2>&1
    fi
}

# ── xinetd 서비스 비활성화 여부 ─────────────────────────────────────────────
# 반환: 0=비활성(안전), non-zero=활성(취약)
is_xinetd_disabled() {
    local svc="$1"
    local path="/etc/xinetd.d/${svc}"
    [[ ! -f "${path}" ]] && return 0   # 파일 없음 = 미설치 = 안전
    grep -qE "disable[[:space:]]*=[[:space:]]*yes" "${path}" 2>/dev/null
}

# ── sshd_config 값 읽기 ─────────────────────────────────────────────────────
# 주석 처리된 줄 제외, 마지막 유효 값 반환
sshd_config_val() {
    local key="$1"
    grep -iE "^[[:space:]]*${key}[[:space:]]" /etc/ssh/sshd_config 2>/dev/null \
        | awk '{print $2}' | tail -1
}

# ── /etc/login.defs 값 읽기 ─────────────────────────────────────────────────
login_defs_val() {
    local key="$1"
    grep -E "^${key}[[:space:]]" /etc/login.defs 2>/dev/null \
        | awk '{print $2}' | tail -1
}

# ── sysctl 파라미터 값 읽기 ─────────────────────────────────────────────────
sysctl_val() {
    sysctl -n "$1" 2>/dev/null || echo ""
}

# ── PAM 설정에서 특정 모듈·키 값 읽기 ──────────────────────────────────────
# Usage: pam_val <pam_file> <module_grep_pattern> <key>
pam_val() {
    local file="$1" module="$2" key="$3"
    grep -E "${module}" "${file}" 2>/dev/null \
        | grep -oE "${key}=[^ ]+" | sed 's/.*=//' | tail -1
}

# ── sysctl 단일 파라미터 점검 헬퍼 ─────────────────────────────────────────
# Usage: check_sysctl <param> <expected_value> <description>
check_sysctl() {
    local param="$1" expected="$2" desc="$3"
    local val
    val=$(sysctl_val "${param}")
    if [[ "${val}" == "${expected}" ]]; then
        result_safe "${param} = ${val} (${desc})"
    else
        result_vuln "${param} = ${val:-미설정} (기대: ${expected}) — ${desc}"
    fi
}

# ── xinetd 서비스 비활성화 점검 래퍼 ────────────────────────────────────────
# Usage: check_xinetd_svc <item_id> <service_name> <display_name>
check_xinetd_svc() {
    local id="$1" svc="$2" name="$3"
    check_header "${id}" "${name} 비활성화"
    if is_xinetd_disabled "${svc}"; then
        result_safe "${name} — 설치되지 않았거나 비활성화되어 있습니다"
    else
        result_vuln "${name} — /etc/xinetd.d/${svc} 에서 활성화되어 있습니다"
    fi
}
