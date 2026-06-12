#!/usr/bin/env bats
# lib/common.sh 유닛 테스트
# 실행: bats tests/test_common.bats
#
# 설치:
#   git clone https://github.com/bats-core/bats-core.git
#   cd bats-core && sudo ./install.sh /usr/local

setup() {
    SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"

    # 의존 라이브러리 로드
    source "${SCRIPT_DIR}/lib/os_detect.sh"

    # 테스트용 임시 결과 파일
    CF="$(mktemp /tmp/vuln_checker_test_XXXXXX.txt)"
    export CF

    # 카운터 초기화
    TOTAL=0; SAFE=0; VULN=0; WARN=0
    export TOTAL SAFE VULN WARN

    source "${SCRIPT_DIR}/lib/output.sh"
    source "${SCRIPT_DIR}/lib/common.sh"
}

teardown() {
    rm -f "${CF}"
}

# ── file_exists ──────────────────────────────────────────────────────────────

@test "file_exists: 존재하는 파일에 1 반환" {
    run file_exists "/etc/passwd"
    [ "${output}" = "1" ]
}

@test "file_exists: 존재하지 않는 파일에 0 반환" {
    run file_exists "/nonexistent_xyz_12345"
    [ "${output}" = "0" ]
}

# ── file_owner ───────────────────────────────────────────────────────────────

@test "file_owner: /etc/passwd 소유자가 root" {
    run file_owner "/etc/passwd"
    [ "${output}" = "root" ]
}

# ── file_perm_octal ──────────────────────────────────────────────────────────

@test "file_perm_octal: /etc/passwd 권한이 숫자형 반환" {
    run file_perm_octal "/etc/passwd"
    [[ "${output}" =~ ^[0-9]{3,4}$ ]]
}

# ── login_defs_val ───────────────────────────────────────────────────────────

@test "login_defs_val: PASS_MAX_DAYS 가 숫자 반환" {
    run login_defs_val "PASS_MAX_DAYS"
    [[ "${output}" =~ ^[0-9]+$ ]] || [[ -z "${output}" ]]
}

# ── sysctl_val ───────────────────────────────────────────────────────────────

@test "sysctl_val: 유효한 파라미터에 값 반환" {
    skip_if_not_root
    run sysctl_val "kernel.hostname"
    [ -n "${output}" ]
}

# ── check_file_attr: 정상 케이스 ─────────────────────────────────────────────

@test "check_file_attr: 소유자·권한 모두 정상 → SAFE++ TOTAL++ 각 1씩" {
    # /etc/passwd 는 root:644 (시스템마다 다를 수 있으나 보통 root 644)
    local _owner _perm
    _owner=$(file_owner "/etc/passwd")
    _perm=$(file_perm_octal "/etc/passwd")

    local before_safe="${SAFE}"
    local before_total="${TOTAL}"

    check_file_attr "/etc/passwd" "${_owner}" "${_perm}"

    [ "${SAFE}"  -eq $(( before_safe  + 1 )) ]
    [ "${TOTAL}" -eq $(( before_total + 1 )) ]
}

@test "check_file_attr: 소유자 불일치 → VULN++ TOTAL++ 각 1씩" {
    local before_vuln="${VULN}"
    local before_total="${TOTAL}"

    check_file_attr "/etc/passwd" "nobody" "644"

    [ "${VULN}"  -ge $(( before_vuln  + 1 )) ]
    [ "${TOTAL}" -ge $(( before_total + 1 )) ]
}

@test "check_file_attr: 존재하지 않는 파일 → PASS 출력, TOTAL 불변" {
    local before_total="${TOTAL}"

    check_file_attr "/nonexistent_xyz_12345" "root" "644"

    [ "${TOTAL}" -eq "${before_total}" ]
    grep -q "PASS" "${CF}"
}

@test "check_file_attr: 권한 복수 허용 (600|640) — 일치 시 안전" {
    # 임시 파일 640으로 생성
    local _tmp
    _tmp=$(mktemp /tmp/bats_perm_test_XXXXXX)
    chmod 640 "${_tmp}"
    chown root "${_tmp}" 2>/dev/null || true

    local _owner
    _owner=$(file_owner "${_tmp}")
    local before_safe="${SAFE}"

    check_file_attr "${_tmp}" "${_owner}" "600|640"

    rm -f "${_tmp}"
    [ "${SAFE}" -ge $(( before_safe + 1 )) ]
}

@test "perm_within_limit: 실제 권한이 기준보다 엄격하면 안전" {
    run perm_within_limit "640" "644"
    [ "${status}" -eq 0 ]
}

@test "perm_within_limit: 실제 권한이 기준보다 느슨하면 취약" {
    run perm_within_limit "666" "644"
    [ "${status}" -ne 0 ]
}

@test "check_file_attr: 기준보다 엄격한 권한은 SAFE++" {
    local _tmp
    _tmp=$(mktemp /tmp/bats_perm_test_XXXXXX)
    chmod 640 "${_tmp}"
    local _owner
    _owner=$(file_owner "${_tmp}")

    local s="${SAFE}" t="${TOTAL}"
    check_file_attr "${_tmp}" "${_owner}" "644"
    rm -f "${_tmp}"

    [ "${SAFE}" -eq $(( s + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

# ── result_* 카운터 동작 ─────────────────────────────────────────────────────

@test "result_safe: SAFE++, TOTAL++" {
    local s="${SAFE}" t="${TOTAL}"
    result_safe "test message"
    [ "${SAFE}"  -eq $(( s + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

@test "result_vuln: VULN++, TOTAL++" {
    local v="${VULN}" t="${TOTAL}"
    result_vuln "test message"
    [ "${VULN}"  -eq $(( v + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

@test "result_warn: WARN++ 만, TOTAL 불변" {
    local w="${WARN}" t="${TOTAL}"
    result_warn "test message"
    [ "${WARN}"  -eq $(( w + 1 )) ]
    [ "${TOTAL}" -eq "${t}" ]
}

@test "result_info: 카운터 변화 없음" {
    local s="${SAFE}" v="${VULN}" w="${WARN}" t="${TOTAL}"
    result_info "test info"
    [ "${SAFE}"  -eq "${s}" ]
    [ "${VULN}"  -eq "${v}" ]
    [ "${WARN}"  -eq "${w}" ]
    [ "${TOTAL}" -eq "${t}" ]
}

# ── 결과 파일 출력 검증 ───────────────────────────────────────────────────────

@test "result_safe: 결과 파일에 [안전] 포함됨" {
    result_safe "파일 권한 적절"
    grep -q "\[안전\]" "${CF}"
}

@test "result_vuln: 결과 파일에 [취약] 포함됨" {
    result_vuln "패스워드 정책 미설정"
    grep -q "\[취약\]" "${CF}"
}

@test "결과 파일에 ANSI 이스케이프 코드가 없음" {
    result_safe "색상 테스트"
    result_vuln "취약 테스트"
    ! grep -qF $'\x1b[' "${CF}"
}

# ── is_service_active ────────────────────────────────────────────────────────

@test "is_service_active: 존재하지 않는 서비스는 non-zero 반환" {
    if is_service_active "nonexistent_service_xyz_12345"; then
        return 1
    fi
}

# ── is_xinetd_disabled ───────────────────────────────────────────────────────

@test "is_xinetd_disabled: 존재하지 않는 xinetd 서비스는 0(안전) 반환" {
    run is_xinetd_disabled "nonexistent_xinetd_svc_xyz"
    [ "${status}" -eq 0 ]
}

# ── sshd_config_val ──────────────────────────────────────────────────────────

@test "sshd_config_val: sshd_config 없어도 빈 문자열 반환 (오류 없음)" {
    # /etc/ssh/sshd_config 가 없는 환경에서도 빈 결과 반환해야 함
    run sshd_config_val "NonExistentKey_xyz_12345"
    [ "${status}" -eq 0 ]
    [ -z "${output}" ]
}

# ── login_defs_val 경계값 ────────────────────────────────────────────────────

@test "login_defs_val: 존재하지 않는 키는 빈 문자열 반환" {
    run login_defs_val "NONEXISTENT_KEY_XYZ_12345"
    [ -z "${output}" ]
}

# ── check_sysctl ─────────────────────────────────────────────────────────────

@test "check_sysctl: 파라미터 일치 시 SAFE++" {
    skip_if_not_root
    local _param="kernel.hostname"
    local _expected
    _expected=$(sysctl -n "${_param}" 2>/dev/null)
    [[ -z "${_expected}" ]] && skip "kernel.hostname 읽기 불가"

    local s="${SAFE}" t="${TOTAL}"
    check_sysctl "${_param}" "${_expected}" "테스트"
    [ "${SAFE}"  -eq $(( s + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

@test "check_sysctl: 파라미터 불일치 시 VULN++" {
    skip_if_not_root
    local _param="kernel.hostname"
    local _val
    _val=$(sysctl -n "${_param}" 2>/dev/null)
    [[ -z "${_val}" ]] && skip "kernel.hostname 읽기 불가"

    local v="${VULN}" t="${TOTAL}"
    check_sysctl "${_param}" "__impossible_value_xyz__" "테스트"
    [ "${VULN}"  -eq $(( v + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

# ── check_file_attr 추가 케이스 ──────────────────────────────────────────────

@test "check_file_attr: 권한 불일치만 있을 때 VULN++ TOTAL++" {
    local _tmp
    _tmp=$(mktemp /tmp/bats_perm_test_XXXXXX)
    chmod 777 "${_tmp}"
    local _owner
    _owner=$(file_owner "${_tmp}")

    local v="${VULN}" t="${TOTAL}"
    check_file_attr "${_tmp}" "${_owner}" "600"
    rm -f "${_tmp}"

    [ "${VULN}"  -eq $(( v + 1 )) ]
    [ "${TOTAL}" -eq $(( t + 1 )) ]
}

@test "check_file_attr: ANSI 코드가 결과 파일에 포함되지 않음" {
    result_vuln "ANSI 오염 테스트"
    ! grep -qF $'\x1b[' "${CF}"
}

# ── result_pass 동작 ─────────────────────────────────────────────────────────

@test "result_pass: 모든 카운터 변화 없음" {
    local s="${SAFE}" v="${VULN}" w="${WARN}" t="${TOTAL}"
    result_pass "해당 없음 테스트"
    [ "${SAFE}"  -eq "${s}" ]
    [ "${VULN}"  -eq "${v}" ]
    [ "${WARN}"  -eq "${w}" ]
    [ "${TOTAL}" -eq "${t}" ]
}

@test "result_pass: 결과 파일에 [PASS] 포함됨" {
    result_pass "파일 없음"
    grep -q "\[PASS\]" "${CF}"
}

# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

skip_if_not_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        skip "root 권한 필요"
    fi
}
