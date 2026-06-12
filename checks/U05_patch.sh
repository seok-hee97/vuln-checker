#!/bin/bash
# 패치 관리 점검 모듈
# KISA U-42
section_header "패치 관리 (U-42)"

check_header "U-42" "최신 보안 패치 적용 여부"

case "${OS_FAMILY}" in
    rhel)
        # RPM 기반: 보안 업데이트 가능 목록 확인
        if command -v "${PKG_MGR}" &>/dev/null; then
            result_info "패키지 매니저: ${PKG_MGR}"
            result_info "보안 업데이트 목록 조회 중... (시간이 걸릴 수 있습니다)"

            _sec_count=0
            _sec_file="${CF%.txt}_${PKG_MGR}_security_updates.txt"
            run_with_timeout 90 "${PKG_MGR}" check-update --security --quiet > "${_sec_file}" 2>/dev/null
            _sec_query_status=$?

            if [[ "${_sec_query_status}" -eq 124 ]]; then
                result_warn "보안 업데이트 조회가 90초 내 완료되지 않았습니다 — 수동 확인 필요"
            elif [[ "${_sec_query_status}" -ne 0 && "${_sec_query_status}" -ne 100 ]]; then
                result_warn "보안 업데이트 조회 실패(exit=${_sec_query_status}) — 저장소 설정과 보안 플러그인 지원 여부 수동 확인 필요"
            else
                _sec_count=$(grep -vc "^$\|^Last metadata" "${_sec_file}" || true)
            fi

            if [[ "${_sec_query_status}" =~ ^(0|100)$ && "${_sec_count}" -eq 0 ]]; then
                result_safe "적용 가능한 보안 업데이트가 없습니다"
            elif [[ "${_sec_query_status}" =~ ^(0|100)$ ]]; then
                result_vuln "보안 업데이트 ${_sec_count}개 미적용 — 즉시 패치 적용 필요"
                result_info "적용 명령: sudo ${PKG_MGR} update --security -y"
            fi
            unset _sec_count _sec_query_status _sec_file

            # 마지막 업데이트 날짜 확인
            _last_update=$(rpm -qa --last 2>/dev/null | head -1 | awk '{print $2, $3, $4, $5}')
            result_info "마지막 패키지 업데이트: ${_last_update:-확인불가}"
            unset _last_update
        else
            result_warn "패키지 매니저(${PKG_MGR})를 찾을 수 없습니다 — 수동 확인 필요"
        fi
        ;;

    debian)
        if command -v apt &>/dev/null; then
            result_info "패키지 매니저: apt"

            _apt_list_file="${CF%.txt}_apt_upgradable.txt"
            _apt_query_ok=false
            if run_with_timeout 90 apt list --upgradable > "${_apt_list_file}" 2>/dev/null; then
                _upgradable=$(grep -c "upgradable" "${_apt_list_file}" || echo 0)
                _sec_upgradable=$(grep -c "security" "${_apt_list_file}" || echo 0)
                _apt_query_ok=true
            else
                _apt_status=$?
                if [[ "${_apt_status}" -eq 124 ]]; then
                    result_warn "apt 업데이트 조회가 90초 내 완료되지 않았습니다 — 수동 확인 필요"
                else
                    result_warn "apt 업데이트 조회 실패 — apt update 상태와 저장소 접근성을 수동 확인 필요"
                fi
                _upgradable=0
                _sec_upgradable=0
                unset _apt_status
            fi

            result_info "업그레이드 가능 전체: ${_upgradable}개"
            if ${_apt_query_ok} && [[ "${_sec_upgradable}" -eq 0 ]]; then
                result_safe "보안 관련 업데이트가 없습니다"
            elif ${_apt_query_ok}; then
                result_vuln "보안 업데이트 ${_sec_upgradable}개 미적용"
                result_info "적용 명령: sudo apt-get upgrade -y"
            fi
            unset _upgradable _sec_upgradable _apt_list_file _apt_query_ok

            # 마지막 업데이트 날짜
            _last_update=$(stat -c "%y" /var/cache/apt/pkgcache.bin 2>/dev/null | cut -d' ' -f1)
            result_info "마지막 apt 캐시 갱신: ${_last_update:-확인불가}"
            unset _last_update
        else
            result_warn "apt 패키지 매니저를 찾을 수 없습니다"
        fi
        ;;

    *)
        result_warn "알 수 없는 OS 계열 (${OS_FAMILY}) — 패치 관리 수동 확인 필요"
        ;;
esac

# 커널 버전과 실행 중인 커널 버전 비교 (재부팅 필요 여부)
result_info "현재 실행 중인 커널: $(uname -r)"
if command -v rpm &>/dev/null; then
    _installed_kernel=$(rpm -q kernel 2>/dev/null | sort -V | tail -1 | sed 's/kernel-//')
    result_info "최신 설치된 커널: ${_installed_kernel:-확인불가}"
    if [[ -n "${_installed_kernel:-}" && "$(uname -r)" != "${_installed_kernel}" ]]; then
        result_warn "실행 중인 커널이 최신 설치 커널과 다릅니다 — 재부팅 필요"
    fi
    unset _installed_kernel
fi
