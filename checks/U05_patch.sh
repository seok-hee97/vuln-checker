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
            _sec_count=$(${PKG_MGR} check-update --security --quiet 2>/dev/null | \
                grep -vc "^$\|^Last metadata" || true)

            if [[ "${_sec_count}" -eq 0 ]]; then
                result_safe "적용 가능한 보안 업데이트가 없습니다"
            else
                result_vuln "보안 업데이트 ${_sec_count}개 미적용 — 즉시 패치 적용 필요"
                result_info "적용 명령: sudo ${PKG_MGR} update --security -y"
            fi
            unset _sec_count

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
            result_info "패키지 목록 갱신 중..."

            apt-get update -qq 2>/dev/null || true

            _upgradable=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo 0)
            _sec_upgradable=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo 0)

            result_info "업그레이드 가능 전체: ${_upgradable}개"
            if [[ "${_sec_upgradable}" -eq 0 ]]; then
                result_safe "보안 관련 업데이트가 없습니다"
            else
                result_vuln "보안 업데이트 ${_sec_upgradable}개 미적용"
                result_info "적용 명령: sudo apt-get upgrade -y"
            fi
            unset _upgradable _sec_upgradable

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
