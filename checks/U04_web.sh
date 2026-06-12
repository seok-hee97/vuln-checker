#!/bin/bash
# 웹 서비스 점검 모듈
# KISA U-35~U-41 (Apache httpd 기반)
section_header "웹 서비스 (U-35 ~ U-41)"

# Apache 설정 파일 경로 탐지
_httpd_conf=""
_httpd_confdir=""
for _f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf; do
    if [[ -f "${_f}" ]]; then
        _httpd_conf="${_f}"
        _httpd_confdir="$(dirname "${_f}")"
        break
    fi
done

if [[ -z "${_httpd_conf}" ]]; then
    result_pass "Apache 웹 서버가 설치되어 있지 않습니다 (U-35~U-41 건너뜀)"
    unset _httpd_conf _httpd_confdir _f
    return
fi

result_info "Apache 설정 파일: ${_httpd_conf}"

# 모든 설정 파일 (VirtualHost 포함) 수집
_all_confs=("${_httpd_conf}")
_server_root=$(grep -hE "^[[:space:]]*ServerRoot[[:space:]]" "${_httpd_conf}" 2>/dev/null \
    | awk '{print $2}' | tr -d '"' | tail -1)
_server_root="${_server_root:-${_httpd_confdir}}"

_add_apache_conf() {
    local _candidate="$1"
    [[ -f "${_candidate}" ]] || return 0
    local _existing
    for _existing in "${_all_confs[@]}"; do
        [[ "${_existing}" == "${_candidate}" ]] && return 0
    done
    _all_confs+=("${_candidate}")
}

while IFS= read -r _inc; do
    # glob 처리
    _inc=$(echo "${_inc}" | sed -E 's/Include(Optional)?[[:space:]]*//' | tr -d '"')
    [[ "${_inc}" != /* ]] && _inc="${_server_root}/${_inc}"
    for _g in ${_inc}; do
        _add_apache_conf "${_g}"
    done
done < <(grep -ihE "^[[:space:]]*(IncludeOptional|Include)[[:space:]]" "${_httpd_conf}" 2>/dev/null || true)
unset _inc _g _f _server_root

# ── U-35: 디렉터리 리스팅 비활성화 ─────────────────────────────────────────────
check_header "U-35" "디렉터리 리스팅 비활성화 (Options -Indexes)"
_listing_vuln=false
for _cf in "${_all_confs[@]}"; do
    if grep -qiE "Options.*[[:space:]]Indexes" "${_cf}" 2>/dev/null; then
        result_vuln "디렉터리 리스팅 활성화: ${_cf} — Options 에서 Indexes 제거 필요"
        _listing_vuln=true
    fi
done
${_listing_vuln} || result_safe "모든 설정 파일에서 Indexes 옵션이 발견되지 않았습니다"
unset _listing_vuln _cf

# ── U-36: 웹 프로세스 권한 제한 (root 실행 금지) ────────────────────────────────
check_header "U-36" "웹 서비스 프로세스 권한 제한 (root 실행 금지)"
_apache_user=$(grep -hE "^[[:space:]]*User[[:space:]]" "${_httpd_conf}" \
    | awk '{print $2}' | tail -1)
_apache_group=$(grep -hE "^[[:space:]]*Group[[:space:]]" "${_httpd_conf}" \
    | awk '{print $2}' | tail -1)
result_info "Apache User  : ${_apache_user:-미설정}"
result_info "Apache Group : ${_apache_group:-미설정}"
if [[ "${_apache_user:-}" == "root" ]]; then
    result_vuln "Apache가 root 계정으로 실행되도록 설정되어 있습니다 — 전용 계정(apache/www-data) 사용 필요"
else
    result_safe "Apache 실행 계정: ${_apache_user:-미설정 (기본값 적용)} (root 아님)"
fi
unset _apache_user _apache_group

# ── U-37: 상위 디렉터리 접근 제한 ──────────────────────────────────────────────
check_header "U-37" "상위 디렉터리 접근 제한 (Options -FollowSymLinks / AllowOverride)"
_symlink_vuln=false
for _cf in "${_all_confs[@]}"; do
    if grep -qiE "Options.*[[:space:]]FollowSymLinks" "${_cf}" 2>/dev/null; then
        result_warn "FollowSymLinks 설정: ${_cf} — 심볼릭 링크를 통한 상위 디렉터리 접근 가능"
        _symlink_vuln=true
    fi
done
${_symlink_vuln} || result_safe "모든 설정에서 FollowSymLinks 미발견"
unset _symlink_vuln _cf

# AllowOverride None 확인 (루트 디렉터리)
if grep -qiE "AllowOverride[[:space:]]+All" "${_httpd_conf}" 2>/dev/null; then
    result_warn "AllowOverride All 설정 — .htaccess 를 통한 보안 우회 가능. None 또는 제한 권장"
else
    result_safe "루트 설정에 AllowOverride All 이 없습니다"
fi

# ── U-38: 불필요한 파일 제거 (U-34 확장) ───────────────────────────────────────
check_header "U-38" "불필요한 파일 제거 (CGI, 매뉴얼, 샘플)"
_docroot=$(grep -hE "^[[:space:]]*DocumentRoot" "${_httpd_conf}" \
    | awk '{print $2}' | tr -d '"' | tail -1)
result_info "DocumentRoot: ${_docroot:-미설정}"

# 위험한 CGI 파일 확인
if [[ -n "${_docroot:-}" ]]; then
    _cgi_list=""
    _cgi_list=$(find "${_docroot}" /usr/lib/cgi-bin /var/www/cgi-bin \
        -name "*.cgi" 2>/dev/null | head -20 || true)
    if [[ -n "${_cgi_list}" ]]; then
        result_warn "CGI 파일 발견 — 불필요한 경우 제거 검토:"
        while IFS= read -r _cgi; do
            result_info "  ${_cgi}"
        done <<< "${_cgi_list}"
    else
        result_safe "DocumentRoot 에서 CGI 파일이 발견되지 않았습니다"
    fi
    unset _cgi_list _cgi
fi
unset _docroot

# ── U-39: 링크 파일 사용 제한 ──────────────────────────────────────────────────
check_header "U-39" "웹 DocumentRoot 내 심볼릭 링크 점검"
_docroot=$(grep -hE "^[[:space:]]*DocumentRoot" "${_httpd_conf}" \
    | awk '{print $2}' | tr -d '"' | tail -1)
if [[ -n "${_docroot:-}" && -d "${_docroot}" ]]; then
    _link_cnt=$(find "${_docroot}" -type l 2>/dev/null | wc -l || echo 0)
    if [[ "${_link_cnt}" -eq 0 ]]; then
        result_safe "DocumentRoot 내 심볼릭 링크가 없습니다"
    else
        result_warn "DocumentRoot 내 심볼릭 링크 ${_link_cnt}개 — 외부 디렉터리 접근 가능성 수동 확인 필요"
    fi
    unset _link_cnt
else
    result_pass "DocumentRoot를 확인할 수 없습니다"
fi
unset _docroot

# ── U-40: 파일 업로드/다운로드 제한 ────────────────────────────────────────────
check_header "U-40" "파일 업로드/다운로드 제한 (LimitRequestBody)"
_limit=$(grep -hiE "^[[:space:]]*LimitRequestBody" "${_httpd_conf}" \
    | awk '{print $2}' | tail -1)
if [[ -n "${_limit:-}" && "${_limit}" -le 10485760 ]]; then
    result_safe "LimitRequestBody = ${_limit} bytes (10MB 이하)"
else
    result_warn "LimitRequestBody = ${_limit:-미설정} — 업로드 크기 제한 설정 권장 (예: 10485760 = 10MB)"
fi
unset _limit

# ── U-41: 웹 서비스 정보 노출 방지 ─────────────────────────────────────────────
check_header "U-41" "웹 서비스 버전 정보 노출 방지 (ServerTokens, ServerSignature)"
_tokens=$(grep -hiE "^[[:space:]]*ServerTokens" "${_all_confs[@]}" \
    | awk '{print $2}' | tail -1)
_signature=$(grep -hiE "^[[:space:]]*ServerSignature" "${_all_confs[@]}" \
    | awk '{print $2}' | tail -1)

result_info "ServerTokens  : ${_tokens:-미설정 (기본값: Full)}"
result_info "ServerSignature: ${_signature:-미설정 (기본값: On)}"

if [[ "${_tokens:-}" == "Prod" || "${_tokens:-}" == "ProductOnly" ]]; then
    result_safe "ServerTokens = ${_tokens} — 제품명만 노출"
else
    result_vuln "ServerTokens = ${_tokens:-Full(기본)} — Prod 로 설정 필요 (버전 정보 노출 차단)"
fi

if [[ "${_signature:-}" == "Off" ]]; then
    result_safe "ServerSignature = Off — 응답 페이지에 버전 정보 미포함"
else
    result_vuln "ServerSignature = ${_signature:-On(기본)} — Off 로 설정 필요"
fi

unset -f _add_apache_conf
unset _tokens _signature _all_confs _httpd_conf _httpd_confdir
