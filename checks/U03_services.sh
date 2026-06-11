#!/bin/bash
# 서비스 관리 점검 모듈
# KISA U-19~U-34, U-58~U-65
section_header "서비스 관리 (U-19 ~ U-34, U-58 ~ U-65)"

# ── U-19: finger 서비스 비활성화 ───────────────────────────────────────────────
check_xinetd_svc "U-19" "finger" "finger 서비스"

# ── U-20: Anonymous FTP 비활성화 ───────────────────────────────────────────────
check_header "U-20" "Anonymous FTP 비활성화"
_ftp_conf=""
for _f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
    [[ -f "${_f}" ]] && { _ftp_conf="${_f}"; break; }
done

if [[ -n "${_ftp_conf}" ]]; then
    _anon=$(grep -E "^[[:space:]]*anonymous_enable[[:space:]]*=" "${_ftp_conf}" \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    if [[ -z "${_anon:-}" || "${_anon^^}" == "NO" ]]; then
        result_safe "FTP 익명 접속 비활성화 (anonymous_enable=${_anon:-NO})"
    else
        result_vuln "FTP 익명 접속 허용 (anonymous_enable=${_anon}) — NO 로 설정 필요"
    fi
    unset _anon
else
    # xinetd ftp 서비스도 확인
    if is_xinetd_disabled "ftp" && ! is_process_running "ftpd" && ! is_process_running "vsftpd"; then
        result_safe "FTP 서비스가 설치되어 있지 않습니다"
    else
        result_warn "FTP 서비스 실행 중 — vsftpd.conf 를 찾을 수 없습니다. 수동 확인 필요"
    fi
fi
unset _ftp_conf _f

# ── U-21: r 계열 서비스 (rsh, rlogin, rexec) 비활성화 ──────────────────────────
check_header "U-21" "r 계열 서비스 비활성화 (rsh, rlogin, rexec)"
_r_found=false
for _svc in rsh rlogin rexec rsh-server rlogin-server; do
    if ! is_xinetd_disabled "${_svc}" 2>/dev/null; then
        result_vuln "${_svc} — /etc/xinetd.d 에서 활성화되어 있습니다"
        _r_found=true
    fi
done
# systemd 서비스도 확인
for _svc in rsh.socket rlogin.socket rexec.socket; do
    if is_service_active "${_svc}" 2>/dev/null; then
        result_vuln "${_svc} 서비스가 실행 중입니다"
        _r_found=true
    fi
done
${_r_found} || result_safe "r 계열 서비스(rsh/rlogin/rexec)가 비활성화되어 있습니다"
unset _r_found _svc

# ── U-22: cron 파일 소유자·권한 ────────────────────────────────────────────────
check_header "U-22" "cron 파일 소유자·권한"
check_file_attr "/etc/cron.allow" "root" "600|640"
check_file_attr "/etc/cron.deny"  "root" "600|640"
check_file_attr "/var/spool/cron" "root" "700"

# cron.d, crontab 소유자·권한
for _f in /etc/crontab /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [[ -e "${_f}" ]] && check_file_attr "${_f}" "root" "700|600|644"
done
unset _f

# ── U-23: DoS 유발 서비스 비활성화 (echo, discard, daytime, chargen) ────────────
# check_xinetd_svc 내부에서 각 서비스별 check_header 를 생성하므로 외부 헤더 불필요
for _svc in echo discard daytime chargen; do
    check_xinetd_svc "U-23-${_svc}" "${_svc}" "DoS 유발 서비스(${_svc})"
done
unset _svc

# ── U-24: NFS 서비스 비활성화 ──────────────────────────────────────────────────
check_header "U-24" "NFS 서비스 비활성화"
_nfs_active=false
for _svc in nfs-server nfs nfs-kernel-server; do
    if is_service_active "${_svc}" 2>/dev/null; then
        _nfs_active=true
        break
    fi
done
is_process_running "rpc.nfsd" && _nfs_active=true

if ${_nfs_active}; then
    result_vuln "NFS 서비스가 실행 중입니다 — 불필요한 경우 중지 필요"
else
    result_safe "NFS 서비스가 실행되지 않고 있습니다"
fi
unset _nfs_active _svc

# ── U-25: NFS 접근 통제 ─────────────────────────────────────────────────────────
check_header "U-25" "NFS 접근 통제 설정 (/etc/exports)"
if [[ -f /etc/exports ]]; then
    # 모두 허용(*) 또는 insecure 옵션 확인
    _insecure=$(grep -v "^#" /etc/exports 2>/dev/null | grep -E "\*|insecure" || true)
    if [[ -n "${_insecure}" ]]; then
        result_vuln "NFS exports 에 모두 허용(*) 또는 insecure 옵션이 있습니다:"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_insecure}"
    else
        result_safe "/etc/exports — 모두 허용(*) 및 insecure 항목이 없습니다"
    fi
    unset _insecure _line
else
    result_pass "/etc/exports 파일이 없습니다 (NFS 미사용)"
fi

# ── U-26: automountd 비활성화 ──────────────────────────────────────────────────
check_header "U-26" "automountd 비활성화"
if is_service_active "autofs" 2>/dev/null || is_process_running "automount"; then
    result_vuln "autofs/automountd 서비스가 실행 중입니다"
else
    result_safe "autofs/automountd 서비스가 실행되지 않고 있습니다"
fi

# ── U-27: RPC 서비스 점검 ───────────────────────────────────────────────────────
check_header "U-27" "RPC 서비스 불필요한 항목 점검"
_rpc_risky=(rpc.ttdbserverd rpc.cmsd rpc.statd rpc.rquotad rpc.yppasswdd rpc.ypupdated)
_rpc_found=false
for _svc in "${_rpc_risky[@]}"; do
    if is_process_running "${_svc}"; then
        result_warn "${_svc} 프로세스가 실행 중입니다 — 필요성 확인 필요"
        _rpc_found=true
    fi
done
${_rpc_found} || result_safe "불필요한 RPC 서비스가 실행되지 않고 있습니다"
unset _rpc_risky _rpc_found _svc

# ── U-28: NIS/NIS+ 서비스 비활성화 ─────────────────────────────────────────────
check_header "U-28" "NIS/NIS+ 서비스 비활성화"
_nis_procs=$(ps aux 2>/dev/null | grep -v grep | grep -cE "ypserv|ypbind|ypxfrd|rpc.yppasswdd" || echo 0)
if [[ "${_nis_procs}" -gt 0 ]]; then
    result_vuln "NIS/NIS+ 서비스 실행 중 — 보안상 취약한 프로토콜, 비활성화 필요"
else
    result_safe "NIS/NIS+ 서비스가 실행되지 않고 있습니다"
fi
unset _nis_procs

# ── U-29: tftp/talk 서비스 비활성화 ────────────────────────────────────────────
check_xinetd_svc "U-29-tftp" "tftp"  "tftp 서비스"
check_xinetd_svc "U-29-talk" "talk"  "talk 서비스"
check_xinetd_svc "U-29-ntalk" "ntalk" "ntalk 서비스"

# ── U-30: Sendmail 버전 취약점 점검 ────────────────────────────────────────────
check_header "U-30" "Sendmail 버전 및 취약점 점검"
if command -v sendmail &>/dev/null; then
    _smver=$(sendmail -d0.1 -bv root 2>&1 | grep -i "version" | head -1 || true)
    result_info "Sendmail 버전: ${_smver:-확인불가}"
    result_warn "Sendmail 버전 정보를 수동으로 확인하고 최신 보안 패치 적용 필요"
elif is_service_active "postfix" 2>/dev/null; then
    result_info "Postfix 사용 중 (sendmail 대체)"
    _pver=$(postconf mail_version 2>/dev/null | awk '{print $3}' || true)
    result_info "Postfix 버전: ${_pver:-확인불가}"
else
    result_pass "메일 서버(sendmail/postfix)가 실행되지 않고 있습니다"
fi
unset _smver _pver

# ── U-31: SMTP 스팸 릴레이 제한 ────────────────────────────────────────────────
check_header "U-31" "SMTP 스팸 릴레이 제한"
if [[ -f /etc/postfix/main.cf ]]; then
    _relay=$(grep -E "^[[:space:]]*smtpd_recipient_restrictions" /etc/postfix/main.cf \
        | head -1 || true)
    if [[ -n "${_relay}" ]]; then
        result_safe "Postfix smtpd_recipient_restrictions 설정 있음"
        result_info "${_relay}"
    else
        result_warn "smtpd_recipient_restrictions 미설정 — 열린 릴레이 위험 수동 확인 필요"
    fi
    unset _relay
elif [[ -f /etc/mail/sendmail.cf ]]; then
    if grep -q "FR-o /etc/mail/relay-domains" /etc/mail/sendmail.cf 2>/dev/null; then
        result_safe "sendmail 릴레이 도메인 파일 설정 있음"
    else
        result_warn "sendmail.cf 릴레이 제한 설정 수동 확인 필요"
    fi
else
    result_pass "메일 서버가 설치되어 있지 않습니다"
fi

# ── U-45: 일반사용자의 Sendmail 실행 방지 (PrivacyOptions) ─────────────────────
check_header "U-45" "일반사용자의 Sendmail 실행 방지 (PrivacyOptions)"
if [[ -f /etc/mail/sendmail.cf ]]; then
    _privacy=$(grep -i "^O PrivacyOptions\|^OPriv" /etc/mail/sendmail.cf 2>/dev/null \
        | grep -v "^#" | tail -1 || true)
    result_info "sendmail.cf PrivacyOptions: ${_privacy:-미설정}"

    # 필수 옵션 4개 확인
    _missing_opts=()
    for _opt in authwarnings novrfy noexpn restrictqrun; do
        if ! echo "${_privacy:-}" | grep -qi "${_opt}"; then
            _missing_opts+=("${_opt}")
        fi
    done

    if [[ "${#_missing_opts[@]}" -eq 0 ]]; then
        result_safe "PrivacyOptions에 필수 항목(authwarnings, novrfy, noexpn, restrictqrun) 모두 설정됨"
    else
        result_vuln "PrivacyOptions 미비 — 누락 항목: ${_missing_opts[*]} (일반사용자 sendmail 실행 허용 위험)"
    fi
    unset _privacy _opt _missing_opts
elif command -v postfix &>/dev/null || is_service_active "postfix" 2>/dev/null; then
    # Postfix는 기본적으로 일반사용자 직접 실행을 제한하지 않으므로 대안 확인
    _smtpd_uid=$(postconf -h mail_owner 2>/dev/null || echo "postfix")
    result_info "Postfix 사용 중 — mail_owner: ${_smtpd_uid}"
    result_safe "Postfix는 sendmail.cf PrivacyOptions와 다른 방식으로 권한 제어"
    # submission 포트에서 AUTH 필수 여부 확인
    if grep -qE "^submission.*smtpd_sasl_auth_enable" /etc/postfix/master.cf 2>/dev/null; then
        result_safe "Postfix submission 포트 SASL 인증 필수 설정됨"
    else
        result_warn "Postfix submission 포트 SASL 인증 설정 수동 확인 권장"
    fi
    unset _smtpd_uid
else
    result_pass "sendmail/postfix 서비스가 설치되어 있지 않습니다"
fi

# ── U-32: DNS 버전 점검 ─────────────────────────────────────────────────────────
check_header "U-32" "DNS 서비스 버전 및 취약점 점검"
if is_service_active "named" 2>/dev/null || is_process_running "named"; then
    _dver=$(named -v 2>&1 | head -1 || true)
    result_info "BIND 버전: ${_dver:-확인불가}"
    result_warn "BIND 버전을 수동으로 확인하고 최신 보안 패치 적용 필요"
    # 버전 은닉 여부
    if grep -rq "version.*\"none\"" /etc/named.conf /etc/named/ 2>/dev/null; then
        result_safe "BIND 버전 은닉 설정이 되어 있습니다"
    else
        result_warn "BIND 버전 은닉 미설정 (named.conf: version \"none\" 권장)"
    fi
    unset _dver
else
    result_pass "DNS 서비스(named)가 실행되지 않고 있습니다"
fi

# ── U-33: DNS zone transfer 제한 ───────────────────────────────────────────────
check_header "U-33" "DNS zone transfer 제한"
if is_service_active "named" 2>/dev/null || is_process_running "named"; then
    _named_conf=""
    for _f in /etc/named.conf /etc/bind/named.conf; do
        [[ -f "${_f}" ]] && { _named_conf="${_f}"; break; }
    done
    if [[ -n "${_named_conf}" ]]; then
        if grep -qE "allow-transfer[[:space:]]*\{" "${_named_conf}" 2>/dev/null; then
            result_safe "DNS zone transfer 제한 설정이 있습니다 (allow-transfer)"
        else
            result_vuln "DNS zone transfer 제한 미설정 — allow-transfer 설정 필요"
        fi
    else
        result_warn "named.conf 파일을 찾을 수 없습니다 — 수동 확인 필요"
    fi
    unset _named_conf _f
else
    result_pass "DNS 서비스가 실행되지 않고 있습니다"
fi

# ── U-34: 웹 서비스 불필요한 파일 제거 ─────────────────────────────────────────
check_header "U-34" "웹 서비스 설치 매뉴얼·기본 파일 제거"
_httpd_root=""
for _f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
    [[ -f "${_f}" ]] && { _httpd_root="${_f}"; break; }
done
if [[ -n "${_httpd_root}" ]]; then
    _docroot=$(grep -E "^[[:space:]]*DocumentRoot" "${_httpd_root}" 2>/dev/null \
        | awk '{print $2}' | tr -d '"' | tail -1)
    result_info "DocumentRoot: ${_docroot:-확인불가}"
    # 기본 설치 파일 확인
    for _test in "${_docroot:-/var/www/html}/index.html" \
                 "${_docroot:-/var/www/html}/index.php" \
                 "/var/www/html/manual"; do
        if [[ -e "${_test}" ]]; then
            result_warn "기본 설치 파일/디렉터리 존재: ${_test} — 제거 검토 필요"
        fi
    done
    result_warn "웹 매뉴얼 파일 및 기본 샘플 파일 수동 확인 권장"
    unset _docroot _test
else
    result_pass "Apache 웹 서비스가 설치되어 있지 않습니다"
fi
unset _httpd_root _f

# ── U-58: SSH 프로토콜 버전 점검 ────────────────────────────────────────────────
check_header "U-58" "SSH 프로토콜 버전 점검 (SSHv1 비활성화)"
if command -v sshd &>/dev/null; then
    _sshver=$(ssh -V 2>&1 | awk '{print $1}' || true)
    result_info "SSH 버전: ${_sshver:-확인불가}"
    _proto=$(sshd_config_val "Protocol")
    if [[ -z "${_proto:-}" || "${_proto}" == "2" ]]; then
        result_safe "SSH Protocol 2 사용 (SSHv1 비활성화)"
    else
        result_vuln "SSH Protocol ${_proto} 설정 — Protocol 2 전용으로 설정 필요"
    fi
    unset _sshver _proto
else
    result_pass "SSH 서버가 설치되어 있지 않습니다"
fi

# ── U-59: FTP 보안 설정 ─────────────────────────────────────────────────────────
check_header "U-59" "FTP 보안 설정 (vsftpd)"
_ftp_conf=""
for _f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
    [[ -f "${_f}" ]] && { _ftp_conf="${_f}"; break; }
done

if [[ -n "${_ftp_conf}" ]]; then
    # chroot 설정 확인
    _chroot=$(grep -E "^[[:space:]]*chroot_local_user[[:space:]]*=" "${_ftp_conf}" \
        | awk -F= '{print $2}' | tr -d ' ' | tail -1)
    if [[ "${_chroot^^}" == "YES" ]]; then
        result_safe "FTP chroot_local_user = YES (사용자 홈 디렉터리 감금)"
    else
        result_warn "FTP chroot_local_user = ${_chroot:-NO} — YES 설정 권장"
    fi
    # 배너 은닉
    _banner=$(grep -E "^[[:space:]]*ftpd_banner[[:space:]]*=" "${_ftp_conf}" | head -1 || true)
    if [[ -n "${_banner}" ]]; then
        result_safe "FTP 서비스 배너 설정 있음"
    else
        result_warn "FTP ftpd_banner 미설정 — 버전 정보 노출 주의"
    fi
    unset _chroot _banner
else
    result_pass "FTP 서버(vsftpd)가 설치되어 있지 않습니다"
fi
unset _ftp_conf _f

# ── U-60: ftpusers 파일 소유자·권한 ────────────────────────────────────────────
check_header "U-60" "ftpusers 파일 소유자·권한"
_found_ftp=false
for _f in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
    if [[ -f "${_f}" ]]; then
        check_file_attr "${_f}" "root" "640|600"
        _found_ftp=true
    fi
done
${_found_ftp} || result_pass "ftpusers 파일이 없습니다 (FTP 미사용)"
unset _found_ftp _f

# ── U-61: at 파일 소유자·권한 ──────────────────────────────────────────────────
check_header "U-61" "at 파일 소유자·권한 (/etc/at.allow, /etc/at.deny)"
check_file_attr "/etc/at.allow" "root" "600|640"
check_file_attr "/etc/at.deny"  "root" "600|640"

# ── U-62: SNMP community string 점검 ───────────────────────────────────────────
check_header "U-62" "SNMP community string 기본값 점검"
if [[ -f /etc/snmp/snmpd.conf ]]; then
    _default_comm=$(grep -E "^[[:space:]]*(com2sec|community)[[:space:]]" /etc/snmp/snmpd.conf \
        2>/dev/null | grep -iE "public|private" | grep -v "^#" || true)
    if [[ -n "${_default_comm}" ]]; then
        result_vuln "SNMP 기본 community string(public/private) 사용 중 — 즉시 변경 필요"
        while IFS= read -r _line; do
            result_info "  ${_line}"
        done <<< "${_default_comm}"
    else
        result_safe "SNMP 기본 community string(public/private)이 발견되지 않았습니다"
    fi
    unset _default_comm _line
else
    result_pass "SNMP 서비스가 설치되어 있지 않습니다 (/etc/snmp/snmpd.conf 없음)"
fi

# ── U-63: 로그온 배너 설정 ─────────────────────────────────────────────────────
check_header "U-63" "로그온 배너 설정"
for _f in /etc/issue.net /etc/motd; do
    if [[ -s "${_f}" ]]; then
        result_safe "${_f} — 배너가 설정되어 있습니다"
    else
        result_warn "${_f} — 배너가 설정되어 있지 않습니다 (경고 문구 설정 권장)"
    fi
done
unset _f

# ── U-64: NFS 서비스 비활성화 (서비스 관리 중복 항목, 재확인) ───────────────────
check_header "U-64" "NFS 서비스 비활성화 (재점검)"
_nfs2=false
for _svc in nfs-server nfs nfs-kernel-server; do
    if is_service_active "${_svc}" 2>/dev/null; then
        _nfs2=true; break
    fi
done
if ${_nfs2}; then
    result_vuln "NFS 서비스가 활성화되어 있습니다"
else
    result_safe "NFS 서비스가 비활성화되어 있습니다"
fi
unset _nfs2 _svc

# ── U-65: Autofs 비활성화 (재확인) ─────────────────────────────────────────────
check_header "U-65" "Autofs 비활성화 (재점검)"
if is_service_active "autofs" 2>/dev/null; then
    result_vuln "autofs 서비스가 활성화되어 있습니다"
else
    result_safe "autofs 서비스가 비활성화되어 있습니다"
fi
