#!/bin/bash
# OS/배포판 탐지 모듈
# 모든 checks/ 모듈에서 아래 변수를 참조한다.
#
# 제공 변수:
#   OS_ID             — rhel, centos, rocky, ubuntu, debian ...
#   OS_VER            — 7, 8, 9, 20.04, 22.04 ...
#   OS_FAMILY         — rhel | debian | unknown
#   PKG_MGR           — dnf | yum | apt | unknown
#   SELINUX_SUPPORTED — true | false
#   SYSTEMD_AVAILABLE — true | false
#   PAM_AUTH_FILE     — /etc/pam.d/password-auth (rhel) | /etc/pam.d/common-auth (debian)
#   PAM_PASS_FILE     — /etc/pam.d/system-auth   (rhel) | /etc/pam.d/common-password (debian)

# shellcheck disable=SC2034
OS_ID=""
OS_VER=""
OS_FAMILY=""
PKG_MGR=""
SELINUX_SUPPORTED=false
SYSTEMD_AVAILABLE=false
PAM_AUTH_FILE=""
PAM_PASS_FILE=""

if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-0}"
fi

case "${OS_ID}" in
    rhel|centos|rocky|almalinux|fedora|ol)
        OS_FAMILY="rhel"
        SELINUX_SUPPORTED=true
        PAM_AUTH_FILE="/etc/pam.d/password-auth"
        PAM_PASS_FILE="/etc/pam.d/system-auth"
        if command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
        ;;
    ubuntu|debian|linuxmint|pop)
        OS_FAMILY="debian"
        SELINUX_SUPPORTED=false
        PKG_MGR="apt"
        PAM_AUTH_FILE="/etc/pam.d/common-auth"
        PAM_PASS_FILE="/etc/pam.d/common-password"
        ;;
    *)
        OS_FAMILY="unknown"
        PKG_MGR="unknown"
        PAM_AUTH_FILE="/etc/pam.d/password-auth"
        PAM_PASS_FILE="/etc/pam.d/system-auth"
        ;;
esac

if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
    SYSTEMD_AVAILABLE=true
fi
