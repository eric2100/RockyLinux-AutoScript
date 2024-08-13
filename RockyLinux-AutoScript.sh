#!/bin/bash
echo "Checking for Bash version...."
echo "The Bash version is $BASH_VERSION !"
echo "Checking user ...."
if (( EUID != 0 )); then
    printf '%s\n' \
    "You must run this script as root.  Either use sudo or 'su -c ${0}'" >&2
    exit 1
fi

#bash version >= 4.2
if (( BASH_VERSINFO[0]*100 + BASH_VERSINFO[1] < 402 )); then
    printf '%s\n' "bash >= 4.2 is required for this script." >&2
    exit 1
fi

echo "Checking network connect...."
death=`ping 168.95.1.1 -c 5 | grep "packet loss" | awk '{print $4}'`
if (($death==0))
then {
        echo "This is Program Require Network."
        exit 1
    }
fi

# User VARIABLES
ADD_USERNAME="eric"                 # 要自動新增的使用者(具有root權限)
ADD_USERPASS="123456"               # 自動新增的使用者密碼
HOSTNAME="www"                      # 主機名稱
DOMAINNAME="test.com.tw"
DB_USER="root"                      # 資料庫帳號
DB_PASSWD="3939889"                 # 資料庫密碼
DB_PORT="33306"                     # 資料庫密碼
SSH_PORT="319"                      # SSH 服務的 PORT 位
sEXTIF="ens3"                       # 這個是可以連上 Public IP 的網路介面
sINIF="enp48s0f0"                   # 內部 LAN 的連接介面；若無則寫成 INIF=""
sINNET="192.168.20.0/24"            # 若無內部網域介面，請填寫成      INNET=""，若有格式為 192.168.20.0/24
EXTNET="1.2.3.4"                    # 外部IP位址
INSTALL_POSTFIX="YES"               # 若不安裝請填寫成          INSTALL_POSTFIX=""
INSTALL_DOVECOT="YES"               # 若不安裝請填寫成          INSTALL_DOVECOT=""
INSTALL_IPTABLES="YES"
INSTALL_PHP="8.3"                   # 8.0 8.1 8.2 8.3 不安裝的話 INSTALL_PHP=""
INSTALL_APACHE="NO"                 # 要裝apache 設定 YES
INSTALL_NGINX="YES" 		            # 要裝 NGINX 設定 YES
FREETDS_IP=""                       # MSSQL 的ip位址
PYTHON_VER="3.12"
IP_NAT_PRINT="211.22.129.238"

custom_settings(){
    # Custom Script 客製化想要新增的規則
    chmod +x /etc/rc.d/rc.local
cat >> /etc/rc.local <<EOT
# Add route table and EEP socker services.
# route add -net 192.168.0.0 netmask 255.255.0.0 gw 192.168.20.254
# socat TCP-LISTEN:4444,fork TCP:192.168.1.3:211 &
EOT

    echo 'vsftpd: ALL' >> /etc/hosts.deny
    echo 'vsftpd:192.168.* 127.0.0.1' >> /etc/hosts.allow

    echo 'sshd:All' >> /etc/hosts.deny
    echo "sshd:192.168.* 127.0.0.1 $EXTNET:Allow" >> /etc/hosts.allow

}
# ================================================================
# System VARIABLES
# ================================================================
# 同步系統時間避免 SSL


github_conf_url="https://raw.githubusercontent.com/eric2100/RockyLinux-AutoScript/master"
OS=`uname -p`;
MYIP=`curl -s ifconfig.me`;
WORK_FOLED=`pwd`
SCRIPT_FILE_NAME=`basename ${BASH_SOURCE[0]}`
SCRIPT_VERSION="0.3.0"
SYSTEM_VER=`rpm -qi --whatprovides /etc/redhat-release | awk '/Version/ {print $3}'`
#SYSTEM_VER=`rpm -qi --whatprovides /etc/redhat-release | awk '/Version/ {print $3}' | awk 'BEGIN {FS="."}{print $1};'`
filename="${WORK_FOLED}/rockylinuxscript."$(date +"%Y-%m-%d")""
logfile="${filename}.log"


# 這幾行從 https://github.com/rocky-linux/rocky-tools 借來的
# Output to 1 goes to stdout and the logfile.
# Output to 2 goes to stderr and the logfile.
# Output to 3 just goes to stdout.
# Output to 4 just goes to stderr.
# Output to 5 just goes to the logfile.

exec \
3>&1 \
4>&2 \
5>> "$logfile" \
> >(tee -a "$logfile") \
2> >(tee -a "$logfile" >&2)

# List nocolor last here so that -x doesn't bork the display.
errcolor=$(tput setaf 1)
infocolor=$(tput setaf 6)
nocolor=$(tput op)

# Single arg just gets returned verbatim, multi arg gets formatted via printf.
# First arg is the name of a variable to store the results.
msg_format () {
    local _var
    _var="$1"
    shift
    if (( $# > 1 )); then
        printf -v "$_var" "$@"
    else
        printf -v "$_var" "%s" "$1"
    fi
}

# Send an info message to the log file and stdout (with color)
infomsg () {
    _sdate=$(date +"%Y-%m-%d %H:%M:%S")
    local msg
    msg_format msg "$@"
    printf '%s' "[${_sdate}] $msg" >&5
    printf '%s%s%s' "$infocolor" "[${_sdate}] $msg" "$nocolor" >&3
}

# Send an error message to the log file and stderr (with color)
errmsg () {
    _sdate=$(date +"%Y-%m-%d %H:%M:%S")
    local msg
    msg_format msg "$@"
    printf '%s' "[${_sdate}] $msg" >&5
    printf '%s%s%s' "$errcolor" "[${_sdate}] $msg" "$nocolor" >&4
}

install_postfix(){
    if [[ $INSTALL_POSTFIX == "" ]]; then
        return 0
    fi
    infomsg '%s\n' $"安裝 postifx"
    dnf -y install postfix
    infomsg '%s\n' $"備份 postifx設定"
    cp -rf /etc/postfix/main.cf /etc/postfix/main.cf.`date +"%Y-%m-%d"`

sh -c "cat > /etc/postfix/main.cf" <<EOF
# 使用 hostname 設定，例如 test.com.tw
myhostname = $HOSTNAME
# 使用domainname 設定，例如 test.com.tw
mydomain = $DOMAINNAME
#myorigin = $mydomain
# add follows to the end
# for example, limit an email size for 10M
message_size_limit = 10485760
# for example, limit a mailbox for 30G
mailbox_size_limit = 3221225472

# SMTP-Auth settings
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
smtpd_recipient_restrictions = permit_mynetworks, permit_auth_destination, permit_sasl_authenticated, reject

alias_database = hash:/etc/aliases
home_mailbox = Maildir/
smtpd_banner = $myhostname ESMTP $mail_name
compatibility_level = 2
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix
inet_interfaces = all
inet_protocols = all
mydestination = $myhostname, localhost.$mydomain, localhost,mail.$mydomain
unknown_local_recipient_reject_code = 550
mynetworks = 168.100.189.0/28, 127.0.0.0/8, 192.168.0.0/16
relay_domains = $mydestination
alias_maps = hash:/etc/aliases
debug_peer_level = 2
debugger_command =
	 PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
	 ddd $daemon_directory/$process_name $process_id & sleep 5
sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
setgid_group = postdrop
html_directory = no
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix/samples
readme_directory = /usr/share/doc/postfix/README_FILES
smtpd_tls_cert_file = /etc/pki/tls/certs/postfix.pem
smtpd_tls_key_file = /etc/pki/tls/private/postfix.key
smtpd_tls_security_level = may
smtp_tls_CApath = /etc/pki/tls/certs
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt
smtp_tls_security_level = may
meta_directory = /etc/postfix
shlib_directory = /usr/lib64/postfix
EOF

    systemctl restart postfix >>/dev/null 2>&1
    systemctl enable --now postfix >/dev/null 2>&1

    postconf -n
}

install_dovecot(){
    if [[ $INSTALL_DOVECOT == "" ]]; then
        return 0
    fi
    dnf -y install dovecot
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#listen = \*, \:\:/listen = \*, \:\:/g' /etc/dovecot/dovecot.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#disable_plaintext_auth = yes/disable_plaintext_auth = no/g' /etc/dovecot/conf.d/10-auth.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#mail_location =/mail_location = maildir:~\/Maildir/g' /etc/dovecot/conf.d/10-mail.conf

    sed -i.$(date '+%Y%m%d%H%M%S') '/# Postfix smtp-auth/a\  unix_listener /var/spool/postfix/private/auth {\n    mode = 0666\n    user = postfix\n    group = postfix\n  }' /etc/dovecot/conf.d/10-master.conf

    sed -i.$(date '+%Y%m%d%H%M%S') 's/ssl = required/ssl = yes/g' /etc/dovecot/conf.d/10-ssl.conf
    systemctl enable --now dovecot
    systemctl restart dovecot.service
}

init() {
    infomsg $'chronyc Package 安裝中 ...........\n'

    if [ -f /usr/sbin/chronyd ]; then
        infomsg $'chronyc Package 已經安裝 ...........\n'
    else
        dnf -y install chrony >&5
    fi

    if [ -f "/etc/chrony.conf" ]; then
        infomsg $'寫入 /etc/chrony.conf ...........\n'
        sed -i.$(date '+%Y%m%d%H%M%S') '1a server tock.stdtime.gov.tw' /etc/chrony.conf
        sed -i.$(date '+%Y%m%d%H%M%S') '2a server watch.stdtime.gov.tw' /etc/chrony.conf
        sed -i.$(date '+%Y%m%d%H%M%S') '3a server time.stdtime.gov.tw' /etc/chrony.conf
        sed -i.$(date '+%Y%m%d%H%M%S') '4a server clock.stdtime.gov.tw' /etc/chrony.conf
        sed -i.$(date '+%Y%m%d%H%M%S') '5a server tick.stdtime.gov.tw' /etc/chrony.conf
    fi
    infomsg $'啟動chronyd並設定每次開機啟動 ...........\n'
    systemctl enable --now chronyd >&5
    systemctl restart chronyd >&5
    chronyc -a makestep >&5
    chronyc -a makestep >&5
    chronyc -a makestep >&5

    sleep 3
    infomsg $'設定系統語言\n'
    dnf -y install glibc-langpack-zh langpacks-zh_TW >&5
    localectl set-locale LANG=zh_TW.UTF-8 >&5
    export PS1="\e[1;34m\u@\h \w> \e[m" >&5
    infomsg $'建立臨時工作目錄\n'
    mkdir -vp ${WORK_FOLED}/tmp >&2

    id -u $ADD_USERNAME &>/dev/null || useradd $ADD_USERNAME -g wheel
    echo $ADD_USERNAME:$ADD_USERPASS | chpasswd
    infomsg $'限制只有 wheel 群組的使用者才能切換root\n'
    sed -i.$(date '+%Y%m%d%H%M%S') "7s:#auth:auth:g" /etc/pam.d/su
    echo "SU_WHEEL_ONLY yes" >> /etc/login.defs

    hostnamectl set-hostname $HOSTNAME
    domainname $DOMAINNAME

    infomsg '%s\n' $"自動釋放記憶體"
    echo 3 > /proc/sys/vm/drop_caches

    infomsg $'設定時區\n'
    timedatectl set-timezone Asia/Taipei

    echo 'max_parallel_downloads=10' >> /etc/dnf/dnf.conf
    echo 'fastestmirror=True' >> /etc/dnf/dnf.conf

    infomsg $'系統更新\n'
    dnf -y update
    dnf -y upgrade
    dnf -y install dnf-automatic
    dnf -y install epel-release
    dnf -y install elrepo-release
    dnf -y --skip-broken install https://rpms.remirepo.net/enterprise/remi-release-${SYSTEM_VER}.rpm

    sed -i.$(date '+%Y%m%d%H%M%S') 's/upgrade_type = default/upgrade_type = security/g' /etc/dnf/automatic.conf >&5
    sed -i.$(date '+%Y%m%d%H%M%S') 's/# system_name = my-host/system_name = ${HOSTNAME}/g' /etc/dnf/automatic.conf >&5
    sed -i.$(date '+%Y%m%d%H%M%S') 's/emit_via = stdio/emit_via = motd/g' /etc/dnf/automatic.conf >&5

    systemctl enable --now dnf-automatic.timer >&5
    return 1
}
basesoftware(){
    # ================================================================
    # isntall base software and tools
    # ================================================================
    # 修改預設python版本
    #alternatives --config python${PYTHON_VER}

    infomsg $'安裝常用軟體與工具程式\n'
    dnf -y groupinstall 'Development Tools'
    dnf -y install cmake

    dnf -y install make cmake htop net-tools wget unzip vim-enhanced p7zip p7zip-plugins screen telnet git gcc ftp socat curl golang traceroute device-mapper-persistent-data lvm2 augeas-libs rsyslog rrdtool iftop nmap bc nethogs ngrep mtr rkhunter net-snmp net-snmp-utils expect bind-utils >&5

    infomsg $'Python 環境設定中 ...........\n'
    dnf -y install python$PYTHON_VER python$PYTHON_VER-pip

cat >> /etc/bashrc <<EOT
alias python=/usr/bin/python$PYTHON_VER
alias python3=/usr/bin/python$PYTHON_VER
EOT

    source ~/.bashrc

    infomsg $'安裝防毒軟體clamav  ...........\n'
    dnf -y --enablerepo=epel install clamav clamav-update >&5
}

install_kernel () {
    # ================================================================
    # kernel update
    # ================================================================

    infomsg $'Install Kernel Software \n'
    dnf -y --enablerepo=elrepo-kernel install kernel-ml >/dev/null 2>&1

    infomsg $'優化SSH設定 \n'
    sed -i.$(date '+%Y%m%d%H%M%S') 's/^GSSAPIAuthentication yes$/GSSAPIAuthentication no/' /etc/ssh/sshd_config
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config

    sed -i.$(date '+%Y%m%d%H%M%S') 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#ClientAliveCountMax 3/ClientAliveCountMax 120/' /etc/ssh/sshd_config

    sed -i.$(date '+%Y%m%d%H%M%S') 's/#Port 22/Port '$SSH_PORT'/' /etc/ssh/sshd_config
    systemctl restart sshd >/dev/null 2>&1
    echo "unset MAILCHECK" >> /etc/profile

    infomsg $'Disable selinux \n'
    systemctl stop firewalld.service
    systemctl disable firewalld.service
    #systemctl disable ip6tables.service
    #systemctl disable messagebus.service
    sed -i.$(date '+%Y%m%d%H%M%S') 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
    sed -i.$(date '+%Y%m%d%H%M%S') 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
}

install_iptables() {
    if [[ $INSTALL_IPTABLES != "YES" ]]
    then
        return 0
    fi
    infomsg $'開始安裝 iptable 防火牆... '
    infomsg $'設定外部 GETWAY\n'
    sed -i "1a NETWORKING=yes"  /etc/sysconfig/network
    sed -i "2a #NETWORKING_IPV6=no"  /etc/sysconfig/network
    sed -i "3a GATEWAY=\"$sINNET\""  /etc/sysconfig/network

    infomsg $'install_iptables Package installed.\n'
    dnf -y install iptables-services >/dev/null 2>&1

    mkdir -p /usr/local/virus >/dev/null 2>&1
    mkdir -p /usr/local/virus/iptables >/dev/null 2>&1

    infomsg $'設定 spamhaus 機構的黑名單... \n'
    mkdir -p /usr/local/virus/iptables/
    wget -O /usr/local/virus/iptables/set_iptables_drop_lasso $github_conf_url/conf/set_iptables_drop_lasso
    infomsg $'設定 iptable 白名單 \n'
    wget -O /usr/local/virus/iptables/iptables.allow $github_conf_url/conf/iptables.allow
    infomsg $'設定 iptable 黑名單 \n'
    wget -O /usr/local/virus/iptables/iptables.deny $github_conf_url/conf/iptables.deny

    infomsg $'設定 iptable 鳥哥的防火牆規則 \n'
    wget -O /usr/local/virus/iptables/iptables.rule $github_conf_url/conf/iptables.rule
    sed -i "1a EXTIF=\"$sEXTIF\""  /usr/local/virus/iptables/iptables.rule
    sed -i "2a sINIF=\"$sINIF\""  /usr/local/virus/iptables/iptables.rule
    sed -i "3a sINNET=\"$sINNET\""  /usr/local/virus/iptables/iptables.rule
    sed -i "4a EXTNET=\"$EXTNET\""  /usr/local/virus/iptables/iptables.rule
    chmod 755 -R /usr/local/virus/iptables/

    infomsg $'設定 每天更新 spamhaus 黑名單 \n'
    ln -s /usr/local/virus/iptables/set_iptables_drop_lasso /etc/cron.daily >/dev/null 2>&1
    sed -i -e '$a\'$'\n''/usr/local/virus/iptables/iptables.rule' /etc/rc.local

    systemctl restart iptables.service
    systemctl enable iptables.service

    /usr/local/virus/iptables/iptables.rule >>/dev/null 2>&1
    return 1
}

setsystem (){
    infomsg $'優化網路卡設定 複寫/etc/sysctl.conf \n'
    wget -O /etc/sysctl.conf $github_conf_url/conf/sysctl.conf

    infomsg $'優化 vim 編輯器\n'
cat >> /etc/vimrc <<EOT
set encoding=utf-8
set fileencodings=utf-8,cp950
syntax on
set fileformats=unix,dos
set nocompatible
set ai
set shiftwidth=4
set tabstop=4
set softtabstop=4
set expandtab
set number
set ruler
set backspace=2
set ic
set ru
set hlsearch
set incsearch
set smartindent
set confirm
set history=100
set cursorline
set laststatus=2
set backup
set backupdir=~/vim_backup
set autoindent
highlight Comment ctermfg=LightCyan
set statusline=%4*%<\%m%<[%f\%r%h%w]\ [%{&ff},%{&fileencoding},%Y]%=\[Position=%l,%v,%p%%]
colorscheme torte
EOT

    infomsg $'設定 Bash 終端機顏色\n'
cat >> /etc/bashrc <<EOT
PS1="\e[1;34m\u@\h \w> \e[m"
alias vi='vim'
alias ll='ls -al --color'
setterm -blength 0
HISTTIMEFORMAT='%F %T '
EOT
    sysctl -p
    chmod +x /etc/rc.d/rc.local

    return 1
}

install_MariaDB () {
    # ================================================================
    # install_MariaDB
    # ================================================================
    infomsg $'Install MariaDB 資料庫\n'
    curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash >/dev/null 2>&1
    sleep 3
    dnf -y update >/dev/null 2>&1
    sleep 2
    dnf -y install mariadb-server

    infomsg $'Set MariaDB character utf8\n'

    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysql\]/a\default-character-set=utf8' /etc/my.cnf.d/mysql-clients.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\character-set-server=utf8' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\innodb_file_per_table = 1' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\net_read_timeout=120' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\event_scheduler = ON' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\innodb_buffer_pool_size = 2G' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\innodb_log_buffer_size =512M' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\skip-name-resolve' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\max_connections=100' /etc/my.cnf.d/server.cnf

    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\# global settings' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\table_cache=35535' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\table_definition_cache=35535' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\max_allowed_packet=4M' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\net_buffer_length=1M' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\bulk_insert_buffer_size=16M' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\query_cache_type=0 #是否使用查詢緩衝,0關閉' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\query_cache_size=0 #0關閉，因為改表操作多，命中低，開啟消耗cpu' /etc/my.cnf.d/server.cnf
    sed -i.$(date '+%Y%m%d%H%M%S') '/\[mysqld\]/a\skip-grant-tables' /etc/my.cnf.d/server.cnf

cat >> /etc/my.cnf.d/charaset.cnf <<EOT
[mysqld]
character-set-server = utf8mb4

[client]
default-character-set = utf8mb4
EOT

    infomsg $'Install mydumper\n'
    release=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/mydumper/mydumper/releases/latest | cut -d'/' -f8)
    dnf -y install https://github.com/mydumper/mydumper/releases/download/${release}/mydumper-${release:1}.el9.x86_64.rpm  >/dev/null 2>&1

    systemctl restart mariadb.service
    systemctl enable mariadb.service
    return 1
}

install_apache() {
    # ================================================================
    # install apache
    # ================================================================
    if [[ $INSTALL_APACHE != "YES" ]]; then
        return
    fi

    infomsg $'Install Apache\n'

    if [ -f "/usr/sbin/httpd" ]; then
        infomsg $'httpd Package installed.\n'
    else
        dnf -y install httpd mod_ssl mod_security mod_security_crs  >/dev/null 2>&1
    fi

    sed -i.$(date '+%Y%m%d%H%M%S') '/#ServerName www.example.com:80/a\ServerName ${HOSTNAME}:80' /etc/httpd/conf/httpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') '152s/AllowOverride None/AllowOverride All/g' /etc/httpd/conf/httpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') '140,150s/Options Indexes FollowSymLinks/Options FollowSymLinks/g' /etc/httpd/conf/httpd.conf

    sed -i.$(date '+%Y%m%d%H%M%S') '/LoadModule mpm_prefork_module modules\/mod_mpm_prefork.so/c\#LoadModule mpm_prefork_module modules\/mod_mpm_prefork.so'  /etc/httpd/conf.modules.d/00-mpm.conf
    sed -i.$(date '+%Y%m%d%H%M%S') '/#LoadModule mpm_event_module modules\/mod_mpm_event.so/c\LoadModule mpm_event_module modules\/mod_mpm_event.so'  /etc/httpd/conf.modules.d/00-mpm.conf

    infomsg $'Change Apache modules [event_module]\n'
cat >> /etc/httpd/conf.d/mpm.conf  <<EOT
<IfModule mpm_event_module>
ServerLimit           1000
StartServers             8
MinSpareThreads         75
MaxClients            3000
MaxSpareThreads        250
ThreadsPerChild         64
MaxRequestWorkers     992
MaxConnectionsPerChild   0
</IfModule>
EOT

cat >> /etc/httpd/conf/httpd.conf <<EOT
ServerTokens ProductOnly
KeepAlive ON
MaxKeepAliveRequests 0
ExtendedStatus Off
HostnameLookups off
KeepAliveTimeout 5
ServerSignature off
EOT

cat >> /etc/httpd/modsecurity.d/local_rules/modsecurity_localrules.conf <<EOT
# default action when matching rules
SecDefaultAction "phase:2,deny,log,status:406"
# [etc/passwd] is included in request URI
SecRule REQUEST_URI "etc/passwd" "id:'500001'"
# [../] is included in request URI
SecRule REQUEST_URI "\.\./" "id:'500002'"
# [<SCRIPT] is included in arguments
SecRule ARGS "<[Ss][Cc][Rr][Ii][Pp][Tt]" "id:'500003'"
# [SELECT FROM] is included in arguments
SecRule ARGS "[Ss][Ee][Ll][Ee][Cc][Tt][[:space:]]+[Ff][Rr][Oo][Mm]" "id:'500004'"
EOT

    echo Apache > /var/www/html/index.html

    systemctl start httpd.service
    systemctl enable httpd.service

    return 1
}

install_nginx(){
    if [[ $INSTALL_NGINX != "YES" ]]; then
        return
    fi

    if [ -f "/usr/sbin/nginx" ]; then
        infomsg $'nginx Package installed\n'
    else
        infomsg $"Install Nginx......"
        dnf -y install nginx
    fi

    #sed -i.$(date '+%Y%m%d%H%M%S') "41s:server_name  _;:server_name ${HOSTNAME};:g" /etc/nginx/nginx.conf
    #sed -i.$(date '+%Y%m%d%H%M%S') "42s:root         /usr/share/nginx/html;:root         /var/www/html;:g" /etc/nginx/nginx.conf
    infomsg $'設定 iptable 白名單 \n'
    wget -O /etc/nginx/nginx.conf $github_conf_url/conf/nginx.conf

    mkdir -p /var/www/html
    chown -R nginx:nginx /var/www/html

    systemctl enable nginx.service
    systemctl restart nginx.service
}

install_php(){
    if [[ $INSTALL_PHP == "" ]]; then
        return 0
    fi
    VER=${INSTALL_PHP}
    infomsg $'Install PHP\n'
    dnf -y module list php
    dnf -y module reset php
    dnf -y module enable php:remi-${INSTALL_PHP}
    infomsg $'Install PHP Extesion\n'

    dnf -y install php-bcmath php-ast php-brotli php-cli php-common php-dba php-dbg php-embedded php-ffi php-fpm php-devel php-enchant php-gd php-geos php-gmp php-imap php-intl php-json php-ldap php-libvirt php-libvirt php-litespeed php-lz4 php-maxminddb php-mbstring php-mysqlnd php-odbc php-opcache php-pdo php-pdo-dblib php-pdo-firebird

    infomsg $'Install FreeTDS\n'
    dnf -y install freetds

    sed -i.$(date '+%Y%m%d%H%M%S') 's/\[egServer50\]/[SYBASE]/g' /etc/freetds.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/symachine.domain.com/'$FREETDS_IP'/g' /etc/freetds.conf
    infomsg $'Seting /etc/php.ini ............. \n'
    sed -i.$(date '+%Y%m%d%H%M%S') '/date.timezone =/a\date.timezone = "Asia/Taipei"' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/expose_php = On/expose_php = Off/g' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/short_open_tag = Off/short_open_tag = On/g' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/display_errors = Off/display_errors = On/g' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/memory_limit = 128M/memory_limit = -1/g' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/post_max_size = 8M/post_max_size = 500M/g' /etc/php.ini
    sed -i.$(date '+%Y%m%d%H%M%S') 's/upload_max_filesize = 2M/upload_max_filesize = 500M/g' /etc/php.ini

    systemctl restart nginx.service >/dev/null 2>&1
    chown nginx:nginx -R /var/lib/php/session

    infomsg $'Install Composer \n'
    php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
    php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer
    php -r "unlink('/tmp/composer-setup.php');"
}

install_vsftpd (){
    if [ -f "/usr/sbin/vsftpd" ]; then
        infomsg $'vsftpd Package installed.  \n'
    else
        dnf -y install vsftpd
    fi

    sed -i.$(date '+%Y%m%d%H%M%S') 's/anonymous_enable=YES/anonymous_enable=No/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#ascii_upload_enable=YES/ascii_upload_enable=YES/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#ascii_download_enable=YES/ascii_download_enable=YES/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#chroot_local_user=YES/chroot_local_user=YES/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#chroot_list_enable=YES/chroot_list_enable=YES/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#chroot_list_file=\/etc\/vsftpd\/chroot_list/chroot_list_file=\/etc\/vsftpd\/chroot_list/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/listen=NO/listen=YES/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/listen_ipv6=YES/listen_ipv6=NO/g' /etc/vsftpd/vsftpd.conf
    sed -i.$(date '+%Y%m%d%H%M%S') 's/#ls_recurse_enable=YES/ls_recurse_enable=YES/g' /etc/vsftpd/vsftpd.conf

    infomsg $'設定 vsftpd.conf\n'
    wget -O /etc/vsftpd/vsftpd.conf $github_conf_url/conf/vsftpd.conf

    touch /etc/vsftpd/chroot_list
    chmod 644 /etc/vsftpd/chroot_list
    echo $ADD_USERNAME >> /etc/vsftpd/chroot_list
    echo $ADD_USERNAME >> /etc/vsftpd/user_list

    systemctl restart vsftpd.service
    systemctl enable vsftpd.service
    return 1
}

install_squid (){
    if [ -f "/usr/sbin/squid" ]; then
        infomsg $'squid Package installed. \n'
    else
        dnf -y install squid
    fi

    touch /etc/squid/allowdomain.txt
    chmod 644 /etc/squid/allowdomain.txt

    infomsg $'加入 proxy 網站白名單\n'
    wget -O /etc/squid/allowdomain.txt $github_conf_url/conf/allowdomain.txt

    touch /etc/squid/allowupdate.txt
    chmod 644 /etc/squid/allowupdate.txt

    echo "$sINNET" >> /etc/squid/allowupdate.txt

    infomsg $'設定 proxy 使用者帳號密碼 \n'
    sed -i.$(date '+%Y%m%d%H%M%S') '1a auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/squid_user.txt' /etc/squid/squid.conf
    sed -i.$(date '+%Y%m%d%H%M%S') '2a auth_param basic children 5'  /etc/squid/squid.conf
    sed -i.$(date '+%Y%m%d%H%M%S') '3a auth_param basic realm Welcome to $HOSTNAME proxy-only web server'  /etc/squid/squid.conf

    systemctl restart squid
    systemctl enable squid
    return 1
}

final(){
    clear
    systemctl restart NetworkManager >>/dev/null 2>&1
    systemctl restart nginx 2>&1
    systemctl restart php-fpm 2>&1
    systemctl restart snmpd 2>&1
    systemctl restart sshd 2>&1
    systemctl restart squid 2>&1
    systemctl restart crond 2>&1

    echo ""
    echo "First of all, this require you to reboot your system...."
    echo "1. this is program use 'iptables -F' command clean all, please set iptable firewall rule,and edit file of /usr/local/virus/iptables/iptables.rule"
    echo "2. test network use 'iptables -P INPUT ACCEPT'"
    echo "2. rclone config, Setting Dropbox,GoogleDrive....."
    return 1
}

# ================================================================
# Main
# ================================================================
printf "Rocky Linux 自動腳本 \n"

#初始化系統
init
#安裝基本軟體
basesoftware
#安裝kernel
install_kernel
#安裝 iptables
install_iptables
#優化環境設定
setsystem
#安裝 php
install_php
#安裝 MariaDB
install_MariaDB
#安裝 apache
install_apache
#安裝 nginx
install_nginx
#安裝 mail
install_postfix
install_dovecot
#安裝vsftpd
install_vsftpd
# 安裝proxy
install_squid
# 自訂環境
custom_settings
final
# ================================================================
# END
# ================================================================
exit 0
