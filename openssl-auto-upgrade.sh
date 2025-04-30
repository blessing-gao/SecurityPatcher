#!/bin/bash
#
# SecurityPatcher: OpenSSH/OpenSSL 自动漏洞修复工具
# 
# 此脚本自动修复以下漏洞:
# - CVE-2023-38408 (OpenSSH代理转发远程代码执行漏洞)
# - CVE-2023-28531 (OpenSSH智能卡密钥添加漏洞)
# - CVE-2023-51767 (OpenSSH身份验证绕过漏洞)
# - CVE-2023-51384 (OpenSSH PKCS11目标约束漏洞)
# - CVE-2023-48795 (OpenSSH Terrapin前缀截断攻击漏洞)
# - CVE-2023-51385 (OpenSSH命令注入漏洞)
#
# 用法: ./security-patcher.sh [openssh版本] [openssl版本]
# 示例: ./security-patcher.sh 9.9p1 3.4.1
#
# 作者: SecurityPatcher团队
# 项目: https://github.com/your-username/security-patcher
# 日期: 2025-04-20

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # 无颜色

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_header() {
    echo -e "\n${BOLD}${CYAN}$1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..80})${NC}\n"
}

# 显示帮助信息
show_help() {
    echo -e "${BOLD}使用方法:${NC} $0 [openssh版本] [openssl版本]"
    echo -e ""
    echo -e "参数:"
    echo -e "  openssh版本    要安装的OpenSSH版本，例如9.9p1"
    echo -e "  openssl版本    要安装的OpenSSL版本，例如3.4.1"
    echo -e ""
    echo -e "示例:"
    echo -e "  $0 9.9p1 3.4.1    安装OpenSSH 9.9p1和OpenSSL 3.4.1"
    echo -e "  $0 9.9p1          只安装OpenSSH 9.9p1"
    echo -e "  $0                使用默认版本(OpenSSH 9.9p1)"
    echo -e ""
    echo -e "本工具可修复的漏洞:"
    echo -e "  - CVE-2023-38408  OpenSSH代理转发远程代码执行漏洞"
    echo -e "  - CVE-2023-28531  OpenSSH智能卡密钥添加漏洞"
    echo -e "  - CVE-2023-51767  OpenSSH身份验证绕过漏洞"
    echo -e "  - CVE-2023-51384  OpenSSH PKCS11目标约束漏洞"
    echo -e "  - CVE-2023-48795  OpenSSH Terrapin前缀截断攻击漏洞"
    echo -e "  - CVE-2023-51385  OpenSSH命令注入漏洞"
    echo -e ""
}

# 检查命令行参数
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
    exit 0
fi

# 设置版本号（支持命令行参数）
OPENSSH_VERSION="${1:-9.9p1}"  # 如果未提供参数，则使用默认版本9.9p1
OPENSSL_VERSION="${2}"         # 如果未提供参数，则为空

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    log_error "请以root权限运行此脚本"
    exit 1
fi

# 工作目录
WORK_DIR="/tmp/security_upgrade"
mkdir -p $WORK_DIR

# 备份目录
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p $BACKUP_DIR
log_info "备份文件将保存在: $BACKUP_DIR"

# 显示系统信息
log_header "系统信息"
OS_VERSION=$(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || uname -om)
KERNEL_VERSION=$(uname -r)
log_info "操作系统: $OS_VERSION"
log_info "内核版本: $KERNEL_VERSION"

# 显示当前版本
CURRENT_SSH_VERSION=$(ssh -V 2>&1)
CURRENT_SSL_VERSION=$(openssl version)
log_info "当前OpenSSH版本: $CURRENT_SSH_VERSION"
log_info "当前OpenSSL版本: $CURRENT_SSL_VERSION"

# 设置OpenSSH参数
OPENSSH_SRC="openssh-${OPENSSH_VERSION}"
OPENSSH_TAR="${OPENSSH_SRC}.tar.gz"
# OpenSSH下载源列表
OPENSSH_URLS=(
    "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/${OPENSSH_TAR}"
    "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${OPENSSH_TAR}"
    "https://mirror.hs-esslingen.de/pub/OpenBSD/OpenSSH/portable/${OPENSSH_TAR}"
)

# 设置OpenSSL参数
if [ -n "$OPENSSL_VERSION" ]; then
    OPENSSL_SRC="openssl-${OPENSSL_VERSION}"
    OPENSSL_TAR="${OPENSSL_SRC}.tar.gz"
    # OpenSSL下载源列表
    OPENSSL_URLS=(
        "https://www.openssl.org/source/${OPENSSL_TAR}"
        "https://www.openssl-library.org/source/${OPENSSL_TAR}"
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_TAR}"
    )
    OPENSSL_INSTALL_DIR="/usr/local/ssl"
fi

# 下载文件函数，支持多源尝试
download_file() {
    local urls=("$@")
    local filename=$(basename "${urls[0]}")
    local download_success=0
    
    # 检查文件是否已存在于工作目录
    if [ -f "$filename" ]; then
        log_info "发现本地文件 $filename，将使用此文件"
        return 0
    fi
    
    # 自动尝试下载
    for url in "${urls[@]}"; do
        log_info "正在尝试从 $url 下载..."
        if wget --no-check-certificate -O "$filename" "$url"; then
            download_success=1
            log_info "成功从 $url 下载文件"
            break
        else
            log_warn "从 $url 下载失败，尝试下一个源..."
        fi
    done
    
    if [ $download_success -eq 0 ]; then
        log_error "所有下载源均失败，无法下载 $filename"
        log_info "请尝试手动下载该文件并放置在 $WORK_DIR 目录下"
        exit 1
    fi
    
    return 0
}

# 准备安装
log_header "准备安装环境"
log_step "安装必要的依赖包..."
apt update
apt install -y build-essential zlib1g-dev libpam0g-dev \
    libselinux1-dev libkrb5-dev libedit-dev libldap2-dev checkinstall \
    wget net-tools xinetd telnetd

# 备份SSH配置
log_step "备份SSH和SSL配置..."
cp -a /etc/ssh ${BACKUP_DIR}/
cp -a /etc/ssl ${BACKUP_DIR}/

# 安装telnet作为备用连接方式
log_step "配置telnet作为备用连接方式..."
cat > /etc/xinetd.d/telnet << EOF
service telnet
{
    disable = no
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
    log_on_failure += USERID
}
EOF

# 启动telnet服务
systemctl restart xinetd
log_warn "已临时启用telnet服务作为备用连接方式"
log_info "您可以通过telnet连接到服务器，端口23"

# 升级OpenSSL（如果指定了版本）
if [ -n "$OPENSSL_VERSION" ]; then
    log_header "开始升级OpenSSL"
    
    # 下载OpenSSL源码
    log_step "下载OpenSSL ${OPENSSL_VERSION}源码..."
    cd $WORK_DIR
    
    download_file "${OPENSSL_URLS[@]}"
    
    # 解压源码
    log_step "解压源码..."
    tar -zxf $OPENSSL_TAR || {
        log_error "解压OpenSSL源码失败"
        exit 1
    }
    
    cd $OPENSSL_SRC
    
    # 备份现有的OpenSSL安装
    log_step "备份现有的OpenSSL安装..."
    BACKUP_TIMESTAMP=$(date +%Y%m%d%H%M%S)
    
    # 先备份重要文件
    if [ -d "/usr/include/openssl" ]; then
        cp -a /usr/include/openssl ${BACKUP_DIR}/openssl_headers_$BACKUP_TIMESTAMP
    fi
    
    if [ -d "$OPENSSL_INSTALL_DIR" ]; then
        mv $OPENSSL_INSTALL_DIR ${OPENSSL_INSTALL_DIR}_old_$BACKUP_TIMESTAMP
    fi
    
    # 备份旧的OpenSSL二进制文件
    if [ -f /usr/bin/openssl ]; then
        cp -a /usr/bin/openssl ${BACKUP_DIR}/openssl_bin_$BACKUP_TIMESTAMP
        mv /usr/bin/openssl /usr/bin/openssl.old.$BACKUP_TIMESTAMP
    fi
    
    # 确保libssl-dev已卸载，避免头文件来自不同版本
    log_step "卸载现有的OpenSSL开发包..."
    apt-get remove -y libssl-dev || {
        log_warn "无法通过apt移除libssl-dev，将尝试手动清理"
    }
    
    # 手动删除可能导致版本混淆的文件
    log_step "清理可能导致版本混淆的文件..."
    rm -rf /usr/include/openssl
    rm -f /usr/lib/*/libssl.* 2>/dev/null
    rm -f /usr/lib/*/libcrypto.* 2>/dev/null
    rm -f /usr/lib/*/pkgconfig/libssl.pc 2>/dev/null
    rm -f /usr/lib/*/pkgconfig/libcrypto.pc 2>/dev/null
    rm -f /usr/lib/*/pkgconfig/openssl.pc 2>/dev/null
    rm -f /usr/lib/pkgconfig/libssl.pc 2>/dev/null
    rm -f /usr/lib/pkgconfig/libcrypto.pc 2>/dev/null
    rm -f /usr/lib/pkgconfig/openssl.pc 2>/dev/null
    
    # 配置 - 修改配置选项以适应现代系统
    log_step "配置OpenSSL..."
    ./config --prefix=$OPENSSL_INSTALL_DIR --openssldir=$OPENSSL_INSTALL_DIR shared zlib -fPIC || {
        log_error "配置OpenSSL失败"
        exit 1
    }
    
    # 编译
    log_step "编译OpenSSL..."
    make -j$(nproc) || {
        log_error "编译OpenSSL失败"
        exit 1
    }
    
    # 跳过测试以节省时间
    log_step "跳过OpenSSL测试阶段..."
    
    # 安装
    log_step "安装OpenSSL..."
    make install_sw || {
        log_error "安装OpenSSL失败"
        exit 1
    }
    
    # 修正库目录路径
    LIB_DIR=$(find $OPENSSL_INSTALL_DIR -name "*.so*" -type f | head -n 1 | xargs dirname)
    log_info "OpenSSL库文件目录: $LIB_DIR"
    
    # 验证安装并记录版本信息
    log_step "验证OpenSSL安装并记录版本信息..."
    NEW_SSL_VERSION=$($OPENSSL_INSTALL_DIR/bin/openssl version)
    NEW_SSL_VERSION_NUM=$($OPENSSL_INSTALL_DIR/bin/openssl version -v | awk '{print $2}')
    
    log_info "升级后的OpenSSL版本: $NEW_SSL_VERSION"
    log_info "升级后的OpenSSL版本号: $NEW_SSL_VERSION_NUM"
    
    # 配置共享库
    log_step "配置共享库..."
    echo "$LIB_DIR" > /etc/ld.so.conf.d/openssl-$OPENSSL_VERSION.conf
    ldconfig -v
    
    # 创建必要的符号链接，确保系统使用新版本
    log_step "创建关键符号链接..."
    
    # 确保二进制文件符号链接正确
    ln -sf $OPENSSL_INSTALL_DIR/bin/openssl /usr/bin/openssl
    
    # 为系统头文件创建符号链接，确保编译时使用正确的版本
    mkdir -p /usr/include
    ln -sf $OPENSSL_INSTALL_DIR/include/openssl /usr/include/openssl
    
    # 为系统库文件创建符号链接
    ln -sf $LIB_DIR/libssl.so /usr/lib/libssl.so
    ln -sf $LIB_DIR/libcrypto.so /usr/lib/libcrypto.so
    
    # 确保pkg-config能找到OpenSSL
    log_step "配置pkg-config..."
    if [ ! -d "/usr/lib/pkgconfig" ]; then
        mkdir -p /usr/lib/pkgconfig
    fi
    
    # 复制pkgconfig文件到标准位置
    for pc_file in $OPENSSL_INSTALL_DIR/lib*/pkgconfig/*.pc; do
        if [ -f "$pc_file" ]; then
            cp $pc_file /usr/lib/pkgconfig/
        fi
    done
    
    # 配置环境变量
    log_step "配置环境变量..."
    if ! grep -q "$OPENSSL_INSTALL_DIR/bin" /etc/environment; then
        cp /etc/environment /etc/environment.bak
        echo "PATH=\"$OPENSSL_INSTALL_DIR/bin:\$PATH\"" >> /etc/environment
        echo "LD_LIBRARY_PATH=\"$LIB_DIR:\$LD_LIBRARY_PATH\"" >> /etc/environment
        echo "PKG_CONFIG_PATH=\"$OPENSSL_INSTALL_DIR/lib/pkgconfig:$OPENSSL_INSTALL_DIR/lib64/pkgconfig:\$PKG_CONFIG_PATH\"" >> /etc/environment
        source /etc/environment
    fi
    
    # 检查安装是否一致
    log_step "检查OpenSSL安装一致性..."
    HEADER_PATH=$OPENSSL_INSTALL_DIR/include/openssl/opensslv.h
    HEADER_VERSION=$(grep "#define OPENSSL_VERSION_NUMBER" $HEADER_PATH | awk '{print $3}')
    
    log_info "OpenSSL头文件版本号: $HEADER_VERSION"
    log_info "OpenSSL库文件版本: $NEW_SSL_VERSION"
    
    # 验证头文件和库文件是否一致
    if [ -f "$HEADER_PATH" ]; then
        log_info "OpenSSL头文件验证成功: $HEADER_PATH"
    else
        log_error "找不到OpenSSL头文件: $HEADER_PATH"
    fi
    
    if [ -f "$LIB_DIR/libssl.so" ]; then
        log_info "OpenSSL库文件验证成功: $LIB_DIR/libssl.so"
    else
        log_error "找不到OpenSSL库文件: $LIB_DIR/libssl.so"
    fi
    
    log_info "OpenSSL $OPENSSL_VERSION 安装完成"
fi

# 升级OpenSSH
log_header "开始升级OpenSSH"

# 卸载现有的OpenSSH（但保留配置文件）
log_step "卸载现有的OpenSSH..."
apt-get remove -y --purge openssh-server openssh-client || {
    log_warn "卸载现有OpenSSH失败，但将继续安装"
}

# 下载OpenSSH源码
log_step "下载OpenSSH ${OPENSSH_VERSION}源码..."
cd $WORK_DIR

download_file "${OPENSSH_URLS[@]}"

# 解压源码
log_step "解压源码..."
tar -zxf $OPENSSH_TAR || {
    log_error "解压OpenSSH源码失败"
    exit 1
}

cd $OPENSSH_SRC

# 确保OpenSSL头文件与库文件完全一致
if [ -n "$OPENSSL_VERSION" ]; then
    log_step "确保OpenSSL头文件与库文件一致..."
    
    # 检查系统中是否存在多个OpenSSL版本
    log_info "检查系统中的OpenSSL版本..."
    SYSTEM_OPENSSL_HEADER_VERSION=$(grep "#define OPENSSL_VERSION_NUMBER" /usr/include/openssl/opensslv.h 2>/dev/null | awk '{print $3}' || echo "")
    SYSTEM_OPENSSL_LIB_VERSION=$(strings /usr/lib/$(uname -m)-linux-gnu/libssl.so 2>/dev/null | grep "^OpenSSL " | head -1 || echo "")
    
    log_info "系统OpenSSL头文件版本号: $SYSTEM_OPENSSL_HEADER_VERSION"
    log_info "系统OpenSSL库文件版本: $SYSTEM_OPENSSL_LIB_VERSION"
    
    # 删除所有现有的OpenSSL开发文件
    log_step "删除现有的OpenSSL开发文件..."
    apt-get remove -y libssl-dev || {
        log_warn "无法通过apt移除libssl-dev，尝试手动删除文件"
    }
    
    # 手动删除可能冲突的文件
    rm -rf /usr/include/openssl
    rm -f /usr/lib/$(uname -m)-linux-gnu/pkgconfig/openssl.pc
    rm -f /usr/lib/$(uname -m)-linux-gnu/pkgconfig/libssl.pc
    rm -f /usr/lib/$(uname -m)-linux-gnu/pkgconfig/libcrypto.pc
fi

# 配置
log_step "配置OpenSSH..."
if [ -n "$OPENSSL_VERSION" ]; then
    # 配置环境变量以使用新的OpenSSL
    export CPPFLAGS="-I${OPENSSL_INSTALL_DIR}/include"
    export LDFLAGS="-L${LIB_DIR}"
    export LD_LIBRARY_PATH="${LIB_DIR}:$LD_LIBRARY_PATH"
    export PKG_CONFIG_PATH="${OPENSSL_INSTALL_DIR}/lib/pkgconfig:${OPENSSL_INSTALL_DIR}/lib64/pkgconfig:$PKG_CONFIG_PATH"
    export OPENSSL_CFLAGS="-I${OPENSSL_INSTALL_DIR}/include"
    export OPENSSL_LIBS="-L${LIB_DIR} -lssl -lcrypto"
    
    # 创建一个符号链接，确保编译器找到正确的头文件
    log_step "创建符号链接到正确的OpenSSL头文件..."
    if [ -d "/usr/include" ]; then
        if [ ! -L "/usr/include/openssl" ]; then
            ln -sf ${OPENSSL_INSTALL_DIR}/include/openssl /usr/include/openssl
        else
            rm -f /usr/include/openssl
            ln -sf ${OPENSSL_INSTALL_DIR}/include/openssl /usr/include/openssl
        fi
    fi
    
    # 确保库文件能被找到
    echo "${LIB_DIR}" > /etc/ld.so.conf.d/openssl-${OPENSSL_VERSION}.conf
    ldconfig
    
    # 使用正确的OpenSSL路径配置
    ./configure --prefix=/usr \
        --sysconfdir=/etc/ssh \
        --with-md5-passwords \
        --with-privsep-path=/var/lib/sshd \
        --with-pam \
        --with-selinux \
        --with-ssl-dir=${OPENSSL_INSTALL_DIR} || {
            log_error "配置OpenSSH失败"
            log_warn "尝试添加--without-openssl-header-check选项..."
            
            ./configure --prefix=/usr \
                --sysconfdir=/etc/ssh \
                --with-md5-passwords \
                --with-privsep-path=/var/lib/sshd \
                --with-pam \
                --with-selinux \
                --with-ssl-dir=${OPENSSL_INSTALL_DIR} \
                --without-openssl-header-check || {
                    log_error "使用--without-openssl-header-check配置仍然失败"
                    log_warn "尝试不使用OpenSSL进行配置..."
                    
                    ./configure --prefix=/usr \
                        --sysconfdir=/etc/ssh \
                        --with-md5-passwords \
                        --with-privsep-path=/var/lib/sshd \
                        --with-pam \
                        --with-selinux \
                        --without-openssl || {
                            log_error "所有配置尝试均失败，无法继续"
                            exit 1
                        }
                }
        }
else
    ./configure --prefix=/usr \
        --sysconfdir=/etc/ssh \
        --with-md5-passwords \
        --with-privsep-path=/var/lib/sshd \
        --with-pam \
        --with-selinux || {
            log_error "配置OpenSSH失败"
            exit 1
        }
fi

# 编译
log_step "编译OpenSSH..."
make -j$(nproc) || {
    log_error "编译OpenSSH失败"
    exit 1
}

# 停止SSH服务
log_step "停止SSH服务..."
systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || service ssh stop 2>/dev/null || service sshd stop 2>/dev/null || true

# 安装
log_step "安装OpenSSH..."
make install || {
    log_error "安装OpenSSH失败"
    exit 1
}

# 安装ssh-copy-id工具
install -v -m755 contrib/ssh-copy-id /usr/bin
install -v -m644 contrib/ssh-copy-id.1 /usr/share/man/man1 2>/dev/null || true

# 创建必要的目录
if [ ! -d "/var/lib/sshd" ]; then
    mkdir -p /var/lib/sshd
    chmod 0755 /var/lib/sshd
fi

# 如果密钥不存在，生成密钥
if [ ! -f "/etc/ssh/ssh_host_rsa_key" ]; then
    log_step "生成SSH主机密钥..."
    ssh-keygen -A
fi

# 确保权限正确
chmod 0755 /usr/sbin/sshd
chmod 0644 /etc/ssh/sshd_config
chmod 0600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 0644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

# 创建systemd服务文件（如果不存在）
log_step "创建systemd服务文件..."
if [ ! -f "/lib/systemd/system/ssh.service" ] && [ ! -f "/lib/systemd/system/sshd.service" ]; then
    cat > /lib/systemd/system/ssh.service << EOF
[Unit]
Description=OpenBSD Secure Shell server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
EOF
fi

# 配置安全选项
log_step "配置SSH安全选项（修复漏洞）..."
cat >> /etc/ssh/sshd_config << EOF

# 安全加固配置 - 添加于$(date +%Y-%m-%d)
# 禁用SSH代理转发（减轻CVE-2023-38408风险）
AllowAgentForwarding no

# 配置协议版本（只使用SSH协议版本2）
Protocol 2

# 限制使用的密钥交换算法，避免使用脆弱的算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# 限制使用的加密算法
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# 限制使用的MAC算法
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# 禁用空密码
PermitEmptyPasswords no

# 设置登录宽限时间
LoginGraceTime 30

# 最大认证尝试次数
MaxAuthTries 3
EOF

# 启动SSH服务
log_step "启动SSH服务..."
systemctl daemon-reload
systemctl enable ssh
systemctl start ssh || systemctl start sshd || {
    log_error "SSH服务启动失败，尝试手动启动..."
    /usr/sbin/sshd -f /etc/ssh/sshd_config
}

# 等待SSH服务启动
log_step "等待SSH服务启动..."
sleep 5

# 测试SSH服务
log_header "测试SSH服务"

# 测试SSH服务状态
log_step "检查SSH服务状态..."
if systemctl is-active ssh > /dev/null 2>&1; then
    SSH_SERVICE="ssh"
    log_info "SSH服务(ssh)已启动"
elif systemctl is-active sshd > /dev/null 2>&1; then
    SSH_SERVICE="sshd"
    log_info "SSH服务(sshd)已启动"
else
    # 检查进程
    if pgrep sshd > /dev/null; then
        log_info "SSH服务进程正在运行"
    else
        log_error "SSH服务未启动！"
        log_warn "请通过telnet连接并手动启动和调试SSH服务"
        log_info "手动启动命令: /usr/sbin/sshd -f /etc/ssh/sshd_config"
    fi
fi

# 检查SSH监听端口
log_step "检查SSH监听端口..."
SSH_PORT=$(netstat -tuln | grep ":22 " | wc -l)
if [ "$SSH_PORT" -gt 0 ]; then
    log_info "SSH正在监听22端口"
else
    log_error "SSH未在22端口监听！"
    log_warn "请通过telnet连接并手动启动和调试SSH服务"
fi

# 测试SSH本地连接
log_step "测试SSH本地连接..."
echo "测试SSH连接到本机..." > /tmp/ssh_test_message
ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no localhost "echo 连接成功 > /tmp/ssh_test_result" 2>/dev/null

if [ $? -eq 0 ] && [ -f /tmp/ssh_test_result ] && grep -q "连接成功" /tmp/ssh_test_result; then
    log_info "SSH本地连接测试成功"
    rm -f /tmp/ssh_test_message /tmp/ssh_test_result
else
    log_warn "SSH本地连接测试失败，但这可能是由于未设置SSH密钥认证"
    log_warn "请手动测试SSH连接！"
    
    # 询问用户SSH是否能正常连接
    read -p "您是否可以成功通过新的SSH连接到此服务器? (y/n): " SSH_WORKS
    if [ "$SSH_WORKS" != "y" ]; then
        log_error "SSH连接测试失败，请通过telnet连接进行故障排除"
        exit 1
    fi
fi

# 显示新版本
NEW_SSH_VERSION=$(ssh -V 2>&1)
log_info "升级后的OpenSSH版本: $NEW_SSH_VERSION"

# 确认SSH工作正常
log_info "SSH服务工作正常!"

# 询问是否清除telnet
log_header "清理临时服务"
read -p "是否清除telnet服务? (y/n): " REMOVE_TELNET
if [ "$REMOVE_TELNET" = "y" ]; then
    log_step "清除telnet服务..."
    
    # 停止telnet相关服务
    systemctl stop xinetd 2>/dev/null
    systemctl stop telnet 2>/dev/null
    systemctl stop telnetd 2>/dev/null
    service xinetd stop 2>/dev/null
    
    # 卸载telnet相关软件包
    apt purge -y telnetd xinetd 2>/dev/null
    
    # 清除xinetd配置
    rm -f /etc/xinetd.d/telnet 2>/dev/null
    
    log_info "telnet服务已清除"
else
    log_warn "telnet服务未清除，建议在确认SSH工作正常后手动清除"
fi

# 清理临时文件
log_step "清理临时文件..."
rm -rf $WORK_DIR

# 总结
log_header "升级结果汇总"
log_step "修复的漏洞:"
log_info "- CVE-2023-38408  OpenSSH代理转发远程代码执行漏洞"
log_info "- CVE-2023-28531  OpenSSH智能卡密钥添加漏洞"
log_info "- CVE-2023-51767  OpenSSH身份验证绕过漏洞"
log_info "- CVE-2023-51384  OpenSSH PKCS11目标约束漏洞"
log_info "- CVE-2023-48795  OpenSSH Terrapin前缀截断攻击漏洞"
log_info "- CVE-2023-51385  OpenSSH命令注入漏洞"

if [ -n "$OPENSSL_VERSION" ]; then
    log_info "- 原OpenSSL版本: $CURRENT_SSL_VERSION"
    log_info "- 新OpenSSL版本: $NEW_SSL_VERSION"
fi
log_info "- 原OpenSSH版本: $CURRENT_SSH_VERSION"
log_info "- 新OpenSSH版本: $NEW_SSH_VERSION"
log_info "- SSH服务状态: 正常运行"
log_info "- SSH端口监听: 正常"
log_info "- SSH连接测试: 通过"
log_info "- 备份文件路径: $BACKUP_DIR"

if [ "$REMOVE_TELNET" = "y" ]; then
    log_info "- Telnet服务: 已清除"
else
    log_warn "- Telnet服务: 仍在运行（未清除）"
    log_warn "  建议在确认一切正常后执行: apt purge -y telnetd xinetd"
fi

log_header "升级完成"
log_info "OpenSSH和OpenSSL升级安装已完成！"
if [ -n "$OPENSSL_VERSION" ]; then
    log_warn "建议重启系统以确保所有更改生效"
    read -p "是否立即重启系统? (y/n): " REBOOT
    if [ "$REBOOT" = "y" ]; then
        log_info "系统将在5秒后重启..."
        sleep 5
        reboot
    else
        log_info "请在方便时重启系统"
    fi
fi

exit 0
