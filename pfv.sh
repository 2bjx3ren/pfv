#!/bin/bash
# PFV - 端口流量监控工具安装和管理脚本
# 版本: 1.0.0

# 颜色设置
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 版本和设置
VERSION="1.0.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/pfv"
DATA_DIR="/var/lib/pfv"
LOG_DIR="/var/log/pfv"
REPO_URL="https://github.com/2bjx3ren/pfv.git" # 更换为实际仓库地址
DEFAULT_API_PORT=56789
DEFAULT_API_KEY="pfv-api-key-2023"

# 检查脚本模式: 安装模式或管理模式
PFV_BINARY="$INSTALL_DIR/pfv"
PFV_ADMIN="$INSTALL_DIR/pfv.sh"
PFV_CONFIG="$CONFIG_DIR/pfv.json"
API_PORT="$DEFAULT_API_PORT"
API_KEY="$DEFAULT_API_KEY"
API_BASE="http://127.0.0.1:$API_PORT"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

#####################################################
# 管理模式函数
#####################################################

# 显示帮助信息
show_help() {
    echo "端口流量监控管理工具"
    echo "用法: $0 [命令] [参数]"
    echo ""
    echo "命令:"
    echo "  add [端口] [阈值GB]  - 添加端口到监控列表"
    echo "                         阈值默认为20GB"
    echo "                         阈值设为0代表不限制，但会继续统计流量"
    echo "  del [端口]           - 从监控列表移除端口"
    echo "  res [端口]           - 重置端口流量统计"
    echo "  all                  - 查看所有端口流量统计"
    echo "  install              - 安装或重新安装FMV工具"
    echo "  status               - 检查FMV服务状态"
    echo "  uninstall            - 卸载FMV工具"
    echo ""
    echo "示例:"
    echo "  $0 add 80           - 添加端口80，使用默认阈值(20GB)"
    echo "  $0 add 80 0         - 添加端口80，不限制流量"
    echo "  $0 add 443 1        - 添加端口443，阈值设为1GB"
    echo "  $0 res 80           - 重置端口80的流量统计"
    echo "  $0 all              - 查看所有端口的统计"
    echo "  $0 install          - 安装FMV工具"
}

# 检查端口参数
check_port() {
    if [ -z "$1" ]; then
        echo "错误: 端口参数不能为空"
        exit 1
    fi
    
    if ! [[ "$1" =~ ^[0-9]+$ ]]; then
        echo "错误: 端口必须是数字"
        exit 1
    fi
    
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "错误: 端口必须在1-65535范围内"
        exit 1
    fi
}

# GB转字节的转换函数
gb_to_bytes() {
    local gb=$1
    if [ "$gb" -eq 0 ]; then
        echo 0
    else
        echo $(( gb * 1024 * 1024 * 1024 ))
    fi
}

# 检查是否已安装
check_installed() {
    if [ ! -f "$PFV_BINARY" ] || [ ! -f "$PFV_CONFIG" ]; then
        return 1  # 未安装
    fi
    return 0  # 已安装
}

# 管理命令处理
handle_command() {
    # 加载API配置
    if [ -f "$PFV_CONFIG" ]; then
        API_PORT=$(grep -oP 'ApiPort\s*=\s*\K\d+' "$PFV_CONFIG" 2>/dev/null || echo "$DEFAULT_API_PORT")
        API_KEY=$(grep -oP 'ApiKey\s*=\s*\K[^\s]+' "$PFV_CONFIG" 2>/dev/null || echo "$DEFAULT_API_KEY")
        API_BASE="http://127.0.0.1:$API_PORT"
    fi
    
    case "$1" in
        add)
            check_port "$2"
            # 默认阈值设为20GB
            gb_threshold="${3:-20}"
            
            # 将GB转换为字节
            bytes_threshold=$(gb_to_bytes $gb_threshold)
            
            # 显示合适的消息
            if [ "$gb_threshold" -eq 0 ]; then
                echo "添加端口 $2 到监控列表，不限制流量..."
            else
                echo "添加端口 $2 到监控列表，阈值设为 $gb_threshold GB..."
            fi
            
            # 调用API，传入字节值
            curl -s -X POST -H "X-API-Key: $API_KEY" "$API_BASE/add/$2?threshold=$bytes_threshold"
            echo ""
            ;;
        del)
            check_port "$2"
            echo "从监控列表移除端口 $2..."
            curl -s -X POST -H "X-API-Key: $API_KEY" "$API_BASE/remove/$2"
            echo ""
            ;;
        res)
            check_port "$2"
            echo "重置端口 $2 的流量统计..."
            curl -s -X POST -H "X-API-Key: $API_KEY" "$API_BASE/reset/$2"
            echo ""
            ;;
        all)
            echo "所有端口的流量统计:"
            curl -s -H "X-API-Key: $API_KEY" "$API_BASE/stats"
            echo ""
            ;;
        status)
            echo "PFV服务状态:"
            sudo systemctl status pfv
            ;;
        uninstall)
            echo "卸载PFV工具..."
            # 停止并禁用服务
            sudo systemctl stop pfv 2>/dev/null || true
            sudo systemctl disable pfv 2>/dev/null || true
            log_info "PFV服务已停止并禁用"
            
            # 删除文件
            sudo rm -f "$INSTALL_DIR/pfv"
            sudo rm -f "$INSTALL_DIR/pfv.bin"
            sudo rm -f "$INSTALL_DIR/pfv_cmd"
            sudo rm -f "$PFV_ADMIN"
            sudo rm -f "$PFV_CONFIG"
            sudo rm -f "/etc/systemd/system/pfv.service"
            sudo systemctl daemon-reload
            sudo rm -rf "$CONFIG_DIR"
            sudo rm -rf "$DATA_DIR"
            sudo rm -rf "$LOG_DIR"
            log_info "PFV文件已删除"
            echo -e "${GREEN}PFV工具已成功卸载!${NC}"
            
            # 重新加载systemd
            sudo systemctl daemon-reload
            
            echo -e "${GREEN}PFV工具已成功卸载${NC}"
            ;;
        install)
            echo "安装PFV工具..."
            install_pfv
            ;;
        --help|-h|help)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

#####################################################
# 安装模式函数
#####################################################

# 检查系统要求
check_requirements() {
    log_info "检查系统要求..."
    
    # 检查操作系统
    if [[ "$(uname)" != "Linux" ]]; then
        log_error "仅支持Linux系统"
        exit 1
    fi
    
    # 检查sudo权限
    if ! command -v sudo &> /dev/null; then
        log_error "未找到sudo命令，请安装sudo或使用root用户运行"
        exit 1
    fi
    
    # 检查必要的工具，但不立即退出，而是尝试自动安装
    local missing_tools=()
    for cmd in curl tar gcc make; do
        if ! command -v $cmd &> /dev/null; then
            missing_tools+=("$cmd")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warn "缺少必要工具: ${missing_tools[*]}"
        log_info "尝试自动安装缺失工具..."
        install_missing_tools "${missing_tools[@]}"
    fi
    
    log_info "系统要求检查通过"
}

# 手动安装Golang
install_golang_manually() {
    log_info "尝试手动安装Go..."
    
    # 下载Go
    local go_version="1.20.5"
    local os_arch="linux-amd64"
    local go_url="https://golang.org/dl/go${go_version}.${os_arch}.tar.gz"
    local temp_dir=$(mktemp -d)
    
    log_info "下载Go ${go_version}..."
    if ! curl -L -o "${temp_dir}/go.tar.gz" "${go_url}"; then
        log_error "Go下载失败"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    # 安装Go
    log_info "安装Go..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${temp_dir}/go.tar.gz"
    rm -rf "${temp_dir}"
    
    # 添加到PATH
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
    fi
    
    # 将Go添加到当前会话的PATH
    export PATH=$PATH:/usr/local/go/bin
    
    # 验证安装
    if command -v go &> /dev/null; then
        log_info "Go安装成功"
        return 0
    else
        log_error "Go安装失败"
        return 1
    fi
}

# 安装缺失的工具
install_missing_tools() {
    local tools=("$@")
    local package_manager=""
    local packages=()
    
    # 检测包管理器
    if command -v apt-get &> /dev/null; then
        package_manager="apt-get"
        sudo apt-get update
    elif command -v yum &> /dev/null; then
        package_manager="yum"
    elif command -v dnf &> /dev/null; then
        package_manager="dnf"
    else
        log_warn "未找到支持的包管理器，请手动安装缺失的工具: ${tools[*]}"
        exit 1
    fi
    
    # 根据工具名映射到包名
    for tool in "${tools[@]}"; do
        case "$tool" in
            gcc)
                if [ "$package_manager" = "apt-get" ]; then
                    packages+=("build-essential")
                else
                    packages+=("gcc")
                fi
                ;;
            *)
                packages+=("$tool")
                ;;
        esac
    done
    
    # 安装缺失的工具
    if [ ${#packages[@]} -gt 0 ]; then
        log_info "安装缺失的工具: ${packages[*]}"
        sudo $package_manager install -y "${packages[@]}"
        
        # 验证安装是否成功
        for tool in "${tools[@]}"; do
            if ! command -v $tool &> /dev/null; then
                log_error "工具 $tool 安装失败，请手动安装"
                exit 1
            fi
        done
    fi
}

# 安装依赖
install_dependencies() {
    log_info "安装Go编译环境..."
    
    # 检查Go是否已安装
    if command -v go &> /dev/null; then
        go_version=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go版本: $go_version"
        return 0
    fi
    
    # 如果没有安装Go，则安装
    log_info "未找到Go环境，开始安装..."
    
    # 检测包管理器
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y golang git build-essential
    elif command -v yum &> /dev/null; then
        sudo yum install -y golang git gcc
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y golang git gcc
    else
        log_warn "未找到支持的包管理器，尝试使用备用方法安装Go..."
        install_golang_manually
    fi
    
    # 再次检查Go是否安装成功
    if ! command -v go &> /dev/null; then
        log_error "Go安装失败，请手动安装或使用预编译的二进制文件"
        exit 1
    fi
    
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go版本: $go_version"
    
    GO_VERSION=$(go version | awk '{print $3}')
    log_info "Go版本: $GO_VERSION"
    
    log_info "依赖安装完成"
}

# 安装Firewalld
install_firewalld() {
    log_info "安装防火墙(Firewalld)..."
    
    # 检测包管理器并安装firewalld
    if command -v apt-get &> /dev/null; then
        sudo apt-get install firewalld -y
    elif command -v yum &> /dev/null; then
        sudo yum install firewalld -y
    elif command -v dnf &> /dev/null; then
        sudo dnf install firewalld -y
    else
        log_warn "未找到支持的包管理器，请手动安装firewalld"
        return 1
    fi
    
    # 启用并启动firewalld服务
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
    
    # 自动获取SSH端口并添加到防火墙
    local ssh_port=$(grep -E '^#?Port' /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$ssh_port" ]; then
        ssh_port=22  # 默认SSH端口
        log_info "未在sshd_config中找到SSH端口配置，使用默认端口22"
    fi
    
    # 添加SSH端口和API端口到防火墙并重新加载
    sudo firewall-cmd --permanent --add-port=${ssh_port}/tcp
    sudo firewall-cmd --permanent --add-port=$DEFAULT_API_PORT/tcp
    sudo firewall-cmd --reload
    
    log_info "防火墙安装完成，SSH端口(${ssh_port})和API端口($DEFAULT_API_PORT)已添加到防火墙规则"
}

# 获取源代码
get_source() {
    log_info "获取源代码..."
    
    local source_dir="$1"
    
    if [ -n "$source_dir" ]; then
        # 使用本地源代码
        log_info "使用本地源代码: $source_dir"
        cd "$source_dir"
    else
        # 克隆仓库
        log_info "从仓库获取源代码..."
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        
        # 尝试使用git克隆
        if command -v git &> /dev/null; then
            log_info "使用git克隆仓库..."
            git clone "$REPO_URL" .
            if [ $? -eq 0 ]; then
                log_info "git克隆成功"
            else
                log_warn "git克隆失败，尝试直接下载..."
                download_source_directly
            fi
        else
            # 如果没有git，直接下载
            log_warn "未找到git，尝试直接下载源代码..."
            download_source_directly
        fi
    fi
    
    # 检查源文件是否存在
    if [ ! -f "pfv.go" ]; then
        log_error "源文件pfv.go不存在，获取源代码失败"
        exit 1
    fi
    
    log_info "源代码准备完成"
}

# 直接下载源代码
download_source_directly() {
    local repo_owner="2bjx3ren"
    local repo_name="pfv"
    local branch="main"
    local file="pfv.go"
    
    log_info "直接下载源文件..."
    
    # 下载主要源文件
    curl -s -o "$file" "https://raw.githubusercontent.com/${repo_owner}/${repo_name}/${branch}/${file}"
    
    # 下载其他必要文件
    curl -s -o "go.mod" "https://raw.githubusercontent.com/${repo_owner}/${repo_name}/${branch}/go.mod" 2>/dev/null || true
    curl -s -o "go.sum" "https://raw.githubusercontent.com/${repo_owner}/${repo_name}/${branch}/go.sum" 2>/dev/null || true
    
    if [ ! -f "$file" ]; then
        log_error "源文件下载失败"
        return 1
    fi
    
    log_info "源文件下载成功"
    return 0
}

# 获取预编译的二进制文件
get_prebuilt_binary() {
    log_info "尝试下载预编译的二进制文件..."
    
    local repo_owner="2bjx3ren"
    local repo_name="pfv"
    local arch="amd64"
    local binary_url="https://github.com/${repo_owner}/${repo_name}/releases/latest/download/pfv-linux-${arch}"
    
    # 下载二进制文件
    if curl -L -o "pfv" "${binary_url}" && [ -f "pfv" ]; then
        # 检查文件大小
        local file_size=$(stat -c %s "pfv" 2>/dev/null || stat -f %z "pfv")
        if [ "$file_size" -lt 1000000 ]; then  # 小于1MB的文件可能不是有效的二进制文件
            log_warn "下载的文件大小异常 ($file_size 字节)，可能不是有效的二进制文件"
            return 1
        fi
        
        # 设置执行权限
        chmod +x "pfv"
        log_info "预编译二进制文件下载成功，文件大小: $file_size 字节"
        return 0
    else
        log_warn "预编译二进制文件下载失败，将尝试从源代码编译"
        return 1
    fi
}

# 编译代码
build_code() {
    log_info "准备二进制文件..."
    
    # 首先尝试下载预编译的二进制文件
    if get_prebuilt_binary; then
        return 0
    fi
    
    log_info "从源代码编译..."
    
    # 检查源文件是否存在
    if [ ! -f "pfv.go" ]; then
        log_error "源文件 pfv.go 不存在"
        exit 1
    fi
    
    # 检查依赖并下载
    log_info "检查依赖..."
    go mod init pfv 2>/dev/null || true
    go mod tidy
    
    # 使用Go构建
    log_info "构建二进制文件..."
    go build -o pfv pfv.go
    
    if [ $? -ne 0 ] || [ ! -f "pfv" ]; then
        log_error "编译失败"
        exit 1
    fi
    
    log_info "编译完成"
}

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    local api_port="$1"
    
    # 创建配置目录
    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$DATA_DIR"
    
    # 创建JSON配置文件
    cat > pfv.json << EOF
{
  "ports": [],
  "api_port": $api_port,
  "log_path": "$LOG_DIR/pfv.log",
  "data_path": "$DATA_DIR/pfv.json",
  "threshold": 21474836480,
  "api_key": "$DEFAULT_API_KEY"
}
EOF
    
    # 复制配置文件到安装目录
    sudo cp pfv.json "$DATA_DIR/pfv.json"
    sudo cp pfv.json "$PFV_CONFIG"
    
    log_info "配置文件已创建"
}

# 创建systemd服务文件
create_service() {
    log_info "创建服务文件..."
    
    cat > pfv.service << EOF
[Unit]
Description=PFV Port Traffic Monitor Service
After=network.target
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/pfv.bin -config $PFV_CONFIG
Restart=on-failure
RestartSec=10
ReadWritePaths=/var/run $DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    log_info "服务文件已创建"
}

# 安装文件
install_files() {
    log_info "安装文件到系统..."
    
    # 创建必要的目录
    sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    
    # 复制文件
    sudo cp pfv "$INSTALL_DIR/pfv.bin"
    sudo cp pfv.json "$CONFIG_DIR/pfv.json"
    sudo cp pfv.service /etc/systemd/system/pfv.service
    
    # 复制自身作为管理脚本（使用不同的名称避免冲突）
    if [ -f "$0" ]; then
        sudo cp "$0" "$PFV_ADMIN"
        sudo chmod +x "$PFV_ADMIN"
    elif [ -f "./pfv.sh" ]; then
        sudo cp "./pfv.sh" "$PFV_ADMIN"
        sudo chmod +x "$PFV_ADMIN"
    else
        # 如果是通过管道传输的，尝试下载脚本
        log_info "下载管理脚本..."
        sudo curl -sSL "https://raw.githubusercontent.com/2bjx3ren/pfv/main/pfv.sh" -o "$PFV_ADMIN"
        sudo chmod +x "$PFV_ADMIN"
    fi
    
    # 创建pfv命令脚本
    log_info "创建pfv命令..."
    cat > pfv_cmd << 'EOF'
#!/bin/bash
# PFV命令行工具

# 调用pfv.sh并传递所有参数
/usr/local/bin/pfv.sh "$@"
EOF
    
    # 安装到系统
    sudo cp pfv_cmd "$INSTALL_DIR/pfv"
    sudo chmod +x "$INSTALL_DIR/pfv"
    
    # 设置权限
    sudo chmod +x "$INSTALL_DIR/pfv.bin"
    
    log_info "文件安装完成"
}

# 启动服务
start_service() {
    log_info "启动服务..."
    
    # 重新加载systemd
    sudo systemctl daemon-reload
    
    # 启用服务
    sudo systemctl enable pfv
    
    # 启动服务
    sudo systemctl start pfv
    
    # 检查状态
    if sudo systemctl is-active pfv > /dev/null; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败，请检查日志: sudo journalctl -u pfv"
        exit 1
    fi
}

# 打印完成信息
print_completion() {
    log_info "PFV端口流量监控工具安装完成!"
    echo ""
    echo -e "${GREEN}使用方法:${NC}"
    echo "  端口管理: pfv [命令] [参数]"
    echo "  查看日志: sudo tail -f $LOG_DIR/pfv.log"
    echo "  服务管理: sudo systemctl [start|stop|restart|status] pfv"
    echo ""
    echo -e "${GREEN}API端口:${NC} $DEFAULT_API_PORT"
    echo -e "${GREEN}API密钥:${NC} $DEFAULT_API_KEY"
    echo -e "${YELLOW}未配置监控端口，请使用 'pfv add [端口]' 命令添加端口${NC}"
    echo ""
    echo -e "${YELLOW}安装完成。使用 'pfv add [端口] [阈值GB]' 添加监控端口。${NC}"
    echo -e "${YELLOW}您也可以使用 'pfv.sh' 代替 'pfv' 执行相同的命令。${NC}"
    echo ""
}

# 安装FMV的主函数
install_pfv() {
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${GREEN}  PFV端口流量监控工具安装程序 v$VERSION ${NC}"
    echo -e "${GREEN}=====================================${NC}"
    echo ""
    
    # 解析参数
    local source_dir=""
    local api_port="$DEFAULT_API_PORT"
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source)
                source_dir="$2"
                shift 2
                ;;
            --api-port)
                api_port="$2"
                shift 2
                ;;
            --help)
                echo "用法: $0 install [选项]"
                echo ""
                echo "选项:"
                echo "  --source DIR    使用本地源代码目录"
                echo "  --api-port NUM  指定API服务的端口，默认56789"
                echo "  --help          显示此帮助信息"
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                exit 1
                ;;
        esac
    done
    
    # 开始安装流程
    check_requirements
    install_firewalld
    
    # 如果提供了源代码目录，则需要编译
    if [ -n "$source_dir" ]; then
        log_info "使用源代码目录进行编译..."
        install_dependencies
        get_source "$source_dir"
        build_code
    else
        # 首先尝试直接获取预编译的二进制文件
        log_info "尝试使用预编译的二进制文件..."
        if get_prebuilt_binary; then
            log_info "成功使用预编译的二进制文件，跳过编译步骤"
        else
            # 如果预编译文件不可用，则回退到编译模式
            log_warn "预编译的二进制文件不可用，将使用源代码编译"
            install_dependencies
            get_source ""
            build_code
        fi
    fi
    
    create_config "$api_port"
    create_service
    install_files
    start_service
    print_completion
}

#####################################################
# 主入口
#####################################################

# 显示帮助信息
show_help() {
    local cmd_name=$(basename "$0")
    if [ "$cmd_name" = "pfv" ]; then
        cmd_name="pfv"
    fi
    
    echo -e "\n使用方法: $cmd_name [命令] [参数]\n"
    echo -e "命令:"
    echo -e "  install\t安装PFV工具"
    echo -e "  uninstall\t卸载PFV工具"
    echo -e "  add <端口> [阈值GB]\t添加端口到监控列表，可选阈值(GB)"
    echo -e "  del <端口>\t从监控列表移除端口"
    echo -e "  res <端口>\t重置端口的流量统计"
    echo -e "  all\t\t显示所有端口的流量统计"
    echo -e "  status\t显示PFV服务状态"
    echo -e "  help\t\t显示此帮助信息\n"
}

# 主函数 - 根据命令或安装状态决定执行模式
main() {
    # 如果二进制已安装且不是安装命令，进入管理模式
    if check_installed && [ "$1" != "install" ] && [ "$1" != "--install" ]; then
        handle_command "$@"
    else
        # 否则进入安装模式
        install_pfv "$@"
    fi
}

# 执行主函数
main "$@"
