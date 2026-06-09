#!/bin/bash

MINISH_VERSION="1.0.0"
if [ "$(id -u 2>/dev/null)" = "0" ]; then
    MINISH_LOG_FILE="${MINISH_LOG_FILE:-/var/log/minish.log}"
else
    MINISH_LOG_FILE="${MINISH_LOG_FILE:-$HOME/.minish.log}"
fi
MINISH_BACKUP_DIR="${MINISH_BACKUP_DIR:-$HOME/.minish/backups}"
MINISH_REPORT_DIR="${MINISH_REPORT_DIR:-$HOME/.minish/reports}"
DOCKER_COMPOSE_CMD=()
DOWNLOADED_SCRIPT=""

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

clear_screen() {
    if [ -n "${TERM:-}" ] && [ "${TERM:-}" != "dumb" ] && command_exists clear; then
        command clear
    fi
}

log_action() {
    local level="$1"
    local message="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '[%s] [%s] %s\n' "$ts" "$level" "$message" >> "$MINISH_LOG_FILE" 2>/dev/null || true
}

info() {
    echo "[INFO] $1"
    log_action "INFO" "$1"
}

warn() {
    echo "[WARN] $1"
    log_action "WARN" "$1"
}

error() {
    echo "[ERROR] $1"
    log_action "ERROR" "$1"
}

pause_return() {
    read -r -p "按回车键继续..." _
}

confirm_action() {
    local prompt="$1"
    local answer
    read -r -p "$prompt [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_positive_int() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ]
}

detect_pkg_manager() {
    for pm in apt dnf yum apk pacman zypper; do
        if command_exists "$pm"; then
            echo "$pm"
            return
        fi
    done
    echo "unknown"
}

common_package_list() {
    local pm="$1"
    case "$pm" in
        apt)
            echo "curl wget sudo vim nano git jq unzip tar lsof dnsutils iproute2 iputils-ping netcat-openbsd traceroute ca-certificates gnupg iperf3"
            ;;
        dnf|yum)
            echo "curl wget sudo vim nano git jq unzip tar lsof bind-utils iproute iputils nmap-ncat traceroute ca-certificates iperf3"
            ;;
        apk)
            echo "curl wget sudo vim nano git jq unzip tar lsof bind-tools iproute2 iputils netcat-openbsd traceroute ca-certificates iperf3"
            ;;
        pacman)
            echo "curl wget sudo vim nano git jq unzip tar lsof bind iproute2 iputils openbsd-netcat traceroute ca-certificates iperf3"
            ;;
        zypper)
            echo "curl wget sudo vim nano git jq unzip tar lsof bind-utils iproute2 iputils netcat-openbsd traceroute ca-certificates iperf3"
            ;;
        *)
            echo ""
            ;;
    esac
}

install_packages_by_manager() {
    local pm="$1"
    shift
    case "$pm" in
        apt)
            sudo apt update && sudo apt install -y "$@"
            ;;
        dnf)
            sudo dnf install -y "$@"
            ;;
        yum)
            sudo yum install -y "$@"
            ;;
        apk)
            sudo apk add "$@"
            ;;
        pacman)
            sudo pacman -Sy --noconfirm "$@"
            ;;
        zypper)
            sudo zypper install -y "$@"
            ;;
        *)
            error "不支持的包管理器：$pm"
            return 1
            ;;
    esac
}

install_common_packages_menu() {
    local pm
    local packages
    local extra_packages
    local -a package_array

    pm=$(detect_pkg_manager)
    if [ "$pm" = "unknown" ]; then
        echo "未检测到支持的包管理器。"
        pause_return
        return 1
    fi

    packages=$(common_package_list "$pm")
    echo "检测到包管理器：$pm"
    echo "将安装以下常用软件包："
    printf "%s\n" "$packages" | tr ' ' '\n'
    echo
    read -p "可追加额外包名（空格分隔，可留空）: " extra_packages
    packages="$packages $extra_packages"
    read -r -a package_array <<< "$packages"

    if ! confirm_action "确认安装以上软件包吗？"; then
        echo "已取消。"
        pause_return
        return 1
    fi

    install_packages_by_manager "$pm" "${package_array[@]}"
    pause_return
}

detect_service_manager() {
    if command_exists systemctl && [ -d /run/systemd/system ]; then
        echo "systemd"
    elif command_exists rc-service; then
        echo "openrc"
    elif command_exists service; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

service_action() {
    local action="$1"
    local service_name="$2"
    local manager
    manager=$(detect_service_manager)

    case "$manager" in
        systemd)
            sudo systemctl "$action" "$service_name"
            ;;
        openrc)
            sudo rc-service "$service_name" "$action"
            ;;
        sysvinit)
            sudo service "$service_name" "$action"
            ;;
        *)
            error "未检测到可用的服务管理器。"
            return 1
            ;;
    esac
}

service_enable() {
    local service_name="$1"
    local manager
    manager=$(detect_service_manager)

    case "$manager" in
        systemd)
            sudo systemctl enable "$service_name"
            ;;
        openrc)
            sudo rc-update add "$service_name" default
            ;;
        sysvinit)
            if command_exists update-rc.d; then
                sudo update-rc.d "$service_name" defaults
            elif command_exists chkconfig; then
                sudo chkconfig "$service_name" on
            else
                warn "未找到 update-rc.d/chkconfig，请手动设置 $service_name 开机启动。"
                return 1
            fi
            ;;
        *)
            warn "未检测到可用的服务管理器，请手动设置 $service_name 开机启动。"
            return 1
            ;;
    esac
}

service_disable() {
    local service_name="$1"
    local manager
    manager=$(detect_service_manager)

    case "$manager" in
        systemd)
            sudo systemctl disable "$service_name"
            ;;
        openrc)
            sudo rc-update del "$service_name" default
            ;;
        sysvinit)
            if command_exists update-rc.d; then
                sudo update-rc.d -f "$service_name" remove
            elif command_exists chkconfig; then
                sudo chkconfig "$service_name" off
            else
                warn "未找到 update-rc.d/chkconfig，请手动取消 $service_name 开机启动。"
                return 1
            fi
            ;;
        *)
            warn "未检测到可用的服务管理器，请手动取消 $service_name 开机启动。"
            return 1
            ;;
    esac
}

backup_file() {
    local path="$1"
    local backup_path
    if [ ! -f "$path" ]; then
        warn "未找到可备份文件：$path"
        return 1
    fi
    backup_path="${path}.minish.bak.$(date '+%Y%m%d-%H%M%S')"
    if sudo cp -p "$path" "$backup_path"; then
        info "已备份 $path 到 $backup_path"
        return 0
    fi
    error "备份失败：$path"
    return 1
}

backup_crontab() {
    local backup_path="$MINISH_BACKUP_DIR/crontab.$(date '+%Y%m%d-%H%M%S').bak"
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || return 1
    if crontab -l > "$backup_path" 2>/dev/null; then
        info "已备份当前用户 crontab 到 $backup_path"
        return 0
    fi
    warn "当前用户没有可备份的 crontab。"
    return 1
}

backup_file_to_store() {
    local source_path="$1"
    local label="$2"
    local backup_path="$MINISH_BACKUP_DIR/${label}.$(date '+%Y%m%d-%H%M%S').bak"
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || {
        error "无法创建备份目录：$MINISH_BACKUP_DIR"
        return 1
    }
    if [ ! -f "$source_path" ]; then
        warn "未找到可备份文件：$source_path"
        return 1
    fi
    if sudo cp -p "$source_path" "$backup_path"; then
        sudo chown "$(id -u)":"$(id -g)" "$backup_path" 2>/dev/null || true
        info "已备份 $source_path 到 $backup_path"
        return 0
    fi
    error "备份失败：$source_path"
    return 1
}

backup_directory_to_store() {
    local source_path="$1"
    local label="$2"
    local backup_path="$MINISH_BACKUP_DIR/${label}.$(date '+%Y%m%d-%H%M%S').tar.gz"
    local parent_dir
    local base_name

    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || {
        error "无法创建备份目录：$MINISH_BACKUP_DIR"
        return 1
    }
    if [ ! -d "$source_path" ]; then
        warn "未找到可备份目录：$source_path"
        return 1
    fi
    if ! command_exists tar; then
        error "缺少 tar，无法备份目录：$source_path"
        return 1
    fi

    parent_dir=$(dirname "$source_path")
    base_name=$(basename "$source_path")
    if sudo tar -czf "$backup_path" -C "$parent_dir" "$base_name"; then
        sudo chown "$(id -u)":"$(id -g)" "$backup_path" 2>/dev/null || true
        info "已备份目录 $source_path 到 $backup_path"
        return 0
    fi
    error "目录备份失败：$source_path"
    return 1
}

safe_clean_directory_contents() {
    local target_dir="$1"
    local label="$2"
    local sudo_mode="${3:-false}"
    local resolved_dir

    if [ -z "$target_dir" ] || [ "$target_dir" = "/" ]; then
        error "拒绝清理危险目录：$target_dir"
        return 1
    fi
    if [ ! -d "$target_dir" ]; then
        warn "目录不存在，跳过：$target_dir"
        return 0
    fi

    resolved_dir=$(cd "$target_dir" 2>/dev/null && pwd -P) || {
        error "无法解析目录：$target_dir"
        return 1
    }

    case "$resolved_dir" in
        /tmp|/private/tmp|/var/tmp|/private/var/tmp|"$HOME/.cache"|"$HOME/.local/share/Trash")
            ;;
        *)
            error "拒绝清理未列入允许清单的目录：$resolved_dir"
            return 1
            ;;
    esac

    echo "即将清理 $label：$resolved_dir"
    if ! confirm_action "确认删除该目录下的直接子项吗？不会删除目录本身"; then
        echo "已取消。"
        return 1
    fi

    if [ "$sudo_mode" = "true" ]; then
        sudo find "$resolved_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    else
        find "$resolved_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    fi
}

download_external_script() {
    local label="$1"
    local url="$2"
    local destination="${3:-}"
    local script_path

    DOWNLOADED_SCRIPT=""
    if [ -z "$label" ] || [ -z "$url" ]; then
        error "外部脚本名称或 URL 为空。"
        return 1
    fi

    echo "外部脚本：$label"
    echo "来源 URL：$url"
    warn "该操作会下载并执行第三方脚本，请确认来源可信。"
    if ! confirm_action "确认下载该脚本吗？"; then
        echo "已取消。"
        return 1
    fi

    if [ -n "$destination" ]; then
        script_path="$destination"
    else
        script_path=$(mktemp /tmp/minish-external-script.XXXXXX.sh) || {
            error "无法创建临时脚本文件。"
            return 1
        }
    fi

    if command_exists curl; then
        if ! curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$script_path"; then
            [ -z "$destination" ] && rm -f "$script_path"
            error "下载失败：$url"
            return 1
        fi
    elif command_exists wget; then
        if ! wget -q -O "$script_path" "$url"; then
            [ -z "$destination" ] && rm -f "$script_path"
            error "下载失败：$url"
            return 1
        fi
    else
        [ -z "$destination" ] && rm -f "$script_path"
        error "缺少 curl/wget，无法下载外部脚本。"
        return 1
    fi

    chmod +x "$script_path" 2>/dev/null || true
    DOWNLOADED_SCRIPT="$script_path"
    info "脚本已下载到：$script_path"
}

run_local_external_script() {
    local label="$1"
    local script_path="$2"
    local interpreter="${3:-bash}"
    if [ "$#" -gt 3 ]; then
        shift 3
    else
        set --
    fi

    if [ ! -f "$script_path" ]; then
        error "脚本不存在：$script_path"
        return 1
    fi

    echo "准备执行外部脚本：$label"
    echo "本地路径：$script_path"
    warn "请确认脚本内容和来源可信。"
    if ! confirm_action "确认执行该脚本吗？"; then
        echo "已取消。"
        return 1
    fi

    chmod +x "$script_path" 2>/dev/null || true
    "$interpreter" "$script_path" "$@"
}

run_external_script() {
    local label="$1"
    local url="$2"
    local interpreter="${3:-bash}"
    local destination="${4:-}"
    local script_path
    local status
    if [ "$#" -gt 4 ]; then
        shift 4
    else
        set --
    fi

    download_external_script "$label" "$url" "$destination" || return 1
    script_path="$DOWNLOADED_SCRIPT"

    if ! confirm_action "确认现在执行 $label 吗？"; then
        [ -z "$destination" ] && rm -f "$script_path"
        echo "已取消执行。"
        return 1
    fi

    "$interpreter" "$script_path" "$@"
    status=$?
    [ -z "$destination" ] && rm -f "$script_path"
    return "$status"
}

run_external_executable() {
    local label="$1"
    local url="$2"
    local destination="${3:-}"
    local executable_path
    local status
    if [ "$#" -gt 3 ]; then
        shift 3
    else
        set --
    fi

    download_external_script "$label" "$url" "$destination" || return 1
    executable_path="$DOWNLOADED_SCRIPT"

    if ! confirm_action "确认现在执行 $label 吗？"; then
        [ -z "$destination" ] && rm -f "$executable_path"
        echo "已取消执行。"
        return 1
    fi

    "$executable_path" "$@"
    status=$?
    [ -z "$destination" ] && rm -f "$executable_path"
    return "$status"
}

backup_ufw_rules() {
    local backup_path="$MINISH_BACKUP_DIR/ufw-status.$(date '+%Y%m%d-%H%M%S').txt"
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || return 1
    if ! command_exists ufw; then
        warn "未安装 ufw，跳过 UFW 规则备份。"
        return 1
    fi
    if sudo ufw status numbered > "$backup_path"; then
        info "已备份 UFW 状态到 $backup_path"
        return 0
    fi
    error "UFW 状态备份失败。"
    return 1
}

backup_ufw_config() {
    local backup_path="$MINISH_BACKUP_DIR/ufw-config.$(date '+%Y%m%d-%H%M%S').tar.gz"
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || {
        error "无法创建备份目录：$MINISH_BACKUP_DIR"
        return 1
    }
    if [ ! -d /etc/ufw ]; then
        warn "未找到 /etc/ufw，无法备份 UFW 可恢复配置。"
        return 1
    fi
    if ! command_exists tar; then
        error "缺少 tar，无法归档 /etc/ufw。"
        return 1
    fi

    if sudo tar -czf "$backup_path" -C /etc ufw; then
        sudo chown "$(id -u)":"$(id -g)" "$backup_path" 2>/dev/null || true
        info "已备份 UFW 可恢复配置到 $backup_path"
        return 0
    fi
    error "UFW 可恢复配置备份失败。"
    return 1
}

select_backup_file() {
    local pattern="$1"
    local title="$2"
    local idx choice
    local -a backups
    SELECTED_BACKUP=""
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || return 1
    mapfile -t backups < <(find "$MINISH_BACKUP_DIR" -maxdepth 1 -type f -name "$pattern" -print 2>/dev/null | sort)

    if [ "${#backups[@]}" -eq 0 ]; then
        echo "未找到可用备份：$pattern"
        return 1
    fi

    echo "$title"
    echo "0. 取消"
    for idx in "${!backups[@]}"; do
        printf "%d. %s\n" "$((idx + 1))" "${backups[$idx]}"
    done

    read -p "请选择备份编号: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#backups[@]}" ]; then
        echo "无效编号。"
        return 1
    fi
    if [ "$choice" -eq 0 ]; then
        echo "已取消。"
        return 1
    fi

    SELECTED_BACKUP="${backups[$((choice - 1))]}"
    return 0
}

restore_file_backup() {
    local pattern="$1"
    local target="$2"
    local label="$3"
    local chmod_mode="${4:-644}"

    select_backup_file "$pattern" "可恢复的 $label 备份：" || return 1
    echo "将恢复：$SELECTED_BACKUP"
    echo "目标文件：$target"
    if ! confirm_action "确认恢复 $label 吗？恢复前会先备份当前文件"; then
        echo "已取消。"
        return 1
    fi

    backup_file_to_store "$target" "${label}.before-restore"
    if sudo cp "$SELECTED_BACKUP" "$target"; then
        sudo chmod "$chmod_mode" "$target" 2>/dev/null || true
        info "$label 已恢复到 $target"
        return 0
    fi

    error "$label 恢复失败。"
    return 1
}

restore_ssh_config() {
    restore_file_backup "sshd_config.*.bak" "/etc/ssh/sshd_config" "sshd_config" "644" || return 1
    if command_exists sshd; then
        if sshd -t >/dev/null 2>&1; then
            echo "sshd 配置检查通过。"
        else
            warn "sshd 配置检查失败，请手动检查 /etc/ssh/sshd_config。"
            return 1
        fi
    else
        warn "缺少 sshd，已跳过配置检查。"
    fi

    if confirm_action "是否立即重启 SSH 服务以应用恢复结果？"; then
        service_action restart ssh || service_action restart sshd || warn "SSH 服务重启失败，请手动处理。"
    fi
}

restore_dns_config() {
    restore_file_backup "resolv.conf.*.bak" "/etc/resolv.conf" "resolv.conf" "644"
}

restore_crontab_backup() {
    select_backup_file "crontab.*.bak" "可恢复的 crontab 备份：" || return 1
    if ! confirm_action "确认用该备份覆盖当前用户 crontab 吗？恢复前会先备份当前 crontab"; then
        echo "已取消。"
        return 1
    fi

    backup_crontab
    if crontab "$SELECTED_BACKUP"; then
        info "当前用户 crontab 已从 $SELECTED_BACKUP 恢复。"
        return 0
    fi
    error "crontab 恢复失败。"
    return 1
}

restore_ufw_config() {
    if ! command_exists tar; then
        error "缺少 tar，无法恢复 UFW 配置归档。"
        return 1
    fi

    select_backup_file "ufw-config.*.tar.gz" "可恢复的 UFW 配置归档：" || return 1
    echo "将恢复：$SELECTED_BACKUP"
    echo "目标目录：/etc/ufw"
    warn "该操作会覆盖 /etc/ufw。恢复前会先备份当前 /etc/ufw。"
    if ! confirm_action "确认恢复 UFW 可恢复配置吗？"; then
        echo "已取消。"
        return 1
    fi

    backup_ufw_config
    if sudo tar -tzf "$SELECTED_BACKUP" 2>/dev/null | grep -q '^ufw/'; then
        if sudo tar -xzf "$SELECTED_BACKUP" -C /etc; then
            info "UFW 配置已恢复到 /etc/ufw"
        else
            error "UFW 配置恢复失败。"
            return 1
        fi
    else
        error "归档内容不包含 ufw/ 目录，已拒绝恢复。"
        return 1
    fi

    if command_exists ufw && confirm_action "是否立即 reload UFW 以应用恢复结果？"; then
        sudo ufw reload || warn "UFW reload 失败，请手动检查。"
    fi
}

# 获取系统信息
get_os_name() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$NAME"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID"
    elif [ -f /etc/redhat-release ]; then
        echo "CentOS"
    else
        echo "未知的系统"
    fi
}

OS_NAME=$(get_os_name)

# 获取虚拟化类型
get_virtualization_type() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TYPE=$(systemd-detect-virt)
    elif command -v virt-what >/dev/null 2>&1; then
        VIRT_TYPE=$(virt-what)
    else
        VIRT_TYPE="无法检测到虚拟化类型"
    fi
    echo "$VIRT_TYPE"
}

VIRT_TYPE=$(get_virtualization_type)

print_kv() {
    printf "%-18s %s\n" "$1" "$2"
}

report_section() {
    printf "\n===== %s =====\n" "$1"
}

run_report_cmd() {
    local fallback="$1"
    shift
    "$@" 2>&1 || echo "$fallback"
}

get_ssh_option() {
    local option="$1"
    local config="/etc/ssh/sshd_config"
    if [ ! -r "$config" ]; then
        echo "无法读取"
        return
    fi
    awk -v key="$option" '
        BEGIN { result = "默认/未设置" }
        $0 ~ /^[[:space:]]*#/ { next }
        tolower($1) == tolower(key) { result = $2 }
        END { print result }
    ' "$config"
}

get_effective_ssh_port() {
    local port
    port=$(get_ssh_option Port)
    if validate_port "$port"; then
        echo "$port"
    else
        echo "22"
    fi
}

set_sshd_option() {
    local option="$1"
    local value="$2"
    local config="/etc/ssh/sshd_config"

    if [ ! -f "$config" ]; then
        error "未找到 SSH 配置文件：$config"
        return 1
    fi

    if grep -qiE "^[#[:space:]]*${option}[[:space:]]+" "$config"; then
        sudo sed -i.bak -E "s|^[#[:space:]]*${option}[[:space:]].*|${option} ${value}|I" "$config"
    else
        echo "${option} ${value}" | sudo tee -a "$config" >/dev/null
    fi
}

test_sshd_config() {
    if ! command_exists sshd; then
        warn "缺少 sshd，无法执行配置语法检查。"
        return 0
    fi
    if sshd -t >/dev/null 2>&1; then
        echo "sshd 配置检查通过。"
        return 0
    fi
    error "sshd 配置检查失败。"
    return 1
}

restart_ssh_service() {
    service_action restart ssh || service_action restart sshd
}

ensure_ufw_allows_port() {
    local port="$1"
    if ! command_exists ufw; then
        return 0
    fi
    if ufw status 2>/dev/null | grep -iq "Status: inactive"; then
        return 0
    fi
    if ufw status 2>/dev/null | grep -Eq "(^|[[:space:]])${port}/tcp"; then
        echo "UFW 已存在 $port/tcp 规则。"
        return 0
    fi
    if confirm_action "检测到 UFW 可能已启用，是否放行 ${port}/tcp？"; then
        sudo ufw allow "${port}/tcp"
    fi
}

install_ufw_if_missing() {
    local pm
    if command_exists ufw; then
        return 0
    fi

    pm=$(detect_pkg_manager)
    echo "未检测到 UFW。"
    if ! confirm_action "是否现在安装 UFW？"; then
        return 1
    fi

    case "$pm" in
        apt)
            sudo apt update && sudo apt install -y ufw
            ;;
        dnf)
            sudo dnf install -y ufw
            ;;
        yum)
            sudo yum install -y ufw
            ;;
        apk)
            sudo apk add ufw
            ;;
        pacman)
            sudo pacman -Sy --noconfirm ufw
            ;;
        zypper)
            sudo zypper install -y ufw
            ;;
        *)
            error "不支持的包管理器，请手动安装 UFW。"
            return 1
            ;;
    esac
}

ufw_is_active() {
    command_exists ufw && ufw status 2>/dev/null | grep -iq "Status: active"
}

ufw_rule_exists_for_port() {
    local port="$1"
    local proto="${2:-tcp}"
    command_exists ufw || return 1
    ufw status 2>/dev/null | grep -Eq "(^|[[:space:]])${port}(/${proto})?([[:space:]]|$)"
}

ufw_allow_port() {
    local port="$1"
    local proto="${2:-tcp}"
    local comment="$3"

    if ! validate_port "$port"; then
        echo "无效端口：$port"
        return 1
    fi

    install_ufw_if_missing || return 1
    if ufw_rule_exists_for_port "$port" "$proto"; then
        echo "规则已存在：${port}/${proto}"
        return 0
    fi

    backup_ufw_rules
    if [ -n "$comment" ]; then
        sudo ufw allow "${port}/${proto}" comment "$comment"
    else
        sudo ufw allow "${port}/${proto}"
    fi
}

ufw_ensure_ssh_allowed() {
    local ssh_port
    ssh_port=$(get_effective_ssh_port)
    echo "当前 SSH 端口：$ssh_port"
    ufw_allow_port "$ssh_port" "tcp" "MiniSH SSH"
}

ufw_enable_safely() {
    local ssh_port
    install_ufw_if_missing || return 1
    ssh_port=$(get_effective_ssh_port)
    echo "启用 UFW 前检查 SSH 端口：$ssh_port/tcp"

    if ! ufw_rule_exists_for_port "$ssh_port" "tcp"; then
        warn "未发现 SSH 端口 $ssh_port/tcp 的放行规则。"
        if ! confirm_action "是否先放行 SSH 端口 $ssh_port/tcp？"; then
            warn "为避免锁定 SSH，已取消启用 UFW。"
            return 1
        fi
        ufw_allow_port "$ssh_port" "tcp" "MiniSH SSH" || return 1
    fi

    backup_ufw_rules
    if confirm_action "确认启用 UFW 吗？"; then
        sudo ufw --force enable
    else
        echo "已取消。"
    fi
}

ufw_show_status() {
    if ! command_exists ufw; then
        echo "未安装 UFW。"
        return
    fi
    ufw status verbose
}

ufw_disable_safely() {
    install_ufw_if_missing || return 1
    if confirm_action "确认禁用 UFW 吗？"; then
        backup_ufw_rules
        sudo ufw disable
    else
        echo "已取消。"
    fi
}

ufw_restart_safely() {
    install_ufw_if_missing || return 1
    echo "将先禁用再安全启用 UFW。"
    if ! confirm_action "确认重启 UFW 吗？"; then
        echo "已取消。"
        return 1
    fi
    backup_ufw_rules
    sudo ufw disable
    ufw_enable_safely
}

ufw_delete_rule_safely() {
    local rule_num
    install_ufw_if_missing || return 1
    ufw status numbered
    read -p "请输入要删除的规则编号: " rule_num
    if ! [[ "$rule_num" =~ ^[0-9]+$ ]] || [ "$rule_num" -lt 1 ]; then
        echo "规则编号无效。"
        return 1
    fi
    if confirm_action "确认删除 UFW 规则 [$rule_num] 吗？"; then
        backup_ufw_rules
        sudo ufw delete "$rule_num"
    else
        echo "已取消。"
    fi
}

ufw_reset_safely() {
    install_ufw_if_missing || return 1
    echo "警告：该操作会删除所有 UFW 规则并重置防火墙。"
    if confirm_action "确认 reset UFW 吗？"; then
        backup_ufw_rules
        sudo ufw --force reset
    else
        echo "已取消。"
    fi
}

apply_sshd_option_change() {
    local option="$1"
    local value="$2"
    local description="$3"

    echo "即将设置：$option $value"
    if ! confirm_action "确认修改 $description 吗？"; then
        echo "已取消。"
        return 1
    fi

    backup_file_to_store "/etc/ssh/sshd_config" "sshd_config"
    set_sshd_option "$option" "$value" || return 1
    if ! test_sshd_config; then
        warn "配置检查失败，请从配置备份菜单恢复 sshd_config。"
        return 1
    fi

    if confirm_action "是否立即重启 SSH 服务以应用修改？"; then
        restart_ssh_service || warn "SSH 服务重启失败，请手动检查。"
    fi
}

install_ssh_public_key() {
    local target_user
    local public_key
    local user_home
    local ssh_dir
    local auth_file

    read -p "请输入目标用户（默认当前用户 $(whoami)）: " target_user
    target_user=${target_user:-$(whoami)}
    if ! id "$target_user" >/dev/null 2>&1; then
        echo "用户不存在：$target_user"
        return 1
    fi

    echo "请输入 SSH 公钥（以 ssh-rsa、ssh-ed25519 等开头）："
    read -r public_key
    if ! [[ "$public_key" =~ ^ssh-(rsa|ed25519|ecdsa)[[:space:]]+ ]]; then
        echo "公钥格式看起来不正确。"
        return 1
    fi

    user_home=$(eval echo "~$target_user")
    ssh_dir="$user_home/.ssh"
    auth_file="$ssh_dir/authorized_keys"

    if ! confirm_action "确认将该公钥追加到 $auth_file 吗？"; then
        echo "已取消。"
        return 1
    fi

    sudo mkdir -p "$ssh_dir"
    if [ -f "$auth_file" ]; then
        backup_file_to_store "$auth_file" "authorized_keys.${target_user}"
    fi
    if sudo grep -Fxq "$public_key" "$auth_file" 2>/dev/null; then
        echo "该公钥已存在。"
    else
        echo "$public_key" | sudo tee -a "$auth_file" >/dev/null
        echo "公钥已追加。"
    fi
    sudo chown -R "$target_user":"$target_user" "$ssh_dir" 2>/dev/null || true
    sudo chmod 700 "$ssh_dir"
    sudo chmod 600 "$auth_file"
}

fail2ban_require_client() {
    if command_exists fail2ban-client; then
        return 0
    fi
    echo "未检测到 fail2ban-client，请先安装 Fail2ban。"
    return 1
}

install_fail2ban_if_missing() {
    local pm
    if command_exists fail2ban-client; then
        echo "Fail2ban 已安装。"
        return 0
    fi

    pm=$(detect_pkg_manager)
    if [ "$pm" = "unknown" ]; then
        error "未检测到支持的包管理器，请手动安装 Fail2ban。"
        return 1
    fi

    echo "检测到包管理器：$pm"
    if ! confirm_action "确认安装 Fail2ban 吗？"; then
        echo "已取消。"
        return 1
    fi

    install_packages_by_manager "$pm" fail2ban || return 1
    service_enable fail2ban || true
    service_action start fail2ban || warn "Fail2ban 服务启动失败，请检查配置。"
}

backup_fail2ban_config() {
    local backup_path="$MINISH_BACKUP_DIR/fail2ban-config.$(date '+%Y%m%d-%H%M%S').tar.gz"
    mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null || {
        error "无法创建备份目录：$MINISH_BACKUP_DIR"
        return 1
    }
    if [ ! -d /etc/fail2ban ]; then
        warn "未找到 /etc/fail2ban，无法备份 Fail2ban 配置。"
        return 1
    fi
    if ! command_exists tar; then
        error "缺少 tar，无法归档 Fail2ban 配置。"
        return 1
    fi

    if sudo tar -czf "$backup_path" -C /etc fail2ban; then
        sudo chown "$(id -u)":"$(id -g)" "$backup_path" 2>/dev/null || true
        info "已备份 Fail2ban 配置到 $backup_path"
        return 0
    fi
    error "Fail2ban 配置备份失败。"
    return 1
}

fail2ban_jail_list() {
    fail2ban_require_client >/dev/null || return 1
    sudo fail2ban-client status 2>/dev/null | awk -F: '
        /Jail list/ {
            gsub(/,/, " ", $2)
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            print $2
        }
    '
}

select_fail2ban_jail() {
    local jails
    local idx
    local choice
    local manual_jail
    local -a jail_array
    SELECTED_FAIL2BAN_JAIL=""

    fail2ban_require_client || return 1
    jails=$(fail2ban_jail_list)
    read -r -a jail_array <<< "$jails"

    if [ "${#jail_array[@]}" -eq 0 ] || [ -z "${jail_array[0]}" ]; then
        warn "当前未读取到 jail 列表，Fail2ban 服务可能未运行。"
        read -p "可手动输入 jail 名称（留空取消）: " manual_jail
        if [ -z "$manual_jail" ]; then
            echo "已取消。"
            return 1
        fi
        SELECTED_FAIL2BAN_JAIL="$manual_jail"
        return 0
    fi

    echo "可用 jail："
    echo "0. 取消"
    for idx in "${!jail_array[@]}"; do
        printf "%d. %s\n" "$((idx + 1))" "${jail_array[$idx]}"
    done
    read -p "请选择 jail 编号: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#jail_array[@]}" ]; then
        echo "无效编号。"
        return 1
    fi
    if [ "$choice" -eq 0 ]; then
        echo "已取消。"
        return 1
    fi

    SELECTED_FAIL2BAN_JAIL="${jail_array[$((choice - 1))]}"
}

show_fail2ban_status() {
    fail2ban_require_client || return 1
    echo "[服务状态]"
    print_kv "fail2ban" "$(service_status_text fail2ban)"
    echo
    echo "[Fail2ban 状态]"
    sudo fail2ban-client status 2>&1
}

show_fail2ban_jail_status() {
    select_fail2ban_jail || return 1
    sudo fail2ban-client status "$SELECTED_FAIL2BAN_JAIL" 2>&1
}

show_fail2ban_banned_ips() {
    select_fail2ban_jail || return 1
    sudo fail2ban-client status "$SELECTED_FAIL2BAN_JAIL" 2>/dev/null \
        | awk -F: '/Banned IP list/ { gsub(/^[ \t]+/, "", $2); print $2 }'
}

set_fail2ban_ip_action() {
    local action="$1"
    local action_text="$2"
    local ip

    select_fail2ban_jail || return 1
    read -p "请输入 IP 地址: " ip
    if ! [[ "$ip" =~ ^[0-9A-Fa-f:.]+$ ]]; then
        echo "IP 地址格式不正确。"
        return 1
    fi

    if ! confirm_action "确认在 jail [$SELECTED_FAIL2BAN_JAIL] 中${action_text} $ip 吗？"; then
        echo "已取消。"
        return 1
    fi

    sudo fail2ban-client set "$SELECTED_FAIL2BAN_JAIL" "$action" "$ip"
}

configure_fail2ban_ssh_jail() {
    local ssh_port
    local maxretry
    local findtime
    local bantime
    local config_dir="/etc/fail2ban/jail.d"
    local config_path="$config_dir/minish-sshd.local"

    install_fail2ban_if_missing || return 1

    ssh_port=$(get_effective_ssh_port)
    echo "将创建/更新 SSH jail：$config_path"
    echo "当前检测到 SSH 端口：$ssh_port"
    read -p "最大失败次数 maxretry（默认 5）: " maxretry
    read -p "统计窗口 findtime 秒（默认 600）: " findtime
    read -p "封禁时长 bantime 秒（默认 3600）: " bantime
    maxretry=${maxretry:-5}
    findtime=${findtime:-600}
    bantime=${bantime:-3600}

    if ! validate_positive_int "$maxretry" || ! validate_positive_int "$findtime" || ! validate_positive_int "$bantime"; then
        echo "maxretry/findtime/bantime 必须为正整数。"
        return 1
    fi

    echo "即将写入："
    print_kv "enabled" "true"
    print_kv "port" "$ssh_port"
    print_kv "maxretry" "$maxretry"
    print_kv "findtime" "$findtime"
    print_kv "bantime" "$bantime"
    if ! confirm_action "确认写入 Fail2ban SSH jail 配置吗？"; then
        echo "已取消。"
        return 1
    fi

    if [ -f "$config_path" ]; then
        backup_file_to_store "$config_path" "fail2ban-minish-sshd.local"
    fi
    sudo mkdir -p "$config_dir"
    sudo tee "$config_path" >/dev/null <<EOF
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = %(sshd_log)s
backend = auto
maxretry = $maxretry
findtime = $findtime
bantime = $bantime
EOF

    if sudo fail2ban-client -t >/dev/null 2>&1; then
        echo "Fail2ban 配置检查通过。"
    else
        warn "Fail2ban 配置检查失败，请检查 $config_path。"
        return 1
    fi

    if confirm_action "是否立即重启 Fail2ban 应用配置？"; then
        service_action restart fail2ban || warn "Fail2ban 重启失败，请手动检查。"
    fi
}

fail2ban_management_menu() {
    while true; do
        clear_screen
        echo "Fail2ban 管理"
        echo "1. 安装/启动 Fail2ban"
        echo "2. 查看 Fail2ban 总体状态"
        echo "3. 查看 jail 状态"
        echo "4. 查看 jail 封禁 IP"
        echo "5. 手动封禁 IP"
        echo "6. 解封 IP"
        echo "7. 配置 SSH jail"
        echo "8. 备份 Fail2ban 配置"
        echo "9. 重启 Fail2ban 服务"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " fail2ban_option

        case $fail2ban_option in
            1)
                install_fail2ban_if_missing
                pause_return
                ;;
            2)
                show_fail2ban_status
                pause_return
                ;;
            3)
                show_fail2ban_jail_status
                pause_return
                ;;
            4)
                show_fail2ban_banned_ips
                pause_return
                ;;
            5)
                set_fail2ban_ip_action "banip" "封禁"
                pause_return
                ;;
            6)
                set_fail2ban_ip_action "unbanip" "解封"
                pause_return
                ;;
            7)
                configure_fail2ban_ssh_jail
                pause_return
                ;;
            8)
                backup_fail2ban_config
                pause_return
                ;;
            9)
                if confirm_action "确认重启 Fail2ban 服务吗？"; then
                    service_action restart fail2ban
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

get_auth_log_file() {
    if [ -r /var/log/auth.log ]; then
        echo "/var/log/auth.log"
    elif [ -r /var/log/secure ]; then
        echo "/var/log/secure"
    else
        echo ""
    fi
}

service_status_text() {
    local service_name="$1"
    local manager
    manager=$(detect_service_manager)

    case "$manager" in
        systemd)
            systemctl is-active "$service_name" 2>/dev/null || echo "unknown"
            ;;
        openrc)
            rc-service "$service_name" status >/dev/null 2>&1 && echo "active" || echo "inactive/unknown"
            ;;
        sysvinit)
            service "$service_name" status >/dev/null 2>&1 && echo "active" || echo "inactive/unknown"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

show_failed_login_top() {
    local auth_log
    auth_log=$(get_auth_log_file)
    if [ -z "$auth_log" ]; then
        echo "未找到可读的 auth.log/secure。"
        return
    fi
    grep -E "Failed password|authentication failure" "$auth_log" 2>/dev/null \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F:]{2,})' \
        | sort | uniq -c | sort -nr | head -n 10
}

show_dns_summary() {
    if [ -r /etc/resolv.conf ]; then
        grep -E '^[[:space:]]*nameserver' /etc/resolv.conf || echo "未配置 nameserver。"
    else
        echo "无法读取 /etc/resolv.conf。"
    fi
}

show_default_routes() {
    if command_exists ip; then
        ip route show default 2>/dev/null
        ip -6 route show default 2>/dev/null
    elif command_exists route; then
        route -n 2>/dev/null | awk '$1 == "0.0.0.0" || $1 == "default"'
    else
        echo "缺少 ip/route，无法显示默认路由。"
    fi
}

get_public_ip() {
    local family="$1"
    if ! command_exists curl; then
        echo "缺少 curl"
        return
    fi
    if [ "$family" = "4" ]; then
        curl -4 -fsS --connect-timeout 4 --max-time 6 https://api.ipify.org 2>/dev/null || echo "获取失败"
    else
        curl -6 -fsS --connect-timeout 4 --max-time 6 https://api64.ipify.org 2>/dev/null || echo "获取失败"
    fi
}

show_system_info() {
    clear_screen
    echo "===== 系统信息 ====="
    print_kv "工具版本" "$MINISH_VERSION"
    print_kv "系统" "$OS_NAME"
    print_kv "内核" "$(uname -sr 2>/dev/null)"
    print_kv "架构" "$(uname -m 2>/dev/null)"
    print_kv "虚拟化" "$VIRT_TYPE"
    print_kv "包管理器" "$(detect_pkg_manager)"
    print_kv "服务管理器" "$(detect_service_manager)"
    print_kv "运行时间" "$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
    echo

    echo "===== 资源 ====="
    if command_exists free; then
        free -h
    else
        warn "缺少 free，无法显示内存信息。"
    fi
    echo
    df -h / 2>/dev/null || warn "无法读取根分区空间。"
    echo

    echo "===== 网络 ====="
    print_kv "公网 IPv4" "$(get_public_ip 4)"
    print_kv "公网 IPv6" "$(get_public_ip 6)"
    if command_exists sysctl; then
        print_kv "TCP 拥塞控制" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 未知)"
    fi
    echo

    echo "===== 监听端口 ====="
    if command_exists ss; then
        ss -tuln | head -n 25
    elif command_exists netstat; then
        netstat -tuln | head -n 25
    else
        warn "缺少 ss/netstat，无法显示监听端口。"
    fi
    echo

    echo "===== 最近登录 ====="
    if command_exists last; then
        last -n 8 2>/dev/null
    else
        warn "缺少 last，无法显示登录记录。"
    fi
    [ "$MINISH_SKIP_PAUSE" = "true" ] || pause_return
}

doctor_check_cmd() {
    local cmd="$1"
    if command_exists "$cmd"; then
        printf "[OK]      %s\n" "$cmd"
    else
        printf "[MISSING] %s\n" "$cmd"
    fi
}

doctor_check_url() {
    local name="$1"
    local url="$2"
    if ! command_exists curl; then
        printf "[SKIP]    %s：缺少 curl\n" "$name"
        return
    fi
    if curl -fsSI --connect-timeout 5 --max-time 8 "$url" >/dev/null 2>&1; then
        printf "[OK]      %s\n" "$name"
    else
        printf "[WARN]    %s：无法访问 %s\n" "$name" "$url"
    fi
}

run_doctor() {
    clear_screen
    echo "===== MiniSH 自检 ====="
    print_kv "工具版本" "$MINISH_VERSION"
    print_kv "系统" "$OS_NAME"
    print_kv "虚拟化" "$VIRT_TYPE"
    print_kv "包管理器" "$(detect_pkg_manager)"
    print_kv "服务管理器" "$(detect_service_manager)"
    print_kv "日志文件" "$MINISH_LOG_FILE"
    echo

    echo "===== 依赖命令 ====="
    for cmd in bash curl wget sudo awk sed grep systemctl service ss lsof ufw docker dig iptables; do
        doctor_check_cmd "$cmd"
    done
    echo

    echo "===== 网络连通性 ====="
    doctor_check_url "GitHub Raw" "https://raw.githubusercontent.com"
    doctor_check_url "Telegram API" "https://api.telegram.org"
    doctor_check_url "Docker Hub" "https://hub.docker.com"
    echo

    echo "自检完成。缺失项不一定影响所有功能，但会影响对应菜单。"
    [ "$MINISH_SKIP_PAUSE" = "true" ] || pause_return
}

get_quality_scan_root() {
    local script_dir
    local script_parent
    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd -P)
    if [ -z "$script_dir" ]; then
        pwd -P
        return
    fi

    if [ "$(basename "$script_dir")" = "VPSTool" ]; then
        script_parent=$(cd "$script_dir/.." 2>/dev/null && pwd -P)
        echo "${script_parent:-$script_dir}"
    else
        echo "$script_dir"
    fi
}

find_shell_scripts() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    find "$scan_root" -maxdepth 6 \
        \( -name ".git" -o \
           -name ".agents" -o \
           -name ".codex" -o \
           -name "node_modules" -o \
           -name ".venv" -o \
           -name "venv" \) -type d -prune -o \
        -type f -name "*.sh" -print 2>/dev/null | sort
}

quality_bash_syntax_check() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    local script_file
    local total=0
    local failed=0

    echo "[bash -n 语法检查]"
    while IFS= read -r script_file; do
        [ -n "$script_file" ] || continue
        total=$((total + 1))
        if bash -n "$script_file" >/dev/null 2>&1; then
            printf "[OK]   %s\n" "$script_file"
        else
            failed=$((failed + 1))
            printf "[FAIL] %s\n" "$script_file"
            bash -n "$script_file" 2>&1 | sed 's/^/       /'
        fi
    done < <(find_shell_scripts "$scan_root")

    print_kv "检查脚本数" "$total"
    print_kv "失败数" "$failed"
    [ "$failed" -eq 0 ]
}

quality_crlf_check() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    local script_file
    local total=0
    local failed=0

    echo "[CRLF 行尾检查]"
    while IFS= read -r script_file; do
        [ -n "$script_file" ] || continue
        total=$((total + 1))
        if LC_ALL=C grep -q $'\r' "$script_file" 2>/dev/null; then
            failed=$((failed + 1))
            printf "[CRLF] %s\n" "$script_file"
        fi
    done < <(find_shell_scripts "$scan_root")

    if [ "$failed" -eq 0 ]; then
        echo "未发现 CRLF 行尾。"
    fi
    print_kv "检查脚本数" "$total"
    print_kv "问题文件数" "$failed"
    [ "$failed" -eq 0 ]
}

quality_dangerous_command_scan() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    local script_file
    local total=0
    local hits=0
    local pattern
    pattern='rm[[:space:]]+-rf[[:space:]]+/|mkfs\.|dd[[:space:]].*of=/dev/|chmod[[:space:]]+-R[[:space:]]+777[[:space:]]+/|chown[[:space:]]+-R[[:space:]].*[[:space:]]+/|:[[:space:]]*\(\)[[:space:]]*\{[[:space:]]*:[[:space:]]*\|[[:space:]]*:[[:space:]]*&[[:space:]]*\}|curl[[:space:]].*\|[[:space:]]*(sh|bash)|wget[[:space:]].*\|[[:space:]]*(sh|bash)'

    echo "[危险命令扫描]"
    echo "说明：这是静态启发式扫描，命中项需要人工判断。"
    while IFS= read -r script_file; do
        [ -n "$script_file" ] || continue
        total=$((total + 1))
        if grep -nE "$pattern" "$script_file" >/dev/null 2>&1; then
            printf "[REVIEW] %s\n" "$script_file"
            grep -nE "$pattern" "$script_file" | sed 's/^/         /'
            hits=$((hits + 1))
        fi
    done < <(find_shell_scripts "$scan_root")

    if [ "$hits" -eq 0 ]; then
        echo "未发现高风险命令模式。"
    fi
    print_kv "检查脚本数" "$total"
    print_kv "命中文件数" "$hits"
    return 0
}

quality_shellcheck_scan() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    local script_file
    local total=0
    local failed=0

    echo "[ShellCheck 检查]"
    if ! command_exists shellcheck; then
        echo "未安装 shellcheck，已跳过。"
        return 0
    fi

    while IFS= read -r script_file; do
        [ -n "$script_file" ] || continue
        total=$((total + 1))
        if shellcheck "$script_file"; then
            printf "[OK]   %s\n" "$script_file"
        else
            failed=$((failed + 1))
            printf "[WARN] %s\n" "$script_file"
        fi
    done < <(find_shell_scripts "$scan_root")

    print_kv "检查脚本数" "$total"
    print_kv "ShellCheck 告警文件数" "$failed"
    [ "$failed" -eq 0 ]
}

run_quality_checks() {
    local scan_root="${1:-$(get_quality_scan_root)}"
    local status=0

    echo "===== 脚本质量检查 ====="
    print_kv "工具版本" "$MINISH_VERSION"
    print_kv "扫描目录" "$scan_root"
    echo

    quality_bash_syntax_check "$scan_root" || status=1
    echo
    quality_crlf_check "$scan_root" || status=1
    echo
    quality_dangerous_command_scan "$scan_root" || true
    echo
    quality_shellcheck_scan "$scan_root" || status=1
    echo

    if [ "$status" -eq 0 ]; then
        echo "质量检查完成：未发现阻断项。"
    else
        echo "质量检查完成：存在需要修复或人工确认的问题。"
    fi
    return "$status"
}

generate_quality_report() {
    local report_path
    mkdir -p "$MINISH_REPORT_DIR" 2>/dev/null || {
        error "无法创建报告目录：$MINISH_REPORT_DIR"
        return 1
    }
    report_path="$MINISH_REPORT_DIR/quality-$(date '+%Y%m%d-%H%M%S').txt"

    if run_quality_checks > "$report_path" 2>&1; then
        echo "$report_path"
        return 0
    fi
    echo "$report_path"
    return 1
}

script_quality_menu() {
    local scan_root
    scan_root=$(get_quality_scan_root)

    while true; do
        clear_screen
        echo "脚本质量工具"
        echo "扫描目录：$scan_root"
        echo "1. 执行全部质量检查"
        echo "2. bash -n 语法检查"
        echo "3. CRLF 行尾检查"
        echo "4. 危险命令扫描"
        echo "5. ShellCheck 检查（如已安装）"
        echo "6. 导出质量报告"
        echo "0. 返回主菜单"
        read -p "请输入选项: " quality_option

        case $quality_option in
            1)
                run_quality_checks "$scan_root"
                pause_return
                ;;
            2)
                quality_bash_syntax_check "$scan_root"
                pause_return
                ;;
            3)
                quality_crlf_check "$scan_root"
                pause_return
                ;;
            4)
                quality_dangerous_command_scan "$scan_root"
                pause_return
                ;;
            5)
                quality_shellcheck_scan "$scan_root"
                pause_return
                ;;
            6)
                generate_quality_report
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

generate_health_report() {
    local report_path
    mkdir -p "$MINISH_REPORT_DIR" 2>/dev/null || {
        error "无法创建报告目录：$MINISH_REPORT_DIR"
        return 1
    }
    report_path="$MINISH_REPORT_DIR/health-$(date '+%Y%m%d-%H%M%S').txt"

    {
        report_section "基础信息"
        print_kv "生成时间" "$(date '+%Y-%m-%d %H:%M:%S %z')"
        print_kv "工具版本" "$MINISH_VERSION"
        print_kv "主机名" "$(hostname 2>/dev/null || echo 未知)"
        print_kv "系统" "$OS_NAME"
        print_kv "内核" "$(uname -sr 2>/dev/null)"
        print_kv "架构" "$(uname -m 2>/dev/null)"
        print_kv "虚拟化" "$VIRT_TYPE"
        print_kv "包管理器" "$(detect_pkg_manager)"
        print_kv "服务管理器" "$(detect_service_manager)"
        print_kv "运行时间" "$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo 未知)"
        print_kv "日志文件" "$MINISH_LOG_FILE"
        print_kv "备份目录" "$MINISH_BACKUP_DIR"
        print_kv "报告目录" "$MINISH_REPORT_DIR"

        report_section "资源概览"
        if command_exists free; then
            free -h
        else
            echo "缺少 free，无法显示内存信息。"
        fi
        echo
        df -h 2>/dev/null || echo "无法读取磁盘空间。"
        echo
        df -ih 2>/dev/null || echo "无法读取 inode 使用情况。"
        echo
        if [ -r /proc/loadavg ]; then
            print_kv "Load Average" "$(cat /proc/loadavg)"
        fi

        report_section "网络概览"
        print_kv "公网 IPv4" "$(get_public_ip 4)"
        print_kv "公网 IPv6" "$(get_public_ip 6)"
        echo
        echo "[默认路由]"
        show_default_routes
        echo
        echo "[DNS]"
        show_dns_summary
        echo
        echo "[TCP 拥塞控制]"
        if command_exists sysctl; then
            sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || echo "无法读取 TCP 设置。"
        else
            echo "缺少 sysctl。"
        fi
        echo
        echo "[监听端口 Top 40]"
        if command_exists ss; then
            ss -tuln | head -n 40
        elif command_exists netstat; then
            netstat -tuln | head -n 40
        else
            echo "缺少 ss/netstat。"
        fi

        report_section "SSH 摘要"
        print_kv "Port" "$(get_effective_ssh_port)"
        print_kv "PermitRootLogin" "$(get_ssh_option PermitRootLogin)"
        print_kv "PasswordAuthentication" "$(get_ssh_option PasswordAuthentication)"
        print_kv "PubkeyAuthentication" "$(get_ssh_option PubkeyAuthentication)"
        test_sshd_config

        report_section "登录与安全"
        echo "[最近登录]"
        if command_exists last; then
            last -n 10 2>/dev/null || echo "无法读取登录记录。"
        else
            echo "缺少 last。"
        fi
        echo
        echo "[失败登录 IP Top 10]"
        show_failed_login_top
        echo
        echo "[UFW 状态]"
        if command_exists ufw; then
            ufw status 2>&1 | head -n 30
        else
            echo "未安装 ufw。"
        fi
        echo
        echo "[Fail2ban 状态]"
        if command_exists fail2ban-client; then
            fail2ban-client status 2>&1
        else
            echo "未安装 fail2ban-client。"
        fi

        report_section "关键服务"
        for svc in ssh sshd docker nginx ufw fail2ban; do
            print_kv "$svc" "$(service_status_text "$svc")"
        done

        report_section "Docker 摘要"
        if command_exists docker; then
            if docker info >/dev/null 2>&1; then
                echo "[Docker 空间]"
                docker system df 2>&1
                echo
                echo "[容器列表]"
                docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>&1
                echo
                echo "[镜像 Top 20]"
                docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' 2>&1 | head -n 21
            else
                echo "Docker 已安装，但当前用户无法访问 Docker daemon 或 daemon 未运行。"
            fi
        else
            echo "未安装 Docker。"
        fi

        report_section "日志与磁盘线索"
        echo "[/var/log 占用 Top 15]"
        du -sh /var/log/* 2>/dev/null | sort -hr | head -n 15 || echo "无法读取 /var/log。"
        echo
        echo "[最近系统错误]"
        if command_exists journalctl; then
            journalctl -p err -n 30 --no-pager 2>/dev/null || echo "无法读取 journal。"
        elif [ -r /var/log/syslog ]; then
            grep -iE 'error|failed|critical' /var/log/syslog | tail -n 30
        elif [ -r /var/log/messages ]; then
            grep -iE 'error|failed|critical' /var/log/messages | tail -n 30
        else
            echo "未找到可读的系统日志。"
        fi
    } > "$report_path" 2>&1

    log_action "INFO" "健康报告已生成：$report_path"
    echo "$report_path"
}

health_report_menu() {
    clear_screen
    echo "健康报告"
    echo "报告目录：$MINISH_REPORT_DIR"
    echo
    if report_path=$(generate_health_report); then
        echo "报告已保存：$report_path"
        if confirm_action "是否立即查看报告内容？"; then
            less "$report_path" 2>/dev/null || cat "$report_path"
        fi
    else
        echo "报告生成失败。"
    fi
    pause_return
}

show_disk_usage_top() {
    local target_dir
    read -p "请输入要分析的目录（默认 /）: " target_dir
    target_dir=${target_dir:-/}
    if [ ! -d "$target_dir" ]; then
        echo "目录不存在：$target_dir"
        return 1
    fi
    echo "目录占用 Top 20：$target_dir"
    du -xhd1 "$target_dir" 2>/dev/null | sort -hr | head -n 20
}

show_large_files_top() {
    local target_dir
    read -p "请输入要扫描的目录（默认 /var/log）: " target_dir
    target_dir=${target_dir:-/var/log}
    if [ ! -d "$target_dir" ]; then
        echo "目录不存在：$target_dir"
        return 1
    fi
    echo "大文件 Top 20：$target_dir"
    find "$target_dir" -xdev -type f -size +1M -print0 2>/dev/null \
        | xargs -0 du -h 2>/dev/null \
        | sort -hr \
        | head -n 20
}

show_var_log_top() {
    echo "/var/log 占用 Top 20"
    du -sh /var/log/* 2>/dev/null | sort -hr | head -n 20 || echo "无法读取 /var/log。"
}

show_journal_usage() {
    if ! command_exists journalctl; then
        echo "未检测到 journalctl。"
        return 1
    fi
    journalctl --disk-usage 2>/dev/null || echo "无法读取 journal 占用。"
}

vacuum_journal_logs() {
    if ! command_exists journalctl; then
        echo "未检测到 journalctl。"
        return 1
    fi
    read -p "保留最近多少天日志？默认 7d: " keep_time
    keep_time=${keep_time:-7d}
    if ! [[ "$keep_time" =~ ^[0-9]+[dD]$ ]]; then
        echo "格式错误，请使用类似 7d、14d。"
        return 1
    fi
    if confirm_action "确认清理 journal，仅保留 $keep_time 吗？"; then
        sudo journalctl --vacuum-time="$keep_time"
    else
        echo "已取消。"
    fi
}

show_recent_system_errors() {
    if command_exists journalctl; then
        journalctl -p err -n 80 --no-pager 2>/dev/null || echo "无法读取 journal。"
    elif [ -r /var/log/syslog ]; then
        grep -iE 'error|failed|critical' /var/log/syslog | tail -n 80
    elif [ -r /var/log/messages ]; then
        grep -iE 'error|failed|critical' /var/log/messages | tail -n 80
    else
        echo "未找到可读的系统日志。"
    fi
}

show_docker_log_usage() {
    local log_path
    if ! command_exists docker; then
        echo "未安装 Docker。"
        return 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon 不可用或当前用户无权限。"
        return 1
    fi
    docker ps -a --format '{{.ID}} {{.Names}}' | while read -r container_id container_name; do
        [ -n "$container_id" ] || continue
        log_path=$(docker inspect --format='{{.LogPath}}' "$container_id" 2>/dev/null)
        if [ -n "$log_path" ] && [ -f "$log_path" ]; then
            du -h "$log_path" 2>/dev/null | awk -v name="$container_name" '{print $1 "\t" name "\t" $2}'
        fi
    done | sort -hr | head -n 20
}

truncate_docker_logs() {
    local log_path
    if ! command_exists docker; then
        echo "未安装 Docker。"
        return 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon 不可用或当前用户无权限。"
        return 1
    fi
    echo "将清空所有容器 json 日志文件，不会删除容器。"
    if ! confirm_action "确认清空 Docker 容器日志吗？"; then
        echo "已取消。"
        return
    fi
    docker ps -aq | while read -r container_id; do
        [ -n "$container_id" ] || continue
        log_path=$(docker inspect --format='{{.LogPath}}' "$container_id" 2>/dev/null)
        if [ -n "$log_path" ] && [ -f "$log_path" ]; then
            sudo truncate -s 0 "$log_path"
            echo "已清空：$log_path"
        fi
    done
}

log_disk_analysis_menu() {
    while true; do
        clear_screen
        echo "日志与磁盘分析"
        echo "1. 查看文件系统占用"
        echo "2. 查看目录占用 Top"
        echo "3. 查找大文件 Top"
        echo "4. 查看 /var/log 占用 Top"
        echo "5. 查看 journal 日志占用"
        echo "6. 清理 journal 日志"
        echo "7. 查看最近系统错误"
        echo "8. 查看 Docker 日志占用"
        echo "9. 清空 Docker 容器日志"
        echo "0. 返回主菜单"
        read -p "请输入选项: " log_option

        case $log_option in
            1)
                df -h
                echo
                df -ih 2>/dev/null || true
                pause_return
                ;;
            2)
                show_disk_usage_top
                pause_return
                ;;
            3)
                show_large_files_top
                pause_return
                ;;
            4)
                show_var_log_top
                pause_return
                ;;
            5)
                show_journal_usage
                pause_return
                ;;
            6)
                vacuum_journal_logs
                pause_return
                ;;
            7)
                show_recent_system_errors
                pause_return
                ;;
            8)
                show_docker_log_usage
                pause_return
                ;;
            9)
                truncate_docker_logs
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

# 清理系统垃圾
clean() {
    local mode="$1"

    if [ "$mode" == "deep" ]; then
        if ! confirm_action "深度清理会清空日志、临时文件并清理 Docker 卷，确认继续吗？"; then
            warn "已取消深度清理。"
            return
        fi
    fi

    echo "正在清理系统日志..."
    if [ "$mode" == "deep" ]; then
        # 深度清理：清空所有日志
        sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
        echo "所有系统日志已清空。"
    else
        # 常规清理：清除 7 天前的日志
        sudo journalctl --vacuum-time=7d
        echo "7 天前的系统日志已删除。"
    fi

    # 检查包管理器
    if command -v apt > /dev/null; then
        echo "正在清理 apt 包管理器..."
        sudo apt clean
        echo "安装包缓存清理完成。"
        sudo apt autoclean
        echo "过期缓存清理完成。"
        sudo apt autoremove -y
        echo "不再需要的依赖包删除完成。"
        sudo apt autoremove --purge -y
        echo "旧内核清理完成。"

    elif command -v yum > /dev/null; then
        echo "正在清理 yum 包管理器..."
        sudo yum clean all
        echo "yum 包管理器清理完成。"
        sudo package-cleanup --oldkernels --count=2
        echo "旧内核清理完成。"

    elif command -v dnf > /dev/null; then
        echo "正在清理 dnf 包管理器..."
        sudo dnf clean all
        echo "dnf 包管理器清理完成。"
        sudo dnf autoremove -y
        echo "不再需要的依赖包删除完成。"
        sudo dnf remove --oldinstallonly
        echo "旧内核清理完成。"

    elif command -v pacman > /dev/null; then
        echo "正在清理 pacman 包管理器..."
        sudo pacman -Scc --noconfirm
        echo "pacman 包管理器清理完成。"
        sudo pacman -Rns $(pacman -Qdtq) --noconfirm
        echo "不再需要的依赖包删除完成。"

    elif command -v zypper > /dev/null; then
        echo "正在清理 zypper 包管理器..."
        sudo zypper clean
        echo "zypper 包管理器清理完成。"
        sudo zypper rm $(zypper se --unneeded | awk '{print $3}')
        echo "不再需要的依赖包删除完成。"

    else
        echo "未检测到支持的包管理器，跳过相关清理步骤。"
    fi

    # 清理用户的临时文件
    echo "用户缓存和回收站清理会删除对应目录下的直接子项。"
    safe_clean_directory_contents "$HOME/.cache" "当前用户缓存" "false" || warn "用户缓存清理未完成。"
    safe_clean_directory_contents "$HOME/.local/share/Trash" "当前用户回收站" "false" || warn "用户回收站清理未完成。"

    # 清理临时文件
    echo "系统临时目录清理会删除 /tmp 和 /var/tmp 下的直接子项。"
    safe_clean_directory_contents "/tmp" "系统临时目录 /tmp" "true" || warn "/tmp 清理未完成。"
    safe_clean_directory_contents "/var/tmp" "系统临时目录 /var/tmp" "true" || warn "/var/tmp 清理未完成。"

    # 检查 Docker 是否安装
    if command -v docker > /dev/null; then
        echo "正在清理 Docker 的未使用资源..."
        if [ "$mode" == "deep" ]; then
            if confirm_action "确认清理 Docker 未使用镜像、容器、网络和卷吗？"; then
                docker system prune -a -f --volumes
                docker network prune -f
                docker volume prune -f
                echo "Docker 的未使用资源清理完成。"
            else
                warn "已跳过 Docker 深度清理。"
            fi
        else
            if confirm_action "确认删除所有未使用的 Docker 镜像吗？"; then
                docker image prune -a -f
                echo "未使用的 Docker 镜像清理完成。"
            else
                warn "已跳过 Docker 镜像清理。"
            fi
        fi
    else
        echo "未检测到 Docker，跳过 Docker 清理步骤。"
    fi
}

# 显示网络菜单
test_dns_latency() {
    local domain
    local dns_server
    local start_time end_time elapsed
    read -p "请输入测试域名（默认 google.com）: " domain
    domain=${domain:-google.com}
    read -p "请输入 DNS 服务器（留空使用系统默认）: " dns_server

    if command_exists dig; then
        if [ -n "$dns_server" ]; then
            dig @"$dns_server" "$domain" +tries=1 +time=3 +stats | awk '/Query time|SERVER|status/ {print}'
        else
            dig "$domain" +tries=1 +time=3 +stats | awk '/Query time|SERVER|status/ {print}'
        fi
    elif command_exists nslookup; then
        start_time=$(date +%s 2>/dev/null)
        if [ -n "$dns_server" ]; then
            nslookup "$domain" "$dns_server"
        else
            nslookup "$domain"
        fi
        end_time=$(date +%s 2>/dev/null)
        elapsed=$((end_time - start_time))
        echo "粗略耗时：${elapsed}s"
    elif command_exists getent; then
        getent hosts "$domain"
    else
        echo "缺少 dig/nslookup/getent，无法测试 DNS。"
    fi
}

test_ip_connectivity() {
    echo "公网 IPv4：$(get_public_ip 4)"
    echo "公网 IPv6：$(get_public_ip 6)"
    echo
    echo "IPv4 ping："
    if command_exists ping; then
        ping -4 -c 4 -W 2 1.1.1.1 2>/dev/null || ping -c 4 1.1.1.1
    else
        echo "缺少 ping。"
    fi
    echo
    echo "IPv6 ping："
    if command_exists ping; then
        ping -6 -c 4 -W 2 2606:4700:4700::1111 2>/dev/null || echo "IPv6 ping 失败或不支持。"
    else
        echo "缺少 ping。"
    fi
}

test_tcp_connectivity() {
    local host
    local port
    read -p "请输入目标主机: " host
    read -p "请输入目标端口: " port
    if [ -z "$host" ] || ! validate_port "$port"; then
        echo "主机或端口无效。"
        return 1
    fi

    if command_exists nc; then
        nc -vz -w 5 "$host" "$port"
    else
        echo "缺少 nc，无法测试 TCP 端口。"
    fi
}

trace_route_target() {
    local target
    read -p "请输入追踪目标（默认 1.1.1.1）: " target
    target=${target:-1.1.1.1}

    if command_exists traceroute; then
        traceroute "$target"
    elif command_exists tracepath; then
        tracepath "$target"
    elif command_exists ping; then
        echo "缺少 traceroute/tracepath，改用 ping 显示基础连通性。"
        ping -c 4 "$target"
    else
        echo "缺少 traceroute/tracepath/ping。"
    fi
}

detect_mtu() {
    local target
    local size
    read -p "请输入 MTU 探测目标（默认 1.1.1.1）: " target
    target=${target:-1.1.1.1}

    if ! command_exists ping; then
        echo "缺少 ping，无法探测 MTU。"
        return 1
    fi

    echo "使用 DF 标记探测 IPv4 MTU，失败并不一定代表线路不可用。"
    for size in 1472 1464 1452 1400 1360 1280 1200; do
        if ping -c 1 -W 2 -M do -s "$size" "$target" >/dev/null 2>&1; then
            echo "可用 payload: $size，估算 MTU: $((size + 28))"
            return 0
        fi
    done
    echo "未探测到可用 MTU，可能系统 ping 不支持 -M do 或目标丢弃 ICMP。"
}

packet_loss_test() {
    local target
    local count
    read -p "请输入测试目标（默认 1.1.1.1）: " target
    target=${target:-1.1.1.1}
    read -p "请输入发包数量（默认 20）: " count
    count=${count:-20}
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ]; then
        echo "发包数量无效。"
        return 1
    fi

    if command_exists ping; then
        ping -c "$count" "$target"
    else
        echo "缺少 ping。"
    fi
}

network_diagnostic_report() {
    echo "===== 网络诊断摘要 ====="
    print_kv "公网 IPv4" "$(get_public_ip 4)"
    print_kv "公网 IPv6" "$(get_public_ip 6)"
    echo
    echo "[默认路由]"
    show_default_routes
    echo
    echo "[DNS]"
    show_dns_summary
    echo
    echo "[监听端口 Top 30]"
    if command_exists ss; then
        ss -tuln | head -n 30
    elif command_exists netstat; then
        netstat -tuln | head -n 30
    else
        echo "缺少 ss/netstat。"
    fi
}

network_diagnostic_menu() {
    while true; do
        clear_screen
        echo "网络诊断"
        echo "1. 网络诊断摘要"
        echo "2. DNS 延迟/解析测试"
        echo "3. IPv4/IPv6 连通性测试"
        echo "4. TCP 端口连通性测试"
        echo "5. 路由追踪"
        echo "6. MTU 探测"
        echo "7. 丢包测试"
        echo "0. 返回网络设置菜单"
        read -p "请输入选项: " diag_option

        case $diag_option in
            1)
                network_diagnostic_report
                pause_return
                ;;
            2)
                test_dns_latency
                pause_return
                ;;
            3)
                test_ip_connectivity
                pause_return
                ;;
            4)
                test_tcp_connectivity
                pause_return
                ;;
            5)
                trace_route_target
                pause_return
                ;;
            6)
                detect_mtu
                pause_return
                ;;
            7)
                packet_loss_test
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

show_congestion_status() {
    echo "内核：$(uname -sr 2>/dev/null)"
    if ! command_exists sysctl; then
        echo "缺少 sysctl，无法读取拥塞控制状态。"
        return 1
    fi
    echo
    echo "当前设置："
    sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
    echo
    echo "可用拥塞控制："
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "无法读取。"
    echo
    echo "已加载 TCP 模块："
    if [ -d /proc/sys/net/ipv4 ]; then
        lsmod 2>/dev/null | grep -E 'tcp_(bbr|cubic|reno)' || echo "无法读取或未发现相关模块。"
    else
        echo "当前系统可能不是 Linux，跳过模块检查。"
    fi
}

sysctl_persist_set() {
    local key="$1"
    local value="$2"
    local config="/etc/sysctl.d/99-minish-network.conf"

    sudo mkdir -p /etc/sysctl.d
    if [ -f "$config" ]; then
        backup_file_to_store "$config" "sysctl-minish-network.conf"
    fi

    if sudo grep -qE "^${key}[[:space:]]*=" "$config" 2>/dev/null; then
        sudo sed -i.bak -E "s|^${key}[[:space:]]*=.*|${key}=${value}|" "$config"
    else
        echo "${key}=${value}" | sudo tee -a "$config" >/dev/null
    fi
}

set_congestion_control() {
    local cc="$1"
    local available
    if ! command_exists sysctl; then
        echo "缺少 sysctl。"
        return 1
    fi
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
    if ! echo " $available " | grep -qw "$cc"; then
        echo "当前内核不支持 $cc。可用项：${available:-未知}"
        return 1
    fi
    if ! confirm_action "确认切换 TCP 拥塞控制为 $cc 吗？"; then
        echo "已取消。"
        return 1
    fi
    sysctl_persist_set "net.ipv4.tcp_congestion_control" "$cc"
    sudo sysctl -w "net.ipv4.tcp_congestion_control=$cc"
}

set_default_qdisc() {
    local qdisc="$1"
    if ! command_exists sysctl; then
        echo "缺少 sysctl。"
        return 1
    fi
    if ! confirm_action "确认设置默认队列算法为 $qdisc 吗？"; then
        echo "已取消。"
        return 1
    fi
    sysctl_persist_set "net.core.default_qdisc" "$qdisc"
    sudo sysctl -w "net.core.default_qdisc=$qdisc"
}

enable_bbr_basic() {
    local available
    echo "将尝试启用当前内核支持的 BBR，不进行内核升级。"
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
    if ! echo " $available " | grep -qw "bbr"; then
        echo "当前内核不支持 bbr。可用项：${available:-未知}"
        return 1
    fi
    if ! confirm_action "确认设置 qdisc=fq 并启用 bbr 吗？"; then
        echo "已取消。"
        return 1
    fi
    sysctl_persist_set "net.core.default_qdisc" "fq"
    sysctl_persist_set "net.ipv4.tcp_congestion_control" "bbr"
    sudo sysctl -w net.core.default_qdisc=fq
    sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
}

congestion_control_menu() {
    while true; do
        clear_screen
        echo "BBR / 拥塞控制管理"
        echo "1. 查看当前状态"
        echo "2. 启用 BBR（当前内核支持时）"
        echo "3. 切换为 cubic"
        echo "4. 切换为 bbr"
        echo "5. 切换为 bbr2"
        echo "6. 设置 qdisc 为 fq"
        echo "7. 设置 qdisc 为 fq_codel"
        echo "0. 返回网络设置菜单"
        read -p "请输入选项: " cc_option

        case $cc_option in
            1)
                show_congestion_status
                pause_return
                ;;
            2)
                enable_bbr_basic
                pause_return
                ;;
            3)
                set_congestion_control "cubic"
                pause_return
                ;;
            4)
                set_congestion_control "bbr"
                pause_return
                ;;
            5)
                set_congestion_control "bbr2"
                pause_return
                ;;
            6)
                set_default_qdisc "fq"
                pause_return
                ;;
            7)
                set_default_qdisc "fq_codel"
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

network_menu() {
    while true; do
        clear_screen
        echo "网络设置菜单："
        echo "1. 网络诊断"
        echo "2. 设置IP优先级"
        echo "3. 设置DNS"
        echo "4. BBR / 拥塞控制管理"
        echo "5. TCP一键管理"
        echo "6. NNC tool"
        echo "0. 返回主菜单"
        read -p "请输入选项: " NETWORK_OPTION

        case $NETWORK_OPTION in
            1)
                network_diagnostic_menu
                ;;
            2)
                set_ip_priority
                ;;
            3)
                configure_dns
                ;;
            4)
                congestion_control_menu
                ;;
            5)
                echo "TCP一键管理"
                run_external_script "TCP 一键管理 tcpx.sh" "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh" "bash" "tcpx.sh"
                ;;
            6)
                echo "nnc tool"
                run_external_script "NNC tools.sh" "http://sh.nekoneko.cloud/tools.sh" "bash" "tools.sh"
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

domain_dns_check() {
    local domain="$1"
    echo "[DNS 解析]"
    if command_exists dig; then
        echo "A 记录："
        dig +short A "$domain" 2>/dev/null || true
        echo "AAAA 记录："
        dig +short AAAA "$domain" 2>/dev/null || true
        echo "CNAME 记录："
        dig +short CNAME "$domain" 2>/dev/null || true
    elif command_exists nslookup; then
        nslookup "$domain"
    elif command_exists getent; then
        getent hosts "$domain"
    else
        echo "缺少 dig/nslookup/getent，无法检查 DNS。"
    fi
}

domain_http_check() {
    local domain="$1"
    local scheme="$2"
    local url="${scheme}://${domain}/"
    local scheme_label
    scheme_label=$(printf "%s" "$scheme" | tr '[:lower:]' '[:upper:]')
    echo "[${scheme_label} 连通性]"
    if ! command_exists curl; then
        echo "缺少 curl，无法检查 $url"
        return 1
    fi
    curl -I -L --connect-timeout 5 --max-time 12 "$url" 2>/dev/null \
        | awk 'BEGIN{count=0} /^HTTP\// || /^server:/ || /^location:/ || /^content-type:/ {print; count++} END{if(count==0) print "未获取到响应头。"}'
}

domain_tls_check() {
    local domain="$1"
    local port="${2:-443}"
    local cert_dates
    echo "[TLS 证书]"
    if ! command_exists openssl; then
        echo "缺少 openssl，无法检查 TLS 证书。"
        return 1
    fi

    cert_dates=$(echo | openssl s_client -servername "$domain" -connect "${domain}:${port}" 2>/dev/null \
        | openssl x509 -noout -subject -issuer -dates 2>/dev/null)
    if [ -z "$cert_dates" ]; then
        echo "未能获取证书，可能端口未开放、SNI 不匹配或 TLS 握手失败。"
        return 1
    fi
    echo "$cert_dates"

    if command_exists date; then
        not_after=$(echo "$cert_dates" | awk -F= '/notAfter=/{print $2}')
        if [ -n "$not_after" ]; then
            if expire_epoch=$(date -d "$not_after" +%s 2>/dev/null); then
                now_epoch=$(date +%s)
                echo "剩余天数：$(( (expire_epoch - now_epoch) / 86400 ))"
            elif expire_epoch=$(date -j -f "%b %e %T %Y %Z" "$not_after" +%s 2>/dev/null); then
                now_epoch=$(date +%s)
                echo "剩余天数：$(( (expire_epoch - now_epoch) / 86400 ))"
            else
                echo "无法解析证书到期时间为剩余天数。"
            fi
        fi
    fi
}

check_local_web_ports() {
    echo "[本机 80/443 监听]"
    if command_exists ss; then
        ss -tuln | grep -E ':(80|443)[[:space:]]' || echo "未发现 80/443 监听。"
    elif command_exists netstat; then
        netstat -tuln | grep -E ':(80|443)[[:space:]]' || echo "未发现 80/443 监听。"
    else
        echo "缺少 ss/netstat，无法检查监听端口。"
    fi
}

domain_full_check() {
    local domain
    read -p "请输入域名（不含 http/https）: " domain
    if [ -z "$domain" ]; then
        echo "域名不能为空。"
        return 1
    fi
    domain=${domain#http://}
    domain=${domain#https://}
    domain=${domain%%/*}

    echo "检查域名：$domain"
    echo
    domain_dns_check "$domain"
    echo
    domain_http_check "$domain" "http"
    echo
    domain_http_check "$domain" "https"
    echo
    domain_tls_check "$domain" "443"
    echo
    check_local_web_ports
}

certificate_domain_menu() {
    local domain
    while true; do
        clear_screen
        echo "证书与域名检查"
        echo "1. 一键完整检查"
        echo "2. DNS 解析检查"
        echo "3. HTTP 连通性检查"
        echo "4. HTTPS 连通性检查"
        echo "5. TLS 证书到期检查"
        echo "6. 本机 80/443 监听检查"
        echo "0. 返回主菜单"
        read -p "请输入选项: " cert_option

        case $cert_option in
            1)
                domain_full_check
                pause_return
                ;;
            2)
                read -p "请输入域名: " domain
                [ -n "$domain" ] && domain_dns_check "$domain"
                pause_return
                ;;
            3)
                read -p "请输入域名: " domain
                [ -n "$domain" ] && domain_http_check "$domain" "http"
                pause_return
                ;;
            4)
                read -p "请输入域名: " domain
                [ -n "$domain" ] && domain_http_check "$domain" "https"
                pause_return
                ;;
            5)
                read -p "请输入域名: " domain
                [ -n "$domain" ] && domain_tls_check "$domain" "443"
                pause_return
                ;;
            6)
                check_local_web_ports
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

# 设置IP优先级
set_ip_priority() {
    clear_screen
    echo "1. IPv4优先"
    echo "2. IPv6优先"
    read -p "请选择IP优先级 (1 或 2): " IP_OPTION
    case $IP_OPTION in
        1)
            if ! grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf; then
                sudo sh -c 'echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf'
                echo "IPv4优先已设置。"
            else
                echo "IPv4优先已存在，无需重复设置。"
            fi
            ;;
        2)
            if grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf; then
                sudo sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf
                echo "IPv4优先已取消，IPv6优先。"
            else
                echo "未找到IPv4优先设置，无需更改。"
            fi
            ;;
        *)
            echo "无效的选项，请选择 1 或 2。"
            ;;
    esac
}

# 添加DNS配置
add_dns() {
    DNS_IP="$1"
    if ! grep -q "nameserver $DNS_IP" /etc/resolv.conf; then
        sudo bash -c "echo 'nameserver $DNS_IP' >> /etc/resolv.conf"
        echo "$DNS_IP 已添加。"
    else
        echo "$DNS_IP 已存在。"
    fi
}

# 配置IPv4 DNS
configure_ipv4_dns() {
    echo "1. 添加DNS"
    echo "2. 覆盖DNS（默认）"
    read -p "请选择操作 (1 或 2): " DNS_OP
    if [[ $DNS_OP -eq 1 ]]; then
        add_dns "1.1.1.1"
        add_dns "8.8.8.8"
    else
        sudo bash -c 'echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf'
        echo "已覆盖并设置新的IPv4 DNS。"
    fi
    sudo systemctl restart networking
    echo "网络服务已重启。"
}

# 配置双栈DNS
configure_dual_stack_dns() {
    echo "1. 添加DNS"
    echo "2. 覆盖DNS（默认）"
    read -p "请选择操作 (1 或 2): " DNS_OP
    if [[ $DNS_OP -eq 1 ]]; then
        add_dns "1.1.1.1"
        add_dns "8.8.8.8"
        add_dns "2606:4700:4700::1111"
        add_dns "2001:4860:4860::8888"
    else
        sudo bash -c 'echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888" > /etc/resolv.conf'
        echo "已覆盖并设置新的双栈DNS。"
    fi
    sudo systemctl restart networking
    echo "网络服务已重启。"
}

# 设置DNS
configure_dns() {
    clear_screen
    echo "当前DNS设置："
    cat /etc/resolv.conf
    echo "1. 配置IPv4 DNS"
    echo "2. 配置双栈DNS"
    echo "3. 查看当前IP地址"
    echo "4. 返回"

    read -p "请选择DNS配置选项: " DNS_OPTION
    case $DNS_OPTION in
        1)
            configure_ipv4_dns
            ;;
        2)
            configure_dual_stack_dns
            ;;
        3)
            echo "当前IPv4地址："
            if ! curl -s --connect-timeout 5 ip.sb; then
                echo "无法获取IPv4地址。"
            fi

            echo "当前IPv6地址："
            if ! timeout 5 curl -s ipv6.ip.sb; then
                echo "无法获取IPv6地址。"
            fi
            ;;
        4)
            return
            ;;
        *)
            echo "无效的选项"
            ;;
    esac
}

# 显示安装代理服务端菜单
install_proxy_server_menu() {
    clear_screen
    while true; do
        echo "安装代理服务端菜单："
        echo "1. 3X-UI"
        echo "2. X-UI"
        echo "3. Misaka-hysteria"
        echo "4. 32M-Reality-Alpine"
        echo "0. 返回主菜单"
        read -p "请输入选项: " PROXY_OPTION

        case $PROXY_OPTION in
            1)
                echo "请选择 3X-UI 版本："
                echo "1. 安装最新版（默认）"
                echo "2. 指定版本"
                read -p "请输入选项: " VERSION_OPTION

                if [ "$VERSION_OPTION" == "2" ]; then
                    read -p "请输入版本号（默认1.7.9）： " VERSION
                    VERSION=${VERSION:-1.7.9}
                    echo "正在安装 3X-UI 版本 $VERSION..."
                    if download_external_script "3X-UI 指定版本安装脚本" "https://raw.githubusercontent.com/mhsanaei/3x-ui/refs/tags/$VERSION/install.sh"; then
                        if confirm_action "确认现在执行 3X-UI 安装脚本吗？"; then
                            VERSION="v$VERSION" bash "$DOWNLOADED_SCRIPT"
                        else
                            echo "已取消执行。"
                        fi
                        rm -f "$DOWNLOADED_SCRIPT"
                    fi
                else
                    echo "正在安装 3X-UI 最新版..."
                    run_external_script "3X-UI 最新版安装脚本" "https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
                fi
                ;;
            2)
                echo "正在安装 X-UI..."
                run_external_script "X-UI 安装脚本" "https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh"
                ;;
            3)
                echo "下载并启动Misaka-hysteria脚本..."
                run_external_script "Misaka Hysteria 安装脚本" "https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/hysteria.sh" "bash" "hysteria.sh"
                ;;
            4)
                echo "正在安装 32M-Reality-Alpine..."
                if command_exists apk; then
                    apk update && apk add bash
                fi
                run_external_script "32M-Reality Alpine 安装脚本" "https://raw.githubusercontent.com/lgdlkq/32m/main/xr_install.sh" "bash" "xr_install.sh"
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 微型机哪吒被控端优化
optimize_nezha() {
    clear_screen
    while true; do
        echo "微型机哪吒被控端优化选项："
        echo "1. 优先v6旗帜"
        echo "2. 减少哪吒上报(风险)"
        echo "3. 禁用哪吒Webshell"
        echo "4. 降级被控端"
        echo "5. 删除被控端"
        echo "0. 返回主菜单"
        read -p "请输入选项: " NEZHA_OPTION

        case $NEZHA_OPTION in
            1)
                run_external_script "哪吒 agent 优先 IPv6 脚本" "https://raw.githubusercontent.com/xykt/Utilities/main/nezha/ipv6flag.sh"
                ;;
            2)
                run_external_script "哪吒 agent 减少上报脚本" "https://raw.githubusercontent.com/xykt/Utilities/main/nezha/lxc_error_reducer.sh"
                ;;
            3)
                run_external_script "哪吒 agent 禁用 WebShell 脚本" "https://raw.githubusercontent.com/xykt/Utilities/main/nezha/nowebshell.sh"
                ;;
            4)
                run_external_script "哪吒 agent 降级脚本" "https://raw.githubusercontent.com/xykt/Utilities/main/nezha/fix1706.sh"
                ;;
            5)
                local agent_dir="/opt/nezha/agent"
                if [ "$agent_dir" != "/opt/nezha/agent" ]; then
                    error "哪吒 agent 路径异常，已拒绝删除：$agent_dir"
                elif confirm_action "确认停止、禁用并删除哪吒被控端目录 $agent_dir 吗？删除前会先备份"; then
                    service_action stop nezha-agent || warn "停止 nezha-agent 失败或服务不存在。"
                    service_disable nezha-agent || warn "禁用 nezha-agent 开机启动失败或服务不存在。"
                    if [ -d "$agent_dir" ]; then
                        backup_directory_to_store "$agent_dir" "nezha-agent"
                        sudo rm -rf -- "$agent_dir"
                    else
                        warn "未找到哪吒 agent 目录：$agent_dir"
                    fi
                    echo "被控端已删除。"
                else
                    echo "已取消。"
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 更改SSH端口
change_ssh_port() {
    clear_screen
    CURRENT_PORT=$(get_effective_ssh_port)
    echo "当前SSH端口: $CURRENT_PORT"

    if ! confirm_action "是否更改 SSH 端口？"; then
        echo "返回上级菜单。"
        return
    fi

    read -p "请输入新端口: " NEW_PORT
    if ! validate_port "$NEW_PORT" || [ "$NEW_PORT" -lt 1024 ]; then
        echo "无效的端口，端口范围应在1024到65535之间。"
        return
    fi

    ensure_ufw_allows_port "$NEW_PORT"
    if apply_sshd_option_change "Port" "$NEW_PORT" "SSH 端口"; then
        echo "SSH端口已更改为 $NEW_PORT。"
    fi
}

show_ssh_security_status() {
    clear_screen
    echo "SSH 安全状态"
    print_kv "配置文件" "/etc/ssh/sshd_config"
    print_kv "端口" "$(get_effective_ssh_port)"
    print_kv "PermitRootLogin" "$(get_ssh_option PermitRootLogin)"
    print_kv "PasswordAuthentication" "$(get_ssh_option PasswordAuthentication)"
    print_kv "PubkeyAuthentication" "$(get_ssh_option PubkeyAuthentication)"
    print_kv "服务 ssh" "$(service_status_text ssh)"
    print_kv "服务 sshd" "$(service_status_text sshd)"
    echo
    test_sshd_config
    echo
    echo "监听端口："
    if command_exists ss; then
        ss -tlnp 2>/dev/null | grep -E ':(22|[0-9]+).*sshd' || ss -tln 2>/dev/null | grep ":$(get_effective_ssh_port)"
    elif command_exists netstat; then
        netstat -tln 2>/dev/null | grep ":$(get_effective_ssh_port)"
    else
        echo "缺少 ss/netstat。"
    fi
}

ssh_security_menu() {
    while true; do
        clear_screen
        echo "SSH 安全加固"
        echo "1. 查看 SSH 安全状态"
        echo "2. 修改 SSH 端口"
        echo "3. 禁用 Root 登录"
        echo "4. 启用 Root 登录"
        echo "5. 禁用密码登录"
        echo "6. 启用密码登录"
        echo "7. 启用公钥登录"
        echo "8. 追加 SSH 公钥"
        echo "9. 检查 sshd 配置"
        echo "10. 重启 SSH 服务"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " ssh_option

        case $ssh_option in
            1)
                show_ssh_security_status
                pause_return
                ;;
            2)
                change_ssh_port
                pause_return
                ;;
            3)
                apply_sshd_option_change "PermitRootLogin" "no" "禁用 Root 登录"
                pause_return
                ;;
            4)
                apply_sshd_option_change "PermitRootLogin" "yes" "启用 Root 登录"
                pause_return
                ;;
            5)
                echo "禁用密码登录前，请确认至少有一个可用 SSH 公钥，否则可能无法登录。"
                apply_sshd_option_change "PasswordAuthentication" "no" "禁用密码登录"
                pause_return
                ;;
            6)
                apply_sshd_option_change "PasswordAuthentication" "yes" "启用密码登录"
                pause_return
                ;;
            7)
                apply_sshd_option_change "PubkeyAuthentication" "yes" "启用公钥登录"
                pause_return
                ;;
            8)
                install_ssh_public_key
                pause_return
                ;;
            9)
                test_sshd_config
                pause_return
                ;;
            10)
                if confirm_action "确认重启 SSH 服务吗？"; then
                    restart_ssh_service || warn "SSH 服务重启失败，请手动检查。"
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

firewall_wizard_menu() {
    while true; do
        clear_screen
        echo "防火墙安全向导"
        echo "1. 查看 UFW 状态"
        echo "2. 一键放行当前 SSH 端口"
        echo "3. 放行 Web 端口 (80, 443)"
        echo "4. 放行自定义端口"
        echo "5. 安全启用 UFW"
        echo "6. 禁用 UFW"
        echo "7. 备份 UFW 状态快照"
        echo "8. 备份 UFW 可恢复配置"
        echo "9. 恢复 UFW 可恢复配置"
        echo "10. 进入 UFW 高级管理"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " fw_option

        case $fw_option in
            1)
                ufw_show_status
                pause_return
                ;;
            2)
                ufw_ensure_ssh_allowed
                pause_return
                ;;
            3)
                ufw_allow_port 80 tcp "MiniSH Web HTTP"
                ufw_allow_port 443 tcp "MiniSH Web HTTPS"
                pause_return
                ;;
            4)
                read -p "请输入端口号: " custom_port
                if ! validate_port "$custom_port"; then
                    echo "无效端口。"
                    pause_return
                    continue
                fi
                read -p "请输入协议 tcp/udp（默认 tcp）: " custom_proto
                custom_proto=${custom_proto:-tcp}
                if [[ "$custom_proto" != "tcp" && "$custom_proto" != "udp" ]]; then
                    echo "协议仅支持 tcp 或 udp。"
                    pause_return
                    continue
                fi
                ufw_allow_port "$custom_port" "$custom_proto" "MiniSH custom"
                pause_return
                ;;
            5)
                ufw_enable_safely
                pause_return
                ;;
            6)
                ufw_disable_safely
                pause_return
                ;;
            7)
                backup_ufw_rules
                pause_return
                ;;
            8)
                backup_ufw_config
                pause_return
                ;;
            9)
                restore_ufw_config
                pause_return
                ;;
            10)
                UFW_menu
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

# 网络安全与防滥用菜单
network_security_menu() {
    while true; do
        clear_screen
        echo "网络安全与防滥用选项："
        echo "1. 防火墙安全向导"
        echo "2. Fail2ban 管理"
        echo "3. SSH安全加固"
        echo "4. 屏蔽BT"
        echo "5. 屏蔽挖矿"
        echo "6. 屏蔽测速站"
        echo "7. 查看密码登陆成功的IP地址及其次数"
        echo "8. 查看密码登陆失败的IP地址及其次数"
        echo "9. 指定国家蔽连接"
        echo "10. 指定端口屏蔽大陆连接"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " SECURITY_OPTION

        case $SECURITY_OPTION in
            1)
                firewall_wizard_menu
                ;;
            2)
                fail2ban_management_menu
                ;;
            3)
                ssh_security_menu
                ;;
            4)
                echo "正在屏蔽BT..."
                for rule in "torrent" ".torrent" "peer_id=" "announce" "info_hash" "get_peers" "BitTorrent" "announce_peer" "BitTorrent protocol" "announce.php?passkey=" "magnet:" "xunlei" "sandai" "Thunder" "XLLiveUD"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "BT已屏蔽。"
                ;;
            5)
                echo "正在屏蔽挖矿..."
                for rule in "ethermine.com" "antpool.one" "antpool.com" "pool.bar" "get_peers" "announce_peer" "find_node" "seed_hash"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "挖矿已屏蔽。"
                ;;
            6)
                echo "正在屏蔽测速站..."
                for rule in ".speed" "speed." ".speed." "fast.com" "speedtest.net" "speedtest.com" "speedtest.cn" "test.ustc.edu.cn" "10000.gd.cn" "db.laomoe.com" "jiyou.cloud" "ovo.speedtestcustom.com" "speed.cloudflare.com" "speedtest"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "测速站已屏蔽。"
                ;;
            7)
                echo "密码登陆成功的IP地址及其次数"
                grep "Accepted password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
                ;;
            8)
                echo "密码登陆失败的IP地址及其次数"
                grep "Failed password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
                ;;
            9)
                echo "指定国家蔽连接"
                if ! confirm_action "该功能会下载/执行外部防火墙脚本，确认继续吗？"; then
                    echo "已取消。"
                    continue
                fi
                if [[ -f ./block-ips.sh ]]; then
                    echo "已存在 block-ips.sh。"
                    run_local_external_script "block-ips.sh 国家屏蔽脚本" "./block-ips.sh" "bash"
                else
                    echo "下载并安装 block-ips.sh..."
                    run_external_script "block-ips.sh 国家屏蔽脚本" "https://raw.githubusercontent.com/iiiiiii1/Block-IPs-from-countries/refs/heads/master/block-ips.sh" "bash" "block-ips.sh"
                fi
                ;;
            10)
                echo "指定端口屏蔽大陆连接"
                if ! confirm_action "该功能会下载/执行外部防火墙脚本，确认继续吗？"; then
                    echo "已取消。"
                    continue
                fi
                if [[ -f ./cnblock.sh ]]; then
                    echo "已存在 cnblock.sh。"
                    run_local_external_script "cnblock.sh 端口屏蔽大陆连接脚本" "./cnblock.sh" "bash"
                else
                    echo "下载并安装 cnblock.sh..."
                    run_external_script "cnblock.sh 端口屏蔽大陆连接脚本" "https://gitlab.com/gitlabvps1/cnipblocker/-/raw/main/cnblock.sh" "bash" "cnblock.sh"
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
        echo ""
        read -p "按 Enter 键继续..." temp
    done
}

# UFW管理菜单函数
UFW_menu() {
    while true; do
        echo "UFW 防火墙"
        echo "1. 安装 UFW"
        echo "2. 状态检查"
        echo "3. 启动 UFW"
        echo "4. 关闭 UFW"
        echo "5. 重启 UFW"
        echo "6. 查看规则"
        echo "7. 添加规则"
        echo "8. 删除规则"
        echo "9. 删除所有规则"
        echo "10. 查看日志"
        echo "0. 退出"
        read -p "请输入选项 [0-10]: " choice

        case $choice in
            1)
                echo "正在安装 UFW..."
                apt update && apt install -y ufw
                echo "UFW 安装完成。"
                ;;
            2)
                status=$(ufw status | head -n 1)
                echo "当前状态: $status"
                if [[ "$status" == "Status: inactive" ]]; then
                    if confirm_action "UFW 未启用，是否现在安全启用？"; then
                        ufw_enable_safely
                    fi
                fi
                ;;
            3)
                ufw_enable_safely
                ;;
            4)
                ufw_disable_safely
                ;;
            5)
                ufw_restart_safely
                ;;
            6)
                echo "1. 仅查看允许规则 (ALLOW)"
                echo "2. 仅查看禁止规则 (DENY)"
                echo "3. 常见端口规则 (22, 80, 443, 8080)"
                echo "4. 查看全部规则"
                read -p "请选择 [1-4]: " filter_choice

                case $filter_choice in
                    1)
                        rules=($(ufw status numbered | sed '1d' | grep -i "ALLOW"))
                        ;;
                    2)
                        rules=($(ufw status numbered | sed '1d' | grep -i "DENY"))
                        ;;
                    3)
                        rules=($(ufw status numbered | sed '1d' | grep -E "22|80|443|8080"))
                        ;;
                    *)
                        rules=($(ufw status numbered | sed '1d'))
                        ;;
                esac

                total_lines=${#rules[@]}
                page=0
                per_page=20

                while true; do
                    clear_screen
                    echo "-------- UFW 规则 (分页显示) --------"
                    start=$((page * per_page))
                    end=$((start + per_page - 1))

                    if [ $start -ge $total_lines ]; then
                        echo "没有更多规则了。"
                        break
                    fi

                    for i in $(seq $start $end); do
                        if [ $i -lt $total_lines ]; then
                            echo "${rules[$i]}"
                        fi
                    done

                    echo "-------------------------------------"
                    echo "页数：$((page + 1)) / $(( (total_lines + per_page - 1) / per_page ))"
                    echo "[n] 下一页 | [p] 上一页 | [b] 返回主菜单"
                    read -p "请选择操作: " nav

                    case $nav in
                        n)
                            page=$((page + 1))
                            ;;
                        p)
                            if [ $page -gt 0 ]; then
                                page=$((page - 1))
                            fi
                            ;;
                        b)
                            break
                            ;;
                        *)
                            echo "无效输入。"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            7)
                add_UFW_rule_menu
                ;;
            8)
                ufw_delete_rule_safely
                ;;
            9)
                ufw_reset_safely
                ;;
            10)
                echo "启用日志记录..."
                ufw logging on
                echo "最近 UFW 日志（按 Ctrl+C 退出）:"
                sleep 1
                tail -f /var/log/ufw.log
                ;;
            0)
                echo "退出 UFW 管理菜单。"
                break
                ;;
            *)
                echo "无效选项，请输入 1-11 之间的数字。"
                ;;
        esac
        echo ""
    done
}

# 添加UFW规则
add_UFW_rule_menu() {
    while true; do
        echo "添加 UFW 规则"
        echo "1. 简单规则 (对象 + 操作 + 端口 + 协议)"
        echo "2. 自定义规则 (手动输入)"
        echo "3. 放行 WEB 端口 (80, 443)"
        echo "4. 放行 SSH (22)"
        echo "5. 放行常见服务端口 (8080)"
        echo "6. 一键放行常用组合 (22, 80, 443, 8080)"
        echo "7. 返回上一级"
        read -p "请选择 [1-7]: " sub_choice

        case $sub_choice in
            1)
                read -p "目标对象（回车跳过，支持 IP / 网段）： " target
                read -p "操作类型（allow 或 deny）： " action
                if [[ "$action" != "allow" && "$action" != "deny" ]]; then
                    echo "无效操作类型，仅支持 allow 或 deny。"
                    continue
                fi

                read -p "端口号（单个: 80，多个: 80,443，范围: 1000:2000）： " ports
                if ! [[ "$ports" =~ ^[0-9:,]+$ ]]; then
                    echo "端口格式错误，请使用合法格式（80,443 或 1000:2000）"
                    continue
                fi

                read -p "协议（tcp / udp / any，默认 any）： " proto
                proto=${proto,,}
                [[ -z "$proto" ]] && proto="any"
                if [[ "$proto" != "tcp" && "$proto" != "udp" && "$proto" != "any" ]]; then
                    echo "协议必须为 tcp、udp 或 any。"
                    continue
                fi

                rule_desc="$action $proto port $ports"
                [[ -n "$target" ]] && rule_desc+=" from $target"

                if ufw status | grep -iq "$action.*$ports.*$proto"; then
                    echo "规则已存在：$rule_desc"
                else
                    cmd=(ufw "$action")
                    [[ -n "$target" ]] && cmd+=(from "$target")
                    cmd+=(to any port "$ports")
                    [[ "$proto" != "any" ]] && cmd+=(proto "$proto")
                    printf "执行："
                    printf "%q " "${cmd[@]}"
                    echo
                    "${cmd[@]}"
                fi
                ;;
            2)
                read -p "请输入完整自定义命令（例如 allow from 192.168.1.0/24 to any port 80 proto tcp）: ufw " custom
                if ufw status | grep -iq "$custom"; then
                    echo "规则已存在：ufw $custom"
                else
                    if confirm_action "确认执行自定义 UFW 命令：ufw $custom 吗？"; then
                        backup_ufw_rules
                        ufw $custom
                    else
                        echo "已取消。"
                    fi
                fi
                ;;
            3)
                for port in 80 443; do
                    if ufw status | grep -iq "$port/tcp"; then
                        echo "规则已存在：$port/tcp"
                    else
                        ufw allow $port/tcp
                    fi
                done
                ;;
            4)
                if ufw status | grep -iq "22/tcp"; then
                    echo "规则已存在：22/tcp"
                else
                    ufw allow 22/tcp
                fi
                ;;
            5)
                if ufw status | grep -iq "8080/tcp"; then
                    echo "规则已存在：8080/tcp"
                else
                    ufw allow 8080/tcp
                fi
                ;;
            6)
                for port in 22 80 443 8080; do
                    if ufw status | grep -iq "$port/tcp"; then
                        echo "规则已存在：$port/tcp"
                    else
                        ufw allow $port/tcp
                        echo "已放行：$port/tcp"
                    fi
                done
                ;;
            7)
                echo "返回主菜单。"
                break
                ;;
            *)
                echo "无效选项，请输入 1-7。"
                ;;
        esac
        echo ""
    done
}

# 安装 iPerf3
install_iperf3() {
    clear_screen
    OS_NAME=$(get_os_name)
    if [[ "$OS_NAME" == *"Debian"* ]] || [[ "$OS_NAME" == *"Ubuntu"* ]]; then
        sudo apt install iperf3 -y
    else
        echo "当前系统不支持自动安装 iPerf3。请手动安装。"
    fi
}

# 启动 iPerf3 服务端
start_server() {
    clear_screen
    echo "启动 iPerf3 服务端..."
    iperf3 -s
}

# 启动 iPerf3 客户端
start_client() {
    clear_screen
    read -p "请输入服务器 IP: " server_ip
    read -p "请输入端口号（默认为 5201）: " port
    port=${port:-5201}
    read -p "请输入测试时间（秒，默认为 10）: " duration
    duration=${duration:-10}
    read -p "请输入窗口大小（如 64K，默认为不设置）: " window_size

    command=(iperf3 -c "$server_ip" -p "$port" -t "$duration")
    if [ -n "$window_size" ]; then
        command+=(-w "$window_size")
    fi
    echo "启动 iPerf3 客户端..."
    "${command[@]}"
}

# 显示 iPerf3 菜单
iperf3_menu() {
    clear_screen
    while true; do
        echo "=== iPerf3 测试菜单 ==="
        echo "1. 安装 iPerf3"
        echo "2. 启动服务端"
        echo "3. 启动客户端"
        echo "4. 退出"

        read -p "请选择一个选项: " choice

        case $choice in
            1)
                install_iperf3
                ;;
            2)
                start_server
                ;;
            3)
                start_client
                ;;
            4)
                break
                ;;
            *)
                echo "无效选项，请重试。"
                ;;
        esac
    done
}

# 安装 hping3
install_hping3() {
    clear_screen
    OS_NAME=$(get_os_name)
    if [[ "$OS_NAME" == *"Debian"* ]] || [[ "$OS_NAME" == *"Ubuntu"* ]]; then
        sudo apt install hping3 -y
    elif [[ "$OS_NAME" == *"CentOS"* ]]; then
        sudo yum install epel-release -y && sudo yum install hping3 -y
    elif [[ "$OS_NAME" == *"Alpine"* ]]; then
        sudo apk add hping3
    else
        echo "当前系统不支持自动安装 hping3。请手动安装。"
    fi
}

# 启动 hping3 服务端（监听模式）
start_hping3_server() {
    clear_screen
    read -p "请输入监听签名（默认 HelloWorld）: " signature
    signature=${signature:-HelloWorld}
    read -p "请输入监听网络接口（默认 eth0）: " interface
    interface=${interface:-eth0}
    echo "启动 hping3 服务端（监听模式），按 Ctrl+C 停止..."
    sudo hping3 --listen "$signature" -I "$interface"
}

# 启动 hping3 客户端
start_hping3_client() {
    clear_screen
    read -p "请输入目标 IP: " target
    if [[ -z "$target" ]]; then
        echo "目标 IP 不能为空。"
        return
    fi

    echo "请选择模式："
    echo "1. TCP SYN（默认）"
    echo "2. UDP"
    echo "3. ICMP"
    read -p "请输入选项: " mode
    mode=${mode:-1}
    case $mode in
        1) mode_flag="-S" ;;
        2) mode_flag="--udp" ;;
        3) mode_flag="-1" ;;
        *) mode_flag="-S" ;;
    esac

    command=(sudo hping3 "$mode_flag" "$target")

    if [[ "$mode" != "3" ]]; then
        read -p "请输入目标端口（默认 80）: " port
        port=${port:-80}
        command+=(-p "$port")
    fi

    read -p "请输入发送数据包数量（默认 10，0 表示无限）: " count
    count=${count:-10}
    if [[ "$count" != "0" ]]; then
        command+=(-c "$count")
    fi

    read -p "请输入数据大小（字节，默认 0）: " size
    size=${size:-0}
    if [[ "$size" != "0" ]]; then
        command+=(-d "$size")
    fi

    read -p "请输入发包间隔（如 u1000 表示 1ms，留空不限制）: " interval
    if [[ -n "$interval" ]]; then
        command+=(-i "$interval")
    fi

    printf "执行: "
    printf "%q " "${command[@]}"
    echo
    "${command[@]}"
}

# 显示 hping3 菜单
hping3_menu() {
    clear_screen
    while true; do
        echo "=== hping3 测试菜单 ==="
        echo "1. 安装 hping3"
        echo "2. 启动服务端"
        echo "3. 启动客户端"
        echo "4. 退出"

        read -p "请选择一个选项: " choice

        case $choice in
            1)
                install_hping3
                ;;
            2)
                start_hping3_server
                ;;
            3)
                start_hping3_client
                ;;
            4)
                break
                ;;
            *)
                echo "无效选项，请重试。"
                ;;
        esac
    done
}

# 显示 测试菜单
function test_menu() {
    clear_screen
    echo "===== 测试菜单 ====="
    echo "1. 流媒体检测（含DNS解锁）"
    echo "2. IP质量体检"
    echo "3. 三网双栈详细回程"
    echo "4. Speedtest（Bench.im）"
    echo "5. HyperSpeed三网测速"
    echo "6. iPerf3"
    echo "7. 大小包检测"
    echo "8. hping3"
    echo "0. 返回主菜单"
    echo "====================="
    read -p "请选择一个选项: " choice
    case $choice in
        1)
            echo "运行流媒体检测（含DNS解锁）..."
            run_external_script "流媒体检测脚本 media.ispvps.com" "https://media.ispvps.com"
            ;;
        2)
            echo "运行IP质量体检..."
            run_external_script "IP 质量体检脚本 IP.Check.Place" "https://IP.Check.Place"
            ;;
        3)
            echo "运行三网双栈详细回程测试..."
            run_external_script "AutoTrace 三网双栈回程测试脚本" "https://raw.githubusercontent.com/Chennhaoo/Shell_Bash/master/AutoTrace.sh" "bash" "AutoTrace.sh"
            ;;
        4)
            echo "运行Speedtest（Bench.im）..."
            run_external_executable "Bench.im speedtest-cli" "https://bench.im/x/x86_64/speedtest-cli" "speedtest-cli"
            ;;
        5)
            echo "运行HyperSpeed三网测速..."
            run_external_script "HyperSpeed 三网测速脚本" "https://bench.im/hyperspeed"
            ;;
        6)
            iperf3_menu
            ;;
        7)
            packet_size_test
            ;;
        8)
            hping3_menu
            ;;
        0)
            return
            ;;
        *)
            echo "无效选项，请重试"
            ;;
    esac
}

packet_size_test() {
    export LANG=C

    TARGETS=(
    "223.5.5.5 AliDNS"
    "119.29.29.29 DNSPod"
    "180.76.76.76 BaiduDNS"
    )

    PING_SIZES=(56 200 500 1000 1400)

    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[36m'
    BOLD='\033[1m'
    RESET='\033[0m'

    RESULTS=()

    line() {
        printf "%b\n" "${BLUE}============================================================${RESET}"
    }

    title() {
        printf "\n%b%s%b\n" "${BOLD}${GREEN}" "$1" "${RESET}"
    }

    need_cmd() {
        command -v "$1" >/dev/null 2>&1
    }

    install_tools() {
        title "[初始化] 检查工具"
        PKGS=()
        need_cmd ping || PKGS+=("iputils-ping")
        [ ${#PKGS[@]} -eq 0 ] && {
            echo -e "${GREEN}所有工具已安装${RESET}"
            return
        }
        echo "正在安装: ${PKGS[*]}"
        if need_cmd apt; then
            apt update -y >/dev/null 2>&1
            apt install -y "${PKGS[@]}"
        elif need_cmd yum; then
            yum install -y "${PKGS[@]}"
        elif need_cmd apk; then
            apk add "${PKGS[@]}"
        else
            echo -e "${RED}不支持的包管理器${RESET}"
            exit 1
        fi
    }

    score_latency() {
        local latency=$1
        awk -v l="$latency" 'BEGIN{
            if (l < 60) print "优秀";
            else if (l < 120) print "良好";
            else if (l < 180) print "一般";
            else print "较差";
        }'
    }

    ping_test() {
        local ip=$1
        local name=$2
        title "[$name] $ip"
        printf "%-10s %-12s %-12s %-12s %-12s\n" \
            "包大小" "平均" "最低" "最高" "抖动"
        local first_avg=0
        local last_avg=0
        for size in "${PING_SIZES[@]}"; do
            result=$(ping -c 10 -s "$size" -W 1 "$ip" 2>/dev/null)
            stat=$(echo "$result" | grep 'min/avg/max')
            if [ -z "$stat" ]; then
                printf "%-10s ${RED}失败${RESET}\n" "$size"
                continue
            fi
            parsed=$(echo "$stat" | awk -F '=' '{print $2}' | tr -d ' ')
            min=$(echo "$parsed" | cut -d '/' -f1)
            avg=$(echo "$parsed" | cut -d '/' -f2)
            max=$(echo "$parsed" | cut -d '/' -f3)
            mdev=$(echo "$parsed" | cut -d '/' -f4)
            [ "$size" = "56" ] && first_avg=$avg
            [ "$size" = "1400" ] && last_avg=$avg
            printf "%-10s %-12sms %-12sms %-12sms %-12sms\n" \
                "$size" "$avg" "$min" "$max" "$mdev"
        done
        delta=$(awk -v a="$first_avg" -v b="$last_avg" 'BEGIN{printf "%.2f", b-a}')
        grade=$(score_latency "$first_avg")
        echo
        if awk "BEGIN{exit !($delta > 30)}"; then
            echo -e "大包影响     : ${RED}+${delta} ms${RESET}"
        else
            echo -e "大包影响     : ${GREEN}+${delta} ms${RESET}"
        fi
        echo -e "线路质量     : ${YELLOW}${grade}${RESET}"
        RESULTS+=("$name|$first_avg|$delta|$grade")
    }

    summary() {
        line
        title "测试结果汇总"
        printf "%-12s %-12s %-15s %-12s\n" \
            "目标" "延迟" "大包差值" "质量"
        for item in "${RESULTS[@]}"; do
            name=$(echo "$item" | cut -d '|' -f1)
            latency=$(echo "$item" | cut -d '|' -f2)
            delta=$(echo "$item" | cut -d '|' -f3)
            quality=$(echo "$item" | cut -d '|' -f4)
            printf "%-12s %-12sms %-15sms %-12s\n" \
                "$name" "$latency" "$delta" "$quality"
        done
        line
    }

    clear_screen
    line
    echo -e "${BOLD} 线路质量测试${RESET}"
    echo " 小包 vs 大包 延迟对比"
    line
    install_tools
    for target in "${TARGETS[@]}"; do
        ip=$(echo "$target" | awk '{print $1}')
        name=$(echo "$target" | awk '{print $2}')
        ping_test "$ip" "$name"
        line
    done
    summary
    read -p "按回车键返回..." temp
}

# 配置备份菜单
config_backup_menu() {
    while true; do
        clear_screen
        echo "配置备份"
        echo "备份目录：$MINISH_BACKUP_DIR"
        echo "1. 备份 SSH 配置"
        echo "2. 备份 DNS 配置"
        echo "3. 备份当前用户 crontab"
        echo "4. 备份 UFW 状态快照"
        echo "5. 一键备份常用配置"
        echo "6. 查看备份列表"
        echo "7. 恢复 SSH 配置"
        echo "8. 恢复 DNS 配置"
        echo "9. 恢复当前用户 crontab"
        echo "10. 备份 Fail2ban 配置"
        echo "11. 备份 UFW 可恢复配置"
        echo "12. 恢复 UFW 可恢复配置"
        echo "0. 返回主菜单"
        read -p "请输入选项: " backup_option

        case $backup_option in
            1)
                backup_file_to_store "/etc/ssh/sshd_config" "sshd_config"
                pause_return
                ;;
            2)
                backup_file_to_store "/etc/resolv.conf" "resolv.conf"
                pause_return
                ;;
            3)
                backup_crontab
                pause_return
                ;;
            4)
                backup_ufw_rules
                pause_return
                ;;
            5)
                backup_file_to_store "/etc/ssh/sshd_config" "sshd_config"
                backup_file_to_store "/etc/resolv.conf" "resolv.conf"
                backup_crontab
                backup_ufw_rules
                backup_ufw_config
                pause_return
                ;;
            6)
                mkdir -p "$MINISH_BACKUP_DIR" 2>/dev/null
                find "$MINISH_BACKUP_DIR" -maxdepth 1 -type f -print 2>/dev/null | sort || echo "暂无备份。"
                pause_return
                ;;
            7)
                restore_ssh_config
                pause_return
                ;;
            8)
                restore_dns_config
                pause_return
                ;;
            9)
                restore_crontab_backup
                pause_return
                ;;
            10)
                backup_fail2ban_config
                pause_return
                ;;
            11)
                backup_ufw_config
                pause_return
                ;;
            12)
                restore_ufw_config
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

# 显示 系统设置菜单
system_settings_menu() {
    while true; do
        clear_screen
        echo "系统设置"
        echo "1. 更改主机名"
        echo "2. 管理计划任务"
        echo "3. 切换软件源"
        echo "4. 服务管理"
        echo "5. 设置时区"
        echo "6. 修改 Swap 大小"
        echo "7. 查看端口占用"
        echo "8. 重启系统"
        echo "9. 修改登录密码"
        echo "0. 返回主菜单"
        read -p "请输入选项: " sys_option

        case $sys_option in
            1)
                read -p "请输入新的主机名: " new_hostname
                if [[ -n "$new_hostname" ]]; then
                    sudo hostnamectl set-hostname "$new_hostname"
                    echo "主机名已更改为: $new_hostname"
                else
                    echo "主机名不能为空。"
                fi
                read -p "按回车键继续..."
                ;;
            2)
                cron_job_menu
                ;;
            3)
                echo "正在切换软件源…"
                run_external_script "LinuxMirrors 换源脚本" "https://linuxmirrors.cn/main.sh"
                read -p "按回车键继续..."
                ;;
            4)
                service_management_menu
                ;;
            5)
                set_timezone_menu
                ;;
            6)
                total_mem=$(free -m | awk '/^Mem:/{print $2}')
                recommended_swap=$(awk 'BEGIN {
                    m='$total_mem'*2;
                    p=512;
                    while(p<m){ p*=2 };
                    print p
                }')
                echo "系统内存：${total_mem}MB"
                echo "推荐 Swap 大小：${recommended_swap}MB (内存约两倍，2 的指数)"
                read -p "请输入新的 Swap 大小（单位 MB，默认：${recommended_swap}）: " swap_size
                swap_size=${swap_size:-$recommended_swap}
                if [[ "$swap_size" =~ ^[0-9]+$ ]]; then
                    sudo swapoff -a
                    sudo dd if=/dev/zero of=/swapfile bs=1M count=$swap_size status=progress
                    sudo chmod 600 /swapfile
                    sudo mkswap /swapfile
                    sudo swapon /swapfile
                    sudo sed -i '/\/swapfile/d' /etc/fstab
                    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
                    echo "Swap 大小已设置为 ${swap_size}MB。"
                else
                    echo "请输入有效的数字。"
                fi
                read -p "按回车键继续..."
                ;;
            7)
                read -p "请输入要查看的端口（留空查看所有端口）: " port
                if [[ -n "$port" ]]; then
                    sudo lsof -i :$port
                else
                    sudo ss -tuln
                fi
                read -p "按回车键继续..."
                ;;
            8)
                read -p "确认重启系统？[y/N]: " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    sudo reboot
                fi
                ;;
            9)
                echo "修改登录密码"
                echo "1) 当前用户（$(whoami)）"
                echo "2) 指定用户"
                read -p "请选择选项: " pwd_option
                if [[ "$pwd_option" == "1" ]]; then
                    echo "为当前用户设置密码：$(whoami)"
                    sudo passwd $(whoami)
                elif [[ "$pwd_option" == "2" ]]; then
                    echo "系统用户列表："
                    users=($(cut -d: -f1 /etc/passwd | grep -E -v '^(nobody|root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|systemd|_.*|halt|operator|gdm|sshd|messagebus|usbmuxd|uuidd|avahi|dnsmasq|ntp|nfsnobody|rpc|polkitd|dbus|tcpdump|mysql|postgres|ftp|rpcuser|named|mailnull|smmsp|apache|xfs|vcsa|postfix|qemu|saslauth|chrony|dhcpd|nginx|firewalld|nm-openconnect|lightdm|systemd-resolve|systemd-network)$'))
                    for i in "${!users[@]}"; do
                        echo "$i) ${users[$i]}"
                    done
                    read -p "请输入用户序号: " user_index
                    selected_user=${users[$user_index]}
                    if [[ -n "$selected_user" ]]; then
                        echo "为用户 $selected_user 设置密码："
                        sudo passwd "$selected_user"
                    else
                        echo "无效的用户序号。"
                    fi
                else
                    echo "无效选项。"
                fi
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                echo "无效选项。"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 管理计划任务
cron_job_menu() {
    while true; do
        clear_screen
        echo "计划任务管理"
        echo "1. 查看当前用户计划任务"
        echo "2. 编辑当前用户计划任务"
        echo "3. 清空当前用户计划任务"
        echo "4. 简单添加当前用户计划任务"
        echo "5. 删除特定当前用户计划任务"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " cron_option

        case $cron_option in
            1)
                echo "当前计划任务："
                crontab -l || echo "无计划任务或 crontab 未设置。"
                read -p "按回车键继续..."
                ;;
            2)
                crontab -e
                ;;
            3)
                if confirm_action "确认清空当前用户所有计划任务吗？"; then
                    backup_crontab
                    crontab -r
                    echo "已清空当前用户计划任务。"
                else
                    echo "已取消。"
                fi
                read -p "按回车键继续..."
                ;;
            4)
                # 简单添加任务
                echo "=== 添加新计划任务 ==="
                # 1) 选择常用周期或自定义
                echo "请选择调度周期："
                echo " 1) 每分钟  2) 每小时  3) 每天  4) 每周  5) 每月  6) 自定义"
                read -p "输入序号 [1-6]: " sched_choice

                case $sched_choice in
                    1) cron_expr="* * * * *" ;;
                    2) cron_expr="0 * * * *" ;;
                    3) cron_expr="0 0 * * *" ;;
                    4) cron_expr="0 0 * * 0" ;;
                    5) cron_expr="0 0 1 * *" ;;
                    6)
                        read -p "分钟 (0-59, 用逗号/短横/星号): " m
                        read -p "小时 (0-23, 用逗号/短横/星号): " h
                        read -p "日 (1-31, 用逗号/短横/星号): " dom
                        read -p "月 (1-12, 用逗号/短横/星号): " mon
                        read -p "周几 (0-7, 用逗号/短横/星号, 0和7都代表周日): " dow
                        cron_expr="$m $h $dom $mon $dow"
                        ;;
                    *)
                        echo "无效选项，使用默认“每天”"
                        cron_expr="0 0 * * *"
                        ;;
                esac

                # 2) 询问要执行的命令
                read -p "请输入要执行的命令或脚本（完整路径）： " cmd
                if [[ -z "$cmd" ]]; then
                    echo "命令不能为空，添加取消。"
                else
                    new_entry="$cron_expr $cmd"
                    existing=$(crontab -l 2>/dev/null)

                    if echo "$existing" | grep -Fxq "$new_entry"; then
                        echo "⚠️ 该计划任务已存在，不会重复添加："
                        echo "   $new_entry"
                    else
                        ( echo "$existing"; echo "$new_entry" ) | crontab -
                        echo "✅ 已添加新任务："
                        echo "   $new_entry"
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            5)
                # 删除特定任务
                echo "=== 删除计划任务 ==="
                # 读取现有任务到数组
                mapfile -t lines < <(crontab -l 2>/dev/null)
                if [ ${#lines[@]} -eq 0 ]; then
                    echo "当前没有任何计划任务。"
                    read -p "按回车键继续..."
                    continue
                fi

                # 列出并编号
                echo "0) 取消"
                for i in "${!lines[@]}"; do
                    idx=$((i+1))
                    printf "%2d) %s\n" "$idx" "${lines[i]}"
                done

                # 读用户选择
                read -p "请输入要删除的任务编号: " del_idx
                if ! [[ "$del_idx" =~ ^[0-9]+$ ]] || [ "$del_idx" -lt 0 ] || [ "$del_idx" -gt ${#lines[@]} ]; then
                    echo "无效编号，取消操作。"
                elif [ "$del_idx" -eq 0 ]; then
                    echo "已取消。"
                else
                    # 确认
                    sel="${lines[$((del_idx-1))]}"
                    read -p "确认删除以下任务？[y/N]: $sel  " yn
                    case "$yn" in
                        [Yy]*)
                            # 从数组中过滤掉选中行
                            new_lines=()
                            for j in "${!lines[@]}"; do
                                [ $j -eq $((del_idx-1)) ] && continue
                                new_lines+=("${lines[j]}")
                            done
                            # 写回 crontab
                            printf "%s\n" "${new_lines[@]}" | crontab -
                            echo "已删除任务："
                            echo "  $sel"
                            ;;
                        *)
                            echo "已取消删除。"
                            ;;
                    esac
                fi
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                echo "无效选项。"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 服务管理
service_management_menu() {
    # 你可以在这里添加或调整常用服务名称
    local services=("sshd" "nginx" "docker" "自定义服务")
    while true; do
        clear_screen
        echo "服务管理"
        for i in "${!services[@]}"; do
            printf "%2d) %s\n" "$((i+1))" "${services[i]}"
        done
        echo " 0) 返回上级菜单"
        read -p "请选择要管理的服务: " svc_idx

        # 返回主菜单
        if [[ "$svc_idx" == "0" ]]; then
            break
        fi

        # 检查索引合法性
        if ! [[ "$svc_idx" =~ ^[1-9]$ ]] || [ "$svc_idx" -gt "${#services[@]}" ]; then
            echo "无效编号。"
            read -p "按回车键继续..."
            continue
        fi

        # 读取服务名
        svc="${services[$((svc_idx-1))]}"
        if [[ "$svc" == "自定义服务" ]]; then
            read -p "请输入自定义服务名称（systemctl 名称）: " svc
            [[ -z "$svc" ]] && { echo "服务名不能为空。"; read -p "按回车键继续..."; continue; }
        fi

        # 操作子菜单
        while true; do
            clear_screen
            echo "管理服务: $svc"
            echo " 1) 查看状态"
            echo " 2) 启动"
            echo " 3) 停止"
            echo " 4) 重启"
            echo " 5) 重新加载配置"
            echo " 0) 返回上级菜单"
            read -p "请选择操作: " action

            case $action in
                1) service_action status "$svc";;
                2) service_action start "$svc" && echo "$svc 已启动";;
                3) service_action stop "$svc" && echo "$svc 已停止";;
                4) service_action restart "$svc" && echo "$svc 已重启";;
                5) service_action reload "$svc" && echo "$svc 配置已重新加载";;
                0) break;;
                *) echo "无效选项。";;
            esac
            read -p "按回车键继续..."
        done
    done
}

# 设置时区
set_timezone_menu() {
    while true; do
        clear_screen
        current_tz=$(timedatectl | grep "Time zone" | awk '{print $3}')
        echo "当前时区：$current_tz"
        echo
        echo "1. 修改时区"
        echo "2. 退出"
        read -p "请选择操作: " opt

        case $opt in
            1)
                while true; do
                    clear_screen
                    echo "请选择时区（常见选项）："
                    echo "1. Asia/Shanghai (中国标准时间)"
                    echo "2. Asia/Tokyo (日本)"
                    echo "3. Asia/Kolkata (印度)"
                    echo "4. Europe/London (英国)"
                    echo "5. America/New_York (纽约)"
                    echo "6. Australia/Sydney (悉尼)"
                    echo "7. 自定义（输入 UTC 偏移）"
                    echo "0. 返回"
                    read -p "请输入选项: " tz_opt

                    case $tz_opt in
                        1) tz="Asia/Shanghai" ;;
                        2) tz="Asia/Tokyo" ;;
                        3) tz="Asia/Kolkata" ;;
                        4) tz="Europe/London" ;;
                        5) tz="America/New_York" ;;
                        6) tz="Australia/Sydney" ;;
                        7)
                            read -p "请输入 UTC 偏移（如 +8 或 -5）: " offset
                            # 转换为 Region/City 格式（根据偏移推断）
                            tz=$(timedatectl list-timezones | grep -E "Etc/GMT[-+]" | grep "Etc/GMT$((-1 * offset))")
                            if [[ -z "$tz" ]]; then
                                echo "不支持的偏移值，请输入范围在 -12 到 +14。"
                                read -p "按回车键继续..."
                                continue
                            fi
                            ;;
                        0) break ;;
                        *) echo "无效选项"; read -p "按回车键继续..."; continue ;;
                    esac

                    if [[ -n "$tz" ]]; then
                        sudo timedatectl set-timezone "$tz"
                        echo "已设置时区为：$tz"
                        read -p "按回车键继续..."
                        break
                    fi
                done
                ;;
            2)
                break
                ;;
            *)
                echo "无效选项"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

show_docker_daemon_config() {
    local daemon_config="/etc/docker/daemon.json"
    if [ -f "$daemon_config" ]; then
        echo "当前 Docker daemon 配置：$daemon_config"
        if command_exists jq; then
            jq . "$daemon_config" 2>/dev/null || cat "$daemon_config"
        else
            cat "$daemon_config"
        fi
    else
        echo "未找到 $daemon_config。"
    fi
}

configure_docker_log_limit() {
    local daemon_config="/etc/docker/daemon.json"
    local max_size
    local max_file
    local tmp_file

    read -p "请输入单个容器日志最大大小（默认 10m）: " max_size
    max_size=${max_size:-10m}
    read -p "请输入保留日志文件数量（默认 3）: " max_file
    max_file=${max_file:-3}

    if ! [[ "$max_size" =~ ^[0-9]+[kKmMgG]$ ]]; then
        echo "max-size 格式错误，请使用类似 10m、100m、1g。"
        return 1
    fi
    if ! [[ "$max_file" =~ ^[0-9]+$ ]] || [ "$max_file" -lt 1 ]; then
        echo "max-file 必须是大于 0 的整数。"
        return 1
    fi

    echo "将写入 Docker 日志限制："
    print_kv "log-driver" "json-file"
    print_kv "max-size" "$max_size"
    print_kv "max-file" "$max_file"
    echo "目标文件：$daemon_config"
    if ! confirm_action "确认修改 Docker daemon 配置吗？"; then
        echo "已取消。"
        return 1
    fi

    sudo mkdir -p /etc/docker
    if [ -f "$daemon_config" ]; then
        backup_file_to_store "$daemon_config" "docker-daemon.json"
    fi

    tmp_file=$(mktemp)
    if [ -f "$daemon_config" ]; then
        if ! command_exists jq; then
            rm -f "$tmp_file"
            echo "已有 $daemon_config，但缺少 jq，无法安全合并 JSON。"
            echo "请先安装 jq，或手动合并以下配置："
            cat <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "$max_size",
    "max-file": "$max_file"
  }
}
EOF
            return 1
        fi
        if ! jq . "$daemon_config" >/dev/null 2>&1; then
            rm -f "$tmp_file"
            error "$daemon_config 不是合法 JSON，已停止修改。"
            return 1
        fi
        jq \
            --arg max_size "$max_size" \
            --arg max_file "$max_file" \
            '.["log-driver"]="json-file" | .["log-opts"]=(.["log-opts"] // {}) | .["log-opts"]["max-size"]=$max_size | .["log-opts"]["max-file"]=$max_file' \
            "$daemon_config" > "$tmp_file"
    else
        cat > "$tmp_file" <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "$max_size",
    "max-file": "$max_file"
  }
}
EOF
    fi

    sudo cp "$tmp_file" "$daemon_config"
    rm -f "$tmp_file"
    echo "Docker daemon 配置已更新。"
    echo "注意：该配置只影响之后创建/重建的容器；已有容器通常需要重建才会应用。"
    if confirm_action "是否现在重启 Docker 服务？"; then
        service_action restart docker || warn "Docker 服务重启失败，请手动重启。"
    fi
}

set_docker_compose_command() {
    if docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD=(docker compose)
        return 0
    fi
    if command_exists docker-compose; then
        DOCKER_COMPOSE_CMD=(docker-compose)
        return 0
    fi
    return 1
}

docker_compose_available() {
    set_docker_compose_command >/dev/null 2>&1
}

show_docker_compose_version() {
    if set_docker_compose_command; then
        "${DOCKER_COMPOSE_CMD[@]}" version
    else
        echo "未检测到 Docker Compose。"
        echo "Debian/Ubuntu 通常可安装 docker-compose-plugin。"
    fi
}

find_compose_files() {
    local roots=("/opt" "$HOME" "/root")
    local root
    for root in "${roots[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 5 -type f \( \
            -name "compose.yml" -o \
            -name "compose.yaml" -o \
            -name "docker-compose.yml" -o \
            -name "docker-compose.yaml" \
        \) -print 2>/dev/null
    done | sort -u
}

select_compose_file() {
    local idx choice
    local -a compose_files
    SELECTED_COMPOSE_FILE=""
    mapfile -t compose_files < <(find_compose_files)

    if [ "${#compose_files[@]}" -eq 0 ]; then
        echo "未在 /opt、$HOME、/root 下找到 compose 文件。"
        return 1
    fi

    echo "可用 Compose 项目："
    echo "0. 取消"
    for idx in "${!compose_files[@]}"; do
        printf "%d. %s\n" "$((idx + 1))" "${compose_files[$idx]}"
    done

    read -p "请选择项目编号: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#compose_files[@]}" ]; then
        echo "无效编号。"
        return 1
    fi
    if [ "$choice" -eq 0 ]; then
        echo "已取消。"
        return 1
    fi

    SELECTED_COMPOSE_FILE="${compose_files[$((choice - 1))]}"
    return 0
}

run_compose_for_file() {
    local compose_file="$1"
    shift
    set_docker_compose_command || {
        echo "未检测到 Docker Compose。"
        return 1
    }
    (cd "$(dirname "$compose_file")" && "${DOCKER_COMPOSE_CMD[@]}" -f "$compose_file" "$@")
}

backup_compose_file() {
    local compose_file="$1"
    local label
    label="compose.$(basename "$(dirname "$compose_file")").$(basename "$compose_file")"
    backup_file_to_store "$compose_file" "$label"
}

validate_compose_file_config() {
    local compose_file="$1"
    set_docker_compose_command || {
        warn "未检测到 Docker Compose，已跳过 compose config 校验。"
        return 2
    }
    (cd "$(dirname "$compose_file")" && "${DOCKER_COMPOSE_CMD[@]}" -f "$compose_file" config >/dev/null)
}

restore_compose_file() {
    local compose_file
    local rollback_file
    local validate_status

    echo "先选择要覆盖恢复的目标 compose 文件。"
    select_compose_file || return 1
    compose_file="$SELECTED_COMPOSE_FILE"

    echo
    select_backup_file "compose.*.bak" "可恢复的 compose 备份：" || return 1
    echo
    echo "目标文件：$compose_file"
    echo "备份文件：$SELECTED_BACKUP"

    if command_exists diff; then
        echo
        echo "差异预览（当前文件 -> 备份文件，最多 120 行）："
        diff -u "$compose_file" "$SELECTED_BACKUP" 2>/dev/null | head -n 120 || true
    fi

    if ! confirm_action "确认用该备份覆盖目标 compose 文件吗？恢复前会先备份当前文件"; then
        echo "已取消。"
        return 1
    fi

    rollback_file=$(mktemp /tmp/minish-compose-rollback.XXXXXX) || {
        error "无法创建临时回滚文件。"
        return 1
    }
    if ! sudo cp -p "$compose_file" "$rollback_file"; then
        sudo rm -f "$rollback_file"
        error "无法创建恢复前临时副本，已取消恢复。"
        return 1
    fi

    backup_compose_file "$compose_file"
    if ! sudo cp -p "$SELECTED_BACKUP" "$compose_file"; then
        sudo cp -p "$rollback_file" "$compose_file" 2>/dev/null || true
        sudo rm -f "$rollback_file"
        error "compose 文件恢复失败，已尝试回滚。"
        return 1
    fi

    validate_compose_file_config "$compose_file"
    validate_status=$?
    if [ "$validate_status" -eq 0 ]; then
        info "compose 文件已恢复并通过配置校验：$compose_file"
        sudo rm -f "$rollback_file"
        return 0
    fi

    if [ "$validate_status" -eq 2 ]; then
        info "compose 文件已恢复：$compose_file"
        sudo rm -f "$rollback_file"
        return 0
    fi

    warn "compose config 校验失败，正在回滚到恢复前版本。"
    if sudo cp -p "$rollback_file" "$compose_file"; then
        sudo rm -f "$rollback_file"
        error "恢复未生效：目标文件已回滚。请检查备份内容后再尝试。"
        return 1
    fi

    sudo rm -f "$rollback_file"
    error "compose config 校验失败，且自动回滚失败。请立即手动检查：$compose_file"
    return 1
}

docker_compose_project_menu() {
    local compose_file="$1"
    while true; do
        clear_screen
        echo "Compose 项目：$compose_file"
        echo "1. 查看项目状态"
        echo "2. 查看日志（最近 100 行）"
        echo "3. 拉取镜像"
        echo "4. 启动/更新项目"
        echo "5. 重启项目"
        echo "6. 停止并删除项目容器"
        echo "7. 备份 compose 文件"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " compose_option

        case $compose_option in
            1)
                run_compose_for_file "$compose_file" ps
                pause_return
                ;;
            2)
                run_compose_for_file "$compose_file" logs --tail=100
                pause_return
                ;;
            3)
                if confirm_action "确认拉取该项目镜像吗？"; then
                    run_compose_for_file "$compose_file" pull
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            4)
                if confirm_action "确认执行 compose up -d 吗？"; then
                    backup_compose_file "$compose_file"
                    run_compose_for_file "$compose_file" up -d
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            5)
                if confirm_action "确认重启该 Compose 项目吗？"; then
                    run_compose_for_file "$compose_file" restart
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            6)
                if confirm_action "确认执行 compose down 吗？这会停止并删除项目容器"; then
                    backup_compose_file "$compose_file"
                    run_compose_for_file "$compose_file" down
                else
                    echo "已取消。"
                fi
                pause_return
                ;;
            7)
                backup_compose_file "$compose_file"
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

docker_compose_management_menu() {
    while true; do
        clear_screen
        echo "Docker Compose 管理"
        echo "1. 查看 Compose 版本"
        echo "2. 扫描 Compose 项目"
        echo "3. 选择 Compose 项目管理"
        echo "4. 备份所有扫描到的 compose 文件"
        echo "5. 恢复 compose 文件"
        echo "0. 返回 Docker 菜单"
        read -p "请输入选项: " compose_menu_option

        case $compose_menu_option in
            1)
                show_docker_compose_version
                pause_return
                ;;
            2)
                find_compose_files || true
                pause_return
                ;;
            3)
                if ! docker_compose_available; then
                    echo "未检测到 Docker Compose。"
                    pause_return
                    continue
                fi
                select_compose_file && docker_compose_project_menu "$SELECTED_COMPOSE_FILE"
                ;;
            4)
                while IFS= read -r compose_file; do
                    backup_compose_file "$compose_file"
                done < <(find_compose_files)
                pause_return
                ;;
            5)
                restore_compose_file
                pause_return
                ;;
            0)
                return
                ;;
            *)
                echo "无效选项。"
                pause_return
                ;;
        esac
    done
}

# Docker
docker_management_menu() {
    if ! command -v docker &> /dev/null; then
        echo "未检测到 Docker。"
        echo "1. 安装 Docker"
        echo "2. 返回主菜单"
        read -p "请输入选项: " docker_missing_option
        case $docker_missing_option in
            1)
                echo "正在安装 Docker..."
                if [[ -f /etc/debian_version ]]; then
                    sudo apt-get update
                    sudo apt-get install -y \
                        ca-certificates \
                        curl \
                        gnupg \
                        lsb-release
                    sudo mkdir -p /etc/apt/keyrings
                    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                    echo \
                      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
                      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                    sudo apt-get update
                    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
                    sudo systemctl enable docker
                    sudo systemctl start docker
                    echo "Docker 安装完成。"
                else
                    echo "当前系统不支持自动安装 Docker，请手动安装后重试。"
                fi
                read -p "按回车键继续..."
                ;;
            *)
                echo "返回主菜单..."
                sleep 1
                return
                ;;
        esac
    fi

    while true; do
        clear_screen
        echo "Docker 管理菜单"
        echo "1. 查看容器列表"
        echo "2. 查看镜像列表"
        echo "3. 启动容器"
        echo "4. 停止容器"
        echo "5. 删除已停止的容器"
        echo "6. 删除未使用的镜像"
        echo "7. 清理所有未使用资源"
        echo "8. 查看 Docker 占用空间"
        echo "9. 重启容器"
        echo "10. 查看容器日志"
        echo "11. 进入容器"
        echo "12. 设置容器资源限制"
        echo "13. 设置容器重启规则"
        echo "14. Docker Compose 管理"
        echo "15. 查看 Docker daemon 配置"
        echo "16. 设置 Docker 日志大小限制"
        echo "0. 返回主菜单"
        read -p "请输入选项: " DOCKER_OPTION

        case $DOCKER_OPTION in
            1)
                docker ps -a
                read -p "按回车键继续..." ;;
            2)
                docker images
                read -p "按回车键继续..." ;;
            3)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要启动的容器ID或名称: " container_id
                docker start "$container_id"
                echo "容器 $container_id 已启动。"
                read -p "按回车键继续..." ;;
            4)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要停止的容器ID或名称: " container_id
                docker stop "$container_id"
                echo "容器 $container_id 已停止。"
                read -p "按回车键继续..." ;;
            5)
                if confirm_action "确认删除所有已停止的 Docker 容器吗？"; then
                    docker container prune -f
                    echo "已删除所有已停止的容器。"
                else
                    echo "已取消。"
                fi
                read -p "按回车键继续..." ;;
            6)
                if confirm_action "确认删除所有未使用的 Docker 镜像吗？"; then
                    docker image prune -a -f
                    echo "已删除所有未使用的镜像。"
                else
                    echo "已取消。"
                fi
                read -p "按回车键继续..." ;;
            7)
                if confirm_action "确认清理 Docker 所有未使用资源吗？"; then
                    docker system prune -a -f
                    echo "已清理所有未使用资源。"
                else
                    echo "已取消。"
                fi
                read -p "按回车键继续..." ;;
            8)
                docker system df
                read -p "按回车键继续..." ;;
            9)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要重启的容器ID或名称: " container_id
                docker restart "$container_id"
                echo "容器 $container_id 已重启。"
                read -p "按回车键继续..." ;;
            10)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入要查看日志的容器ID或名称: " container_id
                docker logs --tail 50 "$container_id"
                read -p "按回车键继续..." ;;
            11)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入要进入的容器ID或名称: " container_id
                docker exec -it "$container_id" bash || docker exec -it "$container_id" sh
                read -p "按回车键继续..." ;;
            12)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入容器ID或名称: " container_id
                read -p "请输入内存限制（例如 512m 或 1g，留空不修改）: " mem_limit
                read -p "请输入 CPU 限制（如 0.5 表示50%，留空不修改）: " cpu_limit
                update_cmd=(docker update)
                [[ -n "$mem_limit" ]] && update_cmd+=(--memory "$mem_limit")
                [[ -n "$cpu_limit" ]] && update_cmd+=(--cpus "$cpu_limit")
                update_cmd+=("$container_id")
                "${update_cmd[@]}"
                echo "资源限制已更新。"
                read -p "按回车键继续..." ;;
            13)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入容器ID或名称: " container_id
                echo "可用重启策略：no | always | unless-stopped | on-failure"
                read -p "请输入重启策略: " restart_policy
                docker update --restart="$restart_policy" "$container_id"
                echo "重启策略已设置为 $restart_policy。"
                read -p "按回车键继续..." ;;
            14)
                docker_compose_management_menu ;;
            15)
                show_docker_daemon_config
                read -p "按回车键继续..." ;;
            16)
                configure_docker_log_limit
                read -p "按回车键继续..." ;;
            0)
                break ;;
            *)
                echo "无效的选项，请重新输入。"
                sleep 1 ;;
        esac
    done
}

handle_cli_args() {
    case "${1:-}" in
        info|system-info)
            MINISH_SKIP_PAUSE=true
            show_system_info
            exit 0
            ;;
        doctor|self-check)
            MINISH_SKIP_PAUSE=true
            run_doctor
            exit 0
            ;;
        report|health-report)
            generate_health_report
            exit $?
            ;;
        quality|quality-report)
            generate_quality_report
            exit $?
            ;;
        -v|--version|version)
            echo "VPSTool $MINISH_VERSION"
            exit 0
            ;;
        -h|--help|help)
            echo "用法: $0 [info|doctor|report|quality|--version|--help]"
            echo "无参数时进入交互菜单。"
            exit 0
            ;;
        "")
            ;;
        *)
            warn "未知参数：$1"
            echo "用法: $0 [info|doctor|report|quality|--version|--help]"
            exit 1
            ;;
    esac
}

handle_cli_args "$1"

# 显示菜单
while true; do
    clear_screen
    echo "VPSTool V$MINISH_VERSION"
    # 输出系统类型
    echo "当前系统是 $OS_NAME"
    # 输出虚拟化类型
    echo "虚拟化类型是 $VIRT_TYPE"
    echo "请选择操作："
    echo "00. 更新脚本"
    echo "1. 更新软件包"
    echo "2. 安装常见软件包"
    echo "3. 微型机哪吒被控端优化"
    echo "4. WARP"
    echo "5. 清理系统"
    echo "6. 网络设置"
    echo "7. 安装代理服务端"
    echo "8. 删除未使用的 Docker 镜像"
    echo "9. 安全与防滥用"
    echo "10. VPS"
    echo "11. 测试"
    echo "12. Docker管理"
    echo "13. 系统信息"
    echo "14. 自检"
    echo "15. 配置备份"
    echo "16. 健康报告"
    echo "17. 日志与磁盘分析"
    echo "18. 证书与域名检查"
    echo "19. 脚本质量工具"
    echo "99. 系统设置"
    echo "0. 退出"
    read -p "请输入选项: " OPTION

    case $OPTION in
        00)
            echo "正在更新脚本..."
            if download_external_script "VPSTool 更新脚本" "https://raw.githubusercontent.com/Yinengjun/MiniSH/refs/heads/main/VPSTool/VPSTool.sh"; then
                if bash -n "$DOWNLOADED_SCRIPT"; then
                    backup_file "$0"
                    if confirm_action "确认用下载的新版本覆盖当前脚本吗？"; then
                        cp "$DOWNLOADED_SCRIPT" "$0"
                        chmod +x "$0"
                        rm -f "$DOWNLOADED_SCRIPT"
                        exec bash "$0"
                    else
                        echo "已取消覆盖。"
                        rm -f "$DOWNLOADED_SCRIPT"
                    fi
                else
                    error "下载的新脚本未通过 bash -n，已取消更新。"
                    rm -f "$DOWNLOADED_SCRIPT"
                fi
            fi
            ;;
        1)
            echo "正在更新软件包..."
            if [[ "$OS_NAME" == *"Ubuntu"* || "$OS_NAME" == *"Debian"* ]]; then
                sudo apt update && sudo apt upgrade -y
            elif [[ "$OS_NAME" == *"CentOS"* ]]; then
                sudo yum update -y
            elif [[ "$OS_NAME" == *"Alpine"* ]]; then
                sudo apk update && sudo apk upgrade
            else
                echo "不支持的系统，无法更新软件包。"
            fi
            ;;
        2)
            install_common_packages_menu
            ;;
        3)
            optimize_nezha
            ;;
        4)
            echo "WARP"
            run_external_script "fscarmen WARP 菜单脚本" "https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh" "bash" "menu.sh"
            ;;
        5)
            # 用户选择清理模式
            clear_screen
            du -sh /var/log/
            echo "请选择清理模式："
            echo "1. 常规清理"
            echo "2. 深度清理"
            read -p "请输入选项（默认 1）： " choice
            choice=${choice:-1}  # 默认选项为 1

            if [ "$choice" == "2" ]; then
                clean "deep"
            else
                clean "normal"
            fi
            ;;
        6)
            network_menu
            ;;
        7)
            install_proxy_server_menu
            ;;
        8)
            if confirm_action "确认删除所有未使用的 Docker 镜像吗？"; then
                echo "正在删除未使用的 Docker 镜像..."
                docker image prune -a --force
                echo "未使用的 Docker 镜像已删除。"
            else
                echo "已取消。"
            fi
            ;;
        9)
            network_security_menu
            ;;
        10)
            run_external_script "memoryCheck 检测脚本" "https://raw.githubusercontent.com/uselibrary/memoryCheck/main/memoryCheck.sh" "bash" "memoryCheck.sh"
            echo "1. 关闭气球驱动（默认）"
            echo "0. 返回主菜单"
            read -p "请输入选项: " Balloon

            if [ "$Balloon" == "1" ]; then
                echo "正在关闭气球驱动..."
                echo "blacklist virtio_balloon" | sudo tee /etc/modprobe.d/blacklist.conf
                sudo update-initramfs -u
                echo "气球驱动已关闭。"
            elif [ "$Balloon" == "0" ]; then
                echo "返回主菜单..."
                continue
            else
                echo "无效的选项，请重新输入。"
            fi
            ;;
        11)
            test_menu
            ;;
        12)
            docker_management_menu
            ;;
        13)
            show_system_info
            ;;
        14)
            run_doctor
            ;;
        15)
            config_backup_menu
            ;;
        16)
            health_report_menu
            ;;
        17)
            log_disk_analysis_menu
            ;;
        18)
            certificate_domain_menu
            ;;
        19)
            script_quality_menu
            ;;
        99)
            system_settings_menu
            ;;
        0)
            echo "退出脚本。"
            exit 0
            ;;
        *)
            echo "无效的选项"
            ;;
    esac
done
