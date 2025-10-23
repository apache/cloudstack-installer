#!/usr/bin/env bash
# c8k.in/stall.sh - Easiest Apache CloudStack Installer
# Install with this command (from your Ubuntu/EL host):
#
# curl -sSfL https://c8k.in/stall.sh | bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.


set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Global variables
SCRIPT_NAME="CloudStack Installer"
CS_LOGFILE="/tmp/cloudstack-install.log"
EXECUTION_MODE=${EXECUTION_MODE:-PROMPT} # PROMPT or SILENT
TRACKER_FILE="$HOME/cloudstack-installer-tracker.conf"

OS_TYPE=""
PACKAGE_MANAGER=""
SELECTED_COMPONENTS=()
ZONE_TYPE=""
MYSQL_SERVICE=""
MYSQL_CONF_DIR=""

CS_VERSION=4.20
INTERFACE=
BRIDGE=cloudbr0
HOST_IP=
GATEWAY=
DNS="8.8.8.8"
NETMASK="255.255.255.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$CS_LOGFILE"
}

# Error handling function
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Success message function
success_msg() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log "SUCCESS: $1"
}

# Warning message function
warn_msg() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log "WARNING: $1"
}

# Info message function
info_msg() {
    echo -e "${BLUE}INFO: $1${NC}"
    log "INFO: $1"
}


declare -A tracker_values

load_tracker() {
    if [[ ! -f "$TRACKER_FILE" ]]; then
        echo "# CloudStack Installer Tracker Config" > "$TRACKER_FILE"
        echo "# Created on: $(date)" >> "$TRACKER_FILE"
        return 0
    fi

    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        tracker_values["$key"]="$value"
    done < "$TRACKER_FILE"
}

get_tracker_field() {
    local key="$1"
    echo "${tracker_values[$key]:-}"
}

is_configured() {
    local key="$1"
    [[ -n "${tracker_values[$key]:-}" ]]
}

# Save or update a field in the tracker file
set_tracker_field() {
    local key="$1"
    local value="$2"

    # Update associative array
    tracker_values["$key"]="$value"

    # Update or append key=value in tracker file
    if grep -q "^$key=" "$TRACKER_FILE"; then
        sed -i.bak "s|^$key=.*|$key=$value|" "$TRACKER_FILE"
    else
        echo "$key=$value" >> "$TRACKER_FILE"
    fi
}

# Utility: check if key is configured, show info/msg/confirm based on mode
check_already_configured() {
    local key="$1"
    local title="$2"
    local mode="${3:-info}"

    if is_configured "$key"; then
        local value="${tracker_values[$key]}"

        case "$mode" in
            info)
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "$title" \
                       --infobox "$key is already configured:\n\n$value" 7 60
                sleep 3
                return 0
                ;;
            msg)
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "$title" \
                       --msgbox "$key is already configured:\n\n$value" 8 60
                return 0
                ;;
            confirm)
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "$title" \
                       --yesno "$key is already configured:\n\n$value\n\nDo you want to reconfigure it?" 10 60
                if [[ $? -ne 0 ]]; then
                    return 0  # skip reconfiguration
                fi
                return 1  # proceed with reconfiguration
                ;;
            *)
                echo "Unknown mode: $mode"
                return 1
                ;;
        esac
    fi
    return 1  # not configured yet, proceed
}


# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Please use 'sudo $0'"
    fi
}

check_system_resources() {
    MIN_RAM_KB=$((8 * 1024 * 1024))  # 8 GB in KB
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')

    # Check if RAM is within the desired range
    if [ "$TOTAL_RAM_KB" -ge "$MIN_RAM_KB" ]; then
        success_msg "RAM check passed: $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB"
    else
        error_exit "RAM check failed: System has $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB RAM"
    fi

    MIN_DISK_GB=75  # Minimum disk space in GB
    TOTAL_DISK_GB=$(df / | tail -1 | awk '{print $2}' | awk '{printf "%.0f", $1/1024/1024}')

    # Check if disk space is within the desired range
    if [ "$TOTAL_DISK_GB" -ge "$MIN_DISK_GB" ]; then
        success_msg "Disk space check passed: $TOTAL_DISK_GB GB available"
    else
        error_exit "Disk space check failed: System has only $TOTAL_DISK_GB GB available"
    fi
}

check_kvm_support() {
    info_msg "Checking KVM prerequisites..."
    if ! grep -E 'vmx|svm' /proc/cpuinfo >/dev/null; then
        error_exit "CPU does not support hardware virtualization (agent)"
    fi
    success_msg "✓ CPU virtualization support detected"

    if ! lsmod | grep -q kvm; then
        error_exit "KVM kernel module is not loaded"
    fi
    success_msg "✓ KVM kernel module loaded"
}

# Function to detect the OS type and pkg mgr
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Cannot detect operating system. /etc/os-release not found."
    fi
    
    source /etc/os-release
    OS_TYPE=$ID
    OS_VERSION=$VERSION_ID
    VERSION_CODENAME=${VERSION_CODENAME:-}
    
    case "$OS_TYPE" in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            MYSQL_SERVICE="mysql"
            MYSQL_CONF_DIR="/etc/mysql/mysql.conf.d"
            ;;
        rhel|centos|ol|rocky|almalinux)
            PACKAGE_MANAGER="dnf"
            MYSQL_SERVICE="mysqld"
            MYSQL_CONF_DIR="/etc/my.cnf.d"
            ;;
        *)
            echo "Unsupported OS: $OS_TYPE"
            exit 1
            ;;
    esac

    log "OS Detection: $OS_TYPE with package manager: $PACKAGE_MANAGER"
}

get_ubuntu_codename_for_debian() {
    case "$1" in
        buster|bullseye)
            echo "focal"
            ;;
        bookworm|trixie)
            echo "jammy"
            ;;
        *)
            echo "ERROR: Unsupported Debian codename '$1'" >&2
            return 1
            ;;
    esac
}

update_system() {
    {
        echo "10"
        echo "# Updating package cache..."
        case "$PACKAGE_MANAGER" in
            apt)
                apt-get update 2>&1 | while IFS= read -r line; do
                    echo "XXX"
                    echo "30"
                    echo "# Updating package lists...\n\n$line"
                    echo "XXX"
                done

                echo "# Installing system updates..."
                apt-get upgrade -y 2>&1 | while IFS= read -r line; do
                    echo "XXX"
                    echo "75"
                    echo "# Installing updates...\n\n$line"
                    echo "XXX"
                done
                ;;
            dnf)
                dnf clean all 2>&1 | while IFS= read -r line; do
                    echo "XXX"
                    echo "20"
                    echo "# Cleaning package cache...\n\n$line"
                    echo "XXX"
                done

                dnf makecache 2>&1 | while IFS= read -r line; do
                    echo "XXX"
                    echo "40"
                    echo "# Updating package cache...\n\n$line"
                    echo "XXX"
                done

                dnf update -y 2>&1 | while IFS= read -r line; do
                    echo "XXX"
                    echo "75"
                    echo "# Installing system updates...\n\n$line"
                    echo "XXX"
                done
                ;;
        esac

        echo "XXX"
        echo "100"
        echo "# System update complete!"
        echo "XXX"
        sleep 2
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "System Update" \
               --gauge "Updating system packages..." 15 70 0

    # Verify update success
    if [[ $? -eq 0 ]]; then
        show_dialog info "System Update" "System packages have been successfully updated." 2
    else
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "Failed to update system packages. Please check the logs." 6 50
        return 1
    fi
}

configure_cloudstack_repo() {
    local repo_file=""
    local repo_complete_path=""
    case "$OS_TYPE" in
        ubuntu|debian)
            repo_file="/etc/apt/sources.list.d/cloudstack.list"
            ;;
        rhel|centos|ol|rocky|almalinux)
            repo_file="/etc/yum.repos.d/cloudstack.repo"
            ;;
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            exit 1
            ;;
    esac
    if [[ -f "$repo_file" ]]; then
        repo_complete_path=$(grep '^deb ' /etc/apt/sources.list.d/cloudstack.list | sed -E 's/^.*] //')
        show_dialog \
            "info" \
            "CloudStack Repository Configuration" "CloudStack repository is configured already: \n\n$repo_complete_path"
            set_tracker_field "repo_url" "$repo_complete_path"
        return 0
    fi

    local default_base_url="https://download.cloudstack.org/"
    local default_cs_version="4.20"
    local repo_base_url cs_version
    if [[ "$EXECUTION_MODE" == "PROMPT" ]]; then
        local form_output
        form_output=$(mktemp)
        dialog --clear --form "Configure CloudStack Repository" 12 70 2 \
            "Repo Base URL:" 1 1 "$default_base_url" 1 20 50 0 \
            "Version:"       2 1 "$default_cs_version"    2 20 50 0 \
            2> "$form_output"

        mapfile -t lines < "$form_output"
        repo_base_url="${lines[0]}"
        cs_version="${lines[1]}"
        rm -f "$form_output"
        if [[ -z "$repo_base_url" || -z "$cs_version" ]]; then
            show_dialog \
                "info" \
                "CloudStack Repo Configuration" \
                "Error: Repository Base URL and Version cannot be empty."
            error_exit "Invalid repository configuration"
        fi
        if [[ ! "$cs_version" =~ ^4\.1[8-9]$|^4\.2[0-1]$ ]]; then
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Error" \
                --msgbox "Unsupported CloudStack version: $cs_version\nSupported versions are: 4.18, 4.19, 4.20, 4.21" 8 60
            error_exit "Unsupported CloudStack version provided in repository configuration"
        fi
    else
        repo_base_url="$default_base_url"
        cs_version="$default_cs_version"
    fi

    local base_url=$(echo "$repo_base_url" | sed -E 's#(https?://[^/]+)/.*#\1/#')
    local gpg_url="${base_url}release.asc"
    case "$OS_TYPE" in
        ubuntu|debian)
            log "Configuring DEB repository for CloudStack version $cs_version from $repo_base_url"
            if [[ "$OS_TYPE" == "debian" ]]; then
                UBUNTU_CODENAME=$(get_ubuntu_codename_for_debian "$VERSION_CODENAME") || exit 1
            else
                UBUNTU_CODENAME="$VERSION_CODENAME"
            fi
            
            repo_complete_path="https://download.cloudstack.org/ubuntu $UBUNTU_CODENAME $cs_version"
            if [[ "$repo_base_url" != *download.cloudstack.org* ]]; then
                repo_complete_path="$repo_base_url/$cs_version /" 
            fi
            _configure_deb_repo "$gpg_url" "$repo_complete_path"
            ;;
        rhel|centos|ol|rocky|almalinux)
            local repo_path=$(determine_rpm_distro_version)
            local repo_complete_path=$repo_base_url/$repo_path/$cs_version/
            _configure_rpm_repo "$gpg_url" "$repo_complete_path"
            ;;
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            exit 1
            ;;
    esac
    log "Final DEB repo path: $repo_complete_path"
    set_tracker_field "repo_url" "$repo_complete_path"
}

_configure_deb_repo() {
    local gpg_key_url="$1"
    local repo_complete_path="$2"
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Confirm Repository" \
           --yesno "The following CloudStack repository will be added:\n\n$repo_complete_path\n\nProceed?" 12 70

    if [[ $? -ne 0 ]]; then
        error_exit "CloudStack repository configuration cancelled by user."
    fi

    {
        echo "Configuring CloudStack repository..."
        echo "Adding CloudStack's signing key..."

        if curl -fsSL "$gpg_key_url" | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null; then
            echo "CloudStack signing key added successfully."
        else
            error_exit "Failed to add CloudStack signing key."
        fi
        
        echo "Adding CloudStack repository..."
        if echo "deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] $repo_complete_path" | sudo tee /etc/apt/sources.list.d/cloudstack.list > /dev/null; then
            echo "CloudStack repository added successfully."
        else
            error_exit "Failed to add CloudStack repository."
        fi
    } | dialog --backtitle "$SCRIPT_NAME" \
                --title "Repository Configuration" \
                --programbox "Configuring CloudStack repository..." 15 70
}


_configure_rpm_repo () {
    local gpg_key_url="$1"
    local repo_base_url="$2"
    {
        echo "20"
        echo "# Adding CloudStack repository..."
        
        if cat > /etc/yum.repos.d/cloudstack.repo <<EOF
[cloudstack]
name=CloudStack
baseurl=$repo_complete_path
enabled=1
gpgcheck=0
gpgkey=$repo_base_url/release.asc
EOF
        then
            echo "# Repository added successfully"
        else
            error_exit "Failed to create CloudStack repository file"
        fi
    } | dialog --backtitle "$SCRIPT_NAME" \
            --title "Repository Configuration" \
            --programbox "Configuring CloudStack repository..." 15 70 0
}

determine_rpm_distro_version() {
    # Extract major version (8 or 9) from version string
    local major_version=${OS_VERSION%%.*}
    case "$OS_TYPE" in
        centos)
            echo "centos/$major_version"
            ;;
        rhel)
            echo "rhel/$major_version"
            ;;
        rocky|almalinux|ol)
            echo "el/$major_version"
            ;;
        *)
            error_exit "Unsupported OS type: $OS_TYPE"
            ;;
    esac
}

preinstall_dialog() {
    log "Updating package list..."
    case "$PACKAGE_MANAGER" in
        apt)
            apt-get update || error_exit "Failed to update package lists"
            ;;
        dnf)
            dnf makecache || error_exit "Failed to update package cache"
            ;;
    esac

    log "Installing 'dialog'..."
    case "$PACKAGE_MANAGER" in
        apt)
            apt-get install -y dialog || error_exit "Failed to install dialog"
            ;;
        dnf)
            dnf install -y dialog || error_exit "Failed to install dialog"
            ;;
    esac
}

strip_ansi() {
    sed 's/\x1b\[[0-9;]*[a-zA-Z]//g'
}

install_base_dependencies() {
    log "Starting base dependencies installation..."
    if ! command -v dialog &>/dev/null; then
        preinstall_dialog
    fi
    
    TMP_LOG=$(mktemp /tmp/install_base.XXXXXX.log)
    title="Installing base dependencies (qemu-kvm, python, curl, etc.)..."
    {   
        echo "XXX"
        echo "30"
        echo $title
        echo "XXX"

        PERCENT=31
        case "$PACKAGE_MANAGER" in
            apt)
                DEBIAN_FRONTEND=noninteractive \
                apt-get install -y qemu-kvm apt-utils curl openntpd openssh-server sshpass sudo wget jq htop tar nmap bridge-utils util-linux >> "$TMP_LOG" 2>&1 &
                ;;
            dnf)
                dnf install -y curl openssh-server chrony sshpass sudo wget jq tar nmap util-linux >> "$TMP_LOG" 2>&1 &
                ;;
        esac

        INSTALL_PID=$!
        PERCENT=31
        while kill -0 "$INSTALL_PID" 2>/dev/null; do
            echo "XXX"
            echo "$PERCENT"
            tail_output=$(tail -n 3 "$TMP_LOG" | strip_ansi | tr '\n' ' ' | cut -c -200)
            echo "$title\n\n$tail_output"
            echo "XXX"
            PERCENT=$((PERCENT + 1))
            [ "$PERCENT" -ge 98 ] && PERCENT=98
            sleep 1
        done

        wait "$INSTALL_PID" || error_exit "Base dependency installation failed"
        echo "XXX"
        echo "100"
        echo "Base dependencies installed successfully"
        echo "XXX"

    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Dependencies" \
               --gauge "Preparing system..." 15 70 0 
    show_dialog "info" "Dependencies Installation" "All Base dependencies installed successfully"
    log "Base dependencies installed successfully"
    
    rm -f "$TMP_LOG"
}

# Function to install packages based on the detected OS
install_package() {
    local package_name=$1
    case "$PACKAGE_MANAGER" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$package_name"
            return $?
            ;;
        dnf)
            dnf install -y "$package_name" >> "$log_file"
            return $?
            ;;
    esac
}

# Function to install CloudStack Management Server
install_management_server() {
    install_package "cloudstack-management"
    systemctl stop cloudstack-management
}

# Function to install CloudStack Usage Server
install_usage_server() {
    install_package "cloudstack-usage"
}

# Function to install KVM Agent
install_kvm_agent() {
    install_package "cloudstack-agent"
}

# Function to install MySQL Server
install_mysql_server() {
    install_package "mysql-server"
    systemctl start $MYSQL_SERVICE
}

# Function to install NFS Server
install_nfs_server() {
    case "$PACKAGE_MANAGER" in
        apt)
            apt-get install -y nfs-kernel-server nfs-common quota
            ;;
        dnf)
            dnf install -y nfs-utils quota
            ;;
    esac
}

select_components() {
    local temp_file=$(mktemp)
    
    dialog --clear --backtitle "$SCRIPT_NAME" \
           --title "Component Selection" \
           --checklist "Select CloudStack components to install:" 15 70 6 \
           "management" "CloudStack Management Server" on \
           "usage" "CloudStack Usage Server" off \
           "agent" "KVM Agent" on \
           "mysql" "MySQL Server" on \
           "nfs" "NFS Server" on \
           2> "$temp_file"
    
    if [[ $? -ne 0 ]]; then
        rm -f "$temp_file"
        error_exit "Component selection cancelled by user"
    fi
    
    # Read selected components
    mapfile -t SELECTED_COMPONENTS < <(tr ' ' '\n' < "$temp_file" | tr -d '"')
    rm -f "$temp_file"
    
    if [[ ${#SELECTED_COMPONENTS[@]} -eq 0 ]]; then
        error_exit "No components selected"
    fi
    
    log "Selected components: ${SELECTED_COMPONENTS[*]}"
}

display_components_versions() {
    local versions=()
    local component version_info

    for component in "${SELECTED_COMPONENTS[@]}"; do
        case "$component" in
            nfs)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy nfs-kernel-server 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info nfs-utils 2>/dev/null | awk '/Version     :/ {print $3}')
                fi
                versions+=("NFS Server: ${version_info:-Not Available}\n")
                ;;
            
            mysql)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy mysql-server 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info mysql-server 2>/dev/null | awk '/Version     :/ {print $3}')
                fi
                versions+=("MySQL Server: ${version_info:-Not Available}\n")
                ;;
            
            management)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-management 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-management 2>/dev/null | awk '/Version     :/ {print $3}')
                fi
                versions+=("CloudStack Management Server: ${version_info:-Not Available}\n")
                ;;
            
            agent)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-agent 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-agent 2>/dev/null | awk '/Version     :/ {print $3}')
                fi
                versions+=("CloudStack KVM Agent: ${version_info:-Not Available}\n")
                ;;
            
            usage)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-usage 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-usage 2>/dev/null | awk '/Version     :/ {print $3}')
                fi
                versions+=("CloudStack Usage Server: ${version_info:-Not Available\n}")
                ;;
        esac
    done

    dialog --backtitle "$SCRIPT_NAME" \
           --title "Installing Components" \
           --msgbox "Available versions from repository:\n\n$(printf '%s\n' "${versions[@]}")" 18 70
}

install_components() {
    TMP_LOG=$(mktemp /tmp/component_install.XXXXXX.log)
    local total_steps=${#SELECTED_COMPONENTS[@]}
    local current_step=0
    display_components_versions

    {
        for component in "${SELECTED_COMPONENTS[@]}"; do
            current_step=$((current_step + 1))
            local start_progress=$(((current_step - 1) * 100 / total_steps))
            local end_progress=$((current_step * 100 / total_steps))
            local percent_step=$start_progress

            : > "$TMP_LOG"
            local status_msg="[$current_step/$total_steps] Installing $component...\n\n"

            echo "XXX"
            echo "$start_progress"
            echo "$status_msg"
            echo "XXX"
            
            case "$component" in
                nfs)
                    install_nfs_server >> "$TMP_LOG" 2>&1 &
                    ;;
                mysql)
                    install_mysql_server >> "$TMP_LOG" 2>&1 &
                    ;;
                management)
                    install_management_server >> "$TMP_LOG" 2>&1 &
                    ;;
                agent)
                    install_kvm_agent >> "$TMP_LOG" 2>&1 &
                    ;;
                usage)
                    install_usage_server >> "$TMP_LOG" 2>&1 &
                    ;;
            esac

            INSTALL_PID=$!
            # Animate the progress for this component
            while kill -0 "$INSTALL_PID" 2>/dev/null; do
                echo "XXX"
                echo "$percent_step"
                tail_output=$(tail -n 5 "$TMP_LOG" | strip_ansi | tr '\n' ' ' | cut -c -300)
                echo "$status_msg $tail_output"
                echo "XXX"
                sleep 1
                percent_step=$((percent_step + 1))
                [ "$percent_step" -ge "$end_progress" ] && percent_step=$((end_progress - 1))
            done

            wait "$INSTALL_PID"
        done

        echo "XXX"
        echo "100"
        echo "All components installed successfully!"
        echo "XXX"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Components" \
               --gauge "Starting installation..." 15 70 0
}

configure_mysql() {
  MYSQL_VERSION=$(mysql -V 2>/dev/null || echo "MySQL not found")
  dialog --title "MySQL Configuration" --msgbox "Detected MySQL Version:\n$MYSQL_VERSION" 8 50
  if [[ "$MYSQL_VERSION" == "MySQL not found" ]]; then
    dialog --title "Error" --msgbox "MySQL is not installed. Please install MySQL first." 6 50
    return 1
  fi
  
  local config_file="$MYSQL_CONF_DIR/cloudstack.cnf"
  if [[ -f "$config_file" ]]; then
    dialog --title "MySQL Configuration" --msgbox "Configuration already exists at:\n$config_file\nSkipping MySQL setup." 8 60
    return
  fi

  mkdir -p "$MYSQL_CONF_DIR"

    if ! dialog --yesno "Do you want to configure MySQL for CloudStack?" 7 50; then
        dialog --msgbox "MySQL configuration skipped." 5 40
        return 0
    fi

  # ensure mysql is running
  if ! systemctl is-active --quiet $MYSQL_SERVICE; then
    dialog --title "MySQL Configuration" --msgbox "MySQL service is not running. Please start MySQL before proceeding." 6 50
    return 1
  fi

  sqlmode="$(mysql -B -e "show global variables like 'sql_mode'" 2>/dev/null | grep sql_mode | awk '{ print $2; }' | sed -e 's/ONLY_FULL_GROUP_BY,//')"

  if [[ -z "$sqlmode" ]]; then
    dialog --msgbox "Failed to fetch current SQL mode. Aborting." 6 50
    return 1
  fi
  
  cat > "$config_file" <<EOF
[mysqld]
server_id = 1
sql_mode = "$sqlmode"
innodb_rollback_on_timeout = 1
innodb_lock_wait_timeout = 600
max_connections = 1000
log_bin = mysql-bin
binlog_format = "ROW"
EOF

  systemctl restart $MYSQL_SERVICE && \
    dialog --msgbox "MySQL has been configured and restarted successfully." 6 50 || \
    dialog --msgbox "Failed to restart MySQL. Please check the service manually." 6 60
}

get_local_cidr() {
  local_ip=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | head -n1)
  echo "$local_ip"  # e.g., 10.1.1.53/24
}


get_export_cidr() {
  ip_cidr=$(get_local_cidr)
  # Convert from 10.1.1.53/24 → 10.1.1.0/24
  base_ip=$(echo "$ip_cidr" | cut -d/ -f1)
  prefix=$(echo "$ip_cidr" | cut -d/ -f2)

  # Use ipcalc or manual mask conversion
  if command -v ipcalc &>/dev/null; then
    network=$(ipcalc "$base_ip/$prefix" | grep -w 'Network' | awk '{print $2}')
  else
    # Fallback: simple /24 assumption
    network="${base_ip%.*}.0/$prefix"
  fi
  echo "$network"
}



configure_nfs_server() {
  dialog --title "NFS Configuration" --msgbox "Starting NFS storage configuration..." 6 50

  if grep -q "^/export " /etc/exports; then
    dialog --title "NFS Configuration" --msgbox "NFS is already configured. Skipping setup." 6 50
    return
  fi

  dialog --title "NFS Setup" --yesno "Do you want to configure the system as an NFS server with:\n\n• Export path: /export\n• Subdirs: /primary & /secondary\n• Permissions: rw, no_root_squash\n\nProceed?" 12 60
  [[ $? -ne 0 ]] && dialog --msgbox "NFS configuration skipped." 5 40 && return

    local export_cidr=$(get_export_cidr)
  # Step 1: Create exports and directories
  echo "/export  ${export_cidr}(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
  mkdir -p /export/primary /export/secondary
  exportfs -a

  # Step 2: Configure ports and services based on distro
  if [[ "$OS_TYPE" =~ ^(ubuntu|debian)$ ]]; then
    sed -i -e 's/^RPCMOUNTDOPTS="--manage-gids"$/RPCMOUNTDOPTS="-p 892 --manage-gids"/g' /etc/default/nfs-kernel-server
    sed -i -e 's/^STATDOPTS=$/STATDOPTS="--port 662 --outgoing-port 2020"/g' /etc/default/nfs-common
    grep -q 'NEED_STATD=yes' /etc/default/nfs-common || echo "NEED_STATD=yes" >> /etc/default/nfs-common
    sed -i -e 's/^RPCRQUOTADOPTS=$/RPCRQUOTADOPTS="-p 875"/g' /etc/default/quota

    systemctl restart nfs-kernel-server
    SERVICE_STATUS=$?
  
  elif [[ "$OS_TYPE" =~ ^(rhel|centos|ol|rocky|almalinux)$ ]]; then
    # Set ports in /etc/sysconfig/nfs if needed
    cat <<EOF >> /etc/sysconfig/nfs
MOUNTD_PORT=892
STATD_PORT=662
STATD_OUTGOING_PORT=2020
LOCKD_TCPPORT=32803
LOCKD_UDPPORT=32769
RQUOTAD_PORT=875
EOF

    systemctl enable --now rpcbind nfs-server
    systemctl restart nfs-server
    SERVICE_STATUS=$?

    # Open firewall ports if firewalld is running
    if systemctl is-active --quiet firewalld; then
      firewall-cmd --permanent --add-service=nfs
      firewall-cmd --permanent --add-service=mountd
      firewall-cmd --permanent --add-service=rpc-bind
      firewall-cmd --reload
    fi
  else
    dialog --title "Error" --msgbox "Unsupported distribution: $OS_TYPE" 6 50
    return 1
  fi

  # Step 3: Final result
  if [[ $SERVICE_STATUS -eq 0 ]]; then
    exports_list=$(exportfs)
    dialog --title "NFS Configuration Complete" --msgbox "NFS Server configured and restarted successfully.\n\nCurrent exports:\n$exports_list" 15 70
  else
    dialog --title "Error" --msgbox "Failed to restart NFS server. Please check the service logs." 6 60
  fi
}

configure_management_server() {
    if systemctl is-active cloudstack-management > /dev/null; then
        dialog --title "Info" --msgbox "CloudStack Management Server is already running.\nSkipping DB deployment." 7 60
        return
    fi

    if [[ -f "/etc/cloudstack/management/db.properties" ]]; then
        local current_db_host=$(grep "^cluster.node.IP" /etc/cloudstack/management/db.properties | cut -d= -f2)
        dialog --title "Info" \
               --yesno "CloudStack database appears to be already configured.\nCurrent database host: $current_db_host\n\nDo you want to reconfigure it?" 10 60
        if [[ $? -ne 0 ]]; then
            dialog --title "Info" \
                   --msgbox "Skipping database configuration." 6 50
            return 0
        fi
    fi

    if [ -z "$BRIDGE" ]; then
        BRIDGE=$(dialog --inputbox "Enter the bridge interface name:" 8 50 "$BRIDGE" 3>&1 1>&2 2>&3)
    fi

    if [[ -z "$BRIDGE" ]]; then
        dialog --title "Error" --msgbox "Bridge interface name cannot be empty.\nAborting." 7 50
        return 1
    fi

    # Get the bridge IP
    cloudbr0_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)

    if [[ -z "$cloudbr0_ip" ]]; then
        dialog --title "Error" --msgbox "Could not determine IP address of interface '$BRIDGE'.\nAborting." 8 60
        return 1
    fi

    dialog --title "Info" --msgbox "Using IP address: $cloudbr0_ip for CloudStack DB setup." 7 60
    # Check if MySQL is running
    if ! systemctl is-active $MYSQL_SERVICE > /dev/null; then
        dialog --title "Error" --msgbox "MySQL service is not running. Please start MySQL before proceeding." 7 60
        return 1
    fi
    {
        echo "# Starting CloudStack database deployment..."
        cloudstack-setup-databases cloud:cloud@localhost --deploy-as=root: -i "$cloudbr0_ip" 2>&1 | \
            while IFS= read -r line; do
                msg=$(echo "$line" | strip_ansi)
                echo "XXX"
                echo "50"
                echo "Deploying CloudStack Database...\n\n$msg"
                echo "XXX"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Database Deployment" \
               --gauge "Starting database deployment..." 10 70 0

    {
        echo "# Starting CloudStack Management Server setup..."
        cloudstack-setup-management 2>&1 | \
            while IFS= read -r line; do
                msg=$(echo "$line" | strip_ansi)
                echo "XXX"
                echo "75"
                echo "Deploying Management Server...\n\n$msg"
                echo "XXX"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Management Server Setup" \
               --gauge "Starting management server setup..." 10 70 0

    sleep 5
    show_dialog "CloudStack Configuration" "CloudStack Management Server has been configured."
}

configure_kvm_agent() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "KVM Host Configuration" \
           --infobox "Starting KVM host configuration..." 5 50

    # Configure VNC
    {
        echo "XXX"
        echo "10"
        echo "Configuring VNC access..."
        echo "XXX"
        if sed -i -e 's/\#vnc_listen.*$/vnc_listen = "0.0.0.0"/g' /etc/libvirt/qemu.conf; then
            echo "XXX"
            echo "25"
            echo "VNC configuration successful"
            echo "XXX"
        else
            error_exit "Failed to configure VNC"
        fi

        if ! grep '^LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd > /dev/null; then
            echo 'LIBVIRTD_ARGS="--listen"' >> /etc/default/libvirtd
        fi

        if ! grep -q '^remote_mode="legacy"' /etc/libvirt/libvirtd.conf; then
            echo 'remote_mode="legacy"' >> /etc/libvirt/libvirtd.conf
        fi

        echo "XXX"
        echo "40"
        echo "Setting up libvirt TCP access..."
        echo "XXX"
        cat >> /etc/libvirt/libvirtd.conf <<EOF
listen_tcp = 1
listen_tls = 0
tcp_port = "16509"
mdns_adv = 0
auth_tcp = "none"
EOF
        echo "XXX"
        echo "60"
        echo "Configuring libvirt sockets..."
        echo "XXX"
        systemctl mask libvirtd.socket \
            libvirtd-ro.socket \
            libvirtd-admin.socket \
            libvirtd-tls.socket \
            libvirtd-tcp.socket &>/dev/null

        echo "XXX"
        echo "75"
        echo "Configuring security policies..."
        echo "XXX"
        case "$OS_TYPE" in
            ubuntu|debian)
                echo "# Configuring AppArmor..."
                if command -v apparmor_parser >/dev/null; then
                    # Check if profiles exist before trying to disable them
                    local profiles=(
                        "/etc/apparmor.d/usr.sbin.libvirtd"
                        "/etc/apparmor.d/usr.lib.libvirt.virt-aa-helper"
                    )
                    
                    for profile in "${profiles[@]}"; do
                        if [[ -f "$profile" ]]; then
                            if [[ ! -L "/etc/apparmor.d/disable/$(basename "$profile")" ]]; then
                                ln -sf "$profile" "/etc/apparmor.d/disable/" 2>/dev/null
                                if [[ -f "$profile" ]]; then
                                    if ! apparmor_parser -R "$profile" 2>/dev/null; then
                                        echo "XXX"
                                        echo "80"
                                        echo "# Warning: Failed to remove profile: $(basename "$profile")"
                                        echo "XXX"
                                    fi
                                fi
                            else
                                echo "Profile $(basename "$profile") already disabled"
                            fi
                        else
                            echo "Profile $profile not found, skipping"
                        fi
                    done
                    
                    # Restart AppArmor service to apply changes
                    if systemctl is-active --quiet apparmor; then
                        systemctl restart apparmor &>/dev/null || true
                    fi
                else
                    echo "AppArmor not installed, skipping configuration"
                fi
                ;;
            rhel|centos|ol|rocky|almalinux)
                # SELinux configuration if needed
                setsebool -P virt_use_nfs 1
                ;;
        esac

        echo "XXX"
        echo "85"
        echo "Configuring firewall..."
        echo "XXX"
        ports=(
            "22"           # SSH
            "1798"         # CloudStack Management Server
            "16509"        # Libvirt
            "16514"        # Libvirt
            "5900:6100"    # VNC
            "49152:49216"  # Live Migration
        )
        case "$OS_TYPE" in
            ubuntu|debian)
                if command -v ufw >/dev/null; then
                    for port in "${ports[@]}"; do
                        ufw allow proto tcp from any to any port "$port"
                    done
                        ufw reload
                else
                    warn_msg "UFW not found, skipping firewall configuration"
                fi
                ;;
            rhel|centos|ol|rocky|almalinux)
                if command -v firewall-cmd >/dev/null; then
                    for port in "${ports[@]}"; do
                        firewall-cmd --permanent --add-port="$port"
                    done
                    firewall-cmd --reload
                fi
                ;;
        esac
        systemctl restart libvirtd
        sleep 2

        echo "XXX"
        echo "90"
        echo "Update agent.properties!"
        echo "XXX"
        AGENT_PROPERTIES="/etc/cloudstack/agent/agent.properties"
        if [ -f "$AGENT_PROPERTIES" ]; then
            local agent_guid=$(uuidgen)
            sed -i '/^guid=/d' "$AGENT_PROPERTIES"
            sed -i '/^private\.network\.device=/d' "$AGENT_PROPERTIES"
            {
                echo "guid=$agent_guid"
                echo "private.network.device=$BRIDGE"
            } >> "$AGENT_PROPERTIES"
        else
            error_exit "Agent properties file not found at $AGENT_PROPERTIES"
        fi
    
        systemctl restart cloudstack-agent
        sleep 5

        echo "XXX"
        echo "100"
        echo "KVM host configuration completed!"
        echo "XXX"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "KVM Host Configuration" \
               --gauge "Configuring KVM host..." 10 70 0

    # Show configuration summary
    local summary="KVM Host Configuration Summary:\n\n"
    summary+="✓ VNC configured for remote access\n"
    summary+="✓ Libvirt TCP access enabled\n"
    summary+="✓ Security policies configured\n"
    summary+="✓ Firewall rules added for ports:\n"
    summary+="  - SSH (22)\n"
    summary+="  - Libvirt (16509)\n"
    summary+="  - VNC (5900-6100)\n"
    summary+="  - Live Migration (49152-49216)\n"

    dialog --backtitle "$SCRIPT_NAME" \
           --title "Configuration Complete" \
           --msgbox "$summary" 15 60

    # Verify configuration
    if ! systemctl is-active --quiet libvirtd; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Warning" \
               --msgbox "Libvirt service is not running! Please check system logs." 6 60
    fi
}

configure_usage_server() {
    sleep 5
}

wait_for_management_server() {
    local timeout=300  # 5 minutes timeout
    local interval=10  # Check every 10 seconds
    local elapsed=0
    local url="http://$HOST_IP:8080/client/api"

    {
        while [ $elapsed -lt $timeout ]; do
            echo "XXX"
            echo "$((elapsed * 100 / timeout))"
            echo "Waiting for Management Server to be ready...\n\nElapsed time: ${elapsed}s / ${timeout}s"
            echo "XXX"
            
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
            if [[ "$status_code" == "200" || "$status_code" == "401" ]]; then
                echo "XXX"
                echo "100"
                echo "Management Server is ready!"
                echo "XXX"
                return 0
            fi
            
            sleep $interval
            elapsed=$((elapsed + interval))
        done

        echo "XXX"
        echo "100"
        echo "Timeout waiting for Management Server!"
        echo "XXX"
        return 1
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Management Server Check" \
               --gauge "Waiting for Management Server to start..." 10 70 0
}

check_cloudmonkey() {
    {
        echo "10"
        echo "# Checking CloudMonkey installation..."
        if ! command -v cmk &>/dev/null; then
            echo "XXX"
            echo "100"
            echo "CloudMonkey (cmk) not found!"
            echo "XXX"
            return 1
        fi

        echo "50"
        echo "# Initializing CloudMonkey..."
        if ! cmk sync &>/dev/null; then
            echo "XXX"
            echo "100"
            echo "Failed to initialize CloudMonkey!"
            echo "XXX"
            return 1
        fi

        echo "100"
        echo "# CloudMonkey ready!"
        return 0
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "CloudMonkey Check" \
               --gauge "Checking CloudMonkey..." 8 60 0
}

show_cloudstack_banner() {
    local banner="
    █████████████████████████████████████████████████████████████
    █─▄▄▄─█▄─▄███─▄▄─█▄─██─▄█▄─▄▄▀█─▄▄▄▄█─▄─▄─██▀▄─██─▄▄▄─█▄─█─▄█
    █─███▀██─██▀█─██─██─██─███─██─█▄▄▄▄─███─████─▀─██─███▀██─▄▀██
    ▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀▄▄▄▄▀▀▄▄▄▄▀▀▄▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

    CloudStack Installation Complete!
    --------------------------------
    Access Details:

    URL: http://$HOST_IP:8080/client
    Username: admin
    Password: password

    Note: Please change the default password after first login.
    "

    dialog --backtitle "$SCRIPT_NAME" \
        --title "Installation Complete" \
        --colors \
        --msgbox "\Z1$banner\Zn" 20 70
}

find_free_ip_range() {
    local network=$1
    local start_from=$2
    local count=$3
    local tempfile=$(mktemp)

    # Scan network to find used IPs
    nmap -sn -n "$network" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > "$tempfile"

    # Get base network
    local base_net="${network%.*}"
    local free_ips=()
    local current=$start_from
    
    while [[ ${#free_ips[@]} -lt $count && $current -lt 255 ]]; do
        if ! grep -q "$base_net.$current" "$tempfile"; then
            free_ips+=("$base_net.$current")
        fi
        ((current++))
    done
    
    rm -f "$tempfile"
    echo "${free_ips[@]}"
}

deploy_zone() {
    log "Starting zone deployment..."
    if [[ -z "$BRIDGE" ]]; then
        BRIDGE=$(dialog --backtitle "$SCRIPT_NAME" \
            --title "KVM Host Configuration" \
            --inputbox "Enter the bridge interface name:" \
            8 60 "$BRIDGE" 3>&1 1>&2 2>&3)
    fi

    HOST_IP=$(ip -4 addr show "$BRIDGE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    GATEWAY=$(ip route | grep default | grep "$BRIDGE" | awk '{print $3}')

    local input_ip=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --inputbox "Detected Host IP: $HOST_IP\n\nYou can modify these values if needed." 10 60 "$HOST_IP" 3>&1 1>&2 2>&3)
    local input_gw=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --inputbox "Detected Gateway: $GATEWAY\n\nYou can modify these values if needed." 10 60 "$GATEWAY" 3>&1 1>&2 2>&3)  
    KVM_HOST_IP=${input_ip:-$HOST_IP}
    GATEWAY=${input_gw:-$GATEWAY}

    if [[ -z "$KVM_HOST_IP" || -z "$GATEWAY" ]]; then
        error_exit "Could not determine host IP or gateway. Is bridge $BRIDGE configured properly?"
    fi


    # Prompt for root password before starting zone deployment
    local MAX_ATTEMPTS=3
    local attempt=0
    local root_pass
    while true; do
        root_pass=$(dialog --backtitle "$SCRIPT_NAME" \
            --title "Host Configuration" \
            --insecure \
            --passwordbox "Enter root password for KVM host ($KVM_HOST_IP):" 8 60 \
            3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Cancelled" \
                --msgbox "Zone deployment cancelled." 6 50
            return 1
        fi

        if [[ -z "$root_pass" ]]; then
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Error" \
                --msgbox "Password cannot be empty. Please enter a valid password." 6 60
            continue
        fi
        
        if sshpass -p "$root_pass" ssh  -o StrictHostKeyChecking=no \
                                        -o ConnectTimeout=5 \
                                        -o LogLevel=ERROR \
                                        -o UserKnownHostsFile=/dev/null \
                                        root@"$KVM_HOST_IP" "echo 2>/dev/null"; then
            break
        else
            attempt=$((attempt + 1))
            if [[ $attempt -ge $MAX_ATTEMPTS ]]; then
                dialog --backtitle "$SCRIPT_NAME" \
                    --title "Error" \
                    --msgbox "Failed to connect to $KVM_HOST_IP after $MAX_ATTEMPTS attempts. Aborting zone deployment." 6 60
                return 1
            fi
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Error" \
                --msgbox "Failed to connect to KVM host. Please check the IP and password.\nAttempts left: $((MAX_ATTEMPTS - attempt))" 8 60    
        fi
    done

    if ! wait_for_management_server; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "Management Server did not become ready in time.\nPlease check the server status and logs." 8 60
        return 1
    fi

    if ! check_cloudmonkey; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "CloudMonkey is not available or failed to initialize.\nPlease install CloudMonkey and try again." 8 60
        return 1
    fi

    local network="${HOST_IP%.*}.0/24"
    # Find IPs for different purposes
    local public_ips=($(find_free_ip_range "$network" 11 20))  # 20 IPs for public
    local pod_ips=($(find_free_ip_range "$network" 31 20))     # 20 IPs for pod
    local guest_ips=($(find_free_ip_range "$network" 51 50))   # 50 IPs for guest


    # Default values
    local defaults=(
        "Zone Name" "Zone1"
        "Guest CIDR" "172.16.1.0/24"
        "Public Start IP" "${public_ips[0]}"
        "Public End IP" "${public_ips[-1]}"
        "Pod Start IP" "${pod_ips[0]}"
        "Pod End IP" "${pod_ips[-1]}"
        "Guest Start IP" "${guest_ips[0]}"
        "Guest End IP" "${guest_ips[-1]}"
        "VLAN Range" "100-200"
        "Physical Network" "Physical Network 1"
        "Pod Name" "Pod1"
        "Cluster Name" "Cluster1"
        "Primary Storage Name" "Primary1"
        "Secondary Storage Name" "Secondary1"
        "NFS Server IP" "$HOST_IP"
        "Primary Storage Path" "/export/primary"
        "Secondary Storage Path" "/export/secondary"
    )

    # Create form entries
    local form_height=$((${#defaults[@]} / 2 + 8))
    local form_entries=()
    local i=0
    while [[ $i -lt ${#defaults[@]} ]]; do
        form_entries+=("${defaults[i]}")     # Label
        form_entries+=("$((i/2+1))")         # Row
        form_entries+=("1")                  # Label column
        form_entries+=("${defaults[i+1]}")   # Default value
        form_entries+=("$((i/2+1))")         # Row for input
        form_entries+=("35")                 # Input column
        form_entries+=("30")                 # Field width
        form_entries+=("0")                  # Max input length
        ((i+=2))
    done


    # show form entries
    echo "Form Entries:"
    for entry in "${form_entries[@]}"; do
        echo "$entry"
    done

    form_args=(
        --backtitle "$SCRIPT_NAME"
        --title "Zone Configuration"
        --form "Configure Zone Deployment Parameters:"
        $form_height 70 0
    )

    for ((i=0; i<${#form_entries[@]}; i+=8)); do
        form_args+=(
            "${form_entries[i]}"      # Label
            "${form_entries[i+1]}"    # Row
            "${form_entries[i+2]}"    # Label column
            "${form_entries[i+3]}"    # Default value
            "${form_entries[i+4]}"    # Input row
            "${form_entries[i+5]}"    # Input column
            "${form_entries[i+6]}"    # Field width
            "${form_entries[i+7]}"    # Max length
        )
    done
    if ! results=$(dialog "${form_args[@]}" 2>&1 >/dev/tty); then
        dialog --backtitle "$SCRIPT_NAME" \
            --title "Cancelled" \
            --msgbox "Zone configuration was cancelled." 6 50
        return 1
    fi

    # Convert results string into array
    mapfile -t results <<< "$results"

    # Map results to variables
    local zone_name="${results[0]}"
    local guest_cidr="${results[1]}"
    local public_start="${results[2]}"
    local public_end="${results[3]}"
    local pod_start="${results[4]}"
    local pod_end="${results[5]}"
    local guest_start="${results[6]}"
    local guest_end="${results[7]}"
    local vlan_range="${results[8]}"
    local phy_name="${results[9]}"
    local pod_name="${results[10]}"
    local cluster_name="${results[11]}"
    local primary_name="${results[12]}"
    local secondary_name="${results[13]}"
    local nfs_server="${results[14]}"
    local primary_path="${results[15]}"
    local secondary_path="${results[16]}"
    local network_type="Advanced"

    # Show confirmation
    local confirm_msg="Please confirm the following configuration:\n\n"
    confirm_msg+="Zone: $zone_name (${network_type})\n"
    confirm_msg+="Guest CIDR: $guest_cidr\n"
    confirm_msg+="Public IPs: $public_start - $public_end\n"
    confirm_msg+="Pod IPs: $pod_start - $pod_end\n"
    confirm_msg+="Guest IPs: $guest_start - $guest_end\n"
    confirm_msg+="VLAN Range: $vlan_range\n"

    if ! dialog --backtitle "$SCRIPT_NAME" \
                --title "Confirm Configuration" \
                --yesno "$confirm_msg" 15 60; then
        return 1
    fi

    local zone_id=""
    local pod_id=""
    local cluster_id="" 
    {
        echo "10"
        echo "# Starting Zone deployment..."

        zone_output=$(cmk create zone name="${zone_name}" \
            networktype="$network_type" \
            dns1="$DNS" \
            internaldns1="$DNS" \
            localstorageenabled=true \
            securitygroupenabled=false \
            guestcidraddress="$guest_cidr")

        if ! zone_id=$(echo "$zone_output" | jq -r '.zone.id' 2>/dev/null); then
            echo "100"
            echo "Failed to create zone: $zone_output"
            return 1
        fi

        echo "20"
        echo "# Creating Physical Network..."
        local phy_id=$(cmk create physicalnetwork name="$phy_name" \
            zoneid="$zone_id" \
            isolationmethods="VLAN" | jq -r '.physicalnetwork.id')
        
        [[ -z "$phy_id" ]] && error_exit "Failed to create physical network"
        
        echo "30"
        echo "# Adding Traffic Types..."
        # Add Traffic Types
        cmk add traffictype traffictype=Management physicalnetworkid="$phy_id"
        cmk add traffictype traffictype=Guest physicalnetworkid="$phy_id"
        cmk add traffictype traffictype=Public physicalnetworkid="$phy_id"

        echo "35"
        echo "# Adding IP Ranges..."

        # Add Public IP Range
        if ! cmk create vlaniprange \
            zoneid="$zone_id" \
            vlan=untagged \
            gateway="$GATEWAY" \
            netmask="$NETMASK" \
            startip="$public_start" \
            endip="$public_end" \
            forvirtualnetwork=true; then
                echo "XXX"
                echo "100"
                echo "Failed to add Public IP range"
                echo "XXX"
                return 1
        fi
        cmk update physicalnetwork id=$phy_id vlan=$vlan_range
        
        echo "40"
        echo "Configuring Virtual Router..."
        cmk update physicalnetwork state=Enabled id="$phy_id"
        
        local nsp_id=$(cmk list networkserviceproviders name=VirtualRouter physicalnetworkid="$phy_id" | jq -r '.networkserviceprovider[0].id')
        local vre_id=$(cmk list virtualrouterelements nspid="$nsp_id" | jq -r '.virtualrouterelement[0].id')
        
        cmk configure virtualrouterelement enabled=true id="$vre_id"
        cmk update networkserviceprovider state=Enabled id="$nsp_id"
        
        echo "XXX"
        echo "50"
        echo "Creating Pod..."
        echo "XXX"
        pod_id=$(cmk create pod name="$pod_name" \
            zoneid="$zone_id" \
            gateway="$GATEWAY" \
            netmask="$NETMASK" \
            startip="$pod_start" \
            endip="$pod_end" | jq -r '.pod.id')
        
        [[ -z "$pod_id" ]] && error_exit "Failed to create pod"
        
        echo "XXX"
        echo "60"
        echo "Adding Cluster..."
        echo "XXX"
        cluster_id=$(cmk add cluster \
            zoneid="$zone_id" \
            podid="$pod_id" \
            clustername="$cluster_name" \
            clustertype=CloudManaged \
            hypervisor=KVM | jq -r '.cluster[0].id')

        [[ -z "$cluster_id" ]] && error_exit "Failed to add cluster"
        
        echo "XXX"
        echo "70"
        echo "Adding Host..."
        echo "XXX"
        # Add Host
        cmk add host zoneid="$zone_id" \
            podid="$pod_id" \
            clusterid="$cluster_id" \
            hypervisor=KVM \
            username=root \
            password="$root_pass" \
            url="http://$KVM_HOST_IP"
        
        echo "XXX"
        echo "80"
        echo "Adding Primary Storage..."
        echo "XXX"
        # Add Primary Storage
        cmk create storagepool name="$primary_name" \
            zoneid="$zone_id" \
            podid="$pod_id" \
            clusterid="$cluster_id" \
            url="nfs://$nfs_server$primary_path" \
            hypervisor=KVM \
            scope=zone
        
        echo "XXX"
        echo "90"
        echo "Adding Secondary Storage..."
        echo "XXX"
        # Add Secondary Storage
        cmk add imagestore name="$secondary_name" \
            zoneid="$zone_id" \
            url="nfs://$nfs_server$secondary_path" \
            provider=NFS

        echo "XXX"
        echo "95"
        echo "Enabling Zone..."
        echo "XXX"
        cmk update zone allocationstate=Enabled id="$zone_id"
        
        echo "XXX"
        echo "100"
        echo "Zone deployment completed successfully!"
        echo "XXX"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Zone Deployment" \
               --gauge "Deploying CloudStack Zone..." 10 70 0

    # Show final success message
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Success" \
           --msgbox "CloudStack Zone has been successfully deployed!" 12 60
    show_cloudstack_banner
}

select_zone_deployment() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Zone Deployment" \
           --yesno "Would you like to deploy a new CloudStack Zone?\n\nThis will:\n\n1. Create a new Zone\n2. Configure Network offerings\n3. Add the first Pod\n4. Add the first Cluster\n5. Add the first Host\n\nDeploy Zone now?" 15 60

    return $?
}


configure_components() {
    local total_steps=${#SELECTED_COMPONENTS[@]}
    local current_step=0
    
    # Function to check if component is selected
    is_component_selected() {
        local component=$1
        [[ " ${SELECTED_COMPONENTS[@]} " =~ " $component " ]]
    }

    # Function to update progress
    update_progress() {
        local message=$1
        local step=$2
        local percent=$((step * 100 / total_steps))
        echo "XXX"
        echo $percent
        echo "$message"
        echo "XXX"
    }

    # First configure core dependencies if selected
    # 1. Configure MySQL (if selected)
    if is_component_selected "mysql"; then
        current_step=$((current_step + 1))
        update_progress "Configuring MySQL Server..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "" 10 70 0
        configure_mysql
    fi

    # 2. Configure NFS (if selected)
    if is_component_selected "nfs"; then
        current_step=$((current_step + 1))
        update_progress "Configuring NFS Server..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "" 10 70 0
        configure_nfs_server
    fi

    # 3. Configure Management Server (if selected)
    if is_component_selected "management"; then
        # Check if dependencies are configured
        if is_component_selected "mysql" && ! systemctl is-active --quiet $MYSQL_SERVICE; then
            dialog --backtitle "$SCRIPT_NAME" \
                   --title "Error" \
                   --msgbox "MySQL must be running before configuring Management Server" 6 60
            return 1
        fi
        
        current_step=$((current_step + 1))
        update_progress "Configuring Management Server..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "" 10 70 0
        configure_management_server
    fi

    # 4. Configure KVM Agent (if selected)
    if is_component_selected "agent"; then
        if is_component_selected "management" && ! systemctl is-active --quiet cloudstack-management; then
            dialog --backtitle "$SCRIPT_NAME" \
                   --title "Error" \
                   --msgbox "Management Server must be running before configuring KVM Agent" 6 60
            return 1
        fi
        
        current_step=$((current_step + 1))
        if ! dialog --backtitle "$SCRIPT_NAME" \
                   --title "Configure KVM Agent" \
                   --yesno "Configure KVM Host Agent.\n\nDo you want to proceed?" 10 60; then
            dialog --backtitle "$SCRIPT_NAME" \
                   --title "Skipped" \
                   --msgbox "KVM Host Agent configuration skipped." 6 50
            return 1
        fi
        update_progress "Configure KVM Agent..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "" 10 70 0
        configure_kvm_agent
    fi

    # 5. Configure Usage Server (if selected)
    if is_component_selected "usage"; then
        if is_component_selected "management" && ! systemctl is-active --quiet cloudstack-management; then
            dialog --backtitle "$SCRIPT_NAME" \
                   --title "Error" \
                   --msgbox "Management Server must be running before configuring Usage Server" 6 60
            return 1
        fi
        current_step=$((current_step + 1))
        update_progress "Configuring Usage Server..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
                --gauge "" 10 70 0
        configure_usage_server
    fi

    # Show final progress
    update_progress "Configuration complete!" $total_steps | \
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Configuring Components" \
           --gauge "" 10 70 0
    sleep 2

    # Show configuration summary
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Configuration Summary" \
           --msgbox "Configured components in order:\n\n$(
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " mysql " ]] && echo "✓ MySQL Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " nfs " ]] && echo "✓ NFS Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]] && echo "✓ Management Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " agent " ]] && echo "✓ KVM Agent\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]] && echo "✓ Usage Server\n"
           )" 15 60
}

configure_cloud_init() {
    # Check if already configured
    if grep -q 'config: disabled' /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg 2>/dev/null; then
        dialog --backtitle "$SCRIPT_NAME" \
                --title "Cloud-init Configuration" \
                --msgbox "Cloud-init network configuration already disabled." 6 50
        return 0
    fi

    {
        echo "50"
        echo "# Disabling cloud-init network configuration..."
        echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
        
        echo "100"
        echo "# Configuration complete!"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Cloud-init Configuration" \
               --gauge "Configuring cloud-init..." 8 60 0
}

show_dialog() {
    local mode="$1"
    local title="$2"
    local msg="$3"
    local seconds="${4:-3}"

    case "$mode" in
        info)
            dialog --backtitle "$SCRIPT_NAME" \
                    --title "$title" \
                    --infobox "$msg" 7 60
            sleep "$seconds"
            return 0
            ;;
        msg)
            dialog --backtitle "$SCRIPT_NAME" \
                    --title "$title" \
                    --msgbox "$msg" 8 60
            return 0
            ;;
        confirm)
            dialog --backtitle "$SCRIPT_NAME" \
                    --title "$title" \
                    --yesno "$msg" 10 60
            if [[ $? -ne 0 ]]; then
                return 0
            fi
            return 1
            ;;
        *)
            echo "Unknown mode: $mode"
            return 1
            ;;
    esac
}

configure_network() {
    local new_bridge=$(dialog --inputbox "Enter the name for the bridge:" 8 60 "$BRIDGE" 3>&1 1>&2 2>&3)
    if [[ -n "$new_bridge" && "$new_bridge" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; then
        BRIDGE="$new_bridge"
    fi

    # First check if bridge already exists
    if ip link show "$BRIDGE" &>/dev/null; then
        local bridge_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)
        show_dialog \
            "info" \
            "Network Configuration" "Bridge interface $BRIDGE already exists with IP $bridge_ip\nSkipping network configuration."
        return 0
    fi

    # Gather interface, IP, gateway
    interface=$(ip -o link show | awk -F': ' '/state UP/ && $2!~/^lo/ {print $2; exit}')
    [[ -n "$interface" ]] || error "No active non-loopback interface found."

    hostipandsub=$(ip -4 addr show dev "$interface" | awk '/inet / {print $2; exit}')
    gateway=$(ip route show default | awk '/default/ {print $3; exit}')

    # Rest of the existing configure_network code follows...
    if [[ "$OS_TYPE" =~ ^(ubuntu|debian)$ ]]; then
        dialog --backtitle "$SCRIPT_NAME" \
               --infobox "Configuring bridge $BRIDGE using Netplan..." 5 50
        sleep 1

        cfgfile="/etc/netplan/01-bridge-$BRIDGE.yaml"
        cat > "$cfgfile" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: false
      dhcp6: false
      optional: true
  bridges:
    $BRIDGE:
      interfaces: [$interface]
      addresses: [$hostipandsub]
      routes:
        - to: default
          via: $gateway
      nameservers:
        addresses: [$DNS]
      parameters:
        stp: false
        forward-delay: 0
EOF
        chmod 600 "$cfgfile"
        configure_cloud_init
        rm -f /etc/netplan/50-cloud-init.yaml

        if netplan generate && netplan apply; then
            dialog --backtitle "$SCRIPT_NAME" \
                   --title "Success" \
                   --msgbox "Bridge $BRIDGE configured successfully with Netplan." 7 60
        else
            error_exit "Failed to apply Netplan configuration"
        fi

    elif [[ "$OS_TYPE" =~ ^(rhel|centos|ol|rocky|almalinux)$ ]]; then
        {
            echo "10"
            echo "# Configuring bridge interface $BRIDGE..."
            
            # Create bridge
            if output=$(nmcli connection add type bridge \
                con-name "$BRIDGE" \
                ifname "$BRIDGE" \
                ipv4.addresses "$hostipandsub" \
                ipv4.gateway "$gateway" \
                ipv4.dns "$DNS" \
                ipv4.method manual \
                autoconnect yes 2>&1); then
                echo "XXX"
                echo "30"
                echo "# Bridge created successfully\n$output"
                echo "XXX"
            else
                echo "XXX"
                echo "100"
                echo "# Failed to create bridge: $output"
                echo "XXX"
                exit 1
            fi

            sleep 2
            
            # Add ethernet interface as slave
            echo "XXX"
            echo "50"
            echo "# Adding interface $interface to bridge..."
            echo "XXX"
            
            local slave_name="${interface}-slave-$BRIDGE"
            if output=$(nmcli connection add type ethernet \
                slave-type bridge \
                con-name "$slave_name" \
                ifname "$interface" \
                master "$BRIDGE" 2>&1); then
                echo "XXX"
                echo "70"
                echo "# Interface added successfully\n$output"
                echo "XXX"
            else
                echo "XXX"
                echo "100"
                echo "# Failed to add interface: $output"
                echo "XXX"
                exit 1
            fi

            sleep 2

            # Activate connections
            echo "XXX"
            echo "90"
            echo "# Activating network connections..."
            echo "XXX"
            
            if output=$(nmcli connection up "$slave_name" 2>&1); then
                echo "XXX"
                echo "95"
                echo "# Slave interface activated\n$output"
                echo "XXX"
            else
                echo "XXX"
                echo "100"
                echo "# Failed to activate slave interface: $output"
                echo "XXX"
                exit 1
            fi

            sleep 5

            if output=$(nmcli connection up "$BRIDGE" 2>&1); then
                echo "XXX"
                echo "100"
                echo "# Bridge activated successfully\n$output"
                echo "XXX"
            else
                echo "XXX"
                echo "100"
                echo "# Failed to activate bridge: $output"
                echo "XXX"
                exit 1
            fi

            sleep 2

        } | dialog --backtitle "$SCRIPT_NAME" \
                --title "Network Configuration" \
                --gauge "Configuring network with NetworkManager..." 10 70 0

        # Verify the configuration
        if ip link show "$BRIDGE" &>/dev/null; then
            show_dialog \
                "info" \
                "Network Configuration" \
                "Bridge $BRIDGE configured successfully with IP $(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)." 5
        else
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Error" \
                --msgbox "Failed to configure bridge $BRIDGE. Check system logs." 7 60
            return 1
        fi
    else
        error_exit "Unsupported OS type: $OS_TYPE"
    fi
}

setup_network() {
    log "Starting network configuration"
    if is_configured "network_name"; then
        BRIDGE=$(get_tracker_field "network_name")
        show_dialog "info" "Network Configuration" "Network already configured with bridge $BRIDGE\n\n Skipping network configuration."
        return 0
    fi
    configure_network
    set_tracker_field "network_name" "$BRIDGE"
    log "Network configured with bridge $BRIDGE"
}

setup_repo() {
    log "Setting up CloudStack repository"
    if is_configured "repo_url"; then
        local repo_url=$(get_tracker_field "repo_url")
        show_dialog "info" "CloudStack Repo Setup" "CloudStack repository already configured with $repo_url\n\n Skipping repository setup."
        return 0
    fi
    configure_cloudstack_repo
}

show_validation_summary() {
    local summary=""
    local status_ok=true

    # 1. Network Validation
    if ip link show "$BRIDGE" &>/dev/null; then
        local bridge_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)
        if [[ -n "$bridge_ip" ]]; then
            summary+="✓ Network: Bridge $BRIDGE configured with IP $bridge_ip\n"
        else
            summary+="✗ Network: Bridge $BRIDGE has no IP address\n"
            status_ok=false
        fi
    else
        summary+="✗ Network: Bridge $BRIDGE not found\n"
        status_ok=false
    fi

    # 2. MySQL Validation
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " mysql " ]]; then
        if systemctl is-active --quiet "$MYSQL_SERVICE"; then
            if [[ -f "$MYSQL_CONF_DIR/cloudstack.cnf" ]]; then
                summary+="✓ MySQL: Running and configured\n"
            else
                summary+="✗ MySQL: Running but missing CloudStack configuration\n"
                status_ok=false
            fi
        else
            summary+="✗ MySQL: Not running\n"
            status_ok=false
        fi
    fi

    # 3. NFS Validation
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " nfs " ]]; then
        if systemctl is-active --quiet nfs-server; then
            if grep -q "^/export" /etc/exports; then
                summary+="✓ NFS: Server running and exports configured\n"
            else
                summary+="✗ NFS: Server running but exports not configured\n"
                status_ok=false
            fi
        else
            summary+="✗ NFS: Server not running\n"
            status_ok=false
        fi
    fi

    # 4. Management Server Validation
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]]; then
        if systemctl is-active --quiet cloudstack-management; then
            if [[ -f "/etc/cloudstack/management/db.properties" ]]; then
                summary+="✓ Management Server: Running and configured\n"
            else
                summary+="✗ Management Server: Running but configuration incomplete\n"
                status_ok=false
            fi
        else
            summary+="✗ Management Server: Not running\n"
            status_ok=false
        fi
    fi

    # 5. KVM Agent Validation
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " agent " ]]; then
        if systemctl is-active --quiet libvirtd; then
            if grep -q "^listen_tcp = 1" /etc/libvirt/libvirtd.conf; then
                summary+="✓ KVM: Libvirt running and configured\n"
                if systemctl is-active --quiet cloudstack-agent; then
                    summary+="✓ KVM: CloudStack agent running\n"
                else
                    summary+="✗ KVM: CloudStack agent not running\n"
                    status_ok=false
                fi
            else
                summary+="✗ KVM: Libvirt TCP not configured\n"
                status_ok=false
            fi
        else
            summary+="✗ KVM: Libvirt not running\n"
            status_ok=false
        fi
    fi

    # 6. Usage Server Validation
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]]; then
        if systemctl is-active --quiet cloudstack-usage; then
            summary+="✓ Usage Server: Running\n"
        else
            summary+="✗ Usage Server: Not running\n"
            status_ok=false
        fi
    fi

    # Log the result
    echo -e "Validation Summary:\n$summary" >> "$CS_LOGFILE"

    # Display final result in dialog
    if $status_ok; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Validation Summary" \
               --colors \
               --msgbox "\Z2✓ All components are properly configured!\n\n\ZnComponent Status:\n\n$summary" 20 70
        return 0
    else
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Validation Summary" \
               --colors \
               --msgbox "\Z1⚠ Some components need attention!\n\n\ZnComponent Status:\n\n$summary" 20 70
        return 1
    fi
}


configure_prerequisites() {
    setup_network
    setup_repo
    update_system
}

validate_setup_pre_req() {
    check_root
    check_kvm_support
    check_system_resources
    detect_os
    install_base_dependencies
}

custom_install() {
    clear
    log "Starting CloudStack installation script"
    select_components
    install_components
    configure_components
}

all_in_one_box() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "All-in-One Installation" \
           --yesno "You have selected all components for installation. This will configure a complete CloudStack setup on this single machine.\n\nProceed with All-in-One installation?" 12 60
    if [[ $? -ne 0 ]]; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Cancelled" \
               --msgbox "All-in-One installation cancelled by user." 6 60
    fi
    SELECTED_COMPONENTS=("nfs" "mysql" "management" "agent" "usage")
    install_components
    configure_components
}

main() {
    load_tracker
    validate_setup_pre_req
    configure_prerequisites
    
    local temp_file=$(mktemp)
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Installation Options" \
           --menu "Select an option:" 15 60 4 \
           1 "All-in-One Installation" \
           2 "Custom Component Installation" \
           3 "Configure CloudStack Repository" \
           4 "Setup Network" \
           5 "Deploy CloudStack Zone" 2> "$temp_file"
    if [[ $? -ne 0 ]]; then
        error_exit "Installation option selection cancelled by user"
    fi
    local option=$(< "$temp_file")
    case $option in
        1)
            all_in_one_box
            ;;
        2)
            custom_install
            ;;
        3)
            setup_repo
            ;;
        4)
            setup_network
            ;;
        5)
            deploy_zone
            ;;
    esac

    if show_validation_summary; then
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]]; then
            if select_zone_deployment; then
                deploy_zone
            else
                dialog --backtitle "$SCRIPT_NAME" \
                        --title "Zone Deployment" \
                        --msgbox "Zone deployment skipped. You can deploy a zone later using CloudStack UI." 8 60
            fi
        fi
    else
        dialog --backtitle "$SCRIPT_NAME" \
            --title "Warning" \
            --msgbox "Zone deployment is not available until all components are properly configured." 8 60
    fi

    # show dialog for script completion
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Installation Complete" \
           --msgbox "CloudStack installation script has completed.\n\nCheck $CS_LOGFILE for details." 8 60
    exit 0
    rm -f "$temp_file"
    cleanup 0 
}

# Cleanup function for trap
cleanup() {
    local exit_code=$1
    clear
    if [[ $exit_code -eq 0 ]]; then
        success_msg "Script completed successfully. Check $CS_LOGFILE for details."
    else
        warn_msg "Script interrupted. Check $CS_LOGFILE for details."
    fi
    exit $exit_code
}

# Set trap for cleanup
trap 'cleanup 1' INT TERM

# Run main function
main "$@"