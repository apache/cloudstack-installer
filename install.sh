#!/usr/bin/env bash
# get.cloudstack.cloud/install.sh - Easiest Apache CloudStack Installer
# Install with this command (from your Ubuntu/EL host):
#
# curl -sSfL https://get.cloudstack.cloud/install.sh | bash
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
SCRIPT_NAME="Apache CloudStack Installer"
CS_LOGFILE="$PWD/installer.log"
TRACKER_FILE="$PWD/cloudstack-installer-tracker.conf"

OS_TYPE=""
PACKAGE_MANAGER=""
SELECTED_COMPONENTS=()
ZONE_TYPE=""
MYSQL_PKG="mysql-server"
MYSQL_SERVICE=""
MYSQL_CONF_DIR=""

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

# 1 = Prompt mode (interactive), 0 = Silent (non-interactive)
PROMPT=1

#-------------------------------------------------------------------------------
# Utility functions
#-------------------------------------------------------------------------------

# checks if prompt mode is enabled
is_interactive() { (( PROMPT )); }
is_silent()      { (( !PROMPT )); }

# Log related utilities
#-------------------------------------------------------------------------------

# Clean up ANSI escape sequences from logs
strip_ansi() {
    sed 's/\x1b\[[0-9;]*[a-zA-Z]//g'
}

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$CS_LOGFILE"
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

# Utilities for resource checks
#-------------------------------------------------------------------------------

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Please use 'sudo $0'"
    fi
}

# Check system resources (RAM and Disk)
check_system_resources() {
    MIN_RAM_KB=$((8 * 1024 * 1024))  # 8 GB in KB
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')

    # Check if RAM is within the desired range
    if [ "$TOTAL_RAM_KB" -ge "$MIN_RAM_KB" ]; then
        success_msg "✓ RAM check passed: $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB"
    else
        error_exit "RAM check failed: System has $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB RAM"
    fi

    MIN_DISK_GB=75  # Minimum disk space in GB
    TOTAL_DISK_GB=$(df / | tail -1 | awk '{print $2}' | awk '{printf "%.0f", $1/1024/1024}')

    # Check if disk space is within the desired range
    if [ "$TOTAL_DISK_GB" -ge "$MIN_DISK_GB" ]; then
        success_msg "✓ Disk space check passed: $TOTAL_DISK_GB GB available"
    else
        error_exit "Disk space check failed: System has only $TOTAL_DISK_GB GB available"
    fi
}

# Ensure kvm modules are loaded for KVM Agent
check_kvm_support() {
    info_msg "Checking KVM prerequisites..."
    if ! grep -E 'vmx|svm' /proc/cpuinfo >/dev/null; then
        error_exit "CPU does not support hardware virtualization (agent)"
    fi
    success_msg "✓ CPU virtualization support detected"

    if grep -q vmx /proc/cpuinfo; then
        MODULE="kvm_intel"
    elif grep -q svm /proc/cpuinfo; then
        MODULE="kvm_amd"
    else
        error_exit "Unable to determine CPU type for KVM module."
    fi

    modprobe "$MODULE" 2>/dev/null || true
    # Validate loaded module
    if ! grep -q "^${MODULE} " /proc/modules; then
        error_exit "KVM module $MODULE is not loaded. Ensure virtualization is enabled in BIOS/UEFI."
    fi
    success_msg "✓ KVM kernel module ($MODULE) loaded"
}

validate_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        SELINUX_MODE=$(getenforce)
        if [ "$SELINUX_MODE" = "Enforcing" ]; then
            msg="SELinux is ENFORCING. Script cannot continue."
            msg+="\nFix it by:"
            msg+="\n  1) Edit /etc/selinux/config → SELINUX=permissive"
            msg+="\n  2) Run: setenforce 0"
            msg+="\n  3) Reboot"
            error_exit "$msg"
        else
            success_msg "✓ SELinux status: $SELINUX_MODE"
        fi
    else
        success_msg "✓ SELinux not detected. Continuing..."
    fi
}

validate_jre_version() {
    if ! command -v java >/dev/null 2>&1; then
        success_msg "✓ Java not found, good to go.."
        return 0
    fi
    java_version=$(java -version 2>&1 | awk -F[\"_] 'NR==1{print $2}')
    major_version=$(echo "$java_version" | cut -d. -f1)

    if (( major_version < 17 )); then
        error_exit "Looks like Java is pre-installed and may conflict with CloudStack. Java 17 or higher is required. Detected version: $java_version"
    fi
    success_msg "✓ Java version $java_version detected, good to go.."
}

# Initialize OS_TYPE, PACKAGE_MANAGER, MYSQL_SERVICE, MYSQL_CONF_DIR
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Cannot detect operating system. /etc/os-release not found."
    fi
    
    source /etc/os-release
    OS_TYPE=$ID
    OS_VERSION=$VERSION_ID
    OS_MAJOR="${OS_VERSION%%.*}"
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
            if [[ ("$OS_TYPE" == "rocky" || "$OS_TYPE" == "almalinux" || "$OS_TYPE" == "ol") && "$OS_MAJOR" =~ ^(10|11)$ ]]; then
                MYSQL_PKG="mysql8.4-server"
            fi
            validate_selinux
            ;;
        *)
            echo "Unsupported OS: $OS_TYPE"
            exit 1
            ;;
    esac

    log "OS Detection: $OS_TYPE with package manager: $PACKAGE_MANAGER"
}

# Tracker file utilities
#-------------------------------------------------------------------------------
# maintains tracker values for installation and configuration steps

declare -A tracker_values

# loads tracker file data into tracker_values
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

# Save or update a field in the tracker file
set_tracker_field() {
    local key="$1"
    local value="$2"

    # Update associative array
    tracker_values["$key"]="$value"

    # Update or append key=value in tracker file
    if grep -q "^$key=" "$TRACKER_FILE"; then
        sed -i "s|^$key=.*|$key=$value|" "$TRACKER_FILE"
    else
        echo "$key=$value" >> "$TRACKER_FILE"
    fi
}

# checks if a step is already tracked in tracker file
is_step_tracked() {
    local key="$1"
    [[ -n "${tracker_values[$key]:-}" ]]
}

# Utility functions for Repository setup
#-------------------------------------------------------------------------------

# Map Debian codenames to Ubuntu codenames for CloudStack repo
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

#  Determine repo_path for CloudStack repository based on OS type and version
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

# Validates repository entry format
validate_repo_entry() {
    local os_type="$1"
    local entry="$2"

    # Basic check: not empty
    if [[ -z "$entry" ]]; then
        error_exit "CloudStack Repository entry cannot be empty."
        return 1
    fi

    # Debian/Ubuntu repo line example:
    # deb [signed-by=...] https://download.cloudstack.org/ubuntu noble 4.20
    if [[ "$os_type" =~ ^(ubuntu|debian)$ ]]; then
        if [[ ! "$entry" =~ https?:// ]]; then
            error_exit "Invalid Repository entry must include a valid URL (http or https)."
            return 1
        fi
    fi

    # RHEL-family example:
    # https://download.cloudstack.org/centos/9/4.20/
    if [[ "$os_type" =~ ^(rhel|centos|rocky|almalinux|ol)$ ]]; then
        if [[ ! "$entry" =~ ^https?:// ]]; then
            error_exit "Invalid Repository baseurl must start with http:// or https://."
            return 1
        fi
    fi

    # Optional: check version (warn, not fatal)
    if [[ ! "$entry" =~ 4\.([1-9][0-9]) ]]; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Warning" \
               --msgbox "The repository entry does not appear to contain a known CloudStack version (4.xx). Please verify before proceeding." 8 70
    fi

    return 0
}

# Update system packages once repository is configured
update_system_packages() {
    local percent=1
    {
        case "$PACKAGE_MANAGER" in
            apt)
                apt-get update 2>&1 | while IFS= read -r line; do
                    percent=$((percent + 1))
                    [ $percent -gt 50 ] && percent=50
                    update_progress_bar "$percent" "# Updating package lists...\n\n$line"
                done

                apt-get upgrade -y 2>&1 | while IFS= read -r line; do
                    percent=$((percent + 1))
                    [ $percent -gt 80 ] && percent=80
                    update_progress_bar "$percent" "# Installing updates...\n\n$line"
                done
                ;;
            dnf)
                dnf clean all 2>&1 | while IFS= read -r line; do
                    percent=$((percent + 1))
                    [ $percent -gt 20 ] && percent=20
                    update_progress_bar "$percent" "# Cleaning package cache...\n\n$line"
                done

                dnf makecache 2>&1 | while IFS= read -r line; do
                    percent=$((percent + 1))
                    [ $percent -gt 60 ] && percent=60
                    update_progress_bar "$percent" "# Updating package cache...\n\n$line"
                done

                dnf update -y 2>&1 | while IFS= read -r line; do
                    percent=$((percent + 1))
                    [ $percent -gt 80 ] && percent=80
                    update_progress_bar "$percent" "# Installing system updates...\n\n$line"
                done
                ;;
        esac

        update_progress_bar "100" "# System update complete!"
        sleep 2
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "System Update" \
               --gauge "Updating system packages..." 15 80 0

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

# Installation related utilities
#-------------------------------------------------------------------------------

is_package_installed() {
    local pkgs=("$@")  # Accept multiple packages
    local pkg

    for pkg in "${pkgs[@]}"; do
        case "$PACKAGE_MANAGER" in
            apt)
                if ! dpkg -s "$pkg" &>/dev/null; then
                    return 1  # one package missing -> not installed
                fi
                ;;
            dnf)
                if ! dnf list installed "$pkg" &>/dev/null; then
                    return 1
                fi
                ;;
        esac
    done
    return 0  # all packages installed
}

install_package() {
    local packages=("$@")  # Capture all arguments (1..N)

    case "$PACKAGE_MANAGER" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
            ;;
        dnf)
            dnf install -y "${packages[@]}"
            ;;
        *)
            echo "Unsupported package manager: $PACKAGE_MANAGER" >&2
            return 1
            ;;
    esac
}

# Generic function, performs package installation with progress dialog
install_pkg_with_progress_bar() {
    local title="$1"
    local package_name="$2"
    local tracker_key="$3"

    # Skip if already configured
    if is_step_tracked "$tracker_key"; then
        log "$title is already installed. Skipping."
        show_dialog "info" "$title Installation" "$title is already installed. Skipping installation."
        return 0
    fi

    # Skip if package already installed
    if is_package_installed "$package_name"; then
        log "$title package already present. Skipping installation."
        set_tracker_field "$tracker_key" "yes"
        show_dialog "info" "$title Installation" "$title package already present. Skipping installation."
        return 0
    fi

    log "Installing $title..."

    # Temporary log file
    local TMP_LOG
    TMP_LOG=$(mktemp /tmp/install_${tracker_key}.XXXXXX.log)

    # Start installation in the background
    install_package $package_name >> "$TMP_LOG" 2>&1 &
    local INSTALL_PID=$!

    local percent=0
    local start_msg="Installing $title..."

    {
        update_progress_bar "$percent" "# $start_msg"

        while kill -0 "$INSTALL_PID" 2>/dev/null; do
            local tail_output
            tail_output=$(tail -n 5 "$TMP_LOG" | strip_ansi | tr -d '\r')
            
            # Add left padding, truncate width, and wrap safely
            tail_output=$(echo "$tail_output" \
            | sed 's/^/   /' \
            | fold -s -w 80 \
            | tail -n 5)

            echo "$percent"
            echo "XXX"
            echo "# $start_msg"
            echo
            echo "$tail_output"
            echo "XXX"

            percent=$((percent + 1))
            [ $percent -gt 90 ] && percent=90
            sleep 1
        done
    } | dialog --backtitle "$SCRIPT_NAME" --title "$title Installation" --gauge "Installing $title..." 15 80 0

    wait "$INSTALL_PID"
    local status=$?

    if [ $status -eq 0 ]; then
        set_tracker_field "$tracker_key" "yes"
        log "$title installed successfully."
        rm -f "$TMP_LOG"
        return 0
    else
        log "Failed to install $title. Check $TMP_LOG"
        error_exit "Failed to install $title."
    fi
}

# function to update progress bar in the dialog
update_progress_bar() {
    local percent="$1"
    local msg="$2"
    echo "XXX"
    echo "$percent"
    echo -e "$msg"
    echo "XXX"
}

# utility function to display dialog for info or message purpose
show_dialog() {
    local mode="$1"
    local title="$2"
    local msg="$3"
    local seconds="${4:-3}"
    local height="${5:-7}"
    local width="${6:-60}"

    case "$mode" in
        info)
            dialog --backtitle "$SCRIPT_NAME" \
                    --title "$title" \
                    --infobox "$msg" $height $width
            sleep "$seconds"
            return 0
            ;;
        msg)
            dialog --backtitle "$SCRIPT_NAME" \
                    --title "$title" \
                    --msgbox "$msg" $height $width
            return 0
            ;;
        *)
            echo "Unknown mode: $mode"
            return 1
            ;;
    esac
}

# Attempts to start service_name
start_service_with_progress() {
    local service_name="$1"
    local display_name="${2:-$service_name}"
    local start_percent="${3:-60}"
    local end_percent="${4:-90}"
    local verify="${5:-verify}"

    if ! systemctl is-active --quiet "$service_name"; then
        {
            update_progress_bar "$start_percent" "# Starting $display_name service..."
            systemctl start "$service_name" >/dev/null 2>&1 &
            local pid=$!

            local i
            for ((i=start_percent; i<=end_percent; i++)); do
                update_progress_bar "$i" "# Waiting for $display_name to start..."
                sleep 0.2
            done

            wait "$pid"
            update_progress_bar "$end_percent" "# $display_name service started successfully."
            sleep 1
        } | dialog --backtitle "$SCRIPT_NAME" \
                   --title "Starting $display_name Service" \
                   --gauge "Starting $display_name service..." 15 70 0

        systemctl enable "$service_name" >/dev/null 2>&1
        if [[ "$verify" == "verify" ]]; then
            if systemctl is-active --quiet "$service_name"; then
                log "$display_name service started successfully."
            else
                error_exit "Failed to start $display_name service."
            fi
        else
            log "$display_name service started (verification skipped)."
        fi

    else
        log "$display_name service is already running."
    fi
}


# CloudStack Banner gets displayed at the end of Zone Deployment
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
    log "$banner"

    dialog --backtitle "$SCRIPT_NAME" \
        --title "Installation Complete" \
        --colors \
        --msgbox "\Z1$banner\Zn" 20 70
}

# Find free IP addresses in a given network range
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

#-------------------------------------------------------------------------------
# Script specific functions
#-------------------------------------------------------------------------------


is_cloudstack_pkg_selected() {
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " || \
          " ${SELECTED_COMPONENTS[@]} " =~ " agent " || \
          " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]]; then
        return 0  # true
    else
        return 1  # false
    fi
}


# Configure CloudStack repository for Debian/Ubuntu
#-------------------------------------------------------------------------------

_configure_deb_repo() {
    local gpg_key_url="$1"
    local repo_entry="$2"
    {
        echo "Configuring CloudStack repository..."
        echo "Adding CloudStack's signing key..."
        mkdir -p /etc/apt/keyrings

        if curl -fsSL "$gpg_key_url" | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null; then
            echo "CloudStack signing key added successfully."
        else
            error_exit "Failed to add CloudStack signing key."
        fi
        
        echo "Adding CloudStack repository..."
        if echo "deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] $repo_entry" | sudo tee /etc/apt/sources.list.d/cloudstack.list > /dev/null; then
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
    local repo_entry="$2"
    mkdir -p /etc/yum.repos.d/
    {
        echo "Adding CloudStack repository..."
        if cat > /etc/yum.repos.d/cloudstack.repo <<EOF
[cloudstack]
name=CloudStack
baseurl=$repo_entry
enabled=1
gpgcheck=0
gpgkey=$gpg_key_url
EOF
        then
            echo "Repository added successfully"
        else
            error_exit "Failed to create CloudStack repository file"
        fi
    } | dialog --backtitle "$SCRIPT_NAME" \
            --title "Repository Configuration" \
            --programbox "Configuring CloudStack repository..." 15 70
}

configure_cloudstack_repo() {
    local title="CloudStack Repository Configuration"
    local tracker_key="repo_url"
    local repo_file=""
    local repo_entry=""
    case "$OS_TYPE" in
        ubuntu|debian)
            repo_file="/etc/apt/sources.list.d/cloudstack.list"
            if [[ -f "$repo_file" ]]; then
                repo_entry=$(grep -E '^deb ' "$repo_file" | sed -E 's/^.*] //')
            fi
            ;;
        rhel|centos|ol|rocky|almalinux)
            repo_file="/etc/yum.repos.d/cloudstack.repo"
            if [[ -f "$repo_file" ]]; then
                repo_entry=$(grep -E '^baseurl=' "$repo_file" | cut -d'=' -f2-)
            fi
            ;;
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            exit 1
            ;;
    esac
    # If repo already exists, show info and exit gracefully for silent mode
    # allow reconfiguration for interactive mode
    if [[ -n "$repo_entry" ]]; then
        if is_silent; then
            show_dialog "info" \
            "$title" \
            "CloudStack repository is already configured:\n\n$repo_entry"
            set_tracker_field "$tracker_key" "$repo_entry"
            return 0
        fi
        
        if is_interactive; then
            if dialog --backtitle "$SCRIPT_NAME" \
               --title "$title" \
               --yesno "CloudStack repository is already configured:\n\n$repo_entry\n\nDo you want to reconfigure it?" 12 70; then
                log "User opted to reconfigure existing CloudStack repository."
            else
                show_dialog "info" "$title" "Skipping CloudStack repository configuration."
                set_tracker_field "$tracker_key" "$repo_entry"
                return 0
            fi
        fi
    fi

    # default repo_entry is required if repo_entry is not set
    if [[ -z "$repo_entry" ]]; then
        # Set default repo_entry based on OS
        local default_repo_url="https://download.cloudstack.org"
        local default_cs_version="4.21"
        # Build default repo_entry depending on distro
        case "$OS_TYPE" in
            ubuntu|debian)
                local ubuntu_codename="$VERSION_CODENAME"
                if [[ "$OS_TYPE" == "debian" ]]; then
                    ubuntu_codename=$(get_ubuntu_codename_for_debian "$VERSION_CODENAME") || exit 1
                fi
                default_repo_entry="${default_repo_url}/ubuntu $ubuntu_codename $default_cs_version"
                ;;
            rhel|centos|ol|rocky|almalinux)
                local repo_path
                repo_path=$(determine_rpm_distro_version)
                default_repo_entry="${default_repo_url}/${repo_path}/${default_cs_version}/"
                ;;
        esac
        repo_entry="$default_repo_entry"
    fi

    if is_interactive; then
        width=60
        prompt_text="Enter the CloudStack repository url:"
        if [[ "$OS_TYPE" =~ ^(ubuntu|debian)$ ]]; then
            prompt_text="Enter the CloudStack repository url.\n\nSupported formats:\n• Ubuntu-style (deb ... ubuntu codename version)\n• Flat layout (deb ... /)\nExample: deb [signed-by=...] http://packages.shapeblue.com/cloudstack/upstream/debian/4.21/ /"
            width=90
        fi
        height=$(( $(echo -e "$prompt_text" | wc -l) + 8 ))
        repo_entry=$(dialog --clear \
            --backtitle "$SCRIPT_NAME" \
            --title "Configure CloudStack Repository" \
            --inputbox "$prompt_text" "$height" "$width" "$repo_entry" \
            3>&1 1>&2 2>&3)
        
        validate_repo_entry "$OS_TYPE" "$repo_entry" || {
            error_exit "Invalid repository entry provided by user."
        }
    fi

    local repo_base_url=$(echo "$repo_entry" | sed -E 's|.*(https?://[^/ ]+).*|\1|')
    local gpg_url="${repo_base_url}/release.asc"
    if is_interactive; then
        if ! dialog --backtitle "$SCRIPT_NAME" \
            --title "Confirm Repository" \
            --yesno "The following CloudStack repository will be added:\n\n$repo_entry\n\nProceed?" 12 70; then
            error_exit "CloudStack repository configuration cancelled by user."
        fi
    else
        show_dialog "info" "$title" "The following CloudStack repository will be added:\n\n$repo_entry" 4
    fi
           
    log "Configuring CS repo: $repo_entry"
    case "$OS_TYPE" in
        ubuntu|debian)
            _configure_deb_repo "$gpg_url" "$repo_entry"
            ;;
        rhel|centos|ol|rocky|almalinux)
            _configure_rpm_repo "$gpg_url" "$repo_entry"
            ;;
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            error_exit "Unsupported OS: $OS_TYPE"
            ;;
    esac
    log "Configured CS repo: $repo_entry"
    set_tracker_field "$tracker_key" "$repo_entry"
}


# Install base dependencies required for CloudStack
#-------------------------------------------------------------------------------

install_dialog_utility() {
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

update_system_time() {
    case $PACKAGE_MANAGER in
        dnf)
            if ! systemctl is-active chronyd >/dev/null 2>&1; then
                systemctl enable --now chronyd >/dev/null 2>&1
            fi
            chronyc makestep >/dev/null 2>&1
            ;;

        apt)
            # Detect what NTP mechanism is available
            if systemctl is-active ntp >/dev/null 2>&1; then
                info_msg ">>> ntp detected, forcing sync via ntpd..."
                ntpd -gq >/dev/null 2>&1 || true
            elif systemctl is-active chrony >/dev/null 2>&1; then
                info_msg ">>> chrony detected, forcing sync via chronyc..."
                chronyc makestep >/dev/null 2>&1  || true
            else
                info_msg ">>> Falling back to systemd-timesyncd..."
                systemctl enable --now systemd-timesyncd >/dev/null 2>&1  || true
                timedatectl set-ntp true >/dev/null 2>&1 || true
                systemctl restart systemd-timesyncd >/dev/null 2>&1 || true
            fi
            ;;
    esac
}

install_base_dependencies() {
    log "Starting base dependencies installation..."
    if ! command -v dialog &>/dev/null; then
        install_dialog_utility
    fi
    
    TMP_LOG=$(mktemp /tmp/install_base.XXXXXX.log)
    title="Installing base dependencies (qemu-kvm, python, curl, etc.)..."
    {   
        update_progress_bar "30" "$title"
        case "$PACKAGE_MANAGER" in
            apt)
                DEBIAN_FRONTEND=noninteractive \
                apt-get install -y qemu-kvm apt-utils gnupg curl openntpd openssh-server sshpass sudo wget jq htop tar nmap bridge-utils util-linux >> "$TMP_LOG" 2>&1 &
                ;;
            dnf)
                dnf install -y curl openssh-server chrony sshpass sudo wget jq tar nmap util-linux >> "$TMP_LOG" 2>&1 &
                ;;
        esac

        INSTALL_PID=$!
        PERCENT=31
        while kill -0 "$INSTALL_PID" 2>/dev/null; do
            tail_output=$(tail -n 5 "$TMP_LOG" | strip_ansi | tr -d '\r')
            # Add left padding, truncate width, and wrap safely
            tail_output=$(echo "$tail_output" \
            | sed 's/^/   /' \
            | fold -s -w 80 \
            | tail -n 5)
            update_progress_bar "$PERCENT" "$title\n\n$tail_output"
            PERCENT=$((PERCENT + 1))
            [ "$PERCENT" -ge 90 ] && PERCENT=90
            sleep 1
        done

        wait "$INSTALL_PID" || error_exit "Base dependency installation failed"
        update_progress_bar "100" "Base dependencies installed successfully"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Dependencies" \
               --gauge "Preparing system..." 15 80 0 
    show_dialog "info" "Dependencies Installation" "All Base dependencies installed successfully"
    log "Base dependencies installed successfully"
    
    rm -f "$TMP_LOG"
}

# Function to show available component versions from repository for SELECTED_COMPONENTS
show_components_versions() {
    local versions=()
    local component version_info

    if [[ " ${SELECTED_COMPONENTS[*]} " =~ " management " ]] && [[ ! " ${SELECTED_COMPONENTS[*]} " =~ " mysql " ]]; then
        SELECTED_COMPONENTS+=("mysql")
    fi

    for component in "${SELECTED_COMPONENTS[@]}"; do
        case "$component" in
            nfs)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy nfs-kernel-server 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
                    version_info=$($PACKAGE_MANAGER info nfs-utils 2>/dev/null | awk -F':' '/Version/ {gsub(/ /,"",$2); print $2}')
                fi
                versions+=("NFS Server: ${version_info:-Not Available}\n")
                ;;
            
            mysql)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy "$MYSQL_PKG" 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
                    version_info=$($PACKAGE_MANAGER info "$MYSQL_PKG" 2>/dev/null | awk -F':' '/Version/ {gsub(/ /,"",$2); print $2}')
                fi
                versions+=("MySQL Server: ${version_info:-Not Available}\n")
                ;;
            
            management)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-management 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-management 2>/dev/null | awk -F':' '/Version/ {gsub(/ /,"",$2); print $2}')
                fi
                versions+=("CloudStack Management Server: ${version_info:-Not Available}\n")
                ;;
            
            agent)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-agent 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-agent 2>/dev/null | awk -F':' '/Version/ {gsub(/ /,"",$2); print $2}')
                fi
                versions+=("CloudStack KVM Agent: ${version_info:-Not Available}\n")
                ;;
            
            usage)
                if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                    version_info=$(apt-cache policy cloudstack-usage 2>/dev/null | awk '/Candidate:/ {print $2}')
                elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
                    version_info=$($PACKAGE_MANAGER info cloudstack-usage 2>/dev/null | awk -F':' '/Version/ {gsub(/ /,"",$2); print $2}')
                fi
                versions+=("CloudStack Usage Server: ${version_info:-Not Available}\n")
                ;;
        esac
    done
    show_dialog info "Component Versions" "Available versions from repository:\n\n$(printf '%s\n' "${versions[@]}")" 6 10 55
}

cmk_api_call() {
    local jq_filter="$1"
    shift 1
    local cmd=(cmk "$@")     # remaining args are the CMK call

    # Run the CMK API call (capture stdout+stderr)
    local cmd_output
    cmd_output="$("${cmd[@]}" 2>&1)"
    if ! echo "$cmd_output" | jq empty >/dev/null 2>&1; then
        log "cmk API returned non-JSON response: $cmd_output"
        return 1
    fi
    
    # Extract value
    local value
    value=$(echo "$cmd_output" | jq -r "$jq_filter // empty")
    # if value is empty
    if [[ -z "$value" ]]; then
        log "cmk returned empty value for jq filter: '$jq_filter' on output: $cmd_output"
        return 1
    fi
    echo "$value"
    return 0
}

cmk_api_fail_dialog_msg() {
    local msg="$1"
    local progress="${2:-100}"
    local sleep_time="${3:-4}"
    update_progress_bar "$progress" "$msg"
    sleep "$sleep_time"
    return 1
}

# Component installation and configuration functions
#-------------------------------------------------------------------------------

# Function to install CloudStack Management Server
install_management_server() {
    local package_name="cloudstack-management"
    local tracker_key="management_installed"
    if is_step_tracked "$tracker_key"; then
        show_dialog "info" "Management Server Installation" "Management Server is already installed.\n\nSkipping installation."
        log "CloudStack Management Server is already installed. Skipping installation."
        return 0
    fi
    if is_package_installed "$package_name"; then
        log "CloudStack Management Server is already installed."
        set_tracker_field "$tracker_key" "yes"
        return 0
    fi
    install_pkg_with_progress_bar "CloudStack Management Server" "$package_name" "$tracker_key"
}

# Function to configure CloudStack Management Server database
configure_management_server_database() {
    local title="CloudStack Database Deployment"
    local tracker_key="db_deployed"
    if is_step_tracked "$tracker_key"; then
        log "CloudStack database is already deployed. Skipping deployment."
        show_dialog "info" "$title" "$title is already done.\n\nSkipping it."
        return 0
    fi
    log "Starting CloudStack database deployment..."
    if ! systemctl is-active $MYSQL_SERVICE > /dev/null; then
         show_dialog "msg" "$title" "MySQL service is not running. Please start MySQL before proceeding." 
        return 1
    fi

    local db_user="cloud"
    local db_pass="cloud"
    if [[ -f "/etc/cloudstack/management/db.properties" ]] && is_step_tracked "$tracker_key"; then
        if mysql -u"$db_user" -p"$db_pass" -e "USE cloud; SHOW TABLES LIKE 'version';" &>/dev/null; then
            local current_db_host=$(grep "^cluster.node.IP" /etc/cloudstack/management/db.properties | cut -d= -f2)
            if ! dialog --title "Info" --yesno "CloudStack database appears to be already configured.\nCurrent database host: $current_db_host\n\nDo you want to reconfigure it?" 10 60; then
                show_dialog "info" "$title" "Skipping database configuration."
                set_tracker_field "$tracker_key" "yes"
                return 0
            fi
        fi
    fi

    if [ -z "$BRIDGE" ]; then
        BRIDGE=$(dialog --inputbox "Enter the bridge interface name:" 8 50 "$BRIDGE" 3>&1 1>&2 2>&3)
    fi
    if [[ -z "$BRIDGE" ]]; then
        show_dialog "msg" "$title" "Bridge interface cannot be empty.\nAborting."
        return 1
    fi

    # Get the bridge IP
    cloudbr0_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)
    if [[ -z "$cloudbr0_ip" ]]; then
        show_dialog "msg" "$title" "Could not determine IP address of interface '$BRIDGE'.\nAborting."
        return 1
    fi

    show_dialog "info" "$title" "Starting CloudStack database deployment using IP: $cloudbr0_ip"
    {
        cloudstack-setup-databases cloud:cloud@localhost --deploy-as=root: -i "$cloudbr0_ip" 2>&1 | \
            while IFS= read -r line; do
                msg=$(echo "$line" | strip_ansi)
                update_progress_bar "50" "Deploying CloudStack Database...\n\n$msg"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "$title" \
               --gauge "Starting database deployment..." 10 70 0

    db_exit=${PIPESTATUS[0]}
    if [ $db_exit -ne 0 ]; then
        dialog --backtitle "$SCRIPT_NAME" \
            --title "Database Setup Failed" \
            --msgbox "CloudStack database setup failed." 10 70
        error_exit "CloudStack database setup failed."
    fi

    {
        echo "# Starting CloudStack Management Server setup..."
        cloudstack-setup-management 2>&1 | \
            while IFS= read -r line; do
                msg=$(echo "$line" | strip_ansi)
                update_progress_bar "75" "Starting Management Server...\n\n$msg"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Management Server Setup" \
               --gauge "Starting management server setup..." 10 72 0
    mgmt_exit=${PIPESTATUS[0]}

    if [ $mgmt_exit -ne 0 ]; then
        dialog --backtitle "$SCRIPT_NAME" \
            --title "Management Setup Failed" \
            --msgbox "CloudStack management setup failed" 10 70
        error_exit "CloudStack management setup failed."
    fi

    sleep 5
    set_tracker_field "$tracker_key" "yes"
    show_dialog "info" "CloudStack Configuration" "CloudStack Management Server has been configured."
}

# Function to install MySQL Server and configure it for CloudStack
install_mysql_server() {
    local tracker_key="mysql_installed"
    if is_step_tracked "$tracker_key"; then
        log "MySQL is already installed. Skipping installation."
        show_dialog "info" "MySQL Server Installation" "MySQL Server is already installed.\n\nSkipping installation."
        return 0
    fi

    if is_package_installed "$MYSQL_PKG"; then
        log "MySQL Server is already installed."
        set_tracker_field "$tracker_key" "yes"
    else
        install_pkg_with_progress_bar "MySQL Server" "$MYSQL_PKG" "$tracker_key"
    fi
    start_service_with_progress "$MYSQL_SERVICE" "MySQL" 60 90
}

configure_mysql_for_cloudstack() {
    local tracker_key="mysql_configured"
    if is_step_tracked "$tracker_key"; then
        log "MySQL is already configured for CloudStack. Skipping configuration."
        show_dialog "info" "MySQL Server Configuration" "MySQL Server is already configured.\n\nSkipping configuration."
        return 0
    fi
    log "Starting MySQL configuration..."
    local title="MySQL Configuration"
    MYSQL_VERSION=$(mysql -V 2>/dev/null || echo "MySQL not found")
    if [[ "$MYSQL_VERSION" == "MySQL not found" ]]; then
        show_dialog "msg" "$title" "MySQL is not installed. Please install MySQL first."
        return 1
    fi
  
    local config_file="$MYSQL_CONF_DIR/cloudstack.cnf"
    if [[ -f "$config_file" ]]; then
        show_dialog "info" "$title" "Configuration already exists at:\n$config_file\n\nSkipping MySQL setup."
        set_tracker_field "$tracker_key" "yes"
        return 0
    fi

    mkdir -p "$MYSQL_CONF_DIR"

    if ! systemctl is-active --quiet $MYSQL_SERVICE; then
        dialog --title "$title" --msgbox "MySQL service is not running. Please start MySQL before proceeding." 6 50
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
sql_mode = $sqlmode
innodb_rollback_on_timeout = 1
innodb_lock_wait_timeout = 600
max_connections = 1000
log_bin = mysql-bin
binlog_format = ROW
EOF

    systemctl restart $MYSQL_SERVICE && \
    show_dialog "info" "$title" "MySQL has been configured and restarted successfully."|| \
    show_dialog "info" "$title" "Failed to restart MySQL. Please check the service manually."
    set_tracker_field "$tracker_key" "yes"
}

# Function to install NFS Server
install_nfs_server() {
    local tracker_key="nfs_installed"
    if is_step_tracked "$tracker_key"; then
        log "NFS Server is already installed. Skipping installation."
        show_dialog "info" "NFS Server Installation" "NFS Server is already installed.\n\nSkipping installation."
        return 0
    fi

    local package_name=""
    local nfs_svc="nfs-server"
    case "$PACKAGE_MANAGER" in
        apt)
            package_name="nfs-kernel-server nfs-common quota"
            nfs_svc="nfs-kernel-server"
            ;;
        dnf)
            package_name="nfs-utils quota"
            ;;
    esac
    if is_package_installed "$package_name"; then
        log "NFS Server is already installed."
        show_dialog "info" "NFS Server Installation" "NFS Server is already installed.\n\nSkipping installation."
        set_tracker_field "$tracker_key" "yes"
    else
        install_pkg_with_progress_bar "NFS Server" "$package_name" "$tracker_key"
    fi
    start_service_with_progress "$nfs_svc" "NFS" 60 90
}

get_export_cidr() {
    if [[ -z "$BRIDGE" ]]; then
        error_exit "Error: BRIDGE interface not defined"
    fi
    ip_cidr=$(ip -o -f inet addr show "$BRIDGE" | awk '{print $4}')
    if [[ -z "$ip_cidr" ]]; then
        error_exit "No IPv4 CIDR found on interface $BRIDGE for NFS export configuration"
    fi
    # Extract IP and prefix from CIDR (10.1.1.53/24 → base_ip=10.1.1.53, prefix=24)
    base_ip="${ip_cidr%/*}"
    prefix="${ip_cidr#*/}"

    # Use ipcalc or manual mask conversion
    if command -v ipcalc &>/dev/null; then
        network=$(ipcalc "$base_ip/$prefix" | grep -w 'Network' | awk '{print $2}')
    else
        # Fallback: simple /24 assumption
        network="${base_ip%.*}.0/$prefix"
    fi
    echo "$network"
}

# Configure NFS Server
configure_nfs_server() {
    local tracker_key="nfs_configured"
    local title="NFS Server Configuration"
    if is_step_tracked "$tracker_key"; then
        log "NFS Server is already configured. Skipping configuration."
        show_dialog "info" "$title" "NFS Server is already configured.\n\nSkipping configuration."
        return 0
    fi
    log "Starting NFS storage configuration..."

    if [[ -d "/export" ]] && grep -q "^/export " /etc/exports; then
        show_dialog "info" "$title" "NFS Server is already configured.\n\nSkipping configuration."
        set_tracker_field "$tracker_key" "yes"
        return 0
    fi

    local export_cidr
    export_cidr=$(get_export_cidr)
    # Step 1: Create exports and directories
    mkdir -p /export/primary /export/secondary
    if ! grep -q "^/export " /etc/exports; then
        echo "/export  ${export_cidr}(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
    fi

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
    show_dialog "info" "$title"  "Unsupported distribution: $OS_TYPE"
    return 1
  fi

  # Step 3: Final result
  if [[ $SERVICE_STATUS -eq 0 ]]; then
    exports_list=$(exportfs)
    show_dialog "info" "$title" "NFS Server configured and restarted successfully.\n\nCurrent exports:\n$exports_list"
    set_tracker_field "$tracker_key" "yes"
    log "NFS server configured successfully."
  else
    show_dialog "info" "$title" "Failed to restart NFS server. Please check the service logs."
  fi
}

# Function to install KVM Agent and configure KVM host
install_kvm_agent() {
    local package_name="cloudstack-agent"
    local tracker_key="agent_installed"
    if is_step_tracked "$tracker_key"; then
        log "KVM Agent is already installed. Skipping installation."
        show_dialog "info" "Cloudstack Agent Installation" "CloudStack Agent is already installed.\n\nSkipping installation."
        return 0
    fi
    if is_package_installed "$package_name"; then
        log "KVM Agent is already installed."
        set_tracker_field "$tracker_key" "yes"
        return 0
    fi
    install_pkg_with_progress_bar "CloudStack Agent" "$package_name" "$tracker_key"
}

configure_kvm_agent() {
    local tracker_key="agent_configured"
    local title="CloudStack Agent Configuration"
    if is_step_tracked "$tracker_key"; then
        log "KVM Agent is already configured. Skipping configuration."
        show_dialog "info" "$title" "CloudStack Agent is already configured.\n\nSkipping configuration."
        return 0
    fi
    log "Starting CloudStack Agent configuration..."
    show_dialog "info" "$title" "Starting CloudStack Agent configuration..."

    # Configure VNC
    {
        update_progress_bar "10"  "Configuring VNC access..."
        if sed -i -e 's/\#vnc_listen.*$/vnc_listen = "0.0.0.0"/g' /etc/libvirt/qemu.conf; then
            update_progress_bar "25" "VNC configuration successful"
        else
            error_exit "Failed to configure VNC"
        fi

        if ! grep -q '^LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd > /dev/null; then
            echo 'LIBVIRTD_ARGS="--listen"' >> /etc/default/libvirtd
        fi

        if ! grep -q '^remote_mode="legacy"' /etc/libvirt/libvirtd.conf; then
            echo 'remote_mode="legacy"' >> /etc/libvirt/libvirtd.conf
        fi

        update_progress_bar "40" "Setting up libvirt TCP access..."
        LIBVIRT_CONF="/etc/libvirt/libvirtd.conf"
        declare -A libvirt_settings=(
            ["listen_tcp"]="1"
            ["listen_tls"]="0"
            ["tcp_port"]="\"16509\""
            ["mdns_adv"]="0"
            ["auth_tcp"]="\"none\""
        )
        touch "$LIBVIRT_CONF"

        for key in "${!libvirt_settings[@]}"; do
            # If key exists (commented or uncommented), replace it
            if grep -Eq "^\s*#?\s*$key\s*=" "$LIBVIRT_CONF"; then
                sed -i "s|^\s*#\?\s*$key\s*=.*|$key = ${libvirt_settings[$key]}|" "$LIBVIRT_CONF"
            else
                # Key doesn't exist, append to file
                echo "$key = ${libvirt_settings[$key]}" >> "$LIBVIRT_CONF"
            fi
        done

        update_progress_bar "60" "Configuring libvirt sockets..."
        systemctl mask libvirtd.socket \
            libvirtd-ro.socket \
            libvirtd-admin.socket \
            libvirtd-tls.socket \
            libvirtd-tcp.socket &>/dev/null

        update_progress_bar "75" "Configuring security policies..."
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
                                        update_progress_bar "80" "# Warning: Failed to remove profile: $(basename "$profile")"
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

        update_progress_bar "85" "Configuring firewall..."
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
                if systemctl is-active --quiet firewalld; then
                    for port in "${ports[@]}"; do
                        # Convert port ranges from 5900:6100 -> 5900-6100 for firewalld
                        range_port="${port/:/-}"
                        firewall-cmd --permanent --add-port="$range_port"/tcp
                    done
                    firewall-cmd --reload
                fi
                ;;

        esac
        systemctl restart libvirtd
        sleep 2

        update_progress_bar "90" "Update agent.properties!"
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
        update_progress_bar "100" "KVM host configuration completed!"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "KVM Agent Configuration" \
               --gauge "Configuring KVM Agent..." 10 70 0

    if ! systemctl is-active --quiet libvirtd; then
        show_dialog "msg" "$title" "Libvirt service is not running! Please check system logs."
    fi
    set_tracker_field "$tracker_key" "yes"
}

# Function to install CloudStack Usage Server and configure it
install_usage_server() {
    local package_name="cloudstack-usage"
    local tracker_key="usage_installed"
    if is_step_tracked "$tracker_key"; then
        log "CloudStack Usage Server is already installed. Skipping installation."
        show_dialog "info" "Usage Server Installation" "CloudStack Usage Server is already installed.\n\nSkipping installation."
        return 0
    fi
    if is_package_installed "$package_name"; then
        log "CloudStack Usage Server is already installed."
        set_tracker_field "$tracker_key" "yes"
        return 0
    fi

    # check if mysql and management server are installed
    if ! is_package_installed "cloudstack-management" "$MYSQL_PKG"; then
        error_exit "CloudStack Management Server and MySQL Server must be installed before installing the Usage Server."
    fi

    install_pkg_with_progress_bar "CloudStack Usage Server" "$package_name" "$tracker_key"
    start_service_with_progress "$package_name" "CloudStack Usage" 40 90 "noverify"
}

configure_usage_server() {
    log "Configuring CloudStack Usage Server..."
    local tracker_key="usage_configured"
    if is_step_tracked "$tracker_key"; then
        log "Usage Server is already configured. Skipping configuration."
        show_dialog "info" "Usage Server Configuration" "CloudStack Usage Server is already configured.\n\nSkipping configuration."
        return 0
    fi
    log "Starting Usage Server configuration..."
    show_dialog "info" "Usage Server Configuration" "Starting Usage Server configuration..."
    # confirm db.properties and key exist
    local db_properties="/etc/cloudstack/usage/db.properties"
    local key_file="/etc/cloudstack/usage/key"

    if [[ ! -f "$db_properties" || ! -f "$key_file" ]]; then
        show_dialog "msg" "Usage Server Configuration" "Database configuration files not found!\nPlease ensure CloudStack Management Server is configured."
        return 1
    fi
    set_tracker_field "$tracker_key" "yes"
    sleep 2
}

# Function to present component selection dialog
select_components_to_setup() {
    local title="CloudStack Component Selection"
    local temp_file=$(mktemp)
    
    if dialog --clear --backtitle "$SCRIPT_NAME" \
           --title "$title" \
           --checklist "Select CloudStack components to install:" 15 70 6 \
           "management" "Management Server" on \
           "usage" "Usage Server" off \
           "agent" "KVM Agent" on \
           "nfs" "NFS Server" on \
           2> "$temp_file"; then

        mapfile -t SELECTED_COMPONENTS < <(tr ' ' '\n' < "$temp_file" | tr -d '"')  
        if [[ ${#SELECTED_COMPONENTS[@]} -eq 0 ]]; then
            error_exit "No components selected"
        fi
        log "Selected components: ${SELECTED_COMPONENTS[*]}"
    else
        log "Component selection cancelled by user"
        show_dialog "msg" "$title" "Component selection cancelled by user."
        return 1
    fi
    rm -f "$temp_file"
}

# Displays validation summary for SELECTED_COMPONENTS
show_validation_summary() {
    local summary=""
    local status_ok=true

    # 1. Network Validation
    if is_cloudstack_pkg_selected; then
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
            if grep -qE '^tcp_port\s*=\s*"16509"' /etc/libvirt/libvirtd.conf; then
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
            status_ok=true   # not critical for zone deployment
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

# Functions related to Zone deployment
#-------------------------------------------------------------------------------

# Prompt user to select zone deployment
select_zone_deployment() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Zone Deployment" \
           --yesno "Would you like to deploy a new CloudStack Zone?\n\nThis will:\n\n1. Create a new Zone\n2. Configure Network\n3. Add the first Pod\n4. Add the first Cluster\n5. Add the first Host\n\nDeploy Zone now?" 15 60

    return $?
}

# Function to check and confirm Management Server readiness
wait_for_management_server() {
    local timeout=600  # 10 minutes timeout
    local interval=10  # Check every 10 seconds
    local elapsed=0
    local url="http://$HOST_IP:8080/client/api"

    {
        while [ $elapsed -lt $timeout ]; do
            update_progress_bar "$((elapsed * 100 / timeout))"  "Waiting for Management Server to be ready...\n\nElapsed time: ${elapsed}s"
            
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
            if [[ "$status_code" == "200" || "$status_code" == "401" ]]; then
                update_progress_bar "100" "Management Server is ready!"
                return 0
            fi
            
            sleep $interval
            elapsed=$((elapsed + interval))
        done

        update_progress_bar "100" "Timeout occurred while waiting for Management Server!"
        return 1
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Management Server Check" \
               --gauge "Waiting for Management Server to start..." 10 70 0
}

# Function to check CloudMonkey installation and initialize it
check_cloudmonkey_availability() {
    {
        echo "10"
        echo "# Checking CloudMonkey installation..."
        if ! command -v cmk &>/dev/null; then
            update_progress_bar "100" "CloudMonkey (cmk) not found!"
            return 1
        fi

        echo "50"
        echo "# Initializing CloudMonkey..."
        if ! cmk sync &>/dev/null; then
            update_progress_bar "100" "Failed to initialize CloudMonkey!"
            return 1
        fi

        update_progress_bar "100" "# CloudMonkey is ready!"
        return 0
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "CloudMonkey Check" \
               --gauge "Checking CloudMonkey..." 8 60 0
}

# Perform Advance Zone Deployment
deploy_zone() {
    local title="Zone Deployment"
    local tracker_key="zone_deployment"
    if is_step_tracked "$tracker_key"; then
        log "$title is already installed. Skipping."
            show_dialog "info" "$title" "$title is already done. Skipping!"
            return 0
    fi
    log "Starting zone deployment..."
    # check if management server is installed
    if ! is_package_installed "cloudstack-management"; then
        show_dialog "msg" "$title" "CloudStack Management Server is not installed.\nPlease install it before deploying a zone."
        error_exit "CloudStack Management Server must be installed before deploying a zone."
    fi

    if [[ -z "$BRIDGE" ]]; then
        BRIDGE=$(dialog --backtitle "$SCRIPT_NAME" \
            --title "KVM Host Configuration" \
            --inputbox "Enter the bridge interface name:" \
            8 60 "$BRIDGE" 3>&1 1>&2 2>&3)
    fi

    HOST_IP=$(ip -4 addr show "$BRIDGE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    GATEWAY=$(ip route | grep default | grep "$BRIDGE" | awk '{print $3}')

    local input_ip=""
    local input_gw=""
    if is_interactive; then
        input_ip=$(dialog --backtitle "$SCRIPT_NAME" \
            --title "Host Configuration" \
            --inputbox "KVM Host IP: $HOST_IP\n\nWant to modify." 10 60 "$HOST_IP" 3>&1 1>&2 2>&3)
        input_gw=$(dialog --backtitle "$SCRIPT_NAME" \
            --title "Host Configuration" \
            --inputbox "Detected Gateway: $GATEWAY\n\nWant to modify." 10 60 "$GATEWAY" 3>&1 1>&2 2>&3)  
    fi
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
            --title "$title" \
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

    local network="${HOST_IP%.*}.0/24"
    # Find IPs for different purposes
    local public_ips=($(find_free_ip_range "$network" 11 20))  # 20 IPs for public
    if [[ ${#public_ips[@]} -eq 0 ]]; then
        error_exit "No free public IPs found in $network"
    fi
    local last_public_ip="${public_ips[-1]}"
    local last_public_octet="${last_public_ip##*.}"
    local pod_start=$((last_public_octet + 1))
    if (( pod_start >= 255 )); then
        error_exit "Not enough IP space to allocate pod IPs"
    fi
    local pod_ips=($(find_free_ip_range "$network" "$pod_start" 20)) # 20 IPs for pod
    if [[ ${#pod_ips[@]} -eq 0 ]]; then
        error_exit "No free pod IPs found in $network"
    fi

    # Default values
    local defaults=(
        "Zone Name" "Zone1"
        "Guest CIDR" "172.16.1.0/24"
        "Public Start IP" "${public_ips[0]}"
        "Public End IP" "$last_public_ip"
        "Pod Start IP" "${pod_ips[0]}"
        "Pod End IP" "${pod_ips[-1]}"
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
    
    local results=()
    # Create zone form entries
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
    local vlan_range="${results[6]}"
    local phy_name="${results[7]}"
    local pod_name="${results[8]}"
    local cluster_name="${results[9]}"
    local primary_name="${results[10]}"
    local secondary_name="${results[11]}"
    local nfs_server="${results[12]}"
    local primary_path="${results[13]}"
    local secondary_path="${results[14]}"
    local network_type="Advanced"

    # Show confirmation
    local zone_details=""
    zone_details+="Zone: $zone_name (${network_type})\n"
    zone_details+="Guest CIDR: $guest_cidr\n"
    zone_details+="Public IPs: $public_start - $public_end\n"
    zone_details+="Pod IPs: $pod_start - $pod_end\n"
    zone_details+="VLAN Range: $vlan_range\n"
    zone_details+="Physical Network Name: $phy_name\n"
    zone_details+="Pod Name: $pod_name\n"
    zone_details+="Cluster Name: $cluster_name\n"
    zone_details+="Primary Storage Name: $primary_name\n"
    zone_details+="Primary Storage Path: nfs://$nfs_server$primary_path\n"
    zone_details+="Secondary Storage Path: nfs://$nfs_server$secondary_path\n"
    
    log "$(printf "Zone details:\n%b" "$zone_details")"
    if is_interactive; then
        local confirm_msg="Please confirm the following configuration:\n\n$zone_details"
        if ! dialog --backtitle "$SCRIPT_NAME" \
                    --title "Confirm Configuration" \
                    --yesno "$confirm_msg" 18 60; then
            return 1
        fi
    fi

    if ! wait_for_management_server; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "Management Server did not become ready in time.\nPlease check the server status and logs." 8 60
        return 1
    fi

    if ! check_cloudmonkey_availability; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "CloudMonkey is not available or failed to initialize.\nPlease install CloudMonkey and try again." 8 60
        return 1
    fi

    local zone_id=""
    local pod_id=""
    local cluster_id="" 
    {
        zone_id=$(get_tracker_field "zone_id")
        if [[ -n "$zone_id" ]]; then
            log "Zone already deployed with ID: $zone_id"
        else
            update_progress_bar "10" "# Starting Zone deployment..."
            zone_id=$(cmk_api_call '.zone.id' create zone name="${zone_name}" \
                networktype="$network_type" \
                dns1="$DNS" \
                internaldns1="$DNS" \
                localstorageenabled=true \
                securitygroupenabled=false \
                guestcidraddress="$guest_cidr") || \
                cmk_api_fail_dialog_msg "Failed to create zone"
        fi
        set_tracker_field "zone_id" "$zone_id"
        
        local physicalnetwork_id=$(get_tracker_field "physicalnetwork_id")
        if [[ -n "$physicalnetwork_id" ]]; then
            log "Physical Network already created with ID: $physicalnetwork_id"
        else
            update_progress_bar "20" "# Creating Physical Network..."
            physicalnetwork_id=$(cmk_api_call '.physicalnetwork.id' create physicalnetwork name="$phy_name" \
                zoneid="$zone_id" \
                isolationmethods="VLAN") || \
                cmk_api_fail_dialog_msg "Failed to create physical network"

            set_tracker_field "physicalnetwork_id" "$physicalnetwork_id"
            # Add Traffic Types
            update_progress_bar "30" "# Adding Traffic Types..."
            cmk add traffictype traffictype=Management physicalnetworkid="$physicalnetwork_id" >/dev/null 2>&1
            cmk add traffictype traffictype=Guest physicalnetworkid="$physicalnetwork_id" >/dev/null 2>&1
            cmk add traffictype traffictype=Public physicalnetworkid="$physicalnetwork_id" >/dev/null 2>&1
        fi

        local vlan_ip_range_id=$(get_tracker_field "vlan_ip_range_id")
        if [[ -n "$vlan_ip_range_id" ]]; then
            log "VLAN IP Range already added with ID: $vlan_ip_range_id"
        else
            update_progress_bar "35" "# Adding IP Ranges..."
            vlan_ip_range_id=$(cmk_api_call '.vlan.id' create vlaniprange \
                zoneid="$zone_id" \
                vlan=untagged \
                gateway="$GATEWAY" \
                netmask="$NETMASK" \
                startip="$public_start" \
                endip="$public_end" \
                forvirtualnetwork=true) || \
                cmk_api_fail_dialog_msg "Failed to add Public IP range"
            set_tracker_field "vlan_ip_range_id" "$vlan_ip_range_id"
        fi

        update_progress_bar "38" "# Configuring Physical network with VLAN range..."
        cmk update physicalnetwork id=$physicalnetwork_id vlan=$vlan_range >/dev/null 2>&1

        update_progress_bar "40" "# Configuring Physical network state..."
        cmk update physicalnetwork state=Enabled id="$physicalnetwork_id" >/dev/null 2>&1
        local nsp_id=$(cmk list networkserviceproviders name=VirtualRouter physicalnetworkid="$physicalnetwork_id" | jq -r '.networkserviceprovider[0].id')
        local vre_id=$(cmk list virtualrouterelements nspid="$nsp_id" | jq -r '.virtualrouterelement[0].id')
        
        update_progress_bar "45" "# Configuring Physical network services..."
        cmk configure virtualrouterelement enabled=true id="$vre_id" >/dev/null 2>&1
        cmk update networkserviceprovider state=Enabled id="$nsp_id" >/dev/null 2>&1
        
        pod_id=$(get_tracker_field "pod_id")
        if [[ -n "$pod_id" ]]; then
            log "Pod already created with ID: $pod_id"
        else
            update_progress_bar "50" "# Creating Pod..."
            pod_id=$(cmk_api_call '.pod.id' create pod name="$pod_name" \
                zoneid="$zone_id" \
                gateway="$GATEWAY" \
                netmask="$NETMASK" \
                startip="$pod_start" \
                endip="$pod_end") || \
                cmk_api_fail_dialog_msg "Failed to create Pod"
            set_tracker_field "pod_id" "$pod_id"
        fi
        
        cluster_id=$(get_tracker_field "cluster_id")
        if [[ -n "$cluster_id" ]]; then
            log "Cluster already created with ID: $cluster_id"
        else
            update_progress_bar "60" "# Adding Cluster..."
            cluster_id=$(cmk_api_call '.cluster[0].id' add cluster \
                zoneid="$zone_id" \
                podid="$pod_id" \
                clustername="$cluster_name" \
                clustertype=CloudManaged \
                hypervisor=KVM)|| \
                cmk_api_fail_dialog_msg "Failed to add Cluster"
            set_tracker_field "cluster_id" "$cluster_id"
        fi
        
        local host_id=$(get_tracker_field "host_id")
        if [[ -n "$host_id" ]]; then
            log "Host already created with ID: $host_id"
        else
            update_progress_bar "70" "# Adding Host..."
            host_id=$(cmk_api_call '.host[0].id' add host zoneid="$zone_id" \
                podid="$pod_id" \
                clusterid="$cluster_id" \
                hypervisor=KVM \
                username=root \
                password="$root_pass" \
                url="http://$KVM_HOST_IP")|| \
                cmk_api_fail_dialog_msg "Failed to add Host"
            set_tracker_field "host_id" "$host_id"
        fi
        
        local primary_storage_id=$(get_tracker_field "primary_storage_id")
        if [[ -n "$primary_storage_id" ]]; then
            log "Primary Storage already added with ID: $primary_storage_id"
        else
            update_progress_bar "80" "# Adding Primary Storage..."
            primary_storage_id=$(cmk_api_call '.storagepool.id' create storagepool name="$primary_name" \
                zoneid="$zone_id" \
                podid="$pod_id" \
                clusterid="$cluster_id" \
                url="nfs://$nfs_server$primary_path" \
                hypervisor=KVM \
                scope=zone) || \
                cmk_api_fail_dialog_msg "Failed to add Primary Storage"
            set_tracker_field "primary_storage_id" "$primary_storage_id"
        fi
        
        local secondary_storage_id=$(get_tracker_field "secondary_storage_id")
        if [[ -n "$secondary_storage_id" ]]; then
            log "Secondary Storage already added with ID: $secondary_storage_id"
        else
            update_progress_bar "90" "# Add Secondary Storage..."
            secondary_storage_id=$(cmk_api_call '.imagestore.id' add imagestore name="$secondary_name" \
                zoneid="$zone_id" \
                url="nfs://$nfs_server$secondary_path" \
                provider=NFS) || \
                cmk_api_fail_dialog_msg "Failed to add Secondary Storage"
            set_tracker_field "secondary_storage_id" "$secondary_storage_id"
        fi

        update_progress_bar "95" "# Enabling Zone..."
        cmk update zone allocationstate=Enabled id="$zone_id" >/dev/null 2>&1
        
        update_progress_bar "100" "# Zone deployment completed successfully!"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "$title" \
               --gauge "Deploying CloudStack Zone..." 10 70 0
    set_tracker_field "$tracker_key" "yes"
    show_dialog "info" "$title" "Zone deployment completed successfully."
    show_cloudstack_banner
}

# Function to setup bridge used for CS
configure_network() {
    if is_interactive; then
        local new_bridge=$(dialog --inputbox "Enter the name for the bridge:" 8 60 "$BRIDGE" 3>&1 1>&2 2>&3)
        if [[ -n "$new_bridge" && "$new_bridge" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; then
            BRIDGE="$new_bridge"
        fi
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
    [[ -n "$interface" ]] || error_exit "No active non-loopback interface found."

    hostipandsub=$(ip -4 addr show dev "$interface" | awk '/inet / {print $2; exit}')
    gateway=$(ip route show default | awk '/default/ {print $3; exit}')

    # Rest of the existing configure_network code follows...
    if [[ "$OS_TYPE" == "ubuntu" ]]; then
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
        rm -f /etc/netplan/50-cloud-init.yaml

        if netplan generate && netplan apply; then
            show_dialog \
                "info" \
                "Network Configuration" \
                "Bridge $BRIDGE configured successfully with IP $hostipandsub."
        else
            error_exit "Failed to apply Netplan configuration"
        fi
    elif [[ "$OS_TYPE" == "debian" ]]; then
        dialog --backtitle "$SCRIPT_NAME" \
                   --infobox "Configuring bridge $BRIDGE using /etc/network/interfaces..." 5 60
            sleep 1

            cfgfile="/etc/network/interfaces.d/01-bridge-$BRIDGE"
            cat > "$cfgfile" <<EOF
auto $BRIDGE
iface $BRIDGE inet static
    address $hostipandsub
    netmask $NETMASK
    gateway $gateway
    dns-nameservers $DNS
    bridge_ports $interface
    bridge_stp off
    bridge_fd 0
EOF
            chmod 600 "$cfgfile"

            if command -v ifreload &>/dev/null; then
                ifreload -a
            else
                ifdown $interface || true
                ifup $BRIDGE
            fi

    elif [[ "$OS_TYPE" =~ ^(rhel|centos|ol|rocky|almalinux)$ ]]; then
        {
            update_progress_bar "5" "# Configuring bridge interface $BRIDGE..."

            # First, check if bridge already exists and remove it
            if nmcli connection show "$BRIDGE" &>/dev/null; then
                update_progress_bar "10" "# Removing existing bridge connection..."
                nmcli connection delete "$BRIDGE" &>/dev/null || true
            fi
            
            # Remove any existing slave connections for this interface
            local slave_name="${interface}-slave-$BRIDGE"
            if nmcli connection show "$slave_name" &>/dev/null; then
                update_progress_bar "15" "# Removing existing slave connection..."
                nmcli connection delete "$slave_name" &>/dev/null || true
            fi
            sleep 2

            # Get the original connection name for the interface
            update_progress_bar "20" "# Detecting current network configuration..."
            local original_conn=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":$interface$" | cut -d: -f1)
            
            # Create bridge
            if output=$(nmcli connection add type bridge \
                con-name "$BRIDGE" \
                ifname "$BRIDGE" \
                bridge.stp no \
                ipv4.addresses "$hostipandsub" \
                ipv4.gateway "$gateway" \
                ipv4.dns "$DNS" \
                ipv4.method manual \
                ipv6.method disabled \
                connection.autoconnect yes \
                connection.autoconnect-slaves 1 2>&1); then
                update_progress_bar "30" "# Bridge created successfully"
            else
                update_progress_bar "100" "# Failed to create bridge: $output"
                error_exit "Failed to create bridge: $output"
            fi
            sleep 2
            
            # Add ethernet interface as slave
            update_progress_bar "50" "# Adding interface $interface to bridge..."
            if output=$(nmcli connection add type ethernet \
                slave-type bridge \
                con-name "$slave_name" \
                ifname "$interface" \
                master "$BRIDGE" \
                connection.autoconnect yes 2>&1); then
                update_progress_bar "60" "# Interface added as bridge slave"
            else
                update_progress_bar "100" "# Failed to add interface: $output"
                error_exit "Failed to add interface: $output"
            fi
            sleep 2

            # Bring down original connection if it exists
            if [[ -n "$original_conn" ]]; then
                update_progress_bar "70" "# Deactivating original connection..."
                nmcli connection down "$original_conn" &>/dev/null || true
                sleep 2
            fi

            # Activate connection
            update_progress_bar "90" "# Activating network connection..."
            if output=$(nmcli connection up "$BRIDGE" 2>&1); then
                update_progress_bar "92" "# Bridge activated successfully"
            else
                update_progress_bar "100" "# Failed to activate bridge: $output"
                sleep 1
                error_exit "Failed to activate bridge: $output"
            fi
            sleep 5

            update_progress_bar "95" "# Verifying bridge configuration..."
            if ! ip link show "$BRIDGE" &>/dev/null; then
                error_exit "Bridge $BRIDGE was not created successfully"
            fi

            # Wait for IP assignment
            local max_wait=10
            local count=0
            local expected_ip=$(echo "$hostipandsub" | cut -d'/' -f1)
            while [[ $count -lt $max_wait ]]; do
                if ip addr show "$BRIDGE" | grep -q "inet.*$expected_ip"; then
                    break
                fi
                sleep 1
                ((count++))
            done
            
            update_progress_bar "100" "# Bridge configuration complete"
            sleep 2

        } | dialog --backtitle "$SCRIPT_NAME" \
                --title "Network Configuration" \
                --gauge "Configuring network with NetworkManager..." 10 70 0

        # Verify the configuration
        if ip link show "$BRIDGE" &>/dev/null; then
            local bridge_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)
            if [[ -n "$bridge_ip" ]]; then
                show_dialog \
                    "info" \
                    "Network Configuration" \
                    "Bridge $BRIDGE configured successfully with IP $bridge_ip." 5
            else
                dialog --backtitle "$SCRIPT_NAME" \
                    --title "Warning" \
                    --msgbox "Bridge $BRIDGE created but IP address not detected.\n\nPlease verify with: ip addr show $BRIDGE" 8 70
                return 1
            fi
        else
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Error" \
                --msgbox "Failed to configure bridge $BRIDGE.\n\nCheck logs with:\njournalctl -xeu NetworkManager" 8 70
            return 1
        fi

    else
        error_exit "Unsupported OS type: $OS_TYPE"
    fi
}

#-------------------------------------------------------------------------------
# Driver functions to setup and install components
#-------------------------------------------------------------------------------

setup_network() {
    log "Starting network configuration"
    if is_step_tracked "network_name"; then
        BRIDGE=$(get_tracker_field "network_name")
        show_dialog "info" "Network Configuration" "Network already configured with bridge $BRIDGE.\n\n Skipping network configuration."
        return 0
    fi
    configure_network
    set_tracker_field "network_name" "$BRIDGE"
    log "Network configured with bridge $BRIDGE"
}

configure_repo() {
    log "Setting up CloudStack repository"
    if is_step_tracked "repo_url"; then
        local repo_url=$(get_tracker_field "repo_url")
        show_dialog "info" "CloudStack Repo Setup" "CloudStack repository already configured with $repo_url\n\n Skipping repository setup."
        return 0
    fi
    configure_cloudstack_repo
}

install_configure_mgmt() {
    install_mysql_server
    install_management_server
    configure_mysql_for_cloudstack
    configure_management_server_database
}

install_configure_agent() {
    install_kvm_agent
    configure_kvm_agent
}

install_configure_usage() {
    install_usage_server
    configure_usage_server
}

# Install and configure selected components
install_configure_components() {
    show_components_versions
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " nfs " ]]; then
        install_nfs_server
        configure_nfs_server
    fi

    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]]; then
        install_configure_mgmt
    fi

    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " agent " ]]; then
        install_configure_agent
    fi
    if [[ " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]]; then
        install_configure_usage
    fi
}

# Validate system resources before setup
validate_system_resources() {
    check_root
    check_kvm_support
    check_system_resources
    validate_jre_version
}

# Configure prerequisites before installation
configure_prerequisites() {
    detect_os
    update_system_time
    install_base_dependencies
}

# Driver function for custom installation
custom_install() {
    if [ ${#SELECTED_COMPONENTS[@]} -eq 0 ]; then
        select_components_to_setup
    fi
    log "Selected components for installation: ${SELECTED_COMPONENTS[*]}"
    if is_cloudstack_pkg_selected; then
        setup_network
        configure_repo
    fi
    update_system_packages
    install_configure_components
}

# Driver function for all-in-one installation
all_in_one_install() {
    PROMPT=0    # configure silent mode for all-in-one
    if dialog --backtitle "$SCRIPT_NAME" \
           --title "All-in-One Installation" \
           --yesno "You have selected all components for installation. This will configure a complete CloudStack setup on this single machine.\n\nProceed with All-in-One installation?" 12 60; then
        SELECTED_COMPONENTS=("nfs" "management" "agent" "usage")
        custom_install
    else
        dialog --backtitle "$SCRIPT_NAME" \
               --title "All-in-One Installation" \
               --msgbox "Installation cancelled by user." 6 60
        exit 0
    fi
}

# Cleanup function for trap
cleanup() {
    local exit_code=${1:-$?}
    clear
    if [[ $exit_code -eq 0 ]]; then
        success_msg "Script completed successfully. Check $CS_LOGFILE for details."
    else
        warn_msg "Script interrupted. Check $CS_LOGFILE for details."
    fi
    exit $exit_code
}

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------

main() {
    log "CloudStack Installer Script Started"
    load_tracker
    validate_system_resources
    configure_prerequisites
    local temp_file=$(mktemp)
    if ! dialog --backtitle "$SCRIPT_NAME" \
           --title "Installation Options" \
           --menu "Select an option:" 12 50 4 \
           1 "All-in-One Installation" \
           2 "Custom Installation" \
           3 "Configure CloudStack Repository" \
           4 "Deploy CloudStack Zone" 2> "$temp_file"; then
        show_dialog "msg" "Installation Options" "Installation option selection cancelled by user."
        error_exit "Installation option selection cancelled by user"
    fi
    local option=$(< "$temp_file")
    case $option in
        1)
            all_in_one_install
            ;;
        2)
            custom_install
            ;;
        3)
            configure_cloudstack_repo
            ;;
        4)
            deploy_zone
            ;;
    esac
    
    if [[ ${#SELECTED_COMPONENTS[@]} -gt 0 ]]; then
        if show_validation_summary; then
            if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]]; then
                if is_interactive; then
                    if ! select_zone_deployment; then
                        dialog --backtitle "$SCRIPT_NAME" \
                            --title "Zone Deployment" \
                            --msgbox "Zone deployment skipped. You can deploy a zone later using CloudStack UI." 8 60
                    else
                        deploy_zone
                    fi
                else
                    deploy_zone
                fi
            fi
        else
            show_dialog "msg" "Zone Deployment" "Warning: Some components are not properly configured.\n\nZone deployment is not available until all components are fixed." 5 10
        fi
    fi
    rm -f "$temp_file"
    cleanup 0 
}

# Set trap for cleanup
trap 'cleanup 1' INT TERM

# Run main function
main "$@"
