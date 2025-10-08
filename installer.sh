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
LOGFILE="/tmp/cloudstack_install.log"
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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
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

                echo "40"
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
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Success" \
               --msgbox "System packages have been successfully updated." 6 50
    else
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Error" \
               --msgbox "Failed to update system packages. Please check the logs." 6 50
        return 1
    fi
}

configure_cloudstack_repo() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "CloudStack Repository Configuration" \
           --msgbox "This step will configure the Apache CloudStack repository for version $CS_VERSION.\n\nThe repository URL is:\nhttps://download.cloudstack.org/\n\nPress OK to proceed." 12 60

    case "$OS_TYPE" in
        ubuntu|debian)
            {
                if [[ "$OS_TYPE" == "debian" ]]; then
                    UBUNTU_CODENAME=$(get_ubuntu_codename_for_debian "$VERSION_CODENAME") || exit 1
                else
                    UBUNTU_CODENAME="$VERSION_CODENAME"
                fi
                echo "Configuring CloudStack repository..."
                echo "Adding CloudStack's signing key..."

                if curl -fsSL https://download.cloudstack.org/release.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null; then
                    echo "CloudStack signing key added successfully."
                else
                    error_exit "Failed to add CloudStack signing key."
                fi
                
                echo "Adding CloudStack repository..."
                if echo "deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] https://download.cloudstack.org/ubuntu $UBUNTU_CODENAME $CS_VERSION" | sudo tee /etc/apt/sources.list.d/cloudstack.list > /dev/null; then
                    echo "CloudStack repository added successfully."
                else
                    error_exit "Failed to add CloudStack repository."
                fi

                echo "Repository configuration completed."
            } | dialog --backtitle "$SCRIPT_NAME" \
                       --title "Repository Configuration" \
                       --programbox "Configuring CloudStack repository..." 15 70
            ;;
            
        rhel|centos|ol|rocky|almalinux)
        {
            echo "20"
            echo "# Adding CloudStack repository..."
            local repo_path=$(determine_distro_version)
            DISTRO_VERSION_URL=https://download.cloudstack.org/$repo_path/$CS_VERSION/
            if cat > /etc/yum.repos.d/cloudstack.repo <<EOF
[cloudstack]
name=CloudStack
baseurl=$DISTRO_VERSION_URL
enabled=1
gpgcheck=0
gpgkey=https://download.cloudstack.org/release.asc
EOF
            then
                echo "XXX"
                echo "60"
                echo "# Repository added successfully"
                echo "XXX"
            else
                error_exit "Failed to create CloudStack repository file"
            fi

            echo "100"
            echo "# Repository configuration completed!"
        } | dialog --backtitle "$SCRIPT_NAME" \
                --title "Repository Configuration" \
                --gauge "Configuring CloudStack repository..." 15 70 0
                ;;
            
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            exit 1
            ;;
    esac
}

determine_distro_version() {
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
    sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g'
}

install_base_dependencies() {
    if ! command -v dialog &>/dev/null; then
        preinstall_dialog
    fi
    
    TMP_LOG=$(mktemp /tmp/install_base.XXXXXX.log)
    {   
        echo "XXX"
        echo "30"
        echo "Installing base dependencies (qemu-kvm, python, curl, etc.)..."
        echo "XXX"

        case "$PACKAGE_MANAGER" in
            apt)
                DEBIAN_FRONTEND=noninteractive \
                apt-get install -y qemu-kvm apt-utils curl openssh-server sshpass sudo wget jq htop tar nmap bridge-utils >> "$TMP_LOG" 2>&1 &
                ;;
            dnf)
                dnf install -y curl openssh-server sshpass sudo wget jq tar nmap >> "$TMP_LOG" 2>&1 &
                    error_exit "Failed to install base dependencies"
                ;;
        esac

        INSTALL_PID=$!
        PERCENT=31
        while kill -0 "$INSTALL_PID" 2>/dev/null; do
            echo "XXX"
            echo "$PERCENT"
            tail -n 3 "$TMP_LOG" | strip_ansi | tr -d '\n' | cut -c -200
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
    
    dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Dependencies" \
               --msgbox "All Base dependencies installed successfully" 10 60
    
    if [ -s "$TMP_LOG" ]; then
        if dialog --yesno "Would you like to view the installation log?" 8 60; then
            dialog --textbox "$TMP_LOG" 20 80
        fi
        rm -f "$TMP_LOG"
    fi
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
            yum install -y nfs-utils quota
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


install_components() {
    TMP_LOG=$(mktemp /tmp/component_install.XXXXXX.log)

    local total_steps=${#SELECTED_COMPONENTS[@]}
    local current_step=0

    {
        for component in "${SELECTED_COMPONENTS[@]}"; do
            current_step=$((current_step + 1))
            # Per-component progress range
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

  dialog --yesno "Do you want to configure MySQL for CloudStack?" 7 50
  response=$?
  if [[ $response -ne 0 ]]; then
    dialog --msgbox "MySQL configuration skipped." 5 40
    return
  fi

  # ensure mysql is running
  if ! systemctl is-active --quiet $MYSQL_SERVICE; then
    dialog --title "MySQL Configuration" --msgbox "MySQL service is not running. Please start MySQL before proceeding." 6 50
    return 1
  fi

  dialog --title "MySQL Configuration" --msgbox "Configuring MYSQL for CloudStack..." 6 50
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


configure_nfs_server() {
  dialog --title "NFS Configuration" --msgbox "Starting NFS storage configuration..." 6 50

  if grep -q "^/export " /etc/exports; then
    dialog --title "NFS Configuration" --msgbox "NFS is already configured. Skipping setup." 6 50
    return
  fi

  dialog --title "NFS Setup" --yesno "Do you want to configure the system as an NFS server with:\n\n• Export path: /export\n• Subdirs: /primary & /secondary\n• Permissions: rw, no_root_squash\n\nProceed?" 12 60
  [[ $? -ne 0 ]] && dialog --msgbox "NFS configuration skipped." 5 40 && return

  # Step 1: Create exports and directories
  echo "/export  *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
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

    # Prompt for bridge interface
    BRIDGE=$(dialog --inputbox "Enter the bridge interface name (e.g., cloudbr0):" 8 50 "cloudbr0" 3>&1 1>&2 2>&3)

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
                echo "$line"
                echo "XXX"
                echo "50"
                echo "Deploying CloudStack Database...\n\n$line"
                echo "XXX"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Database Deployment" \
               --gauge "Starting database deployment..." 10 70 0

    {
        echo "# Starting CloudStack Management Server setup..."
        cloudstack-setup-management 2>&1 | \
            while IFS= read -r line; do
                echo "$line"
                echo "XXX"
                echo "75"
                echo "Deploying Management Server...\n\n$line"
                echo "XXX"
            done
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Management Server Setup" \
               --gauge "Starting management server setup..." 10 70 0

    sleep 10
    echo "100" | dialog --title "Success" --msgbox "CloudStack Management Server has been configured." 7 60
}

configure_kvm_agent() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "KVM Host Configuration" \
           --infobox "Starting KVM host configuration..." 5 50
    sleep 2

    # Configure VNC
    {
        echo "XXX"
        echo "10"
        echo "# Configuring VNC access..."
        echo "XXX"
        if sed -i -e 's/\#vnc_listen.*$/vnc_listen = "0.0.0.0"/g' /etc/libvirt/qemu.conf; then
            echo "VNC configuration successful"
        else
            error_exit "Failed to configure VNC"
        fi

        echo "XXX"
        echo "25"
        echo "# Configuring libvirtd..."
        echo "XXX"
        # Configure libvirtd to listen
        if ! grep '^LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd > /dev/null; then
            echo 'LIBVIRTD_ARGS="--listen"' >> /etc/default/libvirtd
        fi

        echo "XXX"
        echo "40"
        echo "# Setting up libvirt TCP access..."
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
        echo "# Configuring libvirt sockets..."
        echo "XXX"
        systemctl mask libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket
        systemctl restart libvirtd

        echo "XXX"
        echo "75"
        echo "# Configuring security policies..."
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
                                ln -sf "$profile" "/etc/apparmor.d/disable/"
                                if [[ -f "$profile" ]]; then
                                    apparmor_parser -R "$profile" || warn_msg "Failed to remove profile: $profile"
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
                        systemctl restart apparmor || warn_msg "Failed to restart AppArmor"
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
        echo "# Configuring firewall..."
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

        echo "XXX"
        echo "100"
        echo "XXX"
        echo "# KVM host configuration completed!"
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

deploy_zone() {
    local input_bridge=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --inputbox "Enter the bridge interface name connected to public network (e.g., cloudbr0):" 8 60 "$BRIDGE" 3>&1 1>&2 2>&3)
    BRIDGE=${input_bridge:-$BRIDGE}

    HOST_IP=$(ip -4 addr show "$BRIDGE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    GATEWAY=$(ip route | grep default | grep "$BRIDGE" | awk '{print $3}')

    local input_ip=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --inputbox "Detected Host IP: $HOST_IP\n\nYou can modify these values if needed." 10 60 "$HOST_IP" 3>&1 1>&2 2>&3)
    local input_gw=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --inputbox "Detected Gateway: $GATEWAY\n\nYou can modify these values if needed." 10 60 "$GATEWAY" 3>&1 1>&2 2>&3)  
    HOST_IP=${input_ip:-$HOST_IP}
    GATEWAY=${input_gw:-$GATEWAY}  

    if [[ -z "$HOST_IP" || -z "$GATEWAY" ]]; then
        error_exit "Could not determine host IP or gateway. Is bridge $BRIDGE configured properly?"
    fi

    # Prompt for root password before starting zone deployment
    local root_pass=$(dialog --backtitle "$SCRIPT_NAME" \
        --title "Host Configuration" \
        --insecure \
        --passwordbox "Enter root password for KVM host ($HOST_IP):" 8 60 \
        3>&1 1>&2 2>&3)

    # check if password is provided and validate by doing ssh, reprompt until valid or cancelled
    while [[ -n "$root_pass" ]]; do
        if sshpass -p "$root_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$HOST_IP" 'echo "SSH connection successful"' &>/dev/null; then
            break
        else
            root_pass=$(dialog --backtitle "$SCRIPT_NAME" \
                --title "Host Configuration" \
                --insecure \
                --passwordbox "Failed to connect to $HOST_IP via SSH with the provided root password.\nPlease verify the password and ensure SSH access is enabled.\n\nRe-enter root password for KVM host ($HOST_IP):" 10 60 \
                3>&1 1>&2 2>&3)
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

    local zone_id=""
    local pod_id=""
    local cluster_id="" 
    {
        echo "XXX"
        echo "10"
        echo "Creating Zone..."
        echo "XXX"

        zone_output=$(cmk create zone name="Zone1" \
            networktype=Advanced \
            dns1="$DNS" \
            internaldns1="$DNS" \
            localstorageenabled=true \
            securitygroupenabled=false \
            guestcidraddress="172.16.1.0/24")
        
        if ! zone_id=$(echo "$zone_output" | jq -r '.zone.id' 2>/dev/null); then
            echo "XXX"
            echo "100"
            echo "Failed to create zone: $zone_output"
            echo "XXX"
            return 1
        fi

        echo "XXX"
        echo "20"
        echo "Creating Physical Network..."
        echo "XXX"
        # Create Physical Network
        local phy_id=$(cmk create physicalnetwork name="Physical Network 1" \
            zoneid="$zone_id" \
            isolationmethods="VLAN" | jq -r '.physicalnetwork.id')
        
        [[ -z "$phy_id" ]] && error_exit "Failed to create physical network"
        
        echo "XXX"
        echo "30"
        echo "Adding Traffic Types..."
        echo "XXX"
        # Add Traffic Types
        cmk add traffictype traffictype=Management physicalnetworkid="$phy_id"
        cmk add traffictype traffictype=Guest physicalnetworkid="$phy_id"
        cmk add traffictype traffictype=Public physicalnetworkid="$phy_id"

        echo "XXX"
        echo "35"
        echo "Adding IP Ranges..."
        echo "XXX"

        # Add Public IP Range
        if ! cmk create vlaniprange \
            zoneid="$zone_id" \
            vlan=untagged \
            gateway="$GATEWAY" \
            netmask="255.255.255.0" \
            startip="${HOST_IP%.*}.11" \
            endip="${HOST_IP%.*}.30" \
            forvirtualnetwork=true; then
            echo "XXX"
            echo "100"
            echo "Failed to add Public IP range"
            echo "XXX"
            return 1
        fi
        cmk update physicalnetwork id=$phy_id vlan=100-200
        
        echo "XXX"
        echo "40"
        echo "Configuring Virtual Router..."
        echo "XXX"
        # Configure Virtual Router Provider
        cmk update physicalnetwork state=Enabled id="$phy_id"
        
        local nsp_id=$(cmk list networkserviceproviders name=VirtualRouter physicalnetworkid="$phy_id" | jq -r '.networkserviceprovider[0].id')
        local vre_id=$(cmk list virtualrouterelements nspid="$nsp_id" | jq -r '.virtualrouterelement[0].id')
        
        cmk configure virtualrouterelement enabled=true id="$vre_id"
        cmk update networkserviceprovider state=Enabled id="$nsp_id"
        
        echo "XXX"
        echo "50"
        echo "Creating Pod..."
        echo "XXX"
        pod_id=$(cmk create pod name="Pod1" \
            zoneid="$zone_id" \
            gateway="$GATEWAY" \
            netmask="255.255.255.0" \
            startip="${HOST_IP%.*}.31" \
            endip="${HOST_IP%.*}.50" | jq -r '.pod.id')
        
        [[ -z "$pod_id" ]] && error_exit "Failed to create pod"
        
        echo "XXX"
        echo "60"
        echo "Adding Cluster..."
        echo "XXX"
        cluster_id=$(cmk add cluster \
            zoneid="$zone_id" \
            podid="$pod_id" \
            clustername="Cluster1" \
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
            url="http://$HOST_IP"
        
        echo "XXX"
        echo "80"
        echo "Adding Primary Storage..."
        echo "XXX"
        # Add Primary Storage
        cmk create storagepool name="Primary1" \
            zoneid="$zone_id" \
            podid="$pod_id" \
            clusterid="$cluster_id" \
            url="nfs://$HOST_IP/export/primary" \
            hypervisor=KVM \
            scope=zone
        
        echo "XXX"
        echo "90"
        echo "Adding Secondary Storage..."
        echo "XXX"
        # Add Secondary Storage
        cmk add imagestore name="Secondary1" \
            zoneid="$zone_id" \
            url="nfs://$HOST_IP/export/secondary" \
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
        update_progress "Configuring KVM Agent..." $current_step | \
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "" 10 70 0
        configure_kvm_agent
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

configure_network() {
    # First check if bridge already exists
    if ip link show "$BRIDGE" &>/dev/null; then
        local bridge_ip=$(ip -4 addr show "$BRIDGE" | awk '/inet / {print $2}' | cut -d/ -f1)
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Network Configuration" \
               --msgbox "Bridge interface $BRIDGE already exists with IP $bridge_ip\nSkipping network configuration." 8 60
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
            dialog --backtitle "$SCRIPT_NAME" \
                --title "Success" \
                --msgbox "Bridge $BRIDGE configured successfully with NetworkManager." 7 60
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

show_validation_summary() {
    local summary=""
    local status_ok=true
    local validation_steps=0
    local current_step=0

    {
        # 1. Network Validation
        echo "10"
        echo "# Checking Network Configuration..."
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

        # 2. MySQL Validation (if selected)
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " mysql " ]]; then
            echo "30"
            echo "# Checking MySQL..."
            if systemctl is-active --quiet $MYSQL_SERVICE; then
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

        # 3. NFS Validation (if selected)
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " nfs " ]]; then
            echo "50"
            echo "# Checking NFS Server..."
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

        # 4. Management Server Validation (if selected)
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]]; then
            echo "70"
            echo "# Checking Management Server..."
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

        # 5. KVM Agent Validation (if selected)
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " agent " ]]; then
            echo "85"
            echo "# Checking KVM Agent..."
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

        # 6. Usage Server Validation (if selected)
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]]; then
            echo "95"
            echo "# Checking Usage Server..."
            if systemctl is-active --quiet cloudstack-usage; then
                summary+="✓ Usage Server: Running\n"
            else
                summary+="✗ Usage Server: Not running\n"
                status_ok=false
            fi
        fi

        echo "100"
        echo "# Validation complete!"

        echo "Within $summary" >> $LOGFILE
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Component Validation" \
               --gauge "Validating installed components..." 10 70 0
    
    echo "$summary" >> $LOGFILE
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
    configure_cloudstack_repo
    configure_network
    update_system
}

validate_setup_pre_req() {
    check_root
    check_kvm_support
    check_system_resources
    detect_os
    install_base_dependencies
}

select_cloudstack_version() {
    CS_VERSION="4.20"
    TMP_LOG=$(mktemp /tmp/cs_version_input.XXXXXX)
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Welcome" \
           --msgbox "Welcome to the Apache CloudStack Installation Script\!\n\nThis script will help you install and configure CloudStack components on your system.\n\nPress OK to continue." 12 60
    
    # allow user to modify if he wants to change anything
    dialog --backtitle "$SCRIPT_NAME" \
           --title "CloudStack Version" \
           --inputbox "Enter the CloudStack version to install:" 8 50 "$CS_VERSION" 2> $TMP_LOG
    if [[ $? -ne 0 ]]; then
        error_exit "CloudStack version input cancelled by user"
    fi
    CS_VERSION=$(< $TMP_LOG)
    rm -f $TMP_LOG
    dialog --backtitle "$SCRIPT_NAME" \
           --title "CloudStack Version" \
           --msgbox "You have selected CloudStack version: $CS_VERSION\n\nPress OK to continue." 8 50
}


custom_install() {
    # Clear screen and start logging
    clear
    log "Starting CloudStack installation script"
    select_cloudstack_version
    
    configure_prerequisites

    # Main installation flow
    select_components
    install_components

    # Configure components
    configure_components

    show_validation_summary
    validation_status=$?
    if [[ $validation_status -ne 0 ]]; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Warning" \
               --msgbox "Zone deployment is not available until all components are properly configured." 8 60
    fi
    
    if select_zone_deployment; then
        deploy_zone
    else
        dialog --backtitle "$SCRIPT_NAME" \
                --title "Zone Deployment" \
                --msgbox "Zone deployment skipped. You can deploy a zone later using CloudStack UI." 8 60
    fi
    log "CloudStack installation script completed successfully"
    exit 0
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
    select_cloudstack_version

    configure_prerequisites

    SELECTED_COMPONENTS=("nfs" "mysql" "management" "agent" "usage")
    install_components
    configure_components
    show_validation_summary
    deploy_zone
    show_cloudstack_banner
}

main() {
    validate_setup_pre_req
    
    local temp_file=$(mktemp)
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Installation Options" \
           --menu "Select an option:" 15 60 4 \
           1 "All-in-One Installation" \
           2 "Custom Component Installation" \
           3 "Configure CloudStack Repository" \
           4 "Deploy CloudStack Zone" 2> "$temp_file"
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
            configure_cloudstack_repo
            ;;
        4)
            deploy_zone
            ;;
    esac
    rm -f "$temp_file"
    exit 0
}

# Cleanup function for trap
cleanup() {
    clear
    warn_msg "Script interrupted. Check $LOGFILE for details."
    exit 1
}

# Set trap for cleanup
trap cleanup INT TERM

# Run main function
main "$@"