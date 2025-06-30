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

CS_VERSION=4.20
INTERFACE=
BRIDGE=cloudbr0
HOST_IP=
GATEWAY=
DNS="9.9.9.9, 1.1.1.1"

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

check_available_memory() {
    MIN_RAM_KB=$((8 * 1024 * 1024))  # 8 GB in KB
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')

    # Check if RAM is within the desired range
    if [ "$TOTAL_RAM_KB" -ge "$MIN_RAM_KB" ]; then
        log "RAM check passed: $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB"
    else
        error_exit "RAM check failed: System has $(awk "BEGIN {printf \"%.2f\", $TOTAL_RAM_KB/1024/1024}") GB RAM"
        exit 1
    fi
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
        ubuntu)
            PACKAGE_MANAGER="apt"
            ;;
        debian)
            PACKAGE_MANAGER="apt"
            ;;
        rhel|centos|fedora|rocky|alma)
            PACKAGE_MANAGER="dnf"
            ;;
        *)
            echo "Unsupported OS: $OS_TYPE"
            exit 1
            ;;
    esac

    log "OS Detection: $OS_TYPE with package manager: $PACKAGE_MANAGER"
}

configure_cloudstack_repo() {
    {
        echo "Configuring CloudStack repository..."

        case "$OS_TYPE" in
            ubuntu|debian)
                # Add CloudStack's signing key
                curl -fsSL https://download.cloudstack.org/release.asc | gpg --dearmor | tee /etc/apt/keyrings/cloudstack.gpg > /dev/null
                
                # Add CloudStack repository
                echo "deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] https://download.cloudstack.org/ubuntu noble $CS_VERSION" | tee /etc/apt/sources.list.d/cloudstack.list

                # Update the system
                apt-get update
                ;;
            rhel|centos|fedora|rocky|alma)
                # Add CloudStack's signing key
                curl -fsSL https://download.cloudstack.org/release.asc | tee /etc/pki/rpm-gpg/CloudStack.asc
                
                # Add CloudStack repository
                echo "[cloudstack]" | tee /etc/yum.repos.d/cloudstack.repo
                echo "name=CloudStack Repo" | tee -a /etc/yum.repos.d/cloudstack.repo
                echo "baseurl=https://download.cloudstack.org/centos/$OS_VERSION" | tee -a /etc/yum.repos.d/cloudstack.repo
                echo "enabled=1" | tee -a /etc/yum.repos.d/cloudstack.repo
                echo "gpgcheck=1" | tee -a /etc/yum.repos.d/cloudstack.repo
                echo "gpgkey=https://download.cloudstack.org/release.asc" | tee -a /etc/yum.repos.d/cloudstack.repo
                
                # Update the system
                sudo dnf update -y
                ;;
            *)
                echo "Unsupported OS: $OS_TYPE"
                exit 1
                ;;
        esac
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Repository Configuration" \
               --gauge "Configuring Cloudstack repository..." 10 70
}

install_base_dependencies() {
    case "$PACKAGE_MANAGER" in
        apt)
            apt-get install -y dialog &>/dev/null || \
                error_exit "Failed to install base dependencies"
            ;;
        dnf)
            dnf install -y dialog  &>/dev/null || \
                error_exit "Failed to install base dependencies"
            ;;
    esac
    {
        echo "10"
        echo "# Updating package lists..."
        case "$PACKAGE_MANAGER" in
            apt)
                apt-get update &>/dev/null || error_exit "Failed to update package lists"
                ;;
            dnf)
                dnf makecache &>/dev/null || error_exit "Failed to update package cache"
                ;;
        esac
        
        echo "50"
        echo "Installing base dependencies (dialog, python, whiptail, curl, etc.)..."
        case "$PACKAGE_MANAGER" in
            apt)
                apt-get install -y curl openssh-server sudo wget jq htop tar nmap bridge-utils &>/dev/null || \
                    error_exit "Failed to install base dependencies"
                ;;
            dnf)
                dnf install -y curl openssh-server sudo wget jq htop tar nmap bridge-utils &>/dev/null || \
                    error_exit "Failed to install base dependencies"
                ;;
        esac 
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Dependencies" \
               --gauge "Preparing system..." 10 70  
    
    dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Dependencies" \
               --msgbox "Base dependencies installed successfully" 10 60
}

update_system() {
    echo "Updating the system..."
    case "$PACKAGE_MANAGER" in
        apt)
            sudo apt-get update && sudo apt-get upgrade -y
            ;;
        dnf)
            sudo dnf update -y
            ;;
    esac
}

# Function to install packages based on the detected OS
install_package() {
    local package_name=$1
    {
        echo "Installing $package_name..."
        case "$PACKAGE_MANAGER" in
            apt)
                sudo apt-get install -y "$package_name"
                ;;
            dnf)
                sudo dnf install -y "$package_name"
                ;;
        esac
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Installing Packages" \
               --gauge "Installing $package_name..." 10 70
    
}

# Install common packages
install_common_packages() {
    install_package "cloudstack-common"
}

# Function to install CloudStack Management Server
install_management_server() {
    install_package "cloudstack-management"
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
           "kvm" "KVM Agent" on \
           "mysql" "MySQL Server" on \
           "nfs" "NFS Server" off \
           "common" "CloudStack Common (required)" on \
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
    local total_steps=${#SELECTED_COMPONENTS[@]}
    local current_step=0
    
    for component in "${SELECTED_COMPONENTS[@]}"; do
        current_step=$((current_step + 1))
        local progress=$((current_step * 100 / total_steps))
        
        # Show progress
        echo "$progress" | dialog --backtitle "$SCRIPT_NAME" \
                                 --title "Installing Components" \
                                 --gauge "Installing $component..." 10 70
        
        case "$component" in
            management)
                install_management_server
                ;;
            usage)
                install_usage_server
                ;;
            kvm)
                install_kvm_agent
                ;;
            mysql)
                install_mysql_server
                ;;
            nfs)
                install_nfs_server
                ;;
            common)
                install_common_packages
                ;;
        esac
        
        sleep 1  # Brief pause for user experience
    done
    
    # Final progress update
    echo "100" | dialog --backtitle "$SCRIPT_NAME" \
                       --title "Installation Complete" \
                       --gauge "All components installed successfully!" 10 70
    
    sleep 2
}

configure_mysql() {
  MYSQL_VERSION=$(mysql -V 2>/dev/null || echo "MySQL not found")
  dialog --title "MySQL Configuration" --msgbox "Detected MySQL Version:\n$MYSQL_VERSION" 8 50

  if [[ -f "/etc/mysql/mysql.conf.d/cloudstack.cnf" ]]; then
    dialog --title "MySQL Configuration" --msgbox "Configuration already exists.\nSkipping MySQL setup." 6 50
    return
  fi

  dialog --yesno "Do you want to configure MySQL for CloudStack?" 7 50
  response=$?
  if [[ $response -ne 0 ]]; then
    dialog --msgbox "MySQL configuration skipped." 5 40
    return
  fi

  sqlmode="$(mysql -B -e "show global variables like 'sql_mode'" 2>/dev/null | grep sql_mode | awk '{ print $2; }' | sed -e 's/ONLY_FULL_GROUP_BY,//')"

  if [[ -z "$sqlmode" ]]; then
    dialog --msgbox "Failed to fetch current SQL mode. Aborting." 6 50
    return 1
  fi

  cat > /etc/mysql/mysql.conf.d/cloudstack.cnf <<EOF
[mysqld]
server_id = 1
sql_mode = "$sqlmode"
innodb_rollback_on_timeout = 1
innodb_lock_wait_timeout = 600
max_connections = 1000
log_bin = mysql-bin
binlog_format = "ROW"
EOF

  systemctl restart mysql && \
    dialog --msgbox "MySQL has been configured and restarted successfully." 6 50 || \
    dialog --msgbox "Failed to restart MySQL. Please check the service manually." 6 60
}


configure_nfs_server() {
  source /etc/os-release
  DISTRO=$ID

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
  if [[ "$DISTRO" =~ ^(ubuntu|debian)$ ]]; then
    sed -i -e 's/^RPCMOUNTDOPTS="--manage-gids"$/RPCMOUNTDOPTS="-p 892 --manage-gids"/g' /etc/default/nfs-kernel-server
    sed -i -e 's/^STATDOPTS=$/STATDOPTS="--port 662 --outgoing-port 2020"/g' /etc/default/nfs-common
    grep -q 'NEED_STATD=yes' /etc/default/nfs-common || echo "NEED_STATD=yes" >> /etc/default/nfs-common
    sed -i -e 's/^RPCRQUOTADOPTS=$/RPCRQUOTADOPTS="-p 875"/g' /etc/default/quota

    systemctl restart nfs-kernel-server
    SERVICE_STATUS=$?
  
  elif [[ "$DISTRO" =~ ^(rhel|centos|fedora|ol|oracle)$ ]]; then
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
    dialog --title "Error" --msgbox "Unsupported distribution: $DISTRO" 6 50
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


configure_components() {
    local total_steps=${#SELECTED_COMPONENTS[@]}
    local current_step=0
    
    for component in "${SELECTED_COMPONENTS[@]}"; do
        current_step=$((current_step + 1))
        local progress=$((current_step * 100 / total_steps))
        
        # Show progress
        echo "$progress" | dialog --backtitle "$SCRIPT_NAME" \
                                 --title "Installing Components" \
                                 --gauge "Installing $component..." 10 70
        
        case "$component" in
            management)
                configure_management_server
                ;;
            usage)
                configure_usage_server
                ;;
            kvm)
                configure_kvm_agent
                ;;
            mysql)
                configure_mysql
                ;;
            nfs)
                configure_nfs_server
                ;;
        esac
        
        sleep 1  # Brief pause for user experience
    done
    
    # Final progress update
    echo "100" | dialog --backtitle "$SCRIPT_NAME" \
                       --title "Configuration Complete" \
                       --gauge "All components configured successfully!" 10 70
    
    sleep 2
}

configure_cloud_init() {
  [[ -d /etc/cloud/cloud.cfg.d ]] || return
  if ! grep -q 'config: disabled' /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg 2>/dev/null; then
    echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    info "Disabled cloud-init network config"
  fi
}

configure_network() {
    if [[ "$OS_TYPE" =~ ^(ubuntu|debian)$ ]]; then
        info "Detected Debian/Ubuntu – applying Netplan config"

        if [[ -d "/sys/class/net/$BRIDGE/bridge" ]]; then
            info "Bridge $BRIDGE already exists, skipping creation..."
            exit 0
        fi

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
            dhcp4: false
            dhcp6: false
            parameters:
                stp: false
                forward-delay: 0
        EOF
        chmod 600 "$cfgfile"
        configure_cloud_init
        rm -f /etc/netplan/50-cloud-init.yaml
        netplan generate
        netplan apply
        info "Bridge '$BRIDGE' configured via Netplan"

    elif [[ "$OS_TYPE" =~ ^(rhel|centos|fedora|ol|oracle)$ ]]; then
        info "Detected RHEL/CentOS/Oracle – using NetworkManager"

        configure_cloud_init

        # Create bridge if missing
        if ! nmcli connection show "$BRIDGE" &>/dev/null; then
            nmcli connection add type bridge autoconnect yes con-name "$BRIDGE" ifname "$BRIDGE"
            info "Created bridge connection '$BRIDGE'"
        else
            info "Bridge connection '$BRIDGE' already exists"
        fi

        # Attach interface
        slave_name="${interface}-slave-$BRIDGE"
        if ! nmcli connection show "$slave_name" &>/dev/null; then
            nmcli connection add type ethernet slave-type bridge con-name "$slave_name" ifname "$interface" master "$BRIDGE"
            info "Created slave connection '$slave_name'"
        else
            info "Slave connection '$slave_name' already exists"
        fi

        # Set static config
        nmcli connection modify "$BRIDGE" \
            ipv4.method manual \
            ipv4.addresses "$hostipandsub" \
            ipv4.gateway "$gateway" \
            ipv4.dns "$DNS" \
            ipv6.method ignore \
            connection.autoconnect yes

        nmcli connection up "$slave_name" || true
        nmcli connection up "$BRIDGE" || true
        info "Bridge '$BRIDGE' up with interface '$interface' attached"
    else
      error "Unsupported distro: $OS_TYPE"
    fi
}

configure_prerequisites() {
    configure_network
    configure_cloudstack_repo
    update_system
}

# Main function
main() {
    # Clear screen and start logging
    clear
    log "Starting CloudStack installation script"
    
    # Check prerequisites
    check_root

    detect_os
    install_base_dependencies
    configure_prerequisites
    
    # Welcome message
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Welcome" \
           --msgbox "Welcome to the Apache CloudStack Installation Script\!\n\nThis script will help you install and configure CloudStack components on your system.\n\nPress OK to continue." 12 60
    
    # Main installation flow
    select_components
    install_components

    # Configure components
    configure_components
    
    # Optional zone deployment
    if select_zone_deployment; then
        deploy_zone
    fi
    
    # Show final summary
    show_final_summary
    
    log "CloudStack installation script completed successfully"
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