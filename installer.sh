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
    case "$OS_TYPE" in
        ubuntu|debian)
            {
                echo "Configuring CloudStack repository..."
                echo "Adding CloudStack's signing key..."
                if curl -fsSL https://download.cloudstack.org/release.asc | gpg --dearmor | tee /etc/apt/keyrings/cloudstack.gpg > /dev/null; then
                    echo "CloudStack signing key added successfully."
                else
                    echo "ERROR: Failed to add CloudStack signing key."
                    exit 1
                fi
                
                echo "Adding CloudStack repository..."
                if echo "deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] https://download.cloudstack.org/ubuntu noble $CS_VERSION" | tee /etc/apt/sources.list.d/cloudstack.list > /dev/null; then
                    echo "CloudStack repository added successfully."
                else
                    echo "ERROR: Failed to add CloudStack repository."
                    exit 1
                fi
                
                echo "Updating package list..."
                if apt-get update > /dev/null 2>&1; then
                    echo "Package list updated successfully."
                else
                    echo "ERROR: Failed to update package list."
                    exit 1
                fi
                echo "Repository configuration completed."
            } | dialog --backtitle "$SCRIPT_NAME" \
                       --title "Repository Configuration" \
                       --progressbox "Configuring CloudStack repository..." 15 70
            ;;
            
        rhel|centos|fedora|rocky|alma)
            {
                echo "Configuring CloudStack repository..."
                echo "Adding CloudStack's signing key..."
                if curl -fsSL https://download.cloudstack.org/release.asc | tee /etc/pki/rpm-gpg/CloudStack.asc > /dev/null; then
                    echo "CloudStack signing key added successfully."
                else
                    echo "ERROR: Failed to add CloudStack signing key."
                    exit 1
                fi
                
                echo "Adding CloudStack repository..."
                {
                    echo "[cloudstack]"
                    echo "name=CloudStack Repo"
                    echo "baseurl=https://download.cloudstack.org/centos/$OS_VERSION"
                    echo "enabled=1"
                    echo "gpgcheck=1"
                    echo "gpgkey=https://download.cloudstack.org/release.asc"
                } | tee /etc/yum.repos.d/cloudstack.repo > /dev/null
                
                if [ $? -eq 0 ]; then
                    echo "CloudStack repository added successfully."
                else
                    echo "ERROR: Failed to add CloudStack repository."
                    exit 1
                fi
                
                echo "Updating system packages..."
                if dnf update -y > /dev/null 2>&1; then
                    echo "System packages updated successfully."
                else
                    echo "ERROR: Failed to update system packages."
                    exit 1
                fi
                echo "Repository configuration completed."
            } | dialog --backtitle "$SCRIPT_NAME" \
                       --title "Repository Configuration" \
                       --progressbox "Configuring CloudStack repository..." 15 70
            ;;
            
        *)
            dialog --msgbox "Unsupported OS: $OS_TYPE" 6 50
            exit 1
            ;;
    esac
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

    # Deploy CloudStack database
    dialog --infobox "Deploying CloudStack Database..." 5 50
    cloudstack-setup-databases cloud:cloud@localhost --deploy-as=root: -i "$cloudbr0_ip"

    # Deploy management server
    dialog --infobox "Deploying CloudStack Management Server..." 5 50
    cloudstack-setup-management

    dialog --title "Success" --msgbox "CloudStack Management Server has been configured." 7 60
}



configure_usage_server() {
    echo "config usage server"
}

configure_kvm_agent() {
    dialog --backtitle "$SCRIPT_NAME" \
           --title "KVM Host Configuration" \
           --infobox "Starting KVM host configuration..." 5 50
    sleep 2

    # Configure VNC
    {
        echo "10"
        echo "# Configuring VNC access..."
        if sed -i -e 's/\#vnc_listen.*$/vnc_listen = "0.0.0.0"/g' /etc/libvirt/qemu.conf; then
            echo "VNC configuration successful"
        else
            echo "Failed to configure VNC"
            exit 1
        fi

        echo "25"
        echo "# Configuring libvirtd..."
        # Configure libvirtd to listen
        if ! grep '^LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd > /dev/null; then
            echo 'LIBVIRTD_ARGS="--listen"' >> /etc/default/libvirtd
        fi

        echo "40"
        echo "# Setting up libvirt TCP access..."
        cat >> /etc/libvirt/libvirtd.conf <<EOF
listen_tcp = 1
listen_tls = 0
tcp_port = "16509"
mdns_adv = 0
auth_tcp = "none"
EOF

        echo "60"
        echo "# Configuring libvirt sockets..."
        systemctl mask libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket
        systemctl restart libvirtd

        echo "75"
        echo "# Configuring security policies..."
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
            rhel|centos|rocky|oracle)
                # SELinux configuration if needed
                setsebool -P virt_use_nfs 1
                ;;
        esac

        echo "85"
        echo "# Configuring firewall..."
        ports=(
            "22/tcp"           # SSH
            "1798/tcp"         # CloudStack Management Server
            "16509/tcp"        # Libvirt
            "16514/tcp"        # Libvirt
            "5900:6100/tcp"    # VNC
            "49152:49216/tcp"  # Live Migration
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
            rhel|centos|rocky|oracle)
                if command -v firewall-cmd >/dev/null; then
                    for port in "${ports[@]}"; do
                        firewall-cmd --permanent --add-port="$port"
                    done
                    firewall-cmd --reload
                fi
                ;;
        esac

        echo "100"
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

show_final_summary() {
    echo "Summary mgmt server"
}

deploy_zone() {
    echo "Deploying zone"
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

    # First configure core dependencies if selected
    {
        # 1. Configure MySQL (if selected)
        if is_component_selected "mysql"; then
            current_step=$((current_step + 1))
            echo "$((current_step * 100 / total_steps))"
            echo "# Configuring MySQL Server..."
            configure_mysql
        fi

        # 2. Configure NFS (if selected)
        if is_component_selected "nfs"; then
            current_step=$((current_step + 1))
            echo "$((current_step * 100 / total_steps))"
            echo "# Configuring NFS Server..."
            configure_nfs_server
        fi

        # 3. Configure Management Server (if selected)
        if is_component_selected "management"; then
            # Check if dependencies are configured
            if is_component_selected "mysql" && ! systemctl is-active --quiet mysql; then
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "Error" \
                       --msgbox "MySQL must be running before configuring Management Server" 6 60
                return 1
            fi
            
            current_step=$((current_step + 1))
            echo "$((current_step * 100 / total_steps))"
            echo "# Configuring Management Server..."
            configure_management_server
        fi

        # 4. Configure KVM Agent (if selected)
        if is_component_selected "kvm"; then
            # Check if management server is configured when both are selected
            if is_component_selected "management" && ! systemctl is-active --quiet cloudstack-management; then
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "Error" \
                       --msgbox "Management Server must be running before configuring KVM Agent" 6 60
                return 1
            fi
            
            current_step=$((current_step + 1))
            echo "$((current_step * 100 / total_steps))"
            echo "# Configuring KVM Agent..."
            configure_kvm_agent
        fi

        # 5. Configure Usage Server (if selected)
        if is_component_selected "usage"; then
            # Check if management server is configured
            if is_component_selected "management" && ! systemctl is-active --quiet cloudstack-management; then
                dialog --backtitle "$SCRIPT_NAME" \
                       --title "Error" \
                       --msgbox "Management Server must be running before configuring Usage Server" 6 60
                return 1
            fi
            
            current_step=$((current_step + 1))
            echo "$((current_step * 100 / total_steps))"
            echo "# Configuring Usage Server..."
            configure_usage_server
        fi

        # Final progress update
        echo "100"
        echo "# Configuration complete!"
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Configuring Components" \
               --gauge "Setting up CloudStack components..." 10 70 0

    # Give user time to read the final message
    sleep 2

    # Show configuration summary
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Configuration Summary" \
           --msgbox "Configured components in order:\n\n$(
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " mysql " ]] && echo "✓ MySQL Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " nfs " ]] && echo "✓ NFS Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " management " ]] && echo "✓ Management Server\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " kvm " ]] && echo "✓ KVM Agent\n"
                [[ " ${SELECTED_COMPONENTS[@]} " =~ " usage " ]] && echo "✓ Usage Server\n"
           )" 15 60
}

configure_cloud_init() {
  [[ -d /etc/cloud/cloud.cfg.d ]] || return
  if ! grep -q 'config: disabled' /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg 2>/dev/null; then
    echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    info_msg "Disabled cloud-init network config"
  fi
}

configure_network() {
    if [[ "$OS_TYPE" =~ ^(ubuntu|debian)$ ]]; then
        info_msg "Detected Debian/Ubuntu – applying Netplan config"

        if [[ -d "/sys/class/net/$BRIDGE/bridge" ]]; then
            info_msg "Bridge $BRIDGE already exists, skipping creation..."
            return
        fi

        # Gather interface, IP, gateway
        interface=$(ip -o link show | awk -F': ' '/state UP/ && $2!~/^lo/ {print $2; exit}')
        [[ -n "$interface" ]] || error "No active non-loopback interface found."

        hostipandsub=$(ip -4 addr show dev "$interface" | awk '/inet / {print $2; exit}')
        gateway=$(ip route show default | awk '/default/ {print $3; exit}')

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
        info_msg "Bridge '$BRIDGE' configured via Netplan"

    elif [[ "$OS_TYPE" =~ ^(rhel|centos|fedora|ol|oracle)$ ]]; then
        info_msg "Detected RHEL/CentOS/Oracle – using NetworkManager"

        configure_cloud_init

        # Create bridge if missing
        if ! nmcli connection show "$BRIDGE" &>/dev/null; then
            nmcli connection add type bridge autoconnect yes con-name "$BRIDGE" ifname "$BRIDGE"
            info_msg "Created bridge connection '$BRIDGE'"
        else
            info_msg "Bridge connection '$BRIDGE' already exists"
        fi

        # Attach interface
        slave_name="${interface}-slave-$BRIDGE"
        if ! nmcli connection show "$slave_name" &>/dev/null; then
            nmcli connection add type ethernet slave-type bridge con-name "$slave_name" ifname "$interface" master "$BRIDGE"
            info_msg "Created slave connection '$slave_name'"
        else
            info_msg "Slave connection '$slave_name' already exists"
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
        info_msg "Bridge '$BRIDGE' up with interface '$interface' attached"
    else
      error "Unsupported distro: $OS_TYPE"
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
            if systemctl is-active --quiet mysql; then
                if [[ -f "/etc/mysql/mysql.conf.d/cloudstack.cnf" ]]; then
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
        if [[ " ${SELECTED_COMPONENTS[@]} " =~ " kvm " ]]; then
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
    } | dialog --backtitle "$SCRIPT_NAME" \
               --title "Component Validation" \
               --gauge "Validating installed components..." 10 70 0

    # Show validation results with colors
    if $status_ok; then
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Validation Summary" \
               --colors \
               --msgbox "\Z2✓ All components are properly configured!\n\n\ZnComponent Status:\n\n$summary" 20 70
    else
        dialog --backtitle "$SCRIPT_NAME" \
               --title "Validation Summary" \
               --colors \
               --msgbox "\Z1⚠ Some components need attention!\n\n\ZnComponent Status:\n\n$summary" 20 70
    fi

    return $status_ok
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