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
    install_package "nfs-kernel-server"
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
                configure_mysql_server
                ;;
            nfs)
                configure_nfs_server
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

# Main function
main() {
    # Clear screen and start logging
    clear
    log "Starting CloudStack installation script"
    
    # Check prerequisites
    check_root

    detect_os
    install_base_dependencies
    
    # Welcome message
    dialog --backtitle "$SCRIPT_NAME" \
           --title "Welcome" \
           --msgbox "Welcome to the Apache CloudStack Installation Script\!\n\nThis script will help you install and configure CloudStack components on your system.\n\nPress OK to continue." 12 60
    
    # Main installation flow
    configure_cloudstack_repo
    select_components
    install_components

    # Configure components

    
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