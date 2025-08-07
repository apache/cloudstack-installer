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

# NOTE: This is work-in-progress

set -e
set -o noglob

CS_VERSION=4.20
INTERFACE=
BRIDGE=cloudbr0
HOST_IP=
GATEWAY=
DNS="9.9.9.9, 1.1.1.1"

# --- helper functions for logs ---
info()
{
    echo '[INFO] ' "$@"
}
warn()
{
    echo '[WARN] ' "$@" >&2
}
fatal()
{
    echo '[ERROR] ' "$@" >&2
    exit 1
}

### Intro ###

echo "
░█████╗░░█████╗░██╗░░██╗░░░██╗███╗░░██╗
██╔══██╗██╔══██╗██║░██╔╝░░░██║████╗░██║
██║░░╚═╝╚█████╔╝█████═╝░░░░██║██╔██╗██║
██║░░██╗██╔══██╗██╔═██╗░░░░██║██║╚████║
╚█████╔╝╚█████╔╝██║░╚██╗██╗██║██║░╚███║
░╚════╝░░╚════╝░╚═╝░░╚═╝╚═╝╚═╝╚═╝░░╚══╝
Welcome to the CloudStack Installer
"
info "Installing Apache CloudStack All-In-One-Box"
info "NOTE: this works only on Ubuntu 22.04 (tested), and run as 'root' user!"

if [[ $EUID -ne 0 ]]; then
   fatal "This script must be run as root"
   exit 1
fi

warn "Work in progress, try again while this is being hacked"

### Setup Prerequisites ###
info "Installing dependencies"
apt-get update
apt-get install -y openssh-server sudo wget jq htop tar nmap bridge-utils

# FIXME: check for host spec (min 4-8G RAM?) /dev/kvm and

### Setup Bridge ###

setup_bridge() {
  if brctl show $BRIDGE > /dev/null 2>&1; then
    info "Bridge $BRIDGE already exists, skipping create..."
    return
  fi

  interface=$(find /sys/class/net -type l -not -lname '*virtual*' -printf '%f\n' | sort | head -1)
  gateway=$(ip route show 0.0.0.0/0 dev $interface | cut -d ' ' -f 3)
  hostipandsub=$(ip -4 -br addr show ens192 | awk '{ print $3; }' )
  info "Setting up bridge on $interface which has IP $hostip and gateway $gateway"

  cat << EOF > /etc/netplan/01-netcfg.yaml
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
      addresses: [$hostipandsub]
      routes:
        - to: default
          via: $gateway
      nameservers:
        addresses: [$DNS]
      interfaces: [$interface]
      dhcp4: false
      dhcp6: false
      parameters:
        stp: false
        forward-delay: 0
EOF

  # FIX netplan complaining about permissions
  chmod 600 /etc/netplan/01-netcfg.yaml

  info "Disabling cloud-init netplan config"
  rm -f /etc/netplan/50-cloud-init.yaml
  if [[ ! -f "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg" && ! -f "/etc/cloud/cloud.cfg.d/99_disable-network-config.cfg" ]]; then
    echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
  fi

  # FIXME workaround for VMware tools generated network config
  if [[ -f "/etc/netplan/99-netcfg-vmware.yaml" ]]; then
    mv /etc/netplan/99-netcfg-vmware.yaml /etc/netplan/99-netcfg-vmware.yaml.bak
  fi

  netplan generate
  netplan apply

  export INTERFACE="$interface"
}

### Setup CloudStack Packages ###

configure_repo() {
  info "Configuring CloudStack $CS_VERSION repo"
  mkdir -p /etc/apt/keyrings
  wget -O- https://download.cloudstack.org/release.asc 2>/dev/null | gpg --dearmor | sudo tee /etc/apt/keyrings/cloudstack.gpg > /dev/null
  # NOTE: debian-based distro packages are now release agnostic
  echo deb [signed-by=/etc/apt/keyrings/cloudstack.gpg] https://download.cloudstack.org/ubuntu noble $CS_VERSION > /etc/apt/sources.list.d/cloudstack.list
  apt-get update
}

install_packages() {
  info "Installing CloudStack $CS_VERSION, MySQL and NFS server"
  if dpkg -l | grep cloudstack-management > /dev/null; then
    warn "CloudStack packages seem to be already installed, skipping CloudStack packages installation"
    apt-get install -y mysql-server nfs-kernel-server quota qemu-kvm
  else
    apt-get install -y cloudstack-management cloudstack-usage mysql-server nfs-kernel-server quota qemu-kvm cloudstack-agent
    systemctl daemon-reload
    systemctl stop cloudstack-management cloudstack-usage cloudstack-agent
  fi
}

### Configure Methods ###

configure_mysql() {
  info "Configuring MySQL Server: $(mysql -V)"
  if [[ -f "/etc/mysql/mysql.conf.d/cloudstack.cnf" ]]; then
    info "Skipping MySQL configuration setup, already done"
    return
  fi

  sqlmode="$(mysql -B -e "show global variables like 'sql_mode'" | grep sql_mode | awk '{ print $2; }' | sed -e 's/ONLY_FULL_GROUP_BY,//')"

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

  systemctl restart mysql
}

configure_storage() {
  info "Configuring NFS Storage"
  if grep "^/export " /etc/exports > /dev/null; then
    info "Skipping NFS Storage configuration setup, already done"
    return
  fi

  echo "/export  *(rw,async,no_root_squash,no_subtree_check)" >> /etc/exports
  mkdir -p /export/primary /export/secondary
  exportfs -a

  sed -i -e 's/^RPCMOUNTDOPTS="--manage-gids"$/RPCMOUNTDOPTS="-p 892 --manage-gids"/g' /etc/default/nfs-kernel-server
  sed -i -e 's/^STATDOPTS=$/STATDOPTS="--port 662 --outgoing-port 2020"/g' /etc/default/nfs-common
  if ! grep 'NEED_STATD=yes' /etc/default/nfs-common > /dev/null; then
    echo "NEED_STATD=yes" >> /etc/default/nfs-common
  fi
  sed -i -e 's/^RPCRQUOTADOPTS=$/RPCRQUOTADOPTS="-p 875"/g' /etc/default/quota

  service nfs-kernel-server restart
  info "NFS exports created: $(exportfs)"
}

configure_host() {
  info "Configuring KVM on this host"
  sed -i -e 's/\#vnc_listen.*$/vnc_listen = "0.0.0.0"/g' /etc/libvirt/qemu.conf
  if ! grep '^LIBVIRTD_ARGS="--listen"' /etc/default/libvirtd > /dev/null; then
    echo LIBVIRTD_ARGS=\"--listen\" >> /etc/default/libvirtd
  fi
  if ! grep 'listen_tcp=1' /etc/libvirt/libvirtd.conf > /dev/null; then
    echo 'listen_tcp=1' >> /etc/libvirt/libvirtd.conf
    echo 'listen_tls=0' >> /etc/libvirt/libvirtd.conf
    echo 'tcp_port = "16509"' >> /etc/libvirt/libvirtd.conf
    echo 'mdns_adv = 0' >> /etc/libvirt/libvirtd.conf
    echo 'auth_tcp = "none"' >> /etc/libvirt/libvirtd.conf
    systemctl mask libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket
    systemctl restart libvirtd

    # Ubuntu: disable apparmor
    ln -sf /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/
    ln -sf /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper /etc/apparmor.d/disable/
    apparmor_parser -R /etc/apparmor.d/usr.sbin.libvirtd
    apparmor_parser -R /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper
  fi

  if ! kvm-ok; then
    warn "KVM may not work on your host"
  else
    info "KVM host configured"
    virsh nodeinfo
  fi
}

deploy_cloudstack() {
  if systemctl is-active cloudstack-management > /dev/null; then
    info "CloudStack Management Server is already running, skipping DB deployment"
    return
  fi
  info "Deploying CloudStack Database"
  cloudstack-setup-databases cloud:cloud@localhost --deploy-as=root: #-i <cloudbr0 IP here>
  info "Deploying CloudStack Management Server"
  cloudstack-setup-management
}

install_completed() {
  info "CloudStack installation completed!"
  info "Access CloudStack UI at: http://$HOST_IP:8080/client with username 'admin' and password 'password'"
  echo
}

deploy_zone() {
  info "Deploying CloudStack Zone"
  wget -q https://github.com/apache/cloudstack-cloudmonkey/releases/download/6.4.0/cmk.linux.x86-64 -O /usr/bin/cmk > /dev/null
  chmod +x /usr/bin/cmk
  cmk set username admin
  cmk set password password
  cmk set display json
  cmk set asyncblock true
  cmk sync

  info "Starting Zone deployment"

  zone_id=$(cmk create zone dns1=8.8.8.8 internaldns1=$GATEWAY name=AdvZone1 networktype=Advanced | jq '.zone.id')
  info "Created CloudStack Zone with ID $zone_id"

  phy_id=$(cmk create physicalnetwork name=cloudbr0 zoneid=$zone_id | jq '.physicalnetwork.id')
  cmk add traffictype traffictype=Management physicalnetworkid=$phy_id
  cmk add traffictype traffictype=Public physicalnetworkid=$phy_id
  cmk add traffictype traffictype=Guest physicalnetworkid=$phy_id
  cmk update physicalnetwork state=Enabled id=$phy_id
  info "Created CloudStack Physical Network in zone with ID $phy_id"

  nsp_id=$(cmk list networkserviceproviders name=VirtualRouter physicalnetworkid=$phy_id | jq -r '.networkserviceprovider[0].id')
  vre_id=$(cmk list virtualrouterelements nspid=$nsp_id | jq -r '.virtualrouterelement[0].id')
  cmk configure virtualrouterelement enabled=true id=$vre_id
  cmk update networkserviceprovider state=Enabled id=$nsp_id
  info "Configured VR Network Service Provider for zone"

  nsp_id=$(cmk list networkserviceproviders name=Internallbvm physicalnetworkid=$phy_id | jq -r '.networkserviceprovider[0].id')
  ilbvm_id=$(cmk list internalloadbalancerelements nspid=$nsp_id | jq -r '.internalloadbalancerelement[0].id')
  cmk configure internalloadbalancerelement enabled=true id=$ilbvm_id
  cmk update networkserviceprovider state=Enabled id=$nsp_id
  info "Configured ILBVM Network Service Provider for zone"

  nsp_id=$(cmk list networkserviceproviders name=VpcVirtualRouter physicalnetworkid=$phy_id | jq -r '.networkserviceprovider[0].id')
  vpcvre_id=$(cmk list virtualrouterelements nspid=$nsp_id | jq -r '.virtualrouterelement[0].id')
  cmk configure virtualrouterelement enabled=true id=$vpcvre_id
  cmk update networkserviceprovider state=Enabled id=$nsp_id
  info "Configured VPC VR Network Service Provider for zone"

  # TODO: use nmap to scan for free IPs in the range
  # sudo nmap -v -sn -n 192.168.1.0/24 -oG - | awk '/Status: Down/{print $2}'
  # FIXME: prompt for IP range?
  RANGE=$(echo $GATEWAY | sed 's/\..$//g')
  pod_start="$RANGE.200"
  pod_end="$RANGE.220"
  pod_gw=$GATEWAY
  pod_mask=255.255.255.0
  ip_start="$RANGE.221"
  ip_end="$RANGE.240"
  ip_gw=$GATEWAY
  ip_mask=255.255.255.0

  pod_id=$(cmk create pod name=AdvPod1 zoneid=$zone_id gateway=$pod_gw netmask=$pod_mask startip=$pod_start endip=$pod_end | jq '.pod.id')

  cmk create vlaniprange zoneid=$zone_id vlan=untagged gateway=$ip_gw netmask=$ip_mask startip=$ip_start endip=$ip_end forvirtualnetwork=true

  cmk update physicalnetwork id=$phy_id vlan=100-200

  cluster_id=$(cmk add cluster zoneid=$zone_id hypervisor=KVM clustertype=CloudManaged podid=$pod_id clustername=Cluster1 | jq '.cluster[0].id')

  # Add by CloudStack Management Server's public key
  mkdir -p /root/.ssh
  cat /var/lib/cloudstack/management/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
  cmk add host zoneid=$zone_id podid=$pod_id clusterid=$cluster_id clustertype=CloudManaged hypervisor=KVM username=root password= url=http://$HOST_IP

  cmk create storagepool zoneid=$zone_id podid=$pod_id clusterid=$cluster_id name=Primary-StoragePool1 scope=zone hypervisor=KVM url=nfs://$HOST_IP/export/primary

  cmk add imagestore provider=NFS zoneid=$zone_id name=Secondary-StoragePool1 url=nfs://$HOST_IP/export/secondary

  cmk update zone allocationstate=Enabled id=$zone_id
}

display_url() {
echo "
█████████████████████████████████████████████████████████████
█─▄▄▄─█▄─▄███─▄▄─█▄─██─▄█▄─▄▄▀█─▄▄▄▄█─▄─▄─██▀▄─██─▄▄▄─█▄─█─▄█
█─███▀██─██▀█─██─██─██─███─██─█▄▄▄▄─███─████─▀─██─███▀██─▄▀██
▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀▄▄▄▄▀▀▄▄▄▄▀▀▄▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

URL: http://$HOST_IP:8080/client
User: admin
Password: password
"
}

### Installer: Setup ###

setup_bridge
export HOST_IP=$(ip -4 -br addr show $BRIDGE | awk '{ print $3; }' | sed -e 's/\/[0-9]\+//')
export GATEWAY=$(ip route show 0.0.0.0/0 dev $BRIDGE | cut -d ' '  -f 3)
info "Bridge $BRIDGE is setup with IP $HOST_IP"

configure_repo
install_packages
configure_mysql
configure_storage
configure_host
deploy_cloudstack

install_completed

### Installer: Deploy Zone ###

# FIXME: configuration global setting & restart mgmt server

deploy_zone

# FIXME: register Ubuntu template & register ssh-key of this host, configure CKS etc.

### Installer: Finish ###

display_url
