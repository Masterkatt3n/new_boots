#!/bin/bash

# Uninstall Pi-Hole
sudo pihole uninstall -y
sudo apt-get update && sudo apt-get upgrade -y

# Define variables
PIHOLE_IP="192.168.8.187"
GATEWAY="192.168.8.1"
NAMESERVERS="192.168.8.1, 1.1.1.1"
INTERFACE="enp0s3"   # Check so it matches
DHCP_RANGE_START="192.168.8.100"
DHCP_RANGE_END="192.168.8.200"
DHCP_LEASE_TIME="24h"

# Create Netplan configuration file
sudo bash -c "cat > /etc/netplan/99_config.yaml" <<EOL
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - $PIHOLE_IP/24
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
          addresses: [$NAMESERVERS]
EOL

# Apply Netplan configuration
sudo netplan apply

# Update and upgrade the system
sudo apt-get update && sudo apt-get upgrade -y

# Install Pi-Hole
curl -sSL https://install.pi-hole.net | bash

# Configure Pi-Hole to manage DHCP
sudo bash -c "cat > /etc/dnsmasq.d/02-pihole-dhcp.conf" <<EOL
# Pi-Hole DHCP configuration
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE_TIME
dhcp-option=option:router,$GATEWAY
EOL

# Restart Pi-Hole to apply DHCP configuration
sudo pihole restartdns

# Enable DHCP server in Pi-Hole settings
pihole -a enabledhcp $DHCP_RANGE_START $DHCP_RANGE_END $GATEWAY

echo "Pi-Hole DHCP configuration complete. Please disable DHCP on your router to allow Pi-Hole to manage DHCP."
echo "Pi-Hole is now running with a static IP address: $PIHOLE_IP and managing DHCP from $DHCP_RANGE_START to $DHCP_RANGE_END."
