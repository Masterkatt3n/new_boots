#!/bin/bash

# Uninstall Pi-Hole
sudo pihole uninstall -y
sudo apt-get update -y

# Define variables
INTERFACE="enp0s3"   # Check so it matches
STATIC_IP="192.168.8.187/24"
GATEWAY="192.168.8.1"
PIHOLE_IP="192.168.8.187"
DHCP_START="192.168.8.100"
DHCP_END="192.168.8.200"

# 1. Update Netplan configuration
echo "Updating Netplan configuration..."

NETPLAN_CONFIG="/etc/netplan/01-netcfg.yaml"

sudo bash -c "cat > $NETPLAN_CONFIG" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - $STATIC_IP
      gateway4: $GATEWAY
      nameservers:
        addresses:
          - $PIHOLE_IP
          - 8.8.8.8
EOF

# Apply Netplan configuration
echo "Applying Netplan configuration..."
sudo netplan apply

# 2. Install Pi-Hole
echo "Installing Pi-Hole..."

# Download and run Pi-Hole installation script
curl -sSL https://install.pi-hole.net | bash

# 3. Configure Pi-Hole DHCP server
echo "Configuring Pi-Hole DHCP server..."

# Enable DHCP server and set range
# Note: This will use the default Pi-Hole settings file.
sudo pihole -a -d # This sets the Pi-Hole configuration. Adjust if needed.

# Set Pi-Hole password
sudo pihole -a -p password # Set a stronger later

# You may need to manually configure Pi-Hole via the web interface for DHCP settings
# Visit http://$PIHOLE_IP/admin and set DHCP range to $DHCP_START - $DHCP_END

echo "Setup complete! Please configure DHCP settings in Pi-Hole web interface."
