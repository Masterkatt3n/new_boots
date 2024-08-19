#!/bin/bash

# Uninstall Pi-Hole
sudo pihole uninstall -y
sudo apt-get update && sudo apt-get upgrade -y

#!/bin/bash

# Define variables
PIHOLE_IP="192.168.8.187"
GATEWAY="192.168.8.1"
NAMESERVERS="192.168.8.1, 1.1.1.1"
INTERFACE="enp0s3" # Check if it match

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

# Install Pi-Hole
curl -sSL https://install.pi-hole.net | bash

# Note to user:
echo "Pi-Hole installation complete. Please configure your router's DNS settings to point to $PIHOLE_IP if you want Pi-Hole to manage DNS queries."

echo "Pi-Hole is now running with a static IP address: $PIHOLE_IP"
echo "Router DHCP is still managing IP addresses for the network."
