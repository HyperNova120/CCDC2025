#!/bin/bash

USER="$1"
PASS="$2"

if [[ -z "$USER" || -z "$PASS" ]]; then
  echo "Usage: $0 <username> <password>"
  exit 1
fi

# Create the user with a home directory
sudo useradd -m -s /bin/bash "$USER"

# Set the user's password
echo "$USER:$PASS" | sudo chpasswd

# Detect sudo group
if getent group sudo > /dev/null; then
  sudo usermod -aG sudo "$USER"
elif getent group wheel > /dev/null; then
  sudo usermod -aG wheel "$USER"
else
  echo "No sudo/wheel group found. Please configure /etc/sudoers manually."
fi

echo "User '$USER' created, password set, and added to sudo group if available."
