#!/bin/sh

# Usage: ./setupFIM.sh /path/to/file_or_directory
# Example: ./setupFIM.sh /etc/passwd

TARGET_PATH=$1

if [ -z "$TARGET_PATH" ]; then
  echo "❌ Error: You must provide a file or directory path."
  echo "Usage: $0 /path/to/file_or_directory"
  exit 1
fi

SYSBLOCK="<syscheck>
  <directories realtime=\"yes\">${TARGET_PATH}</directories>
</syscheck>"

# Check if already monitored
if grep -q "${TARGET_PATH}" /var/ossec/etc/ossec.conf; then
  echo "ℹ️ ${TARGET_PATH} is already being monitored by Wazuh."
else
  # Insert before the FIRST closing </ossec_config>
  printf "%s\n" "$SYSBLOCK" | sed -i "0,/<\/ossec_config>/r /dev/stdin" /var/ossec/etc/ossec.conf
  echo "✅ Added FIM monitoring for ${TARGET_PATH}"
fi

# Restart agent to apply changes
systemctl restart wazuh-agent
echo "🔄 Wazuh agent restarted. Monitoring is now active."
