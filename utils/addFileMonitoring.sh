#!/bin/sh

# Usage: ./addFileMonitoring.sh /path/to/file log_format
# Example: ./addFileMonitoring.sh /root/testCheck log

FILE_PATH=$1
LOG_FORMAT=$2

LOCALFILE="<localfile>
  <log_format>${LOG_FORMAT}</log_format>
  <location>${FILE_PATH}</location>
</localfile>"

# Check if file is already being monitored
if ! grep -q "${FILE_PATH}" /var/ossec/etc/ossec.conf; then
  # Safely insert block before closing </ossec_config>
  printf "%s\n" "$LOCALFILE" | sed -i "/<\/ossec_config>/r /dev/stdin" /var/ossec/etc/ossec.conf
  echo "✅ Added monitoring for ${FILE_PATH}"
else
  echo "ℹ️ Monitoring for ${FILE_PATH} already exists"
fi
