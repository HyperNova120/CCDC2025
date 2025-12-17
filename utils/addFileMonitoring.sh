#!/bin/sh

# Usage: ./addFileMonitoring.sh /path/to/file log_format
# Example: ./addFileMonitoring.sh /root/testCheck log

FILE_PATH=$1
LOG_FORMAT=$2

LOCALFILE="<localfile>
  <log_format>${LOG_FORMAT}</log_format>
  <location>${FILE_PATH}</location>
</localfile>"

# Only insert if not already present
if ! grep -q "${FILE_PATH}" /var/ossec/etc/ossec.conf; then
  # Insert before the FIRST closing </ossec_config>
  printf "%s\n" "$LOCALFILE" | sed -i "0,/<\/ossec_config>/r /dev/stdin" /var/ossec/etc/ossec.conf
  echo "✅ Added monitoring for ${FILE_PATH} before the first </ossec_config>"
else
  echo "ℹ️ Monitoring for ${FILE_PATH} already exists"
fi
