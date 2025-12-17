#!/bin/sh

# Usage: ./add-monitor.sh /path/to/file.log log
# Arguments:
#   $1 = file path to monitor
#   $2 = log format (log, syslog, json, etc.)

FILE_PATH=$1
LOG_FORMAT=$2

LOCALFILE="<localfile>
  <log_format>${LOG_FORMAT}</log_format>
  <location>${FILE_PATH}</location>
</localfile>"

# Insert before closing </ossec_config>
if ! grep -q "${FILE_PATH}" /var/ossec/etc/ossec.conf; then
  sed -i "/<\/ossec_config>/i ${LOCALFILE}\n" /var/ossec/etc/ossec.conf
  echo "Added monitoring for ${FILE_PATH}"
else
  echo "Monitoring for ${FILE_PATH} already exists"
fi


