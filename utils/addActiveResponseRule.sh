#!/bin/sh

COMMAND_NAME=$1
EXE_NAME=$2
RULE=$3

COMMAND="<command>
  <name>${COMMAND_NAME}</name>
  <executable>${EXE_NAME}</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>"

ACTIVE_RESPONSE="<active-response>
  <command>${COMMAND_NAME}</command>
  <location>local</location>
  <rules_id>${RULE}</rules_id>
  <timeout>300</timeout>
</active-response>"

# Only insert if not already present
if ! grep -q "<name>${COMMAND_NAME}</name>" /var/ossec/etc/ossec.conf; then
  sed -i "/<\/ossec_config>/i ${COMMAND}\n\n${ACTIVE_RESPONSE}\n" /var/ossec/etc/ossec.conf
  echo "Added command and active-response for ${COMMAND_NAME} (rule ${RULE})"
else
  echo "Command ${COMMAND_NAME} already exists in ossec.conf"
fi
