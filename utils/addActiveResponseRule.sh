#!/bin/sh

COMMAND_NAME=$1
EXE_NAME=$2
RULE=$3

COMMAND="\
<command>\n\
  <name>${COMMAND_NAME}</name>\n\
  <executable>${EXE_NAME}</executable>\n\
  <timeout_allowed>yes</timeout_allowed>\n\
</command>"

ACTIVE_RESPONSE="\
<active-response>\n\
  <command>${COMMAND_NAME}</command>\n\
  <location>local</location>\n\
  <rules_id>${RULE}</rules_id>\n\
  <timeout>300</timeout>\n\
</active-response>"

#sed -i '/<!--/{N;N;s/<!--\n  <active-response>/  <active-response>/;s/  <\/active-response>\n  -->/  <\/active-response>/}' /var/ossec/etc/ossec.conf


sed -i "/<\/ossec_config>/i ${COMMAND}\n\n${ACTIVE_RESPONSE}\n" /var/ossec/etc/ossec.conf