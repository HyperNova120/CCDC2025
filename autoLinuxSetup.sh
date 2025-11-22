#!/bin/bash

# Usage: ./run_all_remote.sh <user> <host> <password>
# Example: ./run_all_remote.sh ubuntu 192.168.1.50 mypassword
set -e # exit upon command fail



#USER="$1"
#PASS="$2"

SCRIPT_DIR="./runScripts" # scripts to run
SETUP_DIR="./initScripts" # scripts to ensure needed commands exist
#if [[ -z "$USER" || -z "$PASS" ]]; then
#  echo "Usage: $0 <user> <password>"
#  exit 1
#fi

if [[ ! -d "$SCRIPT_DIR" ]]; then
  echo "Directory $SCRIPT_DIR does not exist."
  exit 1
fi

if [[ ! -d "$SETUP_DIR" ]]; then
  echo "Directory $SETUP_DIR does not exist."
  exit 1
fi

for script in "$SETUP_DIR"/*.sh; do
  if [[ -f "$script" ]]; then
    echo ">>> Running $script on $HOST ..."
    log="${script}.log"
    if ! bash "$script" >"$log" 2>&1; then
      echo "Error running $script. Aborting."
      exit 1
    fi
    echo "Output saved to $log"
  fi
done




for script in "$SCRIPT_DIR"/*.sh; do
  if [[ -f "$script" ]]; then
    echo ">>> Running $script on $HOST ..."
    log="${script}.log"
    if ! bash "$script" >"$log" 2>&1; then
      echo "Error running $script. Aborting."
      exit 1
    fi
    echo "Output saved to $log"
  fi
done

