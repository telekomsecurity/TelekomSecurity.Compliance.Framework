#!/bin/bash

# -----------------------------------------------------------------------------
# Telekom Security - Script for Compliance Check
# SSH (3.04)
# Version: 0.1
# Date: 30-11-18
# Author: Markus Schumburg (security.automation@telekom.de)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Pre-Checks
# -----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  ERR="1"
  ERR_TXT="Script must run with root priviledges!"
fi

if [ "$ERR" == "1" ]; then
  clear
  echo -e "\r\n   -- Important! -----------------------------------------\r\n\r\n" >&2
  echo -e "      $ERR_TXT\r\n\r\n" >&2
  echo -e "   -------------------------------------------------------\r\n" >&2
  exit
fi

# -----------------------------------------------------------------------------
# Output File
# -----------------------------------------------------------------------------
DAY=`date +"%d%m%y"`
OUT_FILE="compliance-ssh-$DAY.log"
OUT_CSV="compliance-ssh-$DAY.csv"

exec >$OUT_FILE
echo -e "-----------------------------------------------------------------------------------"
echo " Telekom Security - Compliance Check - SSH (3.04)"
echo -e "-----------------------------------------------------------------------------------"
echo "   Host:" $HOSTNAME
echo "   Date:" `date +"%d-%m-%y"`
echo "------------------------------------------------------------------------------------"

exec 3>$OUT_CSV
echo ReqNo.,Requirement,Statement of Compliance>&3

if [ -z "$(ls -A /etc/sysctl.d/)" ]; then
  SYSCTL_CONF="/etc/sysctl.conf"
else
  SYSCTL_CONF="/etc/sysctl.conf /etc/sysctl.d/*"
fi

# -----------------------------------------------------------------------------
# Function
# -----------------------------------------------------------------------------
write_to_soc () {
  if [ $1 -eq 0 ]; then
    echo "Req $REQ_NR;$REQ_TXT;Compliant">&3;
  else
    if [ $2 -ne 0 ]; then
       echo "Req $REQ_NR;$REQ_TXT;Partly Compliant">&3;
     else
       echo "Req $REQ_NR;$REQ_TXT;Not Compliant">&3;
     fi
  fi
}

# -----------------------------------------------------------------------------
# Start Compliance Checks
# -----------------------------------------------------------------------------
REQ_NR=0

# Req 1:	The SSH protocol version 2 must be used.
let "REQ_NR++"
REQ_TXT="The SSH protocol version 2 must be used."
FAIL=0
PASS=0

# Test 1/x

write_to_soc $FAIL $PASS

# Req 2:	SSH moduli smaller than 2048 must not be used.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 3:	Only approved key exchange algorithms must be used.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 4:	Only approved ciphers algorithms must be used.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 5:	Only approved MAC algorithms must be used.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 6:	SSH logging must be enabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 7:	SSH LoginGraceTime must be set to one minute or less.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 8:	SSH MaxAuthTries must be set to 5 or less.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 9:	SSH root login must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 10:	SSH strict mode must be enabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 11:	SSH user authentication must be done with public keys.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 12:	SSH password authentication must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 13:	SSH IgnoreRhosts must be enabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 14:	SSH HostbasedAuthentication must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 15:	The usage of the SSH service must be restricted to dedicated groups
# or users.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 16:	The SSH Idle Timeout Interval must be configured to an adequate time.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 17:	SSH tunnel devices must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 18:	SSH TCP port forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 19:	SSH agent forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 20:	SSH gateway ports must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 21:	SSH X11 forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 22:	SSH PermitUserEnvironment must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 23:	SSH PermitEmptyPasswords must be disabled.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 24:	If SFTP is activated, internal server of OpenSSH must be used.
let "REQ_NR++"
REQ_TXT="  "
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS
