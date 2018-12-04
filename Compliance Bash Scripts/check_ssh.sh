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
SSH_CONFIG="/etc/ssh/sshd_config"
PROTOCOL_VERSION=2
MODULI_MIN=2048
KEYEX1="curve25519-sha256 @libssh.org"
KEYEX2="diffie-hellman-group-exchange-sha256"
KEYEX3="ecdh-sha2-nistp521"
KEYEX4="ecdh-sha2-nistp384"
KEYEX5="ecdh-sha2-nistp256"
CIPHER1="chacha20-poly1305@openssh.com"
CIPHER2="aes256-gcm@openssh.com"
CIPHER3="aes128-gcm@openssh.com"
CIPHER4="aes256-ctr"
CIPHER5="aes192-ctr"
CIPHER6="aes128-ctr"
MAC1="hmac-sha2-512-etm@openssh.com"
MAC2="hmac-sha2-256-etm@openssh.com"
MAC3="hmac-ripemd160-etm@openssh.com"
MAC4="umac-128-etm@openssh.com"
MAC5="hmac-sha2-512"
MAC6="hmac-sha2-256"
MAC7="hmac-ripemd160"
LOG_LEVEL=INFO
LOGIN_GRACE_TIME=60
MAX_AUTH_TRIES=5
PERMIT_ROOT=no
STRICT_MODES=yes
PUB_KEY_AUTH=yes
PASS_AUTH=no
IGNORE_RHOSTS=yes
HOST_BASED_AUTH=no

# -----------------------------------------------------------------------------
# Pre-Checks
# -----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  ERR="1"
  ERR_TXT="Script must run with root priviledges!"
fi

if [ -f /etc/os-release ]; then
   OS=`awk -F\" '/^NAME=/ {print $2}' /etc/os-release | awk '{print $1}'`
   if [ "$OS" == "Amazon" ] || [ "$OS" == "Red" ] || [ "$OS" == "CentOS" ]; then
      PACKAGE="rpm -qa";
      OS="RedHat";
   elif [ "$OS" == "Debian" ] ||  [ "$OS" == "Ubuntu" ]; then
      PACKAGE="dpkg -l";
      OS="Ubuntu";
   elif [ "$OS" == "SLES" ]; then
     PACKAGE="rpm -qa";
     OS="Suse";
   else
     ERR="1"
     ERR_TXT="Linux version $OS not supported with this script!"
   fi
else
  ERR="1"
  ERR_TXT="Linux version could not be identified!"
fi

# Check OpenSSH is installed and version

if [ -z "$($PACKAGE | grep -ow openssh-server)" ]; then
  ERR=1
  ERR_TXT="OpenSSH not found on system!"
else
  SSH_VER=$( 2>&1 ssh -V | awk -F_ '{print $2}' | egrep -o "^.{3}")
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
echo "ReqNo.;Requirement;Statement of Compliance">&3

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

# Req 1: The SSH protocol version 2 must be used.
let "REQ_NR++"
REQ_TXT="The SSH protocol version 2 must be used."
FAIL=0
PASS=0

# Test 1/1
if [ $(echo "if (${PROTOCOL_VERSION} >= 7.4) 1 else 0" | bc) -eq 1 ] ; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check ssh protocol version: PASSED";
else
  if [ $(grep -i "^Protocol $PROTOCOL_VERSION$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check if protocol version $PROTOCOL_VERSION: PASSED";
  else
    FAIL=1
    echo "[req-$REQ_NR: test 1/1] check if protocol version $PROTOCOL_VERSION: FAILED (incorrect version)";
  fi
fi

write_to_soc $FAIL $PASS

# Req 2: SSH moduli smaller than 2048 must not be used.
let "REQ_NR++"
REQ_TXT="SSH moduli smaller than 2048 must not be used."
FAIL=0
PASS=0

# Test 1/1
if [ -z "$(awk '$5 < $MODULI_MIN' /etc/ssh/moduli)" ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if moduli >= $MODULI_MIN: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check moduli >= $MODULI_MIN: FAILED (found moduli < $MODULI_MIN)";
fi

write_to_soc $FAIL $PASS

# Req 3: Only approved key exchange algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved key exchange algorithms must be used."
FAIL=0
PASS=0
FOUND_KEYEX=""

# Test 1/1
if [ -z "$(grep -i ^KexAlgorithms $SSH_CONFIG)" ]; then
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check key exchange: FAILED (absent KexAlgorithms)";
else
  CNT=1
  KEYEX=KEYEX$CNT
  while [ $CNT -lt 5 ]; do
    if [ $(grep -i "${!KEYEX}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      PASS=1
      echo "[req-$REQ_NR: test 1/1] check key exchange: PASSED";
      FOUND_KEYEX="$FOUND_KEYEX,${!KEYEX}"
    else
      FAIL=1
      echo "[req-$REQ_NR: test 1/1] check key exchange: FAILED (absent ${!KEYEX})";
    fi
    let CNT++;
    KEYEX=KEYEX$CNT;
  done
  ORG_IFS=$IFS
  IFS=,
  GET_KEYEX="$(awk '/^KexAlgorithms/ {print $2}' $SSH_CONFIG)"
  for CHK in $GET_KEYEX; do
    if [ "$CHK" != "$(echo $FOUND_KEYEX | grep -ow $CHK)" ]; then
      FAIL=1;
      echo "[req-$REQ_NR: test 1/1] check key exchange: FAILED (found incorrect KeyEx:$CHK)";
    fi
  done
fi
IFS=$ORG_IFS

write_to_soc $FAIL $PASS

# Req 4: Only approved ciphers algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved ciphers algorithms must be used."
FAIL=0
PASS=0
FOUND_CIPHERS=""

# Test 1/1
if [ -z "$(grep -i ^Ciphers $SSH_CONFIG)" ]; then
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check ciphers: FAILED (absent Ciphers)";
else
  CNT=1
  CIPHER=CIPHERS$CNT
  while [ $CNT -lt 6 ]; do
    if [ $(grep -i "${!CIPHER}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      PASS=1
      echo "[req-$REQ_NR: test 1/1] check ciphers: PASSED";
      FOUND_CIPHERS="$FOUND_CIPHERS,${!CIPHERS}"
    else
      FAIL=1
      echo "[req-$REQ_NR: test 1/1] check ciphers: FAILED (absent ${!CIPHER})";
    fi
    let CNT++;
    CIPHER=CIPHER$CNT;
  done
  ORG_IFS=$IFS
  IFS=,
  GET_CIPHER="$(awk '/^Ciphers/ {print $2}' $SSH_CONFIG)"
  for CHK in $GET_CIPHER; do
    if [ "$CHK" != "$(echo $FOUND_CIPHER | grep -ow $CHK)" ]; then
      FAIL=1;
      echo "[req-$REQ_NR: test 1/1] check ciphers: FAILED (found incorrect Cipher:$CHK)";
    fi
  done
fi
IFS=$ORG_IFS

write_to_soc $FAIL $PASS

# Req 5: Only approved MAC algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved MAC algorithms must be used."
FAIL=0
PASS=0
FOUND_MACS=""

# Test 1/1
if [ -z "$(grep -i ^MACs $SSH_CONFIG)" ]; then
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check mac algorithms: FAILED (absent MACs)";
else
  CNT=1
  MAC=MAC$CNT
  while [ $CNT -lt 7 ]; do
    if [ $(grep -i "${!MAC}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      PASS=1
      echo "[req-$REQ_NR: test 1/1] check mac algorithms: PASSED";
      FOUND_MACS="$FOUND_MACS,${!MAC}"
    else
      FAIL=1
      echo "[req-$REQ_NR: test 1/1] check mac algorithms: FAILED (absent ${!MAC})";
    fi
    let CNT++;
    MAC=MAC$CNT;
  done
  ORG_IFS=$IFS
  IFS=,
  GET_MAC="$(awk '/^MACs/ {print $2}' $SSH_CONFIG)"
  for CHK in $GET_MAC; do
    if [ "$CHK" != "$(echo $FOUND_MACS| grep -ow $CHK)" ]; then
      FAIL=1;
      echo "[req-$REQ_NR: test 1/1] check mac algorithms: FAILED (found incorrect MAC:$CHK)";
    fi
  done
fi
IFS=$ORG_IFS

write_to_soc $FAIL $PASS

# Req 6: SSH logging must be enabled.
let "REQ_NR++"
REQ_TXT="SSH logging must be enabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^LogLevel $LOG_LEVEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if LogLevel $LOG_LEVEL: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if LogLevel $LOG_LEVEL: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 7: SSH LoginGraceTime must be set to one minute or less.
let "REQ_NR++"
REQ_TXT="SSH LoginGraceTime must be set to one minute or less."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^LoginGraceTime $LOGIN_GRACE_TIME$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if LoginGraceTime $LOGIN_GRACE_TIME: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if LoginGraceTime $LOGIN_GRACE_TIME: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 8: SSH MaxAuthTries must be set to 5 or less.
let "REQ_NR++"
REQ_TXT="SSH MaxAuthTries must be set to 5 or less."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^MaxAuthTries $MAX_AUTH_TRIES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if MaxAuthTries $MAX_AUTH_TRIES: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if MaxAuthTries $MAX_AUTH_TRIES: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 9: SSH root login must be disabled.
let "REQ_NR++"
REQ_TXT="SSH root login must be disabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^PermitRootLogin $PERMIT_ROOT$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if PermitRootLogin $PERMIT_ROOT: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if PermitRootLogin $PERMIT_ROOT: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 10:	SSH strict mode must be enabled.
let "REQ_NR++"
REQ_TXT="SSH strict mode must be enabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^StrictModes $STRICT_MODES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if StrictModes $STRICT_MODES: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if StrictModes $STRICT_MODES: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 11:	SSH user authentication must be done with public keys.
let "REQ_NR++"
REQ_TXT="SSH user authentication must be done with public keys."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^PubkeyAuthentication $PUB_KEY_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if PubkeyAuthentication $PUB_KEY_AUTH: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if PubkeyAuthentication $PUB_KEY_AUTH: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 12:	SSH password authentication must be disabled.
let "REQ_NR++"
REQ_TXT="SSH password authentication must be disabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^PasswordAuthentication $PASS_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if PasswordAuthentication $PASS_AUTH: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if PasswordAuthentication $PASS_AUTH: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 13:	SSH IgnoreRhosts must be enabled.
let "REQ_NR++"
REQ_TXT="SSH IgnoreRhosts must be enabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^IgnoreRhosts $IGNORE_RHOSTS$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if IgnoreRhosts $IGNORE_RHOSTS: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if IgnoreRhosts $IGNORE_RHOSTS: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 14:	SSH HostbasedAuthentication must be disabled.
let "REQ_NR++"
REQ_TXT="SSH HostbasedAuthentication must be disabled."
FAIL=0
PASS=0

# Test 1/1
if [ $(grep -i "^HostbasedAuthentication $HOST_BASED_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 1/1] check if HostbasedAuthentication $HOST_BASED_AUTH: PASSED";
else
  FAIL=1
  echo "[req-$REQ_NR: test 1/1] check if HostbasedAuthentication $HOST_BASED_AUTH: FAILED (incorrect)";
fi

write_to_soc $FAIL $PASS

# Req 15:	The usage of the SSH service must be restricted to dedicated groups
# or users.
let "REQ_NR++"
REQ_TXT="The usage of the SSH service must be restricted to dedicated groups or users."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 16:	The SSH Idle Timeout Interval must be configured to an adequate time.
let "REQ_NR++"
REQ_TXT="The SSH Idle Timeout Interval must be configured to an adequate time."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 17:	SSH tunnel devices must be disabled.
let "REQ_NR++"
REQ_TXT="SSH tunnel devices must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 18:	SSH TCP port forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH TCP port forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 19:	SSH agent forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH agent forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 20:	SSH gateway ports must be disabled.
let "REQ_NR++"
REQ_TXT="SSH gateway ports must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 21:	SSH X11 forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH X11 forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 22:	SSH PermitUserEnvironment must be disabled.
let "REQ_NR++"
REQ_TXT="SSH PermitUserEnvironment must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 23:	SSH PermitEmptyPasswords must be disabled.
let "REQ_NR++"
REQ_TXT="SSH PermitEmptyPasswords must be disabled."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS

# Req 24:	If SFTP is activated, internal server of OpenSSH must be used.
let "REQ_NR++"
REQ_TXT="If SFTP is activated, internal server of OpenSSH must be used."
FAIL=0
PASS=0

# Test 1/x

# write_to_soc $FAIL $PASS
