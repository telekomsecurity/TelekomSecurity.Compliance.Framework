#!/bin/bash

# -----------------------------------------------------------------------------
# Telekom Security - Script for Compliance Check
# Linux OS for Servers (3.65)
# Version: 0.1
# Date: 19-11-18
# Author: Markus Schumburg (security.automation@telekom.de)
# -----------------------------------------------------------------------------

# Variables
# -----------------------------------------------------------------------------
TCP_PORTS="22"
UDP_PORTS=" "
CLIENTS="rsh-redone-client rsh-client talk telnet ldap-utilsi samba"
SERVERS="openbsd-inetd inetutils-inetd xinetd xserver-xorg-core nfs-kernel-server vsftpd ftpd dovecot-core dovecot-pop3d dovecot-imapd isc-dhcp-server nis avahi-daemon cups snmpd"

# Pre-Checks
# -----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  ERR="1"
  ERR_TXT="Script must run with root priviledges!"
fi

if [ -f /etc/os-release ]; then
   OS=`awk -F\" '/^ID=/ {print $2}' /etc/os-release`
   if [ "$OS" == "centos" ] || [ "$OS" == "redhat" ]; then
      PACKAGE="rpm -qa"
   elif [ "$OS" == "ubuntu" ]; then
      PACKAGE="dpkg -l"
   else
     ERR="1"
     ERR_TXT="Linux version $OS not supported with this script!"
   fi
else
  ERR="1"
  ERR_TXT="Linux version could not be identified!"
fi

if [ "$ERR" == "1" ]; then
  clear
  echo -e "\r\n   -- Important! -----------------------------------------\r\n" >&2
  echo -e "      $ERR_TXT\r\n" >&2
  echo -e "   -------------------------------------------------------\r\n" >&2
  exit
fi

# Output File
# -----------------------------------------------------------------------------
DAY=`date +"%d%m%y"`
OUT_FILE="compliance-$DAY.log"
OUT_CSV="compliance-$DAY.csv"

exec >$OUT_FILE
echo -e "-----------------------------------------------------------------------------------"
echo " Telekom Security - Compliance Check - Linux OS"
echo -e "-----------------------------------------------------------------------------------"
echo "   Host:" $HOSTNAME
echo "   Date:" `date +"%d-%m-%y"`
echo -e "------------------------------------------------------------------------------------\r\n"

exec 3>$OUT_CSV
echo ReqNo.,Requirement,Statement of Compliance>&3

# Start Compliance Checks
# -----------------------------------------------------------------------------
REQ_NR=0

# Req 1: Unused services and protocols must be deactivated.
let "REQ_NR++"
REQ_TXT="Unused services and protocols must be deactivated."
CNT_ERR=0

# Test 1/2
CHK_TCP=`ss -nlt 2>/dev/null | awk '($1 == "LISTEN" && $4 !~ /127.0.0.*.:./ && $4 !~ /::*.:./) {print $4}' | sed 's/.*://' | sort -nu`
CNT=0

for CHK in $CHK_TCP; do
  if [ "$CHK" != `echo $TCP_PORTS | grep -ow "$CHK"` ]; then
    let "CNT++";
    echo "[req-$REQ_NR: test 1/2] check open tcp ports: failed! (found port $CHK)";
  else
    echo "[req-$REQ_NR: test 1/2] check open tcp ports: passed!";
  fi
done
if [ $CNT -gt "0" ]; then let "CNT_ERR++"; fi

# Test 2/2
CHK_UDP=`ss -nlu 2>/dev/null | awk '($1 == "UNCONN" && $4 !~ /127.0.0.*.:./ && $4 !~ /::*.:./) {print $4}' | sed 's/.*://' | sort -nu`
CNT=0

for CHK in $CHK_UDP; do
  if [ "$CHK" != "`echo $UDP_PORTS | grep -ow "$CHK"`" ]; then
    let "CNT++";
    echo "[req-$REQ_NR: test 2/2] check open udp ports: failed! (found port $CHK)";
  else
    echo "[req-$REQ_NR: test 2/2] check open udp ports: passed!";
  fi
done
if [ $CNT -gt "0" ]; then let "CNT_ERR++"; fi

case $CNT_ERR in
  0)
    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
  *)
    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
esac

# Req 2: The reachability of services must be restricted.
#let "REQ_NR++"
#REQ_TXT="The reachability of services must be restricted."
#CNT_ERR=0

#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 3: Unused software must not be installed or must be uninstalled.
let "REQ_NR++"
REQ_TXT="Unused software must not be installed or must be uninstalled."
CNT_ERR=0

for CHK in $SERVERS; do
  if [ `$PACKAGE | grep -ow $CHK | wc -l` -ne "0" ]; then
    let "CNT++";
    echo "[req-$REQ_NR: test 1/2] check installed client: failed! (found  $CHK)";
  else
    echo "[req-$REQ_NR: test 1/2] check installed client: passed!";
  fi
done
if [ $CNT -gt "0" ]; then let "CNT_ERR++"; fi

for CHK in $CLIENTS; do
  if [ `$PACKAGE | grep -ow $CHK | wc -l` -ne "0" ]; then
    let "CNT++";
    echo "[req-$REQ_NR: test 2/2] check installed server: failed! (found  $CHK)";
  else
    echo "[req-$REQ_NR: test 2/2] check installed client: passed!";
  fi
done
if [ $CNT -gt "0" ]; then let "CNT_ERR++"; fi

case $CNT_ERR in
  0)
    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
  *)
    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
esac

# Req 4: Unused filesystems must be disabled.
#let "REQ_NR++"
#REQ_TXT="Unused filesystems must be disabled."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 5: Dedicated partitions must be used for growing content that can influence the availability of the system.
#let "REQ_NR++"
#REQ_TXT="Dedicated partitions must be used for growing content that can influence the availability of the system."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 6: Parameters nodev, nosuid and noexec must be set for partitions where this is applicable.
#let "REQ_NR++"
#REQ_TXT="Parameters nodev, nosuid and noexec must be set for partitions where this is applicable."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 7: Automounting must be disabled.
#let "REQ_NR++"
#REQ_TXT="Automounting must be disabled."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 8: The use of at/cron must be restricted to authorized users.
#let "REQ_NR++"
#REQ_TXT="The use of at/cron must be restricted to authorized users."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 9: Sticky bit must be set on all world-writable directories.
#let "REQ_NR++"
#REQ_TXT="Sticky bit must be set on all world-writable directories."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 10: No regular files that are world writable must exist.
#let "REQ_NR++"
#REQ_TXT="No regular files that are world writable must exist."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 11: Passwords must be protected with an appropriate hashing function.
#let "REQ_NR++"
#REQ_TXT="Passwords must be protected with an appropriate hashing function."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 12: The default user umask must be 027 or more restrictive.
#let "REQ_NR++"
#REQ_TXT="The default user umask must be 027 or more restrictive."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 13: Not needed SUID and SGID bits must be removed from executables.
#let "REQ_NR++"
#REQ_TXT="Not needed SUID and SGID bits must be removed from executables."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 14: Core dumps must be disabled.
#let "REQ_NR++"
#REQ_TXT="Core dumps must be disabled."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 15: Protection against buffer overflows must be enabled.
#let "REQ_NR++"
#REQ_TXT="Protection against buffer overflows must be enabled."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 16: Prelink must not be used.
#let "REQ_NR++"
#REQ_TXT="Prelink must not be used"
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 17: IPv4 protocol stack must be securely configured.
#let "REQ_NR++"
#REQ_TXT="IPv4 protocol stack must be securely configured."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 18: IPv6 protocol stack must be securely configured.
#let "REQ_NR++"
#REQ_TXT="IPv6 protocol stack must be securely configured."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 19: Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse.
#let "REQ_NR++"
#REQ_TXT="Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 20: GPG check for repository server must be activated and corresponding keys for trustable repositories must be configured.
#let "REQ_NR++"
#REQ_TXT="GPG check for repository server must be activated and corresponding keys for trustable repositories must be configured."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 21: User accounts must be used that allow unambiguous identification of the user.
#let "REQ_NR++"
#REQ_TXT="User accounts must be used that allow unambiguous identification of the user."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 22: System accounts must be non-login.
#let "REQ_NR++"
#REQ_TXT="System accounts must be non-login."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 23: User accounts must be protected against unauthorized usage by at least one authentication attribute.
#let "REQ_NR++"
#REQ_TXT="User accounts must be protected against unauthorized usage by at least one authentication attribute."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 24: User accounts with extensive rights must be protected with two authentication attributes.
#let "REQ_NR++"
#REQ_TXT="User accounts with extensive rights must be protected with two authentication attributes."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 25: The system must be connected to a central system for user administration.
#let "REQ_NR++"
#REQ_TXT="The system must be connected to a central system for user administration."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 26: Authentication must be used for single user mode.
#let "REQ_NR++"
#REQ_TXT="Authentication must be used for single user mode."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 27: The management of the operating system must be done via a dedicated management network which is independent from the production network.
#let "REQ_NR++"
#REQ_TXT="The management of the operating system must be done via a dedicated management network which is independent from the production network."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 28: Management services must be bound to the management network.
#let "REQ_NR++"
#REQ_TXT="Management services must be bound to the management network."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac

# Req 29: Encrypted protocols must be used for management access to administrate the operating system.

#let "REQ_NR++"
#REQ_TXT="Encrypted protocols must be used for management access to administrate the operating system."
#CNT_ERR=0



#case $CNT_ERR in
#  0)
#    echo -e "Req $REQ_NR,$REQ_TXT, Compliant">&3;;
#  <tbd>)
#    echo -e "Req $REQ_NR,$REQ_TXT,Not  Compliant">&3;;
#  *)
#    echo -e "Req $REQ_NR,$REQ_TXT,Partly  Compliant">&3;;
#esac
