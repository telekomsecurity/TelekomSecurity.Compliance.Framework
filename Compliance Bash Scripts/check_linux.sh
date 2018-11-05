#!/bin/bash
# -----------------------------------------------------------------------------
# Telekom Security - Script for Compliance Check
# Linux OS for Servers (3.65)
# Version: 0.1
# Date: 05-11-18
# Author: Markus Schumburg (security.automation@telekom.de)
# -----------------------------------------------------------------------------

# Variables
# -----------------------------------------------------------------------------
tcp_ports="22"
udp_ports=""

# Pre-Checks
# -----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  echo -e "\r\n   -- Important! -----------------------------\r\n"
  echo -e "      Script must run with root priviledges!\r\n"
  echo -e "   -------------------------------------------\r\n"
  exit
fi

# Output File
# -----------------------------------------------------------------------------
day=`date +"%d%m%y"`
out_file="compliance-$day.log"
echo -e "-----------------------------------------------------------------------------------" >>$out_file
echo " Telekom Security - Compliance Check - Linux OS" >$out_file
echo -e "-----------------------------------------------------------------------------------" >>$out_file
echo "   Host:" $HOSTNAME >>$out_file
echo "   Date:" `date +"%d-%m-%y"` >>$out_file
echo -e "------------------------------------------------------------------------------------\r\n" >>$out_file

# Start Compliance Checks
# -----------------------------------------------------------------------------
req_nr=0

# Req 1: Unused services and protocols must be deactivated.
let "req_nr++"
req_txt="Unused services and protocols must be deactivated."
cnt_err=0

echo "Req-$req_nr Test 1/2:">>$out_file
chk_tcp=`ss -nlt 2>/dev/null | awk '($1 == "LISTEN" && $4 !~ /127.0.0.1:./ && $4 !~ /::1:./) {print $4}' | sed 's/.*://' | sort -nu`
cnt=0

for chk1 in $chk_tcp; do
  chk2=`echo $tcp_ports | grep -ow "$chk1"`;
  if [ "$chk1" != "$chk2" ]; then
    let "cnt++";
    echo "Found open TCP port: $chk1!">>$out_file;
  fi
done
if [ $cnt -gt "0" ]; then let "cnt_err++"; fi

#<tbd>
case $cnt_err in
  0)
    echo -e "Req $req_nr, $req_txt, Compliant\r\n">>$out_file;;
  1)
    echo -e "Req $req_nr, $req_txt, Not Compliant\r\n">>$out_file;;
  *)
    echo -e "Req $req_nr, $req_txt, Partly Compliant\r\n">>$out_file;;
esac

# Req 2: The reachability of services must be restricted.
let "req_nr++"
req_txt="<tbd>"
cnt_err=0

echo "Req-$req_nr Test 1/<tbd>:">>$out_file


case $cnt_err in
  0)
    echo -e "Req $req_nr, $req_txt, Compliant\r\n">>$out_file;;
  <tbd>)
    echo -e "Req $req_nr, $req_txt, Not Compliant\r\n">>$out_file;;
  *)
    echo -e "Req $req_nr, $req_txt, Partly Compliant\r\n">>$out_file;;
esac


# Req 3: Unused software must not be installed or must be uninstalled.
# Req 4: Unused filesystems must be disabled.
# Req 5: Dedicated partitions must be used for growing content that can influence the availability of the system.
# Req 6: Parameters nodev, nosuid and noexec must be set for partitions where this is applicable.
# Req 7: Automounting must be disabled.
# Req 8: The use of at/cron must be restricted to authorized users.
# Req 9: Sticky bit must be set on all world-writable directories.
# Req 10: No regular files that are world writable must exist.
# Req 11: Passwords must be protected with an appropriate hashing function.
# Req 12: The default user umask must be 027 or more restrictive.
# Req 13: Not needed SUID and SGID bits must be removed from executables.
# Req 14: Core dumps must be disabled.
# Req 15: Protection against buffer overflows must be enabled.
# Req 16: Prelink must not be used.
# Req 17: IPv4 protocol stack must be securely configured.
# Req 18: IPv6 protocol stack must be securely configured.
# Req 19: Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse.
# Req 20: GPG check for repository server must be activated and corresponding keys for trustable repositories must be configured.
# Req 21: User accounts must be used that allow unambiguous identification of the user.
# Req 22: System accounts must be non-login.
# Req 23: User accounts must be protected against unauthorized usage by at least one authentication attribute.
# Req 24: User accounts with extensive rights must be protected with two authentication attributes.
# Req 25: The system must be connected to a central system for user administration.
# Req 26: Authentication must be used for single user mode.
# Req 27: The management of the operating system must be done via a dedicated management network which is independent from the production network.
# Req 28: Management services must be bound to the management network.
# Req 29: Encrypted protocols must be used for management access to administrate the operating system.
