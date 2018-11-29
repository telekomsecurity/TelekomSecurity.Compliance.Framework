#!/bin/bash

# -----------------------------------------------------------------------------
# Telekom Security - Script for Compliance Check
# Linux OS for Servers (3.65)
# Version: 0.1
# Date: 29-11-18
# Author: Markus Schumburg (security.automation@telekom.de)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
TCP_PORTS="22"
UDP_PORTS=" "
CLIENTS="rsh-redone-client rsh-client talk telnet ldap-utilsi samba"
SERVERS="openbsd-inetd inetutils-inetd xinetd xserver-xorg-core vsftpd \
 nfs-kernel-server ftpd dovecot-core dovecot-pop3d dovecot-imapd nis \
 isc-dhcp-server avahi-daemon cups snmpd"
FILESYS="cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat"
PARTITIONS="/tmp /var" # add more if needed: /var/tmp, /var/log instead of /var
SUID_FILES="/bin/ping /sbin/pam_timestamp_check /sbin/unix_chkpwd /usr/bin/at \
 /usr/bin/gpasswd /usr/bin/locate /usr/bin/newgrp /usr/bin/passwd /bin/ping6 \
 /usr/bin/ssh-agent /usr/sbin/lockdev /sbin/mount.nfs /sbin/umount.nfs \
 /usr/sbin/sendmail.sendmail /usr/bin/expiry /usr/libexec/utempter/utempter \
 /usr/bin/traceroute6.iputils /sbin/mount.nfs4 /sbin/umount.nfs4 /usr/bin/crontab \
 /usr/bin/wall /usr/bin/write /usr/bin/screen /usr/bin/mlocate /usr/bin/chage \
 /usr/bin/chfn /usr/bin/chsh /bin/fusermount /usr/bin/pkexec /usr/bin/sudo \
 /usr/bin/sudoedit /usr/sbin/postdrop /usr/sbin/postqueue /usr/sbin/suexec \
 /usr/lib/squid/ncsa_auth /usr/lib/squid/pam_auth /usr/kerberos/bin/ksu \
 /usr/sbin/ccreds_validate /usr/lib/dbus-1.0/dbus-daemon-launch-helper \
 /usr/lib/policykit-1/polkit-agent-helper-1"
IPV4_1="net.ipv4.ip_forward = 0"
IPV4_2="net.ipv4.conf.all.accept_redirects = 0"
IPV4_3="net.ipv4.conf.default.accept_redirects = 0"
IPV4_4="net.ipv4.conf.all.secure_redirects = 1"
IPV4_5="net.ipv4.conf.default.secure_redirects = 1"
IPV4_6="net.ipv4.conf.all.send_redirects = 0"
IPV4_7="net.ipv4.conf.default.send_redirects = 0"
IPV4_8="net.ipv4.conf.all.accept_source_route = 0"
IPV4_9="net.ipv4.conf.default.accept_source_route = 0"
IPV4_10="net.ipv4.conf.all.log_martians = 1"
IPV4_11="net.ipv4.conf.default.log_martians = 1"
IPV4_12="net.ipv4.icmp_echo_ignore_broadcasts = 1"
IPV4_13="net.ipv4.icmp_ignore_bogus_error_responses = 1"
IPV4_14="net.ipv4.conf.all.rp_filter = 1"
IPV4_15="net.ipv4.conf.default.rp_filter = 1"
IPV4_16="net.ipv4.tcp_syncookies = 1"
IPV4_17="net.ipv4.icmp_ratelimit = 100"
IPV4_18="net.ipv4.icmp_ratemask = 88089"
IPV4_19="net.ipv4.tcp_timestamps = 0"
IPV4_20="net.ipv4.conf.all.arp_ignore = 2"
IPV4_21="net.ipv4.conf.all.arp_announce = 2"
IPV4_22="net.ipv4.conf.all.arp_notify = 0"
IPV4_23="net.ipv4.conf.all.arp_accept = 0"
IPV6_1="net.ipv6.conf.all.disable_ipv6 = 0"
IPV6_2="net.ipv6.conf.default.disable_ipv6 = 0"
IPV6_3="net.ipv6.conf.all.forwarding = 0"
IPV6_4="net.ipv6.conf.default.forwarding = 0"
IPV6_5="net.ipv6.conf.all.accept_redirects = 0"
IPV6_6="net.ipv6.conf.default.accept_redirects = 0"
IPV6_7="net.ipv6.conf.all.accept_source_route = 0"
IPV6_8="net.ipv6.conf.default.accept_source_route = 0"
IPV6_9="net.ipv6.conf.all.accept_ra = 0"
IPV6_10="net.ipv6.conf.default.accept_ra = 0"
IPV6_11="net.ipv6.conf.all.accept_ra_rtr_pref = 0"
IPV6_12="net.ipv6.conf.default.accept_ra_rtr_pref = 0"
IPV6_13="net.ipv6.conf.all.accept_ra_pinfo = 0"
IPV6_14="net.ipv6.conf.default.accept_ra_pinfo = 0"
IPV6_15="net.ipv6.conf.all.accept_ra_defrtr = 0"
IPV6_16="net.ipv6.conf.default.accept_ra_defrtr = 0"
IPV6_17="net.ipv6.conf.all.router_solicitations = 0"
IPV6_18="net.ipv6.conf.default.router_solicitations = 0"
IPV6_19="net.ipv6.conf.all.dad_transmits = 0"
IPV6_20="net.ipv6.conf.default.dad_transmits = 0"
IPV6_21="net.ipv6.conf.all.autoconf = 0"
IPV6_22="net.ipv6.conf.default.autoconf = 0"

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
   elif [ "$OS" == "Ubuntu" ]; then
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
OUT_FILE="compliance-$DAY.log"
OUT_CSV="compliance-$DAY.csv"

exec >$OUT_FILE
echo -e "-----------------------------------------------------------------------------------"
echo " Telekom Security - Compliance Check - Linux OS"
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

# Req 1: Unused services and protocols must be deactivated.
let "REQ_NR++"
REQ_TXT="Unused services and protocols must be deactivated."
FAIL=0
PASS=0

# Test 1/2
CHK_TCP=`ss -nlt 2>/dev/null | awk '($1 == "LISTEN" && $4 !~ /127.0.0.*.:./ && $4 !~ /::*.:./) {print $4}' | sed 's/.*://' | sort -nu`

for CHK in $CHK_TCP; do
  if [ "$CHK" != "`echo $TCP_PORTS | grep -ow "$CHK"`" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/2] check open tcp ports: FAILED (found port $CHK)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 1/2] check open tcp ports: PASSED";
  fi
done

# Test 2/2
CHK_UDP=`ss -nlu 2>/dev/null | awk '($1 == "UNCONN" && $4 !~ /127.0.0.*.:./ && $4 !~ /::*.:./) {print $4}' | sed 's/.*://' | sort -nu`

for CHK in $CHK_UDP; do
  if [ "$CHK" != "`echo $UDP_PORTS | grep -ow "$CHK"`" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 2/2] check open udp ports: FAILED (found port $CHK)";
  else
    PASS=1;
    echo "[req-$REQ_NR: test 2/2] check open udp ports: PASSED";
  fi
done

write_to_soc $FAIL $PASS

# Req 2: The reachability of services must be restricted.
let "REQ_NR++"
REQ_TXT="The reachability of services must be restricted."

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] restriction of reachability: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS

# Req 3: Unused software must not be installed or must be uninstalled.
let "REQ_NR++"
REQ_TXT="Unused software must not be installed or must be uninstalled."
FAIL=0
PASS=0

# Test 1/2
for CHK in $SERVERS; do
  if [ "`$PACKAGE | grep -ow $CHK | wc -l`" -ne "0" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/2] check unused client ($CHK): FAILED (present)";
  else
    PASS=1;
    echo "[req-$REQ_NR: test 1/2] check unused client ($CHK): PASSED";
  fi
done

# Test 2/2
for CHK in $CLIENTS; do
  if [ "`$PACKAGE | grep -ow $CHK | wc -l`" -ne "0" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 2/2] check unused server ($CHK): FAILED (present)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 2/2] check unused server ($CHK): PASSED";
  fi
done

write_to_soc $FAIL $PASS

# Req 4: Unused filesystems must be disabled.
let "REQ_NR++"
REQ_TXT="Unused filesystems must be disabled."
FAIL=0
PASS=0

# Test 1/1
for CHK in $FILESYS; do
  if [ "`lsmod | grep -o $CHK | sort -u | wc -l`" -ne "0" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/1] check unused filesystem ($CHK): FAILED (present)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check unused filesystems ($CHK): PASSED";
  fi
done

write_to_soc $FAIL $PASS

# Req 5: Dedicated partitions must be used for growing content that can influence
# the availability of the system.
let "REQ_NR++"
REQ_TXT="Dedicated partitions must be used for growing content that can influence the availability of the system."
FAIL=0
PASS=0

# Test 1/1
for CHK in $PARTITIONS; do
  if [ "`grep -o $CHK /etc/fstab | sort -u | wc -l`" -eq "0" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/1] check needed partition ($CHK): FAILED (not found)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check needed partition ($CHK): PASSED";
  fi
done

write_to_soc $FAIL $PASS

# Req 6: Parameters nodev, nosuid and noexec must be set for partitions where
# this is applicable.
let "REQ_NR++"
REQ_TXT="Parameters nodev, nosuid and noexec must be set for partitions where this is applicable."
#<tbd>

# Req 7: Automounting must be disabled.
let "REQ_NR++"
REQ_TXT="Automounting must be disabled."
FAIL=0
PASS=0

# Test 1/1
if [ "`$PACKAGE | grep -ow autofs | wc -l`" -ne "0" ]; then
    FAIL=1
    echo "[req-$REQ_NR: test 1/1] check if autofs is installed: FAILED (present)";
else
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check if autofs is installed: PASSED";
fi

write_to_soc $FAIL $PASS

# Req 8: The use of at/cron must be restricted to authorized users.
let "REQ_NR++"
REQ_TXT="The use of at/cron must be restricted to authorized users."
FAIL=0
PASS=0

# Test 1/2
for CHK in at cron; do
  if [ -f "/etc/$CHK.deny" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/2] check for $CHK.deny file: FAILED (present)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 1/2] check for $CHK.deny file: PASSED";
  fi
done

# Test 1/2
for CHK in at cron; do
  if [ -f "/etc/$CHK.allow" ]; then
    if [ "`stat -L -c "%a %u %g" /etc/$CHK.allow | grep -o ".00 0 0"`" != "" ]; then
      PASS=1
      echo "[req-$REQ_NR: test 2/2] check for $CHK.allow file: PASSED";
    else
      FAIL=1
      echo "[req-$REQ_NR: test 2/2] check for $CHK.allow file: FAILED (wrong permissions)";
    fi
  else
    FAIL=1
    echo "[req-$REQ_NR: test 2/2] check for $CHK.allow file: FAILED (absent)";
  fi
done

write_to_soc $FAIL $PASS

# Req 9: Sticky bit must be set on all world-writable directories.
let "REQ_NR++"
REQ_TXT="Sticky bit must be set on all world-writable directories."
FAIL=0
PASS=0

# Test 1/1
SRCH=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 \! -perm -1000 2>/dev/null`
CHK=`echo "$SRCH" | wc -l`

if [ "$CHK" -eq "0" ]; then
    PASS=1;
    echo "[req-$REQ_NR: test 1/1] check for world-writable directory: PASSED";
else
    FAIL=1;
    for DIR in $SRCH; do
      echo "[req-$REQ_NR: test 1/1] check for world-writable directory: FAILED (found $DIR)";
    done
fi

write_to_soc $FAIL $PASS

# Req 10: No regular files that are world writable must exist.
let "REQ_NR++"
REQ_TXT="No regular files that are world writable must exist."
FAIL=0
PASS=0

# Test 1/1
SRCH=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null`
CHK=`echo "$SRCH" | wc -l`

if [ "$CHK" -eq "0" ]; then
    PASS=1;
    echo "[req-$REQ_NR: test 1/1] check for world-writable files: PASSED";
else
    FAIL=1;
    for FILE in $SRCH; do
      echo "[req-$REQ_NR: test 1/1] check for world-writable files: FAILED (found $FILE)";
    done
fi

write_to_soc $FAIL $PASS

# Req 11: Passwords must be protected with an appropriate hashing function.
let "REQ_NR++"
REQ_TXT="Passwords must be protected with an appropriate hashing function."
FAIL=0
PASS=0

# Test 1/1
if [ "`grep -i "^ENCRYPT_METHOD SHA512" /etc/login.defs`" ] && \
   [ "`grep -i "^SHA_CRYPT_MIN_ROUNDS 640000" /etc/login.defs`" ] && \
   [ "`grep -i "^SHA_CRYPT_MAX_ROUNDS 640000" /etc/login.defs`" ]; then
    echo "[req-$REQ_NR: test 1/1] check password encryption: PASSED";
    PASS=1;
else
    echo "[req-$REQ_NR: test 1/1] check password encryption: FAILED (wrong config)";
    FAIL=1;
fi

write_to_soc $FAIL $PASS

# Req 12: The default user umask must be 027 or more restrictive.
let "REQ_NR++"
REQ_TXT="The default user umask must be 027 or more restrictive."
FAIL=0
PASS=0

# Test 1/1
if [ "`grep -i "^UMASK 027" /etc/login.defs`" ]; then
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check umask: PASSED";
else
    FAIL=1
    echo "[req-$REQ_NR: test 1/1] check password encryption: FAILED (wrong umask)";
fi

write_to_soc $FAIL $PASS

# Req 13: Not needed SUID and SGID bits must be removed from executables.
let "REQ_NR++"
REQ_TXT="Not needed SUID and SGID bits must be removed from executables."
FAIL=0
PASS=0

# Test 1/1
CHK_FILES=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f \( -perm -4000 -o -perm -2000 \) -print`

for CHK in $CHK_FILES; do
  if [ "$CHK" != "`echo $SUID_FILES | grep -ow "$CHK"`" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/1] check not allowed files with SUID: FAILED ($CHK)";
  else
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check not allowed files with SUID: PASSED";
  fi
done

write_to_soc $FAIL $PASS

# Req 14: Core dumps must be disabled.
let "REQ_NR++"
REQ_TXT="Core dumps must be disabled."
FAIL=0
PASS=0

# Test 1/3
DUMP="soft hard"

for CHK in $DUMP; do
  if [ -z "$(ls -A /etc/security/limits.d)" ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 1/3] check if core dump is disaled: FAILED (config file not found)";
  else
    if [ `grep -i "$CHK core 0" /etc/security/limits.d/* | wc -l` -eq 1 ]; then
      PASS=1
      echo "[req-$REQ_NR: test 1/3] check if core dump is disaled: PASSED";
    else
      FAIL=1;
      echo "[req-$REQ_NR: test 1/3] check if core dump is disaled: FAILED ($CHK core)";
    fi
  fi
done

# Test 2/3
SYSCTL=`sysctl fs.suid_dumpable | awk '{print $3}'`

if [ $SYSCTL -eq 0 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 2/3] check if fs.suid_dumpable is disabled: PASSED";
else
  FAIL=1;
  echo "[req-$REQ_NR: test 2/3] check if fs.suid_dumpable is disabled: FAILED (value: $SYSCTL)";
fi

# Test 3/3
CHK_FILE=`grep "fs.suid_dumpable = 0" $SYSCTL_CONF | wc -l`

if [ $CHK_FILE -eq 1 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 3/3] check fs.suid_dumpable in config: PASSED";
elif [ $CHK_FILE -eq 0 ]; then
  FAIL=1;
  echo "[req-$REQ_NR: test 3/3] check fs.suid_dumpable in config: FAILED (absent)";
else
  FAIL=1;
  echo "[req-$REQ_NR: test 3/3] check fs.suid_dumpable in config: FAILED (found multiple entries)";
fi

write_to_soc $FAIL $PASS

# Req 15: Protection against buffer overflows must be enabled.
let "REQ_NR++"
REQ_TXT="Protection against buffer overflows must be enabled."
FAIL=0
PASS=0

# Test 1/3
CHK_NX=`dmesg | awk -F' ' '{if ($3 == "NX") print $7}'`

if [ "$CHK_NX" == "active" ]; then
    PASS=1
    echo "[req-$REQ_NR: test 1/3] check if NX/XD is enabled: PASSED";
else
    FAIL=1;
    echo "[req-$REQ_NR: test 1/3] check if NX/XD is enabled: FAILED ($CHK_NX)";
fi

# Test 2/3
SYSCTL=`sysctl kernel.randomize_va_space | awk '{print $3}'`

if [ $SYSCTL -eq 2 ]; then
  PASS=1
  echo "[req-$REQ_NR: test 2/3] check buffer overflow protection: PASSED";
else
  FAIL=1;
  echo "[req-$REQ_NR: test 2/3] check buffer overflow protection: FAILED (value: $SYSCTL)";
fi

# Test 3/3
CHK_FILE=`grep "kernel.randomize_va_space = 2" $SYSCTL_CONF | wc -l`

if [ $CHK_FILE -eq 1 ]; then
  PASS=1;
  echo "[req-$REQ_NR: test 3/3] check kernel.randomize_va_space in config: PASSED";
elif [ $CHK_FILE -eq 0 ]; then
  FAIL=1;
  echo "[req-$REQ_NR: test 3/3] check kernel.randomize_va_space in config: FAILED (absent)";
else
  FAIL=1;
  echo "[req-$REQ_NR: test 3/3] check kernel.randomize_va_space in config: FAILED (found multiple entries)";
fi

write_to_soc $FAIL $PASS

# Req 16: Prelink must not be used.
let "REQ_NR++"
REQ_TXT="Prelink must not be used"
FAIL=0
PASS=0

# Test 1/1
if [ "`$PACKAGE | grep -ow prelink | wc -l`" -ne "0" ]; then
  echo "[req-$REQ_NR: test 1/1] check if prelink is used: FAILED (found prelink)";
  FAIL=1;
else
  echo "[req-$REQ_NR: test 1/1] check if prelink is used: PASSED";
  PASS=1;
fi

write_to_soc $FAIL $PASS

# Req 17: IPv4 protocol stack must be securely configured.
let "REQ_NR++"
REQ_TXT="IPv4 protocol stack must be securely configured."
FAIL=0
PASS=0
CNT=1
IPV4=IPV4_$CNT

while [ $CNT -lt 24 ]; do
  PAR=`echo ${!IPV4} | awk '{print $1}'`;
  VALUE=`echo ${!IPV4} | awk '{print $3}'`;
  # Test 1/2
  SYSCTL=`sysctl $PAR | awk '{print $3}'`
  if [ $SYSCTL -eq $VALUE ]; then
    PASS=1;
    echo "[req-$REQ_NR: test 1/2] check $PAR: PASSED";
  else
    FAIL=1;
    echo "[req-$REQ_NR: test 1/2] check $PAR: FAILED (value: $SYSCTL)";
  fi
  # Test 2/2
  CHK_FILE=`grep "${!IPV4}" $SYSCTL_CONF | wc -l`
  if [ $CHK_FILE -eq 1 ]; then
    PASS=1
    echo "[req-$REQ_NR: test 2/2] check $PAR in config: PASSED";
  elif [ $CHK_FILE -eq 0 ]; then
    FAIL=1;
    echo "[req-$REQ_NR: test 2/2] check $PAR in config: FAILED (absent)";
  else
    FAIL=1;
    echo "[req-$REQ_NR: test 2/2] check $PAR in config: FAILED (found multiple entries)";
  fi
  let CNT++;
  IPV4=IPV4_$CNT;
done

write_to_soc $FAIL $PASS

# Req 18: IPv6 protocol stack must be securely configured.
let "REQ_NR++"
REQ_TXT="IPv6 protocol stack must be securely configured."
FAIL=0
PASS=0
CNT=1
IPV6=IPV6_$CNT

if [ `sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}'` -eq 0 ] && \
   [ `sysctl net.ipv6.conf.default.disable_ipv6 | awk '{print $3}'` -eq 0 ]; then
     while [ $CNT -lt 23 ]; do
       PAR=`echo ${!IPV6} | awk '{print $1}'`;
       VALUE=`echo ${!IPV6} | awk '{print $3}'`;
       # Test 1/2
       SYSCTL=`sysctl $PAR | awk '{print $3}'`
       if [ $SYSCTL -eq $VALUE ]; then
         PASS=1;
         echo "[req-$REQ_NR: test 1/2] check $PAR: PASSED";
       else
      FAIL=1;
      echo "[req-$REQ_NR: test 1/2] check $PAR: FAILED (value: $SYSCTL)";
    fi
    # Test 2/2
    CHK_FILE=`grep "${!IPV6}" $SYSCTL_CONF | wc -l`
    if [ $CHK_FILE -eq 1 ]; then
      PASS=1
      echo "[req-$REQ_NR: test 2/2] check $PAR in config: PASSED";
    elif [ $CHK_FILE -eq 0 ]; then
      FAIL=1;
      echo "[req-$REQ_NR: test 2/2] check $PAR in config: FAILED (absent)";
    else
      FAIL=1;
      echo "[req-$REQ_NR: test 2/2] check $PAR in config: FAILED (found multiple entries)";
    fi
    let CNT++;
    IPV6=IPV6_$CNT;
  done
  write_to_soc $FAIL $PASS
else
  echo "[req-$REQ_NR: test 2/2] check IPv6 in config: n/a (disabled)";
  echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
fi

# Req 19: Emerged vulnerabilities in software and hardware of a system must be
# fixed or protected against misuse.
let "REQ_NR++"
REQ_TXT="Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse."
FAIL=0
PASS=0
ERR=0

# Test 1/1
if [ "$OS" == "Ubuntu" ]; then
  apt update &>/dev/null
  if [ `apt list --upgradable 2>/dev/null | wc -l` -ne 0 ]; then ERR=1; fi
elif [ "$OS" == "RedHat" ]; then
  if [ `yum check-update 2>/dev/null | grep "updates$" | wc -l` -ne 0 ]; then ERR=1; fi
elif [ "$OS" == "Suse" ]; then
  zypper refresh -s &>/dev/null
  if [ `zypper list-updates 2>/dev/null | grep "No updates found." | wc -l` -ne 1 ]; then ERR=1; fi
fi

if [ $ERR -eq 1 ]; then
  echo "[req-$REQ_NR: test 1/1] check if system is up-to-date: FAILED (updates missing)";
  FAIL=1;
else
  echo "[req-$REQ_NR: test 1/1] check if system is up-to-date: PASSED";
  PASS=1;
fi

write_to_soc $FAIL $PASS

# Req 20: GPG check for repository server must be activated and corresponding
# keys for trustable repositories must be configured.
let "REQ_NR++"
REQ_TXT="GPG check for repository server must be activated and corresponding keys for trustable repositories must be configured."
FAIL=0
PASS=0
ERR=0

# Test 1/1
if [ "$OS" == "Ubuntu" ]; then
  if [ `grep "trusted=yes" /etc/apt/sources.list | wc -l` -ne 0 ]; then ERR=1; fi
elif [ "$OS" == "RedHat" ]; then
  if [ `awk -F\= '/^gpgcheck=/ {print $2}' /etc/yum.conf` -ne 1 ]; then ERR=1; fi
elif [ "$OS" == "Suse" ]; then
  CHK=`awk -F\= '/^gpgcheck=/ {print $2}' /etc/zypp/zypp.conf`
  CHK2=`zypper repos -E | grep -i yes | awk -F'|' '{print $5}' | sort -u | wc -l`
  if [ -z $CHK ]; then
    if [ $CHK2 -ne 1 ]; then ERR=1; fi
  else
    if [ $CHK -ne 1 ]; then ERR=1; fi
  fi
fi

if [ $ERR -eq 1 ]; then
  echo "[req-$REQ_NR: test 1/1] check if repos are trusted: FAILED (found untrusted)";
  FAIL=1;
else
  echo "[req-$REQ_NR: test 1/1] check if repos are trusted: PASSED";
  PASS=1;
fi

write_to_soc $FAIL $PASS

# Req 21: User accounts must be used that allow unambiguous identification of
# the user.
let "REQ_NR++"
REQ_TXT="User accounts must be used that allow unambiguous identification of the user."
FAIL=0
PASS=0

# Test 1/1
if [ "$OS" == "Ubuntu" ]; then
    ACCOUNTS=`awk -F':' '{ if ( $3 >= 1000 && $7 != "/usr/sbin/nologin" ) print $1 }' /etc/passwd`
elif [ "$OS" == "RedHat" ] ||
     [ "$OS" == "Suse" ]; then
    ACCOUNTS=`awk -F':' '{ if ( $3 >= 1000 && $7 != "/sbin/nologin" ) print $1 }' /etc/passwd`
fi

if [ -z "$ACCOUNTS" ]; then
  echo "[req-$REQ_NR: test 1/1] check local user accounts: PASSED";
  PASS=1;
else
  echo "[req-$REQ_NR: test 1/1] check local user accounts: FAILED (check accounts $ACCOUNTS)"
  FAIL=1
fi

write_to_soc $FAIL $PASS

# Req 22: System accounts must be non-login.
let "REQ_NR++"
REQ_TXT="System accounts must be non-login."
FAIL=0
PASS=0
CHK=

# Test 1/1:
CHK=`awk -F':' '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7=="/bin/bash") {print $1}' /etc/passwd`

if [ -z "$CHK" ]; then
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check system acounts if non-login: PASSED";
else
    FAIL=1;
    echo "[req-$REQ_NR: test 1/1] check system acounts if non-login: FAILED (found user(s) $CHK)";
fi

write_to_soc $FAIL $PASS

# Req 23: User accounts must be protected against unauthorized usage by at least
# one authentication attribute.
let "REQ_NR++"
REQ_TXT="User accounts must be protected against unauthorized usage by at least one authentication attribute."
FAIL=0
PASS=0
CHK=

CHK=`awk -F":" '($2 == "" && $2 != "!" && $2 !="*") {print $1}' /etc/shadow`

if [ -z "$CHK" ]; then
    PASS=1
    echo "[req-$REQ_NR: test 1/1] check acounts in /etc/shadow: PASSED";
else
    FAIL=1;
    echo "[req-$REQ_NR: test 1/1] check acounts in /etc/shadow: FAILED (found $CHK without attribute)";
fi

write_to_soc $FAIL $PASS

# Req 24: User accounts with extensive rights must be protected with two
# authentication attributes.
let "REQ_NR++"
REQ_TXT="User accounts with extensive rights must be protected with two authentication attributes."
FAIL=0
PASS=0

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] check 2-factor authentication: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS

# Req 25: The system must be connected to a central system for user administration.
let "REQ_NR++"
REQ_TXT="The system must be connected to a central system for user administration."
FAIL=0
PASS=0

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] check central user administration: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS

# Req 26: Authentication must be used for single user mode.
let "REQ_NR++"
REQ_TXT="Authentication must be used for single user mode."
FAIL=0
PASS=0
ERR=0

# Test 1/1
if [ "$OS" == "Ubuntu" ]; then
    CHK=`grep "^root:[*\!]:" /etc/shadow`
    if [ -z  "$CHK" ]; then ERR=1; fi
elif [ "$OS" == "RedHat" ] ||
     [ "$OS" == "Suse" ]; then
       CHK="ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\""
       if [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/rescue.service`" ] && \
          [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/emergency.service`" ]; then
            ERR=1;
       fi
fi

if [ $ERR = 0 ]; then
  echo "[req-$REQ_NR: test 1/1] check single user mode: PASSED";
  PASS=1;
else
  echo "[req-$REQ_NR: test 1/1] check single user mode: FAILED (not activated)"
  FAIL=1
fi

write_to_soc $FAIL $PASS

# Req 27: The management of the operating system must be done via a dedicated
# management network which is independent from the production network.
let "REQ_NR++"
REQ_TXT="The management of the operating system must be done via a dedicated management network which is independent from the production network."
FAIL=0
PASS=0

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] check management network: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS

# Req 28: Management services must be bound to the management network.
let "REQ_NR++"
REQ_TXT="Management services must be bound to the management network."
FAIL=0
PASS=0

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] check services on management network: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS

# Req 29 = Encrypted protocols must be used for management access to administrate
# the operating system.
let "REQ_NR++"
REQ_TXT="Encrypted protocols must be used for management access to administrate the operating system."
FAIL=0
PASS=0

# Not implemented yet! Manual check necessary!
FAIL=1
echo "[req-$REQ_NR:] check management services for encryption: FAILED (no test: check manual!)"

write_to_soc $FAIL $PASS
