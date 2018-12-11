# Telekom Security - Compliance Bash Scripts

Company: [T-systems International GmbH](https://www.t-systems.com)

Author : [Markus Schumburg](mailto://security.automation@telekom.de)

Version: 0.9

Date   : 11. Dec 2018

-------------------------------------------------------------------------------

## Description

The bash scripts can be used to check compliance for the following security
requirements of Deutsche Telekom AG:

* SecReq 3.65: Linux OS for Servers
* SecReq 3.04: SSH

## Platforms

The scripts are tested on systems with the following Linux OSes for servers.

* Ubuntu 14.04 LTS
* Ubuntu 16.04 LTS
* Ubuntu 18.04 LTS
* RedHat Enterprise Linux 7.x
* Amazon Linux (Version 2)
* Suse Linux Enterprise Server 15

Other Linux versions may work also but they are not tested now.

## Execute

The scripts must be executed with root rights on the system itself to check compliance.

$ sudo ./check_linux.sh
$ sudo ./check_ssh.sh

The script will use bash commands like grep, awk, sed, ss etc. It will not change
or manipulate anything on the system. Two output files will be generated in the directory were the scripts are executed:

Log file: compliance-linux-<date>.log or compliance-ssh-<date>.log

This file will include the results of the performed tests and show if they are
PASSED or FAILED.

SoC file (csv): compliance-linux-<date>.csv or compliance-ssh-<date>.csv

This file will include the compliance statements (compliant, partly compliant, not compliant) for all requirements.

## References

Telekom Security - Security Requirements:
* SecReq 3.65: Linux OS for Servers
* SecReq 3.04: SSH

Telekom Security Compliance Framework: [on GitHub](https://github.com/telekomsecurity/TelekomSecurity.Compliance.Framework)

## License

Copyright 2018, T-Systems International GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
