#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmap_sweep.py - four phase nmap sweep driven from a text file of IP addresses.

Each IP is pushed through four phases.  The phases run back to back for that one
IP, so the moment port discovery for an IP is done its detail scan starts - it
does not wait for the other IPs.  Several IPs are worked on at the same time
(--threads).

  Phase 1  DISCOVERY  TCP : -Pn -T4 -p- --open
                      UDP : -Pn -T4 -sU --top-ports 1000 --open
  Phase 2  DETAIL     -sV --script "default,vuln"   (same as -sC plus vuln)
                      run only against the ports phase 1 found
  Phase 3  SERVICE    per service NSE scripts, e.g. ssl-* on 443, smb-* on 445,
                      http-* on 80/8080, ssh-* on 22, then a sweep-up pass that
                      offers every remaining script to nmap and lets each
                      script's own portrule decide - so nothing is left out
  Phase 4  FINDINGS   read everything above and write a plain english issue list
                      (anonymous SMB, expired certs, SSH Terrapin, regreSSHion,
                       SHA-1 MACs, CBC ciphers, weak TLS, VULNERABLE states ...)

Output tree (default ./nmap_results):

  <IP>.txt              full readable output for that IP, phases 1-3
  open_ports.txt        one line per host:  <IP>:<port>,<port>,...  (udp as <port>/udp)
  open_ports.csv        per-port detail (proto, state, service, product, version)
  findings.txt          issues grouped BY FINDING (not by host): each issue lists
                        every <IP>:<ports> it affects (e.g. all TLS 1.0 in one block)
  findings/<IP>.txt     issues for that IP on its own
  raw/<IP>/*.nmap|.xml  untouched nmap output, kept so you can re-parse later
  sweep.log             run log

Usage:
  python nmap_sweep.py targets.txt
  python nmap_sweep.py targets.txt -o results --threads 4
  python nmap_sweep.py targets.txt --skip-udp --resume
  python nmap_sweep.py targets.txt --dry-run          # print commands only

Run it as root (Linux/macOS) or from an Administrator prompt (Windows, with
Npcap installed).  UDP scanning needs raw sockets and is skipped otherwise.

Only scan hosts you are authorised to test.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

if sys.version_info < (3, 7):
    sys.exit("This script needs Python 3.7 or newer (you have %d.%d)."
             % sys.version_info[:2])

# ============================================================================
# 1.  SETTINGS - change the nmap flags here
# ============================================================================

# Phase 1 - port discovery.  -Pn (no ping) and -T4 are on as requested.
TCP_DISCOVERY_ARGS = ["-Pn", "-n", "-T4", "-p-", "--open",
                      "--min-rate", "1000", "--max-retries", "2"]
UDP_DISCOVERY_ARGS = ["-Pn", "-n", "-T4", "-sU", "--top-ports", "1000", "--open",
                      "--min-rate", "500", "--max-retries", "1"]

# Phase 2 - detail scan.  -sC is only a shortcut for --script default, and a
# --script flag overrides -sC, so both categories are listed in one --script.
DETAIL_ARGS = ["-Pn", "-n", "-T4", "-sV", "--version-all", "--script-timeout", "5m"]
DETAIL_SCRIPTS = ["default", "vuln"]

# Phase 3 - service specific scripts.
SERVICE_ARGS = ["-Pn", "-n", "-T4", "-sV", "--script-timeout", "5m"]

# Script categories that are never selected unless you ask for them:
#   dos       - tries to crash the service
#   brute     - password guessing, slow and locks accounts out
#   external  - sends target details to third party sites (VirusTotal, whois..)
#   broadcast - does not target your host at all
DEFAULT_EXCLUDED_CATEGORIES = ["dos", "brute", "external", "broadcast"]

# Scripts that are never run no matter what, by name or wildcard:
#   targets-*   add NEW hosts to the scan queue - that would take you outside
#               the target list you were authorised to scan
#   *-brute     password guessing that is not tagged with the brute category
#   unittest    runs NSE's own library tests, tells you nothing about the host
#   url-snarf   sniffs traffic off an interface rather than scanning the host
#   mmouse-exec / domcon-cmd   execute commands on the target
NEVER_RUN = ["targets-*", "*-brute", "unittest", "url-snarf",
             "ip-geolocation-map-kml", "mmouse-exec", "domcon-cmd"]

# Minutes allowed for a single nmap call before it is killed.
DEFAULT_TIMEOUT_MIN = 180

# ============================================================================
# 2.  WHICH SCRIPTS BELONG TO WHICH SERVICE
# ============================================================================
# Keyed by the service name nmap prints (-sV).  Values are nmap script
# wildcards.  A wildcard that matches nothing on your nmap build is dropped
# automatically, so it is safe to list extras.

SERVICE_SCRIPT_MAP = {
    # --- web ---------------------------------------------------------------
    "http":         ["http-*"],
    "https":        ["http-*", "ssl-*", "tls-*"],
    "http-proxy":   ["http-*"],
    "http-alt":     ["http-*"],
    "https-alt":    ["http-*", "ssl-*", "tls-*"],
    "ssl":          ["ssl-*", "tls-*"],
    "ssl/http":     ["http-*", "ssl-*", "tls-*"],
    "ipp":          ["cups-*", "http-*"],
    "soap":         ["http-*"],
    "upnp":         ["upnp-*", "http-*"],
    "rtsp":         ["rtsp-*"],
    "sip":          ["sip-*"],
    "sip-tls":      ["sip-*", "ssl-*"],
    "ajp13":        ["ajp-*"],
    "websocket":    ["http-*"],
    # --- smb / windows -----------------------------------------------------
    "microsoft-ds": ["smb-*", "smb2-*"],
    "netbios-ssn":  ["smb-*", "smb2-*", "nbstat"],
    "netbios-ns":   ["nbstat"],
    "msrpc":        ["msrpc-enum", "rpc-grind", "rpcinfo"],
    "ms-wbt-server": ["rdp-*", "ssl-*"],
    "ms-sql-s":     ["ms-sql-*"],
    "wsdapi":       ["http-*"],
    "winrm":        ["http-*"],
    # --- remote access -----------------------------------------------------
    "ssh":          ["ssh-*", "ssh2-*", "sshv1"],
    "telnet":       ["telnet-*", "banner"],
    "vnc":          ["vnc-*", "realvnc-auth-bypass"],
    "vnc-http":     ["http-*", "vnc-*"],
    "x11":          ["x11-*"],
    "exec":         ["banner"],
    "login":        ["banner"],
    "shell":        ["banner"],
    # --- file transfer / shares -------------------------------------------
    "ftp":          ["ftp-*"],
    "ftps":         ["ftp-*", "ssl-*"],
    "ftps-data":    ["ssl-*"],
    "tftp":         ["tftp-*"],
    "nfs":          ["nfs-*", "rpcinfo"],
    "rpcbind":      ["nfs-*", "rpcinfo"],
    "mountd":       ["nfs-*", "rpcinfo"],
    "rsync":        ["rsync-*"],
    "afp":          ["afp-*"],
    "smtp":         ["smtp-*"],
    # --- mail --------------------------------------------------------------
    "smtps":        ["smtp-*", "ssl-*"],
    "submission":   ["smtp-*", "ssl-*"],
    "pop3":         ["pop3-*"],
    "pop3s":        ["pop3-*", "ssl-*"],
    "imap":         ["imap-*"],
    "imaps":        ["imap-*", "ssl-*"],
    # --- directory / auth --------------------------------------------------
    "ldap":         ["ldap-*"],
    "ldapssl":      ["ldap-*", "ssl-*"],
    "globalcatLDAP":    ["ldap-*"],
    "globalcatLDAPssl": ["ldap-*", "ssl-*"],
    "kerberos-sec": ["krb5-*"],
    "kpasswd5":     ["krb5-*"],
    # --- databases ---------------------------------------------------------
    "mysql":        ["mysql-*"],
    "ms-sql":       ["ms-sql-*"],
    "oracle-tns":   ["oracle-*"],
    "postgresql":   ["pgsql-*"],
    "mongodb":      ["mongodb-*"],
    "redis":        ["redis-*"],
    "couchdb":      ["couchdb-*"],
    "cassandra":    ["cassandra-*"],
    "drda":         ["db2-*"],
    "ibm-db2":      ["db2-*"],
    "informix":     ["informix-*"],
    "memcache":     ["memcached-*"],
    "memcached":    ["memcached-*"],
    "elasticsearch": ["http-*"],
    "mysqlx":       ["mysql-*"],
    # --- infrastructure ----------------------------------------------------
    "snmp":         ["snmp-*"],
    "domain":       ["dns-*"],
    "dhcps":        ["dhcp-discover"],
    "ntp":          ["ntp-*"],
    "ipmi":         ["ipmi-*"],
    "asf-rmcp":     ["ipmi-*"],
    "isakmp":       ["ike-version"],
    "java-rmi":     ["rmi-*"],
    "rmiregistry":  ["rmi-*"],
    "jdwp":         ["jdwp-*"],
    "iscsi":        ["iscsi-*"],
    "docker":       ["docker-*"],
    "epmd":         ["epmd-info"],
    "amqp":         ["amqp-info"],
    "mqtt":         ["mqtt-subscribe"],
    "nrpe":         ["nrpe-enum"],
    "puppet":       ["ssl-*"],
    "vmware-auth":  ["vmauthd-*"],
    "svn":          ["svn-*"],
    "git":          ["http-git"],
    "bitcoin":      ["bitcoin-*"],
    "xmpp-client":  ["xmpp-info", "ssl-*"],
    "xmpp-server":  ["xmpp-info", "ssl-*"],
    "irc":          ["irc-*"],
    "finger":       ["finger"],
    "ident":        ["auth-owners"],
    "daytime":      ["banner"],
    "echo":         ["banner"],
    "chargen":      ["banner"],
    "sslh":         ["ssl-*"],
    # --- industrial / OT ---------------------------------------------------
    "modbus":       ["modbus-*"],
    "bacnet":       ["bacnet-*"],
    "iso-tsap":     ["s7-info"],
    "omron":        ["omron-*"],
    "pcworx":       ["pcworx-*"],
    "fox":          ["fox-info"],
    "enip":         ["enip-info"],
    "dnp3":         ["dnp3-info"],
}

# Fallback when -sV could not name the service.  Keyed by port number.
PORT_SCRIPT_MAP = {
    21:   ["ftp-*"],                       22:   ["ssh-*", "ssh2-*", "sshv1"],
    23:   ["telnet-*"],                    25:   ["smtp-*"],
    53:   ["dns-*"],                       69:   ["tftp-*"],
    79:   ["finger"],                      80:   ["http-*"],
    88:   ["krb5-*"],                      110:  ["pop3-*"],
    111:  ["nfs-*", "rpcinfo"],            123:  ["ntp-*"],
    135:  ["msrpc-enum", "rpcinfo"],       137:  ["nbstat"],
    139:  ["smb-*", "smb2-*", "nbstat"],   143:  ["imap-*"],
    161:  ["snmp-*"],                      389:  ["ldap-*"],
    443:  ["http-*", "ssl-*", "tls-*"],    445:  ["smb-*", "smb2-*"],
    465:  ["smtp-*", "ssl-*"],             500:  ["ike-version"],
    512:  ["banner"],                      513:  ["banner"],
    514:  ["banner"],                      548:  ["afp-*"],
    554:  ["rtsp-*"],                      587:  ["smtp-*", "ssl-*"],
    623:  ["ipmi-*"],                      636:  ["ldap-*", "ssl-*"],
    873:  ["rsync-*"],                     993:  ["imap-*", "ssl-*"],
    995:  ["pop3-*", "ssl-*"],             1099: ["rmi-*"],
    1433: ["ms-sql-*"],                    1521: ["oracle-*"],
    1723: ["banner"],                      1883: ["mqtt-subscribe"],
    1900: ["upnp-*"],                      2049: ["nfs-*", "rpcinfo"],
    2181: ["http-*"],                      2375: ["docker-*"],
    2376: ["docker-*", "ssl-*"],           3128: ["http-*"],
    3268: ["ldap-*"],                      3269: ["ldap-*", "ssl-*"],
    3306: ["mysql-*"],                     3389: ["rdp-*", "ssl-*"],
    4369: ["epmd-info"],                   4786: ["http-*"],
    5060: ["sip-*"],                       5061: ["sip-*", "ssl-*"],
    5432: ["pgsql-*"],                     5601: ["http-*"],
    5672: ["amqp-info"],                   5900: ["vnc-*"],
    5985: ["http-*"],                      5986: ["http-*", "ssl-*"],
    6000: ["x11-*"],                       6379: ["redis-*"],
    7001: ["http-*"],                      8000: ["http-*"],
    8008: ["http-*"],                      8080: ["http-*"],
    8443: ["http-*", "ssl-*", "tls-*"],    8888: ["http-*"],
    9200: ["http-*"],                      9300: ["http-*"],
    11211: ["memcached-*"],                27017: ["mongodb-*"],
    27018: ["mongodb-*"],                  44818: ["enip-info"],
    47808: ["bacnet-*"],                   102:  ["s7-info"],
    502:  ["modbus-*"],                    20000: ["dnp3-info"],
}

# Ports that are TLS wrapped even when nmap does not flag a tunnel.
TLS_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 994, 995, 1311, 2376,
             3269, 4443, 5061, 5986, 6697, 8443, 8834, 9443, 10000}

# Service names that mean "this is TLS wrapped".
TLS_SERVICES = {"https", "https-alt", "imaps", "pop3s", "smtps", "submissions",
                "ftps", "ftps-data", "ldapssl", "globalcatLDAPssl", "nntps",
                "telnets", "ircs", "sip-tls", "ssl", "ssl/http", "dnsovertls",
                "xmpp-client-ssl", "radsec", "puppet"}
# ============================================================================
# 3.  FINDINGS RULES - what counts as an issue in the script output
# ============================================================================
# Every rule is: (script name pattern, severity, title, regex to look for)
# The regex is searched inside that script's output block, case insensitive.
# Anything that matches becomes a line in findings.txt with the matching text
# quoted as evidence.  Add your own rules to the bottom of the list.

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# NSE vuln scripts print either "State: VULNERABLE" or "State: NOT VULNERABLE".
# A plain "VULNERABLE" search matches both, so every vuln rule uses this: the
# word VULNERABLE on a line that does not also say NOT VULNERABLE.
VULN = r"^(?!.*\bNOT VULNERABLE\b).*\bVULNERABLE\b"

# Many NSE scripts print a friendly "I looked and found nothing" line. A rule
# that only checks "did this script print anything" would report that as an
# issue, so any block matching this is dropped before the rules run.
NO_RESULT = re.compile(
    r"couldn'?t find|could not find|no .{0,40}\b(?:found|detected|discovered|"
    r"identified|vulnerab\w*)|nothing (?:found|to report)|none found|"
    r"\bNOT VULNERABLE\b|not vulnerable|^\s*\|?\s*(?:ERROR|error):|"
    r"no accounts left|failed to|unable to|timeout|access denied|"
    r"login failed|\bfalse\b positive", re.I)

RULES = [
    # ---------- SMB -------------------------------------------------------
    ("smb-enum-shares", "HIGH", "SMB share readable with an anonymous / guest login",
     r"Anonymous access:\s*READ(?!/WRITE)"),
    ("smb-enum-shares", "CRITICAL", "SMB share is anonymously WRITABLE",
     r"Anonymous access:\s*READ/WRITE"),
    ("smb-enum-shares", "HIGH", "SMB share allows current (null) user write access",
     r"Current user access:\s*READ/WRITE"),
    ("smb2-security-mode", "MEDIUM", "SMB signing is enabled but not required (relay / MITM)",
     r"Message signing enabled but not required"),
    ("smb-security-mode", "MEDIUM", "SMB signing is not required",
     r"Message signing (?:enabled but not required|disabled)"),
    ("smb-security-mode", "HIGH", "SMB is using guest authentication",
     r"Account that was used for smb scripts:\s*guest"),
    ("smb-protocols", "HIGH", "SMBv1 is still enabled (WannaCry / EternalBlue era protocol)",
     r"^\s*\|?\s*(?:NT LM 0\.12|SMBv1)"),
    ("smb-os-discovery", "INFO", "Windows host details disclosed over SMB",
     r"OS:\s*\S+"),
    ("smb-vuln-ms17-010", "CRITICAL", "MS17-010 EternalBlue remote code execution",
     VULN),
    ("smb-vuln-ms08-067", "CRITICAL", "MS08-067 remote code execution",
     VULN),
    ("smb-vuln-cve-2017-7494", "CRITICAL", "SambaCry CVE-2017-7494 remote code execution",
     VULN),
    ("smb-vuln-cve2009-3103", "HIGH", "SMBv2 CVE-2009-3103 denial of service / RCE",
     VULN),
    ("smb-enum-users", "MEDIUM", "Domain / local user list readable over SMB",
     r"\\\\\S+"),
    ("smb-double-pulsar-backdoor", "CRITICAL", "DoublePulsar backdoor implant present",
     VULN),

    # ---------- TLS / SSL certificates ------------------------------------
    # (expiry / self-signed / weak key are handled by check_ssl_cert(), which
    #  needs to compare dates and fields rather than match a regex)
    ("ssl-cert", "MEDIUM", "Certificate signed with a broken hash (MD5 / SHA-1)",
     r"Signature Algorithm:\s*(?:md[245]|sha1)\w*With"),

    # ---------- TLS protocol / ciphers ------------------------------------
    ("ssl-enum-ciphers", "HIGH", "SSLv2 is enabled (obsolete, DROWN)",
     r"^\s*SSLv2:"),
    ("ssl-enum-ciphers", "HIGH", "SSLv3 is enabled (POODLE)",
     r"^\s*SSLv3:"),
    ("ssl-enum-ciphers", "MEDIUM", "TLS 1.0 is enabled (deprecated, PCI fail)",
     r"^\s*TLSv1\.0:"),
    ("ssl-enum-ciphers", "MEDIUM", "TLS 1.1 is enabled (deprecated)",
     r"^\s*TLSv1\.1:"),
    ("ssl-enum-ciphers", "HIGH", "NULL cipher suite offered (no encryption)",
     r"TLS_[A-Z0-9_]*WITH_NULL[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "HIGH", "EXPORT grade cipher suite offered",
     r"TLS_[A-Z0-9_]*EXPORT[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "HIGH", "Anonymous Diffie-Hellman cipher suite offered (no auth)",
     r"TLS_(?:DH|ECDH)_anon[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "HIGH", "RC4 cipher suite offered (broken stream cipher)",
     r"TLS_[A-Z0-9_]*WITH_RC4[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "MEDIUM", "3DES cipher suite offered (Sweet32, CVE-2016-2183)",
     r"TLS_[A-Z0-9_]*WITH_3DES[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "HIGH", "Single DES cipher suite offered",
     r"TLS_[A-Z0-9_]*WITH_DES_CBC[A-Z0-9_]*"),
    ("ssl-enum-ciphers", "MEDIUM", "CBC mode cipher suite offered (BEAST / Lucky13 class)",
     r"TLS_[A-Z0-9_]*CBC_SHA\b"),
    ("ssl-enum-ciphers", "MEDIUM", "Cipher suite with an MD5 MAC offered",
     r"TLS_[A-Z0-9_]*_MD5\b"),
    ("ssl-enum-ciphers", "MEDIUM", "Weak Diffie-Hellman group (1024 bit or smaller)",
     r"\(dh\s*(?:512|768|1024)\)"),
    ("ssl-enum-ciphers", "MEDIUM", "Weak overall cipher strength grade (C or worse)",
     r"least strength:\s*[C-F]\b"),
    ("ssl-dh-params", "HIGH", "Weak or common Diffie-Hellman parameters (Logjam)",
     VULN + r"|Anonymous|weak|common prime"),
    ("ssl-poodle", "HIGH", "POODLE - SSLv3 CBC padding oracle (CVE-2014-3566)", VULN),
    ("ssl-heartbleed", "CRITICAL", "Heartbleed memory disclosure (CVE-2014-0160)", VULN),
    ("ssl-ccs-injection", "HIGH", "OpenSSL CCS injection (CVE-2014-0224)", VULN),
    ("sslv2-drown", "HIGH", "DROWN - SSLv2 cross protocol attack (CVE-2016-0800)", VULN),
    ("ssl-known-key", "CRITICAL", "Certificate uses a publicly known / debian-weak private key",
     VULN + r"|Debian"),
    ("tls-ticketbleed", "HIGH", "Ticketbleed memory disclosure (CVE-2016-9244)", VULN),
    ("tls-alpn", "INFO", "TLS ALPN protocols advertised", r"\S"),
    ("rdp-vuln-ms12-020", "HIGH", "RDP MS12-020 denial of service / RCE", VULN),

    # ---------- SSH -------------------------------------------------------
    # Terrapin, regreSSHion and the algorithm checks need real logic, they live
    # in check_ssh_algorithms() / check_ssh_version() further down.
    ("ssh-hostkey", "MEDIUM", "SSH host key is DSA (ssh-dss, deprecated)", r"\bssh-dss\b"),
    ("ssh-hostkey", "MEDIUM", "SSH host key is an RSA key smaller than 2048 bit",
     r"^\s*(?:512|768|1024)\s+\S+\s+\(RSA\)"),
    ("sshv1", "HIGH", "SSH protocol version 1 supported", r"true|supported"),
    ("ssh-auth-methods", "HIGH", "SSH allows authentication with no credentials",
     r"Authentication is not required"),

    # ---------- FTP / Telnet / plaintext ----------------------------------
    ("ftp-anon", "HIGH", "Anonymous FTP login allowed", r"Anonymous FTP login allowed"),
    ("ftp-proftpd-backdoor", "CRITICAL", "ProFTPD backdoor command execution", VULN),
    ("ftp-vsftpd-backdoor", "CRITICAL", "vsFTPd 2.3.4 backdoor", VULN),
    ("ftp-libopie", "HIGH", "FTP libopie off-by-one (CVE-2010-1938)", VULN),
    ("ftp-vuln-cve2010-4221", "HIGH", "ProFTPD Telnet IAC stack overflow", VULN),
    ("telnet-encryption", "HIGH", "Telnet does not support encryption (credentials in clear)",
     r"does not support encryption"),
    ("telnet-ntlm-info", "MEDIUM", "Windows / NTLM details leak over Telnet", r"\S"),

    # ---------- HTTP ------------------------------------------------------
    ("http-methods", "MEDIUM", "Risky HTTP methods enabled (PUT / DELETE / TRACE)",
     r"Potentially risky methods:\s*.*(?:PUT|DELETE|TRACE|CONNECT|PROPFIND)"),
    ("http-trace", "LOW", "HTTP TRACE method enabled (Cross Site Tracing)", r"TRACE is enabled"),
    ("http-git", "HIGH", "Exposed .git repository", r"Git repository found"),
    ("http-svn-enum", "HIGH", "Exposed Subversion metadata", r"^\s*\|?\s*\w+.*\br\d+\b"),
    ("http-config-backup", "HIGH", "Configuration backup file reachable over HTTP", r"\S"),
    ("http-backup-finder", "MEDIUM", "Backup copies of files reachable over HTTP", r"\S"),
    ("http-open-proxy", "HIGH", "Open HTTP proxy (can be used to relay traffic)",
     r"Potentially OPEN proxy"),
    ("http-webdav-scan", "MEDIUM", "WebDAV is enabled", r"WebDAV type|Allowed Methods"),
    ("http-passwd", "CRITICAL", "Directory traversal lets remote users read local files",
     r"Directory traversal found"),
    ("http-shellshock", "CRITICAL", "Shellshock CGI command execution (CVE-2014-6271)",
     VULN),
    ("http-vuln-cve2017-5638", "CRITICAL", "Apache Struts2 RCE (CVE-2017-5638)", VULN),
    ("http-vuln-cve2021-41773", "CRITICAL", "Apache path traversal / RCE (CVE-2021-41773)",
     VULN),
    ("http-vuln-cve2021-44228", "CRITICAL", "Log4Shell (CVE-2021-44228)", VULN),
    ("http-vuln-*", "HIGH", "HTTP vulnerability confirmed by NSE", r"State:\s*VULNERABLE"),
    ("http-enum", "MEDIUM", "Interesting / sensitive paths found on the web server", r"^\s*/\S+"),
    ("http-default-accounts", "CRITICAL", "Default credentials accepted by the web application",
     r"\S"),
    ("http-auth", "MEDIUM", "HTTP authentication required - check for default credentials",
     r"Basic realm|Digest"),
    ("http-security-headers", "LOW", "Security headers are missing or weak",
     r"(?:Strict_Transport_Security|X_Frame_Options|Content_Security_Policy).*\n.*"),
    ("http-cors", "MEDIUM", "Permissive CORS policy", r"\*"),
    ("http-cookie-flags", "LOW", "Session cookie without httponly / secure flag",
     r"(?:httponly flag not set|secure flag not set)"),
    ("http-dombased-xss", "HIGH", "DOM based cross site scripting",
     r"Found the following possible DOM based XSS"),
    ("http-stored-xss", "HIGH", "Stored cross site scripting",
     r"Found the following stored XSS"),
    ("http-csrf", "MEDIUM", "Possible cross site request forgery",
     r"Found the following possible CSRF"),
    ("http-sql-injection", "CRITICAL", "Possible SQL injection",
     r"Possible sqli for (?:quer|form)"),
    ("http-internal-ip-disclosure", "LOW", "Internal IP address disclosed by the web server",
     r"\d+\.\d+\.\d+\.\d+"),
    ("http-phpmyadmin-dir-admin", "HIGH", "phpMyAdmin console exposed", r"\S"),
    ("http-iis-short-name-brute", "MEDIUM", "IIS 8.3 short name disclosure", VULN),
    ("http-put", "CRITICAL", "HTTP PUT lets you upload files", r"uploaded|success"),

    # ---------- databases and key value stores ----------------------------
    ("mongodb-info", "CRITICAL", "MongoDB reachable without authentication",
     r"MongoDB Build info|totalSize"),
    ("mongodb-databases", "CRITICAL", "MongoDB database list readable without authentication",
     r"databases"),
    ("redis-info", "CRITICAL", "Redis reachable without authentication", r"redis_version"),
    ("memcached-info", "HIGH", "Memcached reachable without authentication (also a DDoS amp)",
     r"Server UP|uptime"),
    ("ms-sql-empty-password", "CRITICAL", "MSSQL account with an empty password", r"\S"),
    ("ms-sql-info", "INFO", "MSSQL version disclosed", r"Version:"),
    ("ms-sql-dump-hashes", "CRITICAL", "MSSQL password hashes dumped", r"\S"),
    ("mysql-empty-password", "CRITICAL", "MySQL account with an empty password", r"\S"),
    ("mysql-users", "HIGH", "MySQL user list readable", r"\S"),
    ("mysql-databases", "HIGH", "MySQL database list readable", r"\S"),
    ("mysql-dump-hashes", "CRITICAL", "MySQL password hashes dumped", r"\S"),
    ("mysql-vuln-cve2012-2122", "CRITICAL", "MySQL authentication bypass (CVE-2012-2122)",
     VULN),
    ("pgsql-brute", "CRITICAL", "PostgreSQL credentials guessed", r"Valid credentials"),
    ("couchdb-stats", "HIGH", "CouchDB reachable without authentication", r"\S"),
    ("cassandra-info", "HIGH", "Cassandra reachable without authentication", r"\S"),
    ("oracle-tns-version", "INFO", "Oracle TNS listener version disclosed", r"\S"),
    ("oracle-sid-brute", "MEDIUM", "Oracle SIDs enumerated", r"\S"),

    # ---------- other services -------------------------------------------
    ("nfs-showmount", "HIGH", "NFS exports visible to everyone", r"\*|0\.0\.0\.0/0|/\S+"),
    ("nfs-ls", "HIGH", "NFS export contents readable", r"\S"),
    ("rsync-list-modules", "MEDIUM", "rsync modules listed without authentication", r"\S"),
    ("snmp-info", "MEDIUM", "SNMP readable with a default community string", r"\S"),
    ("snmp-sysdescr", "MEDIUM", "SNMP system description readable (default community)", r"\S"),
    ("snmp-interfaces", "MEDIUM", "SNMP interface list readable", r"\S"),
    ("snmp-win32-users", "HIGH", "Windows user list readable over SNMP", r"\S"),
    ("snmp-netstat", "MEDIUM", "Connection table readable over SNMP", r"\S"),
    ("smtp-open-relay", "CRITICAL", "SMTP open relay (can be abused to send spam)",
     r"Server is an open relay"),
    ("smtp-vuln-cve2010-4344", "CRITICAL", "Exim heap overflow (CVE-2010-4344)", VULN),
    ("smtp-vuln-cve2011-1720", "HIGH", "Postfix Cyrus SASL memory corruption", VULN),
    ("smtp-commands", "INFO", "SMTP capabilities disclosed", r"\S"),
    ("smtp-enum-users", "MEDIUM", "SMTP user enumeration possible (VRFY / EXPN)", r"\S"),
    ("vnc-info", "HIGH", "VNC security type allows access with weak or no authentication",
     r"Security types:.*(?:None|VNC Authentication)"),
    ("realvnc-auth-bypass", "CRITICAL", "RealVNC authentication bypass (CVE-2006-2369)",
     VULN),
    ("x11-access", "CRITICAL", "X11 server accepts connections from anyone",
     r"X server access is granted"),
    ("rdp-enum-encryption", "MEDIUM", "RDP offers weak / legacy encryption or no NLA",
     r"RDP Security Layer|CredSSP.*NOT|Native RDP"),
    ("rdp-ntlm-info", "LOW", "Windows and domain details leak from RDP before login", r"\S"),
    ("ldap-rootdse", "MEDIUM", "LDAP root DSE readable anonymously", r"\S"),
    ("ldap-search", "HIGH", "LDAP directory readable anonymously", r"\S"),
    ("nbstat", "INFO", "NetBIOS name and MAC address disclosed", r"NetBIOS name"),
    ("rpcinfo", "MEDIUM", "RPC services enumerable via portmapper", r"\S"),
    ("ipmi-cipher-zero", "CRITICAL", "IPMI cipher zero lets anyone in without a password",
     VULN),
    ("ipmi-version", "INFO", "IPMI version disclosed", r"\S"),
    ("jdwp-info", "CRITICAL", "Java Debug Wire Protocol open - direct code execution", r"\S"),
    ("rmi-vuln-classloader", "CRITICAL", "Java RMI remote class loading - code execution",
     VULN),
    ("rmi-dumpregistry", "HIGH", "Java RMI registry readable", r"\S"),
    ("docker-version", "CRITICAL", "Docker API exposed on the network - root equivalent", r"\S"),
    ("afp-showmount", "MEDIUM", "AFP shares visible", r"\S"),
    ("afp-serverinfo", "INFO", "AFP server details disclosed", r"\S"),
    ("dns-recursion", "MEDIUM", "Open DNS resolver (usable for reflection attacks)",
     r"Recursion appears to be enabled"),
    ("dns-zone-transfer", "HIGH", "DNS zone transfer allowed (AXFR)", r"\S"),
    ("dns-update", "CRITICAL", "DNS accepts unauthenticated dynamic updates", r"succeeded"),
    ("ntp-monlist", "MEDIUM", "NTP monlist enabled (DDoS amplification, CVE-2013-5211)", r"\S"),
    ("ntp-info", "INFO", "NTP server details disclosed", r"\S"),
    ("tftp-enum", "HIGH", "Files readable over TFTP without authentication", r"\S"),
    ("upnp-info", "MEDIUM", "UPnP service details disclosed", r"\S"),
    ("clamav-exec", "CRITICAL", "ClamAV command execution (CVE-2016-1405)", VULN),
    ("irc-unrealircd-backdoor", "CRITICAL", "UnrealIRCd backdoor", VULN),
    ("distcc-cve2004-2687", "CRITICAL", "distcc remote command execution", VULN),
    ("finger", "LOW", "finger service discloses logged in users", r"\S"),
    ("modbus-discover", "HIGH", "Modbus industrial controller reachable", r"\S"),
    ("s7-info", "HIGH", "Siemens S7 PLC reachable", r"\S"),
    ("bacnet-info", "HIGH", "BACnet building control device reachable", r"\S"),
    ("enip-info", "HIGH", "EtherNet/IP industrial device reachable", r"\S"),

    # ---------- catch all for anything the vuln category confirms ---------
    ("*", "HIGH", "NSE reported the host as VULNERABLE", r"State:\s*VULNERABLE"),
    ("*", "MEDIUM", "NSE reported a likely vulnerable state",
     r"State:\s*LIKELY VULNERABLE"),
    ("vulners", "HIGH", "Known CVEs matched against the detected software version",
     r"CVE-\d{4}-\d+\s+[\d.]+"),
]

# Ports whose traffic is unencrypted by design - worth calling out on its own.
CLEARTEXT_PORTS = {
    21:  "FTP - credentials and data travel in clear text",
    23:  "Telnet - credentials and session travel in clear text",
    69:  "TFTP - no authentication at all",
    80:  "HTTP - unencrypted web traffic",
    110: "POP3 - credentials in clear text unless STARTTLS is forced",
    143: "IMAP - credentials in clear text unless STARTTLS is forced",
    161: "SNMP - community strings in clear text (v1/v2c)",
    389: "LDAP - directory queries and binds in clear text",
    512: "rexec - legacy remote execution, no encryption",
    513: "rlogin - legacy remote login, no encryption",
    514: "rsh - legacy remote shell, no encryption",
    873: "rsync - unencrypted file sync",
    1433: "MSSQL exposed on the network",
    3306: "MySQL exposed on the network",
    5432: "PostgreSQL exposed on the network",
    5900: "VNC - weak by design, often unencrypted",
    6379: "Redis - no authentication by default",
    11211: "Memcached - no authentication by default",
    27017: "MongoDB - no authentication by default",
}

# ============================================================================
# 4.  SMALL HELPERS
# ============================================================================

PRINT_LOCK = threading.Lock()
FILE_LOCK = threading.Lock()
LOG_PATH: Path | None = None


def log(msg: str) -> None:
    """Print a timestamped line and append it to sweep.log."""
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
    with PRINT_LOCK:
        print(line, flush=True)
        if LOG_PATH:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def safe_name(target: str) -> str:
    """Turn an IP (or IPv6 address) into something valid as a file name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def find_nmap(user_path: str | None = None) -> str:
    """Locate the nmap binary on Linux, macOS and Windows."""
    if user_path:
        if Path(user_path).exists():
            return user_path
        sys.exit("nmap not found at: %s" % user_path)

    found = shutil.which("nmap")
    if found:
        return found

    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap",
    ]
    for c in candidates:
        if Path(c).exists():
            return c

    sys.exit(
        "nmap was not found.\n"
        "  Windows : install from https://nmap.org/download.html (include Npcap)\n"
        "  macOS   : brew install nmap\n"
        "  Linux   : sudo apt install nmap   /   sudo dnf install nmap\n"
        "Or point at it directly with --nmap-path"
    )


def is_privileged() -> bool:
    """True when we can open raw sockets (needed for -sS and -sU)."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


# A CIDR bigger than this is handed to nmap whole instead of being expanded.
MAX_CIDR_EXPANSION = 1024


def read_targets(path: str) -> list[str]:
    """
    One target per line.  Blank lines and # comments are skipped.

    A plain IP or a hostname is used as is.  A small CIDR range is expanded
    into its individual addresses, so every host still gets its own <IP>.txt
    rather than all of them landing in one file.
    """
    targets, seen = [], set()
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        sys.exit("Cannot read the target file %s: %s" % (path, exc))

    def keep(value: str) -> None:
        if value not in seen:
            seen.add(value)
            targets.append(value)

    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        if "/" in line:                       # a CIDR range
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                log("  line %d skipped, not a valid network: %r" % (lineno, line))
                continue
            hosts = list(net.hosts()) or [net.network_address]
            if len(hosts) <= MAX_CIDR_EXPANSION:
                log("  line %d: %s expanded to %d host(s)" % (lineno, line, len(hosts)))
                for host in hosts:
                    keep(str(host))
            else:
                log("  line %d: %s has %d hosts, too many to expand - it is passed "
                    "to nmap whole, so those hosts share one report file"
                    % (lineno, line, len(hosts)))
                keep(line)
            continue

        try:                                  # a single IP address
            ipaddress.ip_address(line)
        except ValueError:                    # or a hostname
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$", line):
                log("  line %d skipped, does not look like an IP or host: %r"
                    % (lineno, line))
                continue
        keep(line)

    if not targets:
        sys.exit("No usable targets in %s" % path)
    return targets


# ============================================================================
# 5.  RUNNING NMAP
# ============================================================================

class RunResult:
    """Truthy when nmap succeeded, and carries the error text when it did not."""

    def __init__(self, ok: bool, error: str = ""):
        self.ok = ok
        self.error = error

    def __bool__(self) -> bool:
        return self.ok

    @property
    def nse_overloaded(self) -> bool:
        """nmap's script selector is parsed by lpeg, which gives up if the
        selection is too big. Seen as 'too many pending calls/choices'."""
        return ("too many pending" in self.error
                or "failed to initialize the script engine" in self.error)


class Runner:
    """Wraps one nmap invocation: build the command, run it, keep the output."""

    def __init__(self, nmap_path: str, timeout_min: int, dry_run: bool,
                 extra_args: list[str]):
        self.nmap = nmap_path
        self.timeout = timeout_min * 60
        self.dry_run = dry_run
        self.extra = extra_args

    def run(self, target: str, args: list[str], out_base: Path,
            label: str) -> RunResult:
        """Run nmap, writing <out_base>.nmap and <out_base>.xml."""
        cmd = ([self.nmap] + args + self.extra +
               ["-oN", str(out_base) + ".nmap",
                "-oX", str(out_base) + ".xml",
                target])

        if self.dry_run:
            log("  [%s] would run: %s" % (target, " ".join(cmd)))
            return RunResult(False)

        log("  [%s] %s" % (target, label))
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, errors="replace")
        except subprocess.TimeoutExpired:
            log("  [%s] %s TIMED OUT after %d min" % (target, label, self.timeout // 60))
            return RunResult(False, "timeout")
        except OSError as exc:
            log("  [%s] %s could not start: %s" % (target, label, exc))
            return RunResult(False, str(exc))

        took = time.time() - started
        if proc.returncode != 0:
            err = (proc.stderr or "") + (proc.stdout or "")
            detail = err.strip().splitlines()
            first = detail[0] if detail else "no error text"
            log("  [%s] %s failed (exit %d): %s" % (target, label, proc.returncode, first))
            # A bad --script selector is the usual cause; keep going with the
            # other phases instead of giving up on the host.
            return RunResult(False, err)

        log("  [%s] %s done in %s" % (target, label, human_time(took)))
        return RunResult(True)


def xml_of(base: Path) -> Path:
    """The .xml next to an nmap output base name (never use with_suffix here -
    it would eat anything after a dot in the file name)."""
    return Path(str(base) + ".xml")


def human_time(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)


# ============================================================================
# 6.  KNOWING WHICH SCRIPTS THIS NMAP ACTUALLY HAS
# ============================================================================

class ScriptCatalog:
    """
    Reads nmap's script.db so we only ever hand nmap wildcards that match
    something.  A wildcard matching nothing makes nmap abort the whole scan.
    """

    def __init__(self, nmap_path: str):
        self.scripts: dict[str, set[str]] = {}   # script name -> categories
        self._load(nmap_path)

    def _candidate_dirs(self, nmap_path: str):
        env = os.environ.get("NMAPDIR")
        if env:
            yield Path(env) / "scripts"
            yield Path(env)
        binary = Path(nmap_path).resolve()
        yield binary.parent.parent / "share" / "nmap" / "scripts"
        yield binary.parent / "scripts"
        for p in ("/usr/share/nmap/scripts", "/usr/local/share/nmap/scripts",
                  "/opt/homebrew/share/nmap/scripts", "/opt/local/share/nmap/scripts",
                  r"C:\Program Files (x86)\Nmap\scripts", r"C:\Program Files\Nmap\scripts"):
            yield Path(p)

    def _load(self, nmap_path: str) -> None:
        pattern = re.compile(
            r'Entry\s*{\s*filename\s*=\s*"([^"]+)"\s*,\s*categories\s*=\s*{([^}]*)}')
        for d in self._candidate_dirs(nmap_path):
            db = d / "script.db"
            if not db.is_file():
                continue
            try:
                text = db.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for filename, cats in pattern.findall(text):
                name = filename[:-4] if filename.endswith(".nse") else filename
                self.scripts[name] = {c.strip().strip('"')
                                      for c in cats.split(",") if c.strip()}
            if self.scripts:
                log("Script catalog: %d NSE scripts found in %s" % (len(self.scripts), d))
                return
        log("Script catalog: script.db not found - wildcards will be passed to "
            "nmap unchecked")

    @property
    def available(self) -> bool:
        return bool(self.scripts)

    def matches(self, glob: str) -> list[str]:
        """Script names matching one wildcard, e.g. 'ssl-*'."""
        if not self.available:
            return []
        return sorted(n for n in self.scripts if fnmatch.fnmatchcase(n, glob))

    def keep_usable(self, globs: list[str]) -> list[str]:
        """Drop wildcards that match no installed script, keeping the order."""
        out, seen = [], set()
        for g in globs:
            if g in seen:
                continue
            seen.add(g)
            if not self.available or "*" not in g:
                # Exact name: keep it only if we know it exists (or we can't tell).
                if not self.available or g in self.scripts:
                    out.append(g)
            elif self.matches(g):
                out.append(g)
        return out

    def expand(self, globs: list[str], excluded_cats: list[str]) -> list[str]:
        """Real script names a selection will end up running - for the report."""
        if not self.available:
            return []
        names = set()
        for g in globs:
            names.update(self.matches(g) if "*" in g else
                         ([g] if g in self.scripts else []))
        bad = set(excluded_cats)
        return sorted(n for n in names if not (self.scripts.get(n, set()) & bad))


    def in_scope(self, excluded_cats: list[str]) -> list[str]:
        """Every installed script we are allowed to run, after the exclusions."""
        bad = set(excluded_cats)
        return sorted(
            name for name, cats in self.scripts.items()
            if not (cats & bad)
            and not any(fnmatch.fnmatchcase(name, g) for g in NEVER_RUN))


def build_script_expr(globs: list[str], excluded_cats: list[str],
                      safe_only: bool) -> str:
    """
    Turn a list of wildcards into one nmap --script expression.  nmap supports
    boolean selectors, so we let nmap do the filtering instead of pasting a
    thousand script names onto the command line (which breaks on Windows).

        (http-* or ssl-*) and not (dos or brute or external or broadcast)
    """
    expr = "(%s)" % " or ".join(globs)
    if excluded_cats:
        expr += " and not (%s)" % " or ".join(excluded_cats)
    expr += " and not (%s)" % " or ".join(NEVER_RUN)
    if safe_only:
        expr += " and safe"
    return expr


# ============================================================================
# 7.  READING NMAP'S XML OUTPUT
# ============================================================================

class Port:
    """One port as nmap reported it."""

    def __init__(self, proto, portid, state, service="", product="",
                 version="", extrainfo="", tunnel=""):
        self.proto = proto            # "tcp" / "udp"
        self.portid = int(portid)
        self.state = state            # "open" / "open|filtered"
        self.service = service or ""
        self.product = product or ""
        self.version = version or ""
        self.extrainfo = extrainfo or ""
        self.tunnel = tunnel or ""

    @property
    def key(self):
        return (self.proto, self.portid)

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version,
                                    "(%s)" % self.extrainfo if self.extrainfo else "")
                        if x).strip()

    def __str__(self):
        return "%d/%s" % (self.portid, self.proto)


class ScriptBlock:
    """One <script> result, tied to the port it came from."""

    def __init__(self, script_id, output, proto="", portid=0, service=""):
        self.script_id = script_id
        self.output = output or ""
        self.proto = proto
        self.portid = portid
        self.service = service

    @property
    def where(self) -> str:
        if self.portid:
            return "%d/%s" % (self.portid, self.proto)
        return "host"


def parse_ports(xml_path: Path) -> list[Port]:
    """Pull every open (or open|filtered) port out of one nmap XML file."""
    ports: list[Port] = []
    if not xml_path.is_file():
        return ports
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return ports

    for host in root.iter("host"):
        for port in host.iter("port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if not state.startswith("open"):
                continue
            svc = port.find("service")
            ports.append(Port(
                proto=port.get("protocol", ""),
                portid=port.get("portid", "0"),
                state=state,
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
                tunnel=svc.get("tunnel", "") if svc is not None else "",
            ))
    return ports


def parse_script_blocks(xml_path: Path) -> list[ScriptBlock]:
    """Pull every NSE result (port level and host level) out of one XML file."""
    blocks: list[ScriptBlock] = []
    if not xml_path.is_file():
        return blocks
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return blocks

    for host in root.iter("host"):
        for port in host.iter("port"):
            svc = port.find("service")
            service = svc.get("name", "") if svc is not None else ""
            for script in port.findall("script"):
                blocks.append(ScriptBlock(
                    script.get("id", ""), script.get("output", ""),
                    port.get("protocol", ""), int(port.get("portid", "0")), service))
        for hs in host.findall("hostscript"):
            for script in hs.findall("script"):
                blocks.append(ScriptBlock(script.get("id", ""), script.get("output", "")))
    return blocks


def merge_ports(base: dict, new: list[Port]) -> None:
    """Add ports to the dict, letting later (more detailed) scans win."""
    for p in new:
        old = base.get(p.key)
        if old is None:
            base[p.key] = p
        else:
            # Keep whichever record actually knows the service.
            if not old.service and p.service:
                base[p.key] = p
            elif p.product and not old.product:
                base[p.key] = p


# ============================================================================
# 8.  PHASE 1 - PORT DISCOVERY
# ============================================================================

def phase1_discovery(target, runner, raw_dir, do_udp) -> dict:
    """All TCP ports (-p-) plus the top 1000 UDP ports."""
    ports: dict = {}

    tcp_base = raw_dir / "01_discovery_tcp"
    if runner.run(target, TCP_DISCOVERY_ARGS, tcp_base, "phase 1/4  TCP port discovery (-p-)"):
        merge_ports(ports, parse_ports(xml_of(tcp_base)))

    if do_udp:
        udp_base = raw_dir / "02_discovery_udp"
        if runner.run(target, UDP_DISCOVERY_ARGS, udp_base,
                      "phase 1/4  UDP port discovery (top 1000)"):
            merge_ports(ports, parse_ports(xml_of(udp_base)))

    tcp_n = sum(1 for k in ports if k[0] == "tcp")
    udp_n = sum(1 for k in ports if k[0] == "udp")
    log("  [%s] discovery found %d TCP and %d UDP port(s)" % (target, tcp_n, udp_n))
    return ports


def port_spec(ports: dict, proto: str) -> str:
    """Comma separated port list for nmap's -p, e.g. '22,80,443'."""
    nums = sorted(p for (pr, p) in ports if pr == proto)
    return ",".join(str(n) for n in nums)


# ============================================================================
# 9.  PHASE 2 - DETAIL SCAN  (-sC -sV --script vuln)
# ============================================================================

def phase2_detail(target, runner, raw_dir, ports, excluded_cats, safe_only) -> Path | None:
    """Version detection plus the default and vuln script categories."""
    tcp = port_spec(ports, "tcp")
    udp = port_spec(ports, "udp")
    if not tcp and not udp:
        log("  [%s] phase 2/4 skipped, no open ports" % target)
        return None

    spec = ",".join(x for x in ("T:" + tcp if tcp else "",
                                "U:" + udp if udp else "") if x)
    args = list(DETAIL_ARGS)
    if udp:
        args.append("-sU")
    if tcp:
        args.append("-sS" if is_privileged() else "-sT")
    args += ["-p", spec,
             "--script", build_script_expr(DETAIL_SCRIPTS, excluded_cats, safe_only)]

    base = raw_dir / "03_detail"
    if runner.run(target, args, base, "phase 2/4  detail scan (-sV, default + vuln scripts)"):
        merge_ports(ports, parse_ports(xml_of(base)))
        return base
    return None


# ============================================================================
# 10.  PHASE 3 - SERVICE SPECIFIC SCRIPTS
# ============================================================================

def globs_for_port(port: Port) -> list[str]:
    """Which script wildcards suit this port."""
    globs: list[str] = []
    service = port.service.lower()

    if service in SERVICE_SCRIPT_MAP:
        globs += SERVICE_SCRIPT_MAP[service]
    if port.portid in PORT_SCRIPT_MAP:
        globs += PORT_SCRIPT_MAP[port.portid]

    # Anything wrapped in TLS gets the ssl/tls scripts as well.
    if (port.tunnel == "ssl" or port.portid in TLS_PORTS
            or service in TLS_SERVICES or "ssl" in service or "tls" in service):
        globs += ["ssl-*", "tls-*"]

    # Last resort: NSE scripts are named <service>-<check>, so the service name
    # nmap detected is usually the right prefix (mysql -> mysql-*).
    if service:
        base = re.sub(r"[^a-z0-9]+", "-", service).strip("-")
        if base and len(base) > 2:
            globs.append(base + "-*")

    # Nothing matched at all - fall back to the broadly useful categories.
    if not globs:
        globs = ["default", "safe", "version"]

    seen, out = set(), []
    for g in globs:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


def phase3_service_scripts(target, runner, raw_dir, ports, catalog,
                           excluded_cats, safe_only) -> set:
    """
    Group the open ports by the set of scripts they need, then run one nmap
    per group.  Grouping keeps it to a handful of nmap calls per host instead
    of one call per port.
    """
    groups: dict[tuple, list[Port]] = {}
    for port in sorted(ports.values(), key=lambda p: (p.proto, p.portid)):
        usable = catalog.keep_usable(globs_for_port(port))
        if not usable:
            continue
        groups.setdefault((port.proto, tuple(usable)), []).append(port)

    if not groups:
        log("  [%s] phase 3/4 skipped, nothing to script" % target)
        return set()

    covered: set = set()
    total = len(groups)
    for index, ((proto, globs), group_ports) in enumerate(sorted(groups.items()), 1):
        spec = ",".join(str(p.portid) for p in group_ports)
        label_service = group_ports[0].service or "port%s" % group_ports[0].portid
        tag = safe_name(label_service)[:20]

        args = list(SERVICE_ARGS)
        args.append("-sU" if proto == "udp" else ("-sS" if is_privileged() else "-sT"))
        args += ["-p", spec,
                 "--script", build_script_expr(list(globs), excluded_cats, safe_only)]

        base = raw_dir / ("04_scripts_%02d_%s_%s" % (index, proto, tag))
        names = catalog.expand(list(globs), excluded_cats)
        detail = " (%d scripts)" % len(names) if names else ""
        ok = runner.run(target, args, base,
                        "phase 3/4  %d/%d %s scripts on %s/%s%s"
                        % (index, total, label_service, spec, proto, detail))
        if ok:
            covered.update(names)
            merge_ports(ports, parse_ports(xml_of(base)))
    return covered


def phase3b_sweep_remaining(target, runner, raw_dir, ports, catalog,
                            excluded_cats, safe_only, already: set) -> None:
    """
    Sweep up whatever the service map did not select.

    The map in section 2 covers the common services, but nmap ships hundreds of
    scripts for niche ones (Citrix, CICS, DAAP, COAP, gpsd, printers, PLCs...).
    Rather than try to name every service, this pass hands nmap every remaining
    script and lets each script's own portrule decide whether it applies - which
    is exactly how nmap is built to work.  Scripts whose portrule does not match
    cost nothing.
    """
    if not catalog.available:
        return
    remaining = [n for n in catalog.in_scope(excluded_cats) if n not in already]
    if safe_only:
        remaining = [n for n in remaining if "safe" in catalog.scripts.get(n, set())]
    if not remaining:
        return

    tcp, udp = port_spec(ports, "tcp"), port_spec(ports, "udp")
    if not tcp and not udp:
        return
    spec = ",".join(x for x in ("T:" + tcp if tcp else "",
                                "U:" + udp if udp else "") if x)

    # nmap parses "a,b,c" as a plain list, but "(a or b or c)" goes through its
    # lpeg expression parser, which gives up at a few dozen terms. So the names
    # go in as a comma separated list, in chunks, and if a chunk is still too
    # much for this nmap build the chunk is halved and retried.
    def run_chunk(chunk: list[str], tag: str) -> None:
        args = list(SERVICE_ARGS)
        if udp:
            args.append("-sU")
        if tcp:
            args.append("-sS" if is_privileged() else "-sT")
        args += ["-p", spec, "--script", ",".join(chunk)]
        base = raw_dir / ("05_scripts_sweep_%s" % tag)
        result = runner.run(target, args, base,
                            "phase 3/4  sweep-up %s (%d remaining scripts)"
                            % (tag, len(chunk)))
        if result:
            merge_ports(ports, parse_ports(xml_of(base)))
        elif result.nse_overloaded and len(chunk) > 1:
            half = len(chunk) // 2
            log("  [%s] sweep-up chunk %s was too big for nmap, splitting it"
                % (target, tag))
            run_chunk(chunk[:half], tag + "a")
            run_chunk(chunk[half:], tag + "b")

    chunk_size = 100
    chunks = [remaining[i:i + chunk_size] for i in range(0, len(remaining), chunk_size)]
    for n, chunk in enumerate(chunks, 1):
        run_chunk(chunk, "%02d" % n)


# ============================================================================
# 11.  PHASE 4 - TURNING SCRIPT OUTPUT INTO FINDINGS
# ============================================================================

class Finding:
    def __init__(self, severity, title, where, evidence, note=""):
        self.severity = severity
        self.title = title
        self.where = where          # "443/tcp" or "host"
        self.evidence = clean(evidence)
        self.note = note

    @property
    def dedupe_key(self):
        return (self.severity, self.title, self.where)

    def as_text(self) -> str:
        out = "  [%-8s] %-9s %s" % (self.severity, self.where, self.title)
        if self.evidence:
            out += "\n               evidence : %s" % self.evidence
        if self.note:
            out += "\n               note     : %s" % self.note
        return out


def clean(text: str, limit: int = 220) -> str:
    """Squash a snippet of nmap output onto one readable line."""
    text = re.sub(r"[\r\n]+", " | ", (text or "").strip())
    text = re.sub(r"\s{2,}", " ", text).strip(" |")
    return text[:limit] + (" ..." if len(text) > limit else "")


def matched_line(output: str, match: re.Match) -> str:
    """The whole line a regex matched on, for use as evidence."""
    start = output.rfind("\n", 0, match.start()) + 1
    end = output.find("\n", match.end())
    line = output[start:end if end != -1 else len(output)].strip()
    if len(line) < 3:                       # rule matched on almost nothing
        for candidate in output.splitlines():
            if candidate.strip():
                return candidate.strip()
    return line


# --- helpers used by the checks that need real logic ------------------------

def algo_sections(output: str) -> dict[str, list[str]]:
    """
    Split ssh2-enum-algos output into its lists:
      {"kex_algorithms": [...], "encryption_algorithms": [...], ...}
    """
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        line = line.strip().lstrip("|_").strip()
        header = re.match(r"^([a-z_]+_algorithms|[a-z_]+):\s*(?:\(\d+\))?\s*$", line)
        if header:
            current = header.group(1)
            sections[current] = []
        elif current and line:
            sections[current].append(line)
    return sections


def parse_openssh_version(version: str):
    """'9.2p1 Debian 2+deb12u2' -> (9, 2, 1).  None if it cannot be read."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?", (version or "").strip())
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(4) or m.group(3) or 0)
    return (major, minor, patch)


# --- the checks -------------------------------------------------------------

def check_ssh_algorithms(block: ScriptBlock, add) -> None:
    """Terrapin, weak MACs, CBC ciphers and old key exchange methods."""
    if block.script_id != "ssh2-enum-algos":
        return
    s = algo_sections(block.output)
    kex = s.get("kex_algorithms", [])
    hostkey = s.get("server_host_key_algorithms", [])
    enc = s.get("encryption_algorithms", [])
    macs = s.get("mac_algorithms", [])
    where = block.where

    # ---- Terrapin, CVE-2023-48795 ----
    strict_kex = any("kex-strict" in k for k in kex)
    chacha = [e for e in enc if e.startswith("chacha20-poly1305")]
    cbc = [e for e in enc if e.endswith("-cbc")]
    etm = [m for m in macs if m.endswith("-etm@openssh.com")]
    if (chacha or (cbc and etm)) and not strict_kex:
        reason = ("ChaCha20-Poly1305 offered: " + ", ".join(chacha)) if chacha else \
                 ("CBC cipher with an Encrypt-then-MAC algorithm: %s + %s"
                  % (", ".join(cbc[:3]), ", ".join(etm[:3])))
        add(Finding("MEDIUM", "SSH Terrapin prefix truncation attack (CVE-2023-48795)",
                    where, reason,
                    "The server does not advertise strict key exchange "
                    "(kex-strict-s-v00@openssh.com). Upgrade OpenSSH to 9.6+ or "
                    "disable chacha20-poly1305 and *-cbc + *-etm combinations."))
    elif (chacha or (cbc and etm)) and strict_kex:
        add(Finding("INFO", "Terrapin-affected algorithms present but strict KEX is on",
                    where, "kex-strict-s-v00@openssh.com is advertised",
                    "Not exploitable while both ends support strict key exchange."))

    # ---- weak MACs ----
    weak_mac = [m for m in macs if re.search(
        r"(?:^|[^a-z0-9])(?:hmac-sha1|hmac-md5|umac-64)(?:-96)?(?:-etm)?", m)]
    if weak_mac:
        add(Finding("MEDIUM", "SSH offers weak MAC algorithms (SHA-1 / MD5 / 64-bit UMAC)",
                    where, ", ".join(weak_mac),
                    "Keep only hmac-sha2-256/512-etm@openssh.com and umac-128-etm@openssh.com."))

    # ---- weak ciphers ----
    weak_enc = [e for e in enc if e.endswith("-cbc") or e.startswith(("3des", "arcfour",
                                                                     "blowfish", "cast128",
                                                                     "des-", "rijndael"))
                or e == "none"]
    if weak_enc:
        add(Finding("MEDIUM", "SSH offers weak ciphers (CBC mode / 3DES / RC4 / none)",
                    where, ", ".join(weak_enc),
                    "Keep only AES-GCM and AES-CTR suites."))

    # ---- weak key exchange ----
    weak_kex = [k for k in kex if k in (
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1", "rsa1024-sha1", "gss-group1-sha1-")
        or k.endswith("-sha1") or k.startswith("gss-group1")]
    if weak_kex:
        add(Finding("MEDIUM", "SSH offers SHA-1 based or 1024-bit key exchange",
                    where, ", ".join(weak_kex),
                    "Remove SHA-1 KEX; keep curve25519-sha256 and "
                    "diffie-hellman-group16/18-sha512."))

    # ---- weak host key algorithms ----
    weak_hk = [h for h in hostkey if h in ("ssh-dss", "ssh-rsa")
               or h.startswith("ssh-dss")]
    if weak_hk:
        add(Finding("LOW", "SSH offers SHA-1 / DSA host key algorithms",
                    where, ", ".join(weak_hk),
                    "Disable ssh-dss and ssh-rsa; use rsa-sha2-256/512 or ed25519."))


def check_ssh_version(port: Port, add) -> None:
    """CVEs that can only be judged from the OpenSSH version banner."""
    if "openssh" not in (port.product or "").lower():
        return
    version = parse_openssh_version(port.version)
    if not version:
        return
    where = str(port)
    banner = "%s %s" % (port.product, port.version)
    backport = ("Distributions backport fixes without changing this version "
                "string - confirm against the vendor package version before "
                "reporting it.")

    # regreSSHion, CVE-2024-6387: unauthenticated RCE as root
    if version < (4, 4, 1) or (8, 5, 1) <= version < (9, 8, 1):
        add(Finding("HIGH", "SSH regreSSHion unauthenticated RCE (CVE-2024-6387)",
                    where, banner,
                    "Affects OpenSSH < 4.4p1 and 8.5p1 - 9.7p1. Fixed in 9.8p1. " + backport))

    # CVE-2023-38408: ssh-agent PKCS#11 remote code execution
    if version < (9, 3, 2):
        add(Finding("MEDIUM", "OpenSSH ssh-agent PKCS#11 code execution (CVE-2023-38408)",
                    where, banner,
                    "Only exploitable when agent forwarding is used. Fixed in 9.3p2. "
                    + backport))

    # CVE-2018-15473: username enumeration
    if version < (7, 7, 1):
        add(Finding("LOW", "OpenSSH username enumeration (CVE-2018-15473)",
                    where, banner, "Fixed in 7.7p1. " + backport))

    if version < (7, 4, 0):
        add(Finding("MEDIUM", "OpenSSH version is very old and unsupported",
                    where, banner, "Upgrade to a currently supported release."))


def check_ssl_cert(block: ScriptBlock, add) -> None:
    """Expiry dates, self signed certificates and weak keys."""
    if block.script_id != "ssl-cert":
        return
    text, where = block.output, block.where

    def field(name):
        m = re.search(r"^\s*%s:\s*(.+)$" % re.escape(name), text, re.M | re.I)
        return m.group(1).strip() if m else ""

    not_after, not_before = field("Not valid after"), field("Not valid before")
    subject, issuer = field("Subject"), field("Issuer")

    def to_date(value):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue
        return None

    now = datetime.now()
    end, start = to_date(not_after), to_date(not_before)

    if end:
        days = (end - now).days
        if days < 0:
            add(Finding("HIGH", "TLS certificate has expired", where,
                        "expired %d day(s) ago, not valid after %s" % (-days, not_after),
                        "Subject: %s" % (subject or "unknown")))
        elif days <= 30:
            add(Finding("MEDIUM", "TLS certificate expires within 30 days", where,
                        "%d day(s) left, not valid after %s" % (days, not_after),
                        "Subject: %s" % (subject or "unknown")))
    if start and start > now:
        add(Finding("MEDIUM", "TLS certificate is not valid yet", where,
                    "not valid before %s" % not_before))

    if subject and issuer and subject == issuer:
        add(Finding("MEDIUM", "TLS certificate is self signed", where, "Issuer = %s" % issuer,
                    "Clients cannot verify this certificate against a trusted CA."))
    elif issuer and re.search(r"localhost|example\.com|snakeoil|self.?signed|"
                              r"default|test\s*ca|IIS|Plesk", issuer, re.I):
        add(Finding("MEDIUM", "TLS certificate looks like a default / placeholder cert",
                    where, "Issuer = %s" % issuer))

    bits = field("Public Key bits")
    key_type = field("Public Key type").lower()
    if bits.isdigit():
        n = int(bits)
        if key_type in ("rsa", "dsa", "dh") and n < 2048:
            add(Finding("HIGH", "TLS certificate uses a key smaller than 2048 bit",
                        where, "%s %d bit" % (key_type or "key", n)))
        elif key_type in ("ec", "ecdsa") and n < 256:
            add(Finding("HIGH", "TLS certificate uses an EC key smaller than 256 bit",
                        where, "%s %d bit" % (key_type, n)))

    if start and end and (end - start).days > 398:
        add(Finding("LOW", "TLS certificate validity period is longer than 398 days",
                    where, "%s to %s" % (not_before, not_after),
                    "Public CAs and browsers cap certificate lifetime at 398 days."))


def check_cleartext(port: Port, add) -> None:
    """Protocols that carry credentials in the clear just by being open."""
    if port.portid in CLEARTEXT_PORTS and port.state == "open":
        severity = "MEDIUM" if port.portid in (23, 21, 69, 512, 513, 514) else "LOW"
        if port.portid in (6379, 11211, 27017):
            severity = "HIGH"
        add(Finding(severity, "Cleartext or unauthenticated service exposed", str(port),
                    "%s  %s" % (port.service or "unknown", port.banner),
                    CLEARTEXT_PORTS[port.portid]))


def analyse(target: str, ports: dict, blocks: list[ScriptBlock]) -> list[Finding]:
    """Phase 4: run every rule and every check over the collected output."""
    findings: list[Finding] = []
    seen: set = set()

    def add(finding: Finding) -> None:
        if finding.dedupe_key not in seen:
            seen.add(finding.dedupe_key)
            findings.append(finding)

    # 1. the regex rule table
    for block in blocks:
        if not block.output.strip():
            continue
        # "found nothing" output is not a finding
        blank_result = bool(NO_RESULT.search(block.output))
        named_hit = False
        for pattern, severity, title, regex in RULES:
            if not fnmatch.fnmatchcase(block.script_id, pattern):
                continue
            # the "*" rules are a safety net; skip them when a rule written for
            # this exact script has already reported something
            if pattern == "*" and named_hit:
                continue
            try:
                m = re.search(regex, block.output, re.I | re.M)
            except re.error:
                continue
            if not m:
                continue
            # A rule that only tests "did the script print something" must not
            # fire on a negative result. Rules with a real pattern still do -
            # they matched actual evidence, not just any output.
            if blank_result and regex in (r"\S", r"^\s*/\S+"):
                continue
            if pattern != "*":
                named_hit = True
            add(Finding(severity, title, block.where, matched_line(block.output, m),
                        "reported by %s" % block.script_id))

    # 2. the checks that need real logic
    for block in blocks:
        check_ssh_algorithms(block, add)
        check_ssl_cert(block, add)

    # 3. checks based on the service banner alone
    for port in ports.values():
        check_ssh_version(port, add)
        check_cleartext(port, add)

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity)
                                 if f.severity in SEVERITY_ORDER else 99,
                                 f.where, f.title))
    return findings


# ============================================================================
# 12.  WRITING THE REPORTS
# ============================================================================

BAR = "=" * 78


def section(title: str) -> str:
    return "\n%s\n %s\n%s\n" % (BAR, title, BAR)


def collect_raw(raw_dir: Path):
    """Re-read every XML this host produced - used for --report-only too."""
    ports: dict = {}
    blocks: list[ScriptBlock] = []
    for xml in sorted(raw_dir.glob("*.xml")):
        merge_ports(ports, parse_ports(xml))
        blocks.extend(parse_script_blocks(xml))
    return ports, blocks


def write_ip_report(target: str, out_dir: Path, raw_dir: Path, ports: dict) -> Path:
    """The per host file: <IP>.txt, holding the whole detailed scan."""
    path = out_dir / ("%s.txt" % safe_name(target))
    parts = [
        BAR,
        " nmap sweep report for %s" % target,
        " generated %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        " issues found for this host are listed in findings/%s.txt"
        % safe_name(target),
        BAR,
        section("OPEN PORTS"),
        format_port_table(ports) or "  no open ports found",
    ]

    titles = {
        "01_discovery_tcp": "PHASE 1 - TCP PORT DISCOVERY  (-Pn -T4 -p-)",
        "02_discovery_udp": "PHASE 1 - UDP PORT DISCOVERY  (-Pn -T4 -sU --top-ports 1000)",
        "03_detail":        "PHASE 2 - DETAIL SCAN  (-sV, default + vuln scripts)",
    }
    for nmap_file in sorted(raw_dir.glob("*.nmap")):
        stem = nmap_file.stem
        title = titles.get(stem)
        if title is None and stem.startswith("05_scripts_sweep"):
            title = ("PHASE 3 - SWEEP-UP SCRIPTS, part %s  (every remaining "
                     "script offered to nmap)" % stem.rsplit("_", 1)[-1])
        elif title is None:
            pretty = stem.split("_", 3)[-1].replace("_", " ")
            title = "PHASE 3 - SERVICE SCRIPTS  (%s)" % pretty
        try:
            body = nmap_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            body = "could not read %s: %s" % (nmap_file, exc)
        parts.append(section(title))
        parts.append(body)

    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path


def format_port_table(ports: dict) -> str:
    if not ports:
        return ""
    rows = ["  %-12s %-14s %-18s %s" % ("PORT", "STATE", "SERVICE", "VERSION"),
            "  " + "-" * 74]
    for port in sorted(ports.values(), key=lambda p: (p.proto, p.portid)):
        rows.append("  %-12s %-14s %-18s %s"
                    % (str(port), port.state, port.service or "unknown", port.banner))
    return "\n".join(rows)


def append_open_ports(target: str, ports: dict, out_dir: Path) -> None:
    """Append this host's ports to the detailed CSV. The readable open_ports.txt
    (one <IP>:<ports> line per host) is built from all results at the end."""
    with FILE_LOCK:
        with open(out_dir / "open_ports.csv", "a", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            for port in sorted(ports.values(), key=lambda p: (p.proto, p.portid)):
                writer.writerow([target, port.proto, port.portid, port.state,
                                 port.service, port.product, port.version])


def write_findings(target: str, findings: list[Finding], out_dir: Path) -> None:
    """Write the per-host findings file (findings/<IP>.txt). The combined
    findings.txt is built, grouped by issue, at the end of the run."""
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    tally = "  ".join("%s:%d" % (s, counts[s]) for s in SEVERITY_ORDER if counts[s])

    lines = [BAR, " findings for %s" % target,
             " generated %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"), BAR, ""]
    if not findings:
        lines.append("  Nothing flagged by the rules. Read %s.txt for the raw output."
                     % safe_name(target))
    else:
        lines.append("  %d issue(s)   %s" % (len(findings), tally))
        lines.append("")
        current = None
        for finding in findings:
            if finding.severity != current:
                current = finding.severity
                lines.append("")
                lines.append("  --- %s ---" % current)
            lines.append(finding.as_text())

    (out_dir / "findings" / ("%s.txt" % safe_name(target))).write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def split_where(where: str):
    """Port number from a finding's 'where' ('443/tcp' -> 443), or None (host)."""
    if "/" in where:
        num = where.partition("/")[0]
        if num.isdigit():
            return int(num)
    return None


def ip_sort_key(ip: str):
    """Sort real IPs numerically, hostnames/CIDRs after them by string."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, str(ip))


def compact_ports(ports: dict) -> str:
    """'22,80,443,161/udp' for a host's open ports ('none' if empty)."""
    tcp = sorted(p for (pr, p) in ports if pr == "tcp")
    udp = sorted(p for (pr, p) in ports if pr == "udp")
    parts = [str(p) for p in tcp] + ["%d/udp" % p for p in udp]
    return ",".join(parts) if parts else "none"


def write_combined_reports(out_dir: Path, results: dict, started: float) -> None:
    """
    Build the two readable combined files from every host's results:

      open_ports.txt  - one line per host:   <IP>:<port>,<port>,...
      findings.txt    - grouped BY FINDING (not by host): each issue lists every
                        <IP>:<ports> it affects, so e.g. all TLS 1.0 across the
                        whole scan is a single block.
    """
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---- open_ports.txt : <IP>:<ports> per host --------------------------------
    op = [BAR, " OPEN PORTS - all hosts - %s" % stamp, BAR, ""]
    for target in sorted(results, key=ip_sort_key):
        op.append("%s:%s" % (target, compact_ports(results[target]["ports"])))
    with FILE_LOCK:
        (out_dir / "open_ports.txt").write_text("\n".join(op) + "\n", encoding="utf-8")

    # ---- findings.txt : grouped by (severity, title) across all hosts ----------
    # groups: (severity, title) -> {"note", "hosts": {ip: set(ports)}, "hostlevel": set(ip)}
    groups: dict = {}
    grand = {s: 0 for s in SEVERITY_ORDER}
    hosts_flagged = set()
    for target in results:
        for f in results[target]["findings"]:
            if f.severity in grand:
                grand[f.severity] += 1
            hosts_flagged.add(target)
            g = groups.setdefault((f.severity, f.title),
                                  {"note": f.note, "hosts": {}, "hostlevel": set()})
            if not g["note"] and f.note:
                g["note"] = f.note
            port = split_where(f.where)
            if port is None:
                g["hostlevel"].add(target)
            else:
                g["hosts"].setdefault(target, set()).add(port)

    total = sum(grand.values())
    lines = [BAR, " FINDINGS - grouped by issue - all hosts",
             " generated %s" % stamp, BAR,
             " %s   (%d finding(s) across %d host(s))"
             % ("  ".join("%s:%d" % (s, grand[s]) for s in SEVERITY_ORDER),
                total, len(hosts_flagged))]

    ordered = sorted(groups.items(),
                     key=lambda kv: (SEVERITY_ORDER.index(kv[0][0])
                                     if kv[0][0] in SEVERITY_ORDER else 99, kv[0][1]))
    last_sev = None
    for (severity, title), g in ordered:
        if severity != last_sev:
            last_sev = severity
            lines.append("")
            lines.append("%s %s %s" % ("=" * 28, severity.upper(), "=" * 28))
        lines.append("")
        lines.append("[%s] %s ->" % (severity, title))
        if g["note"]:
            lines.append("    (%s)" % g["note"])
        for ip in sorted(g["hosts"], key=ip_sort_key):
            lines.append("    %s:%s" % (ip, ",".join(str(p) for p in sorted(g["hosts"][ip]))))
        for ip in sorted(g["hostlevel"], key=ip_sort_key):
            if ip not in g["hosts"]:
                lines.append("    %s" % ip)

    if total == 0:
        lines.append("")
        lines.append("  Nothing flagged by the rules across %d host(s)." % len(results))
    lines.append("")
    lines.append(" scan finished in %s" % human_time(time.time() - started))

    with FILE_LOCK:
        (out_dir / "findings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ============================================================================
# 13.  PUTTING THE FOUR PHASES TOGETHER FOR ONE HOST
# ============================================================================

class Sweep:
    def __init__(self, opts, runner: Runner, catalog: ScriptCatalog, out_dir: Path):
        self.opts = opts
        self.runner = runner
        self.catalog = catalog
        self.out_dir = out_dir
        self.excluded = [] if opts.include_all else [
            c for c in DEFAULT_EXCLUDED_CATEGORIES
            if not (c == "brute" and opts.include_brute)
            and not (c == "dos" and opts.include_dos)
            and not (c == "external" and opts.include_external)
        ]

    def scan_one(self, target: str) -> dict:
        raw_dir = self.out_dir / "raw" / safe_name(target)
        raw_dir.mkdir(parents=True, exist_ok=True)
        started = time.time()

        if self.opts.report_only:
            log("[%s] re-reading existing output" % target)
            ports, blocks = collect_raw(raw_dir)
        else:
            log("[%s] starting" % target)
            # Phase 1 - discovery
            ports = phase1_discovery(target, self.runner, raw_dir,
                                     do_udp=not self.opts.skip_udp)
            # Phase 2 - detail scan, started the moment discovery for THIS host
            # is done, without waiting for any other host
            if not self.opts.skip_detail:
                phase2_detail(target, self.runner, raw_dir, ports,
                              self.excluded, self.opts.safe_only)
            # Phase 3 - service specific scripts, then everything left over
            if not self.opts.skip_service_scripts:
                covered = phase3_service_scripts(target, self.runner, raw_dir, ports,
                                                 self.catalog, self.excluded,
                                                 self.opts.safe_only)
                # Phase 2 already ran the default and vuln categories.
                covered |= {n for n, c in self.catalog.scripts.items()
                            if c & {"default", "vuln"}}
                if not self.opts.no_sweep_up:
                    phase3b_sweep_remaining(target, self.runner, raw_dir, ports,
                                            self.catalog, self.excluded,
                                            self.opts.safe_only, covered)
            _, blocks = collect_raw(raw_dir)

        # Phase 4 - findings
        findings = analyse(target, ports, blocks)

        if not self.opts.dry_run:
            write_ip_report(target, self.out_dir, raw_dir, ports)
            append_open_ports(target, ports, self.out_dir)
            write_findings(target, findings, self.out_dir)

        tcp_n = sum(1 for k in ports if k[0] == "tcp")
        udp_n = sum(1 for k in ports if k[0] == "udp")
        log("[%s] finished in %s - %d TCP, %d UDP open, %d finding(s)"
            % (target, human_time(time.time() - started), tcp_n, udp_n, len(findings)))
        return {"ports": ports, "findings": findings}


# ============================================================================
# 14.  COMMAND LINE
# ============================================================================

def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="nmap_sweep.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Four phase nmap sweep over a text file of IP addresses.",
        epilog="""examples:
  python nmap_sweep.py targets.txt
  python nmap_sweep.py targets.txt -o results -t 4
  python nmap_sweep.py targets.txt --skip-udp --resume
  python nmap_sweep.py targets.txt --top-ports 3000      quick pass, not -p-
  python nmap_sweep.py targets.txt --dry-run             show the commands only
  python nmap_sweep.py targets.txt --report-only         rebuild reports from raw/

Only scan hosts you have permission to test.""")

    ap.add_argument("targets", help="text file with one IP (or CIDR / hostname) per line")
    ap.add_argument("-o", "--output", default="nmap_results", help="output directory")
    ap.add_argument("-t", "--threads", type=int, default=3,
                    help="how many hosts to scan at once (default 3)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_MIN,
                    help="minutes before a single nmap call is killed (default %d)"
                         % DEFAULT_TIMEOUT_MIN)
    ap.add_argument("--nmap-path", help="path to the nmap binary if it is not on PATH")

    ap.add_argument("--skip-udp", action="store_true", help="skip the UDP discovery scan")
    ap.add_argument("--skip-detail", action="store_true", help="skip phase 2")
    ap.add_argument("--skip-service-scripts", action="store_true", help="skip phase 3")
    ap.add_argument("--no-sweep-up", action="store_true",
                    help="in phase 3 run only the mapped service scripts, and skip "
                         "the final pass that offers every remaining script to nmap")
    ap.add_argument("--top-ports", type=int, metavar="N",
                    help="scan the top N TCP ports instead of all 65535")

    ap.add_argument("--safe-only", action="store_true",
                    help="only run scripts in nmap's 'safe' category")
    ap.add_argument("--include-brute", action="store_true",
                    help="also run *-brute scripts (slow, can lock accounts out)")
    ap.add_argument("--include-dos", action="store_true",
                    help="also run dos scripts (can crash the target)")
    ap.add_argument("--include-external", action="store_true",
                    help="also run scripts that query third party services")
    ap.add_argument("--include-all", action="store_true",
                    help="no category is excluded at all")

    ap.add_argument("--resume", action="store_true",
                    help="skip hosts that already have an <IP>.txt in the output dir")
    ap.add_argument("--report-only", action="store_true",
                    help="run no scans, just rebuild the reports from raw/")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the nmap commands without running them")
    ap.add_argument("--extra", default="",
                    help="extra nmap arguments, quoted, e.g. --extra \"-e eth0 --min-rate 500\"")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    global LOG_PATH
    opts = parse_args(argv)

    out_dir = Path(opts.output).expanduser().resolve()
    (out_dir / "findings").mkdir(parents=True, exist_ok=True)
    (out_dir / "raw").mkdir(parents=True, exist_ok=True)
    LOG_PATH = out_dir / "sweep.log"

    nmap_path = find_nmap(opts.nmap_path)
    targets = read_targets(opts.targets)

    log(BAR)
    log("nmap_sweep - %d target(s) from %s" % (len(targets), opts.targets))
    log("nmap       : %s" % nmap_path)
    log("output     : %s" % out_dir)

    if opts.top_ports:
        TCP_DISCOVERY_ARGS[:] = ["-Pn", "-n", "-T4", "--top-ports", str(opts.top_ports),
                                 "--open", "--min-rate", "1000", "--max-retries", "2"]
        log("TCP scan   : top %d ports (not -p-)" % opts.top_ports)

    privileged = is_privileged()
    if not privileged and not opts.skip_udp and not opts.report_only:
        log("NOT running as root/Administrator - UDP scanning needs raw sockets, "
            "so UDP is being skipped. Re-run elevated for UDP.")
        opts.skip_udp = True
    if not privileged:
        log("Tip: without root/Administrator nmap falls back to a slower TCP "
            "connect scan (-sT).")

    if opts.resume:
        before = len(targets)
        targets = [t for t in targets
                   if not (out_dir / ("%s.txt" % safe_name(t))).exists()]
        log("resume: skipping %d host(s) already done" % (before - len(targets)))
        if not targets:
            log("nothing left to do")
            return 0

    catalog = ScriptCatalog(nmap_path)
    extra = opts.extra.split() if opts.extra else []
    runner = Runner(nmap_path, opts.timeout, opts.dry_run, extra)
    sweep = Sweep(opts, runner, catalog, out_dir)
    log("excluded script categories: %s"
        % (", ".join(sweep.excluded) if sweep.excluded else "none"))
    log(BAR)

    # open_ports.txt and findings.txt are (re)built, grouped, from all results at
    # the end of the run; only the detailed CSV is written incrementally (so it
    # survives an interruption).
    if not opts.dry_run:
        csv_path = out_dir / "open_ports.csv"
        if not csv_path.exists():
            with open(csv_path, "w", encoding="utf-8", newline="") as fh:
                csv.writer(fh).writerow(["ip", "protocol", "port", "state",
                                         "service", "product", "version"])

    started = time.time()
    results: dict = {}
    workers = max(1, min(opts.threads, len(targets)))

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(sweep.scan_one, t): t for t in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    results[target] = future.result()
                except Exception as exc:                  # keep the sweep going
                    log("[%s] ERROR: %s: %s" % (target, type(exc).__name__, exc))
                    results[target] = {"ports": {}, "findings": []}
    except KeyboardInterrupt:
        log("interrupted - writing combined reports for the %d host(s) that finished"
            % len(results))
        if not opts.dry_run and results:
            write_combined_reports(out_dir, results, started)
        return 130

    if not opts.dry_run:
        write_combined_reports(out_dir, results, started)

    total_findings = sum(len(r["findings"]) for r in results.values())
    log(BAR)
    log("done in %s - %d host(s), %d finding(s)"
        % (human_time(time.time() - started), len(results), total_findings))
    if not opts.dry_run:
        log("  per host scan output : %s%s<IP>.txt" % (out_dir, os.sep))
        log("  all open ports       : %s" % (out_dir / "open_ports.txt"))
        log("  all findings         : %s" % (out_dir / "findings.txt"))
    log(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
