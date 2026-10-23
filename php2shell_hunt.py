#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_hunt.py - hunt for PHP2Shell traces on ISPConfig, cPanel,
DirectAdmin and single-site servers.

PHP2Shell covers two PHP engine bugs fixed on 2026-10-21
(8.2.35, 8.3.36, 8.4.27, 8.5.12; affected back to PHP 5.4):

CVE-2026-109618 "rawkey"     OOM while parsing $_POST, triggered by a huge
                             field name (>1 MB, urlencoded or multipart).
                             Error log signature:
                             "Allowed memory size ... in Unknown on line 0".
CVE-2026-109619 "php2shell"  stale global state via session.upload_progress.
                             Small multipart request (~450 bytes) with
                             PHPSESSID as a form field and a filename holding
                             <?php or serialized-object syntax.

Access logs don't store request bodies, so most of the detection is indirect:
User-Agent, published source IPs, status codes, POST bursts, PHP errors during
request startup, worker crashes, OOM killer and restarts. With --deep it also
checks session files, webroots, temp dirs, published sample hashes, processes
running from memfd and crontabs of web users (post-exploitation artifacts).

Read-only. Run as root. Python 3.6+, standard library only.

Examples:
  ./php2shell_hunt.py
  ./php2shell_hunt.py --env cpanel --since 2026-10-01 --deep --json report.json
  ./php2shell_hunt.py --env single --www /var/www/html --logs /var/log/nginx
  ./php2shell_hunt.py --sites example.com web12 --ioc 203.0.113.7 --md report.md

Exit code: 2 if there are CRIT/HIGH findings, 1 if the worst is MED, 0 otherwise.
"""

import argparse
import bz2
import glob
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Severities
# ---------------------------------------------------------------------------
SEVERITIES = ['INFO', 'LOW', 'MED', 'HIGH', 'CRIT']
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {'INFO': 0, 'LOW': 1, 'MED': 3, 'HIGH': 10, 'CRIT': 50}

def bump(sev):
    """Raise severity one level (used for bursts)."""
    return SEVERITIES[min(SEV_RANK[sev] + 1, len(SEVERITIES) - 1)]

class Rule(object):
    """Per-line signature. On each line the first matching rule wins."""
    __slots__ = ('id', 'sev', 'rx', 'desc', 'burst')
    def __init__(self, rid, sev, pattern, desc, burst=False):
        self.id = rid
        self.sev = sev
        self.rx = re.compile(pattern, re.IGNORECASE)
        self.desc = desc
        self.burst = burst  # True: a burst raises severity one level

# ---------------------------------------------------------------------------
# Environment profiles
# ---------------------------------------------------------------------------
ENV_PROFILES = {
    'ispconfig': {
        'www_default': '/var/www',
        'site_globs': ['*', 'clients/client*/web*'],
        'log_subdir': 'log',
        'web_subdir': 'web',
        'tmp_subdir': 'tmp',
        'global_logs': [
            ('_global', '/var/log/apache2/*'),
            ('_global', '/var/log/httpd/*'),
            ('_global', '/var/log/nginx/*'),
            ('_global', '/var/log/php*-fpm.log*'),
            ('_global', '/var/log/php*/*'),
            ('_global', '/var/log/php-fpm/*'),
            ('_global', '/opt/php*/var/log/*'),
            ('_ispconfig', '/var/log/ispconfig/httpd/*/*'),
            ('_system', '/var/log/kern.log*'),
            ('_system', '/var/log/syslog*'),
            ('_system', '/var/log/messages*'),
        ],
        'session_globs': ['/var/lib/php/sessions', '/var/lib/php*/sessions',
                          '/opt/php*/var/lib/php/sessions'],
        'web_user_re': r'^(?:web\d+|www-data|apache|nginx|httpd|wwwrun)$',
        'cron_note': 'ISPConfig puts its own cron jobs in /etc/cron.d/ispc_*',
    },
    'cpanel': {
        'www_default': '/home',
        'site_globs': ['*'],
        'log_subdir': None,
        'web_subdir': 'public_html',
        'tmp_subdir': 'tmp',
        'global_logs': [
            ('_global', '/usr/local/apache/logs/*'),
            ('_global', '/usr/local/apache/domlogs/*'),
            ('_global', '/var/log/httpd/*'),
            ('_global', '/var/log/nginx/*'),
            ('_global', '/var/cpanel/php-fpm/*/logs/*'),
            ('_global', '/opt/cpanel/ea-php*/root/var/log/php-fpm/*'),
            ('_cpanel', '/usr/local/cpanel/logs/*'),
            ('_system', '/var/log/kern.log*'),
            ('_system', '/var/log/syslog*'),
            ('_system', '/var/log/messages*'),
            ('_system', '/var/log/secure*'),
        ],
        'session_globs': ['/var/cpanel/php/sessions/*', '/tmp'],
        'web_user_re': r'^(?:nobody|cpanel|cpsess)$',
        'cron_note': 'cPanel user crontabs',
    },
    'directadmin': {
        'www_default': '/home',
        'site_globs': ['*/domains/*'],
        'log_subdir': None,
        'web_subdir': 'public_html',
        'tmp_subdir': None,
        'global_logs': [
            ('_global', '/var/log/httpd/domains/*'),
            ('_global', '/var/log/nginx/domains/*'),
            ('_global', '/var/log/httpd/*'),
            ('_global', '/var/log/nginx/*'),
            ('_directadmin', '/var/log/directadmin/*'),
            ('_system', '/var/log/kern.log*'),
            ('_system', '/var/log/syslog*'),
            ('_system', '/var/log/messages*'),
        ],
        'session_globs': ['/tmp'],
        'web_user_re': r'^(?:apache|nginx|webapps|access)$',
        'cron_note': 'DirectAdmin user crontabs',
    },
    'single': {
        'www_default': '/var/www',
        'site_globs': ['*'],
        'log_subdir': None,
        'web_subdir': '',
        'tmp_subdir': None,
        'global_logs': [
            ('_global', '/var/log/apache2/*'),
            ('_global', '/var/log/httpd/*'),
            ('_global', '/var/log/nginx/*'),
            ('_global', '/var/log/php*-fpm.log*'),
            ('_global', '/var/log/php*/*'),
            ('_global', '/var/log/php-fpm/*'),
            ('_system', '/var/log/kern.log*'),
            ('_system', '/var/log/syslog*'),
            ('_system', '/var/log/messages*'),
        ],
        'session_globs': ['/var/lib/php/sessions', '/var/lib/php*/sessions', '/tmp'],
        'web_user_re': r'^(?:www-data|apache|nginx|httpd|wwwrun|nobody)$',
        'cron_note': 'web user crontabs',
    },
}

FALLBACK_WEB_ROOTS = ['/var/www', '/home', '/srv', '/opt']
FALLBACK_LOG_DIRS = ['/var/log/apache2', '/var/log/httpd', '/var/log/nginx',
                     '/var/log']

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
COMMON_RULES = [
    Rule('WAF_PHP2SHELL', 'HIGH',
         r'ModSecurity.*(?:php2shell|rawkey|php-gh11189)|id "3[12]0100\d"',
         'WAF rule for PHP2Shell/rawkey fired'),
    Rule('IOC_C2', 'CRIT',
         r'(?<![\d.])(?:15\.235\.206\.16|92\.118\.112\.100|134\.199\.154\.64|117\.55\.202\.115|'
         r'150\.251\.112\.208)(?![\d.])|godofthunder\.st|botlesscucks\.st|gettingheadfromduckysmom\.st|'
         r'jackalsyn\.com',
         'PHP2Shell C2/staging host or domain (Ellio, phpup-2026)'),
    Rule('IOC_STRING', 'CRIT',
         r'rawkey|coalition-scanner|php2shell|php-session-startup-rce-poc|B8RAT/|'
         r'PHP2SHELL_OK|JACKALPOC|P2SMA?R?K',
         'Exploit/scanner string (UA, boundary or marker used by PHP2Shell tooling)'),
    Rule('IOC_BOUNDARY', 'HIGH',
         r'boundary=-{2,8}p2s|-{4,8}p2s(?:hell)?[0-9a-f]{6,}|--nucleiBoundary|boundary=-{4,8}atk\b',
         'Multipart boundary used by PHP2Shell tooling (needs a body-logging WAF)'),
]

LOG_RULES = COMMON_RULES + [
    Rule('OOM_UNKNOWN', 'CRIT',
         r'(?:Allowed memory size of \d+ bytes exhausted|Out of memory).{0,300}in Unknown on line 0|'
         r'PHP Request Startup:.{0,40}(?:Allowed memory size of \d+ bytes exhausted|Out of memory)|'
         r'Allowed memory size of \d+ bytes exhausted.{0,300}rfc1867\.c',
         'OOM during request startup ("in Unknown on line 0"), CVE-2026-109618 signature', True),
    Rule('TIMEOUT_UNKNOWN', 'HIGH',
         r'Maximum execution time of \d+ seconds? exceeded.{0,200}in Unknown on line',
         'Timeout outside script execution (request startup/shutdown)', True),
    Rule('HEAP_CORRUPTION', 'HIGH',
         r'zend_mm_heap corrupted|double free or corruption|free\(\): invalid|'
         r'malloc\(\): (?:corrupted|invalid|unaligned|memory corruption)|'
         r'corrupted size vs\. prev_size|munmap_chunk\(\): invalid pointer',
         'Heap corruption in PHP/Apache', True),
    Rule('APACHE_PARENT_SEGV', 'CRIT', r'AH00060',
         'Segfault in the Apache parent process'),
    Rule('APACHE_CHILD_CRASH', 'HIGH',
         r'AH0005[12]:.*exit signal (?:Segmentation fault|Abort(?:ed)?|Bus error|Illegal instruction|Floating point)',
         'Apache child killed by a signal (crash)', True),
    Rule('FPM_CHILD_CRASH', 'HIGH',
         r'child \d+ exited on signal (?:4|6|7|8|11)\b',
         'PHP-FPM worker killed by a signal (SIGSEGV/SIGABRT/...)', True),
    Rule('FPM_STARTUP_FAIL', 'HIGH',
         r'child \d+ exited with code (?:70|137)\b',
         'PHP-FPM worker exited with code 70/137 (request startup failure or OOM)', True),
    Rule('FPM_SIGKILL', 'MED',
         r'child \d+ exited on signal 9\b',
         'PHP-FPM worker got SIGKILL (OOM killer or request_terminate_timeout)', True),
    Rule('OOM_KILL_WEB', 'HIGH',
         r'(?:Out of memory: Killed process \d+ \(|oom-kill:.*task=)(?:php|apache2|httpd|lsphp|nginx)',
         'OOM killer killed a PHP/web process', True),
    Rule('SEGV_WEB', 'HIGH',
         r'(?:php|apache2|httpd|lsphp)[\w.\-]*\[\d+\]: (?:segfault at|general protection|trap )',
         'PHP/Apache segfault logged by the kernel', True),
    Rule('SYSTEMD_OOM', 'HIGH',
         r'(?:apache2|httpd|php[\w.\-]*fpm[\w.\-]*|nginx)\.service: .*(?:OOM killer|oom-kill)',
         'systemd: web service hit by the OOM killer', True),
    Rule('SYSTEMD_FAIL', 'MED',
         r'(?:apache2|httpd|php[\w.\-]*fpm[\w.\-]*|nginx)\.service: '
         r'(?:Main process exited, code=(?:killed|dumped)|Failed with result|Scheduled restart job)',
         'systemd: Apache/PHP-FPM crash or unclean restart', True),
    Rule('OOM_KILL_OTHER', 'LOW', r'Out of memory: Killed process|oom-kill:',
         'OOM killer (other process)', True),
    Rule('STARTUP_SESSION', 'HIGH',
         r'(?:PHP Request Startup|Unknown): Session (?:cookie|cache limiter) cannot be sent|'
         r'Session (?:cookie|cache limiter) cannot be sent.{0,300}in Unknown on line 0',
         'Session started during request startup (upload_progress path, CVE-2026-109619)', True),
    Rule('SESS_ID_BOUNDARY', 'CRIT', r'sess_\S{0,200}ndary=',
         'Session file name holds multipart boundary text (session ID taken from the body)'),
    Rule('SESSION_DECODE_STARTUP', 'HIGH',
         r'(?:PHP Request Startup|Unknown): Failed to decode session object',
         'Session decode failure during request startup (poisoned session, CVE-2026-109619)', True),
    Rule('SESS_ID_ILLEGAL_STARTUP', 'HIGH',
         r'(?:PHP Request Startup|Unknown): .{0,40}session id is too long or contains illegal characters',
         'Illegal session ID during request startup (PHPSESSID injected via multipart)', True),
    Rule('FCGI_BAD_RECORD', 'HIGH', r'upstream sent unexpected FastCGI record',
         'nginx got a corrupt FastCGI record from PHP-FPM (lab-observed during exploitation)', True),
    Rule('NESTING_LEVEL', 'HIGH', r'Input variable nesting level exceeded',
         'Field names with excessive nesting (a[][][]...)', True),
    Rule('MULTIPART_MALFORMED', 'MED',
         r'(?:Missing|Invalid) boundary in multipart|File Upload Mime headers garbled|'
         r'Maximum number of allowable file uploads|Multipart body parts limit exceeded',
         'Malformed or abusive multipart/form-data', True),
    Rule('POST_TOO_LARGE', 'MED', r'POST Content-Length of \d+ bytes exceeds the limit',
         'POST above post_max_size', True),
    Rule('BODY_TOO_LARGE', 'MED',
         r'is larger than the configured limit|Request body (?:no files )?data length is larger|'
         r'Failed to parse request body|request body exceeds',
         'Request body rejected for size or unparseable', True),
    Rule('INPUT_VARS', 'MED', r'Input variables exceeded',
         'Too many fields in the request (max_input_vars)', True),
    Rule('SESSION_DECODE', 'MED', r'Failed to decode session object',
         'Session decode failure', True),
    Rule('SESS_ID_ILLEGAL', 'LOW', r'session id is too long or contains illegal characters',
         'Illegal session ID (bots do this too)', True),
    Rule('FCGI_WORKER_GONE', 'LOW',
         r'upstream prematurely closed connection while reading response header|'
         r'AH01075: Error dispatching request|readv\(\) failed \(104: Connection reset by peer\) while reading upstream',
         'PHP backend dropped the request (crashed worker, correlate with OOM/SIGSEGV)', True),
    Rule('OOM_SCRIPT', 'MED', r'Allowed memory size of \d+ bytes exhausted',
         'memory_limit exhausted inside a script', True),
    Rule('OOM_PHP', 'HIGH', r'\bOut of memory\b',
         'Out of memory in PHP', True),
    Rule('GUARD_BLOCK', 'MED', r'hp_uploadprogress_guard',
         'Blocked by the hp_uploadprogress_guard module', True),
    Rule('MALFORMED_REQUEST', 'LOW',
         r'malformed request|request failed: error reading the headers|invalid method in request|'
         r'Invalid URI in request|Size of a request header field exceeds|request header exceeds|'
         r'Request header read timeout|client sent invalid|client sent too long',
         'Malformed HTTP request', True),
    Rule('EVAL_CODE', 'MED', r"eval\(\)'d code",
         'Error inside eval() code (possible webshell)'),
    Rule('PHP_STARTUP_ERR', 'LOW',
         r'PHP (?:Fatal error|Warning|Notice).{0,300}in Unknown on line 0|PHP Request Startup:',
         'PHP error during request startup (Unknown line 0)', True),
    Rule('PHP_FATAL', 'LOW', r'PHP Fatal error',
         'PHP Fatal error', True),
    Rule('FPM_MAX_CHILDREN', 'LOW', r'reached (?:pm\.)?max_children',
         'PHP-FPM pool saturated', True),
    Rule('APACHE_RESTART', 'INFO',
         r'AH00163|AH00169|AH00171|AH00493|AH00494|caught SIGTERM, shutting down|Graceful restart requested',
         'Apache start/stop/restart'),
    Rule('FPM_RESTART', 'INFO',
         r'fpm is running, pid|ready to handle connections|Terminating \.\.\.|exiting, bye-bye|Reloading in progress',
         'PHP-FPM start/stop/reload'),
    Rule('SYSTEMD_RESTART', 'INFO',
         r'(?:Started|Stopped|Reloaded|Stopping|Starting|Reloading) .{0,80}'
         r'(?:Apache|PHP .{0,20}FastCGI|php[\w.\-]*-fpm|nginx)',
         'Web service start/stop (systemd)'),
]

# ---------------------------------------------------------------------------
# Rules correlated per client IP in Hunter.finalize()
CORR_ANCHORS = {'INPUT_VARS', 'OOM_UNKNOWN'}
CORR_RULES = CORR_ANCHORS | {'STARTUP_SESSION', 'SESSION_DECODE_STARTUP', 'SESS_ID_ILLEGAL_STARTUP',
                              'SESS_ID_BOUNDARY'}

KNOWN_SOURCE_IPS = {
    '103.216.220.92', '31.223.184.166', '37.19.200.5', '134.209.159.64', '103.114.163.188',
    '95.217.98.37',
    '94.154.43.7', '38.180.45.91', '80.66.66.66', '217.60.242.76', '87.192.237.19',
    '34.19.34.88', '34.76.232.95', '34.76.218.47', '194.42.196.44',
    '45.198.224.169', '92.118.112.100', '152.233.51.47', '146.70.202.189', '185.5.70.233',
    '176.65.132.128', '122.97.242.167', '192.140.154.1', '47.238.232.123', '31.182.51.55',
    '98.80.11.91', '200.119.44.50', '45.136.71.89', '34.136.122.211', '77.237.246.73',
    '146.70.184.216', '38.207.136.217',
}

# ---------------------------------------------------------------------------
# Access logs (combined, with or without leading %v, optional trailing %I %O)
# ---------------------------------------------------------------------------
ACCESS_RE = re.compile(
    r'(?P<ip>[0-9A-Fa-f:.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
    r'(?: (?P<rin>\d+) (?P<rout>\d+))?')
REQ_LINE_RE = re.compile(r'^([A-Z]{3,10}) (\S+) HTTP/\d(?:\.\d)?$')
BODY_METHODS = {'POST', 'PUT', 'PATCH'}
REJECT_STATUS = {400, 411, 413, 415, 417, 431}
WEBSHELL_PARAM_RE = re.compile(
    r'[?&](?:cmd|exec|command|system|passthru|shell|shell_exec|popen|proc_open)=', re.I)
UPLOAD_PHP_RE = re.compile(
    r'/(?:wp-content/uploads|uploads?|files|images|media)/[^?#]*\.(?:php\d?|phtml|phar|pht)(?:[?#/]|$)', re.I)
SESSION_IN_URL_RE = re.compile(r'[?&](?:PHPSESSID|PHP_SESSION_UPLOAD_PROGRESS)=', re.I)
CLIENT_RE = re.compile(r'(\[client |client: |\[remote )([0-9A-Fa-f:.]+)')

# ---------------------------------------------------------------------------
# --deep: post-exploitation artifacts on disk
# ---------------------------------------------------------------------------
UPLOAD_DIR_NAMES = {'uploads', 'upload', 'files', 'images', 'img', 'media'}
PHP_EXT_RE = re.compile(r'\.(?:php\d?|phtml|phar|pht|phps)$', re.I)
SUSP_CODE_RE = re.compile(
    rb'eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|assert\s*\(|'
    rb'shell_exec\s*\(|passthru\s*\(|\bsystem\s*\(|proc_open\s*\(|popen\s*\(', re.I)
SESS_PHP_RE = re.compile(rb'<\?(?:php\b|=)', re.I)
SESS_MARKER_RE = re.compile(
    rb'P2SMA?R?K|POC_[0-9a-f]{8}|nuclei-probe|JACKALPOC|PHP2SHELL_OK|\|x\|i:1;|'
    rb'shell_upload|phtml_test|php5_test|dbl_test')
SESS_NAME_RE = re.compile(r'^sess_(?:leaksessionid\d*|attacksessionid\d*|nuclei.*|.*ndary=.*)$', re.I)
KNOWN_WEBSHELL_RE = re.compile(rb'Code by Bin|rootkit\.net\.cn|z-cg\.com')
KNOWN_SHA256 = {
    '0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486': 'Mirai-style loader (nfs)',
    '7133612558a5d0f257ca6bdb4f765453af9465bc5298acdcf33b5761b8c59aac': 'booter',
    '17758cf05e3376f8448dff926564e038b763b4a46668455e2ccb5ac0839e629c': 'PHP webshell (Code by Bin)',
    'dd98bf48899aa385035352688357742c73ddc5e47ec4ecc7d7b74c53c2e3ca3d': 'Go agent',
    '0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63': 'php-up-2026 PoC archive',
}
KNOWN_DROP_PATHS = ['/tmp/nfs', '/dev/shm/.cache.so', '/var/tmp/nfs']
TMP_DIRS = ['/tmp', '/var/tmp', '/dev/shm']
AUTO_PREPEND_RE = re.compile(r'auto_(?:prepend|append)_file', re.I)
SKIP_FILE_RE = re.compile(
    r'^(?:wtmp|btmp|lastlog|faillog)|\.(?:journal~?|pid|sock|db|zst|lz4)$', re.I)

# Reverse shell patterns in /proc/*/cmdline
REVSHELL_RE = re.compile(
    r'/dev/tcp/|/dev/udp/|fsockopen|nc\s+-[elp]|ncat\s+-[elp]|socat.*exec:|'
    r'bash\s+-i\s+>&|sh\s+-i\s+>&|python[23]?\s+-c\s+.*socket|'
    r'perl\s+-e\s+.*socket|ruby\s+-rsocket|php\s+-r\s+.*fsockopen', re.I)

PHP_BIN_GLOBS = ['/usr/bin/php*', '/usr/sbin/php-fpm*', '/usr/local/bin/php*',
                 '/usr/local/sbin/php-fpm*', '/opt/php*/bin/php', '/opt/php*/sbin/php-fpm',
                 '/usr/local/php*/bin/php', '/usr/local/php*/sbin/php-fpm']
PHP_BIN_NAME_RE = re.compile(r'^php(?:-fpm|-cgi)?(?:\d+(?:\.\d+)?)?$')
PHP_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
TS_CLF = re.compile(r'(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})')
TS_APACHE = re.compile(r'\[\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]')
TS_PHP = re.compile(r'\[(\d{1,2})-(\w{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})')
TS_ISO = re.compile(r'(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?')
TS_SYSLOG = re.compile(r'(\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ')

def _epoch(y, mo, d, h, mi, s, tz=None):
    try:
        dt = datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None
    if tz:
        if tz == 'Z':
            off = 0
        else:
            sign = -1 if tz[0] == '-' else 1
            hhmm = tz[1:].replace(':', '')
            off = sign * (int(hhmm[:2]) * 3600 + int(hhmm[2:4]) * 60)
        return (dt - datetime(1970, 1, 1)).total_seconds() - off
    return time.mktime(dt.timetuple())

def parse_clf(s):
    m = TS_CLF.match(s)
    if not m or m.group(2) not in MONTHS:
        return None
    return _epoch(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1)),
                  int(m.group(4)), int(m.group(5)), int(m.group(6)), m.group(7))

def parse_ts(line):
    head = line[:200]
    m = TS_APACHE.search(head)
    if m and m.group(1) in MONTHS:
        return _epoch(int(m.group(6)), MONTHS[m.group(1)], int(m.group(2)),
                      int(m.group(3)), int(m.group(4)), int(m.group(5)))
    m = TS_PHP.search(head)
    if m and m.group(2) in MONTHS:
        return _epoch(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1)),
                      int(m.group(4)), int(m.group(5)), int(m.group(6)))
    m = TS_ISO.match(head)
    if m:
        return _epoch(*[int(x) for x in m.groups()[:6]], tz=m.group(7))
    m = TS_SYSLOG.match(head)
    if m and m.group(1) in MONTHS:
        now = datetime.now()
        ts = _epoch(now.year, MONTHS[m.group(1)], int(m.group(2)),
                    int(m.group(3)), int(m.group(4)), int(m.group(5)))
        if ts and ts > time.time() + 86400:
            ts = _epoch(now.year - 1, MONTHS[m.group(1)], int(m.group(2)),
                        int(m.group(3)), int(m.group(4)), int(m.group(5)))
        return ts
    m = TS_CLF.search(head)
    if m:
        return parse_clf(head[m.start():])
    return None

def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else '?'

def max_window(sorted_ts, window):
    best = j = 0
    for i, t in enumerate(sorted_ts):
        while t - sorted_ts[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best

# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
def open_log(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    if path.endswith('.bz2'):
        return bz2.open(path, 'rt', encoding='utf-8', errors='replace')
    if path.endswith('.xz'):
        return lzma.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')

def read_head(path, limit=262144):
    try:
        with open(path, 'rb') as fh:
            return fh.read(limit)
    except (OSError, IOError):
        return b''

def client_ip(line):
    m = CLIENT_RE.search(line)
    if not m:
        return None
    s = m.group(2).rstrip(':.')
    if '.' in s and s.count(':') == 1:
        return s.split(':')[0]
    if m.group(1) == '[client ' and s.count(':') > 1:
        head, _, tail = s.rpartition(':')
        if tail.isdigit() and head:
            return head
    return s

def classify(path):
    name = os.path.basename(path).lower()
    if SKIP_FILE_RE.search(name):
        return None
    return 'access' if 'access' in name else 'log'

class Colors(object):
    CODES = {'CRIT': '\033[1;41;97m', 'HIGH': '\033[1;31m', 'MED': '\033[33m',
             'LOW': '\033[36m', 'INFO': '\033[2m', 'B': '\033[1m', 'D': '\033[2m', 'R': '\033[0m'}
    def __init__(self, enabled):
        self.on = enabled
    def __call__(self, key, text):
        return '%s%s%s' % (self.CODES[key], text, self.CODES['R']) if self.on else text

# ---------------------------------------------------------------------------
# Findings accumulator
# ---------------------------------------------------------------------------
class Agg(object):
    __slots__ = ('sev', 'desc', 'burst', 'count', 'ts', 'ips', 'samples', 'maxw', 'bursted')
    def __init__(self, sev, desc, burst):
        self.sev, self.desc, self.burst = sev, desc, burst
        self.count = 0
        self.ts = []
        self.ips = Counter()
        self.samples = []
        self.maxw = 0
        self.bursted = False

class Hunter(object):
    def __init__(self, args, profile):
        self.a = args
        self.profile = profile
        self.since = args.since_epoch
        self.aggs = {}
        self.post_ts = defaultdict(list)
        self.post_sites = defaultdict(set)
        self.seen_files = set()
        self.files_scanned = 0
        self.lines_scanned = 0
        self.req_bytes_seen = False
        self.warnings = []
        self.corr = defaultdict(list)
        self.post_5xx = defaultdict(list)

        extra = self._ioc_rules()
        self.access_rules = extra + COMMON_RULES
        self.log_rules = extra + LOG_RULES
        self.access_pre = re.compile('|'.join('(?:%s)' % r.rx.pattern for r in self.access_rules), re.I)
        self.log_pre = re.compile('|'.join('(?:%s)' % r.rx.pattern for r in self.log_rules), re.I)

    # -- setup ------------------------------------------------------------
    def _ioc_rules(self):
        iocs = list(self.a.ioc or [])
        if self.a.ioc_file:
            with open(self.a.ioc_file, encoding='utf-8') as fh:
                iocs += [l.strip() for l in fh if l.strip() and not l.startswith('#')]
        if not iocs:
            return []
        parts = []
        for x in iocs:
            p = re.escape(x)
            if re.fullmatch(r'[0-9A-Fa-f:.]+', x):
                p = r'(?<![\w.:])%s(?![\w.])' % p
            parts.append(p)
        return [Rule('IOC_CUSTOM', 'HIGH', '|'.join(parts), 'User-supplied IOC')]

    def warn(self, msg):
        self.warnings.append(msg)
        if self.a.verbose:
            print('  [!] %s' % msg, file=sys.stderr)

    # -- recording ---------------------------------------------------------
    def record(self, site, rid, sev, desc, burst, ts, ip, where, text):
        if rid in CORR_RULES and ip and ts is not None:
            self.corr[ip].append((ts, rid, site, where, text))
        key = (site, rid)
        agg = self.aggs.get(key)
        if agg is None:
            agg = self.aggs[key] = Agg(sev, desc, burst)
        agg.count += 1
        if ts is not None:
            agg.ts.append(ts)
        if ip:
            agg.ips[ip] += 1
        if len(agg.samples) < self.a.samples:
            agg.samples.append('%s: %s' % (where, text.strip()[:300]))

    def apply_rules(self, rules, site, where, line, ts, ip):
        for r in rules:
            if r.rx.search(line):
                self.record(site, r.id, r.sev, r.desc, r.burst, ts, ip, where, line)
                return r
        return None

    # -- log reading ---------------------------------------------------
    def iter_file(self, path):
        try:
            fh = open_log(path)
        except (OSError, IOError) as e:
            self.warn('cannot open %s: %s' % (path, e))
            return
        with fh:
            try:
                for n, line in enumerate(fh, 1):
                    yield n, line.rstrip('\n')
            except Exception as e:
                self.warn('read aborted in %s: %s' % (path, e))

    def scan_file(self, site, path, kind):
        rp = os.path.realpath(path)
        if rp in self.seen_files:
            return
        self.seen_files.add(rp)
        try:
            st = os.stat(rp)
        except OSError as e:
            self.warn('stat %s: %s' % (path, e))
            return
        if st.st_size == 0 or (self.since and st.st_mtime < self.since):
            return
        self.files_scanned += 1
        if self.a.verbose:
            print('  %-8s %s (%d KB)' % (kind, path, st.st_size // 1024), file=sys.stderr)
        self.scan_lines(site, path, self.iter_file(rp), kind)

    def scan_lines(self, site, label, lines, kind):
        since = self.since
        if kind == 'access':
            for lineno, line in lines:
                self.lines_scanned += 1
                m = ACCESS_RE.search(line)
                ts = parse_clf(m.group('ts')) if m else parse_ts(line)
                if since and ts is not None and ts < since:
                    continue
                ip = m.group('ip') if m else None
                where = '%s:%d' % (label, lineno)
                if self.access_pre.search(line):
                    self.apply_rules(self.access_rules, site, where, line, ts, ip)
                if ip in KNOWN_SOURCE_IPS:
                    self.record(site, 'IOC_KNOWN_IP', 'MED',
                                'Request from an IP published as a PHP2Shell sender (shared infra, verify)',
                                False, ts, ip, where, line)
                if m:
                    self.check_access(site, where, line, m, ts, ip)
        else:
            for lineno, line in lines:
                self.lines_scanned += 1
                if not self.log_pre.search(line):
                    continue
                ts = parse_ts(line)
                if since and ts is not None and ts < since:
                    continue
                ip = client_ip(line)
                self.apply_rules(self.log_rules, site, '%s:%d' % (label, lineno), line, ts, ip)
                if ip in KNOWN_SOURCE_IPS:
                    self.record(site, 'IOC_KNOWN_IP', 'MED',
                                'Request from an IP published as a PHP2Shell sender (shared infra, verify)',
                                False, ts, ip, '%s:%d' % (label, lineno), line)

    def check_access(self, site, where, line, m, ts, ip):
        req = m.group('req')
        status = int(m.group('status'))
        rm = REQ_LINE_RE.match(req)
        if rm:
            method, uri = rm.group(1), rm.group(2)
        else:
            method, uri = None, ''
        if not (req == '-' and status == 408):
            self.record(site, 'ACC_MALFORMED', 'LOW', 'Malformed or binary request line',
                        True, ts, ip, where, line)
        if method in BODY_METHODS:
            if ip and ts is not None:
                self.post_ts[ip].append(ts)
                self.post_sites[ip].add(site)
            if status >= 500:
                self.post_5xx[ip].append((ts, status, site, where, line))
        ua = m.group('ua') or ''
        if ua.startswith('fasthttp'):
            self.record(site, 'ACC_FASTHTTP_POST', 'MED',
                        'POST with the fasthttp UA (used by the 1 MB memory-pressure cluster, OffSeq)',
                        True, ts, ip, where, line)
        if status in REJECT_STATUS:
            self.record(site, 'ACC_POST_REJECTED', 'MED',
                        'POST/PUT rejected by the server (400/411/413/415/417/431)',
                        True, ts, ip, where, line)
        elif status >= 500:
            self.record(site, 'ACC_POST_5XX', 'LOW', 'POST/PUT answered with 5xx',
                        True, ts, ip, where, line)
        rin = m.group('rin')
        if rin is not None:
            self.req_bytes_seen = True
            if int(rin) >= self.a.big_post:
                self.record(site, 'ACC_BIG_POST', 'MED',
                            'POST of %d bytes or more (%%I field in LogFormat)' % self.a.big_post,
                            True, ts, ip, where, line)
        if uri:
            if WEBSHELL_PARAM_RE.search(uri):
                self.record(site, 'ACC_WEBSHELL_PARAM', 'MED',
                            'Typical webshell parameter in the URL (cmd=, exec=, system=...)',
                            False, ts, ip, where, line)
            if UPLOAD_PHP_RE.search(uri) and 200 <= status < 400:
                self.record(site, 'ACC_PHP_IN_UPLOADS', 'HIGH',
                            'Successful request to a .php inside an upload directory',
                            False, ts, ip, where, line)
            if SESSION_IN_URL_RE.search(uri):
                self.record(site, 'ACC_SESSION_IN_URL', 'LOW',
                            'PHPSESSID or PHP_SESSION_UPLOAD_PROGRESS in the URL',
                            False, ts, ip, where, line)

    # -- discovery -------------------------------------------------------
    def discover_sites(self):
        """[(name, real root, log dir)] adapted to the environment profile."""
        sites, seen = [], set()
        www = self.a.www
        p = self.profile

        if self.a.logs:
            # User specified log dirs manually: one pseudo-site per dir
            for ld in self.a.logs:
                ld = os.path.realpath(ld)
                if os.path.isdir(ld) and ld not in seen:
                    seen.add(ld)
                    sites.append((os.path.basename(ld) or '_logs', www, ld))
            return sites

        if self.a.env == 'single':
            if os.path.isdir(www):
                sites.append(('_single', os.path.realpath(www), None))
            return sites

        for sg in p['site_globs']:
            for d in sorted(glob.glob(os.path.join(www, sg))):
                if not os.path.isdir(d):
                    continue
                root = os.path.realpath(d)
                if root in seen:
                    continue

                if p['log_subdir']:
                    logdir = os.path.join(d, p['log_subdir'])
                    if not os.path.isdir(logdir):
                        continue
                else:
                    logdir = None

                seen.add(root)
                name = os.path.relpath(d, www)
                if self.a.sites and not ({name, os.path.basename(d), os.path.basename(root)}
                                         & set(self.a.sites)):
                    continue
                sites.append((name, root, logdir))
        return sites

    def scan_sites(self, sites):
        for name, _root, logdir in sites:
            if not logdir:
                continue
            try:
                entries = sorted(os.listdir(logdir))
            except OSError as e:
                self.warn('listdir %s: %s' % (logdir, e))
                continue
            for fn in entries:
                path = os.path.join(logdir, fn)
                kind = classify(path)
                if kind and os.path.isfile(path):
                    self.scan_file(name, path, kind)

    def scan_global(self):
        log_globs = list(self.profile['global_logs'])
        if self.a.logs:
            for ld in self.a.logs:
                log_globs.append(('_custom', os.path.join(ld, '*')))

        for site, pat in log_globs:
            for path in sorted(glob.glob(pat)):
                if not os.path.isfile(path):
                    continue
                if site.startswith('_') and site not in ('_global', '_system', '_journal', '_custom'):
                    parent = os.path.basename(os.path.dirname(path))
                    if self.a.sites and parent not in self.a.sites:
                        continue
                    label = parent
                else:
                    label = site
                kind = classify(path)
                if kind:
                    self.scan_file(label, path, kind)

    def scan_journal(self):
        if not shutil.which('journalctl'):
            return
        since = self.a.since_dt or (datetime.now() - timedelta(days=30))
        base = ['journalctl', '--no-pager', '-q', '-o', 'short-iso',
                '--since', since.strftime('%Y-%m-%d %H:%M:%S')]
        cmds = [base + ['-u', 'apache2*', '-u', 'httpd*', '-u', 'php*fpm*', '-u', 'nginx*',
                        '-u', 'lsphp*', '-u', 'lsws*']]
        if not (glob.glob('/var/log/kern.log*') or glob.glob('/var/log/messages*')):
            cmds.append(base + ['_TRANSPORT=kernel'])
        for cmd in cmds:
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     universal_newlines=True, errors='replace')
            except OSError as e:
                self.warn('journalctl: %s' % e)
                continue
            self.files_scanned += 1
            self.scan_lines('_journal', 'journalctl',
                            ((n, l.rstrip('\n')) for n, l in enumerate(p.stdout, 1)), 'log')
            p.wait()

    def scan_fallback(self):
        """When the expected panel layout is missing, walk common locations."""
        self.warn('expected layout not found, falling back to recursive search')
        seen = set()
        for d in FALLBACK_LOG_DIRS:
            rd = os.path.realpath(d)
            if os.path.isdir(rd) and rd not in seen:
                seen.add(rd)
                for dirpath, _dirs, files in os.walk(rd):
                    for fn in files:
                        path = os.path.join(dirpath, fn)
                        kind = classify(path)
                        if kind and os.path.isfile(path):
                            self.scan_file('_fallback', path, kind)
        for d in FALLBACK_WEB_ROOTS:
            rd = os.path.realpath(d)
            if os.path.isdir(rd) and rd not in seen:
                seen.add(rd)
                self.walk_webroot('_fallback', rd)

    # -- --deep ------------------------------------------------------------
    def deep_scan(self, sites):
        p = self.profile
        web_user_re = re.compile(p['web_user_re'])

        for name, root, _ in sites:
            if p['web_subdir']:
                web = os.path.join(root, p['web_subdir'])
            else:
                web = root
            self.walk_webroot(name, web if os.path.isdir(web) else root)

            if p['tmp_subdir']:
                tmp = os.path.join(root, p['tmp_subdir'])
                if os.path.isdir(tmp):
                    self.scan_tmp(name, tmp)

            ak = os.path.join(root, '.ssh', 'authorized_keys')
            if self.since and os.path.isfile(ak) and os.path.getmtime(ak) >= self.since:
                self.record(name, 'DEEP_AUTHKEYS', 'MED', 'Site authorized_keys modified inside the window',
                            False, os.path.getmtime(ak), None, ak, 'mtime ' + fmt_ts(os.path.getmtime(ak)))

        if not self.a.sites:
            seen = set()
            for sg in p['session_globs']:
                for d in glob.glob(sg):
                    rd = os.path.realpath(d)
                    if os.path.isdir(rd) and rd not in seen:
                        seen.add(rd)
                        self.scan_tmp('_sessions', rd)
            for f in glob.glob('/tmp/sess_*'):
                self.check_session('_sessions', f)

        self.scan_crontabs(web_user_re)
        self.scan_system_tmp(web_user_re)
        self.scan_memfd(web_user_re)
        self.scan_proc_cmdline()
        self.scan_ld_preload()
        self.scan_uid0()
        self.scan_shell_rc(web_user_re)

    def walk_webroot(self, site, web):
        for dirpath, _dirs, files in os.walk(web):
            rel = os.path.relpath(dirpath, web).lower().split(os.sep)
            in_upload = bool(set(rel) & UPLOAD_DIR_NAMES)
            for fn in files:
                full = os.path.join(dirpath, fn)
                low = fn.lower()
                if low in ('.user.ini', '.htaccess'):
                    self.check_ini(site, full)
                    continue
                if not PHP_EXT_RE.search(low):
                    # ELF binaries inside the webroot
                    if read_head(full, 4) == b'\x7fELF':
                        try:
                            mt = os.path.getmtime(full)
                        except OSError:
                            mt = None
                        self.record(site, 'DEEP_ELF_WEBROOT', 'HIGH',
                                    'ELF binary inside the webroot',
                                    False, mt, None, full, 'mtime ' + fmt_ts(mt))
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                mtime = st.st_mtime
                head = read_head(full)
                if KNOWN_WEBSHELL_RE.search(head) or self.known_hash(full, st):
                    self.record(site, 'DEEP_KNOWN_WEBSHELL', 'CRIT',
                                'Webshell published as dropped through PHP2Shell (Ellio)',
                                False, mtime, None, full, 'mtime ' + fmt_ts(mtime))
                    continue
                if in_upload:
                    if SUSP_CODE_RE.search(head):
                        self.record(site, 'DEEP_WEBSHELL_UPLOADS', 'CRIT',
                                    'PHP with webshell functions in an upload directory',
                                    False, mtime, None, full, 'mtime ' + fmt_ts(mtime))
                    else:
                        self.record(site, 'DEEP_PHP_UPLOADS', 'HIGH',
                                    'PHP file in an upload directory',
                                    False, mtime, None, full, 'mtime ' + fmt_ts(mtime))
                elif self.since and mtime >= self.since:
                    self.record(site, 'DEEP_RECENT_PHP', 'LOW',
                                'PHP file modified inside the --since window',
                                False, mtime, None, full, 'mtime ' + fmt_ts(mtime))

    def check_ini(self, site, path):
        data = read_head(path, 65536).decode('utf-8', 'replace')
        for n, line in enumerate(data.splitlines(), 1):
            if AUTO_PREPEND_RE.search(line) and not line.lstrip().startswith(('#', ';')):
                self.record(site, 'DEEP_AUTO_PREPEND', 'MED',
                            'auto_prepend/append_file in .htaccess/.user.ini (Wordfence uses it legitimately)',
                            False, None, None, '%s:%d' % (path, n), line)

    def scan_tmp(self, site, d):
        for dirpath, _dirs, files in os.walk(d):
            for fn in files:
                full = os.path.join(dirpath, fn)
                if fn.startswith('sess_'):
                    self.check_session(site, full)
                elif PHP_EXT_RE.search(fn):
                    mtime = os.path.getmtime(full)
                    self.record(site, 'DEEP_PHP_IN_TMP', 'HIGH', 'PHP file in the site tmp/session dir',
                                False, mtime, None, full, 'mtime ' + fmt_ts(mtime))

    def known_hash(self, path, st=None, limit=16 << 20):
        try:
            st = st or os.lstat(path)
            if not os.path.isfile(path) or st.st_size > limit:
                return None
            h = hashlib.sha256()
            with open(path, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            return KNOWN_SHA256.get(h.hexdigest())
        except (OSError, IOError):
            return None

    def scan_system_tmp(self, web_user_re):
        import pwd
        for pth in KNOWN_DROP_PATHS:
            if os.path.lexists(pth):
                mt = os.lstat(pth).st_mtime
                self.record('_system', 'DEEP_KNOWN_DROP', 'CRIT',
                            'Path used by the loader seen in PHP2Shell attacks (Ellio)',
                            False, mt, None, pth, 'mtime ' + fmt_ts(mt))
        for d in TMP_DIRS:
            for dirpath, dirs, files in os.walk(d):
                if dirpath.count(os.sep) - d.count(os.sep) >= 3:
                    dirs[:] = []
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    try:
                        st = os.lstat(full)
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except (OSError, KeyError):
                        continue
                    if not os.path.isfile(full):
                        continue
                    name = self.known_hash(full, st)
                    if name:
                        self.record('_system', 'DEEP_KNOWN_HASH', 'CRIT',
                                    'File matches a published PHP2Shell sample hash',
                                    False, st.st_mtime, None, full, '%s, owner %s' % (name, owner))
                    elif web_user_re.match(owner) and read_head(full, 4) == b'\x7fELF':
                        self.record('_system', 'DEEP_WEB_ELF_TMP', 'HIGH',
                                    'ELF binary owned by a web user in a temp dir',
                                    False, st.st_mtime, None, full,
                                    'owner %s, %d bytes, mtime %s' % (owner, st.st_size, fmt_ts(st.st_mtime)))

    def scan_memfd(self, web_user_re):
        for exe in glob.glob('/proc/[0-9]*/exe'):
            try:
                target = os.readlink(exe)
            except OSError:
                continue
            if target.startswith('/memfd:runc'):
                continue
            if target.startswith('/memfd:') or ('(deleted)' in target and
                target.startswith(('/tmp/', '/dev/shm/', '/var/tmp/'))):
                pid = exe.split('/')[2]
                try:
                    import pwd
                    owner = pwd.getpwuid(os.stat('/proc/' + pid).st_uid).pw_name
                except (OSError, KeyError):
                    owner = '?'
                try:
                    cmd = open('/proc/%s/cmdline' % pid, 'rb').read().replace(b'\0', b' ').decode('utf-8', 'replace')
                except (OSError, IOError):
                    cmd = ''
                web = bool(web_user_re.match(owner))
                self.record('_system', 'DEEP_FILELESS_PROC', 'CRIT' if web else 'HIGH',
                            'Running process executed from memfd or a deleted temp file'
                            + (' (web user)' if web else ''),
                            False, time.time(), None, 'pid ' + pid,
                            'owner %s  %s  cmd: %s' % (owner, target, cmd[:200]))

    def scan_proc_cmdline(self):
        """Reverse shells and suspicious commands in running processes."""
        for exe in glob.glob('/proc/[0-9]*/exe'):
            pid = exe.split('/')[2]
            try:
                with open('/proc/%s/cmdline' % pid, 'rb') as fh:
                    cmd = fh.read().replace(b'\0', b' ').decode('utf-8', 'replace').strip()
            except (OSError, IOError):
                continue
            if not cmd:
                continue
            if REVSHELL_RE.search(cmd):
                try:
                    import pwd
                    owner = pwd.getpwuid(os.stat('/proc/' + pid).st_uid).pw_name
                except (OSError, KeyError):
                    owner = '?'
                self.record('_system', 'DEEP_REVSHELL_PROC', 'CRIT',
                            'Running process with reverse shell pattern in cmdline',
                            False, time.time(), None, 'pid ' + pid,
                            'owner %s  cmd: %s' % (owner, cmd[:300]))

    def scan_ld_preload(self):
        """ld.so.preload hijacking."""
        try:
            with open('/etc/ld.so.preload', 'r') as fh:
                content = fh.read().strip()
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.record('_system', 'DEEP_LD_PRELOAD', 'CRIT',
                                    '/etc/ld.so.preload contains a library (rootkit indicator)',
                                    False, os.path.getmtime('/etc/ld.so.preload'), None,
                                    '/etc/ld.so.preload', line)
        except (OSError, IOError):
            pass

    def scan_uid0(self):
        """Extra UID 0 accounts."""
        try:
            import pwd
            for entry in pwd.getpwall():
                if entry.pw_uid == 0 and entry.pw_name != 'root':
                    self.record('_system', 'DEEP_UID0_ACCOUNT', 'CRIT',
                                'Non-root account with UID 0',
                                False, None, None, '/etc/passwd',
                                '%s uid=%d gid=%d home=%s shell=%s' % (
                                    entry.pw_name, entry.pw_uid, entry.pw_gid,
                                    entry.pw_dir, entry.pw_shell))
        except Exception:
            pass

    def scan_shell_rc(self, web_user_re):
        """Recently modified .bashrc/.profile/.bash_profile of web users."""
        if not self.since:
            return
        import pwd
        for entry in pwd.getpwall():
            if not web_user_re.match(entry.pw_name):
                continue
            for rc in ('.bashrc', '.profile', '.bash_profile'):
                path = os.path.join(entry.pw_dir, rc)
                if os.path.isfile(path) and os.path.getmtime(path) >= self.since:
                    self.record('_system', 'DEEP_WEB_RC_MODIFIED', 'MED',
                                'Shell rc file of a web user modified inside the window',
                                False, os.path.getmtime(path), None, path,
                                'user %s, mtime %s' % (entry.pw_name, fmt_ts(os.path.getmtime(path))))

    def check_session(self, site, path):
        data = read_head(path, 1 << 20)
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except OSError:
            return
        if SESS_NAME_RE.match(os.path.basename(path)):
            self.record(site, 'DEEP_SESSION_POC_ID', 'HIGH',
                        'Session ID used by public PHP2Shell PoCs, or holding boundary text',
                        False, mtime, None, path, 'mtime %s, %d bytes' % (fmt_ts(mtime), size))
        if SESS_MARKER_RE.search(data):
            self.record(site, 'DEEP_SESSION_MARKER', 'HIGH',
                        'Session holds a marker used by PHP2Shell tooling (P2SMARK, POC_, nuclei-probe...)',
                        False, mtime, None, path, 'mtime %s, %d bytes' % (fmt_ts(mtime), size))
        if SESS_PHP_RE.search(data):
            self.record(site, 'DEEP_SESSION_PHP', 'CRIT',
                        'Session file containing a PHP tag (LFI chain payload, CVE-2026-109619)',
                        False, mtime, None, path, 'mtime %s, %d bytes' % (fmt_ts(mtime), len(data)))
        elif b'upload_progress_' in data:
            self.record(site, 'DEEP_SESSION_UPLOAD', 'MED',
                        'Session with leftover upload_progress data (should not persist with cleanup=On)',
                        False, mtime, None, path, 'mtime %s, %d bytes' % (fmt_ts(mtime), len(data)))
        elif size > 256 * 1024:
            self.record(site, 'DEEP_SESSION_BIG', 'LOW',
                        'Unusually large session file (>256 KB)',
                        False, mtime, None, path, 'mtime %s, %d bytes' % (fmt_ts(mtime), size))

    def scan_crontabs(self, web_user_re):
        for f in glob.glob('/var/spool/cron/crontabs/*') + glob.glob('/var/spool/cron/*'):
            user = os.path.basename(f)
            if not os.path.isfile(f) or not web_user_re.match(user):
                continue
            body = read_head(f, 65536).decode('utf-8', 'replace')
            jobs = [l for l in body.splitlines() if l.strip() and not l.lstrip().startswith('#')]
            if jobs:
                mtime = os.path.getmtime(f)
                for j in jobs:
                    self.record('_system', 'DEEP_WEB_CRONTAB', 'MED',
                                'Web user crontab (%s, so this is unusual)' % self.profile['cron_note'],
                                False, mtime, None, f, j)

    # -- wrap-up -----------------------------------------------------------
    def finalize(self):
        for ip, tss in self.post_ts.items():
            if len(tss) < self.a.post_burst:
                continue
            tss.sort()
            n = max_window(tss, self.a.post_window)
            if n >= self.a.post_burst:
                self.record('_global', 'ACC_POST_BURST', 'MED',
                            'POST/PUT burst from a single IP', False, tss[0], ip, 'access logs',
                            '%s: %d POSTs in %d s (sites: %s)' % (
                                ip, n, self.a.post_window, ', '.join(sorted(self.post_sites[ip]))))

        win = self.a.corr_window
        for ip, evs in self.corr.items():
            evs.sort()
            for i, (ts, rid, site, where, text) in enumerate(evs):
                if rid not in CORR_ANCHORS:
                    continue
                near = {e[1] for e in evs if abs(e[0] - ts) <= win} - {rid}
                if near:
                    self.record(site, 'CHAIN_STARTUP', 'CRIT',
                                'Same client: %s together with %s within %ds (PHP2Shell startup sequence)'
                                % (rid, '/'.join(sorted(near)), win), True, ts, ip, where, text)
                    break

        for ip, evs in self.post_5xx.items():
            evs.sort()
            arms = [e for e in evs if e[1] == 500]
            fires = [e for e in evs if e[1] in (502, 503)]
            for a in arms:
                f = next((f for f in fires if 0 < f[0] - a[0] <= self.a.post_window), None)
                if f:
                    self.record(f[2], 'ACC_ARM_FIRE', 'HIGH',
                                'Same IP: POST answered 500 then POST answered %d (arm/fire pattern)' % f[1],
                                False, a[0], ip, f[3], f[4])
                    break

        for agg in self.aggs.values():
            if agg.ts:
                agg.ts.sort()
                agg.maxw = max_window(agg.ts, self.a.window)
            if agg.burst and agg.maxw >= self.a.burst:
                agg.sev = bump(agg.sev)
                agg.bursted = True

    def ip_ranking(self):
        score, detail = Counter(), defaultdict(Counter)
        sites = defaultdict(set)
        for (site, rid), agg in self.aggs.items():
            w = SEV_WEIGHT[agg.sev]
            for ip, n in agg.ips.items():
                score[ip] += w * min(n, 20)
                detail[ip][rid] += n
            sites[ip].add(site)
        return [(ip, s, detail[ip], sites[ip]) for ip, s in score.most_common(self.a.top_ips) if s > 0]

# ---------------------------------------------------------------------------
# PHP versions
# ---------------------------------------------------------------------------
def pkg_version(path):
    try:
        if shutil.which('dpkg'):
            r = subprocess.run(['dpkg', '-S', path], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
            if r.returncode == 0 and ':' in r.stdout:
                pkg = r.stdout.split(':')[0].strip()
                v = subprocess.run(['dpkg-query', '-W', '-f', '${Version}', pkg], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
                return '%s %s' % (pkg, v.stdout.strip())
        elif shutil.which('rpm'):
            r = subprocess.run(['rpm', '-qf', path], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
            if r.returncode == 0:
                return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ''

def php_versions():
    out, seen = [], set()
    for g in PHP_BIN_GLOBS:
        for p in sorted(glob.glob(g)):
            if not PHP_BIN_NAME_RE.match(os.path.basename(p)):
                continue
            rp = os.path.realpath(p)
            if rp in seen or not os.path.isfile(rp) or not os.access(rp, os.X_OK):
                continue
            seen.add(rp)
            try:
                r = subprocess.run([rp, '-v'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   universal_newlines=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            m = re.search(r'PHP (\d+)\.(\d+)\.(\d+)(\S*)', r.stdout)
            if not m:
                continue
            ver = tuple(int(x) for x in m.groups()[:3])
            fixed = PHP_FIXED.get(ver[:2])
            if fixed:
                vuln = ver < fixed
                status = ('VULNERABLE unless vendor backport (fixed in %d.%d.%d)' % fixed
                          if vuln else 'patched')
            elif ver[:2] < (8, 2):
                vuln, status = True, 'EOL: vulnerable unless vendor backport (affected since 5.4)'
            else:
                vuln, status = None, 'branch not listed in the advisory'
            out.append({'binary': p, 'real': rp, 'version': '.'.join(map(str, ver)) + m.group(4),
                        'package': pkg_version(rp), 'vulnerable': vuln, 'status': status})
    return out

def apache_php_modules():
    for cmd in (['apache2ctl', '-M'], ['apachectl', '-M'], ['httpd', '-M']):
        if shutil.which(cmd[0]):
            try:
                r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   universal_newlines=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            return [l.strip() for l in r.stdout.splitlines() if 'php' in l.lower()]
    return []

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def print_report(h, versions, modphp, nsites, c):
    a = h.a
    min_rank = SEV_RANK[a.min_sev]
    print(c('B', '== PHP2Shell hunt: %s, %s ==' % (socket.gethostname(), fmt_ts(time.time()))))
    print('Env: %s | Window: %s | files: %d | lines: %d | sites: %d' % (
        h.a.env,
        'since ' + fmt_ts(h.since) if h.since else 'all available',
        h.files_scanned, h.lines_scanned, nsites))

    if versions:
        print(c('B', '\n-- PHP binaries --'))
        for v in versions:
            tag = {True: c('HIGH', '[VULN]'), False: c('LOW', '[ OK ]'), None: '[ ?? ]'}[v['vulnerable']]
            pkg = ' (%s)' % v['package'] if v['package'] else ''
            print('%s %-28s %-12s %s%s' % (tag, v['binary'], v['version'], v['status'], pkg))

    if modphp:
        print(c('HIGH', 'mod_php loaded in Apache (%s): this is the SAPI with demonstrated exploitation.'
                % ', '.join(modphp)))

    findings = sorted(((site, rid, agg) for (site, rid), agg in h.aggs.items()),
                      key=lambda x: (-SEV_RANK[x[2].sev], -x[2].count, x[0]))

    per_site = defaultdict(Counter)
    for site, rid, agg in findings:
        per_site[site][agg.sev] += agg.count

    if per_site:
        print(c('B', '\n-- Per-site summary (events) --'))
        print('%-40s %6s %6s %6s %6s' % ('site', 'CRIT', 'HIGH', 'MED', 'LOW'))
        order = sorted(per_site, key=lambda s: tuple(-per_site[s][x] for x in ('CRIT', 'HIGH', 'MED', 'LOW')))
        for s in order:
            cnt = per_site[s]
            if not any(cnt[x] for x in ('CRIT', 'HIGH', 'MED', 'LOW')):
                continue
            print('%-40s %6d %6d %6d %6d' % (s[:40], cnt['CRIT'], cnt['HIGH'], cnt['MED'], cnt['LOW']))

    print(c('B', '\n-- Findings (>= %s) --' % a.min_sev))
    shown = 0
    for site, rid, agg in findings:
        if agg.sev == 'INFO' or SEV_RANK[agg.sev] < min_rank:
            continue
        shown += 1
        rng = '%s .. %s' % (fmt_ts(agg.ts[0]), fmt_ts(agg.ts[-1])) if agg.ts else ''
        burst = ' | max %d in %ds%s' % (agg.maxw, a.window, ' (BURST)' if agg.bursted else '') if agg.maxw > 1 else ''
        print('%s %s %s x%d %s%s' % (c(agg.sev, '[%s]' % agg.sev), c('B', site), rid, agg.count, rng, burst))
        print('       %s' % agg.desc)
        if agg.ips:
            print('       IPs: %s' % ', '.join('%s(%d)' % x for x in agg.ips.most_common(5)))
        for s in agg.samples:
            print(c('D', '       > %s' % s))

    if not shown:
        print('Nothing above the threshold.')

    restarts = [(site, rid, agg) for site, rid, agg in findings if agg.sev == 'INFO']
    if restarts:
        print(c('B', '\n-- Starts/stops/restarts (cross-check with the crashes above) --'))
        for site, rid, agg in restarts:
            last = ', '.join(fmt_ts(t) for t in agg.ts[-5:])
            print('%-14s %-16s x%-4d latest: %s' % (site[:14], rid, agg.count, last))

    ranking = h.ip_ranking()
    if ranking:
        print(c('B', '\n-- IPs with the most signals --'))
        for ip, score, det, sites in ranking:
            print('%-40s score %-5d %s  [%s]' % (
                ip, score, ', '.join('%s:%d' % x for x in det.most_common(4)), ', '.join(sorted(sites))[:80]))

    notes = []
    if not h.req_bytes_seen:
        notes.append('Access logs have no %I (bytes received), so POST size cannot be measured. '
                     'Adding "%I %O" to the LogFormat helps catch the rawkey pattern (>1 MB).')
    notes.append('Request bodies are not logged: PHPSESSID as a form field or <?php in a filename '
                 'are only visible with ModSecurity (SecAuditLog) or an IDS.')
    if h.warnings:
        notes.append('%d read warnings (use -v to see them).' % len(h.warnings))

    print(c('B', '\n-- Notes --'))
    for n in notes:
        print('- ' + n)

def to_json(h, versions, modphp):
    out = {'host': socket.gethostname(), 'generated': fmt_ts(time.time()),
           'environment': h.a.env,
           'since': fmt_ts(h.since) if h.since else None,
           'files_scanned': h.files_scanned, 'lines_scanned': h.lines_scanned,
           'php_binaries': versions, 'mod_php': modphp, 'findings': [], 'ips': [],
           'warnings': h.warnings}
    for (site, rid), agg in sorted(h.aggs.items(), key=lambda x: -SEV_RANK[x[1].sev]):
        out['findings'].append({
            'site': site, 'rule': rid, 'severity': agg.sev, 'description': agg.desc,
            'count': agg.count, 'first': fmt_ts(agg.ts[0]) if agg.ts else None,
            'last': fmt_ts(agg.ts[-1]) if agg.ts else None, 'max_in_window': agg.maxw,
            'burst': agg.bursted, 'top_ips': agg.ips.most_common(10), 'samples': agg.samples})
    for ip, score, det, sites in h.ip_ranking():
        out['ips'].append({'ip': ip, 'score': score, 'rules': dict(det), 'sites': sorted(sites)})
    return out

def to_markdown(h, versions, modphp):
    lines = []
    lines.append('# PHP2Shell Hunt Report')
    lines.append('')
    lines.append('Host: %s' % socket.gethostname())
    lines.append('Generated: %s' % fmt_ts(time.time()))
    lines.append('Environment: %s' % h.a.env)
    lines.append('Window: %s' % ('since ' + fmt_ts(h.since) if h.since else 'all available'))
    lines.append('Files scanned: %d | Lines scanned: %d' % (h.files_scanned, h.lines_scanned))
    lines.append('')

    if versions:
        lines.append('## PHP Binaries')
        lines.append('')
        lines.append('| Binary | Version | Status | Package |')
        lines.append('|--------|---------|--------|---------|')
        for v in versions:
            tag = {True: 'VULNERABLE', False: 'patched', None: 'unknown'}[v['vulnerable']]
            lines.append('| `%s` | %s | %s | %s |' % (v['binary'], v['version'], tag, v['package'] or '-'))
        lines.append('')

    if modphp:
        lines.append('**mod_php loaded in Apache (%s): this is the SAPI with demonstrated exploitation.**'
                     % ', '.join(modphp))
        lines.append('')

    findings = sorted(((site, rid, agg) for (site, rid), agg in h.aggs.items()),
                      key=lambda x: (-SEV_RANK[x[2].sev], -x[2].count, x[0]))

    if findings:
        lines.append('## Findings')
        lines.append('')
        for site, rid, agg in findings:
            if agg.sev == 'INFO':
                continue
            lines.append('### [%s] %s / %s (x%d)' % (agg.sev, site, rid, agg.count))
            lines.append('')
            lines.append('%s' % agg.desc)
            if agg.ts:
                lines.append('')
                lines.append('First: %s | Last: %s | Peak: %d in %ds' % (
                    fmt_ts(agg.ts[0]), fmt_ts(agg.ts[-1]), agg.maxw, h.a.window))
            if agg.ips:
                lines.append('')
                lines.append('Top IPs: %s' % ', '.join('%s (%d)' % x for x in agg.ips.most_common(5)))
            if agg.samples:
                lines.append('')
                lines.append('```')
                for s in agg.samples:
                    lines.append(s)
                lines.append('```')
            lines.append('')
    else:
        lines.append('## Findings')
        lines.append('')
        lines.append('No findings above the threshold.')
        lines.append('')

    ranking = h.ip_ranking()
    if ranking:
        lines.append('## IP Ranking')
        lines.append('')
        lines.append('| IP | Score | Rules | Sites |')
        lines.append('|----|-------|-------|-------|')
        for ip, score, det, sites in ranking:
            lines.append('| %s | %d | %s | %s |' % (
                ip, score,
                ', '.join('%s:%d' % x for x in det.most_common(4)),
                ', '.join(sorted(sites))[:80]))
        lines.append('')

    if h.warnings:
        lines.append('## Warnings')
        lines.append('')
        for w in h.warnings:
            lines.append('- %s' % w)
        lines.append('')

    return '\n'.join(lines)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def parse_since(s):
    m = re.fullmatch(r'(\d+)d', s)
    if m:
        return datetime.now() - timedelta(days=int(m.group(1)))
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError('invalid date: %s (YYYY-MM-DD[ HH:MM] or Nd)' % s)

def main():
    ap = argparse.ArgumentParser(
        description='Hunt for PHP2Shell (CVE-2026-109618/109619) traces on hosting servers.')
    ap.add_argument('--env', choices=sorted(ENV_PROFILES), default='ispconfig',
                    help='server environment (default: ispconfig)')
    ap.add_argument('--www', default=None, help='sites root (default depends on --env)')
    ap.add_argument('--logs', nargs='+', help='log directories to scan (overrides auto-discovery)')
    ap.add_argument('--sites', nargs='+', help='only these sites (domain or webN)')
    ap.add_argument('--since', type=parse_since,
                    help='only events since this date: YYYY-MM-DD[ HH:MM] or 30d')
    ap.add_argument('--deep', action='store_true',
                    help='also check sessions, webroots, temp dirs, known hashes, memfd processes, crontabs')
    ap.add_argument('--no-global', action='store_true', help='skip global and system logs')
    ap.add_argument('--no-journal', action='store_true', help='skip journalctl')
    ap.add_argument('--ioc', action='append', help='extra string or IP to look for (repeatable)')
    ap.add_argument('--ioc-file', help='file with one IOC per line')
    ap.add_argument('--window', type=int, default=600, help='burst window in seconds (600)')
    ap.add_argument('--burst', type=int, default=5, help='events in the window to count as a burst (5)')
    ap.add_argument('--post-window', type=int, default=900,
                    help='window for POST bursts and arm/fire pairs, seconds (900)')
    ap.add_argument('--corr-window', type=int, default=60,
                    help='window for the per-client startup sequence, seconds (60)')
    ap.add_argument('--post-burst', type=int, default=150, help='POSTs per IP in the window (150)')
    ap.add_argument('--big-post', type=int, default=1000000, help='large POST threshold in bytes (1000000)')
    ap.add_argument('--samples', type=int, default=3, help='sample lines per finding (3)')
    ap.add_argument('--top-ips', type=int, default=15, help='how many IPs to list in the ranking (15)')
    ap.add_argument('--min-sev', default='LOW', choices=SEVERITIES[1:], help='minimum severity to print')
    ap.add_argument('--json', help='also write the report as JSON')
    ap.add_argument('--md', help='also write the report as Markdown')
    ap.add_argument('--no-color', action='store_true', help='plain output, no ANSI colors')
    ap.add_argument('-v', '--verbose', action='store_true', help='print each file as it is read, plus read warnings')
    args = ap.parse_args()

    profile = ENV_PROFILES[args.env]
    if args.www is None:
        args.www = profile['www_default']

    args.since_dt = args.since
    args.since_epoch = time.mktime(args.since.timetuple()) if args.since else None

    if os.geteuid() != 0:
        print('Warning: without root not every log will be readable.', file=sys.stderr)

    h = Hunter(args, profile)
    sites = h.discover_sites()

    if not sites and not args.logs:
        print('No sites found under %s for env=%s, falling back to recursive search.'
              % (args.www, args.env), file=sys.stderr)
        h.scan_fallback()
    else:
        h.scan_sites(sites)

    if not args.no_global:
        h.scan_global()
    if not args.no_journal:
        h.scan_journal()
    if args.deep:
        h.deep_scan(sites)

    h.finalize()

    versions = php_versions()
    modphp = apache_php_modules()

    print_report(h, versions, modphp, len(sites), Colors(sys.stdout.isatty() and not args.no_color))

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(to_json(h, versions, modphp), fh, indent=2, ensure_ascii=False)
        print('\nJSON: %s' % args.json)

    if args.md:
        with open(args.md, 'w', encoding='utf-8') as fh:
            fh.write(to_markdown(h, versions, modphp))
        print('Markdown: %s' % args.md)

    top = max([SEV_RANK[agg.sev] for agg in h.aggs.values()] or [0])
    sys.exit(2 if top >= SEV_RANK['HIGH'] else 1 if top == SEV_RANK['MED'] else 0)

if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)