# php2shell_hunt

Hunting tool for PHP2Shell (CVE-2026-109618 and CVE-2026-109619) traces on
ISPConfig, cPanel, DirectAdmin and single-site servers. It goes through the
logs of every site, plus the global Apache/nginx/PHP-FPM logs, syslog/kern.log
and journald, and tells you if anything there looks like exploitation or the
aftermath of it.

On a shared hosting box you have dozens of vhosts, rotated and gzipped logs
everywhere, several PHP versions installed side by side, and grepping by hand
doesn't scale. This tool handles the layout of each panel automatically, and
falls back to a recursive search when the expected directories are missing.
Read-only, stdlib only, Python 3.6+.

## Background

PHP fixed both bugs on 21 October 2026 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
The vulnerable code goes back to PHP 5.4, so anything older than those releases
is affected unless your distro backported the fix.

**CVE-2026-109618 ("rawkey"):** OOM corruption while PHP parses `$_POST`. The
exploit sends a large urlencoded (or multipart) body with an absurdly long
field name, memory runs out before any script runs, and request shutdown works
on half-initialized state. The best log signature is a fatal error ending in
`in Unknown on line 0`. The ASLR brute force before it shows up as hundreds of
big POSTs from one IP and a pile of `AH00052` child crashes.

**CVE-2026-109619 ("php2shell"):** stale global state through
`session.upload_progress`. Tiny multipart requests (~450 bytes) with
`PHPSESSID` sent as a form field and a filename carrying `<?php` or serialized
objects, which end up in the session file.

mod_php is the confirmed exploitation path. PHP-FPM is harder to exploit but
not safe.

It was being exploited before the patch. AWS saw the first attempt in their
MadPot honeypots on 17 October, four days before disclosure, and by 21-22
October honeypot fleets were seeing the usual crowd: PoC scanners, a
Mirai-style loader dropped to `/tmp/nfs`, a booter, a Go agent and a PHP
webshell.

Patch first. This tool is for finding out whether someone got in before you did.

## Supported environments

| `--env` | Web roots | Per-site logs | Session dirs |
|---------|-----------|---------------|--------------|
| `ispconfig` | `/var/www/<site>/web`, `/var/www/clients/clientN/webN/web` | `<site>/log/` | `<site>/tmp/`, `/var/lib/php*/sessions`, `/opt/php*/var/lib/php/sessions` |
| `cpanel` | `/home/<user>/public_html` | centralized: `/usr/local/apache/domlogs/`, `/var/cpanel/php-fpm/*/logs/` | `/var/cpanel/php/sessions/`, `/tmp` |
| `directadmin` | `/home/<user>/domains/<domain>/public_html` | centralized: `/var/log/httpd/domains/`, `/var/log/nginx/domains/`, `/var/log/directadmin/` | `/tmp` |
| `single` | `--www` (default `/var/www`) | global logs only | `/var/lib/php*/sessions`, `/tmp` |

If the expected layout is not found, the tool falls back to a recursive walk
of `/var/www`, `/home`, `/srv`, `/opt` and `/var/log`. You can also point it
at specific log directories with `--logs`.

## What it looks for

### Access logs

- Strings from public tooling anywhere in the line (CRIT): UAs
  `php2shell-scan/109618`, `php2shell-verify/1.0`,
  `Mozilla/5.0 (php-session-startup-rce-poc)`, `B8RAT/1.0`, and markers such
  as `PHP2SHELL_OK`, `JACKALPOC` or `P2SMARK`. Also `rawkey-rce` and
  `coalition-scanner-rawkey`, which aren't in any public report yet
- C2 and staging hosts from the Ellio report (`15.235.206.16`,
  `92.118.112.100`, `godofthunder.st`...) anywhere in a log line (CRIT)
- Requests from IPs published as PHP2Shell senders by AWS, OffSeq and Ellio
  (MED). Most of them are VPS, cloud or anonymisation exits that carry other
  traffic too, so a hit means "look closer", not "owned"
- POSTs with the `fasthttp` UA, used by the 1 MB memory-pressure cluster
  OffSeq saw (MED)
- Arm/fire pattern: the same IP gets a 500 on a POST (the OOM) and later a
  502/503 on another POST (the worker dying), within 15 minutes (HIGH)
- POSTs/PUTs rejected with 400/411/413/415/417/431, and POSTs answered with 5xx
- POSTs over 1 MB, only if your LogFormat has `%I`
- Bursts of POSTs from a single IP (default 150 in 15 minutes)
- Malformed or binary request lines
- Successful hits on `.php` files under `uploads/`, `files/`, `images/`, `media/`
- Webshell-ish parameters in the URL (`cmd=`, `exec=`, `system=`...)

### Error logs (Apache, nginx, PHP, PHP-FPM) and system logs

- `Allowed memory size ... in Unknown on line 0` (CRIT) and plain memory exhaustion
- `PHP Request Startup: Session cookie cannot be sent ...`: a session started
  before any script ran, which only the upload_progress callback does. That's
  the CVE-2026-109619 path (HIGH)
- `Failed to decode session object` during request startup: a poisoned session
  being read back (HIGH; outside startup, MED)
- Illegal session IDs during request startup, i.e. a `PHPSESSID` injected
  through the multipart body (HIGH)
- A session file name containing `ndary=`: the session ID was taken from
  boundary junk in the body (CRIT)
- The startup sequence from a single client: a `max_input_vars` warning or a
  startup OOM next to any of the session signals above, within 60 seconds
  (CRIT, `CHAIN_STARTUP`)
- PHP-FPM backends dropping requests: nginx `upstream sent unexpected FastCGI
  record` (HIGH, seen in lab exploitation), `upstream prematurely closed
  connection`, Apache `AH01075` (LOW, generic, useful next to an OOM)
- Multipart boundaries used by public tooling (`----p2shell<hex>`,
  `--nucleiBoundary`...), which only show up if ModSecurity logs bodies
- Timeouts outside script execution
- Heap corruption messages (`zend_mm_heap corrupted`, `double free`, `malloc():`...)
- Apache child crashes (`AH00051`/`AH00052` with SIGSEGV or SIGABRT), parent
  segfault (`AH00060`)
- PHP-FPM workers dying on signals, or exiting with code 70/137
- OOM killer hitting php/apache, kernel segfaults, systemd units failing or
  being OOM-killed
- Input nesting level exceeded, `max_input_vars` hits, `post_max_size`
  exceeded, broken multipart boundaries
- ModSecurity rules for PHP2Shell/rawkey firing, if you have them
- Apache and FPM starts/stops/reloads, listed as a timeline so you can line
  them up with the crashes

Repeated events of the same kind in the same site within 10 minutes get bumped
one severity level.

### With `--deep` it also checks the disk

- Session files containing `<?php` or `<?=`, and leftover upload_progress data
- Session files with session IDs or progress values used by public PoCs
  (`attacksessionid0001`, `leaksessionid01`, `P2SMARK`, `POC_<hex>`,
  `nuclei-probe`...), and unusually large ones
- PHP files anywhere in the webroot carrying the webshell seen in the wild
  ("Code by Bin", `rootkit.net.cn`, `z-cg.com`) or matching a published SHA-256
- `/tmp`, `/var/tmp` and `/dev/shm`: the loader paths (`/tmp/nfs`,
  `/dev/shm/.cache.so`), files matching published sample hashes, and ELF
  binaries owned by a web user
- Running processes executed from `memfd` or from a deleted file in a temp dir
  (fileless payloads). CRIT if the owner is a web user, HIGH otherwise; EDR
  and telemetry agents sometimes do this legitimately, `runc` is skipped
- Running processes with reverse shell patterns in their cmdline
  (`/dev/tcp/`, `nc -e`, `bash -i >&`, `python -c ...socket`, ...)
- `/etc/ld.so.preload` containing libraries (rootkit indicator)
- Non-root accounts with UID 0
- Shell rc files (`.bashrc`, `.profile`) of web users modified inside the
  `--since` window
- `.php` files in upload directories, CRIT if they contain the usual webshell
  functions
- `.php` files in the site's `tmp/`
- ELF binaries inside the webroot
- `auto_prepend_file`/`auto_append_file` in `.htaccess` and `.user.ini`
  (Wordfence uses this legitimately, so check before panicking)
- Crontabs for web users
- `authorized_keys` of a site modified inside the `--since` window
- Recently modified `.php` files anywhere in the webroot (LOW, for review)

It also lists the PHP binaries on the box, their package version, whether
they're below the fixed release, and whether mod_php is loaded.

## Usage

Run it as root, otherwise half the logs won't be readable.

```bash
# ISPConfig, everything, all available history (default)
sudo ./php2shell_hunt.py

# cPanel box, exposed since August, full disk check
sudo ./php2shell_hunt.py --env cpanel --since 2026-08-01 --deep --json /root/php2shell.json

# DirectAdmin
sudo ./php2shell_hunt.py --env directadmin --deep

# single site, custom webroot and log location
sudo ./php2shell_hunt.py --env single --www /var/www/html --logs /var/log/nginx

# only some sites, plus your own IOCs, Markdown report
sudo ./php2shell_hunt.py --sites example.com web12 --ioc 203.0.113.7 --ioc-file iocs.txt --md report.md

# just the serious stuff, paged
sudo ./php2shell_hunt.py --min-sev HIGH | less -R