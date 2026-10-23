# php2shell_hunt

Quick and dirty hunting script for PHP2Shell (CVE-2026-109618 and CVE-2026-109619) on ISPConfig servers. It goes through the logs of every site under `/var/www/<site>/log`, plus the global Apache/nginx/PHP-FPM logs, syslog/kern.log and journald, and tells you if anything there looks like exploitation or the aftermath of it.

I wrote it because on a shared ISPConfig box you have dozens of vhosts, rotated and gzipped logs everywhere, several PHP versions installed side by side, and grepping by hand doesn't scale. It's read-only, stdlib only, Python 3.6+.

## Background

PHP fixed both bugs on 21 October 2026 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. The vulnerable code goes back to PHP 5.4, so anything older than those releases is affected unless your distro backported the fix.

- **CVE-2026-109618 ("rawkey")**: OOM corruption while PHP parses `$_POST`. The exploit sends a large urlencoded (or multipart) body with an absurdly long field name, memory runs out before any script runs, and request shutdown works on half-initialized state. The best log signature is a fatal error ending in `in Unknown on line 0`. The ASLR brute force before it shows up as hundreds of big POSTs from one IP and a pile of `AH00052` child crashes.
- **CVE-2026-109619 ("php2shell")**: stale global state through `session.upload_progress`. Tiny multipart requests (~450 bytes) with `PHPSESSID` sent as a form field and a filename carrying `<?php` or serialized objects, which end up in the session file.

mod_php is the confirmed exploitation path. PHP-FPM is harder to exploit but not safe.

It was being exploited before the patch. AWS saw the first attempt in their MadPot honeypots on 17 October, four days before disclosure, and by 21-22 October honeypot fleets were seeing the usual crowd: PoC scanners, a Mirai-style loader dropped to `/tmp/nfs`, a booter, a Go agent and a PHP webshell.

Patch first. This script is for finding out whether someone got in before you did.

## What it looks for

Access logs:

- Strings from public tooling anywhere in the line (CRIT): UAs `php2shell-scan/109618`, `php2shell-verify/1.0`, `Mozilla/5.0 (php-session-startup-rce-poc)`, `B8RAT/1.0`, and markers such as `PHP2SHELL_OK`, `JACKALPOC` or `P2SMARK`. Also `rawkey-rce` and `coalition-scanner-rawkey`, which I've seen mentioned but which aren't in any public report yet, so treat those two as unconfirmed
- C2 and staging hosts from the Ellio report (`15.235.206.16`, `92.118.112.100`, `godofthunder.st`...) anywhere in a log line, e.g. inside a `curl` payload in the URL (CRIT)
- Requests from IPs published as PHP2Shell senders by AWS, OffSeq and Ellio (MED). Most of them are VPS, cloud or anonymisation exits that carry other traffic too, so a hit means "look closer", not "owned"
- POSTs with the `fasthttp` UA, used by the 1 MB memory-pressure cluster OffSeq saw (MED)
- Arm/fire pattern: the same IP gets a 500 on a POST (the OOM) and later a 502/503 on another POST (the worker dying), within 15 minutes (HIGH)
- POST/PUT rejected with 400/411/413/415/417/431, and POSTs answered with 5xx
- POSTs over 1 MB, only if your LogFormat has `%I`
- Bursts of POSTs from a single IP (default 150 in 15 minutes)
- Malformed or binary request lines
- Successful hits on `.php` files under `uploads/`, `files/`, `images/`, `media/`
- Webshell-ish parameters in the URL (`cmd=`, `exec=`, `system=`...)

Error logs (Apache, nginx, PHP, PHP-FPM) and system logs:

- `Allowed memory size ... in Unknown on line 0` (CRIT) and plain memory exhaustion
- `PHP Request Startup: Session cookie cannot be sent ...`: a session started before any script ran, which only the upload_progress callback does. That's the CVE-2026-109619 path (HIGH)
- `Failed to decode session object` during request startup: a poisoned session being read back (HIGH; outside startup, MED)
- Illegal session IDs during request startup, i.e. a `PHPSESSID` injected through the multipart body (HIGH)
- A session file name containing `ndary=`: the session ID was taken from boundary junk in the body (CRIT; same idea as the SigmaHQ php2shell rule)
- The startup sequence from a single client: a `max_input_vars` warning or a startup OOM next to any of the session signals above, within 60 seconds (CRIT, `CHAIN_STARTUP`)
- PHP-FPM backends dropping requests: nginx `upstream sent unexpected FastCGI record` (HIGH, seen in lab exploitation), `upstream prematurely closed connection`, Apache `AH01075` (LOW, generic, useful next to an OOM)
- Multipart boundaries used by public tooling (`----p2shell<hex>`, `--nucleiBoundary`...), which only show up if ModSecurity logs bodies
- Timeouts outside script execution
- Heap corruption messages (`zend_mm_heap corrupted`, `double free`, `malloc():`...)
- Apache child crashes (`AH00051`/`AH00052` with SIGSEGV or SIGABRT), parent segfault (`AH00060`)
- PHP-FPM workers dying on signals, or exiting with code 70/137
- OOM killer hitting php/apache, kernel segfaults, systemd units failing or being OOM-killed
- Input nesting level exceeded, `max_input_vars` hits, `post_max_size` exceeded, broken multipart boundaries
- ModSecurity rules for PHP2Shell/rawkey firing, if you have them
- Apache and FPM starts/stops/reloads, listed as a timeline so you can line them up with the crashes

Repeated events of the same kind in the same site within 10 minutes get bumped one severity level.

With `--deep` it also checks the disk:

- Session files containing `<?php` or `<?=` (in ISPConfig each site keeps its sessions in its own `tmp/`), and leftover upload_progress data
- Session files with session IDs or progress values used by public PoCs (`attacksessionid0001`, `leaksessionid01`, `P2SMARK`, `POC_<hex>`, `nuclei-probe`...), and unusually large ones
- PHP files anywhere in the webroot carrying the webshell seen in the wild ("Code by Bin", `rootkit.net.cn`, `z-cg.com`) or matching a published SHA-256
- `/tmp`, `/var/tmp` and `/dev/shm`: the loader paths (`/tmp/nfs`, `/dev/shm/.cache.so`), files matching published sample hashes, and ELF binaries owned by a web user
- Running processes executed from `memfd` or from a deleted file in a temp dir (fileless payloads). CRIT if the owner is a web user, HIGH otherwise; EDR and telemetry agents sometimes do this legitimately, `runc` is skipped
- `.php` files in upload directories, CRIT if they contain the usual webshell functions
- `.php` files in the site's `tmp/`
- `auto_prepend_file`/`auto_append_file` in `.htaccess` and `.user.ini` (Wordfence uses this legitimately, so check before panicking)
- Crontabs for `webN`, `www-data`, `apache` or `nginx` users (ISPConfig puts its own cron jobs in `/etc/cron.d/ispc_*`)
- `authorized_keys` of a site modified inside the `--since` window
- Recently modified `.php` files anywhere in the webroot (LOW, for review)

It also lists the PHP binaries on the box (including the ones ISPConfig builds under `/opt/php-*`), their package version, whether they're below the fixed release, and whether mod_php is loaded.

## Usage

Run it as root, otherwise half the logs won't be readable.

```bash
# everything, all available history
sudo ./php2shell_hunt.py

# what I'd actually run on a box that was exposed
sudo ./php2shell_hunt.py --since 2026-08-01 --deep --json /root/php2shell.json

# only some sites, plus your own IOCs
sudo ./php2shell_hunt.py --sites example.com web12 --ioc 203.0.113.7 --ioc-file iocs.txt

# just the serious stuff, paged
sudo ./php2shell_hunt.py --min-sev HIGH | less -R
```

Options worth knowing:

| Option | Default | |
|---|---|---|
| `--www` | `/var/www` | Root where the ISPConfig sites live |
| `--sites` | all | Domain names or `webN` |
| `--since` | everything | `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` or `30d` |
| `--deep` | off | Disk checks described above |
| `--no-global` | off | Skip global and system logs |
| `--no-journal` | off | Skip journalctl |
| `--ioc`, `--ioc-file` | | Extra strings or IPs to look for |
| `--window`, `--burst` | 600 s, 5 | Burst detection per rule and site |
| `--post-window`, `--post-burst` | 900 s, 150 | POST flood per IP; the window is also used for arm/fire pairs |
| `--corr-window` | 60 s | Per-client startup sequence (`CHAIN_STARTUP`) |
| `--big-post` | 1000000 | Bytes, needs `%I` in the LogFormat |
| `--min-sev` | LOW | Minimum severity printed |
| `--json` | | Also dump the report as JSON |

Exit code is 2 if there's anything CRIT/HIGH, 1 if the worst is MED, 0 otherwise, so you can drop it in cron and alert on it.

## Output

You get, in this order: PHP binaries and their status, a per-site summary, findings sorted by severity (with first/last timestamp, peak count in the burst window, top IPs and a few sample lines), the restart timeline, and a ranking of IPs by how many signals they triggered across all sites.

## Limitations

Be realistic about what a log grep can see.

- Apache doesn't log request bodies. The php2shell variant (CVE-2026-109619) is basically invisible in a normal access log: small multipart request, short field names, nothing to size-gate on. The `PHPSESSID` form field and the `<?php` filename only show up if you run ModSecurity with an audit log, or an IDS in front.
- Without `%I` in the LogFormat there's no request size, so the "POST over 1 MB" check for rawkey doesn't work. Adding `%I %O` to the format is cheap and worth it.
- The exploit runs below the application, so your app logs may show nothing at all.
- Distro packages (Debian, Ubuntu, RHEL) sometimes backport fixes and keep the old version number. When a binary shows up as VULNERABLE, check the package changelog before trusting the label.
- The published IPs, UAs and hashes are what honeypots caught in the first days. Attackers rotate all of them, so the behavioural checks matter more than the IOC list.
- The arm/fire pattern and the `CHAIN_STARTUP` correlation need the client IP in the log line. PHP-FPM's own log doesn't have it; Apache and nginx error logs do.
- Ubuntu/Debian write the same kernel messages to `kern.log` and `syslog`, so system events may show up twice.
- It finds traces. A clean report doesn't prove nobody got in, and plenty of LOW/MED findings are just broken apps or noisy bots.

If you do find something: isolate the box, copy the web, PHP and system logs somewhere safe before restarting or rebuilding anything, then look for webshells, new files in webroots, cron jobs and new accounts. Rotate whatever secrets the affected sites could read (DB passwords, API keys, `.env`).

## Mitigation while you can't patch

Not a fix, PHP is clear that upgrading is the only complete one. In the php.ini or FPM pool of each affected version:

```ini
session.upload_progress.enabled = 0   ; CVE-2026-109619, keep it off even after patching if you don't use it
memory_limit = -1                     ; CVE-2026-109618, bound memory at the OS level instead
fatal_error_backtraces = 0            ; PHP 8.5 only
```

Restart every worker afterwards. Old workers keep the vulnerable state until they die. Also purge the session directories, because a session file poisoned before you deployed this can still be included later.

## References

- PHP security advisory, 21 Oct 2026: https://www.php.net/index.php#2026-10-21-5
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618): https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619): https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- Abstract Security, WAF rules and hunting guidance: https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
- Hackplayers, PHP2Shell analysis (startup warnings and crash sequence on Apache prefork + PHP 8.4.26): https://www.hackplayers.com/2026/10/php2shell-al-descubierto-analisis.html
- AWS, exploitation before disclosure in MadPot: https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
- OffSeq, first 48 hours on a honeypot fleet: https://offseq.com/en/research/php2shell-first-48-hours/
- Ellio, what was observed (loader, booter, webshell, hashes): https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/
- Detection guide (Blevene): https://gist.github.com/Blevene/472692937d05145d29d17dc3c6edc2a0
- Nextron, THOR coverage and the SigmaHQ php2shell rule: https://www.nextron-systems.com/2026/10/22/php2shell-detection-coverage-in-thor/
- rjmendez/phpup-2026, IOCs and rules: https://github.com/rjmendez/phpup-2026
- Lexsah/php2shell-detection, Sigma/YARA/Suricata/ModSecurity/Falco: https://github.com/Lexsah/php2shell-detection
- Beazley Security advisory: https://labs.beazley.security/advisories/BSL-A1233
- Sophos advisory: https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell
- hp_uploadprogress_guard (Hosted Power), useful to understand the OOM and stale-state paths: https://github.com/HOSTED-POWER/php_uploadprogress_guard
