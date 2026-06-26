# eyesharvester

A defensive surveillance-device discovery tool. Given an IP range, it identifies
exposed IP cameras, DVRs, and NVRs, then audits them for default credentials and
known critical CVEs so you can patch, isolate, or replace vulnerable devices.

Single-file Python 3, standard library only, no dependencies.

> **Authorized use only.** Active scanning, login attempts, and version probing
> against networks you do not own or have written permission to test is illegal
> in most jurisdictions. This tool is for asset owners and authorized
> engagements (pentests, internal audits, CTF labs).

---

## Features

- **Any IP range format**: CIDR of any mask (`203.0.113.0/24`, `10.0.0.0/8`),
  hyphen ranges (`203.0.113.1-203.0.113.50`), last-octet shorthand
  (`203.0.113.1-50`), or single IPs.
- **Two-phase detection**:
  1. Port scan over surveillance-relevant ports.
  2. Active protocol fingerprinting: HTTP(S) banners + login paths,
     RTSP `OPTIONS`, unauthenticated ONVIF SOAP, and vendor DVRIP control
     ports (Dahua 37777, XiongMai 34567).
- **Vendor classification** with confidence levels: Hikvision, Dahua, Axis,
  XiongMai/Sofia, Vivotek, Foscam, Reolink, Uniview, Amcrest, Bosch,
  Hanwha/Samsung, TP-Link/Tapo.
- **Output filters camera/DVR/NVR only** - non-surveillance hosts are dropped.
- **Default-credential audit** (`--check-creds`): tries the identified brand's
  factory default first, then generic pairs, capped at 3 attempts per host to
  stay under typical lockout thresholds.
- **Defensive hardening report** (`--harden`): maps the detected vendor to
  known critical CVEs (auth-bypass / RCE) with remediation guidance. No
  exploit code, identification only.
- **Live terminal UI**: progress bar (0-100%) per phase with a live counter of
  cameras found / devices identified / default creds cracked. Auto-disables
  when not a TTY so output piping stays clean.
- **Pipe-friendly modes**: `-q` for IPs-only on stdout, `-oJ file.json` for
  structured output.
- **Bounded streaming**: handles wide masks (a `/16` or larger) without
  exhausting memory, with a `--max-probes` guardrail.

---

## Install

```bash
git clone <your-private-repo-url> eyesharvester
cd eyesharvester
python3 eyesharvester.py --help
```

Requires Python 3.8+. No dependencies.

---

## Usage

### Basic detection

```bash
python3 eyesharvester.py 203.0.113.0/24
```

Sample output:
```
203.0.113.10     DVR/NVR [confirmed] - Hikvision
                 ports: 80/http,554/rtsp,8000/http

203.0.113.42     IP camera [likely] - unknown vendor
                 ports: 554/rtsp,8080/http
```

### IPs only (pipe-friendly)

```bash
python3 eyesharvester.py 203.0.113.0/24 -q > cameras.txt
```

### Confidence filter

```bash
python3 eyesharvester.py 203.0.113.0/24 -c confirmed     # only rock-solid hits
```

### Default-credential audit

Lockout-aware (3 attempts max per host, brand default tried first):

```bash
python3 eyesharvester.py 203.0.113.0/24 --check-creds
```

Throttle between attempts and use a custom wordlist:
```bash
python3 eyesharvester.py 203.0.113.0/24 --check-creds \
    --creds-file mylist.txt --cred-delay 1
```

### Hardening / CVE report

```bash
python3 eyesharvester.py 203.0.113.0/24 --harden
```

For each detected device prints reported firmware (best-effort), the known
critical CVEs affecting that vendor (e.g. Hikvision CVE-2021-36260, Dahua
CVE-2021-33044/45, Axis Devil's Ivy chain, XiongMai Mirai-class exposure),
severity, and remediation. A general hardening checklist is printed once.

### Full audit with JSON

```bash
python3 eyesharvester.py 203.0.113.0/24 --check-creds --harden -oJ audit.json
```

---

## Flags

| Flag | Purpose |
|---|---|
| `range` | CIDR of any mask, hyphen range, last-octet shorthand, or single IP |
| `-t, --timeout SECS` | Per-connection timeout (default 1.5) |
| `-w, --workers N` | Concurrent connections (default 200) |
| `-v, --verbose` | Print matched evidence for each detection |
| `-q, --ips-only` | Print only matching IPs to stdout, one per line |
| `-c, --min-confidence` | `possible` / `likely` / `confirmed` (default `possible`) |
| `--check-creds` | Phase 3: test factory default credentials |
| `--creds-file PATH` | Custom wordlist (`user:pass` per line) |
| `--no-vendor-first` | Don't prioritize the detected brand's default |
| `--max-cred-tries N` | Max attempts per host (default 3 = lockout safe) |
| `--cred-delay SECS` | Sleep between credential attempts |
| `--harden` | Defensive CVE / hardening report |
| `--no-progress` | Disable the live progress bar |
| `--max-probes N` | Refuse scans larger than this without `-y` |
| `-y, --yes` | Bypass `--max-probes` |
| `-oJ PATH` | Write JSON results to file |

---

## How detection works

For every host with a surveillance-relevant port open, the tool runs four
protocol probes and classifies on the combined evidence:

| Signal | Probe |
|---|---|
| **RTSP** | `OPTIONS rtsp://host:554/` - any valid `RTSP/1.0` reply, plus `Server:` header |
| **ONVIF** | Unauthenticated `GetSystemDateAndTime` SOAP to `/onvif/device_service` |
| **DVRIP** | Dahua `37777/37778`, XiongMai `34567/34599` open |
| **Web UI** | `Server:`, `WWW-Authenticate` realm, vendor login paths (`/ISAPI`, `/RPC2`, `/doc/page/login.asp`), title and body snippets |

Confidence levels:
- **confirmed** - vendor named, ONVIF responded, or DVRIP control port open
- **likely** - RTSP speaker or known camera webserver banner (Boa, GoAhead, App-webs, uc-httpd, ...)
- **possible** - any other positive signal

---

## Default-credential audit (lockout-aware)

Most DVR/NVR/cameras lock the account after about 3 failed logins. The
`--check-creds` phase is designed around that:

1. **Brand default first.** Hikvision -> `admin:12345`, Dahua/Amcrest -> `admin:admin`, Axis -> `root:pass`, XiongMai -> `admin:<blank>`, etc.
2. **Then generic fallbacks** (`admin:admin`, `root:root`, `666666:666666`, ...).
3. **Capped at 3 attempts** by default - the brand default lands within the lockout window.
4. **Stops on first success.** Reports `user:pass` per device.

The phase only runs against devices already classified as camera/DVR/NVR;
it never sprays login attempts at unidentified hosts. It also first checks
that the protected endpoint returns `401` - so it skips open pages and won't
false-positive.

> Default credentials on internet-exposed surveillance gear were the primary
> infection vector for the Mirai botnet and successors. This audit is a
> standard part of asset hygiene.

---

## Defensive hardening report

`--harden` maps each detected vendor to known critical advisories (CVE id,
severity, summary, fix) and prints a general hardening checklist (VPN/
segmentation, firmware updates, kill default creds, disable Telnet/UPnP/P2P,
firewall by source IP). The CVE table is curated and starts with the most
notorious advisories per vendor; cross-check exact firmware against the
vendor PSIRT and NVD for production use.

Vendor coverage:
- Hikvision: CVE-2021-36260 (Critical 9.8), CVE-2017-7921
- Dahua / Amcrest (OEM): CVE-2021-33044/45, CVE-2017-7925
- Axis: CVE-2018-10660/61/62, CVE-2017-9765 (Devil's Ivy)
- XiongMai/Sofia: Mirai-class OEM exposure
- Other recognized brands: generic PSIRT pointer

---

## Output

Default: human-readable report on stdout.
- `-q`: bare IP list on stdout, progress/status on stderr (pipe-friendly).
- `-oJ FILE`: structured JSON containing only positively detected devices,
  with vendor, confidence, ports, reported version, default credentials (if
  audited), and advisories (if `--harden`).

---

## Limitations

- TCP-connect scanning is not stealthy and will appear in target logs. For
  internet-scale ranges, use a SYN scanner (e.g. `masscan`) for discovery
  first, then run `eyesharvester` on the live hosts.
- Vendor / version extraction is heuristic and can be spoofed. Treat results
  as leads, not proof.
- The CVE advisory table is at vendor granularity, not exact firmware. Verify
  each device's specific build against the vendor PSIRT before declaring it
  vulnerable.
- No IPv6 yet.

---

## License

MIT - see [LICENSE](LICENSE).

---

## Disclaimer

This tool performs active network probing, authenticated login attempts, and
version fingerprinting. Use it only on networks you own or have explicit
written authorization to test. The author accepts no liability for misuse.
