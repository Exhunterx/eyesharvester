#!/usr/bin/env python3
"""
DVR / NVR / IP-camera detector.

Takes an IP range (CIDR of any mask, hyphen range, last-octet shorthand, or
a single IP) and does two passes:

 1. Scan a surveillance-focused port set.
 2. Actively fingerprint every host that has a relevant port open:
    - HTTP(S): Server header, WWW-Authenticate realm, login paths, body
    - RTSP  : OPTIONS probe + Server header (port 554 / 8554)
    - ONVIF : unauthenticated GetSystemDateAndTime SOAP probe
    - DVRIP : vendor control ports (Dahua 37777, XiongMai 34567)

 Each host is classified into a device type (camera / dvr-nvr) with a vendor
 guess, a confidence level, and the concrete evidence behind the call.

 Optional phase 3 (--check-creds) tests factory default credentials against
 the detected devices' web UIs (HTTP Basic/Digest), capped per host to limit
 lockouts. This is an active login attempt - authorized use only.

Examples:
 python3 eyesharvester.py 203.0.113.0/24
 python3 eyesharvester.py 198.51.100.0/22 -w 500 -oJ cams.json
 python3 eyesharvester.py 203.0.113.7 -v         # show evidence
 python3 eyesharvester.py 203.0.113.0/24 --check-creds  # + default-cred audit
 python3 eyesharvester.py 203.0.113.0/24 --stealth      # low-and-slow mode

Heuristic, not authoritative - confirm before acting. Only scan hosts you
own or are explicitly authorized to test.
"""

import argparse
import ipaddress
import json
import random
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# A common-looking browser UA used in --stealth so the tool stops self-identifying.
STEALTH_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
DEFAULT_UA = "eyesharvester/1.0"

# Probe paths used in normal mode. Stealth keeps only the bland root request.
HTTP_PATHS_FULL = ["/", "/doc/page/login.asp", "/cgi-bin/", "/onvif/device_service"]
HTTP_PATHS_STEALTH = ["/"]


class RateLimiter:
  """Simple thread-safe rate limiter: at most `rate` events per second,
  with +/- jitter*100% randomness. Disabled if rate <= 0."""

  def __init__(self, rate, jitter=0.0):
    import threading
    self.rate = float(rate or 0)
    self.jitter = max(0.0, min(1.0, float(jitter or 0.0)))
    self._next = 0.0
    self._lock = threading.Lock()

  def wait(self):
    if self.rate <= 0:
      return
    interval = 1.0 / self.rate
    if self.jitter:
      interval *= 1.0 + random.uniform(-self.jitter, self.jitter)
    with self._lock:
      now = time.monotonic()
      sleep_for = self._next - now
      if sleep_for > 0:
        time.sleep(sleep_for)
        now = time.monotonic()
      self._next = max(now, self._next) + interval


class Progress:
  """A single-line live progress bar + counters, drawn on stderr.

  Auto-disables when stderr isn't a TTY (so pipes/redirects stay clean) or
  when there's no work. Redraws are throttled to avoid flooding the terminal.
  Updates happen from the main thread's as_completed loop, so no locking.
  """

  def __init__(self, total, label, enabled=True):
    self.total = max(int(total), 1)
    self.label = label
    self.n = 0
    self.extra = ""
    self.enabled = bool(enabled) and total > 0 and sys.stderr.isatty()
    self._last = 0.0

  def update(self, inc=1, extra=None):
    self.n += inc
    if extra is not None:
      self.extra = extra
    self._render(False)

  def _render(self, force):
    if not self.enabled:
      return
    now = time.monotonic()
    if not force and now - self._last < 0.08:
      return
    self._last = now
    pct = min(100, int(self.n * 100 / self.total))
    width = 26
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    content = f"{self.label} [{bar}] {pct:3d}% {self.n}/{self.total}"
    if self.extra:
      content += f" | {self.extra}"
    cols = shutil.get_terminal_size((80, 20)).columns
    sys.stderr.write("\r" + content[:cols - 1].ljust(cols - 1))
    sys.stderr.flush()

  def finish(self, extra=None):
    if extra is not None:
      self.extra = extra
    self.n = self.total
    self._render(True)
    if self.enabled:
      sys.stderr.write("\n")
      sys.stderr.flush()


def parse_targets(spec):
  """Expand a range spec into (host_count, host_iterator).

  Accepts CIDR of any mask (203.0.113.0/24), hyphen range
  (203.0.113.1-203.0.113.50), last-octet shorthand (203.0.113.1-50),
  or a single IP. Returns an iterator so huge masks don't materialize.
  """
  spec = spec.strip()

  if "/" in spec: # CIDR, any prefix /0../32
    net = ipaddress.ip_network(spec, strict=False)
    if net.num_addresses > 2:
      return net.num_addresses - 2, net.hosts()
    return net.num_addresses, iter(net)

  if "-" in spec: # hyphen range
    start_s, end_s = (p.strip() for p in spec.split("-", 1))
    start = ipaddress.ip_address(start_s)
    if "." not in end_s: # last-octet shorthand
      base = start_s.rsplit(".", 1)[0]
      end = ipaddress.ip_address(f"{base}.{end_s}")
    else:
      end = ipaddress.ip_address(end_s)
    if int(end) < int(start):
      raise ValueError("range end is before range start")
    count = int(end) - int(start) + 1
    gen = (ipaddress.ip_address(i) for i in range(int(start), int(end) + 1))
    return count, gen

  return 1, iter([ipaddress.ip_address(spec)]) # single IP


def scan_port(ip, port, timeout):
  """Return (port, True) if a TCP connect succeeds, else (port, False)."""
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(timeout)
  try:
    return port, s.connect_ex((str(ip), port)) == 0
  except OSError:
    return port, False
  finally:
    s.close()

# Ports that surveillance gear commonly exposes, with a coarse hint.
CAMERA_PORTS = {
  23: "telnet", 80: "http", 81: "http", 82: "http", 83: "http", 88: "http",
  443: "https", 554: "rtsp", 1935: "rtmp",
  8000: "http", 8080: "http", 8081: "http", 8443: "https", 8554: "rtsp",
  8899: "http", 9000: "http",
  37777: "dahua-dvrip", 37778: "dahua-dvrip",
  34567: "xm-dvrip", 34599: "xm-dvrip",
}

HTTP_PORTS = {80, 81, 82, 83, 88, 8000, 8080, 8081, 8899, 9000}
TLS_PORTS = {443, 8443}
RTSP_PORTS = {554, 8554}
DVRIP_PORTS = {37777, 37778, 34567, 34599}

# Default probe config. Overridden by main() based on flags. Mutated globally
# so the existing probe signatures don't need an extra arg threaded through.
class ProbeConfig:
  user_agent = DEFAULT_UA
  http_paths = HTTP_PATHS_FULL
  stealth = False

# Backwards-compatibility alias for downstream patches/readers.
HTTP_PATHS = ProbeConfig.http_paths

# Vendor signatures matched (case-insensitive) against collected evidence text
# (status lines, headers, realms, body snippets). Patterns are substrings.
VENDOR_SIGNATURES = {
  "Hikvision": ["hikvision", "ds-2cd", "ds-7", "ds-2de", "/doc/page/login",
         "/isapi", "app-webs", "dvrdvs", "webs/", "ivms"],
  "Dahua": ["dahua", "dh-", "/rpc2", "/current_config", "webrtc-streaming",
       "dvrip", "web service"],
  "XiongMai/Sofia": ["uc-httpd", "netsurveillance", "dvr_h264", "sofia",
            "xmeye", "netdvr"],
  "Axis": ["axis", "/axis-cgi", "axis_", "vapix"],
  "Vivotek": ["vivotek", "vvtk", "/cgi-bin/viewer"],
  "Foscam": ["foscam", "netwave ip camera", "ipcamera_"],
  "Reolink": ["reolink", "/api.cgi"],
  "Uniview": ["uniview", "unv", "/lapi"],
  "Amcrest": ["amcrest"],
  "Bosch": ["bosch", "/rcp.xml"],
  "Hanwha/Samsung": ["hanwha", "wisenet", "samsung techwin", "snb-", "snp-"],
  "TP-Link/Tapo": ["tp-link", "tapo", "vigi"],
}

# Generic embedded webservers very common on cheap cameras/DVRs. Weaker signal
# than a vendor hit, but still moves a host into "likely camera/DVR".
CAMERA_WEBSERVERS = ["boa/", "goahead-webs", "thttpd", "jaws/", "router webserver",
           "app-webs", "webs/", "uc-httpd", "netwave", "hipcam",
           "dnvrs-webs", "h264dvr"]

# Words in titles/realms that suggest a recorder (DVR/NVR) vs a single camera.
RECORDER_HINTS = ["dvr", "nvr", "network video recorder", "digital video recorder",
         "embedded net dvr", "xvr", "recorder", "ivms", "netsurveillance"]
CAMERA_HINTS = ["ipcam", "ip camera", "ipcamera", "network camera", "webcam",
        "live view", "camera", "onvif"]


def http_probe(ip, port, timeout, use_tls):
  """Collect HTTP evidence: status line, Server, WWW-Authenticate, title, body.

  Returns a list of lowercase evidence strings (possibly empty).
  """
  evidence = []
  scheme_paths = ProbeConfig.http_paths if port in (80, 443, 8080, 8443, 8000) else ["/"]
  for path in scheme_paths:
    raw = _http_get(ip, port, path, timeout, use_tls)
    if not raw:
      continue
    head, _, body = raw.partition("\r\n\r\n")
    head_l = head.lower()
    # Status line
    first = head.split("\r\n", 1)[0]
    if first:
      evidence.append(first.lower())
    # Interesting headers
    for hdr in ("server:", "www-authenticate:", "location:", "set-cookie:"):
      m = re.search(rf"^{hdr}.*$", head_l, re.MULTILINE)
      if m:
        evidence.append(m.group(0).strip())
    # <title>
    mt = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if mt:
      evidence.append("title: " + mt.group(1).strip().lower()[:120])
    # A slice of body for vendor strings
    if body:
      evidence.append(body[:1500].lower())
    # Root path usually enough; only keep probing if root gave nothing useful
    if path == "/" and any(k in " ".join(evidence)
                for sig in VENDOR_SIGNATURES.values() for k in sig):
      break
  return evidence


def _http_get(ip, port, path, timeout, use_tls):
  """Raw HTTP GET returning decoded response head+body, or None."""
  try:
    sock = socket.create_connection((str(ip), port), timeout=timeout)
  except OSError:
    return None
  try:
    if use_tls:
      ctx = ssl._create_unverified_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      sock = ctx.wrap_socket(sock, server_hostname=str(ip))
    sock.settimeout(timeout)
    req = (f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n"
        f"User-Agent: {ProbeConfig.user_agent}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    sock.sendall(req.encode())
    chunks = []
    total = 0
    while total < 8192:
      try:
        data = sock.recv(2048)
      except OSError:
        break
      if not data:
        break
      chunks.append(data)
      total += len(data)
    return b"".join(chunks).decode("latin-1", "replace")
  except OSError:
    return None
  finally:
    try:
      sock.close()
    except OSError:
      pass


def rtsp_probe(ip, port, timeout):
  """Send an RTSP OPTIONS and return evidence strings if it speaks RTSP."""
  try:
    with socket.create_connection((str(ip), port), timeout=timeout) as s:
      s.settimeout(timeout)
      req = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
          f"CSeq: 1\r\nUser-Agent: {ProbeConfig.user_agent}\r\n\r\n")
      s.sendall(req.encode())
      data = s.recv(1024).decode("latin-1", "replace")
  except OSError:
    return []
  if "RTSP/1.0" not in data and "RTSP/2.0" not in data:
    return []
  ev = ["rtsp: speaks rtsp"]
  for line in data.split("\r\n"):
    l = line.lower()
    if l.startswith(("server:", "public:")):
      ev.append("rtsp " + l.strip())
  return ev


# Unauthenticated per ONVIF spec - a valid response confirms an ONVIF device.
ONVIF_SOAP = (
  '<?xml version="1.0" encoding="UTF-8"?>'
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
  '<s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
  '<tds:GetSystemDateAndTime/></s:Body></s:Envelope>'
)


def onvif_probe(ip, port, timeout, use_tls):
  """POST an unauthenticated ONVIF call; return evidence if it responds."""
  try:
    sock = socket.create_connection((str(ip), port), timeout=timeout)
  except OSError:
    return []
  try:
    if use_tls:
      ctx = ssl._create_unverified_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      sock = ctx.wrap_socket(sock, server_hostname=str(ip))
    sock.settimeout(timeout)
    body = ONVIF_SOAP.encode()
    req = (f"POST /onvif/device_service HTTP/1.1\r\nHost: {ip}\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    sock.sendall(req + body)
    data = b""
    while len(data) < 4096:
      try:
        chunk = sock.recv(2048)
      except OSError:
        break
      if not chunk:
        break
      data += chunk
    text = data.decode("latin-1", "replace").lower()
  except OSError:
    return []
  finally:
    try:
      sock.close()
    except OSError:
      pass
  if "getsystemdateandtimeresponse" in text or "onvif.org" in text:
    return ["onvif: device_service responded (onvif)"]
  return []


# --- Default-credential checking -------------------------------------------

# Per-brand factory defaults, ordered most-likely first. Because these devices
# typically lock the account after ~3 failed logins, the correct brand default
# MUST be tried before any generic guessing - that's the whole point of
# fingerprinting the vendor first.
VENDOR_DEFAULT_CREDS = {
  "Hikvision": [("admin", "12345"), ("admin", "123456")],
  "Dahua": [("admin", "admin"), ("admin", "123456")],
  "Amcrest": [("admin", "admin"), ("admin", "")],
  "XiongMai/Sofia": [("admin", ""), ("admin", "admin"), ("default", "tluafed")],
  "Axis": [("root", "pass"), ("root", "root")],
  "Vivotek": [("root", ""), ("root", "root")],
  "Foscam": [("admin", ""), ("admin", "admin")],
  "Reolink": [("admin", ""), ("admin", "admin")],
  "Uniview": [("admin", "123456"), ("admin", "admin")],
  "Hanwha/Samsung": [("admin", "4321"), ("admin", "1111111")],
  "Bosch": [("service", "service"), ("live", "live"), ("user", "user")],
  "TP-Link/Tapo": [("admin", "admin")],
}

# Generic fallbacks, tried only after the brand-specific defaults (and only if
# the attempt budget allows). "" means an empty password.
DEFAULT_CREDS = [
  ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
  ("admin", ""), ("admin", "password"), ("admin", "admin123"),
  ("admin", "1234"), ("admin", "9999"), ("admin", "4321"),
  ("admin", "111111"), ("admin", "123456789"), ("admin", "pass"),
  ("admin", "meinsm"), ("admin", "system"), ("admin", "ipcam"),
  ("root", "root"), ("root", "12345"), ("root", "pass"),
  ("root", "admin"), ("root", ""), ("root", "ikwd"),
  ("service", "service"), ("supervisor", "supervisor"),
  ("user", "user"), ("guest", "guest"),
  ("666666", "666666"), ("888888", "888888"),
]


def order_creds(vendor, generic):
  """Brand-specific defaults first, then generic - de-duplicated, order kept.

  With a ~3-attempt lockout, this guarantees the most probable password for
  the identified brand is tried within the first attempt(s).
  """
  seen = set()
  ordered = []
  for pair in VENDOR_DEFAULT_CREDS.get(vendor, []) + list(generic):
    if pair not in seen:
      seen.add(pair)
      ordered.append(pair)
  return ordered

# Protected endpoint per vendor that returns 200 only with valid creds.
# value: (path, body_marker_or_None). None marker => any 200 counts.
CRED_ENDPOINTS = {
  "Hikvision": ("/ISAPI/Security/userCheck", b"statusValue"),
  "Dahua": ("/cgi-bin/magicBox.cgi?action=getSystemInfo", b"="),
  "Amcrest": ("/cgi-bin/magicBox.cgi?action=getSystemInfo", b"="),
  "Axis": ("/axis-cgi/param.cgi?action=list&group=root.Brand", b"root.Brand"),
  "Vivotek": ("/cgi-bin/viewer/getparam.cgi", b"="),
  "Reolink": ("/cgi-bin/api.cgi?cmd=GetDevInfo", b"value"),
}
# Web ports to try for the login check, in preference order.
WEB_PREF_PLAIN = [80, 8000, 8080, 81, 82, 83, 88, 8081, 8899, 9000]
WEB_PREF_TLS = [443, 8443]


def _web_target(open_ports):
  """Pick the best (port, use_tls) web endpoint for a login check."""
  for p in WEB_PREF_PLAIN:
    if p in open_ports:
      return p, False
  for p in WEB_PREF_TLS:
    if p in open_ports:
      return p, True
  return None


def _plain_status(url, timeout, ctx):
  """HTTP status of an unauthenticated GET, or None."""
  req = urllib.request.Request(url, headers={"User-Agent": ProbeConfig.user_agent})
  try:
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
      return r.getcode()
  except urllib.error.HTTPError as e:
    return e.code
  except (urllib.error.URLError, OSError, ValueError):
    return None


def _auth_get(url, user, pwd, timeout, ctx):
  """GET url with Basic+Digest auth handlers. Returns (status, body)."""
  mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
  mgr.add_password(None, url, user, pwd)
  handlers = [urllib.request.HTTPBasicAuthHandler(mgr),
        urllib.request.HTTPDigestAuthHandler(mgr)]
  if ctx is not None:
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
  opener = urllib.request.build_opener(*handlers)
  req = urllib.request.Request(url, headers={"User-Agent": ProbeConfig.user_agent})
  try:
    with opener.open(req, timeout=timeout) as r:
      return r.getcode(), r.read(512)
  except urllib.error.HTTPError as e:
    return e.code, b""
  except (urllib.error.URLError, OSError, ValueError):
    return None, b""


def check_default_creds(ip, open_ports, vendor, timeout, creds, max_tries, delay,
            vendor_first=True):
  """Try default creds against a host's web UI. Returns list of 'user:pass'.

  Tries the identified brand's factory default(s) FIRST, then generic pairs,
  so the most probable password lands inside the lockout window. Stops at the
  first working pair and never exceeds max_tries attempts.
  """
  target = _web_target(open_ports)
  if not target:
    return []
  port, use_tls = target
  ctx = None
  if use_tls:
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
  base = f"{'https' if use_tls else 'http'}://{ip}:{port}"
  path, marker = CRED_ENDPOINTS.get(vendor, ("/", None))
  url = base + path

  # Confirm the endpoint actually demands auth; if it returns 200 with no
  # creds we can't tell success from an open page, so skip to avoid noise.
  baseline = _plain_status(url, timeout, ctx)
  if baseline != 401:
    return []

  attempts = order_creds(vendor, creds) if vendor_first else list(creds)
  found = []
  for i, (user, pwd) in enumerate(attempts):
    if i >= max_tries:
      break
    status, body = _auth_get(url, user, pwd, timeout, ctx)
    ok = status == 200 and (marker is None or marker in body)
    if ok:
      found.append(f"{user}:{pwd or '<blank>'}")
      break # one valid credential is enough; stop hammering
    if delay:
      time.sleep(delay)
  return found


def load_creds(path):
  """Load user:pass pairs from a file, or return the built-in list."""
  if not path:
    return DEFAULT_CREDS
  pairs = []
  with open(path) as fh:
    for line in fh:
      line = line.rstrip("\n")
      if not line or line.startswith("#"):
        continue
      user, _, pwd = line.partition(":")
      pairs.append((user, pwd))
  return pairs or DEFAULT_CREDS


# --- Defensive CVE/hardening advisories ------------------------------------
#
# Identification only: maps the detected VENDOR to well-known critical
# advisories so an owner can verify firmware and patch / isolate the device.
# No exploit code, no proof-of-concept - remediation guidance only.

KNOWN_CVES = {
  "Hikvision": [
    {"id": "CVE-2021-36260", "severity": "Critical (9.8)",
     "summary": "Unauthenticated web-server command injection across a wide "
          "range of cameras and NVRs (full device compromise).",
     "fix": "Apply Hikvision's Sept-2021 (or later) firmware. Do not expose "
        "the web UI to the internet."},
    {"id": "CVE-2017-7921", "severity": "Critical",
     "summary": "Improper authentication lets unauthenticated users read "
          "device data / config on many older IP cameras.",
     "fix": "Update to patched firmware; if the model is end-of-life, replace it."},
  ],
  "Dahua": [
    {"id": "CVE-2021-33044 / CVE-2021-33045", "severity": "Critical",
     "summary": "Identity-authentication bypass in the login process on many "
          "Dahua IP cameras / NVRs.",
     "fix": "Update to Dahua's 2021+ patched firmware; restrict network exposure."},
    {"id": "CVE-2017-7925", "severity": "High",
     "summary": "Credential/hash disclosure in older firmware allowing "
          "password recovery.",
     "fix": "Update firmware and rotate all credentials."},
  ],
  "Amcrest": [ # Amcrest devices are largely Dahua OEM
    {"id": "CVE-2021-33044 / CVE-2021-33045 (Dahua OEM)", "severity": "Critical",
     "summary": "Shares the Dahua authentication-bypass exposure on affected "
          "firmware.",
     "fix": "Apply Amcrest/Dahua patched firmware; keep off the public internet."},
  ],
  "Axis": [
    {"id": "CVE-2018-10660/10661/10662", "severity": "Critical",
     "summary": "Chain of flaws in older AXIS OS enabling unauthenticated "
          "remote code execution.",
     "fix": "Update to fixed AXIS OS; subscribe to AXIS security advisories."},
    {"id": "CVE-2017-9765 (Devil's Ivy)", "severity": "High",
     "summary": "gSOAP/ONVIF stack overflow affecting many ONVIF devices.",
     "fix": "Update firmware to a build with the patched gSOAP library."},
  ],
  "XiongMai/Sofia": [
    {"id": "XiongMai OEM (Mirai-class) exposure", "severity": "Critical",
     "summary": "XM-based OEM DVRs/cameras ship hardcoded accounts and a "
          "control service (often tcp/9530, 34567) with no secure "
          "update path; mass-exploited by Mirai and successors.",
     "fix": "These devices generally cannot be hardened - remove from the "
        "internet and replace with a maintained product."},
  ],
}

# Generic advisory for a recognized surveillance vendor not in the table above.
GENERIC_CVE_ADVISORY = {
  "id": "vendor advisories", "severity": "varies",
  "summary": "Internet-exposed surveillance device. Check the vendor PSIRT / "
        "security advisories for your exact model and firmware.",
  "fix": "Update to current firmware and place the device behind a VPN, not "
      "directly on the public internet."}

# General hardening checklist printed once per hardening run.
HARDENING_CHECKLIST = [
  "Do not expose camera/DVR/NVR web UIs, RTSP, or vendor control ports to the "
  "public internet - put them behind a VPN or a restricted management VLAN.",
  "Update to the latest vendor firmware; retire end-of-life models that no "
  "longer receive security updates.",
  "Replace all default/weak passwords with unique strong credentials.",
  "Disable unused services (Telnet, UPnP, P2P/cloud relay, ONVIF if not needed).",
  "Restrict access by source IP / firewall; log and alert on new exposures.",
  "Segment surveillance devices away from business/IT networks.",
]

# Best-effort version string from already-collected evidence (no new requests).
_VER_CONTEXT = re.compile(
  r"(?:firmware|version|softwareversion|fw|build)[^0-9]{0,12}"
  r"([vV]?\d+\.\d+(?:\.\d+){0,2}(?:[ _]?build[ _]?\d+)?)", re.IGNORECASE)
_VER_BARE = re.compile(r"\b[vV](\d+\.\d+\.\d+(?:\.\d+)?)\b")


def extract_version(evidence):
  """Pull a likely firmware/version string from evidence, or None.

  Heuristic and easily fooled - always treat the result as 'reported, verify'.
  """
  blob = " ".join(evidence)
  m = _VER_CONTEXT.search(blob)
  if m:
    return m.group(1)
  m = _VER_BARE.search(blob)
  return m.group(0) if m else None


def cve_advisories(vendor):
  """Return the advisory list for a vendor (generic if unknown)."""
  if vendor in KNOWN_CVES:
    return KNOWN_CVES[vendor]
  return [GENERIC_CVE_ADVISORY]


# ---------------------------------------------------------------------------


def classify(open_ports, evidence):
  """Turn open ports + evidence into a device verdict."""
  blob = " ".join(evidence)
  matched = []

  # Vendor
  vendor = None
  for name, sigs in VENDOR_SIGNATURES.items():
    hits = [s for s in sigs if s in blob]
    if hits:
      vendor = name
      matched += [f"{name}:{h}" for h in hits[:3]]
      break

  speaks_rtsp = "rtsp: speaks rtsp" in blob
  speaks_onvif = "onvif:" in blob
  dvrip = [p for p in open_ports if p in DVRIP_PORTS]
  cam_webserver = [w for w in CAMERA_WEBSERVERS if w in blob]

  if speaks_rtsp:
    matched.append("rtsp")
  if speaks_onvif:
    matched.append("onvif")
  if dvrip:
    matched.append("dvrip-port:" + ",".join(str(p) for p in dvrip))
  if cam_webserver:
    matched.append("webserver:" + cam_webserver[0])

  # Device type
  is_recorder = any(h in blob for h in RECORDER_HINTS) or bool(dvrip)
  is_camera = any(h in blob for h in CAMERA_HINTS)
  if is_recorder and not is_camera:
    dtype = "DVR/NVR"
  elif speaks_rtsp or speaks_onvif or is_camera:
    dtype = "IP camera"
  elif dvrip or cam_webserver or vendor:
    dtype = "DVR/NVR or camera"
  else:
    dtype = None # not surveillance

  # Confidence
  strong = bool(vendor) or speaks_onvif or bool(dvrip)
  medium = speaks_rtsp or bool(cam_webserver)
  if dtype is None:
    confidence = None
  elif strong:
    confidence = "confirmed"
  elif medium:
    confidence = "likely"
  else:
    confidence = "possible"

  return {
    "device_type": dtype,
    "vendor": vendor,
    "confidence": confidence,
    "evidence": matched,
  }


def fingerprint_host(ip, open_ports, timeout):
  """Run all relevant protocol probes against one host's open ports."""
  evidence = []
  for port in open_ports:
    if port in TLS_PORTS:
      evidence += http_probe(ip, port, timeout, use_tls=True)
      evidence += onvif_probe(ip, port, timeout, use_tls=True)
    elif port in HTTP_PORTS or port == 8080:
      evidence += http_probe(ip, port, timeout, use_tls=False)
      evidence += onvif_probe(ip, port, timeout, use_tls=False)
    if port in RTSP_PORTS:
      evidence += rtsp_probe(ip, port, timeout)
  verdict = classify(open_ports, evidence)
  verdict["ip"] = str(ip)
  verdict["open_ports"] = sorted(open_ports)
  verdict["version"] = extract_version(evidence)
  return verdict


def main():
  ap = argparse.ArgumentParser(
    description="Detect DVR/NVR/IP-camera devices in an IP range.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="Heuristic. Only scan hosts you own or are authorized to test.",
  )
  ap.add_argument("range", help="IP range: CIDR (any mask), a-b, a-LASTOCTET, or single IP")
  ap.add_argument("-t", "--timeout", type=float, default=1.5,
          help="per-connection timeout in seconds (default 1.5)")
  ap.add_argument("-w", "--workers", type=int, default=200,
          help="concurrent connections (default 200)")
  ap.add_argument("-v", "--verbose", action="store_true",
          help="print the matched evidence for each detection")
  ap.add_argument("-q", "--ips-only", action="store_true",
          help="print ONLY the matching IPs to stdout, one per line "
             "(everything else goes to stderr; ideal for piping)")
  ap.add_argument("-c", "--min-confidence", choices=["confirmed", "likely", "possible"],
          default="possible",
          help="only report detections at/above this confidence "
             "(default possible; use 'likely' or 'confirmed' to cut noise)")
  ap.add_argument("--max-probes", type=int, default=2_000_000,
          help="refuse port-scan stage above this without -y")
  ap.add_argument("-y", "--yes", action="store_true", help="bypass --max-probes")
  ap.add_argument("--check-creds", action="store_true",
          help="phase 3: test factory default credentials against "
             "detected devices (WARNING: can lock out accounts)")
  ap.add_argument("--creds-file",
          help="file of user:pass per line; tried after the brand "
             "default unless --no-vendor-first")
  ap.add_argument("--no-vendor-first", action="store_true",
          help="do not prioritize the detected brand's factory "
             "default (try the list in given order instead)")
  ap.add_argument("--max-cred-tries", type=int, default=3,
          help="max credential attempts per host (default 3, matching "
             "the typical lockout threshold; brand default is tried first)")
  ap.add_argument("--cred-delay", type=float, default=0.0,
          help="seconds to wait between credential attempts (default 0)")
  ap.add_argument("--harden", action="store_true",
          help="defensive report: flag detected firmware against known "
             "critical CVEs and print a hardening checklist "
             "(identification only, no exploitation)")
  ap.add_argument("--no-progress", action="store_true",
          help="disable the live progress bar (auto-off when not a TTY)")
  ap.add_argument("-oJ", "--json-out", help="write results to a JSON file")
  # --- low-and-slow / stealth options -----------------------------------
  ap.add_argument("--stealth", action="store_true",
          help="low-and-slow mode: rate-limit probes, jitter timing, "
             "cross-host sweep order, browser-like User-Agent, minimal "
             "probe paths. Reduces SOC/IDS rate-trigger noise but is NOT "
             "wire stealth (still TCP-connect; auth attempts still log).")
  ap.add_argument("--rate", type=float, default=0,
          help="cap probes per second (0 = no limit). --stealth defaults this to 5.")
  ap.add_argument("--jitter", type=float, default=0,
          help="randomize timing by +/- this fraction (0..1). --stealth defaults to 0.4.")
  ap.add_argument("--shuffle", action="store_true",
          help="randomize host x port order (auto-on with --stealth)")
  ap.add_argument("--user-agent", default=None,
          help="custom HTTP/RTSP User-Agent string (overrides default and --stealth UA)")
  args = ap.parse_args()

  # Apply stealth preset BEFORE anything else looks at the values.
  if args.stealth:
    if args.rate == 0: args.rate = 5
    if args.jitter == 0: args.jitter = 0.4
    args.shuffle = True
    if args.workers == 200:  # only if user didn't override
      args.workers = 5
    if args.timeout == 1.5:
      args.timeout = 4.0
    ProbeConfig.stealth = True
    ProbeConfig.http_paths = HTTP_PATHS_STEALTH
    ProbeConfig.user_agent = args.user_agent or STEALTH_UA
  else:
    ProbeConfig.user_agent = args.user_agent or DEFAULT_UA

  try:
    host_count, hosts = parse_targets(args.range)
  except ValueError as e:
    ap.error(f"bad range: {e}")

  ports = list(CAMERA_PORTS)
  total = host_count * len(ports)
  if args.stealth or args.rate or args.shuffle:
    eta = f", ~{total/args.rate:.0f}s minimum" if args.rate > 0 else ""
    print(f"[*] stealth: rate={args.rate}/s jitter={args.jitter} "
       f"workers={args.workers} shuffle={args.shuffle} "
       f"UA='{ProbeConfig.user_agent[:40]}...'{eta}", file=sys.stderr)
    print("[*] note: still TCP-connect (not wire-stealth); auth attempts "
       "still produce log entries on targets", file=sys.stderr)
  print(f"[*] phase 1: port scan {host_count:,} host(s) x {len(ports)} camera "
     f"port(s) = {total:,} probes", file=sys.stderr)
  if total > args.max_probes and not args.yes:
    print(f"[!] {total:,} probes exceeds --max-probes. Use -y to proceed.",
       file=sys.stderr)
    sys.exit(2)

  # Phase 1: find which camera ports are open per host (bounded streaming).
  # Iteration order matters for stealth: sweeping (port, ip) instead of
  # (ip, port) spreads probes across hosts so no single host sees a
  # back-to-back port scan that would trigger per-source rate alarms.
  host_open = {} # ip(str) -> set(ports)
  if args.shuffle and total <= 200_000:
    host_list = list(hosts)
    random.shuffle(host_list)
    port_list = list(ports); random.shuffle(port_list)
    jobs = ((ip, port) for port in port_list for ip in host_list)
  else:
    # Streaming: port-major so back-to-back probes hit different hosts.
    host_list = None
    jobs = ((ip, port) for port in ports for ip in hosts)

  limiter = RateLimiter(args.rate, args.jitter)
  in_flight = args.workers * 4
  prog1 = Progress(total, "scan ", enabled=not args.no_progress)
  with ThreadPoolExecutor(max_workers=args.workers) as pool:
    pending = {}

    def drain(target):
      for fut in as_completed(list(pending)):
        fip, fport = pending.pop(fut)
        try:
          _, is_open = fut.result()
        except Exception:
          is_open = False
        if is_open:
          host_open.setdefault(str(fip), set()).add(fport)
        prog1.update(1, extra=f"camera hosts: {len(host_open)}")
        if len(pending) <= target:
          break

    for ip, port in jobs:
      limiter.wait()
      pending[pool.submit(scan_port, ip, port, args.timeout)] = (ip, port)
      if len(pending) >= in_flight:
        drain(in_flight // 2)
    drain(0)
  prog1.finish(extra=f"camera hosts: {len(host_open)}")

  print(f"[*] phase 2: fingerprinting {len(host_open)} host(s) with open "
     f"camera ports", file=sys.stderr)

  # Phase 2: fingerprint hosts that had any camera port open.
  findings = []
  detected_live = 0
  prog2 = Progress(len(host_open), "ident", enabled=not args.no_progress)
  ident_workers = min(args.workers, 5 if args.stealth else 100)
  ident_hosts = list(host_open)
  if args.shuffle:
    random.shuffle(ident_hosts)
  with ThreadPoolExecutor(max_workers=ident_workers) as pool:
    futs = {}
    for ip in ident_hosts:
      limiter.wait()
      fut = pool.submit(fingerprint_host, ipaddress.ip_address(ip),
                host_open[ip], args.timeout)
      futs[fut] = ip
    for fut in as_completed(futs):
      try:
        r = fut.result()
        findings.append(r)
        if r["device_type"]:
          detected_live += 1
      except Exception:
        pass
      prog2.update(1, extra=f"devices found: {detected_live}")
  prog2.finish(extra=f"devices found: {detected_live}")

  # Only IPs positively identified as camera/DVR/NVR, at or above the
  # requested confidence. Everything else is ignored.
  CONF_RANK = {"possible": 1, "likely": 2, "confirmed": 3}
  threshold = CONF_RANK[args.min_confidence]
  findings.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
  detected = [f for f in findings
        if f["device_type"] and CONF_RANK.get(f["confidence"], 0) >= threshold]

  # Phase 3 (opt-in): test factory default credentials on detected devices.
  if args.check_creds and detected:
    creds = load_creds(args.creds_file)
    print(f"[*] phase 3: testing default creds on {len(detected)} device(s) "
       f"(<={args.max_cred_tries} tries each, brand default first) - "
       f"lockout risk, authorized use only", file=sys.stderr)
    prog3 = Progress(len(detected), "creds", enabled=not args.no_progress)
    cracked_live = 0
    cred_workers = min(args.workers, 3 if args.stealth else 30)
    with ThreadPoolExecutor(max_workers=cred_workers) as pool:
      futs = {pool.submit(check_default_creds,
                ipaddress.ip_address(f["ip"]), set(f["open_ports"]),
                f["vendor"], args.timeout, creds,
                args.max_cred_tries, args.cred_delay,
                not args.no_vendor_first): f
          for f in detected}
      for fut in as_completed(futs):
        try:
          futs[fut]["default_credentials"] = fut.result()
        except Exception:
          futs[fut]["default_credentials"] = []
        if futs[fut].get("default_credentials"):
          cracked_live += 1
        prog3.update(1, extra=f"default creds: {cracked_live}")
    prog3.finish(extra=f"default creds: {cracked_live}")

  # Hardening (opt-in): attach known-CVE advisories for each detected vendor.
  if args.harden:
    for f in detected:
      f["advisories"] = cve_advisories(f["vendor"]) if f["vendor"] else \
        [GENERIC_CVE_ADVISORY]

  # -q / --ips-only: stdout is nothing but the matching IPs (pipe-friendly).
  if args.ips_only:
    for f in detected:
      print(f["ip"])
    print(f"[*] {len(detected)} surveillance device(s) detected", file=sys.stderr)
  else:
    print()
    if not detected:
      print("No DVR/NVR/IP-camera devices identified.")
    for f in detected:
      vendor = f["vendor"] or "unknown vendor"
      label = f"{f['device_type']} [{f['confidence']}] - {vendor}"
      ports_s = ",".join(str(p) + "/" + CAMERA_PORTS.get(p, "?")
                for p in f["open_ports"])
      print(f"{f['ip']:<16} {label}")
      print(f"         ports: {ports_s}")
      if args.harden and f.get("version"):
        print(f"         reported version (verify): {f['version']}")
      creds = f.get("default_credentials")
      if creds:
        print(f"         ⚠ DEFAULT CREDS: {', '.join(creds)}")
      elif args.check_creds:
        print(f"         default creds: none found")
      for adv in f.get("advisories", []):
        print(f"         ⚠ {adv['id']} [{adv['severity']}]")
        print(f"           {adv['summary']}")
        print(f"           fix: {adv['fix']}")
      if args.verbose and f["evidence"]:
        for e in f["evidence"]:
          print(f"         · {e}")
      print()

    if args.harden and detected:
      print("Hardening checklist:")
      for item in HARDENING_CHECKLIST:
        print(f" • {item}")
      print()

    vuln = sum(1 for f in detected if f.get("default_credentials"))
    tail = f", {vuln} with default creds" if args.check_creds else ""
    print(f"[*] {len(detected)} device(s) identified out of "
       f"{len(host_open)} host(s) with camera ports open{tail}",
       file=sys.stderr)

  if args.json_out:
    payload = {
      "range": args.range,
      "scanned_hosts": host_count,
      "finished": datetime.now(timezone.utc).isoformat(),
      "min_confidence": args.min_confidence,
      "detected": detected,
    }
    with open(args.json_out, "w") as fh:
      json.dump(payload, fh, indent=2, default=str)
    print(f"[*] wrote {args.json_out}", file=sys.stderr)


if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    print("\n[!] interrupted", file=sys.stderr)
    sys.exit(130)
