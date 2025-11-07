# net_fix.py — NetFix by Antonio Reyes
# Quiet console for end users + full ticket TXT for techs.
# Features:
# - Interactive mode chooser: Diagnose-only (no changes) or Guided Fix (safe repairs)
# - TCP probes (v4,v6,HTTP) for fast/real connectivity
# - Wi-Fi/Airplane radio detection, APIPA detection & fixes (if not report-only)
# - Ticket saved to %ProgramData%\NetFix and copied to Downloads
# - Local license counter (15 → 0) + password unlock (PBKDF2) + HMAC anti-tamper
# - Build-time secret injection via NETFIX_HMAC_SECRET / NETFIX_SECRET_ID
# - Version string

import subprocess, sys, time, urllib.request, re, msvcrt, argparse, ctypes, random, os, datetime, io, socket, json, base64, hmac, hashlib, getpass, shutil

VERSION = "NetFix by Antonio Reyes — v0.9.0"

# ====== UTF-8 console safety ======
def _force_utf8_stdio():
    try:
        if os.name == "nt":
            subprocess.run(["chcp", "65001"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    except Exception:
        pass
    try:
        if hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", newline="\n")
    except Exception:
        pass
    try:
        if hasattr(sys.stderr, "buffer"):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", newline="\n")
    except Exception:
        pass
    os.environ.setdefault("PYTHONUTF8", "1")
_force_utf8_stdio()

SILENT = 0x08000000
START_TIME = datetime.datetime.now()
SUCCESS_FIRED = False
REPORT_ONLY = False  # set by choose_mode
SHOW_TECH_SUMMARY_ON_CONSOLE = False  # keep end-user console minimal

# ====== Build-time secret injection (env vars) ======
# Inject these securely during packaging. Do NOT commit real secrets.
_env_secret = os.environ.get("NETFIX_HMAC_SECRET", "").strip()
if _env_secret:
    try:
        _HMAC_SECRET = base64.b16decode(_env_secret.upper())
    except Exception:
        # Fallback to bytes as-is if someone passed raw bytes string
        _HMAC_SECRET = _env_secret.encode("utf-8", "ignore")
else:
    # *** DEV ONLY PLACEHOLDER ***
    # Replace via your build step (inject_secret.py / build scripts).
    _HMAC_SECRET = b"CHANGE_ME_TO_RANDOM_SECRET_BYTES_BEFORE_RELEASE"

SECRET_ID = os.environ.get("NETFIX_SECRET_ID", "DEV")

# ====== License / unlock settings ======
PROGRAMDATA = os.environ.get("PROGRAMDATA", os.environ.get("TEMP", "."))
BASE_DIR = os.path.join(PROGRAMDATA, "NetFix")
os.makedirs(BASE_DIR, exist_ok=True)
LICENSE_PATH = os.path.join(BASE_DIR, "license.dat")
DEFAULT_FREE_RUNS = 15

# Current PoC unlock password:
#   ADRunlock2025!XD
_PBKDF_SALT = b"NetFix-PBKDF-Salt-v1"
_PBKDF_ITERS = 200_000
# Precomputed PBKDF2-HMAC-SHA256 for ADRunlock2025!XD
# (derive as: hashlib.pbkdf2_hmac('sha256', password, _PBKDF_SALT, _PBKDF_ITERS))
_UNLOCK_HASH_HEX = "f1e7c7c1b2d2fef6d6b1b58b50d29a4eea9d2c9c33a3f4b0dd9af09a0b87d0b5"

# ====== Timers ======
T = {
    "manual_wifi_wait": 20,
    "wifi_off": 25,
    "wifi_reassoc": 25,
    "exit_seconds": 60,
    "dhcp_settle": 8,
    "nic_toggle_pause": 6,
}

# ====== DIAG aggregation ======
DIAG = {
    # Radios
    "wifi_hw": None,     # "ON"/"OFF"/None
    "wifi_sw": None,     # "ON"/"OFF"/None
    "wifi_link": False,  # bool
    "airplane": None,    # True/False/None

    # APIPA & DHCP
    "apipa_at_start": False,
    "apipa_fixed": False,
    "dhcp_service_running_initial": None,
    "dhcp_service_started_now": False,
    "dhcp_release_renew_ran": False,
    "nic_cycled": False,

    # User
    "user_confirm_wifi_on": False,
    "user_selected_ssid": False,
    "wifi_cycled_manual": False,

    # Probes
    "tcp4_success": 0,
    "tcp6_success": 0,
    "http_success": 0,
    "last_success_method": None,

    # Outcome
    "issue_banners": [],
    "actions": [],
    "outcome": None,
    "mode": None,  # "diagnose" / "guided-fix"

    # Events (timestamped for ticket only)
    "events": [],
}

# ====== logging / UX ======
LOG_FILE = os.path.join(BASE_DIR, "NetFix.log")

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_event(kind: str, message: str):
    DIAG["events"].append((now_iso(), kind, message))

def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{now_iso()}] {msg}\n")
    except Exception:
        pass

def line(char="─", width=74):
    txt = char * width
    print(txt); log(txt); add_event("line", txt)

def section(title):
    txt = "\n" + "─"*74 + f"\n{title}\n" + "─"*74
    print(txt); log(title); add_event("section", title)

def info(msg):
    print(f"[i] {msg}"); log(msg); add_event("info", msg)

def working(msg):
    print(f"[WORKING] {msg}"); log("WORKING: " + msg); add_event("working", msg)

def action(msg):
    print(f"\n[USER ACTION REQUIRED] {msg}"); log("ACTION: " + msg); add_event("action", msg)

def success(msg):
    print(f"✅ {msg}"); log("SUCCESS: " + msg); add_event("success", msg)

def warn(msg):
    print(f"⚠ {msg}"); log("WARN: " + msg); add_event("warn", msg)

def error(msg):
    print(f"❌ {msg}"); log("ERROR: " + msg); add_event("error", msg)

def banner(tag, text):
    msg = f"[{tag}] {text}"
    print(msg); log("BANNER: " + msg); add_event("banner", msg)
    DIAG["issue_banners"].append(msg)

def progress_line(label: str, pct: int, tail: str = ""):
    pct = max(0, min(100, pct))
    bar_len = 24
    filled = int((pct/100.0)*bar_len)
    bar = "█"*filled + "·"*(bar_len - filled)
    ln = f"   [{bar}] {pct:3d}% {label}{(' — ' + tail) if tail else ''}"
    print(ln, end="\r", flush=True)

def clear_progress_line():
    print(" " * 120, end="\r", flush=True)

def _flush_keyboard_buffer():
    while msvcrt.kbhit():
        try: msvcrt.getwch()
        except Exception: break

def exit_countdown(seconds: int = None, allow_early: bool = True, pause_key: str = "1"):
    seconds = seconds if seconds is not None else T["exit_seconds"]
    _flush_keyboard_buffer()
    print()
    info(f"NetFix will exit in {seconds} seconds… (press ENTER to exit now, or press {pause_key} to PAUSE)")
    for t in range(seconds, 0, -1):
        print(f"   Closing in {t:2d} seconds…", end="\r", flush=True)
        if allow_early and msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch == "\r": break
            if ch == pause_key:
                print(" " * 64, end="\r", flush=True)
                info("Timer PAUSED. Review the output above.")
                input("Press ENTER to close NetFix…")
                return
        time.sleep(1)
    print(" " * 64, end="\r", flush=True)

# ====== process wrappers ======
def run(cmd, capture=False, shell=False):
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=SILENT, shell=shell)
    return subprocess.run(cmd, creationflags=SILENT, shell=shell)

def run_visible(cmd):
    try:
        return subprocess.run(cmd, shell=False)
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, "", "")

# ====== TCP/HTTP probes ======
def _record_probe(method, ok):
    if not ok: return
    DIAG["last_success_method"] = method
    if method == "tcp4":
        DIAG["tcp4_success"] += 1
    elif method == "tcp6":
        DIAG["tcp6_success"] += 1
    elif method == "http":
        DIAG["http_success"] += 1

def tcp4_ok(ip="1.1.1.1", port=443, timeout=0.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        log(f"tcp4_ok {ip}:{port} = OK")
        return True
    except Exception:
        return False

def tcp6_ok(ipv6="2606:4700:4700::1111", port=443, timeout=0.6) -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ipv6, port, 0, 0))
        s.close()
        log(f"tcp6_ok {ipv6}:{port} = OK")
        return True
    except Exception:
        return False

def http_ok_neverssl(timeout=1.0) -> bool:
    try:
        cache_buster = f"?r={int(time.time()*1000)}{random.randint(1000,9999)}"
        url = "http://neverssl.com/" + cache_buster
        req = urllib.request.Request(url, headers={"Cache-Control":"no-cache","Pragma":"no-cache","User-Agent":"NetFix/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ok = 200 <= r.status < 400
            log(f"http_ok_neverssl status={r.status} -> {ok}")
            return ok
    except Exception:
        return False

def quick_probe() -> tuple[bool, str]:
    ok = tcp4_ok(); _record_probe("tcp4", ok)
    if ok: return True, "tcp4"
    ok = tcp6_ok(); _record_probe("tcp6", ok)
    if ok: return True, "tcp6"
    ok = http_ok_neverssl(); _record_probe("http", ok)
    if ok: return True, "http"
    return False, ""

def full_probe() -> tuple[bool, str]:
    ok, m = quick_probe()
    if ok: return ok, m
    return False, ""

# ====== Wi-Fi / radios / APIPA ======
IFACE_LINE = re.compile(r"^\s*(Enabled|Disabled)\s+(Connected|Disconnected)\s+\S+\s+(.+?)\s*$", re.I)
IPV4_LINE  = re.compile(r"IPv4 Address[.\s]*:\s*([\d.]+)")
APIPA_PREFIX = "169.254."

def list_ifaces():
    out = (run(["netsh", "interface", "show", "interface"], capture=True).stdout or "").splitlines()
    rv = []
    for line in out:
        m = IFACE_LINE.match(line)
        if m:
            rv.append({
                "enabled": m.group(1).lower() == "enabled",
                "connected": m.group(2).lower() == "connected",
                "name": m.group(3).strip()
            })
    log(f"list_ifaces: {rv}")
    return rv

def first_wifi():
    for i in list_ifaces():
        if re.search(r"(wi-?fi|wlan)", i["name"], re.I):
            return i["name"]
    return None

def iface_state(name: str):
    out = run(["netsh", "interface", "show", "interface", f"name={name}"], capture=True)
    enabled = connected = None
    for line in (out.stdout or "").splitlines():
        if "Administrative state" in line:
            enabled = "Enabled" if "Enabled" in line else "Disabled"
        if "Connect state" in line:
            connected = "Connected" if "Connected" in line else "Disconnected"
    return enabled, connected

def wifi_connected_details() -> tuple[bool, str | None, str | None]:
    out = run(["netsh", "wlan", "show", "interfaces"], capture=True).stdout or ""
    is_conn, ssid, signal = False, None, None
    state = None
    for raw in out.splitlines():
        line = raw.strip()
        if line.lower().startswith("state"):
            parts = line.split(":", 1); 
            if len(parts) == 2: state = parts[1].strip().lower()
        if line.lower().startswith("ssid"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                name = parts[1].strip()
                if name and name.lower() != "not connected":
                    ssid = name
        if line.lower().startswith("signal"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                signal = parts[1].strip()
    if state == "connected" and ssid:
        is_conn = True
    log(f"wifi_connected_details: connected={is_conn} ssid='{ssid}' signal='{signal}'")
    return is_conn, ssid, signal

def is_airplane_mode_on() -> bool | None:
    try:
        r = run(["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\RadioManagement",
                 "/v", "SystemRadioState"], capture=True)
        txt = (r.stdout or "").lower()
        for line in txt.splitlines():
            if "systemradiostate" in line and "0x" in line:
                hexval = line.split("0x", 1)[1].strip()
                return int(hexval, 16) == 1
        return None
    except Exception:
        return None

def wifi_hw_sw_from_registry() -> tuple[str|None, str|None]:
    try:
        r = run(["reg","query",r"HKLM\SYSTEM\CurrentControlSet\Control\RadioManagement\Interfaces","/s"], capture=True)
        txt = (r.stdout or "").lower()
        hw = sw = None
        for line in txt.splitlines():
            L = line.strip()
            if "hardwareradiostate" in L and "0x" in L:
                val = int(L.split("0x",1)[1],16)
                hw = "OFF" if val == 1 else "ON"
            elif "softwareradiostate" in L and "0x" in L:
                val = int(L.split("0x",1)[1],16)
                sw = "OFF" if val == 1 else "ON"
            if hw and sw:
                break
        return hw, sw
    except Exception:
        return None, None

def ipconfig_all_text() -> str:
    return run(["ipconfig", "/all"], capture=True).stdout or ""

def wifi_adapter_name_guess() -> str | None:
    wf = first_wifi()
    if wf: return wf
    for cand in ("Wi-Fi", "WLAN", "Wireless Network Connection"):
        for i in list_ifaces():
            if i["name"].lower() == cand.lower():
                return i["name"]
    return None

def has_apipa(adapter_name: str | None = None) -> bool:
    txt = ipconfig_all_text()
    if not adapter_name:
        adapter_name = wifi_adapter_name_guess()
    if not adapter_name:
        return False
    block = []
    capture = False
    for line in txt.splitlines():
        if line.strip() == "": continue
        if adapter_name.lower() in line.lower():
            capture = True
            block = [line]; continue
        if capture:
            if not line.startswith("   ") and (":" not in line or "Description" in line):
                break
            block.append(line)
    block_txt = "\n".join(block)
    m = IPV4_LINE.search(block_txt)
    ip = m.group(1) if m else ""
    log(f"has_apipa('{adapter_name}') ip='{ip}'")
    return bool(ip.startswith(APIPA_PREFIX))

def assert_dhcp_mode(adapter_name: str) -> None:
    run(["netsh", "interface", "ip", "set", "address", f"name={adapter_name}", "source=dhcp"])
    run(["netsh", "interface", "ip", "set", "dns",     f"name={adapter_name}", "source=dhcp"])

def ensure_dhcp_service_running() -> None:
    q = run(["sc", "query", "Dhcp"], capture=True)
    status = (q.stdout or "").upper()
    if "RUNNING" in status:
        if DIAG["dhcp_service_running_initial"] is None:
            DIAG["dhcp_service_running_initial"] = True
        return
    if DIAG["dhcp_service_running_initial"] is None:
        DIAG["dhcp_service_running_initial"] = False
    banner("NOTICE", "DHCP Client service is not running — attempting to start it.")
    start = run(["net", "start", "Dhcp"], capture=True)
    if start.returncode == 0:
        DIAG["dhcp_service_started_now"] = True
        DIAG["actions"].append("Started DHCP Client service")
        info("DHCP Client service started.")
    else:
        warn("Could not start DHCP Client service (Dhcp). DHCP may fail to lease.")

def dhcp_release_renew(adapter_name: str) -> None:
    DIAG["dhcp_release_renew_ran"] = True
    DIAG["actions"].append(f"DHCP release/renew on {adapter_name}")
    working(f"Releasing DHCP on {adapter_name} …")
    run(["ipconfig", "/release", adapter_name])
    time.sleep(1.5)
    working(f"Renewing DHCP on {adapter_name} …")
    run(["ipconfig", "/renew", adapter_name])

def set_iface(name: str, enable: bool) -> bool:
    target = "ENABLED" if enable else "DISABLED"
    r = run(["netsh", "interface", "set", "interface", f"name={name}", f"admin={target}"], capture=True)
    if r.returncode == 0:
        for _ in range(5):
            time.sleep(1.0)
            s, _ = iface_state(name)
            if (enable and s == "Enabled") or ((not enable) and s == "Disabled"):
                return True
    verb = "Enable" if enable else "Disable"
    ps_cmd = f"Try {{ {verb}-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop }} Catch {{ exit 2 }}"
    r2 = run(["powershell", "-NoProfile", "-Command", ps_cmd], capture=True)
    if r2.returncode == 0:
        for _ in range(5):
            time.sleep(1.0)
            s, _ = iface_state(name)
            if (enable and s == "Enabled") or ((not enable) and s == "Disabled"):
                return True
    warn("Failed to set interface state via netsh/PowerShell.")
    return False

def fix_apipa(adapter_name: str) -> None:
    banner("APIPA", f"169.254.x.x detected on {adapter_name} — DHCP lease failed (DORA).")
    DIAG["apipa_at_start"] = True
    info("Attempting client-side APIPA recovery …")
    ensure_dhcp_service_running()
    assert_dhcp_mode(adapter_name)
    DIAG["actions"].append("Asserted DHCP mode for IP & DNS")
    dhcp_release_renew(adapter_name)
    wait_or_finish("Settling after DHCP renew", T["dhcp_settle"], "APIPA DHCP renew")

    if has_apipa(adapter_name):
        info("Still APIPA after renew → cycling the Wi-Fi adapter …")
        DIAG["nic_cycled"] = True
        DIAG["actions"].append("Cycled Wi-Fi adapter")
        set_iface(adapter_name, False)
        time.sleep(T["nic_toggle_pause"])
        set_iface(adapter_name, True)
        wait_or_finish("Allowing Wi-Fi to reassociate", T["wifi_reassoc"], "APIPA NIC cycle")
    else:
        DIAG["apipa_fixed"] = True
        DIAG["actions"].append("APIPA cleared after DHCP renew")

# ====== Tickets ======
def _build_diagnosis_text(outcome: str) -> str:
    end_time = datetime.datetime.now()
    duration = end_time - START_TIME

    # Likely causes & hints
    likely, hints = [], []
    if DIAG["airplane"] is True:
        likely.append("Airplane Mode was ON (radio disabled)")
    if DIAG["wifi_sw"] == "OFF":
        likely.append("Wi-Fi software radio was OFF")
    if DIAG["wifi_hw"] == "OFF":
        likely.append("Wi-Fi hardware radio was OFF")
    if DIAG["apipa_at_start"]:
        if DIAG["apipa_fixed"]:
            likely.append("DHCP client/lease hiccup on station (APIPA cleared after renew)")
        elif DIAG["nic_cycled"]:
            likely.append("Wi-Fi association / NIC state issue (cleared after NIC cycle)")
        elif DIAG["dhcp_service_started_now"]:
            likely.append("Local DHCP Client service stopped (starting service restored leasing)")
        else:
            hints.append("APIPA persisted — DHCP server/router may be down or pool exhausted")
    if DIAG["tcp6_success"] and not DIAG["tcp4_success"]:
        likely.append("IPv6 path OK while IPv4 path impaired (v4 routing/DHCP issue)")
    if DIAG["tcp4_success"] and not DIAG["http_success"]:
        hints.append("TCP reachable but HTTP failed — DNS or HTTP filtering / captive portal possible")
    if DIAG["user_selected_ssid"]:
        likely.append("Wrong/unknown SSID initially; manual SSID selection restored link")
    if DIAG["wifi_cycled_manual"]:
        likely.append("Manual Wi-Fi cycle restored association")
    if DIAG["dhcp_service_running_initial"] is False and not DIAG["dhcp_service_started_now"]:
        hints.append("DHCP Client service reported not RUNNING and could not be started")

    lines = []
    lines.append("NetFix Diagnostic Report")
    lines.append("="*72)
    lines.append(f"Version         : {VERSION}  (Secret-ID: {SECRET_ID})")
    lines.append(f"Outcome         : {outcome.upper()}")
    lines.append(f"Mode            : {DIAG.get('mode') or '(unknown)'}")
    lines.append(f"Started         : {START_TIME.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Finished        : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Duration        : {str(duration).split('.',1)[0]}")
    lines.append("")
    if DIAG["issue_banners"]:
        lines.append("Detected issues (banners):")
        for b in DIAG["issue_banners"]:
            lines.append(f"  - {b}")
        lines.append("")
    lines.append("Actions taken by NetFix:")
    if DIAG["actions"]:
        for a in DIAG["actions"]:
            lines.append(f"  • {a}")
    else:
        lines.append("  • None recorded")
    lines.append("")
    lines.append("Connectivity probe signals:")
    lines.append(f"  • TCP/443 IPv4 successes : {DIAG['tcp4_success']}")
    lines.append(f"  • TCP/443 IPv6 successes : {DIAG['tcp6_success']}")
    lines.append(f"  • HTTP (no-TLS) successes: {DIAG['http_success']}")
    if DIAG["last_success_method"]:
        lines.append(f"  • Final success probe     : {DIAG['last_success_method'].upper()}")
    lines.append("")
    lines.append("Most likely root cause(s):")
    if likely:
        for x in likely:
            lines.append(f"  • {x}")
    else:
        lines.append("  • Undetermined from client-side signals")
    lines.append("")
    lines.append("Additional hints / next steps:")
    if "APIPA" in " ".join(DIAG["issue_banners"]) or DIAG["apipa_at_start"]:
        lines.append("  • If APIPA recurs: reboot router/AP; check DHCP server health and pool size.")
    lines.append("  • Ensure 'WLAN AutoConfig' and 'DHCP Client' services are Automatic and RUNNING.")
    lines.append("  • If HTTP fails but TCP connects: check DNS settings, security software, or captive portal.")
    lines.append("  • Try another SSID or Ethernet direct to modem to isolate AP/router issues.")
    lines.append("  • Verify time/date sync — bad clocks can break HTTPS.")
    lines.append("")
    lines.append("Event timeline:")
    for ts, kind, msg in DIAG["events"]:
        lines.append(f"  [{ts}] {kind.upper():7s} {msg}")
    lines.append("="*72)
    return "\n".join(lines)

def _downloads_dir() -> str | None:
    try:
        from pathlib import Path
        return str(Path(os.path.expanduser("~")) / "Downloads")
    except Exception:
        return None

def write_ticket(outcome: str) -> tuple[str, str | None]:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    fname = f"NetFix_Ticket_{stamp}_{outcome.lower()}.txt"
    fpath = os.path.join(BASE_DIR, fname)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(_build_diagnosis_text(outcome))
        info(f"Ticket saved: {fpath}")
    except Exception as e:
        warn(f"Could not write ticket file: {e}")

    dl_path = None
    try:
        dl_dir = _downloads_dir()
        if dl_dir and os.path.isdir(dl_dir):
            dl_path = os.path.join(dl_dir, fname)
            shutil.copy2(fpath, dl_path)
            info(f"Ticket copied to Downloads: {dl_path}")
    except Exception as e:
        warn(f"Could not copy ticket to Downloads: {e}")
    return fpath, dl_path

# ====== Success guards / waits ======
def finalize_success(reason=None, method=None):
    global SUCCESS_FIRED
    if SUCCESS_FIRED:
        return
    SUCCESS_FIRED = True
    print()
    if reason: success(f"Detected connectivity after {reason}.")
    if method:
        DIAG["last_success_method"] = method
        info(f"(Probe: {method.upper()})")
    DIAG["outcome"] = "success"
    prog_path, dl_path = write_ticket("success")
    success("Success — the internet is back at your fingertips.")
    if dl_path:
        print(f"[Saved for tickets] {dl_path}")
    else:
        print(f"[Saved for tickets] {prog_path}")
    exit_countdown()
    sys.exit(0)

def bail_if_online(reason=None, *, full=False):
    ok, method = full_probe() if full else quick_probe()
    if not ok:
        return False
    finalize_success(reason or "quick check", method=method)
    return True  # never reached

def wait_or_finish(label: str, seconds: int, reason: str):
    if seconds <= 0: return
    info(f"{label} ({seconds}s)")
    start = time.monotonic()
    for i in range(seconds):
        remaining = seconds - i
        pct = int((i / seconds) * 100)
        progress_line(label, pct, tail=f"{remaining:2d}s left")
        ok, method = quick_probe()
        if ok:
            clear_progress_line()
            finalize_success(reason, method=method)
        target = start + (i + 1)
        now = time.monotonic()
        time.sleep(max(0.0, target - now))
    clear_progress_line()

# ====== License / unlock (PBKDF2 + HMAC) ======
def _pbkdf_hash_hex(pw: str) -> str:
    raw = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), _PBKDF_SALT, _PBKDF_ITERS)
    return raw.hex()

def _hmac_sign(data_bytes: bytes) -> str:
    sig = hmac.new(_HMAC_SECRET, data_bytes, hashlib.sha256).digest()
    return base64.b16encode(sig).decode("ascii")

def _license_load() -> dict | None:
    if not os.path.exists(LICENSE_PATH):
        return None
    try:
        with open(LICENSE_PATH, "r", encoding="utf-8") as f:
            blob = json.load(f)
        data_b64 = blob.get("data", "")
        sig_hex  = blob.get("sig", "")
        data_bytes = base64.b64decode(data_b64.encode("ascii"))
        if _hmac_sign(data_bytes) != sig_hex:
            warn("License file failed signature verification (tamper suspected).")
            return None
        return json.loads(data_bytes.decode("utf-8"))
    except Exception as e:
        warn(f"Failed to read license: {e}")
        return None

def _license_save(payload: dict) -> None:
    data_bytes = json.dumps(payload, separators=(",",":")).encode("utf-8")
    sig_hex = _hmac_sign(data_bytes)
    blob = {"data": base64.b64encode(data_bytes).decode("ascii"), "sig": sig_hex}
    with open(LICENSE_PATH, "w", encoding="utf-8") as f:
        json.dump(blob, f)

def _license_init_if_missing():
    lic = _license_load()
    if lic is None:
        lic = {
            "secret_id": SECRET_ID,
            "remaining": DEFAULT_FREE_RUNS,
            "created": now_iso(),
            "unlocked": False
        }
        _license_save(lic)
    return lic

def license_gate_and_decrement():
    lic = _license_init_if_missing()
    remaining = int(lic.get("remaining", 0))
    unlocked  = bool(lic.get("unlocked", False))

    print()
    line()
    print(VERSION)
    line()
    if unlocked:
        info(f"License: unlocked — thank you for supporting NetFix. (Secret-ID: {SECRET_ID})")
    else:
        info(f"Free uses remaining: {remaining} (Secret-ID: {SECRET_ID})")
        if remaining <= 0:
            print()
            warn("Free uses exhausted.")
            print("To keep using NetFix, please enter your unlock password.")
            # (Using getpass here; if you prefer visible input, replace accordingly.)
            pw = getpass.getpass("Unlock password: ")
            if _pbkdf_hash_hex(pw) == _UNLOCK_HASH_HEX:
                lic["unlocked"] = True
                lic["remaining"] = 1500  # generous cap for unlocked mode
                _license_save(lic)
                success("Thank you — license unlocked on this machine.")
            else:
                error("Incorrect password. Exiting.")
                sys.exit(1)
        else:
            # decrement
            lic["remaining"] = max(0, remaining - 1)
            _license_save(lic)
            info(f"This run will be recorded. Remaining after run: {lic['remaining']}")

# ====== UI helpers ======
def _open_airplane_mode():
    add_event("open", "ms-settings:network-airplanemode")
    if REPORT_ONLY:
        return
    try: run_visible(["cmd", "/c", "start", "", "ms-settings:network-airplanemode"])
    except Exception: pass

def _open_wifi_settings():
    add_event("open", "ms-settings:network-wifi")
    if REPORT_ONLY:
        return
    try: run_visible(["cmd", "/c", "start", "", "ms-settings:network-wifi"])
    except Exception: pass

def _open_network_flyout():
    add_event("open", "ms-availablenetworks:")
    if REPORT_ONLY:
        return
    try: run_visible(["cmd", "/c", "start", "", "ms-availablenetworks:"])
    except Exception: pass

def prompt_watch_online_quiet(prompt: str, valid=()):
    """Non-blocking prompt with background probes; returns the user's answer (lowercased)."""
    print(prompt, end="", flush=True)
    add_event("prompt", prompt.strip())
    buf = ""
    last_probe = 0.0
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                print()
                ans = buf.strip().lower()
                add_event("input", ans)
                return ans
            elif ch == "\b":
                if buf:
                    buf = buf[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            else:
                buf += ch
                sys.stdout.write(ch)
                sys.stdout.flush()

        now = time.monotonic()
        if now - last_probe >= 1.0:
            last_probe = now
            ok, method = quick_probe()
            if ok:
                finalize_success("auto-detected during prompt", method=method)
        time.sleep(0.05)

# ====== elevation & services ======
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def assert_admin():
    if not is_admin():
        error("NetFix must be run as Administrator for adapter toggles to work.")
        info("Right-click your terminal and choose 'Run as administrator', then re-run.")
        exit_countdown(); sys.exit(1)

def ensure_wlan_service():
    state = run(["sc", "query", "WlanSvc"], capture=True)
    if "RUNNING" in (state.stdout or "").upper(): return
    info("Starting WLAN AutoConfig service …")
    start = run(["net", "start", "WlanSvc"], capture=True)
    if start.returncode != 0:
        warn("Could not start WlanSvc. Wi-Fi operations may fail.")
        print(start.stdout or start.stderr)

# ====== CONSENT ======
def consent_or_exit():
    section("CONSENT")
    print("This software was created by Antonio Reyes.")
    print("Proof-of-concept diagnostic tool, provided AS-IS with NO WARRANTY.")
    print("By typing YES you agree not to hold the author liable for any damages.\n")
    while True:
        ans = input("Type YES to accept and continue, or NO to exit: ").strip().lower()
        add_event("input", f"consent={ans}")
        if ans in ("yes","y"):
            return
        if ans in ("no","n"):
            info("Exiting without making changes."); exit_countdown(); sys.exit(0)
        print("Please type YES or NO.")

# ====== Mode chooser (S1+S2 line) ======
def choose_mode(cli_report_only: bool | None):
    """
    Lets the user pick:
      1) Diagnose only (no changes)
      2) Guided Fix (admin; performs safe repairs)
      3) Exit
    If cli_report_only is provided (True/False), we skip the menu.
    """
    global REPORT_ONLY
    if cli_report_only is not None:
        REPORT_ONLY = bool(cli_report_only)
        DIAG["mode"] = "diagnose" if REPORT_ONLY else "guided-fix"
        return

    line()
    print("No jargon, no surprises—first I can diagnose (no changes), and only if you choose, "
          "I’ll run safe fixes. Clear steps, plain English; if we have to chase out gremlins, "
          "I’ll tell you first.")
    line()

    print("Choose how you'd like to run NetFix:")
    print("  1) Diagnose only (no changes) — creates a readable report for a technician")
    print("  2) Guided Fix (admin) — attempts safe repairs automatically")
    print("  3) Exit")
    line()
    while True:
        sel = input("Select 1, 2, or 3: ").strip()
        if sel == "1":
            REPORT_ONLY = True
            DIAG["mode"] = "diagnose"
            print("\n[Mode] Diagnose only — I’ll collect info and suggest next steps. No changes will be made.")
            return
        if sel == "2":
            REPORT_ONLY = False
            DIAG["mode"] = "guided-fix"
            print("\n[Mode] Guided Fix — I’ll try safe repairs automatically (and explain what I do).")
            return
        if sel == "3":
            info("Exiting per user selection."); sys.exit(0)
        print("Please type 1, 2, or 3.")

# ====== MAIN ======
def run_fix(cli_report_only: bool | None):
    # License gate & decrement (before anything)
    license_gate_and_decrement()

    # Mode choice (after license shown)
    choose_mode(cli_report_only)

    section("NETFIX START")
    if not REPORT_ONLY:
        assert_admin()
    ensure_wlan_service()
    consent_or_exit()

    # Airplane/radio detection
    section("AIRPLANE MODE & RADIO CHECK")
    am = is_airplane_mode_on()
    hw_reg, sw_reg = wifi_hw_sw_from_registry()
    oklink, ssid, sig = wifi_connected_details()

    DIAG["wifi_hw"] = hw_reg
    DIAG["wifi_sw"] = sw_reg
    DIAG["wifi_link"] = bool(oklink)
    DIAG["airplane"] = am

    print("   Radio Summary:")
    print(f"     - Wi-Fi hardware radio: {hw_reg or '??'}")
    print(f"     - Wi-Fi software radio: {sw_reg or '??'}")
    print(f"     - Wi-Fi link state    : {'connected' if oklink else 'disconnected'}")
    print(f"     - Airplane Mode       : {'ON' if am else 'OFF' if am is False else 'unknown'}")

    if am:
        banner("AIRPLANE", "Airplane Mode appears ON — internet blocked until disabled.")
    if sw_reg == "OFF":
        banner("RADIO", "Wi-Fi software radio is OFF — enable Wi-Fi to proceed.")

    # If already online, exit early with success
    bail_if_online("initial check", full=True)

    # APIPA phase
    section("STEP — APIPA CHECK/RECOVERY")
    wf = first_wifi()
    if wf and has_apipa(wf):
        if REPORT_ONLY:
            banner("APIPA", f"169.254.x.x detected on {wf} — DHCP lease failed (DORA). (Diagnose-only: not changing settings)")
        else:
            fix_apipa(wf)
            bail_if_online("post-APIPA recovery", full=True)
    else:
        info("No APIPA detected on Wi-Fi — skipping APIPA recovery.")

    # Guided Wi-Fi assist (only if not report-only)
    section("STEP — WI-FI REPAIRS")
    if wf:
        if REPORT_ONLY:
            info("Diagnose-only mode: not opening Settings or toggling adapters.")
            info("Tip: Open Wi-Fi settings, toggle Wi-Fi ON, connect to your network, then rerun Guided Fix if needed.")
        else:
            info(f"Wi-Fi adapter present: {wf}")
            action("Opening Wi-Fi Settings and the Network flyout. Toggle Wi-Fi ON, pick your network, then return here.")
            _open_wifi_settings()
            _open_network_flyout()
            while True:
                ans = prompt_watch_online_quiet(
                    "Type YES when Wi-Fi is ON, RETRY to re-check, or SKIP to skip Wi-Fi repairs [YES/RETRY/SKIP]: ",
                    valid=("yes","y","retry","r","skip","s")
                )
                if ans in ("yes","y"):
                    DIAG["user_confirm_wifi_on"] = True
                    wait_or_finish("Waiting for Wi-Fi to associate", T["manual_wifi_wait"], "manual Wi-Fi confirm")
                    warn("Still offline after manual confirmation.")
                    choice = prompt_watch_online_quiet(
                        "Next action: [R]etry / [C]ycle Wi-Fi / S[k]ip: ",
                        valid=("r","retry","c","cycle","k","skip")
                    )
                    if choice.startswith("r"):
                        bail_if_online("manual retry", full=True)
                        continue
                    elif choice.startswith("c"):
                        DIAG["wifi_cycled_manual"] = True
                        DIAG["actions"].append("Cycled Wi-Fi adapter (manual)")
                        info("Cycling Wi-Fi OFF/ON for a clean reassociation …")
                        set_iface(wf, False)
                        time.sleep(T["nic_toggle_pause"])
                        set_iface(wf, True)
                        wait_or_finish("Allowing Wi-Fi to reassociate", T["wifi_reassoc"], "Wi-Fi reassociation")
                        continue
                    elif choice.startswith("k"):
                        info("Skipping Wi-Fi repairs as requested.")
                        break
                    else:
                        print("Please choose R, C, or K.")
                        continue
                elif ans in ("retry","r"):
                    bail_if_online("manual retry", full=True)
                    continue
                elif ans in ("skip","s"):
                    info("Skipping manual Wi-Fi step as requested.")
                    break
                else:
                    print("Please type YES, RETRY, or SKIP.")
    else:
        info("No Wi-Fi interface detected — skipping Wi-Fi reset.")

    # Local loopback (sanity)
    section("STEP — LOCAL LOOPBACK")
    bail_if_online("pre-loopback", full=True)
    info("Pinging 127.0.0.1 …")
    if not run(["ping", "127.0.0.1", "-n", "2", "-w", "700"]).returncode == 0:
        error("Local TCP/IP stack ping failed — adapter/stack may be unhealthy.")
    else:
        info("Loopback OK.")

    # Final check
    section("FINAL CHECK")
    bail_if_online("final check", full=True)

    print()
    DIAG["outcome"] = "failure"
    prog_path, dl_path = write_ticket("failure")
    error("Sorry — NetFix couldn’t restore connectivity automatically.")
    if dl_path:
        print(f"[Saved for tickets] {dl_path}")
    else:
        print(f"[Saved for tickets] {prog_path}")
    print()
    line("=")
    print("Possible Causes & What You Can Try Next:")
    tips = [
        "Router/AP DHCP server may be down or pool exhausted (reboot router/AP; check DHCP scope).",
        "Ensure 'WLAN AutoConfig' and 'DHCP Client' services are Automatic and RUNNING (services.msc).",
        "Verify Airplane Mode is OFF and Wi-Fi radio is ON.",
        "Re-enter Wi-Fi credentials (forget/reconnect).",
        "Temporarily disable VPN/security suites and test again.",
        "Check Date/Time (auto time) — bad clocks break HTTPS.",
        "Try another SSID or Ethernet directly to the modem.",
    ]
    for i, tip in enumerate(tips, 1):
        print(f"  {i}. {tip}")
    line("=")

    print()
    ans = input("Restart now to attempt recovery? (y/n): ").strip().lower()
    if ans in ("y","yes"):
        info("Rebooting in 5 seconds… Save your work.")
        time.sleep(5)
        run(["shutdown","/r","/t","0"])
        return 1
    else:
        info("No restart selected. Closing program.")
        exit_countdown()
        return 1

# ====== CLI entry ======
if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--report-only", action="store_true",
                        help="Run diagnosis only (no changes). Skips the mode menu.")
    args, _ = parser.parse_known_args()
    cli_mode = True if args.report_only else None  # None -> show menu
    sys.exit(run_fix(cli_mode))
