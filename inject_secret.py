#!/usr/bin/env python3
"""
inject_secret.py

Usage:
  python inject_secret.py path\to\net_fix.py

Reads env vars:
  NETFIX_HMAC_SECRET_HEX  -> 64+ hex chars (recommended: 32 random bytes => 64 hex)
  NETFIX_SECRET_ID        -> e.g., "2025.11.06-rc1"
  NETFIX_VERSION          -> e.g., "1.0.0"

If NETFIX_HMAC_SECRET_HEX is missing, a random 32-byte secret is generated for this build.
If SECRET_ID / VERSION are missing, reasonable defaults are generated.

It replaces these lines in net_fix.py (wherever they appear):
  _HMAC_SECRET = ...
  SECRET_ID    = ...
  VERSION      = ...
"""

import os, re, sys, datetime, binascii

def die(msg: str, code: int = 2):
    print(f"[inject_secret] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return f.read()

def write_text(path: str, text: str):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)

def main():
    if len(sys.argv) != 2:
        die("Usage: python inject_secret.py path\\to\\net_fix.py")

    target = sys.argv[1]
    if not os.path.isfile(target):
        die(f"File not found: {target}")

    src = read_text(target)

    # --- gather inputs ---
    hex_secret = os.getenv("NETFIX_HMAC_SECRET_HEX", "").strip()
    if hex_secret:
        # normalize & validate
        hex_secret = hex_secret.lower().replace("0x", "")
        try:
            raw = binascii.unhexlify(hex_secret)
        except binascii.Error as e:
            die(f"NETFIX_HMAC_SECRET_HEX is not valid hex: {e}")
        if len(raw) < 16:
            die("NETFIX_HMAC_SECRET_HEX too short; need at least 16 bytes (32 hex). Recommended: 32 bytes (64 hex).")
        if len(raw) != 32:
            print(f"[inject_secret] WARNING: secret has {len(raw)} bytes; recommended is 32 bytes.", file=sys.stderr)
    else:
        import os as _os
        raw = _os.urandom(32)
        hex_secret = raw.hex()
        print("[inject_secret] No NETFIX_HMAC_SECRET_HEX provided; generated a random 32-byte secret for this build.")

    secret_id = os.getenv("NETFIX_SECRET_ID", "").strip() or f"local-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    version   = os.getenv("NETFIX_VERSION", "").strip()   or "0.0.0-dev"

    # --- build replacement strings ---
    rep_secret  = f"_HMAC_SECRET = bytes.fromhex('{hex_secret}')"
    rep_secid   = f"SECRET_ID    = '{secret_id}'"
    rep_version = f"VERSION      = '{version}'"

    # --- regexes (loose; replace entire assignment lines) ---
    pat_secret  = re.compile(r"^(\s*)_HMAC_SECRET\s*=\s*.*$", re.MULTILINE)
    pat_secid   = re.compile(r"^(\s*)SECRET_ID\s*=\s*.*$", re.MULTILINE)
    pat_version = re.compile(r"^(\s*)VERSION\s*=\s*.*$", re.MULTILINE)

    # ensure targets exist; if not, append near top after imports
    inserted = False
    if not pat_secret.search(src):
        src = src.replace("\n# --- UTF-8 console safety ---", f"\n# Build-time injected\n{rep_secret}\n{rep_secid}\n{rep_version}\n\n# --- UTF-8 console safety ---")
        inserted = True
    else:
        # keep indentation from first match, if any
        m = pat_secret.search(src)
        indent = m.group(1) if m else ""
        src = pat_secret.sub(f"\\1{rep_secret}", src)

        if pat_secid.search(src):
            src = pat_secid.sub(f"\\1{rep_secid}", src)
        else:
            src = src.replace(rep_secret, f"{rep_secret}\n{indent}{rep_secid}")

        if pat_version.search(src):
            src = pat_version.sub(f"\\1{rep_version}", src)
        else:
            src = src.replace(rep_secid, f"{rep_secid}\n{indent}{rep_version}")

    write_text(target, src)

    print("[inject_secret] Injection complete.")
    print(f"[inject_secret] SECRET_ID = {secret_id}")
    print(f"[inject_secret] VERSION   = {version}")
    if inserted:
        print("[inject_secret] (Placeholders not found; inserted new constants block.)")

if __name__ == "__main__":
    main()
