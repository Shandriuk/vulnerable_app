#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Catalog of Python Security Anti-Patterns (educational)
======================================================

This single-file catalog summarizes MANY common vulnerability patterns you might run
into in Python projects. It is designed for **education** and **code review training**.
Every "vulnerable" snippet is intentionally commented-out so it cannot run by accident.
Each section includes a short explanation and a safer alternative (sketch).

⚠️ IMPORTANT: Do not copy the vulnerable patterns into real code.
"""

from __future__ import annotations
import os
import re
import sys
import hmac
import json
import base64
import sqlite3
import hashlib
import logging
import secrets
import tempfile
import zipfile
import stat
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

try:
    import requests  # for some examples; not required to run this file
except Exception:
    requests = None

try:
    import yaml  # PyYAML
except Exception:
    yaml = None

try:
    import xml.etree.ElementTree as ET
except Exception:
    ET = None

# ---------------------------------------------------------------------------
# 0. Contents
# ---------------------------------------------------------------------------

CONTENTS = [
    "1. eval/exec on untrusted input (CWE-94)",
    "2. OS command injection via shell=True / os.system (CWE-78)",
    "3. SQL Injection by string formatting (CWE-89)",
    "4. Path Traversal when using user-controlled file paths (CWE-22)",
    "5. Zip Slip on extraction (CWE-22)",
    "6. Insecure deserialization with pickle (CWE-502)",
    "7. Unsafe YAML load (CWE-502)",
    "8. Weak randomness for secrets (CWE-330)",
    "9. Hardcoded credentials & keys (CWE-798)",
    "10. SSL verification disabled (CWE-295)",
    "11. SSRF: fetching user-supplied URLs (CWE-918)",
    "12. Open Redirect in web apps (CWE-601)",
    "13. XSS by disabling autoescape / trusting HTML (CWE-79)",
    "14. Missing CSRF protection (CWE-352)",
    "15. IDOR (Insecure Direct Object Reference) (CWE-639)",
    "16. Insecure hashing for passwords (MD5/SHA1) (CWE-327)",
    "17. Block cipher misuse (ECB / static IV) (CWE-327)",
    "18. JWT verification pitfalls (alg=none / wrong verification) (CWE-347)",
    "19. Overly-permissive file permissions (CWE-732)",
    "20. Insecure temp files (CWE-377)",
    "21. TOCTOU race (CWE-367)",
    "22. Verbose error leaks / debug mode (CWE-209)",
    "23. Logging sensitive data (CWE-532)",
    "24. Wildcard CORS (CWE-942)",
    "25. Unbounded file upload / request size (CWE-400)",
    "26. ReDoS: catastrophic regex backtracking (CWE-1333)",
    "27. Decompression bombs (zip/gzip) (CWE-409)",
    "28. XXE (XML External Entity) (CWE-611)",
    "29. Server-Side Template Injection (SSTI) (CWE-1336)",
    "30. Using assert for auth/validation (CWE-617)",
    "31. Unbounded network timeouts (CWE-400)",
    "32. Host header injection / URL building (CWE-74/918)",
    "33. Prototype-style config pollution (overriding reserved keys) (CWE-915)",
    "34. Insecure caching / missing cache key parts (CWE-1021)",
    "35. Insecure chmod/umask on secrets (CWE-266)",
    "36. Cryptographic oracle by detailed error messages (CWE-209/203)",
    "37. Missing rate limiting / brute-forceable endpoints (CWE-307)",
    "38. Unvalidated redirects in OAuth flows (CWE-601)",
    "39. Unsafe use of eval in admin/bot flows (CWE-94)",
    "40. Shell expansion with globbing/wildcards (CWE-78)",
]

# ---------------------------------------------------------------------------
# 1. eval/exec on untrusted input (CWE-94)
# ---------------------------------------------------------------------------

def example_eval_exec(user_input: str) -> Any:
    """
    VULNERABLE idea: evaluating untrusted input.
    Never use eval/exec on data you don't fully control.
    """
    # VULNERABLE (commented out):
    # result = eval(user_input)  # DO NOT DO THIS
    # exec(user_input)           # DO NOT DO THIS

    # SAFER: avoid dynamic evaluation. Parse and validate inputs explicitly.
    # For calculators or DSLs, write a parser or use a vetted sandbox library.
    return "Avoid eval/exec; parse input instead."

# ---------------------------------------------------------------------------
# 2. OS command injection via shell=True / os.system (CWE-78)
# ---------------------------------------------------------------------------

def example_os_command_injection(filename: str) -> None:
    """
    VULNERABLE idea: constructing shell commands from untrusted strings.
    Attacker can inject; e.g., filename='report.txt; rm -rf /'.
    """
    # VULNERABLE (commented out):
    # os.system(f"cat {filename}")  # command injection risk
    # subprocess.run(f"cat {filename}", shell=True)  # injection risk

    # SAFER: use subprocess with list args and shell=False. Validate the path.
    # subprocess.run(["cat", filename], check=True)  # still validate input!
    pass

# ---------------------------------------------------------------------------
# 3. SQL Injection by string formatting (CWE-89)
# ---------------------------------------------------------------------------

def example_sql_injection(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    """
    VULNERABLE idea: building SQL with format/concat.
    username = "' OR 1=1 --" may dump all rows.
    """
    # VULNERABLE (commented out):
    # cur = conn.cursor()
    # cur.execute(f"SELECT * FROM users WHERE username = '{username}'")  # NO!
    # return cur.fetchone()

    # SAFE: parameterized queries
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

# ---------------------------------------------------------------------------
# 4. Path Traversal (CWE-22)
# ---------------------------------------------------------------------------

def example_path_traversal(user_path: str, base_dir: Path) -> bytes:
    """
    VULNERABLE idea: directly joining user path to base dir, allowing '../../'.
    """
    # VULNERABLE (commented out):
    # target = base_dir / user_path
    # return target.read_bytes()  # could read /etc/passwd

    # SAFE: resolve & ensure inside base directory
    target = (base_dir / user_path).resolve()
    base = base_dir.resolve()
    if not str(target).startswith(str(base) + os.sep):
        raise ValueError("Invalid path")
    return b""

# ---------------------------------------------------------------------------
# 5. Zip Slip on extraction (CWE-22)
# ---------------------------------------------------------------------------

def example_zip_slip(zip_path: Path, extract_to: Path) -> None:
    """
    VULNERABLE idea: blindly extracting archive paths that contain '../'.
    """
    # VULNERABLE (commented out):
    # with zipfile.ZipFile(zip_path, 'r') as z:
    #     z.extractall(extract_to)  # may overwrite arbitrary files

    # SAFE: sanitize each member
    with zipfile.ZipFile(zip_path, 'r') as z:
        for member in z.infolist():
            out = (extract_to / member.filename).resolve()
            if not str(out).startswith(str(extract_to.resolve()) + os.sep):
                raise ValueError("Zip Slip detected")
            # z.extract(member, extract_to)  # Uncomment only after checks
    return None

# ---------------------------------------------------------------------------
# 6. Insecure deserialization with pickle (CWE-502)
# ---------------------------------------------------------------------------

def example_pickle_load(data: bytes) -> Any:
    """
    VULNERABLE idea: pickle allows arbitrary code execution when loading.
    """
    # VULNERABLE (commented out):
    # import pickle
    # return pickle.loads(data)  # DO NOT load untrusted pickle

    # SAFE: use JSON or other safe formats; define strict schema.
    return json.loads(data.decode("utf-8")) if data else None

# ---------------------------------------------------------------------------
# 7. Unsafe YAML load (CWE-502)
# ---------------------------------------------------------------------------

def example_yaml_load(text: str) -> Any:
    """
    VULNERABLE idea: yaml.load can construct arbitrary objects.
    """
    if yaml is None:
        return None
    # VULNERABLE (commented out):
    # return yaml.load(text, Loader=yaml.Loader)  # unsafe

    # SAFE:
    return yaml.safe_load(text)

# ---------------------------------------------------------------------------
# 8. Weak randomness for secrets (CWE-330)
# ---------------------------------------------------------------------------

def example_weak_random_token() -> str:
    """
    VULNERABLE idea: using random for tokens/session IDs.
    """
    # VULNERABLE (commented out):
    # token = "".join(str(random.randint(0, 9)) for _ in range(16))

    # SAFE:
    return secrets.token_urlsafe(32)

# ---------------------------------------------------------------------------
# 9. Hardcoded credentials & keys (CWE-798)
# ---------------------------------------------------------------------------

# VULNERABLE (commented out):
# DB_PASSWORD = "supersecret"  # Hardcoded in source
# API_KEY = "sk_live_abc123"

def example_no_hardcoded_secrets() -> None:
    """Use env vars or secret managers; rotate regularly."""
    os.getenv("DB_PASSWORD")
    return None

# ---------------------------------------------------------------------------
# 10. SSL verification disabled (CWE-295)
# ---------------------------------------------------------------------------

def example_insecure_tls(url: str) -> Optional[requests.Response]:
    """
    VULNERABLE idea: turning off certificate verification.
    """
    if requests is None:
        return None
    # VULNERABLE (commented out):
    # return requests.get(url, verify=False)  # MITM risk

    # SAFE:
    return requests.get(url, timeout=10)

# ---------------------------------------------------------------------------
# 11. SSRF: fetching user-supplied URLs (CWE-918)
# ---------------------------------------------------------------------------

def example_ssrf_fetch(url: str) -> str:
    """
    VULNERABLE idea: backend fetches arbitrary URL provided by the client.
    Can hit internal metadata services or localhost.
    """
    # VULNERABLE (commented out):
    # return requests.get(url, timeout=5).text

    # SAFE: validate scheme/host against an allowlist; block private IPs.
    return "Use allowlists and DNS/IP validation"

# ---------------------------------------------------------------------------
# 12. Open Redirect (CWE-601)
# ---------------------------------------------------------------------------

def example_open_redirect(next_url: str) -> str:
    """
    VULNERABLE idea: redirecting to arbitrary user-provided URL.
    """
    # VULNERABLE (commented out):
    # return redirect(next_url)

    # SAFE:
    allowed = {"https://example.com/dashboard"}
    return next_url if next_url in allowed else "/"

# ---------------------------------------------------------------------------
# 13. XSS by trusting HTML (CWE-79)
# ---------------------------------------------------------------------------

def example_xss_render(user_html: str) -> str:
    """
    VULNERABLE idea: rendering user HTML directly or disabling autoescape.
    """
    # VULNERABLE (commented out):
    # return f"<div>{user_html}</div>"  # may contain <script>

    # SAFE: escape user input or use templating with autoescape on.
    return "Escaped/autoescaped output"

# ---------------------------------------------------------------------------
# 14. Missing CSRF protection (CWE-352)
# ---------------------------------------------------------------------------

def example_missing_csrf() -> str:
    """
    VULNERABLE idea: state-changing endpoints with no CSRF token validation.
    """
    # SAFE: use framework CSRF protection (e.g., flask-wtf, Django middleware).
    return "Ensure CSRF tokens and same-site cookies"

# ---------------------------------------------------------------------------
# 15. IDOR (CWE-639)
# ---------------------------------------------------------------------------

def example_idor(resource_owner_id: int, requested_id: int) -> str:
    """
    VULNERABLE idea: 'requested_id' read without verifying ownership/role.
    """
    # VULNERABLE (commented out):
    # return db.get_profile(requested_id)

    # SAFE:
    if resource_owner_id != requested_id:
        raise PermissionError("Forbidden")
    return "Profile data"

# ---------------------------------------------------------------------------
# 16. Insecure hashing for passwords (CWE-327)
# ---------------------------------------------------------------------------

def example_md5_password_hash(password: str) -> str:
    """
    VULNERABLE idea: MD5/SHA1 without salt for passwords.
    """
    # VULNERABLE (commented out):
    # return hashlib.md5(password.encode()).hexdigest()

    # SAFE: use bcrypt/argon2/scrypt via reputable libs.
    return "Use argon2/bcrypt with per-user salts"

# ---------------------------------------------------------------------------
# 17. Block cipher misuse (ECB/static IV) (CWE-327)
# ---------------------------------------------------------------------------

def example_ecb_static_iv() -> str:
    """
    VULNERABLE idea: AES-ECB or static IV for CBC/GCM.
    """
    return "Use AEAD (e.g., AES-GCM/ChaCha20-Poly1305) with random IVs"

# ---------------------------------------------------------------------------
# 18. JWT verification pitfalls (CWE-347)
# ---------------------------------------------------------------------------

def example_jwt_alg_none(token: str) -> str:
    """
    VULNERABLE idea: accepting tokens with alg='none' or wrong key.
    """
    return "Always verify signature; restrict accepted algorithms"

# ---------------------------------------------------------------------------
# 19. Overly-permissive file permissions (CWE-732)
# ---------------------------------------------------------------------------

def example_over_permissive_perms(secret_path: Path) -> None:
    """
    VULNERABLE idea: world-readable secrets (e.g., chmod 0o777).
    """
    # VULNERABLE (commented out):
    # os.chmod(secret_path, 0o777)

    # SAFE:
    os.chmod(secret_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

# ---------------------------------------------------------------------------
# 20. Insecure temp files (CWE-377)
# ---------------------------------------------------------------------------

def example_insecure_tempfile(name: str) -> None:
    """
    VULNERABLE idea: predictable temp file names in shared directories.
    """
    # VULNERABLE (commented out):
    # tmp = f"/tmp/{name}.tmp"
    # open(tmp, "w").write("data")  # raceable

    # SAFE:
    with tempfile.NamedTemporaryFile(delete=True) as f:
        f.write(b"data")

# ---------------------------------------------------------------------------
# 21. TOCTOU race (CWE-367)
# ---------------------------------------------------------------------------

def example_toctou(path: Path) -> None:
    """
    VULNERABLE idea: check-then-use without atomicity.
    """
    # VULNERABLE (commented out):
    # if path.exists():
    #     with open(path, "w") as f:
    #         f.write("x")  # attacker can swap path

    # SAFE: open with flags ensuring atomic creation; use os.open + O_EXCL on *nix.
    # fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    # os.close(fd)
    pass

# ---------------------------------------------------------------------------
# 22. Verbose error leaks / debug mode (CWE-209)
# ---------------------------------------------------------------------------

def example_debug_mode() -> str:
    """
    VULNERABLE idea: deploying with debug=True (Flask) or stack traces to users.
    """
    return "Never enable debug in production; return sanitized errors"

# ---------------------------------------------------------------------------
# 23. Logging sensitive data (CWE-532)
# ---------------------------------------------------------------------------

def example_log_secrets(password: str) -> None:
    """
    VULNERABLE idea: logging secrets/API keys/PII.
    """
    # VULNERABLE (commented out):
    # logging.info("User password is %s", password)

    # SAFE:
    logging.info("Authenticated user")  # avoid sensitive fields

# ---------------------------------------------------------------------------
# 24. Wildcard CORS (CWE-942)
# ---------------------------------------------------------------------------

def example_cors() -> str:
    """
    VULNERABLE idea: Access-Control-Allow-Origin: * with credentials.
    """
    return "Restrict origins; avoid '*' with cookies; use allowlists"

# ---------------------------------------------------------------------------
# 25. Unbounded upload/request size (CWE-400)
# ---------------------------------------------------------------------------

def example_unbounded_upload(content_length: int) -> str:
    """
    VULNERABLE idea: accepting arbitrarily large uploads or requests.
    """
    max_len = 10 * 1024 * 1024
    if content_length > max_len:
        raise ValueError("Too large")
    return "OK"

# ---------------------------------------------------------------------------
# 26. ReDoS: catastrophic regex (CWE-1333)
# ---------------------------------------------------------------------------

def example_redos(user_text: str) -> bool:
    """
    VULNERABLE idea: catastrophic backtracking regex on attacker strings.
    """
    # VULNERABLE (commented out):
    # return bool(re.match(r"^(a+)+$", user_text))

    # SAFE: design linear-time regex or use timeouts.
    return bool(re.match(r"^a+$", user_text))

# ---------------------------------------------------------------------------
# 27. Decompression bombs (CWE-409)
# ---------------------------------------------------------------------------

def example_decompression_bomb(zip_fp: Path) -> str:
    """
    VULNERABLE idea: decompressing untrusted archives without limits.
    """
    # SAFE: impose limits on total uncompressed size and entry counts.
    return "Validate archive sizes and counts before extraction"

# ---------------------------------------------------------------------------
# 28. XXE (XML External Entity) (CWE-611)
# ---------------------------------------------------------------------------

def example_xxe(xml_text: str) -> Any:
    """
    VULNERABLE idea: parsing XML with external entities enabled.
    """
    if ET is None:
        return None
    # VULNERABLE (commented out):
    # ET.fromstring(xml_text)  # default parser may allow entity expansion

    # SAFE: use defusedxml or disable entity resolution explicitly.
    return "Use defusedxml or hardened parser"

# ---------------------------------------------------------------------------
# 29. SSTI (Server-Side Template Injection) (CWE-1336)
# ---------------------------------------------------------------------------

def example_ssti(template_str: str, context: Dict[str, Any]) -> str:
    """
    VULNERABLE idea: rendering user-controlled templates with Jinja directly.
    """
    # VULNERABLE (commented out):
    # from jinja2 import Template
    # return Template(template_str).render(**context)

    # SAFE: keep templates static; whitelist minimal template features.
    return "Do not render user-supplied templates"

# ---------------------------------------------------------------------------
# 30. Using assert for auth/validation (CWE-617)
# ---------------------------------------------------------------------------

def example_assert_checks(is_admin: bool) -> str:
    """
    VULNERABLE idea: 'assert is_admin' can be stripped with -O.
    """
    # VULNERABLE (commented out):
    # assert is_admin, "not admin"

    # SAFE:
    if not is_admin:
        raise PermissionError("Forbidden")
    return "OK"

# ---------------------------------------------------------------------------
# 31. Unbounded network timeouts (CWE-400)
# ---------------------------------------------------------------------------

def example_no_timeouts(url: str) -> Optional[str]:
    """
    VULNERABLE idea: network calls without timeouts (resource exhaustion).
    """
    if requests is None:
        return None
    # VULNERABLE (commented out):
    # requests.get(url)  # no timeout

    # SAFE:
    r = requests.get(url, timeout=5)
    return r.text

# ---------------------------------------------------------------------------
# 32. Host header injection / URL building (CWE-74/918)
# ---------------------------------------------------------------------------

def example_host_header_injection(host_header: str, path: str) -> str:
    """
    VULNERABLE idea: trusting Host header to build absolute URLs.
    """
    # VULNERABLE (commented out):
    # return f"http://{host_header}{path}"

    # SAFE: use a trusted canonical host from config.
    return f"https://example.com{path}"

# ---------------------------------------------------------------------------
# 33. Prototype-style config pollution (CWE-915)
# ---------------------------------------------------------------------------

RESERVED_CONFIG_KEYS = {"__class__", "__dict__", "__bases__", "__mro__"}

def example_config_pollution(user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    VULNERABLE idea: blindly merging user config into app config.
    """
    base_cfg = {"role": "user", "features": []}
    for k in list(user_cfg.keys()):
        if k in RESERVED_CONFIG_KEYS:
            raise ValueError("Reserved key")
    base_cfg.update(user_cfg)  # validate keys/values
    return base_cfg

# ---------------------------------------------------------------------------
# 34. Insecure caching / missing cache key parts (CWE-1021)
# ---------------------------------------------------------------------------

def example_bad_cache_key(user_id: int, page: int) -> str:
    """
    VULNERABLE idea: cache key misses auth/role/locale, causing mixups.
    """
    # VULNERABLE (commented out):
    # cache_key = f"page:{page}"

    # SAFE:
    cache_key = f"user:{user_id}:page:{page}"
    return cache_key

# ---------------------------------------------------------------------------
# 35. Insecure chmod/umask on secrets (CWE-266)
# ---------------------------------------------------------------------------

def example_save_secret(secret_path: Path, data: bytes) -> None:
    """
    VULNERABLE idea: writing secrets with default umask -> wider perms.
    """
    # SAFE: set restrictive permissions explicitly.
    with open(secret_path, "wb") as f:
        f.write(data)
    os.chmod(secret_path, stat.S_IRUSR | stat.S_IWUSR)

# ---------------------------------------------------------------------------
# 36. Cryptographic oracle via detailed errors (CWE-209/203)
# ---------------------------------------------------------------------------

def example_crypto_oracle(message: bytes, mac: bytes, key: bytes) -> bool:
    """
    VULNERABLE idea: returning distinct errors for MAC length vs content leaks timing/info.
    """
    # SAFE: use constant-time compare and uniform error messages.
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac)

# ---------------------------------------------------------------------------
# 37. Missing rate limiting (CWE-307)
# ---------------------------------------------------------------------------

def example_rate_limiting(ip: str, attempts: int) -> str:
    """
    VULNERABLE idea: unlimited login attempts -> brute force.
    """
    if attempts > 5:
        time.sleep(2)  # naive backoff; use proper rate limiting
        return "Too many attempts"
    return "OK"

# ---------------------------------------------------------------------------
# 38. Unvalidated redirects in OAuth flows (CWE-601)
# ---------------------------------------------------------------------------

def example_oauth_redirect(redirect_uri: str) -> str:
    """
    VULNERABLE idea: accepting arbitrary redirect_uri.
    """
    allowed = {"https://app.example.com/callback"}
    return redirect_uri if redirect_uri in allowed else "reject"

# ---------------------------------------------------------------------------
# 39. Unsafe eval in admin/bot flows (CWE-94)
# ---------------------------------------------------------------------------

def example_admin_eval(command: str) -> str:
    """
    VULNERABLE idea: admin-only eval endpoints/chatops; creds can be stolen.
    """
    # VULNERABLE (commented out):
    # return str(eval(command))

    return "Replace with explicit allowed commands"

# ---------------------------------------------------------------------------
# 40. Shell expansion with globbing/wildcards (CWE-78)
# ---------------------------------------------------------------------------

def example_shell_globbing(pattern: str) -> List[str]:
    """
    VULNERABLE idea: passing user patterns to shell globbing.
    """
    # VULNERABLE (commented out):
    # subprocess.run(f"rm {pattern}", shell=True)

    # SAFE: enumerate allowed files; avoid shell.
    return []

# ---------------------------------------------------------------------------
# End
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("This file is an educational catalog of Python security anti-patterns.")
    for entry in CONTENTS:
        print(" -", entry)
