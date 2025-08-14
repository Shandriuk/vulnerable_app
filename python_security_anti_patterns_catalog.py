
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intentionally Vulnerable Patterns for Scanner Testing (Education Only)
=====================================================================

This single file includes patterns meant to be caught by:
- Gitleaks Scan (10 examples)
- Bandit (10 examples)
- Trufflehog3 Scan (10 examples)
- Trivy Code Dependencies (10 vulnerable pins as a requirements sample)
- Semgrep (10 examples)

⚠️ WARNING: This content is for testing scanners in an isolated, non-production repo.
Do NOT use any real secrets. All secrets below are FAKE placeholders for detection only.
Nothing is executed by default.
"""

# ---------------------------------------------------------------------------
# Section A — GITLEAKS (10 patterns)
# ---------------------------------------------------------------------------
# Note: These are FAKE tokens, crafted to match common secret regexes for scanner tests.

GITLEAKS_01_AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"  # 20 chars, looks like AWS Access Key ID (FAKE)
GITLEAKS_02_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars (FAKE)
GITLEAKS_03_GITHUB_PAT = "ghp_ZYXWvutsrqponmlkjihgfedcba1234567890"  # GitHub Personal Access Token pattern (FAKE)
GITLEAKS_04_SLACK_BOT_TOKEN = "xoxb-123456789012-123456789012-ABCDEFGHIJKLMNOPQRST"  # Slack bot token (FAKE)
GITLEAKS_05_GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstu"  # Google API key (FAKE)
GITLEAKS_06_STRIPE_LIVE_SECRET = "sk_live_51HfKc0AbCdEfGhIjKlMnOpQr"  # Stripe live secret key pattern (FAKE)
GITLEAKS_07_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArandomrandomrandomrandomrandomrandom
-----END RSA PRIVATE KEY-----
"""  # Private key block (FAKE)
GITLEAKS_08_OPENSSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABGZha2U=
-----END OPENSSH PRIVATE KEY-----
"""  # OpenSSH key block (FAKE)
GITLEAKS_09_SENTRY_DSN = "https://12345abcde@o12345.ingest.sentry.io/1234567"  # Sentry DSN (FAKE)
GITLEAKS_10_TWILIO_AUTH_TOKEN = "TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef"  # Twilio token-ish (FAKE)

# ---------------------------------------------------------------------------
# Section B — TRUFFLEHOG3 (10 patterns)
# ---------------------------------------------------------------------------
# Additional secret-like values (FAKE). Trufflehog uses regex + entropy.

TRUFFLEHOG3_01_AZURE_STORAGE = (
    "DefaultEndpointsProtocol=https;AccountName=dummyacct;"
    "AccountKey=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGh=;"
    "EndpointSuffix=core.windows.net"
)  # FAKE Azure Storage connection string

TRUFFLEHOG3_02_POSTGRES_URL = "postgres://scanuser:VeryS3cretPassw0rd@db.example.com:5432/appdb"  # FAKE DSN
TRUFFLEHOG3_03_GITLAB_PAT = "glpat-1234567890abcdefghijklmn"  # GitLab Personal Access Token pattern (FAKE)
TRUFFLEHOG3_04_SENDGRID_API_KEY = "SG.abcdEFGHijklMNOPqrstUVWX.yz0123456789ABCDEFGHijklMNOPQRSTUV"  # FAKE
TRUFFLEHOG3_05_NPM_TOKEN = "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"  # FAKE
TRUFFLEHOG3_06_PYPI_TOKEN = "pypi-AgENdGVzdC5weXBpLm9yZwIkLWFhYmJiY2NjZGRkZWVl"  # FAKE
TRUFFLEHOG3_07_SHOPIFY_TOKEN = "shpat_1234567890abcdef1234567890abcdef"  # FAKE
TRUFFLEHOG3_08_DOCKERHUB_TOKEN = "dckr_pat_abcdefghijklmno1234567890"  # FAKE-ish
TRUFFLEHOG3_09_AWS_SESSION_TOKEN = "IQoJb3JpZ2luX2VjEKD//////////wEaDmV1LXdlc3QtMiJHMEUCIQDxFAKEl0"  # FAKE
TRUFFLEHOG3_10_GCP_SA_JSON = """{
  "type": "service_account",
  "project_id": "scanner-test",
  "private_key_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BA...FAKE...\n-----END PRIVATE KEY-----\n",
  "client_email": "svc@scanner-test.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth"
}"""  # FAKE

# ---------------------------------------------------------------------------
# Section C — BANDIT (10 examples)
# ---------------------------------------------------------------------------
# Intentionally unsafe patterns. Not executed unless you call them.

def bandit_01_eval(user_input: str = "1+1"):
    # BAD: eval on untrusted input (B307)
    return eval(user_input)  # nosec B307

def bandit_02_exec(user_input: str = "print('hello')"):
    # BAD: exec on untrusted input (B102)
    exec(user_input)  # nosec B102

def bandit_03_subprocess_shell(cmd: str = "ls -la"):
    # BAD: shell=True allows injection (B602/B607)
    import subprocess
    subprocess.Popen(cmd, shell=True)  # nosec B602

def bandit_04_yaml_load(data: str = "a: 1"):
    # BAD: unsafe yaml.load (B506)
    import yaml
    return yaml.load(data, Loader=yaml.Loader)  # nosec B506

def bandit_05_pickle_load(blob: bytes = b"cos\nsystem\n(S'echo hello'\ntR."):
    # BAD: pickle loads arbitrary code (B301)
    import pickle
    return pickle.loads(blob)  # nosec B301

def bandit_06_md5(password: str = "secret"):
    # BAD: weak hash for passwords (B303)
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()  # nosec B303

def bandit_07_random_for_secrets():
    # BAD: insecure randomness for secrets (B311)
    import random
    return "".join(str(random.randint(0, 9)) for _ in range(16))  # nosec B311

def bandit_08_requests_insecure():
    # BAD: disable TLS verification + missing timeout (B501/B113)
    import requests
    return requests.get("https://example.com", verify=False)  # nosec B501

def bandit_09_tempfile_mktemp():
    # BAD: insecure temp file creation (B306)
    import tempfile
    name = tempfile.mktemp()  # nosec B306
    return name

def bandit_10_tarfile_extractall(tar_path: str = "archive.tar"):
    # BAD: unsafe tar extraction (B202)
    import tarfile
    tf = tarfile.open(tar_path)
    tf.extractall(path="./extract_here")  # nosec B202

# ---------------------------------------------------------------------------
# Section D — SEMGREP (10 examples)
# ---------------------------------------------------------------------------
# Semgrep rulesets (e.g., python.lang.security) should flag these.

def semgrep_01_exec(user_input: str = "print('hi')"):
    # bad: exec on untrusted input
    exec(user_input)

def semgrep_02_eval(user_input: str = "2*3"):
    # bad: eval on untrusted input
    return eval(user_input)

def semgrep_03_subprocess_shell(cmd: str = "whoami"):
    import subprocess
    # bad: shell=True
    subprocess.call(cmd, shell=True)

def semgrep_04_requests_verify_false():
    import requests
    # bad: TLS verification disabled
    return requests.get("https://example.com", verify=False)

def semgrep_05_yaml_unsafe_load(s: str = "a: 1"):
    import yaml
    # bad: yaml.load with default/unsafe loader
    return yaml.load(s)

def semgrep_06_pickle_load(blob: bytes = b"cos\nsystem\n(S'echo x'\ntR."):
    import pickle
    # bad: pickle.loads on untrusted data
    return pickle.loads(blob)

def semgrep_07_flask_debug():
    # bad: Flask debug=True, host=0.0.0.0
    from flask import Flask
    app = Flask(__name__)
    app.run(host="0.0.0.0", debug=True)

def semgrep_08_assert_auth(is_admin: bool = False):
    # bad: assert used for auth logic
    assert is_admin

def semgrep_09_hardcoded_password():
    # bad: hardcoded password literal
    password = "P@ssw0rd123"
    return password

def semgrep_10_insecure_hash(data: bytes = b"abc"):
    import hashlib
    # bad: MD5 used
    return hashlib.md5(data).hexdigest()

# ---------------------------------------------------------------------------
# Section E — TRIVY Code Dependencies (10 vulnerable pins)
# ---------------------------------------------------------------------------
# Trivy checks dependency manifests. Use this helper to emit a sample requirements file.
# All versions below are *intentionally old* and known historically to have CVEs.
# Do NOT deploy them. They are for scanner exercises only.

TRIVY_REQUIREMENTS_SAMPLE = """\
# FAKE requirements for Trivy scanner testing ONLY — do not use in production!
requests==2.19.1        # CVE-2018-18074 (session fixation/cred leak)
urllib3==1.24.1         # CVE-2019-11324
PyYAML==5.1             # CVE-2020-1747 et al (unsafe load)
Django==2.0.0           # multiple historical CVEs
Flask==0.12             # historical issues
Jinja2==2.10            # CVE-2019-10906
Pillow==6.2.0           # multiple CVEs
lxml==4.6.0             # CVE-2021-43818 et al
cryptography==2.1.4     # historical CVEs
MarkupSafe==1.0         # historical CVEs
"""

def emit_requirements_for_trivy(path: str = "requirements_trivy_example.txt") -> str:
    """Write the TRIVY_REQUIREMENTS_SAMPLE to a file to be scanned by Trivy."""
    p = Path(path)
    p.write_text(TRIVY_REQUIREMENTS_SAMPLE, encoding="utf-8")
    return str(p)

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("This file is for scanner testing in a safe environment.")
    print("Nothing runs unless you call functions manually.")
    print("If you want a requirements.txt for Trivy, call emit_requirements_for_trivy().")
