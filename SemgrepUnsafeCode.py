import os
import subprocess
import yaml
import requests

# BAD: hardcoded secret (will be flagged by Semgrep's secrets pack)
API_KEY = "sk_live_1234567890SECRET"

def run_ls(user_input):
    """
    Demonstrates command injection risk on Windows.
    Uses & to chain commands in cmd.exe and catches errors so the script won't crash.
    """
    cmd = f"dir {user_input}"  # user_input is unsanitized -> injection risk
    try:
        out = subprocess.check_output(cmd, shell=True)
        return out
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed with exit code {e.returncode}")
        return b""

def parse_cfg(s):
    """
    Demonstrates unsafe YAML deserialization.
    Explicitly passes Loader=yaml.Loader so Semgrep will flag it.
    """
    try:
        return yaml.load(s, Loader=yaml.Loader)
    except Exception as e:
        print(f"[!] YAML load error: {e}")
        return None

def fetch(url):
    """
    Demonstrates insecure TLS practice (verify=False).
    """
    try:
        r = requests.get(url, verify=False, timeout=5)
        return r.text[:100]  # print only first 100 chars
    except Exception as e:
        print(f"[!] Fetch error: {e}")
        return None

if __name__ == "__main__":
    # Demonstrate directory listing and command injection vector
    print(run_ls("& whoami").decode(errors="ignore"))

    # Demonstrate unsafe YAML parsing
    malicious_yaml = "!!python/object/apply:os.system ['echo pwned_from_yaml']"
    parse_cfg(malicious_yaml)

    # Demonstrate TLS verify disabled
    print(fetch("https://example.com"))
