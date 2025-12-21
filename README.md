# Python Nmap Wrapper

A comprehensive Python wrapper for nmap with configuration profiles, structured output generation, and multi-layer architecture.

## Project Objectives

This project provides a user-friendly Python interface to the nmap network scanning tool with the following objectives:

- **Simplified Scanning**: Abstract complex nmap command-line options into easy-to-use predefined profiles
- **Safety Controls**: Implement validation, public IP warnings, and confirmation prompts for aggressive scans
- **Structured Output**: Automatically generate CSV and JSON reports from scan results for easy analysis

## Features

### Predefined Scan Profiles

The wrapper includes 7 scan profiles organized by risk level:

**Passive Scans** (Non-intrusive):
- `ping` - Host discovery only (ICMP, TCP SYN/ACK)
- `quick` - Fast scan of 100 most common ports (-T4 -F)

**Standard Scans** (Balanced):
- `standard` - TCP connect scan with service version detection
- `version` - Intensive service/version detection
- `udp` - Top 100 UDP ports scan

**Aggressive Scans** (Intrusive, requires confirmation):
- `stealth` - TCP SYN scan with packet fragmentation
- `intense` - Comprehensive scan with OS detection and NSE scripts
- `vuln` - Active vulnerability scanning using NSE vuln scripts
- `comprehensive` - All ports with maximum detail

### Safety Features

- **Target Validation**: Validates IP addresses, CIDR ranges, and hostnames
- **Public IP Detection**: Warns when scanning public internet addresses
- **Confirmation Prompts**: Requires explicit approval for aggressive scans
- **Privilege Checking**: Validates permissions for root-required scans

### Output Formats

- **XML**: Native nmap output 
- **CSV**: Spreadsheet-friendly format with one port per row
- **JSON**: Structured data for programmatic processing
- **Terminal**: Real-time scan progress and summary statistics

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows with WSL
- **Python**: Version 3.6 or higher
- **Nmap**: Must be installed and accessible in PATH

### Installing Nmap

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install nmap
```

**macOS**:
```bash
brew install nmap
```

**Fedora/RHEL**:
```bash
sudo dnf install nmap
```

**Windows**:

Download and install Windows version from [nmap.org/download.html](https://nmap.org/download.html)


**Verify installation**:
```bash
nmap --version
```

## Setup Instructions

### 1. Clone or Download the Repository

**Linux/macOS/WSL**:
```bash
cd /path/to/your/projects
git clone https://github.com/phlypinoy/CYB333_nmap_wrapper.git
cd CYB333_nmap_wrapper
```

**Windows Command Prompt or PowerShell**:
```cmd
cd C:\Users\YourUsername\Documents
git clone https://github.com/phlypinoy/CYB333_nmap_wrapper.git
cd CYB333_nmap_wrapper
```

### 2. Verify Python Version

**Linux/macOS/WSL**:
```bash
python3 --version
# Should be 3.6 or higher
```

**Windows**:
```cmd
python --version
# Should be 3.6 or higher
```

### 3. Check Dependencies

This project uses **only Python standard library modules** - no pip installations required!

The following standard library modules are used:
- `subprocess` - Execute nmap commands
- `argparse` - Command-line interface
- `csv` / `json` - Output generation
- `xml.etree.ElementTree` - Parse nmap XML
- `logging` - Application logging
- `ipaddress` - IP validation
- `datetime`, `os`, `sys`, `socket`, `typing` - Utilities

### 4. Set Execute Permissions (Linux/macOS only)

```bash
chmod +x nmap_wrapper.py
```

**Note for Windows users**: Execute permissions are not needed. You can run the script directly using `python nmap_wrapper.py`.

## Usage

### Basic Command Structure

**Linux/macOS/WSL**:
```bash
python3 nmap_wrapper.py [OPTIONS] <target1> [target2 ...]
```

**Windows**:
```cmd
python nmap_wrapper.py [OPTIONS] <target1> [target2 ...]
```

### Quick Start Examples

**Note**: On Windows, replace `python3` with `python` in all examples below.

**1. Ping sweep to discover active hosts:**
```bash
python3 nmap_wrapper.py --profile ping 192.168.1.0/24
```

**2. Quick scan of local network:**
```bash
python3 nmap_wrapper.py --profile quick 192.168.1.1
```

**3. Standard scan with service detection:**
```bash
python3 nmap_wrapper.py --profile standard scanme.nmap.org
```

**4. Scan specific ports:**
```bash
python3 nmap_wrapper.py --profile standard --ports 80,443,8080 192.168.1.1
```

**5. Custom nmap options:**
```bash
python3 nmap_wrapper.py --custom "-sS -p- -T2" 192.168.1.1
```

**6. Generate CSV and JSON output:**
```bash
python3 nmap_wrapper.py --profile version --output-dir ./reports 192.168.1.1
```

**7. Verbose logging to file:**
```bash
python3 nmap_wrapper.py --profile standard --verbose --log scan.log 192.168.1.1
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Use predefined scan profile (ping, quick, standard, version, udp, stealth, intense, vuln, comprehensive) |
| `--custom <options>` | Provide custom nmap options (e.g., "-sS -p-") |
| `--ports <spec>` | Port specification (e.g., "80,443" or "1-1000") |
| `--output-dir <dir>` | Directory for output files (default: current directory) |
| `--list-profiles` | Display all available scan profiles and exit |
| `--verbose` | Enable detailed debug logging |
| `--log <file>` | Write logs to specified file |
| `--no-warning` | Skip public IP warning prompts |
| `--help` | Show help message and exit |

### Available Scan Profiles

View all profiles with descriptions:
```bash
python3 nmap_wrapper.py --list-profiles
```

```bash
python3 nmap_wrapper.py --list-profiles

Available Scan Profiles:
================================================================================

PASSIVE SCANS (Safe, non-intrusive)
--------------------------------------------------------------------------------

  ping
    Host discovery only using ICMP echo, TCP SYN/ACK, and ICMP timestamp
    requests. No port scanning performed. Safe for production networks.
    Useful for quickly identifying active hosts on a network.

    Options: -sn

  quick
    Fast scan of the 100 most common TCP ports using aggressive timing
    (-T4). Completes in seconds to minutes. Ideal for quick reconnaissance
    and initial network mapping. May miss less common services.

    Options: -T4 -F

STANDARD SCANS (Balanced detection)
--------------------------------------------------------------------------------

  standard
    Standard TCP connect() scan on default 1000 ports with service version
    detection. Uses normal timing (-T3). No root required. Attempts to
    identify service names and versions. Moderately stealthy and reliable
    for general purpose scanning.

    Options: -sT -sV -T3

  version
    Intensive service and version detection scan with medium-high intensity
    (5/9). Probes open ports to determine service protocol, application
    name, version number, and OS details. Faster timing (-T4). Useful for
    vulnerability assessment and inventory management.

    Options: -sV -T4 --version-intensity 5

  udp
    UDP port scan targeting the top 100 most common UDP services (DNS, SNMP,
    DHCP, etc.). Slower than TCP scans due to UDP protocol limitations. May
    require root/admin privileges. Important for discovering services not
    visible via TCP scanning.

    Options: -sU -T4 --top-ports 100

AGGRESSIVE SCANS (Intrusive, requires confirmation)
--------------------------------------------------------------------------------

  stealth ⚠️  [REQUIRES CONFIRMATION]
    TCP SYN "half-open" scan with packet fragmentation (-f) and slow timing
    (-T2) to evade basic IDS/IPS. Requires root/admin privileges. Does not
    complete TCP handshake. Fragments packets into 8-byte chunks. Still
    detectable by modern security systems but harder to attribute.

    Options: -sS -T2 -f

  intense ⚠️  [REQUIRES CONFIRMATION]
    Comprehensive aggressive scan combining SYN scanning, service version
    detection, OS fingerprinting, and NSE default scripts. Attempts to
    identify operating system, version, device type, and uptime. Runs ~40
    safe NSE scripts for additional enumeration. Highly visible to security
    monitoring. Requires root privileges.

    Options: -sS -sV -O -T4 --script default

  vuln ⚠️  [REQUIRES CONFIRMATION]
    Active vulnerability scanning using NSE vuln scripts. Attempts to
    identify known CVEs and security weaknesses including SQL injection,
    XSS, outdated software, weak credentials, and misconfigurations. Very
    intrusive - sends exploit probes and may crash unstable services. Only
    use on authorized test systems.

    Options: -sS -sV --script vuln -T4

  comprehensive ⚠️  [REQUIRES CONFIRMATION]
    Full-spectrum scan of ALL 65,535 TCP ports (-p-) with OS detection,
    service versioning, and default+discovery NSE scripts. Extremely
    thorough but very time-consuming (hours to days). Generates significant
    network traffic. Discovers hidden services on non-standard ports.
    Maximum visibility to network security. Requires root privileges.

    Options: -sS -sV -O -p- --script default,discovery -T4

  firewall-bypass ⚠️  [REQUIRES CONFIRMATION]
    Evasion-focused scan using packet fragmentation (-f), 10 random decoy
    hosts (-D RND:10), source port spoofing to port 53/DNS (--source-port
    53), and slow timing (-T2). Attempts to evade stateful firewalls and IDS
    by mimicking DNS traffic and obscuring scan source. Highly detectable by
    modern security systems. Requires root privileges.

    Options: -sS -f -D RND:10 --source-port 53 -T2

================================================================================
```

### Output Files

Scans automatically generate timestamped files:
- `nmap_scan_YYYYMMDD_HHMMSS.xml` - Raw nmap XML output
- `nmap_results_YYYYMMDD_HHMMSS.csv` - Spreadsheet-friendly CSV
- `nmap_results_YYYYMMDD_HHMMSS.json` - Structured JSON data

### Privilege Requirements

Some scans require root/administrator privileges:
- TCP SYN scans (`-sS`)
- OS detection (`-O`)
- UDP scans (`-sU`)
- Raw packet operations

**Linux/macOS/WSL**:
```bash
sudo python3 nmap_wrapper.py --profile stealth 192.168.1.1
```

**Windows**:
Run Command Prompt or PowerShell as Administrator:
1. Right-click on Command Prompt or PowerShell
2. Select "Run as administrator"
3. Navigate to project directory and run:
```cmd
python nmap_wrapper.py --profile stealth 192.168.1.1
```