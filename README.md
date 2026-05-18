
# Korenix JetPort Connect

A Linux desktop application for configuring and managing the **Korenix JetPort 5601** Serial Device Server (RS-232/422/485 → Redundant Ethernet). Built because the official JetPort Commander utility is Windows-only and the device's web interface requires TLS 1.0 with legacy ciphers that modern browsers refuse.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![PyQt6](https://img.shields.io/badge/UI-PyQt6-brightgreen) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Features

- **Direct HTTPS configuration** — scrapes the device's own web forms and submits changes back, preserving all hidden fields
- **Auto network discovery** — scans all local subnets in parallel, fingerprints Korenix/JetPort devices
- **In-app SSH terminal** — full interactive shell with old-device key exchange algorithm negotiation
- **URL probe tool** — fetches root and index pages, follows framesets, dumps every discovered URL with status code so the real page structure becomes visible
- **Connection log** — every HTTP request/response timestamped in real time

---

## Requirements

| Package | Version |
|---------|---------|
| Python | 3.10+ |
| PyQt6 | ≥ 6.4.0 |
| urllib3 | ≥ 1.26.0 |
| pexpect | ≥ 4.8.0 |
| netifaces | any (optional, for network scan) |

> `netifaces` is optional. Without it the network scan button returns no results, but everything else works.

---

## Installation

```bash
# Clone
git clone https://github.com/DanielFrankDK/korenix-jetport-connect.git
cd korenix-jetport-connect

# Install dependencies
pip3 install --user -r requirements.txt

# Optional: netifaces for network scan
pip3 install --user netifaces

# Launch
bash launch.sh
# or
python3 jetport.py
# or with a specific IP
python3 jetport.py 192.168.10.2
```

---

## Usage

### 1. Connect tab

Enter the device IP (default `192.168.10.2`) and password (default `admin`), then click **Connect**. On success:

- The three status indicators turn green (ICMP, HTTPS, Logged in)
- The Device Info box shows which config sections were auto-discovered from the root page links

**Check Connectivity** re-tests ICMP ping and TCP port 443 without a full login.

**Probe Device URLs** fetches the root page and common index paths (`/index.htm`, `/index.asp`, `/main.htm`, `/frameset.asp`, …), follows any `<frame>`/`<iframe>` sources one level deep, and logs every URL with its HTTP status and response size. Open the **Log** tab to see the output — this reveals the device's actual page structure so you know which paths are valid.

**Scan Network** runs a two-phase discovery:
1. Parallel TCP probe of port 443 across all local subnets (80 concurrent, 350 ms timeout)
2. HTTPS fingerprint check — looks for `jetport`, `korenix`, `serial device server` in the root page HTML

Found devices appear in a list; double-click one to connect to it immediately.

---

### 2. Server Config tab

Reads and writes the device's basic settings page. Fields:

| Field | Description |
|-------|-------------|
| Device Name | Hostname/label shown in the web UI |
| Location | Free-text location string |
| Time Zone | GMT offset selector |
| SNTP | Enable NTP sync + server address + port |
| Web Console | Enable/disable HTTPS web interface |
| SSH/Telnet Console | Enable/disable CLI access |
| IP Mode | Static / DHCP / BootP |
| IP Address / Netmask / Gateway / DNS | Network parameters |
| Change Password | Old → new password (max 12 chars) |

Click **Load from Device** first to pull current values, edit what you need, then **Apply Only** (sends without saving to flash) or **Apply and Save** (persists across reboots).

---

### 3. Port Config tab

Serial parameters for Port 1:

| Field | Options |
|-------|---------|
| Baud Rate | 110 – 460800 |
| Data Bits | 5 / 6 / 7 / 8 |
| Stop Bits | 1 / 1.5 / 2 |
| Parity | None / Even / Odd / Mark / Space |
| Flow Control | None / XON-XOFF / RTS-CTS / DTR-DSR |
| Interface | RS232 / RS422 / RS485 4-wire / RS485 2-wire |
| Performance | Throughput / Latency |
| Force TX Interval | 0 – 65535 ms |

---

### 4. Service Mode tab

Sets how the serial port is exposed over the network:

| Mode | Description |
|------|-------------|
| Virtual COM | RFC 2217 — serial port as network tty |
| TCP Server | Device listens; clients connect to the data port |
| TCP Client | Device initiates TCP connection to a remote host |
| UDP | Broadcasts/unicasts to an IP range |

Each mode shows the relevant fields (port number, destination host, idle timeout, keep-alive, max connections).

---

### 5. Save / Restart tab

| Action | Effect |
|--------|--------|
| Reboot | Warm-restarts the device (unapplied changes are lost) |
| Load Factory Defaults | Resets all config except IP; device reboots |
| Export Config | Downloads the device config file to a local path |

---

### 6. SSH Terminal tab

An in-app terminal that SSHs directly into the device shell. Handles the old-device SSH quirks automatically:

```
-o HostKeyAlgorithms=+ssh-rsa,ssh-dss
-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,...
-o Ciphers=+3des-cbc,aes128-cbc,aes256-cbc,aes128-ctr
-o StrictHostKeyChecking=no
```

Type commands in the input bar at the bottom; output scrolls in the terminal above.

---

### 7. Log tab

Every HTTP GET/POST, status code, error, and URL-probe result is appended here with a `[HH:MM:SS]` timestamp. The log auto-refreshes every second. Use **Clear** to reset it.

---

## Technical notes

### SSL compatibility

The JetPort 5601 dates from ~2006 and only supports **TLS 1.0** with old cipher suites and the pre-RFC-5746 renegotiation handshake. Modern OpenSSL (≥ 3.0) and Python (≥ 3.10) refuse all three of these by default. The app applies three layers of workarounds via a custom `ssl.SSLContext`:

```python
ctx.minimum_version = ssl.TLSVersion.TLSv1      # allow TLS 1.0
ctx.set_ciphers("DEFAULT:@SECLEVEL=0")           # allow weak ciphers
ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT      # allow pre-RFC-5746 renegotiation
```

If the connection still fails with `UNSUPPORTED_PROTOCOL`, your system's OpenSSL policy may be blocking TLS 1.0 at the OS level. Fix it by editing `/etc/ssl/openssl.cnf`:

```ini
[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT:@SECLEVEL=0
```

### Form scraping approach

Rather than hard-coding form payloads, each config tab fetches the device's actual HTML page, parses **all** form fields (including hidden fields that carry CSRF tokens or state), merges the user's changes in, and POSTs the complete payload back. This avoids missing required hidden fields that would silently break submissions.

### URL discovery

The device's config page URLs are not standardised. On connect, the app parses `<a href>`, `<frame src>`, and `<iframe src>` from the root page and matches them against keyword hints (e.g. `"basic"`, `"network"`, `"serial"`) to build a section→URL map. If discovery finds nothing (e.g. the root page is a frameset with no links), each tab falls back to a list of ~16 candidate URLs (`.asp`, `.htm`, `.html`, `/cgi-bin/` variants) tried in sequence until one returns HTTP 200 with a form.

Use **Probe Device URLs** to see exactly what the root page contains and which paths return valid pages.

---

## Device defaults

| Setting | Value |
|---------|-------|
| IP address | 192.168.10.2 |
| Subnet mask | 255.255.255.0 |
| HTTPS port | 443 |
| SSH port | 22 |
| Username | admin |
| Password | admin |

---

## License

MIT — see [LICENSE](LICENSE) if present, otherwise use freely.
