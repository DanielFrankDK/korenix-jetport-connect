#!/usr/bin/env python3
"""JetPort 5601 Manager — direct HTTPS config + in-app SSH terminal."""

import sys, threading, subprocess, socket, ssl, re, os, queue, time
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QComboBox, QGroupBox,
    QFormLayout, QCheckBox, QSpinBox, QTextEdit, QScrollArea, QFrame,
    QStatusBar, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QRadioButton, QStackedWidget, QSizePolicy, QFileDialog,
)
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCursor

# ── SSL context ───────────────────────────────────────────────────────────────

def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ssl.SSLError):
        for opt in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            try: ctx.options &= ~getattr(ssl, opt)
            except AttributeError: pass
    for cs in ("DEFAULT:@SECLEVEL=0", "ALL:@SECLEVEL=0", "ALL"):
        try: ctx.set_ciphers(cs); break
        except ssl.SSLError: continue
    # Device predates RFC 5746 (2010) and uses the old renegotiation mechanism.
    try:
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    except AttributeError:
        pass
    return ctx

# ── HTML parsers (stdlib only, no BeautifulSoup) ──────────────────────────────

class FormParser(HTMLParser):
    """Extract all forms (fields + hidden fields + action URL) from HTML."""
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._f = None
        self._sel = None   # current select name
        self._sel_val = None
        self._sel_first = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs); tag = tag.lower()
        if tag == "form":
            self._f = {"action": d.get("action",""), "method": d.get("method","GET").upper(),
                       "fields": {}, "hidden": {}}
            self.forms.append(self._f)
        elif self._f is None:
            return
        name = d.get("name","")
        if tag == "input":
            t = d.get("type","text").lower()
            if t == "hidden":
                self._f["hidden"][name] = d.get("value","")
            elif t == "checkbox":
                self._f["fields"][name] = ("checked" in d)
            elif t == "radio":
                if "checked" in d:
                    self._f["fields"][name] = d.get("value","")
                elif name not in self._f["fields"]:
                    self._f["fields"][name] = d.get("value","")
            elif t not in ("submit","button","image","reset") and name:
                self._f["fields"][name] = d.get("value","")
        elif tag == "select" and name:
            self._sel = name; self._sel_val = None; self._sel_first = None
        elif tag == "option" and self._sel:
            v = d.get("value","")
            if self._sel_first is None: self._sel_first = v
            if "selected" in d: self._sel_val = v
        elif tag == "textarea" and name:
            self._f["fields"][name] = ""

    def handle_endtag(self, tag):
        if tag == "select" and self._sel and self._f is not None:
            self._f["fields"][self._sel] = self._sel_val if self._sel_val is not None else (self._sel_first or "")
            self._sel = None
        elif tag == "form":
            self._f = None

class LinkParser(HTMLParser):
    """Collects <a href>, <frame src>, <iframe src> — everything that points to a URL."""
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str,str]] = []   # (href, display_text_or_tag)
        self._href = ""; self._txt = ""; self._in_a = False
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            self._href = d.get("href",""); self._txt = ""; self._in_a = True
        elif tag in ("frame","iframe"):
            src = d.get("src","")
            if src: self.links.append((src, f"<{tag}>"))
    def handle_data(self, data):
        if self._in_a: self._txt += data
    def handle_endtag(self, tag):
        if tag == "a" and self._in_a:
            self.links.append((self._href, self._txt.strip())); self._in_a = False

# ── Device connection ─────────────────────────────────────────────────────────

# Hints used to match discovered hrefs/link-text to config sections.
# The JetPort 5601 web UI tabs are named: General, Security, Networking,
# Notification, Firmware, Save/Load — and Port Serial Settings / Service Mode.
SECTION_HINTS = {
    "basic":   ["general","basic","setting","config","system","server_basic","sysname","devname","overview"],
    "network": ["networking","network","netconfig","ip_config","ipaddr","ethernet","lan"],
    "port":    ["serial","port","serial_setting","serialsetting","com","uart","portconf","baud"],
    "service": ["service","mode","servicemode","vcom","virtual","tcpserver","tcp","udp","operation"],
    "acl":     ["security","acl","access","filter","ipfilter","firewall"],
    "notify":  ["notification","notify","event","alert","snmp","email","syslog","trap"],
    "save":    ["save","saveload","reload","restart","reboot","factory","default","firmware","upgrade","restore"],
}

# Fallback URL candidates tried in order when auto-discovery finds nothing.
# Ordered so the names the JetPort 5601 manual actually uses come first.
FALLBACK_URLS: dict[str, list[str]] = {
    "basic": [
        # Exact tab name from manual: "General"
        "/General.asp","/general.asp","/General.htm","/general.htm",
        # Overview page has a "Basic Setting" link
        "/Basic_Setting.asp","/basic_setting.asp","/Basic_Setting.htm","/basic_setting.htm",
        # Other common guesses
        "/server_basic.asp","/server_basic.htm",
        "/basic.asp","/basic.htm","/server.asp","/server.htm",
        "/system.asp","/system.htm","/config.asp","/config.htm",
        "/overview.asp","/overview.htm",
        "/cgi-bin/general.cgi","/cgi-bin/basic.cgi","/cgi-bin/server.cgi",
    ],
    "network": [
        # Exact tab name from manual: "Networking"
        "/Networking.asp","/networking.asp","/Networking.htm","/networking.htm",
        # Overview page has a "Network Setting" link
        "/Network_Setting.asp","/network_setting.asp","/Network_Setting.htm","/network_setting.htm",
        # Other common guesses
        "/server_network.asp","/server_network.htm",
        "/network.asp","/network.htm","/ip.asp","/ip.htm",
        "/ip_config.asp","/ip_config.htm","/netconfig.asp","/netconfig.htm",
        "/ethernet.asp","/ethernet.htm",
        "/cgi-bin/networking.cgi","/cgi-bin/network.cgi","/cgi-bin/ip.cgi",
    ],
    "port": [
        # Exact tab name from manual: "Serial Settings" / "Port Serial Settings"
        "/Serial_Settings.asp","/serial_settings.asp","/Serial_Settings.htm","/serial_settings.htm",
        "/Port_Serial.asp","/port_serial.asp","/Port_Serial.htm","/port_serial.htm",
        "/serial.asp","/serial.htm","/port.asp","/port.htm",
        "/port1.asp","/port1.htm",
        "/serial_setting.asp","/serial_setting.htm",
        "/com1.asp","/com1.htm","/uart.asp","/uart.htm",
        "/cgi-bin/serial.cgi","/cgi-bin/port.cgi",
    ],
    "service": [
        # Exact tab name from manual: "Service Mode" / "Port Service Mode"
        "/Service_Mode.asp","/service_mode.asp","/Service_Mode.htm","/service_mode.htm",
        "/Port_Service.asp","/port_service.asp","/Port_Service.htm","/port_service.htm",
        "/service.asp","/service.htm","/mode.asp","/mode.htm",
        "/vcom.asp","/vcom.htm","/operation.asp","/operation.htm",
        "/tcp_server.asp","/tcp_server.htm","/tcpserver.asp",
        "/cgi-bin/service.cgi","/cgi-bin/servicemode.cgi","/cgi-bin/mode.cgi",
    ],
    "acl": [
        # Exact tab name from manual: "Security"
        "/Security.asp","/security.asp","/Security.htm","/security.htm",
        "/ip_filter.asp","/ip_filter.htm","/acl.asp","/acl.htm",
        "/access.asp","/access.htm","/filter.asp","/filter.htm",
        "/firewall.asp","/firewall.htm",
        "/cgi-bin/security.cgi","/cgi-bin/acl.cgi","/cgi-bin/filter.cgi",
    ],
    "notify": [
        # Exact tab name from manual: "Notification"
        "/Notification.asp","/notification.asp","/Notification.htm","/notification.htm",
        "/notify.asp","/notify.htm","/event.asp","/event.htm",
        "/alert.asp","/alert.htm","/snmp.asp","/snmp.htm",
        "/email.asp","/email.htm","/syslog.asp","/syslog.htm",
        "/Port_Notification.asp","/port_notification.asp",
        "/cgi-bin/notification.cgi","/cgi-bin/notify.cgi","/cgi-bin/event.cgi",
    ],
    "save": [
        # Exact label from manual: "Save / Reload" and "Save / Restart"
        "/Save_Reload.asp","/save_reload.asp","/SaveReload.asp","/savereload.asp",
        "/Save_Restart.asp","/save_restart.asp","/SaveRestart.asp","/saverestart.asp",
        "/save.asp","/save.htm","/restart.asp","/restart.htm",
        "/reboot.asp","/reboot.htm",
        "/Firmware.asp","/firmware.asp","/Firmware.htm","/firmware.htm",
        "/upgrade.asp","/upgrade.htm","/restore.asp","/restore.htm",
        "/factory.asp","/factory.htm",
        "/cgi-bin/save.cgi","/cgi-bin/savereload.cgi","/cgi-bin/reboot.cgi",
    ],
}

class DeviceConnection:
    """HTTPS client with automatic form discovery and scraping."""

    def __init__(self, ip: str):
        self.ip = ip
        self.password = ""
        self._pool: urllib3.HTTPSConnectionPool | None = None
        self._cookies: dict[str,str] = {}
        self._section_urls: dict[str,str] = {}  # discovered section → URL
        self.connected = False
        self.log: list[str] = []

    # ── internal HTTP helpers ─────────────────────────────────────────────────

    def _pool_for(self, ip: str) -> urllib3.HTTPSConnectionPool:
        return urllib3.HTTPSConnectionPool(
            ip, port=443, ssl_context=_make_ssl_context(),
            timeout=urllib3.Timeout(connect=6, read=15),
        )

    def _cookie_hdr(self) -> str:
        return "; ".join(f"{k}={v}" for k,v in self._cookies.items())

    def _update_cookies(self, hdrs):
        raw = hdrs.getlist("Set-Cookie") if hasattr(hdrs,"getlist") else []
        for v in raw:
            m = re.match(r"([^=]+)=([^;]*)", v)
            if m and m.group(2).strip():
                self._cookies[m.group(1).strip()] = m.group(2).strip()

    def _get(self, path: str) -> tuple[int, str]:
        if self._pool is None: return 0, "not connected"
        h = {"Host": self.ip}
        if self._cookies: h["Cookie"] = self._cookie_hdr()
        try:
            r = self._pool.urlopen("GET", path, headers=h, redirect=True, preload_content=True)
            self._update_cookies(r.headers)
            self._log(f"GET {path} → {r.status}")
            return r.status, r.data.decode("utf-8", errors="replace")
        except Exception as e:
            self._log(f"GET {path} ERROR: {e}")
            return 0, str(e)

    def _post(self, path: str, data: dict) -> tuple[int, str]:
        if self._pool is None: return 0, "not connected"
        body = urlencode(data).encode()
        h = {"Host": self.ip,
             "Content-Type": "application/x-www-form-urlencoded",
             "Content-Length": str(len(body))}
        if self._cookies: h["Cookie"] = self._cookie_hdr()
        try:
            r = self._pool.urlopen("POST", path, headers=h, body=body, redirect=True, preload_content=True)
            self._update_cookies(r.headers)
            self._log(f"POST {path} → {r.status}")
            return r.status, r.data.decode("utf-8", errors="replace")
        except Exception as e:
            self._log(f"POST {path} ERROR: {e}")
            return 0, str(e)

    def _log(self, msg: str):
        entry = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.log.append(entry)
        if len(self.log) > 200: self.log = self.log[-200:]

    # ── connect / discover ────────────────────────────────────────────────────

    def connect(self, password: str = "") -> tuple[bool, str]:
        self.password = password
        self._pool = self._pool_for(self.ip)
        self._cookies.clear()
        self._section_urls.clear()

        status, html = self._get("/")
        if status == 0:
            return False, f"Cannot reach device: {html}"

        # Login if there's a password field
        if "password" in html.lower() and status in (200, 401):
            ok, msg = self._login(html, password)
            if not ok:
                return False, msg
            status, html = self._get("/")

        self._discover(html)
        self.connected = True
        self._log("Connected and discovered pages")
        return True, "Connected"

    def _login(self, html: str, password: str) -> tuple[bool, str]:
        """Submit password form."""
        fp = FormParser(); fp.feed(html)
        for form in fp.forms:
            fields = dict(form["hidden"])
            fields.update(form["fields"])
            # Find password field
            pw_key = next((k for k in fields if "pass" in k.lower() or "pwd" in k.lower()), None)
            if pw_key is None: continue
            fields[pw_key] = password
            action = form["action"] or "/"
            if not action.startswith("/"): action = "/" + action
            st, body = self._post(action, fields)
            if st in (200, 302) and ("error" not in body.lower() or "overview" in body.lower()):
                self._log("Login OK")
                return True, "logged in"
        # No form found — try a direct POST
        for path in ["/", "/login.htm", "/login.cgi"]:
            st, body = self._post(path, {"password": password, "submit": "Submit"})
            if st in (200,302):
                return True, "login attempted"
        return True, "no login form found, proceeding"

    def _discover(self, html: str):
        """Map section names to their config page URLs by parsing root links."""
        lp = LinkParser(); lp.feed(html)
        if lp.links:
            self._log(f"Root page contains {len(lp.links)} link(s):")
            for href, text in lp.links:
                self._log(f"  {href!r}  [{text}]")
        else:
            self._log("Root page: no <a>/<frame>/<iframe> links found")
        for href, text in lp.links:
            if not href or href.startswith(("http://","https://","#","javascript","mailto")):
                continue
            href_l = href.lower(); text_l = text.lower()
            for section, hints in SECTION_HINTS.items():
                if section not in self._section_urls:
                    if any(h in href_l or h in text_l for h in hints):
                        self._section_urls[section] = href if href.startswith("/") else "/" + href
        if self._section_urls:
            self._log(f"Auto-mapped sections: {list(self._section_urls.keys())}")
        else:
            self._log("No sections auto-mapped — will try fallback URLs for each tab")

    def probe_urls(self) -> list[tuple[str, int, int]]:
        """
        Fetch root + common index pages, follow <frame>/<iframe> srcs one level deep.
        Logs every URL with its HTTP status and response size.
        Returns list of (url, status, length).
        """
        visited: set[str] = set()
        results: list[tuple[str, int, int]] = []

        def _fetch(path: str, follow_frames: bool = True):
            if path in visited: return
            visited.add(path)
            st, html = self._get(path)
            results.append((path, st, len(html)))
            if follow_frames and st == 200 and html:
                lp = LinkParser(); lp.feed(html)
                for src, tag in lp.links:
                    if tag in ("<frame>", "<iframe>") and src:
                        norm = src if src.startswith("/") else "/" + src
                        _fetch(norm, follow_frames=False)

        for start in ["/", "/index.htm", "/index.asp", "/index.html",
                       "/main.htm", "/main.asp", "/home.htm", "/home.asp",
                       "/frameset.htm", "/frameset.asp"]:
            _fetch(start)

        self._log("=== URL Probe ===")
        for url, st, length in results:
            self._log(f"  {url}: HTTP {st}  ({length} bytes)")
        self._log("=== End Probe ===")
        return results

    # ── read config page ──────────────────────────────────────────────────────

    def load_section(self, section: str) -> tuple[str | None, dict, dict]:
        """Return (url, visible_fields, hidden_fields) for a config section."""
        url = self._section_urls.get(section)
        candidates = ([url] if url else []) + FALLBACK_URLS.get(section, [])
        for u in candidates:
            if not u: continue
            st, html = self._get(u)
            if st != 200 or len(html) < 100: continue
            fp = FormParser(); fp.feed(html)
            if fp.forms:
                f = fp.forms[0]
                action = f["action"] or u
                if not action.startswith("/"): action = "/" + action
                self._section_urls[section] = u   # remember working URL
                self._log(f"Loaded section '{section}' from {u}: {len(f['fields'])} fields")
                return action, f["fields"], f["hidden"]
        self._log(f"Could not load section '{section}'")
        return None, {}, {}

    def submit_section(self, action: str, visible: dict, hidden: dict, overrides: dict) -> tuple[bool, str]:
        """Merge overrides into form fields and POST."""
        payload = dict(hidden)
        payload.update(visible)
        payload.update(overrides)
        st, body = self._post(action, payload)
        ok = st in (200, 302)
        return ok, f"HTTP {st}"

    # ── reboot / defaults ─────────────────────────────────────────────────────

    def reboot(self) -> tuple[bool, str]:
        action, fields, hidden = self.load_section("save")
        if action:
            payload = dict(hidden); payload.update(fields)
            for k in list(payload.keys()):
                if "reboot" in k.lower() or "restart" in k.lower():
                    payload[k] = "1"
            st, _ = self._post(action, payload)
            if st in (200,302): return True, f"HTTP {st}"
        # Fallback guesses
        for path in ["/reboot.cgi","/restart.cgi","/save_restart.cgi"]:
            st, _ = self._post(path, {"action":"reboot","reboot":"1"})
            if st in (200,302): return True, f"HTTP {st} via {path}"
        return False, "Could not find reboot endpoint"

    def load_defaults(self) -> tuple[bool, str]:
        for path in ["/defaults.cgi","/factory.cgi","/restore.cgi"]:
            st, _ = self._post(path, {"action":"defaults","factory":"1"})
            if st in (200,302): return True, f"HTTP {st} via {path}"
        return False, "Could not find factory-reset endpoint"

    def ping_https(self) -> bool:
        try:
            s = socket.create_connection((self.ip, 443), timeout=2); s.close(); return True
        except OSError: return False

    def ping_icmp(self) -> bool:
        try:
            r = subprocess.run(["ping","-c1","-W2",self.ip], capture_output=True, timeout=4)
            return r.returncode == 0
        except Exception: return False

# ── Network discovery ─────────────────────────────────────────────────────────

def scan_network() -> list[tuple[str, str]]:
    """
    Find JetPort / Korenix devices on all local subnets.
    Returns sorted list of (ip, description) for every host with port 443 open,
    with a JetPort fingerprint check on each candidate.
    Limits to /16 or smaller subnets to stay fast.
    """
    try:
        import netifaces, ipaddress
    except ImportError:
        return []

    # Collect unique hosts from every local interface subnet
    hosts: list[str] = []
    seen: set[str] = set()
    for iface in netifaces.interfaces():
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            ip   = addr.get("addr", "")
            mask = addr.get("netmask", "")
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                key = str(net)
                if key in seen or net.num_addresses > 65536:
                    continue
                seen.add(key)
                hosts.extend(str(h) for h in net.hosts())
            except ValueError:
                pass

    if not hosts:
        return []

    # Phase 1 — fast parallel TCP probe of port 443 (0.35 s timeout)
    candidates: list[str] = []
    lock = threading.Lock()
    sem  = threading.Semaphore(80)

    def _probe(ip: str):
        with sem:
            try:
                s = socket.create_connection((ip, 443), timeout=0.35)
                s.close()
                with lock:
                    candidates.append(ip)
            except OSError:
                pass

    ts = [threading.Thread(target=_probe, args=(h,), daemon=True) for h in hosts]
    for t in ts: t.start()
    for t in ts: t.join(timeout=10)

    if not candidates:
        return []

    # Phase 2 — HTTPS fingerprint: check root page for JetPort/Korenix strings
    results: list[tuple[str, str]] = []

    def _verify(ip: str):
        try:
            pool = urllib3.HTTPSConnectionPool(
                ip, port=443, ssl_context=_make_ssl_context(),
                timeout=urllib3.Timeout(connect=3, read=6),
            )
            r    = pool.urlopen("GET", "/", headers={"Host": ip},
                                redirect=True, preload_content=True)
            html = r.data.decode("utf-8", errors="replace")
            low  = html.lower()
            jetport_kw = ("jetport", "korenix", "serial device server", "jetseries")
            is_jp = any(k in low for k in jetport_kw)
            # Try to extract model name
            m = re.search(r"JetPort\s*([\w/]+)", html, re.I)
            if m:
                desc = f"JetPort {m.group(1)}"
            elif is_jp:
                desc = "Korenix / JetPort device"
            else:
                desc = "HTTPS device (not confirmed JetPort)"
            with lock:
                results.append((ip, desc))
        except Exception as e:
            with lock:
                results.append((ip, f"port 443 open (verify failed: {type(e).__name__})"))

    ts2 = [threading.Thread(target=_verify, args=(ip,), daemon=True) for ip in candidates]
    for t in ts2: t.start()
    for t in ts2: t.join(timeout=15)

    return sorted(results, key=lambda x: [int(p) for p in x[0].split(".")])


# ── Worker thread ─────────────────────────────────────────────────────────────

class Worker(QThread):
    result = pyqtSignal(object)
    error  = pyqtSignal(str)
    def __init__(self, fn, *a, **kw):
        super().__init__(); self._fn=fn; self._a=a; self._kw=kw
    def run(self):
        try: self.result.emit(self._fn(*self._a, **self._kw))
        except Exception as e: self.error.emit(str(e))

# ── Style helpers ─────────────────────────────────────────────────────────────

ACCENT="#1a6ecc"; BG="#f5f6f8"; CARD="#ffffff"; BORDER="#dde1e7"
GREEN="#2da44e"; RED="#cf222e"; ORANGE="#e36209"

def card(title="") -> QGroupBox:
    g = QGroupBox(title)
    g.setStyleSheet(f"QGroupBox{{background:{CARD};border:1px solid {BORDER};"
                    f"border-radius:6px;margin-top:8px;padding:8px;}}"
                    f"QGroupBox::title{{subcontrol-origin:margin;left:10px;"
                    f"color:#444;font-weight:bold;}}")
    return g

def btn(text, primary=False, danger=False) -> QPushButton:
    b = QPushButton(text)
    if primary:
        b.setStyleSheet(f"QPushButton{{background:{ACCENT};color:white;border:none;"
                        f"border-radius:5px;padding:7px 16px;font-weight:bold;}}"
                        f"QPushButton:hover{{background:#155cb4;}}"
                        f"QPushButton:disabled{{background:#9ab4d4;}}")
    elif danger:
        b.setStyleSheet(f"QPushButton{{background:{RED};color:white;border:none;"
                        f"border-radius:5px;padding:7px 16px;}}"
                        f"QPushButton:hover{{background:#a71d29;}}")
    else:
        b.setStyleSheet(f"QPushButton{{background:#eaedf1;color:#24292f;"
                        f"border:1px solid {BORDER};border-radius:5px;padding:7px 16px;}}"
                        f"QPushButton:hover{{background:#dde1e7;}}")
    return b

def le(placeholder="", password=False) -> QLineEdit:
    w = QLineEdit(); w.setPlaceholderText(placeholder)
    if password: w.setEchoMode(QLineEdit.EchoMode.Password)
    w.setStyleSheet(f"QLineEdit{{border:1px solid {BORDER};border-radius:4px;"
                    f"padding:4px 8px;background:white;color:#333;}}"
                    f"QLineEdit:focus{{border-color:{ACCENT};}}")
    return w

def cb(items) -> QComboBox:
    w = QComboBox(); w.addItems(items)
    w.setStyleSheet(
        f"QComboBox{{border:1px solid {BORDER};border-radius:4px;"
        f"padding:4px 8px;background:white;color:#333;}}"
        f"QComboBox QAbstractItemView{{background:white;color:#333;border:1px solid {BORDER};"
        f"selection-background-color:{ACCENT};selection-color:white;}}"
    )
    return w

def dot(color) -> QLabel:
    l = QLabel("●"); l.setStyleSheet(f"color:{color};font-size:14px;"); return l

def scrolled(widget: QWidget) -> QScrollArea:
    sa = QScrollArea(); sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    sa.setStyleSheet("QScrollArea{border:none;background:transparent;}")
    sa.setWidget(widget); return sa

BAUD=["110","300","600","1200","2400","4800","9600","19200","38400","57600","115200","230400","460800"]
DBITS=["5","6","7","8"]; SBITS=["1","1.5","2"]
PARITY=["None","Even","Odd","Mark","Space"]
FLOW=["None","XON/XOFF","RTS/CTS","DTR/DSR"]
IFACE=["RS232","RS422","RS485 (4-wire)","RS485 (2-wire)"]
SVCMODES=["Virtual COM","TCP Server","TCP Client","UDP"]
TIMEZONES=["GMT-12:00","GMT-11:00","GMT-10:00","GMT-09:00","GMT-08:00","GMT-07:00",
           "GMT-06:00","GMT-05:00","GMT-04:00","GMT-03:30","GMT-03:00","GMT-02:00",
           "GMT-01:00","GMT+00:00","GMT+01:00","GMT+02:00","GMT+03:00","GMT+03:30",
           "GMT+04:00","GMT+04:30","GMT+05:00","GMT+05:30","GMT+05:45","GMT+06:00",
           "GMT+06:30","GMT+07:00","GMT+08:00 Taipei","GMT+09:00","GMT+09:30",
           "GMT+10:00","GMT+11:00","GMT+12:00"]

# ── Shared tab base ───────────────────────────────────────────────────────────

class ConfigTab(QWidget):
    """Base for config tabs: provides load_section / submit helpers."""

    section = ""   # override in subclass

    def __init__(self, conn: DeviceConnection, app):
        super().__init__()
        self.conn = conn; self.app = app
        self._action: str | None = None
        self._hidden: dict = {}
        self._visible: dict = {}
        self._worker: Worker | None = None

    def _load_btn(self) -> QPushButton:
        b = btn("Load from Device")
        b.clicked.connect(self._do_load)
        return b

    def _apply_btns(self) -> tuple[QPushButton, QPushButton]:
        ba = btn("Apply Only"); bs = btn("Apply and Save", primary=True)
        ba.clicked.connect(lambda: self._do_submit(False))
        bs.clicked.connect(lambda: self._do_submit(True))
        return ba, bs

    def _do_load(self):
        if not self.conn.connected:
            self.app.set_status("Not connected — use the Connect button", error=True); return
        sender = self.sender(); sender.setEnabled(False)
        def load():
            return self.conn.load_section(self.section)
        w = Worker(load)
        w.result.connect(self._on_loaded)
        w.error.connect(lambda e: (self.app.set_status(e, error=True), sender.setEnabled(True)))
        w.finished.connect(lambda: sender.setEnabled(True))
        w.start(); self._worker = w

    def _on_loaded(self, res):
        action, visible, hidden = res
        if action is None:
            self.app.set_status(f"Could not load '{self.section}' page — see Log tab", error=True)
            QMessageBox.warning(
                self,
                "Page Not Found on Device",
                f"Could not find the <b>{self.section}</b> configuration page on the device.<br><br>"
                f"All known URL candidates returned 404. The device's actual page paths are unknown.<br><br>"
                f"<b>To find the real URLs:</b><br>"
                f"1. Connect to the device (Connect tab)<br>"
                f"2. Click <b>Probe Device URLs</b> — results appear in the <b>Log</b> tab<br>"
                f"3. Share the log output so the correct paths can be added<br><br>"
                f"<b>To change the IP right now:</b> use the <b>SSH Terminal</b> tab — "
                f"log in as admin and navigate the text menu.",
            )
            return
        self._action = action; self._visible = visible; self._hidden = hidden
        self.populate(visible)
        self.app.set_status(f"Loaded '{self.section}' ({len(visible)} fields)")

    def _do_submit(self, save: bool):
        if not self.conn.connected:
            self.app.set_status("Not connected", error=True); return
        if self._action is None:
            self.app.set_status("Load from device first", error=True); return
        overrides = self.collect()
        if save: overrides["save"] = "1"
        action = self._action

        def submit():
            return self.conn.submit_section(action, self._visible, self._hidden, overrides)
        w = Worker(submit)
        w.result.connect(lambda r: self.app.set_status(
            f"Saved ({r[1]})" if r[0] else f"Submit failed: {r[1]}", error=not r[0]))
        w.start(); self._worker = w

    # Override in subclass:
    def populate(self, fields: dict): pass
    def collect(self) -> dict: return {}

# ── Dashboard tab ─────────────────────────────────────────────────────────────

class DashboardTab(QWidget):
    def __init__(self, conn: DeviceConnection, app):
        super().__init__(); self.conn = conn; self.app = app; self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(16,16,16,16); root.setSpacing(12)

        # ── Discovery card ────────────────────────────────────────────────────
        dc = card("Discover Devices on Network")
        dl = QVBoxLayout(dc); dl.setContentsMargins(12,20,12,12); dl.setSpacing(8)

        top_row = QHBoxLayout()
        self.btn_scan   = btn("Scan Network", primary=True)
        self.lbl_scan   = QLabel("Scans all local subnets for port 443 and verifies JetPort fingerprint.")
        self.lbl_scan.setStyleSheet("color:#555;font-size:12px;")
        self.lbl_scan.setWordWrap(True)
        self.btn_scan.clicked.connect(self._start_scan)
        top_row.addWidget(self.btn_scan); top_row.addWidget(self.lbl_scan, 1)
        dl.addLayout(top_row)

        from PyQt6.QtWidgets import QListWidget
        self.lst_devices = QListWidget()
        self.lst_devices.setMaximumHeight(120)
        self.lst_devices.setStyleSheet(
            f"QListWidget{{border:1px solid {BORDER};border-radius:4px;background:white;}}"
            f"QListWidget::item{{padding:4px 8px;}}"
            f"QListWidget::item:selected{{background:{ACCENT};color:white;}}"
        )
        self.lst_devices.setVisible(False)
        self.lst_devices.itemDoubleClicked.connect(self._use_selected)
        dl.addWidget(self.lst_devices)

        use_row = QHBoxLayout()
        self.btn_use = btn("Connect to Selected")
        self.btn_use.setVisible(False)
        self.btn_use.clicked.connect(self._use_selected)
        use_row.addStretch(); use_row.addWidget(self.btn_use)
        dl.addLayout(use_row)
        root.addWidget(dc)

        # ── Connect card ──────────────────────────────────────────────────────
        cc = card("Connect to Device")
        cl = QFormLayout(cc); cl.setContentsMargins(12,20,12,12); cl.setSpacing(8)
        self.le_ip   = le("192.168.10.2"); self.le_ip.setText(self.conn.ip)
        self.le_pass = le("password (blank = none)", password=True)
        self.btn_conn = btn("Connect", primary=True)
        self.btn_conn.clicked.connect(self._connect)
        cl.addRow("Device IP:", self.le_ip)
        cl.addRow("Password:", self.le_pass)
        cl.addRow("", self.btn_conn)
        root.addWidget(cc)

        # ── Status card ───────────────────────────────────────────────────────
        sc = card("Status")
        sl = QVBoxLayout(sc); sl.setContentsMargins(12,20,12,12)
        self.dot_icmp  = dot(ORANGE); self.dot_https = dot(ORANGE); self.dot_conn = dot(ORANGE)
        for d, label in [(self.dot_icmp,"ICMP ping"),(self.dot_https,"HTTPS port 443"),
                         (self.dot_conn,"Logged in / session active")]:
            row = QHBoxLayout(); row.addWidget(d)
            lbl = QLabel(label); lbl.setStyleSheet("color:#333;font-size:13px;")
            row.addWidget(lbl); row.addStretch(); sl.addLayout(row)
        btn_row = QHBoxLayout()
        self.btn_check = btn("Check Connectivity")
        self.btn_check.clicked.connect(self._check)
        self.btn_probe = btn("Probe Device URLs")
        self.btn_probe.clicked.connect(self._probe)
        btn_row.addWidget(self.btn_check); btn_row.addWidget(self.btn_probe); btn_row.addStretch()
        sl.addLayout(btn_row)
        root.addWidget(sc)

        # ── Device info ───────────────────────────────────────────────────────
        ic = card("Device Info")
        il = QFormLayout(ic); il.setContentsMargins(12,20,12,12)
        self.lbl_info = QLabel("Connect to populate device info.")
        self.lbl_info.setWordWrap(True); self.lbl_info.setStyleSheet("color:#555;font-size:12px;")
        il.addRow(self.lbl_info)
        root.addWidget(ic)
        root.addStretch()

    # ── scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        self.btn_scan.setEnabled(False)
        self.lst_devices.clear()
        self.lst_devices.setVisible(False)
        self.btn_use.setVisible(False)
        self.lbl_scan.setText("Scanning… this takes a few seconds.")
        self.app.set_status("Scanning network for JetPort devices…")

        w = Worker(scan_network)
        w.result.connect(self._on_scan_done)
        w.error.connect(lambda e: (self.lbl_scan.setText(f"Scan error: {e}"),
                                   self.btn_scan.setEnabled(True)))
        w.finished.connect(lambda: self.btn_scan.setEnabled(True))
        w.start(); self._scan_w = w

    def _on_scan_done(self, results: list):
        if not results:
            self.lbl_scan.setText("No devices found. Check that you're on the same network.")
            self.app.set_status("Scan complete — no devices found")
            return
        self.lst_devices.clear()
        for ip, desc in results:
            self.lst_devices.addItem(f"{ip}   —   {desc}")
        self.lst_devices.setVisible(True)
        self.btn_use.setVisible(True)
        n = len(results)
        self.lbl_scan.setText(f"Found {n} device{'s' if n != 1 else ''}. Double-click or select and click Connect.")
        self.app.set_status(f"Scan complete — {n} device(s) found")
        # Auto-fill if exactly one device found
        if n == 1:
            self.le_ip.setText(results[0][0])

    def _use_selected(self):
        item = self.lst_devices.currentItem()
        if item:
            ip = item.text().split()[0]
            self.le_ip.setText(ip)
            self._connect()

    # ── connectivity check ────────────────────────────────────────────────────

    def _check(self):
        self.btn_check.setEnabled(False)
        def do():
            return self.conn.ping_icmp(), self.conn.ping_https()
        w = Worker(do)
        w.result.connect(self._on_check)
        w.finished.connect(lambda: self.btn_check.setEnabled(True))
        w.start(); self._w = w

    def _on_check(self, res):
        icmp, https = res
        self.dot_icmp.setStyleSheet(f"color:{GREEN if icmp else RED};font-size:14px;")
        self.dot_https.setStyleSheet(f"color:{GREEN if https else RED};font-size:14px;")
        if not icmp:
            self.app.set_status("Device not reachable via ping — check network", error=True)
        elif not https:
            self.app.set_status("HTTPS port 443 not responding", error=True)
        else:
            self.app.set_status("Device reachable on HTTPS")

    # ── probe ─────────────────────────────────────────────────────────────────

    def _probe(self):
        if not self.conn.connected:
            self.app.set_status("Not connected — connect first", error=True); return
        self.btn_probe.setEnabled(False)
        self.app.set_status("Probing device URLs — check the Log tab for results…")
        w = Worker(self.conn.probe_urls)
        w.result.connect(lambda r: self.app.set_status(f"Probe complete — {len(r)} URL(s) checked. See Log tab."))
        w.error.connect(lambda e: self.app.set_status(f"Probe error: {e}", error=True))
        w.finished.connect(lambda: self.btn_probe.setEnabled(True))
        w.start(); self._probe_w = w

    # ── connect ───────────────────────────────────────────────────────────────

    def _connect(self):
        self.conn.ip = self.le_ip.text().strip()
        self.conn._pool = None; self.conn.connected = False
        self.btn_conn.setEnabled(False)
        w = Worker(self.conn.connect, self.le_pass.text())
        w.result.connect(self._on_connect)
        w.finished.connect(lambda: self.btn_conn.setEnabled(True))
        w.start(); self._w = w

    def _on_connect(self, res):
        ok, msg = res
        c = GREEN if ok else RED
        self.dot_conn.setStyleSheet(f"color:{c};font-size:14px;")
        if ok:
            self.app.set_status(f"Connected to {self.conn.ip}")
            discovered = ", ".join(self.conn._section_urls.keys()) or "none"
            self.lbl_info.setText(
                f"IP: {self.conn.ip}\n"
                f"Auto-discovered config sections: {discovered}\n\n"
                f"Use the config tabs and click 'Load from Device' to read current settings."
            )
        else:
            self.app.set_status(f"Connect failed: {msg}", error=True)

# ── Server Config tab ─────────────────────────────────────────────────────────

class ServerConfigTab(ConfigTab):
    section = "basic"

    def __init__(self, conn, app):
        super().__init__(conn, app); self._build()

    def _build(self):
        inner = QWidget()
        root = QVBoxLayout(inner); root.setContentsMargins(16,16,16,16); root.setSpacing(12)

        bc = card("Basic Settings")
        bl = QFormLayout(bc); bl.setContentsMargins(12,20,12,12); bl.setSpacing(8)
        self.le_name = le("device name"); self.le_loc = le("location")
        self.cb_tz   = cb(TIMEZONES); self.cb_tz.setCurrentText("GMT+08:00 Taipei")
        self.chk_ntp = QCheckBox("Enable SNTP Time Server")
        self.le_ntp  = le("pool.ntp.org"); self.le_ntp.setText("pool.ntp.org")
        self.sp_ntp  = QSpinBox(); self.sp_ntp.setRange(1,65535); self.sp_ntp.setValue(123)
        self.chk_web = QCheckBox("Enable Web Console"); self.chk_web.setChecked(True)
        self.chk_ssh = QCheckBox("Enable SSH/Telnet Console"); self.chk_ssh.setChecked(True)
        ntp_row = QHBoxLayout(); ntp_row.addWidget(self.le_ntp)
        ntp_row.addWidget(QLabel("Port:")); ntp_row.addWidget(self.sp_ntp)
        bl.addRow("Device Name:", self.le_name); bl.addRow("Location:", self.le_loc)
        bl.addRow("Time Zone:", self.cb_tz); bl.addRow("", self.chk_ntp)
        bl.addRow("NTP Server:", ntp_row)
        bl.addRow("", self.chk_web); bl.addRow("", self.chk_ssh)
        root.addWidget(bc)

        nc = card("Network Settings")
        nl = QFormLayout(nc); nl.setContentsMargins(12,20,12,12); nl.setSpacing(8)
        self.rb_static = QRadioButton("Static IP"); self.rb_dhcp = QRadioButton("DHCP")
        self.rb_bootp  = QRadioButton("BootP"); self.rb_static.setChecked(True)
        ip_row = QHBoxLayout()
        for r in [self.rb_static, self.rb_dhcp, self.rb_bootp]: ip_row.addWidget(r)
        ip_row.addStretch()
        self.le_ip   = le("192.168.10.2"); self.le_ip.setText("192.168.10.2")
        self.le_mask = le("255.255.255.0"); self.le_mask.setText("255.255.255.0")
        self.le_gw   = le("gateway"); self.le_dns1 = le("primary DNS"); self.le_dns2 = le("secondary DNS")
        nl.addRow("IP Mode:", ip_row); nl.addRow("IP Address:", self.le_ip)
        nl.addRow("Netmask:", self.le_mask); nl.addRow("Gateway:", self.le_gw)
        nl.addRow("DNS 1:", self.le_dns1); nl.addRow("DNS 2:", self.le_dns2)
        root.addWidget(nc)

        pw = card("Change Password")
        pl = QFormLayout(pw); pl.setContentsMargins(12,20,12,12); pl.setSpacing(8)
        self.le_pw_old = le("old password", password=True)
        self.le_pw_new = le("new password (max 12 chars)", password=True)
        self.le_pw_cfm = le("confirm new password", password=True)
        pl.addRow("Old:", self.le_pw_old); pl.addRow("New:", self.le_pw_new)
        pl.addRow("Confirm:", self.le_pw_cfm)
        root.addWidget(pw)

        br = QHBoxLayout(); br.addStretch()
        lb = self._load_btn(); ba, bs = self._apply_btns()
        for w in [lb, ba, bs]: br.addWidget(w)
        root.addLayout(br); root.addStretch()

        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(0,0,0,0)
        self.layout().addWidget(scrolled(inner))

    def populate(self, f: dict):
        def _set(w, keys, transform=None):
            for k in keys:
                if k in f:
                    v = f[k]
                    if transform: v = transform(v)
                    if isinstance(w, QLineEdit): w.setText(str(v))
                    elif isinstance(w, QCheckBox): w.setChecked(bool(v) if isinstance(v,bool) else v in ("1","on","true","yes","enabled"))
                    elif isinstance(w, QComboBox):
                        idx = w.findText(str(v), Qt.MatchFlag.MatchContains)
                        if idx >= 0: w.setCurrentIndex(idx)
                    break
        _set(self.le_name,  ["devname","name","sysname","DevName"])
        _set(self.le_loc,   ["location","loc","Location"])
        _set(self.le_ip,    ["ip","ipaddr","IPAddr","ip_addr"])
        _set(self.le_mask,  ["mask","netmask","NetMask","subnet"])
        _set(self.le_gw,    ["gw","gateway","Gateway","gwy"])
        _set(self.le_dns1,  ["dns1","dns","DNS1","dns_server1"])
        _set(self.le_dns2,  ["dns2","DNS2","dns_server2"])
        _set(self.le_ntp,   ["ntp","ntpserver","NTPServer","time_server"])
        _set(self.chk_web,  ["web_en","web","WebEn","httpEn"])
        _set(self.chk_ssh,  ["ssh_en","telnet_en","ssh","SshEn","TelnetEn"])
        _set(self.chk_ntp,  ["ntp_en","NtpEn","time_en"])

    def collect(self) -> dict:
        ipmode = "static" if self.rb_static.isChecked() else "dhcp" if self.rb_dhcp.isChecked() else "bootp"
        d = {
            "devname": self.le_name.text(), "location": self.le_loc.text(),
            "ipmode": ipmode, "ip": self.le_ip.text(), "mask": self.le_mask.text(),
            "gw": self.le_gw.text(), "dns1": self.le_dns1.text(), "dns2": self.le_dns2.text(),
            "ntp_en": "1" if self.chk_ntp.isChecked() else "0",
            "ntp": self.le_ntp.text(), "ntp_port": str(self.sp_ntp.value()),
            "web_en": "1" if self.chk_web.isChecked() else "0",
            "ssh_en": "1" if self.chk_ssh.isChecked() else "0",
        }
        if self.le_pw_new.text():
            if self.le_pw_new.text() != self.le_pw_cfm.text():
                QMessageBox.warning(self, "Error", "New passwords do not match."); return {}
            d.update({"pw_old": self.le_pw_old.text(), "pw_new": self.le_pw_new.text(),
                      "pw_confirm": self.le_pw_cfm.text()})
        return d

# ── Port Config tab ───────────────────────────────────────────────────────────

class PortConfigTab(ConfigTab):
    section = "port"

    def __init__(self, conn, app):
        super().__init__(conn, app); self._build()

    def _build(self):
        inner = QWidget()
        root = QVBoxLayout(inner); root.setContentsMargins(16,16,16,16); root.setSpacing(12)

        sc = card("Serial Parameters — Port 1")
        sl = QFormLayout(sc); sl.setContentsMargins(12,20,12,12); sl.setSpacing(8)
        self.le_alias  = le("port alias")
        self.cb_baud   = cb(BAUD);  self.cb_baud.setCurrentText("9600")
        self.cb_data   = cb(DBITS); self.cb_data.setCurrentText("8")
        self.cb_stop   = cb(SBITS); self.cb_stop.setCurrentText("1")
        self.cb_parity = cb(PARITY); self.cb_parity.setCurrentText("None")
        self.cb_flow   = cb(FLOW);  self.cb_flow.setCurrentText("None")
        self.cb_iface  = cb(IFACE); self.cb_iface.setCurrentText("RS232")
        self.rb_thru   = QRadioButton("Throughput"); self.rb_lat = QRadioButton("Latency")
        self.rb_thru.setChecked(True)
        perf = QHBoxLayout(); perf.addWidget(self.rb_thru); perf.addWidget(self.rb_lat); perf.addStretch()
        self.sp_ftx    = QSpinBox(); self.sp_ftx.setRange(0,65535); self.sp_ftx.setSuffix(" ms")
        sl.addRow("Port Alias:", self.le_alias); sl.addRow("Baud Rate:", self.cb_baud)
        sl.addRow("Data Bits:", self.cb_data);   sl.addRow("Stop Bits:", self.cb_stop)
        sl.addRow("Parity:", self.cb_parity);    sl.addRow("Flow Control:", self.cb_flow)
        sl.addRow("Interface:", self.cb_iface);  sl.addRow("Performance:", perf)
        sl.addRow("Force TX Interval:", self.sp_ftx)
        root.addWidget(sc)

        br = QHBoxLayout(); br.addStretch()
        lb = self._load_btn(); ba, bs = self._apply_btns()
        for w in [lb, ba, bs]: br.addWidget(w)
        root.addLayout(br); root.addStretch()

        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(0,0,0,0)
        self.layout().addWidget(scrolled(inner))

    def populate(self, f: dict):
        def _cb(w, keys):
            for k in keys:
                if k in f:
                    idx = w.findText(str(f[k]), Qt.MatchFlag.MatchContains)
                    if idx >= 0: w.setCurrentIndex(idx); break
        def _le(w, keys):
            for k in keys:
                if k in f: w.setText(str(f[k])); break
        _le(self.le_alias, ["alias","port_alias","PortAlias","portAlias"])
        _cb(self.cb_baud,  ["baud","baudrate","BaudRate","baud_rate"])
        _cb(self.cb_data,  ["data","databits","DataBits","data_bits"])
        _cb(self.cb_stop,  ["stop","stopbits","StopBits","stop_bits"])
        _cb(self.cb_parity,["parity","Parity"])
        _cb(self.cb_flow,  ["flow","flowctrl","FlowCtrl","flow_control"])
        _cb(self.cb_iface, ["iface","interface","Interface","mode","rs_mode"])
        for k in ["perf","performance","Performance"]:
            if k in f:
                if "lat" in str(f[k]).lower(): self.rb_lat.setChecked(True)
                else: self.rb_thru.setChecked(True)

    def collect(self) -> dict:
        return {
            "alias": self.le_alias.text(), "baud": self.cb_baud.currentText(),
            "data": self.cb_data.currentText(), "stop": self.cb_stop.currentText(),
            "parity": self.cb_parity.currentText(), "flow": self.cb_flow.currentText(),
            "iface": self.cb_iface.currentText(),
            "perf": "latency" if self.rb_lat.isChecked() else "throughput",
            "force_tx": str(self.sp_ftx.value()),
        }

# ── Service Mode tab ──────────────────────────────────────────────────────────

class ServiceModeTab(ConfigTab):
    section = "service"

    def __init__(self, conn, app):
        super().__init__(conn, app); self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(16,16,16,16); root.setSpacing(12)

        mc = card("Service Mode — Port 1")
        ml = QVBoxLayout(mc); ml.setContentsMargins(12,20,12,12)
        mode_row = QHBoxLayout()
        self.cb_mode = cb(SVCMODES); self.cb_mode.currentIndexChanged.connect(self._on_mode)
        mode_row.addWidget(QLabel("Mode:")); mode_row.addWidget(self.cb_mode); mode_row.addStretch()
        ml.addLayout(mode_row)
        root.addWidget(mc)

        self.stack = QStackedWidget(); root.addWidget(self.stack)
        self.stack.addWidget(self._vcom_page())
        self.stack.addWidget(self._tcp_srv_page())
        self.stack.addWidget(self._tcp_cli_page())
        self.stack.addWidget(self._udp_page())

        br = QHBoxLayout(); br.addStretch()
        lb = self._load_btn(); ba, bs = self._apply_btns()
        for w in [lb, ba, bs]: br.addWidget(w)
        root.addLayout(br); root.addStretch()

    def _common(self, form):
        self.sp_idle  = QSpinBox(); self.sp_idle.setRange(0,65535); self.sp_idle.setSuffix(" s")
        self.sp_alive = QSpinBox(); self.sp_alive.setRange(0,65535); self.sp_alive.setSuffix(" s")
        self.sp_maxc  = QSpinBox(); self.sp_maxc.setRange(1,5)
        form.addRow("Idle Timeout:", self.sp_idle)
        form.addRow("Alive Check:", self.sp_alive)
        form.addRow("Max Connections:", self.sp_maxc)

    def _vcom_page(self):
        w = QWidget(); f = QFormLayout(w); f.setContentsMargins(4,4,4,4)
        f.addRow(QLabel("Virtual COM: exposes serial port as a network tty device."))
        self._common(f); return w

    def _tcp_srv_page(self):
        w = QWidget(); f = QFormLayout(w); f.setContentsMargins(4,4,4,4)
        self.sp_srv_port = QSpinBox(); self.sp_srv_port.setRange(1,65535); self.sp_srv_port.setValue(4000)
        f.addRow("TCP Data Port:", self.sp_srv_port)
        self._common(f); return w

    def _tcp_cli_page(self):
        w = QWidget(); f = QFormLayout(w); f.setContentsMargins(4,4,4,4)
        self.le_cli_host = le("destination host IP")
        self.sp_cli_port = QSpinBox(); self.sp_cli_port.setRange(1,65535); self.sp_cli_port.setValue(4000)
        self.rb_on_start = QRadioButton("Connect on Startup"); self.rb_on_char = QRadioButton("Connect on Any Char")
        self.rb_on_start.setChecked(True)
        conn_row = QHBoxLayout(); conn_row.addWidget(self.rb_on_start); conn_row.addWidget(self.rb_on_char); conn_row.addStretch()
        f.addRow("Destination Host:", self.le_cli_host)
        f.addRow("Port:", self.sp_cli_port); f.addRow("Connect:", conn_row)
        self._common(f); return w

    def _udp_page(self):
        w = QWidget(); f = QFormLayout(w); f.setContentsMargins(4,4,4,4)
        self.sp_udp_listen = QSpinBox(); self.sp_udp_listen.setRange(1,65535); self.sp_udp_listen.setValue(4000)
        self.le_udp_start  = le("e.g. 192.168.10.1"); self.le_udp_end = le("e.g. 192.168.10.100")
        self.sp_udp_send   = QSpinBox(); self.sp_udp_send.setRange(1,65535); self.sp_udp_send.setValue(4040)
        rng = QHBoxLayout(); rng.addWidget(self.le_udp_start); rng.addWidget(QLabel("→")); rng.addWidget(self.le_udp_end)
        f.addRow("Listen Port:", self.sp_udp_listen); f.addRow("Dest Range:", rng)
        f.addRow("Send Port:", self.sp_udp_send); return w

    def _on_mode(self, idx): self.stack.setCurrentIndex(idx)

    def populate(self, f: dict):
        mode_map = {"virtualcom":"Virtual COM","vcom":"Virtual COM",
                    "tcpserver":"TCP Server","tcp_server":"TCP Server",
                    "tcpclient":"TCP Client","tcp_client":"TCP Client","udp":"UDP"}
        for k in ["mode","service_mode","ServiceMode","svcmode"]:
            if k in f:
                v = str(f[k]).lower().replace(" ","")
                mapped = mode_map.get(v, "")
                if mapped:
                    self.cb_mode.setCurrentText(mapped)

    def collect(self) -> dict:
        mode = self.cb_mode.currentText()
        d = {"mode": mode, "idle": str(self.sp_idle.value()),
             "alive": str(self.sp_alive.value()), "maxconn": str(self.sp_maxc.value())}
        if mode == "TCP Server": d["port"] = str(self.sp_srv_port.value())
        elif mode == "TCP Client":
            d["dest_host"] = self.le_cli_host.text(); d["dest_port"] = str(self.sp_cli_port.value())
            d["conn_on"] = "startup" if self.rb_on_start.isChecked() else "char"
        elif mode == "UDP":
            d["listen_port"] = str(self.sp_udp_listen.value())
            d["dest_start"] = self.le_udp_start.text(); d["dest_end"] = self.le_udp_end.text()
            d["send_port"] = str(self.sp_udp_send.value())
        return d

# ── Save / Restart tab ────────────────────────────────────────────────────────

class SaveRestartTab(ConfigTab):
    section = "save"

    def __init__(self, conn, app):
        super().__init__(conn, app); self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(16,16,16,16); root.setSpacing(12)

        for title, info, action_label, cb in [
            ("Reboot Device",
             "Sends a warm-restart command. Unapplied settings will be lost.",
             "Reboot", self._reboot),
            ("Load Factory Defaults",
             "Resets all config to factory defaults except IP address. Device will reboot.",
             "Load Defaults", self._defaults),
        ]:
            c = card(title); cl = QHBoxLayout(c); cl.setContentsMargins(12,20,12,12)
            lbl = QLabel(info); lbl.setWordWrap(True); lbl.setStyleSheet("color:#555;")
            b = btn(action_label, danger=True); b.clicked.connect(cb)
            cl.addWidget(lbl); cl.addWidget(b); root.addWidget(c)

        ec = card("Export / Import Config")
        el = QVBoxLayout(ec); el.setContentsMargins(12,20,12,12)
        exp_row = QHBoxLayout()
        exp_info = QLabel("Save device configuration to a local file.")
        exp_info.setWordWrap(True)
        b_exp = btn("Export Config"); b_exp.clicked.connect(self._export)
        exp_row.addWidget(exp_info); exp_row.addWidget(b_exp)
        el.addLayout(exp_row)
        root.addWidget(ec)
        root.addStretch()

    def _reboot(self):
        if QMessageBox.question(self,"Reboot","Reboot device?",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        w = Worker(self.conn.reboot)
        w.result.connect(lambda r: self.app.set_status(f"Rebooted: {r[1]}" if r[0] else f"Reboot failed: {r[1]}", error=not r[0]))
        w.start(); self._worker = w

    def _defaults(self):
        if QMessageBox.question(self,"Factory Defaults","Reset ALL settings to defaults?",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        w = Worker(self.conn.load_defaults)
        w.result.connect(lambda r: self.app.set_status(f"Defaults loaded: {r[1]}" if r[0] else f"Failed: {r[1]}", error=not r[0]))
        w.start(); self._worker = w

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self,"Export Config","jetport_config.bin","All files (*)")
        if not path: return
        def do():
            for url in ["/export.cgi","/backup.cgi","/config.cgi"]:
                st, data = self.conn._get(url)
                if st == 200 and data: return data, None
            return None, "Could not find export endpoint"
        def on_res(res):
            data, err = res
            if err: QMessageBox.warning(self,"Export Failed", err); return
            with open(path,"w") as f: f.write(data)
            QMessageBox.information(self,"Exported",f"Saved to {path}")
        w = Worker(do); w.result.connect(on_res); w.start(); self._worker = w

# ── In-app SSH terminal ───────────────────────────────────────────────────────

class SSHTerminalTab(QWidget):
    def __init__(self, device_ip: str):
        super().__init__()
        self.device_ip = device_ip
        self._child    = None
        self._reader   = None
        self._q: queue.Queue[str] = queue.Queue()
        self._build()
        self._timer = QTimer(self); self._timer.timeout.connect(self._flush); self._timer.start(50)

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # Connection bar
        bar = QWidget(); bar.setStyleSheet(f"background:{CARD};border-bottom:1px solid {BORDER};")
        bl  = QHBoxLayout(bar); bl.setContentsMargins(12,8,12,8); bl.setSpacing(8)
        self.le_host = QLineEdit(self.device_ip)
        self.sp_port = QSpinBox(); self.sp_port.setRange(1,65535); self.sp_port.setValue(22)
        self.le_user = QLineEdit("admin")
        self.le_pass = QLineEdit("admin"); self.le_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.btn_con = btn("Connect", primary=True)
        self.btn_dis = btn("Disconnect"); self.btn_dis.setEnabled(False)
        self.btn_con.clicked.connect(self.connect)
        self.btn_dis.clicked.connect(self.disconnect)
        for label, w in [("Host:", self.le_host), ("Port:", self.sp_port),
                         ("User:", self.le_user),  ("Pass:", self.le_pass)]:
            bl.addWidget(QLabel(label)); bl.addWidget(w)
        bl.addWidget(self.btn_con); bl.addWidget(self.btn_dis); bl.addStretch()
        root.addWidget(bar)

        # Output
        self.output = QTextEdit(); self.output.setReadOnly(True)
        self.output.setFont(QFont("Monospace", 10))
        self.output.setStyleSheet("background:#1e1e1e;color:#d4d4d4;border:none;")
        root.addWidget(self.output)

        # Input bar
        ib = QWidget(); ib.setStyleSheet(f"background:#2d2d2d;border-top:1px solid #444;")
        il = QHBoxLayout(ib); il.setContentsMargins(8,4,8,4); il.setSpacing(6)
        prompt = QLabel("›"); prompt.setStyleSheet("color:#7ec8e3;font-family:Monospace;font-size:14px;")
        self.inp = QLineEdit()
        self.inp.setFont(QFont("Monospace",10))
        self.inp.setStyleSheet("background:transparent;color:#d4d4d4;border:none;")
        self.inp.setPlaceholderText("type command, press Enter…")
        self.inp.returnPressed.connect(self._send)
        il.addWidget(prompt); il.addWidget(self.inp)
        root.addWidget(ib)

    def connect(self):
        if self._child is not None:
            try:
                if self._child.isalive(): return
            except Exception: pass
        try:
            import pexpect
        except ImportError:
            self._write("[pexpect not found — run: pip3 install pexpect]\n", RED); return

        host = self.le_host.text(); port = self.sp_port.value()
        user = self.le_user.text(); password = self.le_pass.text()
        self._write(f"Connecting to {user}@{host}:{port} …\n", ORANGE)
        self.btn_con.setEnabled(False); self.btn_dis.setEnabled(True)

        def reader():
            import pexpect
            try:
                cmd = (f"ssh "
                       f"-o StrictHostKeyChecking=no "
                       f"-o UserKnownHostsFile=/dev/null "
                       f"-o HostKeyAlgorithms=+ssh-rsa,ssh-dss "
                       f"-o KexAlgorithms=+diffie-hellman-group1-sha1,"
                       f"diffie-hellman-group14-sha1,diffie-hellman-group14-sha256 "
                       f"-o Ciphers=+3des-cbc,aes128-cbc,aes256-cbc,aes128-ctr "
                       f"-p {port} {user}@{host}")
                self._child = pexpect.spawn(cmd, timeout=20, encoding="utf-8", echo=False)
                idx = self._child.expect(["[Pp]assword:", "yes/no", pexpect.TIMEOUT, pexpect.EOF])
                if idx == 1:
                    self._child.sendline("yes")
                    self._child.expect("[Pp]assword:", timeout=10)
                    idx = 0
                if idx == 0:
                    self._child.sendline(password)
                elif idx >= 2:
                    self._q.put(("\n[Connection timed out or refused]\n", RED)); return

                # Continuous read
                while True:
                    try:
                        data = self._child.read_nonblocking(size=4096, timeout=0.1)
                        if data:
                            clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", data)
                            clean = re.sub(r"\x1b[()][AB012]", "", clean)
                            clean = clean.replace("\r\n","\n").replace("\r","\n")
                            self._q.put((clean, None))
                    except pexpect.TIMEOUT:
                        continue
                    except (pexpect.EOF, EOFError):
                        self._q.put(("\n[Connection closed]\n", ORANGE)); break
                    except Exception as e:
                        self._q.put((f"\n[Error: {e}]\n", RED)); break
            except Exception as e:
                self._q.put((f"\n[SSH error: {e}]\n", RED))
            finally:
                self._q.put(("__DONE__", None))

        self._reader = threading.Thread(target=reader, daemon=True)
        self._reader.start()

    def disconnect(self):
        if self._child:
            try: self._child.close(force=True)
            except Exception: pass
            self._child = None
        self.btn_con.setEnabled(True); self.btn_dis.setEnabled(False)
        self._write("\n[Disconnected]\n", ORANGE)

    def _send(self):
        text = self.inp.text(); self.inp.clear()
        if self._child:
            try:
                self._child.sendline(text)
                self._write(f"\n", None)  # newline after input echo
            except Exception as e:
                self._write(f"[send error: {e}]\n", RED)

    def _write(self, text: str, color: str | None):
        if color:
            self.output.setTextColor(QColor(color))
        else:
            self.output.setTextColor(QColor("#d4d4d4"))
        self.output.insertPlainText(text)
        self.output.moveCursor(QTextCursor.MoveOperation.End)

    def _flush(self):
        while True:
            try:
                text, color = self._q.get_nowait()
                if text == "__DONE__":
                    self.btn_con.setEnabled(True); self.btn_dis.setEnabled(False); return
                self._write(text, color)
            except queue.Empty:
                break

# ── Connection log tab ────────────────────────────────────────────────────────

class LogTab(QWidget):
    def __init__(self, conn: DeviceConnection):
        super().__init__(); self.conn = conn; self._build()
        t = QTimer(self); t.timeout.connect(self._refresh); t.start(1000)

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(16,16,16,16)
        self.te = QTextEdit(); self.te.setReadOnly(True)
        self.te.setFont(QFont("Monospace",9))
        self.te.setStyleSheet("background:#1e1e1e;color:#d4d4d4;border:1px solid #444;border-radius:4px;")
        b = btn("Clear"); b.clicked.connect(lambda: (self.conn.log.clear(), self.te.clear()))
        row = QHBoxLayout(); row.addStretch(); row.addWidget(b)
        root.addWidget(self.te); root.addLayout(row)

    def _refresh(self):
        current = self.te.toPlainText().count("\n")
        new_lines = self.conn.log[current:]
        if new_lines:
            self.te.setTextColor(QColor("#d4d4d4"))
            for line in new_lines:
                if "ERROR" in line: self.te.setTextColor(QColor("#ff6b6b"))
                else: self.te.setTextColor(QColor("#d4d4d4"))
                self.te.append(line)
            self.te.moveCursor(QTextCursor.MoveOperation.End)

# ── Main window ───────────────────────────────────────────────────────────────

class JetPortManager(QMainWindow):
    def __init__(self, device_ip="192.168.10.2"):
        super().__init__()
        self.conn = DeviceConnection(device_ip)
        self._build()

    def _build(self):
        self.setWindowTitle(f"JetPort 5601 Manager")
        self.resize(860, 680); self.setMinimumSize(720, 500)
        self.setStyleSheet(f"""
            QMainWindow,QWidget{{background:{BG};}}
            QTabWidget::pane{{border:none;}}
            QTabBar::tab{{background:#e9ecef;color:#555;border-radius:5px 5px 0 0;
                          padding:7px 16px;margin-right:2px;}}
            QTabBar::tab:selected{{background:{ACCENT};color:white;}}
            QTabBar::tab:hover:!selected{{background:#d3d9e0;}}
            QLabel{{color:#333;}} QSpinBox{{border:1px solid {BORDER};border-radius:4px;
                                            padding:4px 8px;background:white;color:#333;}}
            QCheckBox{{color:#333;}} QRadioButton{{color:#333;}}
        """)

        # Header
        hdr = QWidget(); hdr.setFixedHeight(50); hdr.setStyleSheet(f"background:{ACCENT};")
        hl = QHBoxLayout(hdr); hl.setContentsMargins(16,0,16,0)
        title = QLabel("  JetPort 5601 Manager")
        title.setFont(QFont("Sans",14,QFont.Weight.Bold)); title.setStyleSheet("color:white;")
        hl.addWidget(title); hl.addStretch()

        central = QWidget(); self.setCentralWidget(central)
        vl = QVBoxLayout(central); vl.setContentsMargins(0,0,0,0); vl.setSpacing(0)
        vl.addWidget(hdr)

        tabs = QTabWidget(); tabs.setDocumentMode(True)
        tabs.setStyleSheet(f"QTabWidget::pane{{background:{BG};border-top:1px solid {BORDER};}}")
        vl.addWidget(tabs)

        dash   = DashboardTab(self.conn, self)
        srv    = ServerConfigTab(self.conn, self)
        port   = PortConfigTab(self.conn, self)
        svc    = ServiceModeTab(self.conn, self)
        save   = SaveRestartTab(self.conn, self)
        ssh    = SSHTerminalTab(self.conn.ip)
        log    = LogTab(self.conn)

        tabs.addTab(dash,  "Connect")
        tabs.addTab(srv,   "Server Config")
        tabs.addTab(port,  "Port Config")
        tabs.addTab(svc,   "Service Mode")
        tabs.addTab(save,  "Save / Restart")
        tabs.addTab(ssh,   "SSH Terminal")
        tabs.addTab(log,   "Log")

        self.sb = QStatusBar()
        self.sb.setStyleSheet(f"background:{CARD};border-top:1px solid {BORDER};color:#555;font-size:11px;")
        self.setStatusBar(self.sb); self.sb.showMessage("Ready — connect to device first")

    def set_status(self, msg: str, error=False):
        self.sb.showMessage(msg)
        color = RED if error else "#555"
        self.sb.setStyleSheet(f"background:{CARD};border-top:1px solid {BORDER};color:{color};font-size:11px;")
        if error:
            QTimer.singleShot(5000, lambda: self.sb.setStyleSheet(
                f"background:{CARD};border-top:1px solid {BORDER};color:#555;font-size:11px;"))

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ip = next((a for a in sys.argv[1:] if re.match(r"^\d+\.\d+\.\d+\.\d+$", a)), "192.168.10.2")
    app = QApplication(sys.argv); app.setStyle("Fusion")

    # Force a light-mode palette so Fusion doesn't inherit dark system colors.
    # Without this, popup windows (combo dropdowns, etc.) draw white text on
    # white because QPalette.Text is white from the OS dark theme.
    from PyQt6.QtGui import QPalette
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window,          QColor(BG))
    p.setColor(QPalette.ColorRole.WindowText,      QColor("#333333"))
    p.setColor(QPalette.ColorRole.Base,            QColor("#ffffff"))
    p.setColor(QPalette.ColorRole.AlternateBase,   QColor(BG))
    p.setColor(QPalette.ColorRole.Text,            QColor("#333333"))
    p.setColor(QPalette.ColorRole.PlaceholderText, QColor("#aaaaaa"))
    p.setColor(QPalette.ColorRole.Button,          QColor("#eaedf1"))
    p.setColor(QPalette.ColorRole.ButtonText,      QColor("#24292f"))
    p.setColor(QPalette.ColorRole.Highlight,       QColor(ACCENT))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.ColorRole.ToolTipBase,     QColor("#ffffff"))
    p.setColor(QPalette.ColorRole.ToolTipText,     QColor("#333333"))
    app.setPalette(p)

    win = JetPortManager(ip); win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
