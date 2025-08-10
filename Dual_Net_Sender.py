#!/usr/bin/env python3
"""
DualNetSender.py — multi-connection race tester for pentesters & bug bounty
"""
# Send TWO raw HTTP requests via DIFFERENT network paths (LAN & Wi‑Fi), either:
#   - SEQUENTIALLY,
#   - CONCURRENT per iteration (pairwise barrier),
#   - CONCURRENT **MULTI-CONNECTION**: fire ALL requests at ONE instant.
#
# Features:
# - Bind per path by LOCAL IP (requests) or INTERFACE NAME (pycurl)
# - Show PUBLIC IP via https://ifconfig.io/ip (per path)
# - Barrier for simultaneous fire (pairwise or multi-connection)
# - Iterations with index-suffixed outputs (.001, .002, …)
# - Decode Content‑Encoding: br/gzip/deflate (Brotli via optional package)
# - Proxy support: --proxy / -p
# - TLS: --verify-tls / -vt (verify), else suppress warning
# - Colorized console (colorama)
#
# Short flags:
#   -O, -L, -W, -lq, -wq, -ls, -ws, -lo, -wo, -vt, -t, -p, -sm, -i, -si, -mc

import argparse
import re
import sys
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Dict, Tuple, Optional, List
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager

# Optional: pycurl for interface-name binding
try:
    import pycurl  # type: ignore
    _HAS_PYCURL = True
except Exception:
    _HAS_PYCURL = False

# Optional: Brotli support
import zlib
try:
    import brotli  # type: ignore
    _HAS_BROTLI = True
except Exception:
    _HAS_BROTLI = False

# Colorized output
from colorama import init as colorama_init, Fore, Style
colorama_init(autoreset=True)


# ==================
# Models & parsing
# ==================

@dataclass
class RawRequest:
    """Parsed elements of a Burp-style raw HTTP request."""
    method: str
    start_line_target: str  # "/path" or "http(s)://host:port/path"
    headers: Dict[str, str]
    body: bytes


def parse_raw_request_file(path: str) -> RawRequest:
    """
    Parse a raw HTTP request file (Burp style).
    - First line: "METHOD SP request-target SP HTTP/1.x"
    - Headers: one per line until blank line
    - Body: raw bytes after the first blank line
    """
    raw = Path(path).read_bytes()
    sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    head, body = raw.split(sep, 1) if sep in raw else (raw, b"")

    head_text = head.decode("utf-8", errors="replace").replace("\r\n", "\n")
    lines = head_text.split("\n")
    if not lines or len(lines[0].strip().split()) < 3:
        raise ValueError(f"Invalid request start line in {path!r}")

    req_line = lines[0].strip()
    parts = req_line.split()
    method = parts[0].upper()
    request_target = parts[1]

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    return RawRequest(method=method, start_line_target=request_target, headers=headers, body=body)


def sanitize_headers(h: Dict[str, str]) -> Dict[str, str]:
    """Drop hop-by-hop/managed headers; client sets them correctly."""
    drop = {"connection", "content-length", "transfer-encoding", "host"}
    return {k: v for k, v in h.items() if k.lower() not in drop}


def split_host_port(hostport: str, default_port: int) -> Tuple[str, int]:
    """Return (host, port) for 'example.com:8443' or '[::1]:8443' or bare host."""
    m = re.match(r"^\[(.+)\]:(\d+)$", hostport)  # IPv6 with port: [::1]:8443
    if m:
        return m.group(1), int(m.group(2))
    if ":" in hostport and hostport.rsplit(":", 1)[1].isdigit():
        host, port_str = hostport.rsplit(":", 1)
        return host, int(port_str)
    return hostport.strip("[]"), default_port


def build_url(raw: RawRequest, scheme: str) -> Tuple[str, str, int, str]:
    """Build (scheme, host, port, path) from the raw request + chosen scheme."""
    target = raw.start_line_target

    if target.lower().startswith(("http://", "https://")):
        m = re.match(r"^(https?)://([^/]+)(/.*)?$", target, re.IGNORECASE)
        if not m:
            raise ValueError(f"Invalid absolute URL in request line: {target}")
        sch = m.group(1).lower()
        hostport = m.group(2)
        path = m.group(3) or "/"
        host, port = split_host_port(hostport, default_port=(80 if sch == "http" else 443))
        return sch, host, port, path

    host_header = raw.headers.get("Host") or raw.headers.get("host")
    if not host_header:
        raise ValueError("Missing Host header for origin-form request target.")
    host, port = split_host_port(host_header, default_port=(80 if scheme == "http" else 443))
    path = target if target.startswith("/") else "/" + target
    return scheme, host, port, path


# =========================
# Proxy utils
# =========================

def parse_proxy(proxy_url: Optional[str]):
    """Return a requests-style proxies dict and pycurl args for a given proxy URL."""
    if not proxy_url:
        return None, None
    proxies = {"http": proxy_url, "https": proxy_url}
    m = re.match(r"^(https?)://([^:/]+):(\d+)$", proxy_url, re.IGNORECASE)
    if not m:
        raise SystemExit(f"Unsupported proxy format: {proxy_url} (use http://host:port)")
    _, host, port = m.group(1).lower(), m.group(2), int(m.group(3))
    pycurl_conf = {"host": host, "port": port}
    return proxies, pycurl_conf


# =========================
# Binding by local IP (requests)
# =========================

class SourceIPAdapter(HTTPAdapter):
    """HTTPAdapter that binds sockets to a given local/source IP."""
    def __init__(self, source_ip: str, **kwargs):
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs.setdefault("source_address", (self.source_ip, 0))
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)


@dataclass
class RespInfo:
    status: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: float
    http_version: str
    reason: str
    raw_status_line: Optional[str] = None
    raw_header_lines: Optional[List[str]] = None


def http_version_from_requests(resp) -> str:
    v = getattr(resp.raw, "version", None)
    if v == 10:
        return "HTTP/1.0"
    if v == 11:
        return "HTTP/1.1"
    if v == 20:
        return "HTTP/2"
    return "HTTP/1.1"


def session_bound_to_ip(local_ip: str, verify_tls: bool, proxies: Optional[Dict[str, str]]) -> requests.Session:
    s = requests.Session()
    adapter = SourceIPAdapter(local_ip)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = verify_tls
    if proxies:
        s.proxies.update(proxies)
    return s


def public_ip_via_local_ip(local_ip: str, timeout: int, verify_tls: bool, proxies: Optional[Dict[str, str]]) -> Tuple[int, str]:
    """GET https://ifconfig.io/ip using a session bound to local_ip."""
    sess = session_bound_to_ip(local_ip, verify_tls=verify_tls, proxies=proxies)
    try:
        r = sess.get("https://ifconfig.io/ip", timeout=timeout)
        return r.status_code, r.text.strip()
    except Exception as ex:
        return 0, f"ERROR: {ex!r}"


def send_via_local_ip(local_ip: str, method: str, url: str, headers: Dict[str, str], body: bytes, verify_tls: bool, timeout: int, proxies: Optional[Dict[str, str]]) -> RespInfo:
    s = session_bound_to_ip(local_ip, verify_tls=verify_tls, proxies=proxies)
    t0 = time.perf_counter()
    try:
        resp = s.request(method, url, headers=headers, data=body or None, timeout=timeout)
        elapsed = (time.perf_counter() - t0) * 1000.0
        return RespInfo(
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content,
            elapsed_ms=elapsed,
            http_version=http_version_from_requests(resp),
            reason=getattr(resp, "reason", "") or ""
        )
    except Exception as ex:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return RespInfo(
            status=0,
            headers={},
            body=f"ERROR: {ex!r}".encode(),
            elapsed_ms=elapsed,
            http_version="HTTP/1.1",
            reason="ERROR"
        )


# =========================
# Binding by interface (pycurl)
# =========================

def public_ip_via_interface(iface: str, timeout: int, verify_tls: bool, pycurl_proxy: Optional[Dict[str, str]]) -> Tuple[int, str]:
    if not _HAS_PYCURL:
        raise RuntimeError("pycurl not installed; interface binding requires: pip install pycurl")
    buf = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, b"https://ifconfig.io/ip")
    c.setopt(c.INTERFACE, iface.encode("utf-8"))
    c.setopt(c.TIMEOUT, timeout)
    c.setopt(c.WRITEDATA, buf)
    c.setopt(c.SSL_VERIFYPEER, 1 if verify_tls else 0)
    c.setopt(c.SSL_VERIFYHOST, 2 if verify_tls else 0)
    if pycurl_proxy:
        c.setopt(c.PROXY, pycurl_proxy["host"])
        c.setopt(c.PROXYPORT, pycurl_proxy["port"])
        c.setopt(c.PROXYTYPE, pycurl.PROXYTYPE_HTTP)
    c.perform()
    code = c.getinfo(c.RESPONSE_CODE)
    c.close()
    return code, buf.getvalue().decode("utf-8", errors="replace").strip()


def send_via_interface(iface: str, method: str, url: str, headers: Dict[str, str], body: bytes, verify_tls: bool, timeout: int, pycurl_proxy: Optional[Dict[str, str]]) -> RespInfo:
    if not _HAS_PYCURL:
        raise RuntimeError("pycurl not installed; interface binding requires: pip install pycurl")

    body = body or b""
    header_list = [f"{k}: {v}" for k, v in headers.items()]

    buf = BytesIO()
    header_buf = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, url.encode("utf-8"))
    c.setopt(c.INTERFACE, iface.encode("utf-8"))
    c.setopt(c.TIMEOUT, timeout)
    c.setopt(c.NOPROGRESS, True)
    c.setopt(c.SSL_VERIFYPEER, 1 if verify_tls else 0)
    c.setopt(c.SSL_VERIFYHOST, 2 if verify_tls else 0)
    c.setopt(c.WRITEDATA, buf)
    c.setopt(c.HEADERFUNCTION, header_buf.write)
    if pycurl_proxy:
        c.setopt(c.PROXY, pycurl_proxy["host"])
        c.setopt(c.PROXYPORT, pycurl_proxy["port"])
        c.setopt(c.PROXYTYPE, pycurl.PROXYTYPE_HTTP)

    m = method.upper()
    if m == "GET":
        c.setopt(c.HTTPGET, True)
    elif m == "POST":
        c.setopt(c.POST, True)
        if body:
            c.setopt(c.POSTFIELDS, body)
            c.setopt(c.POSTFIELDSIZE, len(body))
    else:
        c.setopt(c.CUSTOMREQUEST, m)
        if body:
            c.setopt(c.POSTFIELDS, body)
            c.setopt(c.POSTFIELDSIZE, len(body))

    if header_list:
        c.setopt(c.HTTPHEADER, header_list)

    t0 = time.perf_counter()
    c.perform()
    elapsed = (time.perf_counter() - t0) * 1000.0
    status = c.getinfo(c.RESPONSE_CODE)
    c.close()

    header_text = header_buf.getvalue().decode("utf-8", errors="replace").replace("\r\n", "\n")
    lines = [ln for ln in header_text.split("\n") if ln.strip()]

    raw_status_line = None
    raw_header_lines: List[str] = []
    for ln in lines:
        if ln.upper().startswith("HTTP/"):
            raw_status_line = ln.strip()
            continue
        if ":" in ln:
            raw_header_lines.append(ln.strip())

    headers_dict: Dict[str, str] = {}
    for ln in raw_header_lines:
        k, v = ln.split(":", 1)
        headers_dict[k.strip()] = v.strip()

    reason = ""
    if raw_status_line:
        m = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\s+(.*)$", raw_status_line)
        if m:
            reason = m.group(2)

    http_version = raw_status_line.split()[0] if raw_status_line else "HTTP/1.1"

    return RespInfo(
        status=status,
        headers=headers_dict,
        body=buf.getvalue(),
        elapsed_ms=elapsed,
        http_version=http_version,
        reason=reason,
        raw_status_line=raw_status_line,
        raw_header_lines=raw_header_lines
    )


# ==========
# Decoding & writing HTTP transcript
# ==========

def decode_body_if_possible(body: bytes, headers: Dict[str, str]):
    h = {k.lower(): v for k, v in headers.items()}
    enc = (h.get("content-encoding", "") or "").lower()

    if enc == "br":
        if _HAS_BROTLI:
            try:
                return brotli.decompress(body)
            except Exception:
                return body
        else:
            return body

    if enc == "gzip":
        try:
            return zlib.decompress(body, zlib.MAX_WBITS | 16)
        except Exception:
            return body
    elif enc == "deflate":
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(body, wbits)
            except Exception:
                continue
        return body

    return body


def write_http_transcript(out_path: str, resp: RespInfo):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    status_line = resp.raw_status_line or f"{resp.http_version} {resp.status} {resp.reason or ''}".strip()

    if resp.raw_header_lines:
        header_lines = resp.raw_header_lines
    else:
        header_lines = [f"{k}: {v}" for k, v in resp.headers.items()]

    decoded_bytes = decode_body_if_possible(resp.body, resp.headers)

    try:
        body_text = decoded_bytes.decode("utf-8")
        body_bytes_to_write = body_text.encode("utf-8")
    except UnicodeDecodeError:
        body_bytes_to_write = decoded_bytes

    header_block = status_line + "\n" + "\n".join(header_lines) + "\n\n"
    with open(out_path, "wb") as f:
        f.write(header_block.encode("utf-8"))
        f.write(body_bytes_to_write)


def numbered_name(base: str, idx: int) -> str:
    p = Path(base)
    stem, suf = p.stem, p.suffix
    return str(p.with_name(f"{stem}.{idx:03d}{suf}"))


# ==========
# CLI
# ==========

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Send two Burp-style raw HTTP requests via different network paths (LAN & Wi‑Fi).",        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-O", "--os", choices=["windows", "linux", "macos"], required=True, help="Operating system (for logs/validation).")

    # Network bindings: each can be a LOCAL IP or an INTERFACE NAME
    p.add_argument("-L", "--lan", required=True, help="LAN binding (local IP or interface; e.g., '192.168.1.23' or 'eth0').")
    p.add_argument("-W", "--wifi", required=True, help="Wi‑Fi binding (local IP or interface; e.g., '10.0.0.55' or 'wlan0').")

    # Raw request files
    p.add_argument("-lq", "--lan-request", required=True, help="Path to raw HTTP request file for LAN.")
    p.add_argument("-wq", "--wifi-request", required=True, help="Path to raw HTTP request file for Wi‑Fi.")

    # Scheme selection (if the start-line is not absolute URL)
    p.add_argument("-ls", "--lan-scheme", choices=["http", "https"], help="Scheme for LAN request if not absolute in file.")
    p.add_argument("-ws", "--wifi-scheme", choices=["http", "https"], help="Scheme for Wi‑Fi request if not absolute in file.")

    # Output (HTTP transcript per iteration)
    p.add_argument("-lo", "--lan-out", required=True, help="Base file to write LAN HTTP transcript (e.g., ./out/lan.http)." )
    p.add_argument("-wo", "--wifi-out", required=True, help="Base file to write Wi‑Fi HTTP transcript (e.g., ./out/wifi.http)." )

    # TLS & timeout
    p.add_argument("-vt", "--verify-tls", action="store_true", default=False, help="Enable TLS certificate verification (default: off)." )
    p.add_argument("-t", "--timeout", type=int, default=20, help="Per-request timeout in seconds (default: 20)." )

    # Proxy
    p.add_argument("-p", "--proxy", help="Intercept proxy URL for both http/https (e.g., http://127.0.0.1:8080)." )

    # Concurrency / Race
    p.add_argument("-sm", "--send-mode", choices=["sequential", "concurrent"], default="sequential",                   help="Sequential (LAN then Wi‑Fi) or concurrent (pairwise or multi-connection). Default: sequential.")
    p.add_argument("-i", "--iterations", type=int, default=1, help="Number of iterations (pairs)." )
    p.add_argument("-si", "--sleep-ms-between-iters", type=int, default=0, help="Pause in milliseconds between iterations (default 0)." )
    p.add_argument("-mc", "--multi-connection", action="store_true",                   help="With --send-mode concurrent: fire ALL connections at the SAME instant (2*iterations total)." )

    return p


def looks_like_ip(s: str) -> bool:
    if ":" in s and "." not in s:
        return True
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def prompt_scheme(name: str) -> str:
    while True:
        val = input(f"{Fore.CYAN}Choose scheme for {name} (http/https): {Style.RESET_ALL}").strip().lower()
        if val in ("http", "https"):
            return val
        print(Fore.YELLOW + "Please type 'http' or 'https'." + Style.RESET_ALL)


def main():
    args = build_parser().parse_args()

    # Conditionally suppress urllib3 InsecureRequestWarning when verification is off
    if not args.verify_tls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Parse raw requests
    lan_req = parse_raw_request_file(args.lan_request)
    wifi_req = parse_raw_request_file(args.wifi_request)

    # Decide binding mode (IP vs interface)
    lan_binding = args.lan
    wifi_binding = args.wifi
    lan_is_ip = looks_like_ip(lan_binding)
    wifi_is_ip = looks_like_ip(wifi_binding)

    if (not lan_is_ip or not wifi_is_ip) and not _HAS_PYCURL:
        print(Fore.RED + "Error: Interface-name binding requires 'pycurl'. Install with: pip install pycurl" + Style.RESET_ALL)
        sys.exit(1)

    # Determine scheme where needed
    lan_scheme = (args.lan_scheme if not lan_req.start_line_target.lower().startswith(("http://", "https://")) else None)
    wifi_scheme = (args.wifi_scheme if not wifi_req.start_line_target.lower().startswith(("http://", "https://")) else None)

    if lan_scheme is None and not lan_req.start_line_target.lower().startswith(("http://", "https://")):
        lan_scheme = prompt_scheme("LAN")
    if wifi_scheme is None and not wifi_req.start_line_target.lower().startswith(("http://", "https://")):
        wifi_scheme = prompt_scheme("Wi‑Fi")

    # Build URLs
    lan_scheme, lan_host, lan_port, lan_path = build_url(lan_req, lan_scheme or "https")
    wifi_scheme, wifi_host, wifi_port, wifi_path = build_url(wifi_req, wifi_scheme or "https")
    lan_url = f"{lan_scheme}://{lan_host}:{lan_port}{lan_path}"
    wifi_url = f"{wifi_scheme}://{wifi_host}:{wifi_port}{wifi_path}"

    # Clean headers
    lan_headers = sanitize_headers(lan_req.headers)
    wifi_headers = sanitize_headers(wifi_req.headers)

    # Proxy parse
    proxies, pycurl_proxy = parse_proxy(args.proxy) if args.proxy else (None, None)

    print(Fore.CYAN + f"[i] OS: {args.os}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[i] LAN binding:  {'IP' if lan_is_ip else 'iface'} = {lan_binding}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[i] Wi‑Fi binding: {'IP' if wifi_is_ip else 'iface'} = {wifi_binding}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[i] Mode: {args.send_mode} | Iterations: {args.iterations} | Sleep(ms): {args.sleep_ms_between_iters} | Multi-connection: {args.multi_connection}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[i] TLS verify: {'ON' if args.verify_tls else 'OFF'} | Proxy: {args.proxy or 'None'}" + Style.RESET_ALL)
    print("")

    # Public IP checks
    print(Fore.MAGENTA + "[*] Checking LAN public IP via ifconfig.io ..." + Style.RESET_ALL)
    if lan_is_ip:
        code, iptxt = public_ip_via_local_ip(lan_binding, timeout=args.timeout, verify_tls=args.verify_tls, proxies=proxies)
    else:
        code, iptxt = public_ip_via_interface(lan_binding, timeout=args.timeout, verify_tls=args.verify_tls, pycurl_proxy=pycurl_proxy)
    print(f"    LAN public IP ({code}): {Fore.GREEN}{iptxt}{Style.RESET_ALL}")

    print(Fore.MAGENTA + "[*] Checking Wi‑Fi public IP via ifconfig.io ..." + Style.RESET_ALL)
    if wifi_is_ip:
        code, iptxt = public_ip_via_local_ip(wifi_binding, timeout=args.timeout, verify_tls=args.verify_tls, proxies=proxies)
    else:
        code, iptxt = public_ip_via_interface(wifi_binding, timeout=args.timeout, verify_tls=args.verify_tls, pycurl_proxy=pycurl_proxy)
    print(f"    Wi‑Fi public IP ({code}): {Fore.GREEN}{iptxt}{Style.RESET_ALL}")

    # Single send callables → RespInfo
    def send_lan_once() -> RespInfo:
        if lan_is_ip:
            return send_via_local_ip(lan_binding, lan_req.method, lan_url, lan_headers, lan_req.body,
                                     verify_tls=args.verify_tls, timeout=args.timeout, proxies=proxies)
        else:
            return send_via_interface(lan_binding, lan_req.method, lan_url, lan_headers, lan_req.body,
                                      verify_tls=args.verify_tls, timeout=args.timeout, pycurl_proxy=pycurl_proxy)

    def send_wifi_once() -> RespInfo:
        if wifi_is_ip:
            return send_via_local_ip(wifi_binding, wifi_req.method, wifi_url, wifi_headers, wifi_req.body,
                                     verify_tls=args.verify_tls, timeout=args.timeout, proxies=proxies)
        else:
            return send_via_interface(wifi_binding, wifi_req.method, wifi_url, wifi_headers, wifi_req.body,
                                      verify_tls=args.verify_tls, timeout=args.timeout, pycurl_proxy=pycurl_proxy)

    def persist(label: str, base_out: str, idx: int, info: RespInfo):
        out_i = numbered_name(base_out, idx)
        write_http_transcript(out_i, info)
        color = Fore.GREEN if 200 <= info.status < 400 else Fore.YELLOW if info.status else Fore.RED
        print(f"    {label:<4} -> {color}{info.status}{Style.RESET_ALL} (saved {out_i})")

    # ---- SEQUENTIAL MODE ----
    if args.send_mode == "sequential":
        for i in range(1, args.iterations + 1):
            print(Fore.BLUE + f"\n[iter {i}/{args.iterations}] Sending FIRST via LAN ..." + Style.RESET_ALL)
            info = send_lan_once()
            print(f"    {lan_req.method} {lan_url}")
            persist("LAN", args.lan_out, i, info)

            print(Fore.BLUE + f"[iter {i}/{args.iterations}] Sending SECOND via Wi‑Fi ..." + Style.RESET_ALL)
            info = send_wifi_once()
            print(f"    {wifi_req.method} {wifi_url}")
            persist("Wi‑Fi", args.wifi_out, i, info)

            if i < args.iterations and args.sleep_ms_between_iters > 0:
                time.sleep(args.sleep_ms_between_iters / 1000.0)

    # ---- CONCURRENT MODE ----
    else:
        if args.multi_connection and args.iterations > 1:
            # MULTI-CONNECTION: Fire ALL requests for ALL iterations at once
            total_threads = args.iterations * 2
            print(Fore.BLUE + f"\n[*] CONCURRENT MULTI-CONNECTION: arming {total_threads} threads to fire at the SAME instant." + Style.RESET_ALL)
            from threading import Barrier
            start_barrier = Barrier(total_threads)

            tasks = []  # (label, index, future)
            def run_with_barrier(sender_func):
                start_barrier.wait()
                return sender_func()

            with ThreadPoolExecutor(max_workers=total_threads) as ex:
                for i in range(1, args.iterations + 1):
                    fut_lan = ex.submit(run_with_barrier, send_lan_once)
                    fut_wifi = ex.submit(run_with_barrier, send_wifi_once)
                    tasks.append(("LAN", i, fut_lan))
                    tasks.append(("Wi‑Fi", i, fut_wifi))

                for label, idx, fut in tasks:
                    info = fut.result()
                    print(f"    {('LAN' if label=='LAN' else 'Wi‑Fi'):>4} {idx:03d}: {info.status}")
                    if label == "LAN":
                        persist("LAN", args.lan_out, idx, info)
                    else:
                        persist("Wi‑Fi", args.wifi_out, idx, info)

        else:
            # Per-iteration simultaneous PAIRS
            print(Fore.BLUE + "\n[*] CONCURRENT mode: firing both requests at the SAME instant per iteration." + Style.RESET_ALL)
            from threading import Barrier
            for i in range(1, args.iterations + 1):
                print(Fore.BLUE + f"\n[iter {i}/{args.iterations}] Arming pair ..." + Style.RESET_ALL)
                start_barrier = Barrier(2)

                def run_with_barrier(sender_func):
                    start_barrier.wait()
                    return sender_func()

                with ThreadPoolExecutor(max_workers=2) as ex:
                    fut_lan = ex.submit(run_with_barrier, send_lan_once)
                    fut_wifi = ex.submit(run_with_barrier, send_wifi_once)
                    info_lan = fut_lan.result()
                    info_wifi = fut_wifi.result()

                persist("LAN", args.lan_out, i, info_lan)
                persist("Wi‑Fi", args.wifi_out, i, info_wifi)

                if i < args.iterations and args.sleep_ms_between_iters > 0:
                    time.sleep(args.sleep_ms_between_iters / 1000.0)

    print(Fore.GREEN + "\nDone." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
