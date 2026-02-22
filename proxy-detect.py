#!/usr/bin/python
#
# Updated the original script published by Marcus Hutchins
# Tests for HTTP reverse proxy even if HTTP requests return 404 response
# By crafting two HTTP GET requests, one valid and one invalid, and comparing response times.
#
# The valid request triggers a 404 error (page not found), the invalid request triggers a 400 error.
# Both 404 and 400 pages should have similar response times on a direct server; however,
# if we're dealing with a reverse proxy the timing will differ noticeably.
# The valid request is forwarded to the origin server, but the invalid one is rejected at the edge,
# so the invalid request gets a response much faster than the valid one.
#
# From MalwareTech article on C2 Botnet hunting:
# https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html
#

import socket
import datetime
import argparse
import sys


PROXY_THRESHOLD   = 1.8   # ratio of valid/invalid time to confidently flag a proxy
UNCERTAIN_THRESHOLD = 1.3  # ratio below which result is inconclusive
SAMPLES = 3               # number of requests per type (median is used)
TIMEOUT = 10              # socket timeout in seconds


def time_request(ip, port, request):
    """Open a raw TCP socket, send an HTTP request, and return elapsed time in ms."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.settimeout(TIMEOUT)
    try:
        s.connect((ip, port))
        time_start = datetime.datetime.now()
        s.send(request.encode('utf-8'))
        s.recv(4096)
        time_end = datetime.datetime.now()
    finally:
        s.close()
    return (time_end - time_start).total_seconds() * 1000


def sample(ip, port, request, n):
    """Run n requests and return the median response time."""
    times = []
    for i in range(n):
        try:
            t = time_request(ip, port, request)
            times.append(t)
        except socket.timeout:
            print(f"  [!] Request timed out (sample {i+1}/{n})")
        except Exception as e:
            print(f"  [!] Error on sample {i+1}/{n}: {e}")
    if not times:
        return None
    times.sort()
    return times[len(times) // 2]


def verdict(valid_ms, invalid_ms):
    """Return a verdict string and ratio based on timing."""
    if valid_ms is None or invalid_ms is None:
        return None, "UNKNOWN — one or more requests failed entirely"
    ratio = valid_ms / invalid_ms if invalid_ms > 0 else float('inf')
    if ratio >= PROXY_THRESHOLD:
        label = "REVERSE PROXY DETECTED"
    elif ratio >= UNCERTAIN_THRESHOLD:
        label = "INCONCLUSIVE (possible proxy)"
    else:
        label = "DIRECT SERVER (no proxy detected)"
    return ratio, label


def main():
    parser = argparse.ArgumentParser(
        description="Detect reverse proxies via HTTP timing analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python proxy-detect.py --host 192.168.1.1:80
  python proxy-detect.py --host 10.0.0.1:8080 --samples 5 --timeout 5
        """
    )
    parser.add_argument('--host',    help="Target host in ip:port format (e.g. 192.168.1.1:80)", required=True)
    parser.add_argument('--samples', help=f"Number of requests per type, median used (default: {SAMPLES})", type=int, default=SAMPLES)
    parser.add_argument('--timeout', help=f"Socket timeout in seconds (default: {TIMEOUT})", type=int, default=TIMEOUT)
    args = parser.parse_args()

    # Parse host
    try:
        parts = args.host.rsplit(':', 1)
        ip   = parts[0]
        port = int(parts[1])
    except (IndexError, ValueError):
        print("[!] Invalid --host format. Use ip:port, e.g. 192.168.1.1:80")
        sys.exit(1)

    host_header = args.host
    valid_request   = f'GET /aaaaaaaa HTTP/1.1\r\nHost: {host_header}\r\n\r\n'
    invalid_request = f'GET /aaaaaaaa HTTP/1.1\r\nMost: {host_header}\r\n\r\n'

    print(f"\n[*] Target       : {ip}:{port}")
    print(f"[*] Samples      : {args.samples}")
    print(f"[*] Timeout      : {args.timeout}s")
    print(f"[*] Threshold    : proxy if ratio ≥ {PROXY_THRESHOLD}x, uncertain if ≥ {UNCERTAIN_THRESHOLD}x\n")

    print(f"[>] Sending {args.samples} valid requests   (expect 404 — should be forwarded by proxy)...")
    valid_ms = sample(ip, port, valid_request, args.samples)
    if valid_ms is not None:
        print(f"    Median: {valid_ms:.2f} ms")

    print(f"\n[>] Sending {args.samples} invalid requests (expect 400 — should be rejected at edge)...")
    invalid_ms = sample(ip, port, invalid_request, args.samples)
    if invalid_ms is not None:
        print(f"    Median: {invalid_ms:.2f} ms")

    ratio, label = verdict(valid_ms, invalid_ms)

    print("\n" + "─" * 50)
    if ratio is not None:
        print(f"  Valid   : {valid_ms:.2f} ms")
        print(f"  Invalid : {invalid_ms:.2f} ms")
        print(f"  Ratio   : {ratio:.2f}x  (valid / invalid)")
    print(f"\n  Result  : {label}")
    print("─" * 50 + "\n")


if __name__ == '__main__':
    main()
