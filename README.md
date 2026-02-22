# Proxy-Detect: Reverse Proxy Identification via HTTP Temporal Analysis

Identify potential C2 reverse proxies by analyzing the response times to crafted HTTP requests. HTTP timing analysis tools available as both a **Python CLI script** and a **browser-based HTML app**.

The technique was originally described by Marcus Hutchins (MalwareTech) in his article on [investigating C2 botnet infrastructure](https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html):
"The way this works is it sends two HTTP requests: one which should trigger a 404 error (page not found), followed by one which should trigger a 400 error (invalid request), recording the time taken for each. Both 404 and 400 pages should have similar response times; however, if we’re dealing with a reverse proxy the timing should differ noticeably. The first request will get forwarded to the origin, which will see the page doesn’t exist and return a 404. The second request is invalid so the proxy will not bother to forward it, instead a 400 error will be returned directly. Due to the fact the valid request is forwarded to the origin but the invalid one isn’t, the invalid request will get a response much faster than the valid one, if we’re dealing with a reverse proxy."

This technique may not be the most accurate with current threat hunting methodologies and you may need to scan several times. It is not meant to be used solely to identify C2 servers running reverse proxies, but rather as a complimentary enrichment tool in your threat hunting process.

---

## How It Works

Two HTTP requests are crafted and sent to the target:

| Request | Header | Expected response | Proxy behaviour |
|---|---|---|---|
| **Valid** | `Host: <target>` | `404 Not Found` | Forwarded to origin server |
| **Invalid** | `Most: <target>` (typo) | `400 Bad Request` | Rejected at the edge |

On a **direct server**, both requests are handled locally and respond in similar times.

On a **reverse proxy**, the valid request is forwarded all the way to the origin server before a response is returned, while the invalid request is rejected immediately at the proxy edge, making it respond noticeably faster.

If the valid request takes significantly longer than the invalid one, a reverse proxy is likely present.

```
valid   request → [proxy] → origin server → response   (slower)
invalid request → [proxy] → 400 returned immediately   (faster)
```

---

## Python Script

### Requirements

- Python 3.6+
- No external dependencies, only the standard library

### Usage

```bash
python proxy-detect.py --host <IP>:<Port>
```

### Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--host` | ✅ | — | Target in `ip:port` format |
| `--samples` | ❌ | `3` | Number of requests per type (median is used) |
| `--timeout` | ❌ | `10` | Socket timeout in seconds |

### Examples

```bash
# Basic scan
python proxy-detect.py --host 192.168.1.1:80

# Custom sample count and timeout
python proxy-detect.py --host 10.0.0.1:8080 --samples 5 --timeout 5
```

### Example Output

```
[*] Target       : 192.168.1.1:80
[*] Samples      : 3
[*] Timeout      : 10s
[*] Threshold    : proxy if ratio ≥ 1.8x, uncertain if ≥ 1.3x

[>] Sending 3 valid requests   (expect 404 — should be forwarded by proxy)...
    Median: 312.45 ms

[>] Sending 3 invalid requests (expect 400 — should be rejected at edge)...
    Median: 48.12 ms

──────────────────────────────────────────────────
  Valid   : 312.45 ms
  Invalid : 48.12 ms
  Ratio   : 6.49x  (valid / invalid)

  Result  : REVERSE PROXY DETECTED
──────────────────────────────────────────────────
```

### Verdict Thresholds

| Ratio (valid ÷ invalid) | Verdict |
|---|---|
| ≥ 1.8× | **Reverse proxy detected** |
| 1.3× – 1.8× | **Inconclusive** (possible proxy) |
| < 1.3× | **Direct server** (no proxy detected) |

---

## HTML App

A self-contained single-file local web app that runs entirely in your browser. No server or installation required.

### Usage

1. Input a suspicious C2 IP address or use one from the FEODO threat intel feed: https://feodotracker.abuse.ch/blocklist/#iocs
2. (Optional) Specify a port number in the port input box (e.g. 8080). 
You can type the port with or without the colon :8080 or 8080 both work. 
If you already include a port in the host field (e.g. 192.168.1.1:8080), the separate port box takes precedence and overrides it.
4. Click "SCAN" and wait for the timing analysis results.
5. In the example screenshot below, we are using a known Emotet C2 IP address with the port 8080 and can see the valid request took twice as long as the invalid request. 

![proxydetect](https://github.com/user-attachments/assets/e34f29bb-c330-4f84-bea7-cbce07b820e0)

### Features

- Live analysis log with timestamped entries
- Median timing over multiple samples per request type
- Visual verdict with colour-coded result and ratio bar
- Automatic warning when a domain name is entered instead of a raw IP

### ⚠ Browser App Limitations

The HTML app uses the browser `fetch` API rather than raw TCP sockets, which introduces some important caveats:

- **Domain names** (e.g. `example.com`) will show a warning that browsers cannot send malformed `Host` headers, so both request types may be forwarded by any proxy, masking the timing difference. Results are unreliable for domain targets.
- **Raw IP:port targets** (e.g. `192.168.1.1:8080`) give the most accurate results, as the timing difference is more likely to be detectable.
- **HTTPS targets** may behave unexpectedly due to TLS and HSTS.
- **CORS** does not block `no-cors` fetch requests, but response bodies are not accessible, only timing is measured.

For the most reliable results, use the **Python script**, which uses raw TCP sockets and can craft truly malformed HTTP requests exactly as the technique requires.

---

## Credits

- Original technique and script by **Marcus Hutchins** ([@MalwareTechBlog](https://twitter.com/MalwareTechBlog))
- Source article: [Investigating Command & Control Infrastructure (Emotet)](https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html)

---

## Disclaimer

This tool is intended for legitimate security research, infrastructure analysis, and educational purposes only. Only scan hosts you own or have explicit permission to test.


