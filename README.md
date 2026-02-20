# Reverse Proxy Temporal Analysis
Identify C2 reverse proxies by timing crafted HTTP responses. Technique originally discussed by Marcus Hutchins using a Python script in 2017: https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html:

"The way this works is it sends two HTTP requests: one which should trigger a 404 error (page not found), followed by one which should trigger a 400 error (invalid request), recording the time taken for each. Both 404 and 400 pages should have similar response times; however, if we’re dealing with a reverse proxy the timing should differ noticeably. The first request will get forwarded to the origin, which will see the page doesn’t exist and return a 404. The second request is invalid so the proxy will not bother to forward it, instead a 400 error will be returned directly. Due to the fact the valid request is forwarded to the origin but the invalid one isn’t, the invalid request will get a response much faster than the valid one, if we’re dealing with a reverse proxy."

## Usage
1. Input a suspicious C2 IP or use one from the FEODO threat intel feed: https://feodotracker.abuse.ch/blocklist/#iocs
2. (Optional) Specify a port number e.g. 8080
3. Click "SCAN" and wait for the timing analysis results.
4. In the example screenshot below, we are using a known Emotet C2 IP address with the port 8080 and can see the valid request took twice as long as the invalid request.

![proxydetect](https://github.com/user-attachments/assets/e34f29bb-c330-4f84-bea7-cbce07b820e0)

Since this tool runs in a browser, raw TCP socket access isn't available like in the Python code. It uses the fetch API with mode: 'no-cors' instead, which means:

- CORS won't block the requests, but you won't see response bodies or status codes
- The timing signal is still measurable via performance.now()
- Results are best-effort — HTTPS targets with HSTS, or servers that close connections immediately, may skew readings
