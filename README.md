# Reverse Proxy Temporal Analysis
Identify C2 reverse proxies by timing crafted HTTP responses. Technique originally discussed by Marcus Hutchins using a Python script in 2017: https://www.malwaretech.com/2017/11/investigating-command-and-control-infrastructure-emotet.html:

"The way this works is it sends two HTTP requests: one which should trigger a 404 error (page not found), followed by one which should trigger a 400 error (invalid request), recording the time taken for each. Both 404 and 400 pages should have similar response times; however, if we’re dealing with a reverse proxy the timing should differ noticeably. The first request will get forwarded to the origin, which will see the page doesn’t exist and return a 404. The second request is invalid so the proxy will not bother to forward it, instead a 400 error will be returned directly. Due to the fact the valid request is forwarded to the origin but the invalid one isn’t, the invalid request will get a response much faster than the valid one, if we’re dealing with a reverse proxy.

When we run the script against our suspected reverse proxy, we can see that the invalid request was more than 4 times faster than the valid one, so it’s pretty certain this is a proxy."

Since this tool runs in a browser, raw TCP socket access isn't available like in the Python code. It uses the fetch API with mode: 'no-cors' instead, which means:

- CORS won't block the requests, but you won't see response bodies or status codes
- The timing signal is still measurable via performance.now()
- Results are best-effort — HTTPS targets with HSTS, or servers that close connections immediately, may skew readings
