"""TEST-ONLY launcher: runs the real app but with canned provider responses (sandbox has no internet).
Never used in normal operation."""
import os, sys, httpx, uvicorn
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import providers
R = lambda s, b: httpx.Response(s, json=b, request=httpx.Request("GET", "https://x"))
ROUTES = {
 "rdap.org/domain": R(200, {"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}], "entities": [], "status": ["active"]}),
 "crt.sh": R(200, [{"name_value": "example.com\nwww.example.com"}]),
 "urlscan.io": R(200, {"results": []}),
 "internetdb": R(200, {"ports": [80, 3389], "vulns": [], "tags": []}),
 "rdap.org/ip": R(200, {"name": "TEST-NET", "entities": []}), "ipwho.is": R(200, {"success": False}),
}
def fake_get(url, headers=None, params=None, timeout=15):
    for k, v in ROUTES.items():
        if k in url: return v
    raise httpx.ConnectError("offline")
providers.http_get = fake_get
providers.dns_lookup = lambda t, x: [providers.F("DNS", "A records", "93.184.216.34")]
providers.reverse_dns = lambda t, x: [providers.F("DNS", "No reverse DNS record")]
from app.main import app
uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning")
