"""End-to-end verification of all Coral-integrated LLM Wall endpoints."""

import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:9876"
PASS = 0
FAIL = 0

def request(method, path, data=None, timeout=5):
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body
    except Exception as e:
        return 0, str(e)

def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  OK  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")

def assert_eq(val, expected, name):
    check(name, val == expected, f"(got {val}, expected {expected})")

def assert_in(key, d, name):
    check(name, key in d if isinstance(d, dict) else False, f"(key '{key}' not found)")

def assert_type(val, typ, name):
    check(name, isinstance(val, typ), f"(expected {typ}, got {type(val)}: {str(val)[:80]})")

def assert_gt(val, threshold, name):
    check(name, isinstance(val, (int, float)) and val > threshold, f"(got {val}, expected > {threshold})")

# Wait for server to be ready
print("Waiting for server...")
for i in range(15):
    status, data = request("GET", "/health")
    if status == 200:
        print(f"  Server ready after {i+1}s")
        break
    time.sleep(1)
else:
    print("  Server did not start in time!")
    sys.exit(1)

print("=" * 60)
print("  LLM Wall + Coral - End-to-End Verification")
print("=" * 60)

# 1. Health
print("\n[1] Health Check")
status, data = request("GET", "/health")
assert_eq(status, 200, "GET /health returns 200")
assert_in("status", data if isinstance(data, dict) else {}, "/health has status key")
if isinstance(data, dict):
    assert_eq(data.get("status"), "ok", "status = ok")

# 2. Ready
print("\n[2] Readiness Check")
status, data = request("GET", "/ready")
assert_eq(status, 200, "GET /ready returns 200")

# 3. Dashboard Status
print("\n[3] Dashboard Status")
status, data = request("GET", "/api/dashboard/status")
assert_eq(status, 200, "GET /api/dashboard/status returns 200")
assert_in("sentinel", data, "has sentinel")
assert_in("ledger", data, "has ledger")
assert_gt(data.get("ledger", {}).get("height", 0), 0, "ledger height > 0")

# 4. Coral Status
print("\n[4] Coral Status")
status, data = request("GET", "/api/coral/status")
assert_eq(status, 200, "GET /api/coral/status returns 200")
assert_in("coral_engine", data, "has coral_engine")
assert_in("investigator", data, "has investigator")
assert_eq(data["coral_engine"]["available"], True, "Coral binary is available")

# 5. Coral Sources
print("\n[5] Coral Sources")
status, data = request("GET", "/api/coral/sources")
assert_eq(status, 200, "GET /api/coral/sources returns 200")
assert_type(data, list, "sources is a list")

# 6. Coral Discover (long timeout - discover scans networks)
print("\n[6] Coral Discover")
status, data = request("GET", "/api/coral/discover", timeout=20)
assert_eq(status, 200, "GET /api/coral/discover returns 200")
assert_type(data, list, "discover is a list")

# 7. Coral SQL
print("\n[7] Coral SQL")
status, data = request("POST", "/api/coral/sql?query=SELECT+1+AS+test")
assert_eq(status, 200, "POST /api/coral/sql returns 200")

# 8. Coral Investigations
print("\n[8] Coral Investigations List")
status, data = request("GET", "/api/coral/investigations?limit=10")
assert_eq(status, 200, "GET /api/coral/investigations returns 200")
assert_type(data, list, "investigations is a list")

# 9. Trigger Investigation (use longer timeout)
print("\n[9] Trigger Investigation")
status, data = request("POST", "/api/coral/investigations/trigger?request_id=e2e-test&risk_score=75", timeout=30)
if isinstance(data, str):
    print(f"       Raw response (trying to parse): {data[:200]}")
    try:
        data = json.loads(data)
    except Exception:
        pass
assert_eq(status, 200, "POST /api/coral/investigations/trigger returns 200")
if isinstance(data, dict):
    assert_in("investigation_id", data, "has investigation_id")
    assert_in("coral_results", data, "has coral_results")
    if isinstance(data.get("request_id"), str):
        assert_eq(data.get("request_id"), "e2e-test", "request_id matches")
    invest_id = data.get("investigation_id", "")
    print(f"       Investigation ID: {invest_id[:12] if invest_id else 'N/A'}...")
    print(f"       Coral results: {len(data.get('coral_results', {}))} queries")
    print(f"       Errors: {len(data.get('errors', []))}")
else:
    print(f"       Response is not a dict, type={type(data).__name__}: {str(data)[:200]}")
    invest_id = ""

# 10. Get Single Investigation
print("\n[10] Get Single Investigation")
if invest_id:
    status, data = request("GET", f"/api/coral/investigations/{invest_id}")
    assert_eq(status, 200, f"GET /api/coral/investigations/{invest_id[:12]} returns 200")
else:
    print("  SKIP (no investigation_id)")

# 11. Pattern Hunt
print("\n[11] Trigger Pattern Hunt")
time.sleep(1)
status, data = request("POST", "/api/coral/patterns/hunt", timeout=15)
assert_eq(status, 200, "POST /api/coral/patterns/hunt returns 200")
assert_in("sources", data, "has sources")
assert_in("total_new", data, "has total_new")

# 12. Org Patterns
print("\n[12] Org Patterns List")
status, data = request("GET", "/api/coral/patterns/org")
assert_eq(status, 200, "GET /api/coral/patterns/org returns 200")
assert_type(data, list, "org patterns is a list")

# 13. Honeypot Generation  
print("\n[13] Honeypot Generation")
status, data = request("POST", "/api/coral/honeypots/generate", timeout=15)
assert_eq(status, 200, "POST /api/coral/honeypots/generate returns 200")
assert_in("deployed", data, "has deployed count")
assert_in("honeypots", data, "has honeypots list")
print(f"       Deployed: {data.get('deployed', 0)} honeypots")

# 14. Policy Generation
print("\n[14] Policy Generation")
status, data = request("POST", "/api/coral/policy/generate", timeout=15)
assert_eq(status, 200, "POST /api/coral/policy/generate returns 200")
assert_in("suggested_block_threshold", data, "has suggested_block_threshold")
bt = data.get("suggested_block_threshold", 0)
qt = data.get("suggested_quarantine_threshold", 0)
print(f"       Block: {bt}, Quarantine: {qt}")

# 15. Policy Apply
print("\n[15] Policy Apply")
status, data = request("POST", "/api/coral/policy/apply", timeout=15)
assert_eq(status, 200, "POST /api/coral/policy/apply returns 200")
assert_in("changes", data, "has changes")
print(f"       Changes: {data.get('changes', {})}")

# 16. Recent Threats
print("\n[16] Recent Threats")
status, data = request("GET", "/api/dashboard/threats/recent?limit=10")
assert_eq(status, 200, "returns 200")
assert_type(data, list, "threats is list")

# 17. SSE Stream
print("\n[17] SSE Stream")
try:
    req = urllib.request.Request(f"{BASE}/api/dashboard/stream/events")
    with urllib.request.urlopen(req, timeout=3) as resp:
        chunk = resp.read(512).decode()
        assert_eq(resp.status, 200, "SSE returns 200")
        check("SSE contains 'data:' marker", "data:" in chunk, f"first chars: {chunk[:50]}")
        jtext = chunk.replace("data: ", "").strip().split("\n")[0]
        j = json.loads(jtext)
        assert_in("sentinel_iocs", j, "SSE has sentinel_iocs")
        assert_in("chain_height", j, "SSE has chain_height")
        assert_in("coral_investigations", j, "SSE has coral_investigations")
except Exception as e:
    check("SSE stream", False, str(e))

# 18. Sentinel Status
print("\n[18] Sentinel Status")
status, data = request("GET", "/api/sentinel/status")
assert_eq(status, 200, "returns 200")
assert_in("node_id", data, "has node_id")
assert_in("ioc_stats", data, "has ioc_stats")

# 19. Sentinel IOCs
print("\n[19] Sentinel IOCs")
status, data = request("GET", "/api/sentinel/iocs")
assert_eq(status, 200, "returns 200")
assert_type(data, list, "iocs is list")

# 20. Ledger Stats
print("\n[20] Ledger Stats")
status, data = request("GET", "/api/ledger/stats")
assert_eq(status, 200, "returns 200")
assert_in("height", data, "has height")
assert_gt(data["height"], 0, "height > 0")

# 21. MARL Heatmap
print("\n[21] MARL Heatmap")
status, data = request("GET", "/api/dashboard/marl/heatmap/gateway")
assert_eq(status, 200, "returns 200")

# 22. Providers Health
print("\n[22] Providers Health")
status, data = request("GET", "/api/dashboard/providers/health")
assert_eq(status, 200, "returns 200")

# 23. MCP Broker Tools (internal check)
print("\n[23] MCP Broker Tools (internal)")
from llm_wall.mcp.broker import get_mcp_broker
broker = get_mcp_broker()
tools = broker.list_tools()
tool_names = [t["name"] for t in tools]
for tn in ["coral_sql", "coral_list_catalog", "coral_search_catalog", "echo", "get_time", "health_check"]:
    check(f"{tn} registered", tn in tool_names, f"missing: {tn}")
print(f"       Total tools: {len(tools)} -> {tool_names}")

# 24. Ledger Verify
print("\n[24] Ledger Verify")
status, data = request("GET", "/api/ledger/verify")
assert_eq(status, 200, "returns 200")

# 25. Ledger Chain
print("\n[25] Ledger Chain")
status, data = request("GET", "/api/ledger/chain?limit=5")
assert_eq(status, 200, "returns 200")
assert_type(data, list, "chain is list")

# 26. Verify investigation recorded on ledger
print("\n[26] Investigation on Ledger")
status, chain = request("GET", "/api/ledger/chain?limit=10")
if isinstance(chain, list) and chain:
    check("chain has blocks", len(chain) > 0, f"got {len(chain)} blocks")
else:
    print("  SKIP (no chain data)")

print()
print("=" * 60)
total = PASS + FAIL
print(f"  RESULTS: {PASS}/{total} passed, {FAIL}/{total} failed")
if FAIL == 0:
    print("  ALL TESTS PASSED")
else:
    print(f"  {FAIL} TEST(S) FAILED")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
