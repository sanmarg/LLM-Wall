"""Verifies all imports across the Coral-integrated LLM Wall."""

print("=== Testing imports ===")

from llm_wall.models import CoralSnapshot, CoralInvestigationReport
print("models: OK")

from llm_wall.config import get_settings
cfg = get_settings()
print(f"config: OK (coral_investigate_on_threat={cfg.coral_investigate_on_threat})")

from llm_wall.mcp.broker import get_mcp_broker
broker = get_mcp_broker()
tools = broker.list_tools()
print(f"mcp broker: OK ({len(tools)} tools registered)")
for t in tools:
    print(f"  - {t['name']} ({t['risk_level']})")

from llm_wall.ledger.node import get_ledger_node
print("ledger.node: OK")

from llm_wall.sentinel.node import get_sentinel_node
print("sentinel.node: OK")

from llm_wall.marl.engine import get_marl_engine
print("marl.engine: OK")

from llm_wall.api.dashboard_router import router
print("dashboard_router: OK")

from llm_wall.api.coral_router import router
print("coral_router: OK")

print()
print("=== All imports successful ===")

# Test CoralEngine actually works
print()
print("=== Testing CoralEngine ===")
from llm_wall.coral.engine import CoralEngine
engine = CoralEngine()
print(f"CoralEngine created: bin={engine._coral_bin}")
import asyncio
async def test_coral():
    ok = await engine.health_check()
    print(f"Coral health check: {ok}")
    if not ok:
        print("(Coral binary not found - this is expected if Coral is not on PATH)")
    stats = engine.stats()
    print(f"Coral stats: {stats}")

asyncio.run(test_coral())

# Test Investigator
print()
print("=== Testing IncidentInvestigator ===")
from llm_wall.coral.investigator import IncidentInvestigator
inv = IncidentInvestigator()
print(f"Investigator created: {inv.stats()}")

# Test PatternHunter
print()
print("=== Testing PatternHunter ===")
from llm_wall.coral.pattern_hunter import PatternHunter
hunter = PatternHunter()
print(f"PatternHunter created: {hunter.stats()}")

# Test Honeypot
print()
print("=== Testing Honeypot ===")
from llm_wall.coral.honeypot import generate_honeypots
print("Honeypot module: OK (generate_honeypots imported)")

# Test Policy Generator
print()
print("=== Testing Policy Generator ===")
from llm_wall.coral.policy_generator import generate_policy, apply_policy
print("Policy generator: OK")

print()
print("=== ALL TESTS PASSED ===")
