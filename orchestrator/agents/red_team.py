import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.smart_tools import (
        http_batch_get_smart,
        test_sqli_smart,
        test_xss_smart,
        scan_for_vulns_comprehensive,
    )
except ModuleNotFoundError:
    from agents.smart_tools import (
        http_batch_get_smart,
        test_sqli_smart,
        test_xss_smart,
        scan_for_vulns_comprehensive,
    )

try:
    from orchestrator.agents.tools import (
        query_recon_data,
        get_recon_summary,
    )
except ModuleNotFoundError:
    from agents.tools import (
        query_recon_data,
        get_recon_summary,
    )


RECON_INSTRUCTIONS = "Scan with http_batch_get_smart. List vulns found."

VULN_HUNTER_INSTRUCTIONS = "Use test_sqli_smart and test_xss_smart. Brief."

EXPLOIT_DEV_INSTRUCTIONS = "Chain exploits. Brief."

COMMANDER_INSTRUCTIONS = "Run: recon→hunt→exploit. Brief bullets."


RUN_MODE = os.environ.get("RUN_MODE", "demo")
# OPTIMIZATION: Use cheapest model to save tokens
MODEL = os.environ.get("RED_TEAM_MODEL", "gpt-4o-mini")
RECON_MODEL = os.environ.get("RECON_MODEL", "gpt-4o-mini")
HUNTER_MODEL = os.environ.get("VULN_HUNTER_MODEL", "gpt-4o-mini")
EXPLOIT_MODEL = os.environ.get("EXPLOIT_MODEL", "gpt-4o-mini")


recon_agent = Agent(
    name="Recon Agent",
    model=RECON_MODEL,
    instructions=RECON_INSTRUCTIONS,
    tools=[http_batch_get_smart, get_recon_summary],
)

vulnerability_hunter = Agent(
    name="Vulnerability Hunter",
    model=HUNTER_MODEL,
    instructions=VULN_HUNTER_INSTRUCTIONS,
    tools=[test_sqli_smart, test_xss_smart, scan_for_vulns_comprehensive, query_recon_data],
)

exploit_developer = Agent(
    name="Exploit Developer",
    model=EXPLOIT_MODEL,
    instructions=EXPLOIT_DEV_INSTRUCTIONS,
    tools=[http_batch_get_smart, get_recon_summary],
)

red_team_commander = Agent(
    name="Red Team Commander",
    model=MODEL,
    instructions=COMMANDER_INSTRUCTIONS,
    tools=[
        recon_agent.as_tool(tool_name="recon_agent", tool_description="Run recon agent"),
        vulnerability_hunter.as_tool(
            tool_name="vulnerability_hunter", tool_description="Run vulnerability hunter"
        ),
        exploit_developer.as_tool(
            tool_name="exploit_developer", tool_description="Run exploit developer"
        ),
    ],
)
