import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.tools import block_ip, get_recent_logs, rate_limit_ip
except ModuleNotFoundError:
    from agents.tools import block_ip, get_recent_logs, rate_limit_ip


SOC_INSTRUCTIONS = "Check recent logs for attack indicators. Summarize confirmed attack paths."

PATCH_DEV_INSTRUCTIONS = "TODO: implement faster patching workflow later."

COMMANDER_INSTRUCTIONS_FLAT = """You are the Blue Team Commander.
1) Call get_recent_logs() first.
2) Identify likely vulnerabilities from log patterns.
3) When you see active exploitation, call block_ip(ip=...) or rate_limit_ip(ip=..., limit=..., window=...).
4) Explicitly state if an exploit is blocked preemptively.
Return brief bullet steps + what you detected.
If a tool returns an error, retry once before moving on."""

COMMANDER_INSTRUCTIONS_HIERARCHICAL = "Run SOC→Patch. Brief bullets."


RUN_MODE = os.environ.get("RUN_MODE", "demo")
# OPTIMIZATION: Use cheapest model to save tokens
MODEL = os.environ.get("BLUE_TEAM_MODEL", "gpt-3.5-turbo")
SOC_MODEL = os.environ.get("SOC_MODEL", "gpt-3.5-turbo")
PATCH_MODEL = os.environ.get("PATCH_MODEL", "gpt-3.5-turbo")

# CONFIGURATION: Set to 'true' for hierarchical mode (requires higher rate limits)
# Set to 'false' for flat mode (works with free tier 3 RPM)
USE_HIERARCHICAL = os.environ.get("USE_HIERARCHICAL_AGENTS", "false").lower() == "true"

if USE_HIERARCHICAL:
    # HIERARCHICAL MODE: Commander with sub-agents (requires paid tier)
    # Makes 3+ API calls: Commander → SOC → Patch
    soc_monitor = Agent(
        name="SOC Monitor",
        model=SOC_MODEL,
        instructions=SOC_INSTRUCTIONS,
        tools=[get_recent_logs],
    )

    patch_developer = Agent(
        name="Patch Developer",
        model=PATCH_MODEL,
        instructions=PATCH_DEV_INSTRUCTIONS,
        tools=[get_source_file],
    )

    blue_team_commander = Agent(
        name="Blue Team Commander",
        model=MODEL,
        instructions=COMMANDER_INSTRUCTIONS_HIERARCHICAL,
        tools=[
            soc_monitor.as_tool(tool_name="soc_monitor", tool_description="Analyze logs"),
        ],
    )
else:
    # FLAT MODE: Single agent with all tools (free tier compatible)
    # Makes only 1 API call with direct tool access
    blue_team_commander = Agent(
        name="Blue Team Commander",
        model=MODEL,
        instructions=COMMANDER_INSTRUCTIONS_FLAT,
        tools=[
            # Direct access to logs only (no patching)
            get_recent_logs,
            block_ip,
            rate_limit_ip,
        ],
    )
