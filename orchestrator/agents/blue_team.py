import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.tools import apply_patch, get_recent_logs, get_source_file
except ModuleNotFoundError:
    from agents.tools import apply_patch, get_recent_logs, get_source_file


SOC_INSTRUCTIONS = "Scan logs for attacks. Report type and evidence. Brief."

PATCH_DEV_INSTRUCTIONS = "Create unified diff patch. Brief summary."

COMMANDER_INSTRUCTIONS = "Run SOC→Patch. Brief bullets."


RUN_MODE = os.environ.get("RUN_MODE", "demo")
# OPTIMIZATION: Use cheapest model to save tokens
MODEL = os.environ.get("BLUE_TEAM_MODEL", "gpt-4o-mini")
SOC_MODEL = os.environ.get("SOC_MODEL", "gpt-4o-mini")
PATCH_MODEL = os.environ.get("PATCH_MODEL", "gpt-4o-mini")


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
    instructions=COMMANDER_INSTRUCTIONS,
    tools=[
        soc_monitor.as_tool(tool_name="soc_monitor", tool_description="Analyze logs"),
        patch_developer.as_tool(
            tool_name="patch_developer", tool_description="Generate patch"
        ),
        apply_patch,
    ],
)
