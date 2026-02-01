import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.tools import apply_patch, get_recent_logs, get_source_file
except ModuleNotFoundError:
    from agents.tools import apply_patch, get_recent_logs, get_source_file


SOC_INSTRUCTIONS = """
You are SOC. Scan recent logs for SQLi, XSS, brute force, IDOR, SSRF, auth bypass.
Return attack type, confidence, and evidence. Be concise.
""".strip()

PATCH_DEV_INSTRUCTIONS = """
You are a security engineer. Produce a minimal unified diff patch to fix the given vuln.
Return diff + one-sentence summary. Be concise.
""".strip()

COMMANDER_INSTRUCTIONS = """
You are Blue Team Commander. Trigger SOC, then Patch Developer on confirmed attacks.
Summarize actions briefly in bullets. Be concise.
""".strip()


RUN_MODE = os.environ.get("RUN_MODE", "demo")
MODEL = os.environ.get("BLUE_TEAM_MODEL", "gpt-5.2-pro" if RUN_MODE == "prod" else "gpt-5-mini")
SOC_MODEL = os.environ.get("SOC_MODEL", "gpt-5-mini")
PATCH_MODEL = os.environ.get("PATCH_MODEL", "gpt-5.2-codex" if RUN_MODE == "prod" else "gpt-5-mini")


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
