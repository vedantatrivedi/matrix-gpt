import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.tools import http_get, http_post
except ModuleNotFoundError:
    from agents.tools import http_get, http_post


RECON_INSTRUCTIONS = """
You are a recon tester. Map endpoints, inputs, and errors. Start at / then probe /api, /admin, /auth.
Be concise and output bullet points only.
""".strip()

VULN_HUNTER_INSTRUCTIONS = """
You validate likely vulns using real HTTP requests: SQLi, XSS, auth bypass, IDOR, info disclosure.
For each confirmed vuln, report type, endpoint, payload, and proof. Be concise.
""".strip()

EXPLOIT_DEV_INSTRUCTIONS = """
Chain confirmed vulns to maximize impact. Execute each step via HTTP requests.
Return a short numbered list with key request/response proof. Be concise.
""".strip()

COMMANDER_INSTRUCTIONS = """
You orchestrate recon → vuln hunt → exploit chain. Summarize strategy briefly and dispatch agents.
Be concise and use bullet points.
""".strip()


RUN_MODE = os.environ.get("RUN_MODE", "demo")
MODEL = os.environ.get("RED_TEAM_MODEL", "gpt-5.2-pro" if RUN_MODE == "prod" else "gpt-5-mini")
RECON_MODEL = os.environ.get("RECON_MODEL", "gpt-5-mini")
HUNTER_MODEL = os.environ.get("VULN_HUNTER_MODEL", "gpt-5-mini")
EXPLOIT_MODEL = os.environ.get("EXPLOIT_MODEL", MODEL)


recon_agent = Agent(
    name="Recon Agent",
    model=RECON_MODEL,
    instructions=RECON_INSTRUCTIONS,
    tools=[http_get, http_post],
)

vulnerability_hunter = Agent(
    name="Vulnerability Hunter",
    model=HUNTER_MODEL,
    instructions=VULN_HUNTER_INSTRUCTIONS,
    tools=[http_get, http_post],
)

exploit_developer = Agent(
    name="Exploit Developer",
    model=EXPLOIT_MODEL,
    instructions=EXPLOIT_DEV_INSTRUCTIONS,
    tools=[http_get, http_post],
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
