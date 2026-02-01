import os

try:
    from orchestrator.oai_agents import Agent
except ModuleNotFoundError:
    from oai_agents import Agent

try:
    from orchestrator.agents.recon import deep_dive_endpoint, exploit_vulnerability, suggest_next_attacks
except ModuleNotFoundError:
    from agents.recon import deep_dive_endpoint, exploit_vulnerability, suggest_next_attacks


# Updated instructions for post-scan analysis
COMMANDER_INSTRUCTIONS_FLAT = """You are a Red Team security analyst. You have THREE TOOLS available:
1. exploit_vulnerability - MUST call this for each vulnerability found
2. suggest_next_attacks - MUST call this after exploitation
3. deep_dive_endpoint - Use for detailed endpoint analysis

CRITICAL: You MUST call these tools. Do NOT just write text. CALL THE TOOLS.

When pre-scan results show vulnerabilities:

STEP 1: IMMEDIATELY call exploit_vulnerability for EACH vulnerability
Example pre-scan shows SQL Injection at /api/products → IMMEDIATELY call:
  exploit_vulnerability(url="http://localhost:8001/api/products", vuln_type="sqli", attempts=5)

Example pre-scan shows XSS at / → IMMEDIATELY call:
  exploit_vulnerability(url="http://localhost:8001/", vuln_type="xss", attempts=3)

STEP 2: After all exploitations, call suggest_next_attacks with all confirmed vulns

STEP 3: Return JSON summary:
{
  "exploited": [
    {"url": "...", "type": "...", "attempts": N, "success_rate": "X/Y"}
  ],
  "suggested": [
    {"target": "...", "attack": "...", "reasoning": "..."}
  ]
}

CRITICAL REMINDER: CALL THE TOOLS. DO NOT JUST WRITE A REPORT. USE exploit_vulnerability() NOW.
If a tool returns an error, retry once with corrected arguments before moving on."""

COMMANDER_INSTRUCTIONS_HIERARCHICAL = "Run: recon→hunt→exploit. Brief bullets."


RUN_MODE = os.environ.get("RUN_MODE", "demo")
# OPTIMIZATION: Use cheapest model to save tokens
MODEL = os.environ.get("RED_TEAM_MODEL", "gpt-4o-mini")
RECON_MODEL = os.environ.get("RECON_MODEL", "gpt-4o-mini")
HUNTER_MODEL = os.environ.get("VULN_HUNTER_MODEL", "gpt-4o-mini")
EXPLOIT_MODEL = os.environ.get("EXPLOIT_MODEL", "gpt-4o-mini")

# CONFIGURATION: Set to 'true' for hierarchical mode (requires higher rate limits)
# Set to 'false' for flat mode (works with free tier 3 RPM)
USE_HIERARCHICAL = os.environ.get("USE_HIERARCHICAL_AGENTS", "false").lower() == "true"

if USE_HIERARCHICAL:
    # HIERARCHICAL MODE: Not actively used with new pre-scan approach
    # Kept for backward compatibility
    red_team_commander = Agent(
        name="Red Team Commander",
        model=MODEL,
        instructions=COMMANDER_INSTRUCTIONS_HIERARCHICAL,
        tools=[deep_dive_endpoint, exploit_vulnerability, suggest_next_attacks],
    )
else:
    # FLAT MODE: Single agent for post-scan analysis (free tier compatible)
    # Pre-scan runs first, then LLM analyzes and exploits findings
    red_team_commander = Agent(
        name="Red Team Commander",
        model=MODEL,
        instructions=COMMANDER_INSTRUCTIONS_FLAT,
        tools=[
            deep_dive_endpoint,  # Deeper analysis on specific endpoints
            exploit_vulnerability,  # Actually exploit vulnerabilities
            suggest_next_attacks,  # Suggest follow-up attacks
        ],
    )
