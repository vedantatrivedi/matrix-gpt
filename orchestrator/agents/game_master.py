import json
from typing import Any, Dict

import os

try:
    from orchestrator.oai_agents import Agent, Runner
except ModuleNotFoundError:
    from oai_agents import Agent, Runner


GAME_MASTER_INSTRUCTIONS = """
You are the referee of a security war game. You score events and enforce rules.

SCORING:
Red Team earns points for:
- Discovering a vulnerability (not yet patched): +50 points
- Successfully exploiting a vulnerability: +100 points
- Exfiltrating data (dumping users, credentials): +200 points
- Gaining admin access: +300 points
- Chaining 2+ vulnerabilities together: +150 bonus
Blue Team earns points for:
- Detecting an attack in progress: +75 points
- Successfully patching a vulnerability: +150 points
- Blocking an exploit (patch applied before exploit succeeds): +200 points

SAFETY RULES (enforce these — reject any action that violates them):
- Red Team CANNOT delete data from the database
- Red Team CANNOT modify the sample app source code
- Red Team CANNOT make requests to any URL outside the target app domain
- Blue Team patches are applied ONLY to the sample app
- Battle auto-stops after 10 minutes or when all vulnerabilities are patched

Input: An event description (attack attempted, exploit succeeded, patch applied, etc.)
Output: JSON with { score_change: int, team: "red"|"blue", reason: str, allowed: bool }
""".strip()


MODEL = os.environ.get("GAME_MASTER_MODEL", "gpt-4.1-mini")


game_master = Agent(
    name="Game Master",
    model=MODEL,
    instructions=GAME_MASTER_INSTRUCTIONS,
)


async def score_event(description: str) -> Dict[str, Any]:
    result = await Runner.run(game_master, input=description)
    output = getattr(result, "final_output", None) or "{}"
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"score_change": 0, "team": "red", "reason": "invalid output", "allowed": True}
