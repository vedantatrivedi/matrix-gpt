import asyncio
import json
import sys
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))

# Configure agent logging to file
LOGS_DIR = PARENT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

agent_logger = logging.getLogger("agents")
agent_logger.setLevel(logging.INFO)
if not agent_logger.handlers:
    handler = logging.FileHandler(LOGS_DIR / "agents.log")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s"))
    agent_logger.addHandler(handler)

from orchestrator.oai_agents import Runner
from orchestrator.agents.blue_team import blue_team_commander
from orchestrator.agents.game_master import score_event
from orchestrator.agents.red_team import red_team_commander
from orchestrator.agents.tools import set_battle_context
from orchestrator.db import (
    create_battle,
    end_battle,
    get_battle,
    insert_event,
    list_vulnerabilities,
    update_scores,
    update_vuln_status,
)

from openai.types.responses import ResponseTextDeltaEvent


class BattleManager:
    def __init__(self, event_sink):
        self._event_sink = event_sink
        self._battle_id: Optional[str] = None
        self._stop_event = asyncio.Event()
        self._red_task: Optional[asyncio.Task] = None
        self._blue_task: Optional[asyncio.Task] = None
        self._target_url: Optional[str] = None
        self._start_time: Optional[datetime] = None
        self._throttle_seconds = float(os.environ.get("AGENT_THROTTLE_SECONDS", "2.0"))
        self._rate_limit_backoff = float(os.environ.get("AGENT_RATE_LIMIT_BACKOFF", "3.0"))

    @property
    def battle_id(self) -> Optional[str]:
        return self._battle_id

    async def start_battle(self, target_url: str) -> str:
        print(f"[DEBUG] start_battle called. Current _battle_id: {self._battle_id}")
        # Check if existing battle is actually still running
        if self._battle_id:
            existing_battle = get_battle(self._battle_id)
            if existing_battle and existing_battle.get('status') == 'running':
                print(f"[DEBUG] Returning existing running battle_id: {self._battle_id}")
                return self._battle_id
            else:
                print(f"[DEBUG] Existing battle stopped, resetting")
                self._battle_id = None
        self._target_url = target_url
        self._battle_id = create_battle(target_url)
        print(f"[DEBUG] Created new battle_id: {self._battle_id}")
        self._start_time = datetime.utcnow()
        self._stop_event.clear()

        # Set battle context for recon tools
        set_battle_context(self._battle_id)

        await self._event_sink(
            {
                "type": "battle_start",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"battle_id": self._battle_id, "target_url": target_url},
            }
        )
        if os.environ.get("MOCK_MODE", "false").lower() == "true":
            self._red_task = asyncio.create_task(self._mock_loop())
            self._blue_task = None
        else:
            # FREE TIER FIX: If using flat agents, run teams sequentially
            use_hierarchical = os.environ.get("USE_HIERARCHICAL_AGENTS", "false").lower() == "true"
            if use_hierarchical:
                # Paid tier: Start both teams concurrently
                self._red_task = asyncio.create_task(self._red_loop())
                self._blue_task = asyncio.create_task(self._blue_loop())
            else:
                # Free tier: Run teams one after another (Red completes, then Blue starts)
                self._red_task = asyncio.create_task(self._sequential_battle())
                self._blue_task = None  # Handled inside sequential_battle
        return self._battle_id

    async def stop_battle(self, status: str = "stopped") -> None:
        if not self._battle_id:
            return
        self._stop_event.set()
        tasks = [t for t in (self._red_task, self._blue_task) if t]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        end_battle(self._battle_id, status)
        self._red_task = None
        self._blue_task = None
        await self._event_sink(
            {
                "type": "battle_end",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"battle_id": self._battle_id, "status": status},
            }
        )
        self._battle_id = None

    async def _sequential_battle(self) -> None:
        """FREE TIER FIX: Run teams one after another to stay under 3 RPM.

        Red team runs first, completes, then Blue team runs.
        Adds 20s delay between teams to ensure rate limit window resets.
        """
        # Step 1: Run Red Team
        await self._event_sink({
            "type": "battle_event",
            "team": "system",
            "agent": "Battle Manager",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"description": "Starting Red Team (sequential mode)", "severity": "low"},
        })
        await self._red_loop()

        # Step 2: Wait for rate limit window to reset (65s to ensure full 60s window passes)
        if not self._should_stop():
            await self._event_sink({
                "type": "battle_event",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Red Team complete. Waiting 65s for rate limit window to reset...", "severity": "low"},
            })
            await asyncio.sleep(65)

        # Step 3: Run Blue Team
        if not self._should_stop():
            await self._event_sink({
                "type": "battle_event",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Starting Blue Team (sequential mode)", "severity": "low"},
            })
            await self._blue_loop()

        # Step 4: Battle complete
        await self.stop_battle("completed")

    async def _red_loop(self) -> None:
        """EMERGENCY FIX: Run once to prevent token explosion."""
        if self._should_stop():
            return

        # PRE-SCAN: Run recon WITHOUT LLM to save tokens
        try:
            from orchestrator.agents.recon import run_prescan, format_findings_for_llm

            agent_logger.info("=== PRE-SCAN STARTED ===")
            agent_logger.info(f"Target: {self._target_url}")

            # UI Event: Pre-scan started
            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Pre-Scan",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": f"Starting pre-scan of {self._target_url} (20 endpoints)", "severity": "low"}
            })

            # Step 1: Port discovery
            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Pre-Scan",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Discovering open ports...", "severity": "low"}
            })

            prescan_result = await asyncio.to_thread(run_prescan, self._target_url)

            # Step 2: Report port discovery
            agent_logger.info(f"=== PRE-SCAN COMPLETE ===")
            agent_logger.info(f"Ports discovered: {prescan_result['ports_discovered']}")
            agent_logger.info(f"Endpoints tested: {prescan_result['total_tested']}")
            agent_logger.info(f"CRITICAL: {prescan_result['critical_count']}, HIGH: {prescan_result['high_count']}")

            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Pre-Scan",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "description": f"Port scan complete: {prescan_result['ports_discovered']} ports open, testing {prescan_result['total_tested']} endpoints",
                    "severity": "low"
                }
            })

            # Step 3: Report vulnerabilities
            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Pre-Scan",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "description": f"Scan complete: {prescan_result['critical_count']} CRITICAL, {prescan_result['high_count']} HIGH severity issues found",
                    "severity": "high" if prescan_result['critical_count'] > 0 else ("medium" if prescan_result['high_count'] > 0 else "low")
                }
            })

            # Announce CRITICAL vulnerabilities
            findings = prescan_result['findings']
            if findings['critical']:
                for vuln in findings['critical']:
                    vuln_type = vuln.get('type', 'Unknown')
                    await self._event_sink({
                        "type": "attack_detected",
                        "team": "red",
                        "agent": "Pre-Scan",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "description": f"🔴 CRITICAL: {vuln_type} at {vuln['url']}",
                            "severity": "critical"
                        }
                    })
                    agent_logger.info(f"CRITICAL: {vuln_type} - {vuln['url']}")

            # Announce HIGH vulnerabilities
            if findings['high']:
                for vuln in findings['high']:
                    vuln_type = vuln.get('type', 'Unknown')
                    await self._event_sink({
                        "type": "attack_detected",
                        "team": "red",
                        "agent": "Pre-Scan",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "description": f"🟠 HIGH: {vuln_type} at {vuln['url']}",
                            "severity": "high"
                        }
                    })
                    agent_logger.info(f"HIGH: {vuln_type} - {vuln['url']}")

            # Format findings for LLM
            findings_text = format_findings_for_llm(prescan_result)

            agent_logger.info(f"=== FINDINGS FOR LLM ===")
            agent_logger.info(findings_text)

            # UI Event: Sending to LLM for analysis
            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Red Team Commander",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Analyzing vulnerabilities with AI...", "severity": "low"}
            })

            # Now call LLM with pre-scanned findings
            await self._run_agent_loop(
                team="red",
                agent_name="Red Team Commander",
                agent=red_team_commander,
                input_text=findings_text,
            )
        except ImportError:
            # Fallback to old method if recon module not available
            await self._run_agent_loop(
                team="red",
                agent_name="Red Team Commander",
                agent=red_team_commander,
                input_text=f"Scan {self._target_url}. Test common endpoints: /, /api, /admin, /login, /api/users, /api/products. Use tools.",
            )
        except asyncio.CancelledError:
            return
        except Exception as exc:
            await self._event_sink(
                {
                    "type": "battle_event",
                    "team": "system",
                    "agent": "Battle Manager",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"description": f"Red loop error: {exc}", "severity": "low"},
                }
            )

        # DON'T stop battle here in sequential mode - let _sequential_battle handle it
        # Only stop in hierarchical mode (when both teams run concurrently)
        use_hierarchical = os.environ.get("USE_HIERARCHICAL_AGENTS", "false").lower() == "true"
        if use_hierarchical:
            await self.stop_battle("completed")

        # ORIGINAL LOOP (commented out to save tokens):
        # while not self._stop_event.is_set():
        #     if self._should_stop():
        #         await self.stop_battle("completed")
        #         return
        #     try:
        #         await self._run_agent_loop(...)
        #     except asyncio.CancelledError:
        #         return
        #     except Exception as exc:
        #         await self._event_sink({...})
        #     await asyncio.sleep(self._throttle_seconds)

    async def _blue_loop(self) -> None:
        """EMERGENCY FIX: Run once to prevent token explosion."""
        if self._should_stop():
            return

        try:
            await self._run_agent_loop(
                team="blue",
                agent_name="Blue Team Commander",
                agent=blue_team_commander,
                input_text="Check logs. Patch.",
            )
        except asyncio.CancelledError:
            return
        except Exception as exc:
            await self._event_sink(
                {
                    "type": "battle_event",
                    "team": "system",
                    "agent": "Battle Manager",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"description": f"Blue loop error: {exc}", "severity": "low"},
                }
            )

        # STOP HERE - Don't loop
        # Original loop commented out to save tokens

    def _should_stop(self) -> bool:
        if not self._battle_id or not self._start_time:
            return True
        if datetime.utcnow() - self._start_time > timedelta(minutes=15):
            return True
        vulns = list_vulnerabilities(self._battle_id)
        if vulns and all(v["status"] == "patched" for v in vulns):
            return True
        return False

    async def _mock_loop(self) -> None:
        async def emit(
            event_type: str,
            team: str,
            agent: str,
            payload: Dict[str, Any],
            description: str,
        ) -> None:
            insert_event(
                self._battle_id,
                event_type=event_type,
                team=team,
                agent_name=agent,
                description=description,
                details=payload,
            )
            await self._event_sink(
                {
                    "type": event_type,
                    "team": team if team in ("red", "blue") else "system",
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": payload,
                }
            )

        timeline = [
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Recon Agent",
                "payload": {"text": "Starting recon sweep. Map HTML + /api endpoints, focus on inputs."},
                "desc": "Recon Agent planning initial sweep.",
            },
            {
                "type": "tool_call",
                "team": "red",
                "agent": "Recon Agent",
                "payload": {"tool": "http_get", "args": {"url": "/"}},
                "desc": "Recon Agent requests /",
            },
            {
                "type": "tool_result",
                "team": "red",
                "agent": "Recon Agent",
                "payload": {"output": "200 OK • HTML with product listings + reviews section"},
                "desc": "Recon Agent receives / response",
            },
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Recon Agent",
                "payload": {"text": "Discovered /api/products?search. Looks injectable. Queueing SQLi probe."},
                "desc": "Recon Agent suspects SQLi surface.",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Recon Agent",
                "payload": {"description": "Recon sweep: 12 endpoints mapped. /api/products?search looks injectable."},
                "desc": "Recon sweep: 12 endpoints mapped. /api/products?search looks injectable.",
            },
            {
                "type": "agent_thinking",
                "team": "blue",
                "agent": "SOC Monitor",
                "payload": {"text": "Watching logs. Saw unusual SQL keywords in query params. Raising alert."},
                "desc": "SOC Monitor flags SQLi patterns.",
            },
            {
                "type": "tool_call",
                "team": "blue",
                "agent": "SOC Monitor",
                "payload": {"tool": "get_recent_logs", "args": {"since_timestamp": "T-5s"}},
                "desc": "SOC Monitor queries recent logs",
            },
            {
                "type": "tool_result",
                "team": "blue",
                "agent": "SOC Monitor",
                "payload": {"output": "Log sample: GET /api/products?search=' OR '1'='1"},
                "desc": "SOC Monitor receives log batch",
            },
            {
                "type": "attack_detected",
                "team": "blue",
                "agent": "SOC Monitor",
                "payload": {"description": "SQL keywords detected in query params. Confidence: HIGH."},
                "desc": "SQL keywords detected in query params. Confidence: HIGH.",
            },
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Vulnerability Hunter",
                "payload": {"text": "Testing SQLi on /api/products search parameter."},
                "desc": "Vulnerability Hunter tests SQLi.",
            },
            {
                "type": "tool_call",
                "team": "red",
                "agent": "Vulnerability Hunter",
                "payload": {"tool": "http_get", "args": {"url": "/api/products?search=' OR '1'='1"}},
                "desc": "SQLi probe sent",
            },
            {
                "type": "tool_result",
                "team": "red",
                "agent": "Vulnerability Hunter",
                "payload": {"output": "200 OK • 10 products returned"},
                "desc": "SQLi probe succeeded",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Vulnerability Hunter",
                "payload": {"description": "SQL injection confirmed. Payload returns all products."},
                "desc": "SQL injection confirmed. Payload returns all products.",
            },
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "payload": {"description": "Red found SQL Injection (+50)."},
                "desc": "Red found SQL Injection (+50).",
            },
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"text": "Pivoting: UNION SELECT to dump users. Target admin credentials."},
                "desc": "Exploit Developer plans credential dump.",
            },
            {
                "type": "tool_call",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {
                    "tool": "http_get",
                    "args": {"url": "/api/products?search=' UNION SELECT username,password,email FROM users--"},
                },
                "desc": "UNION SELECT credential dump sent",
            },
            {
                "type": "tool_result",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"output": "200 OK • users: admin / admin123 / admin@matrix.local"},
                "desc": "Credential dump response",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"description": "Exploit chain: SQLi → dump credentials. Admin user exfiltrated."},
                "desc": "Exploit chain: SQLi → dump credentials. Admin user exfiltrated.",
            },
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "payload": {"description": "Red exfiltrated credentials (+200)."},
                "desc": "Red exfiltrated credentials (+200).",
            },
            {
                "type": "agent_thinking",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"text": "Generating parameterized query patch for /api/products."},
                "desc": "Patch Developer prepares SQLi fix.",
            },
            {
                "type": "tool_call",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"tool": "apply_patch", "args": {"file": "app.py", "diff": "..." }},
                "desc": "Patch tool invoked",
            },
            {
                "type": "tool_result",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"output": "Patch applied: parameterized query"},
                "desc": "Patch tool response",
            },
            {
                "type": "patch_applied",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"description": "Patched SQLi with parameterized queries."},
                "desc": "Patched SQLi with parameterized queries.",
            },
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "payload": {"description": "Blue patched SQL Injection (+150)."},
                "desc": "Blue patched SQL Injection (+150).",
            },
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"text": "Switching to SSRF. Target internal /api/admin/users via image-proxy."},
                "desc": "Exploit Developer shifts to SSRF.",
            },
            {
                "type": "tool_call",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"tool": "http_post", "args": {"url": "/api/image-proxy", "json_body": {"url": "http://localhost:8001/api/admin/users"}}},
                "desc": "SSRF probe sent",
            },
            {
                "type": "tool_result",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"output": "200 OK • admin users list returned"},
                "desc": "SSRF probe succeeded",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"description": "SSRF used to hit /api/admin/users via image proxy."},
                "desc": "SSRF used to hit /api/admin/users via image proxy.",
            },
            {
                "type": "attack_detected",
                "team": "blue",
                "agent": "SOC Monitor",
                "payload": {"description": "SSRF attempt detected targeting internal admin endpoint."},
                "desc": "SSRF attempt detected targeting internal admin endpoint.",
            },
            {
                "type": "agent_thinking",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"text": "Adding URL allowlist + private IP block for image-proxy."},
                "desc": "Patch Developer prepares SSRF fix.",
            },
            {
                "type": "patch_applied",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"description": "SSRF allowlist added; private IP ranges blocked."},
                "desc": "SSRF allowlist added; private IP ranges blocked.",
            },
            {
                "type": "agent_thinking",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"text": "Delivering stored XSS via avatar upload, then CSRF order creation."},
                "desc": "Exploit Developer plans XSS+CSRF chain.",
            },
            {
                "type": "tool_call",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"tool": "http_post", "args": {"url": "/api/users/avatar", "files": {"avatar": "payload.html"}}},
                "desc": "Malicious upload sent",
            },
            {
                "type": "tool_result",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"output": "200 OK • /uploads/payload.html"},
                "desc": "Upload succeeded",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"description": "Upload payload: stored XSS delivered via avatar upload."},
                "desc": "Upload payload: stored XSS delivered via avatar upload.",
            },
            {
                "type": "battle_event",
                "team": "red",
                "agent": "Exploit Developer",
                "payload": {"description": "XSS + CSRF: forged order created as admin."},
                "desc": "XSS + CSRF: forged order created as admin.",
            },
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "payload": {"description": "Red chained 2+ vulns (+150)."},
                "desc": "Red chained 2+ vulns (+150).",
            },
            {
                "type": "agent_thinking",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"text": "Locking uploads to images + enforcing CSRF tokens."},
                "desc": "Patch Developer prepares upload/CSRF fix.",
            },
            {
                "type": "patch_applied",
                "team": "blue",
                "agent": "Patch Developer",
                "payload": {"description": "File upload restricted; HTML blocked. CSRF token required for /api/orders."},
                "desc": "File upload restricted; HTML blocked. CSRF token required for /api/orders.",
            },
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "payload": {"description": "Blue blocked exploit with preemptive patch (+200)."},
                "desc": "Blue blocked exploit with preemptive patch (+200).",
            },
            {
                "type": "battle_event",
                "team": "system",
                "agent": "Battle Manager",
                "payload": {"description": "All primary attack paths sealed. Battle ending."},
                "desc": "All primary attack paths sealed. Battle ending.",
            },
        ]

        score_map = {
            "Red found SQL Injection (+50).": ("red", 50),
            "Red exfiltrated credentials (+200).": ("red", 200),
            "Blue patched SQL Injection (+150).": ("blue", 150),
            "Red chained 2+ vulns (+150).": ("red", 150),
            "Blue blocked exploit with preemptive patch (+200).": ("blue", 200),
        }

        vuln_updates = [
            ("SQL Injection", "found"),
            ("SQL Injection", "exploited"),
            ("SQL Injection", "patched"),
            ("SSRF", "exploited"),
            ("SSRF", "patched"),
            ("Unrestricted File Upload", "exploited"),
            ("CSRF", "exploited"),
            ("Unrestricted File Upload", "patched"),
            ("CSRF", "patched"),
        ]
        vuln_index = 0

        for item in timeline:
            if self._stop_event.is_set():
                return
            event_type = item["type"]
            team = item["team"]
            agent = item["agent"]
            payload = item["payload"]
            desc = item["desc"]

            if event_type == "score_update" and desc in score_map:
                side, delta = score_map[desc]
                scores = update_scores(
                    self._battle_id,
                    red_delta=delta if side == "red" else 0,
                    blue_delta=delta if side == "blue" else 0,
                )
                await emit(
                    "score_update",
                    "system",
                    "Game Master",
                    {
                        "red_score": scores["red_score"],
                        "blue_score": scores["blue_score"],
                        "reason": desc,
                    },
                    desc,
                )
            else:
                await emit(event_type, team, agent, payload, desc)

            if vuln_index < len(vuln_updates) and event_type in ("battle_event", "patch_applied"):
                name, status = vuln_updates[vuln_index]
                update_vuln_status(self._battle_id, name, status)
                vuln_index += 1

            await asyncio.sleep(self._throttle_seconds)

        await self.stop_battle("completed")

    async def _run_agent_loop(self, team: str, agent_name: str, agent, input_text: str) -> None:
        result = await self._run_streamed_with_retry(agent, input_text)
        async for event in result.stream_events():
            await self._handle_stream_event(team, agent_name, event)
        final_output = getattr(result, "final_output", None)

        # Log final output to agents.log
        agent_logger.info(f"=== AGENT FINAL OUTPUT ===")
        agent_logger.info(f"Agent: {agent_name}")
        agent_logger.info(f"Team: {team}")
        agent_logger.info(f"Output length: {len(str(final_output)) if final_output else 0} chars")
        agent_logger.info(f"Output: {str(final_output) if final_output else 'None'}")  # Full output

        if final_output:
            insert_event(
                self._battle_id,
                event_type="battle_event",
                team=team,
                agent_name=agent_name,
                description=str(final_output),
                details={"output": str(final_output)},
            )
            await self._event_sink(
                {
                    "type": "battle_event",
                    "team": team,
                    "agent": agent_name,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"description": str(final_output), "severity": "medium"},
                }
            )
            await self._score_and_broadcast(str(final_output))
            self._update_vuln_status_from_text(str(final_output))

    async def _run_streamed_with_retry(self, agent, input_text: str):
        # Log request to model
        agent_logger.info(f"=== API REQUEST ===")
        agent_logger.info(f"Agent: {agent.name}")
        agent_logger.info(f"Model: {agent.model}")
        agent_logger.info(f"Input length: {len(input_text)} chars")
        agent_logger.info(f"Input preview: {input_text[:300]}")
        agent_logger.info(f"Tools: {[t.__name__ if hasattr(t, '__name__') else str(t) for t in getattr(agent, 'tools', [])]}")

        try:
            result = Runner.run_streamed(agent, input=input_text)
            agent_logger.info(f"API call started, streaming response...")
            return result

        except Exception as exc:
            message = str(exc)
            agent_logger.error(f"=== API ERROR ===")
            agent_logger.error(f"Agent: {agent.name}")
            agent_logger.error(f"Error: {message[:500]}")

            if "Rate limit" in message or "rate limit" in message or "429" in message:
                agent_logger.info(f"Rate limit hit, waiting {self._rate_limit_backoff}s and retrying...")
                await asyncio.sleep(self._rate_limit_backoff)
                agent_logger.info(f"=== API RETRY ===")
                agent_logger.info(f"Agent: {agent.name}")
                return Runner.run_streamed(agent, input=input_text)
            raise

    async def _handle_stream_event(self, team: str, agent_name: str, event) -> None:
        if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
            payload = {
                "type": "agent_thinking",
                "team": team,
                "agent": agent_name,
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"text": event.data.delta[:200]},
            }
            await self._event_sink(payload)

    async def _score_and_broadcast(self, description: str) -> None:
        """EMERGENCY FIX: Scoring disabled to save tokens (100+ API calls)."""
        # TODO: Re-enable with rule-based scoring (no LLM calls)
        # from optimizations_quick_wins import score_event_rules
        # score = score_event_rules(description)
        return

        # ORIGINAL CODE (commented out):
        # if not self._battle_id:
        #     return
        # score = await score_event(description)
        # if not score.get("allowed", True):
        #     return
        # team = score.get("team")
        # delta = int(score.get("score_change", 0))
        # if team == "red":
        #     scores = update_scores(self._battle_id, red_delta=delta)
        # else:
        #     scores = update_scores(self._battle_id, blue_delta=delta)
        # await self._event_sink({...})

    def _update_vuln_status_from_text(self, text: str) -> None:
        if not self._battle_id:
            return
        mapping = {
            "SQL Injection": "SQL Injection",
            "Stored XSS": "Stored XSS",
            "JWT": "Broken Authentication (JWT bypass)",
            "IDOR": "IDOR",
            "File Upload": "Unrestricted File Upload",
            "SSRF": "SSRF",
            "Hardcoded": "Hardcoded Credentials",
            "Rate": "No Rate Limit",
            "Information Disclosure": "Information Disclosure",
            "CSRF": "CSRF",
        }
        for key, name in mapping.items():
            if key.lower() in text.lower():
                update_vuln_status(self._battle_id, name, "found")
