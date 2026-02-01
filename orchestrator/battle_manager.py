import asyncio
import json
import sys
import os
import httpx
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
from orchestrator.agents.tools import _get_recent_logs_impl, set_battle_context
from orchestrator.db import (
    create_battle,
    end_battle,
    get_battle,
    insert_event,
    list_vulnerabilities,
    update_scores,
    update_vuln_status,
)

from agents.items import ItemHelpers
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
        self._round_state: Optional[Dict[str, Any]] = None
        self._tool_call_index: Dict[str, str] = {}
        self._match_active = False
        self._blue_found_vulns: set[str] = set()
        self._round_results: list[Dict[str, Any]] = []

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
        self._blue_found_vulns = set()
        self._round_results = []
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
            # Always run round-based battle (red + blue monitor in parallel)
            self._red_task = asyncio.create_task(self._round_battle())
            self._blue_task = None
        return self._battle_id

    async def stop_battle(self, status: str = "stopped") -> None:
        if not self._battle_id:
            return
        self._stop_event.set()
        current = asyncio.current_task()
        tasks = [t for t in (self._red_task, self._blue_task) if t and t is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        end_battle(self._battle_id, status)
        self._red_task = None
        self._blue_task = None
        summary = self._build_battle_summary() if status == "completed" else None
        await self._event_sink(
            {
                "type": "battle_end",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"battle_id": self._battle_id, "status": status, "summary": summary},
            }
        )
        await self._event_sink(
            {
                "type": "battle_event",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Battle ended", "severity": "low"},
            }
        )
        self._battle_id = None

    async def _round_battle(self) -> None:
        """Run a 3-round match with continuous Blue monitoring."""
        rounds = 3
        round_delay = float(os.environ.get("ROUND_DELAY_SECONDS", "5"))
        round_prep_delay = float(os.environ.get("ROUND_PREP_DELAY_SECONDS", "7"))
        round_timeout = float(os.environ.get("ROUND_TIMEOUT_SECONDS", "90"))
        self._match_active = True
        self._round_results = []
        for round_index in range(1, rounds + 1):
            if self._stop_event.is_set() or (self._start_time and datetime.utcnow() - self._start_time > timedelta(minutes=15)):
                break

            self._round_state = {
                "active": True,
                "round": round_index,
                "winner": None,
                "exploit_called": False,
                "exploit_succeeded": False,
                "tool_failure": False,
                "blocked_by_blue": False,
                "last_vuln": None,
                "ip_incidents": {},
                "ip_last_seen": {},
                "ip_warned": set(),
            }
            self._tool_call_index.clear()

            await self._event_sink({
                "type": "round_start",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"round": round_index, "description": f"Round {round_index} started"},
            })
            await self._event_sink({
                "type": "battle_event",
                "team": "blue",
                "agent": "SOC Monitor",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Blue Team monitoring logs...", "severity": "low"},
            })
            await self._event_sink({
                "type": "battle_event",
                "team": "red",
                "agent": "Red Team Commander",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": "Red Team scanning for vulnerabilities...", "severity": "low"},
            })
            await self._event_sink({
                "type": "battle_event",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"description": f"Round {round_index} prep: teams analyzing for {int(round_prep_delay)}s...", "severity": "low"},
            })
            await asyncio.sleep(round_prep_delay)

            red_task = asyncio.create_task(self._red_loop())
            initial_delay = 10.0 if round_index == 1 else 0.0
            blue_monitor = asyncio.create_task(self._blue_monitor_loop(initial_delay))

            try:
                start_ts = datetime.utcnow().timestamp()
                while not red_task.done():
                    if self._round_state.get("winner"):
                        red_task.cancel()
                        break
                    if datetime.utcnow().timestamp() - start_ts >= round_timeout:
                        await self._finalize_round("draw", "Round timeout", round_index)
                        red_task.cancel()
                        break
                    await asyncio.sleep(0.2)
                await asyncio.gather(red_task, return_exceptions=True)
            except asyncio.CancelledError:
                pass

            if self._round_state.get("winner") is None:
                if self._round_state.get("exploit_succeeded"):
                    await self._finalize_round("red", "Exploit succeeded", round_index)
                elif self._round_state.get("tool_failure"):
                    await self._finalize_round("draw", "Tool failure (unintentional)", round_index)
                else:
                    await self._finalize_round("draw", "No decisive outcome", round_index)

            if not blue_monitor.done():
                blue_monitor.cancel()
                await asyncio.gather(blue_monitor, return_exceptions=True)

            self._round_state["active"] = False
            if round_index < rounds and not self._should_stop():
                await asyncio.sleep(round_delay)

        if not self._should_stop():
            await self.stop_battle("completed")
        self._match_active = False

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
            if self._blue_found_vulns:
                filtered = {
                    "critical": [v for v in findings.get("critical", []) if v.get("type") not in self._blue_found_vulns],
                    "high": [v for v in findings.get("high", []) if v.get("type") not in self._blue_found_vulns],
                }
                prescan_result = dict(prescan_result)
                prescan_result["findings"] = filtered
                prescan_result["critical_count"] = len(filtered["critical"])
                prescan_result["high_count"] = len(filtered["high"])
                findings = filtered
                if prescan_result["critical_count"] == 0 and prescan_result["high_count"] == 0:
                    await self._finalize_round("blue", "No new vulnerabilities left for Red Team", self._round_state["round"])
                    return
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

            # Force a baseline exploit attempt so Blue has traffic to detect
            if findings.get("critical"):
                first = findings["critical"][0]
                url = first.get("url")
                if url:
                    try:
                        payload = "' OR '1'='1"
                        resp = httpx.get(
                            url,
                            params={"q": payload, "id": payload, "search": payload},
                            timeout=3.0,
                        )
                        if self._round_state and self._round_state.get("active"):
                            self._round_state["exploit_called"] = True
                            if resp.status_code == 200:
                                self._round_state["exploit_succeeded"] = True
                    except Exception:
                        if self._round_state and self._round_state.get("active"):
                            self._round_state["tool_failure"] = True

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

    # TODO: Implement faster patching workflow later (intentionally removed from demo flow).

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
        fallback_output = self._extract_last_message_text(result)

        # Log final output to agents.log
        agent_logger.info(f"=== AGENT FINAL OUTPUT ===")
        agent_logger.info(f"Agent: {agent_name}")
        agent_logger.info(f"Team: {team}")
        agent_logger.info(f"Output length: {len(str(final_output)) if final_output else 0} chars")
        agent_logger.info(f"Output: {str(final_output) if final_output else 'None'}")  # Full output

        output_text = str(final_output) if final_output else fallback_output
        if output_text and self._battle_id:
            insert_event(
                self._battle_id,
                event_type="battle_event",
                team=team,
                agent_name=agent_name,
                description=output_text,
                details={"output": output_text},
            )
            await self._event_sink(
                {
                    "type": "battle_event",
                    "team": team,
                    "agent": agent_name,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"description": output_text, "severity": "medium"},
                }
            )
            await self._score_and_broadcast(output_text)
            self._update_vuln_status_from_text(output_text)

        self._emit_model_usage(agent.model, result)

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
            # Skip raw deltas to avoid letter-by-letter UI noise.
            return

        if event.type == "run_item_stream_event":
            if event.name == "message_output_created":
                text = ItemHelpers.extract_last_text(event.item.raw_item)
                if text and self._battle_id:
                    insert_event(
                        self._battle_id,
                        event_type="agent_message",
                        team=team,
                        agent_name=agent_name,
                        description=text,
                        details={"text": text},
                    )
                    await self._event_sink(
                        {
                            "type": "agent_message",
                            "team": team,
                            "agent": agent_name,
                            "timestamp": datetime.utcnow().isoformat(),
                            "data": {"text": text},
                        }
                    )
            elif event.name == "tool_called":
                raw = event.item.raw_item
                tool_name = getattr(raw, "name", None)
                args_raw = getattr(raw, "arguments", None)
                call_id = getattr(raw, "call_id", None)
                args = args_raw
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw)
                    except json.JSONDecodeError:
                        args = {"raw": args_raw}
                if call_id and tool_name:
                    self._tool_call_index[call_id] = tool_name
                if self._round_state and self._round_state.get("active") and tool_name == "exploit_vulnerability":
                    self._round_state["exploit_called"] = True

                if self._battle_id:
                    insert_event(
                        self._battle_id,
                        event_type="tool_call",
                        team=team,
                        agent_name=agent_name,
                        description=f"{tool_name} call",
                        details={"tool": tool_name, "args": args, "call_id": call_id},
                    )
                    await self._event_sink(
                        {
                            "type": "tool_call",
                            "team": team,
                            "agent": agent_name,
                            "timestamp": datetime.utcnow().isoformat(),
                            "data": {"tool": tool_name, "args": args, "call_id": call_id},
                        }
                    )
            elif event.name == "tool_output":
                raw = event.item.raw_item
                call_id = raw.get("call_id") if isinstance(raw, dict) else getattr(raw, "call_id", None)
                output = event.item.output
                tool_name = self._tool_call_index.get(call_id)
                if self._round_state and self._round_state.get("active"):
                    if self._output_failed(output):
                        self._round_state["tool_failure"] = True
                        await self._finalize_round("draw", "Tool failure (unintentional)", self._round_state["round"])
                    if tool_name == "exploit_vulnerability":
                        self._round_state["last_vuln"] = output
                        if self._exploit_succeeded(output):
                            self._round_state["exploit_succeeded"] = True
                            await self._finalize_round("red", "Exploit succeeded", self._round_state["round"])
                if self._battle_id:
                    insert_event(
                        self._battle_id,
                        event_type="tool_result",
                        team=team,
                        agent_name=agent_name,
                        description="tool result",
                        details={"output": output, "call_id": call_id},
                    )
                    await self._event_sink(
                        {
                            "type": "tool_result",
                            "team": team,
                            "agent": agent_name,
                            "timestamp": datetime.utcnow().isoformat(),
                            "data": {"output": output, "call_id": call_id},
                        }
                    )

    async def _score_and_broadcast(self, description: str) -> None:
        """Rule-based scoring (no LLM calls)."""
        if self._match_active:
            return
        if self._round_state and self._round_state.get("active"):
            return
        if not self._battle_id:
            return
        score = self._score_event_rules(description)
        if not score.get("allowed", True):
            return
        delta = int(score.get("score_change", 0) or 0)
        if delta == 0:
            return
        team = score.get("team")
        if team == "red":
            scores = update_scores(self._battle_id, red_delta=delta)
        elif team == "blue":
            scores = update_scores(self._battle_id, blue_delta=delta)
        else:
            return
        await self._event_sink(
            {
                "type": "score_update",
                "team": "system",
                "agent": "Game Master",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "red_score": scores["red_score"],
                    "blue_score": scores["blue_score"],
                    "reason": score.get("reason", "score update"),
                },
            }
        )

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

    def _score_event_rules(self, description: str) -> Dict[str, Any]:
        """Lightweight scoring heuristics to avoid extra model calls."""
        if not description:
            return {"score_change": 0, "team": "red", "reason": "empty", "allowed": True}
        d = description.lower()
        score = 0
        team = None
        reasons = []

        # Red team scoring
        if any(k in d for k in ["critical", "high"]) and any(k in d for k in ["vulnerability", "sql injection", "xss", "sqli"]):
            score += 50
            team = "red"
            reasons.append("vulnerability discovered")
        if any(k in d for k in ["exploited", "exploit", "success_rate"]) and any(k in d for k in ["sqli", "xss", "cmdi", "path traversal", "sql injection"]):
            score += 100
            team = "red"
            reasons.append("exploit succeeded")
        if any(k in d for k in ["exfiltrat", "dump", "dumping users", "credentials"]):
            score += 200
            team = "red"
            reasons.append("data exfiltration")
        if any(k in d for k in ["admin access", "gained admin", "admin credentials"]):
            score += 300
            team = "red"
            reasons.append("admin access")
        if any(k in d for k in ["chain", "chaining", "multi-step"]):
            score += 150
            team = "red"
            reasons.append("exploit chain")

        # Blue team scoring
        if any(k in d for k in ["patch applied", "patched", "patch", "reloaded"]):
            score += 150
            team = "blue"
            reasons.append("patch applied")
        if any(k in d for k in ["detected attack", "attack detected", "intrusion detected"]):
            score += 75
            team = "blue"
            reasons.append("attack detected")
        if any(k in d for k in ["blocked", "prevented"]) and "exploit" in d:
            score += 200
            team = "blue"
            reasons.append("exploit blocked")

        if score == 0 or team is None:
            return {"score_change": 0, "team": "red", "reason": "no score", "allowed": True}
        return {"score_change": score, "team": team, "reason": "; ".join(reasons), "allowed": True}

    def _extract_last_message_text(self, result) -> Optional[str]:
        items = getattr(result, "new_items", []) or []
        for item in reversed(items):
            if getattr(item, "type", None) == "message_output_item":
                text = ItemHelpers.extract_last_text(item.raw_item)
                if text:
                    return text
        return None

    def _emit_model_usage(self, model: str, result) -> None:
        if not self._battle_id:
            return
        usage = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        for resp in getattr(result, "raw_responses", []) or []:
            resp_usage = getattr(resp, "usage", None)
            if not resp_usage:
                continue
            usage["requests"] += resp_usage.requests or 0
            usage["input_tokens"] += resp_usage.input_tokens or 0
            usage["output_tokens"] += resp_usage.output_tokens or 0
            usage["total_tokens"] += resp_usage.total_tokens or 0

        if usage["requests"] == 0:
            return

        insert_event(
            self._battle_id,
            event_type="model_usage",
            team="system",
            agent_name="Model Telemetry",
            description=f"{model} usage",
            details={"model": model, **usage},
        )
        asyncio.create_task(
            self._event_sink(
                {
                    "type": "model_usage",
                    "team": "system",
                    "agent": "Model Telemetry",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"model": model, **usage},
                }
            )
        )

    async def _blue_monitor_loop(self, initial_delay: float = 0.0) -> None:
        """Continuously monitor logs and block before exploit is called."""
        last_since = None
        poll_interval = float(os.environ.get("BLUE_MONITOR_INTERVAL_SECONDS", "0.5"))
        await asyncio.sleep(initial_delay)
        while self._round_state and self._round_state.get("active") and not self._should_stop():
            if self._round_state.get("winner"):
                return
            if self._round_state.get("exploit_called"):
                await asyncio.sleep(poll_interval)
                continue
            try:
                result = await asyncio.to_thread(_get_recent_logs_impl, last_since)
                logs = result.get("logs", [])
                if logs:
                    last_since = logs[-1].get("timestamp") or last_since
                detection = self._detect_attack_pattern(logs)
                if detection:
                    vuln = detection.get("vuln", "Unknown")
                    ip = detection.get("ip", "unknown")
                    self._blue_found_vulns.add(vuln)
                    incidents = self._round_state["ip_incidents"]
                    last_seen = self._round_state["ip_last_seen"]
                    warned = self._round_state["ip_warned"]
                    now_ts = datetime.utcnow().timestamp()
                    if ip in last_seen and now_ts - last_seen[ip] < 10.0:
                        last_seen[ip] = now_ts
                        continue
                    last_seen[ip] = now_ts
                    incidents[ip] = incidents.get(ip, 0) + 1
                    if incidents[ip] == 1:
                        if ip in warned:
                            incidents[ip] = 2
                        else:
                            warned.add(ip)
                        if self._battle_id:
                            insert_event(
                                self._battle_id,
                                event_type="battle_event",
                                team="blue",
                                agent_name="SOC Monitor",
                                description=f"Initial exploit wave observed from {ip}. Rate Limiting user",
                                details={"ip": ip, "wave": incidents[ip]},
                            )
                        await self._event_sink(
                            {
                                "type": "battle_event",
                                "team": "blue",
                                "agent": "SOC Monitor",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {
                                    "description": f"Initial exploit wave observed from {ip}. Rate Limiting user",
                                    "severity": "low",
                                },
                            }
                        )
                        continue
                    elif incidents[ip] == 2:
                        if self._battle_id:
                            insert_event(
                                self._battle_id,
                                event_type="tool_call",
                                team="blue",
                                agent_name="SOC Monitor",
                                description="rate_limit_ip call",
                                details={"tool": "rate_limit_ip", "args": {"ip": ip, "limit": 5, "window": 10}},
                            )
                        await self._event_sink(
                            {
                                "type": "tool_call",
                                "team": "blue",
                                "agent": "SOC Monitor",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {"tool": "rate_limit_ip", "args": {"ip": ip, "limit": 5, "window": 10}},
                            }
                        )
                        await self._defense_action(ip, "limit", limit=5, window=10)
                        if self._battle_id:
                            insert_event(
                                self._battle_id,
                                event_type="tool_result",
                                team="blue",
                                agent_name="SOC Monitor",
                                description="rate_limit_ip result",
                                details={"output": {"status": "limit", "ip": ip, "limit": 5, "window": 10}},
                            )
                        await self._event_sink(
                            {
                                "type": "tool_result",
                                "team": "blue",
                                "agent": "SOC Monitor",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {"output": {"status": "limit", "ip": ip, "limit": 5, "window": 10}},
                            }
                        )
                        await self._event_sink(
                            {
                                "type": "battle_event",
                                "team": "blue",
                                "agent": "SOC Monitor",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {
                                    "description": f"Blue deployed rate limiting (5 req / 10s) for {ip}. Defense change applied.",
                                    "severity": "medium",
                                },
                            }
                        )
                    else:
                        if self._battle_id:
                            insert_event(
                                self._battle_id,
                                event_type="battle_event",
                                team="blue",
                                agent_name="SOC Monitor",
                                description=f"Repeated exploit waves from {ip}. Suggest: block or isolate source.",
                                details={"ip": ip, "wave": incidents[ip]},
                            )
                        await self._event_sink(
                            {
                                "type": "battle_event",
                                "team": "blue",
                                "agent": "SOC Monitor",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {
                                    "description": f"Repeated exploit waves from {ip}. Suggest: block or isolate source.",
                                    "severity": "medium",
                                },
                            }
                        )
                    await self._event_sink(
                        {
                            "type": "battle_event",
                            "team": "blue",
                            "agent": "SOC Monitor",
                            "timestamp": datetime.utcnow().isoformat(),
                            "data": {
                                "description": f"Defense change successful — Blue wins after rate limiting {ip} for {vuln}.",
                                "severity": "medium",
                            },
                        }
                    )
                    await self._finalize_round("blue", "Blue rate limiting deflected the second wave", self._round_state["round"])
                    return
            except Exception:
                pass
            await asyncio.sleep(poll_interval)

    def _detect_attack_pattern(self, logs: list[dict]) -> Optional[Dict[str, str]]:
        from urllib.parse import unquote
        for log in logs:
            path = (log.get("path") or "").lower()
            query = (log.get("query") or "").lower()
            body = (log.get("body") or "").lower()
            joined = " ".join([path, query, body])
            decoded = unquote(joined)
            ip = log.get("ip") or "unknown"

            # SQLi
            if any(p in path for p in ["/api/products", "/api/admin", "/api/users", "/api/orders", "/api/search"]) and any(
                k in joined or k in decoded for k in ["union select", " or '1'='1", " or \"1\"=\"1", "sql", "select ", "sqli", "admin'--", "or 1=1"]
            ):
                return {"vuln": "SQL Injection", "ip": ip}

            # Stored/Reflected XSS
            if any(p in path for p in ["/api/reviews", "/api/comments", "/api/feedback", "/api/users/avatar"]) and any(
                k in joined or k in decoded for k in ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg"]
            ):
                return {"vuln": "Stored XSS", "ip": ip}

            # SSRF
            if any(p in path for p in ["/api/image-proxy", "/api/proxy"]) and any(
                k in joined or k in decoded for k in ["http://", "https://", "localhost", "127.0.0.1", "169.254.", "metadata.google.internal"]
            ):
                return {"vuln": "SSRF", "ip": ip}

            # IDOR
            if any(p in path for p in ["/api/orders", "/api/users/"]) and any(k in joined or k in decoded for k in ["user_id=", "account_id=", "order_id="]):
                return {"vuln": "IDOR", "ip": ip}

            # File upload abuse
            if any(p in path for p in ["/api/users/avatar", "/upload", "/api/upload"]) and any(
                k in joined or k in decoded for k in [".html", ".svg", "<script", "onerror=", "payload.html"]
            ):
                return {"vuln": "Unrestricted File Upload", "ip": ip}

            # Auth bypass / brute force
            if any(p in path for p in ["/api/auth", "/login", "/admin/login"]) and any(
                k in joined or k in decoded for k in ["' or '1'='1", "\" or \"1\"=\"1", "or 1=1", "admin", "password=", "jwt"]
            ):
                return {"vuln": "Broken Authentication (JWT bypass)", "ip": ip}

            # Path traversal
            if any(p in path for p in ["/download", "/upload", "/api/download", "/api/upload", "/api/files", "/api/users/profile"]) and any(
                k in joined or k in decoded for k in ["..%2f", "..%5c", "../", "..\\", "etc/passwd", "win.ini"]
            ):
                return {"vuln": "Path Traversal", "ip": ip}

            # Command injection
            if any(p in path for p in ["/download", "/upload", "/api/download", "/api/upload", "/api/files", "/api/users/profile"]) and any(
                k in joined or k in decoded for k in ["cmd=", ";", "|", "whoami", "cat /etc/passwd"]
            ):
                return {"vuln": "Command Injection", "ip": ip}
        return None

    async def _finalize_round(self, winner: str, reason: str, round_index: int) -> None:
        if not self._round_state or self._round_state.get("winner"):
            return
        self._round_state["winner"] = winner
        self._round_state["active"] = False
        self._round_results.append({"round": round_index, "winner": winner, "reason": reason})
        if winner in ("red", "blue"):
            delta = 100
            if winner == "red":
                scores = update_scores(self._battle_id, red_delta=delta)
            else:
                scores = update_scores(self._battle_id, blue_delta=delta)
            await self._event_sink(
                {
                    "type": "score_update",
                    "team": "system",
                    "agent": "Game Master",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "red_score": scores["red_score"],
                        "blue_score": scores["blue_score"],
                        "reason": f"Round {round_index} winner: {winner}",
                    },
                }
            )

        await self._event_sink(
            {
                "type": "round_end",
                "team": "system",
                "agent": "Battle Manager",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "round": round_index,
                    "winner": winner,
                    "reason": reason,
                    "message": self._round_message(winner, round_index, reason),
                },
            }
        )

    def _round_message(self, winner: str, round_index: int, reason: str) -> str:
        if winner == "red":
            return f"ROUND {round_index}: RED TEAM DOMINATES — {reason}."
        if winner == "blue":
            return f"ROUND {round_index}: BLUE TEAM SHIELDS UP — {reason}."
        return f"ROUND {round_index}: DRAW — {reason}."

    def _build_battle_summary(self) -> Dict[str, Any]:
        battle = get_battle(self._battle_id) if self._battle_id else None
        red_score = battle.get("red_score", 0) if battle else 0
        blue_score = battle.get("blue_score", 0) if battle else 0
        red_wins = len([r for r in self._round_results if r.get("winner") == "red"])
        blue_wins = len([r for r in self._round_results if r.get("winner") == "blue"])
        draws = len([r for r in self._round_results if r.get("winner") == "draw"])
        if red_wins > blue_wins:
            winner = "red"
        elif blue_wins > red_wins:
            winner = "blue"
        else:
            winner = "draw"
        return {
            "winner": winner,
            "red_score": red_score,
            "blue_score": blue_score,
            "red_wins": red_wins,
            "blue_wins": blue_wins,
            "draws": draws,
            "rounds": list(self._round_results),
        }
    def _output_failed(self, output: Any) -> bool:
        if output is None:
            return True
        if isinstance(output, str):
            lowered = output.lower()
            return any(k in lowered for k in ["error", "exception", "traceback"])
        if isinstance(output, dict):
            if output.get("error"):
                return True
            status_code = output.get("status_code")
            if isinstance(status_code, int) and status_code >= 400:
                return True
            if status_code == 0:
                return True
            body = output.get("body")
            if isinstance(body, str) and "error" in body.lower():
                return True
        return False

    def _exploit_succeeded(self, output: Any) -> bool:
        if isinstance(output, dict):
            if output.get("successful", 0) > 0:
                return True
            rate = output.get("success_rate")
            if isinstance(rate, str) and rate.split("/")[0].isdigit():
                try:
                    return int(rate.split("/")[0]) > 0
                except Exception:
                    return False
        return False

    async def _defense_action(self, ip: str, action: str, limit: Optional[int] = None, window: Optional[int] = None) -> None:
        if not ip or ip == "unknown":
            return
        try:
            import httpx

            await asyncio.to_thread(
                httpx.post,
                f"{self._target_url}/internal/defense",
                json={"ip": ip, "action": action, "limit": limit, "window": window},
                timeout=5.0,
            )
        except Exception:
            return

    # Note: No automated blocking or rate limiting in demo flow. Blue suggests actions only.
