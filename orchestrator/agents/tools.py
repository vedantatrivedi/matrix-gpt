import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
try:
    from orchestrator.oai_agents import function_tool
except ModuleNotFoundError:
    from oai_agents import function_tool
from unidiff import PatchSet

try:
    from orchestrator.db import store_recon_result, get_recon_results
except ModuleNotFoundError:
    from db import store_recon_result, get_recon_results


TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8001")

# Global to track current battle_id for recon tools
_current_battle_id: Optional[str] = None


def set_battle_context(battle_id: str) -> None:
    """Set the current battle ID for recon tools to use."""
    global _current_battle_id
    _current_battle_id = battle_id


@dataclass
class HTTPResponse:
    status_code: int
    headers: Dict[str, Any]
    body: str


def _truncate(text: str, limit: int = 100) -> str:
    """OPTIMIZATION: Aggressive truncation from 800 to 100 chars to save tokens."""
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _parse_json_arg(value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _with_retry(action, attempts: int = 2, delay: float = 0.3):
    last_exc = None
    for i in range(attempts):
        try:
            return action()
        except Exception as exc:
            last_exc = exc
            if i < attempts - 1:
                time.sleep(delay * (i + 1))
    raise last_exc


def _defense_action_impl(ip: str, action: str, limit: Optional[int] = None, window: Optional[int] = None) -> Dict[str, Any]:
    try:
        def _do_request():
            resp = httpx.post(
                f"{TARGET_URL}/internal/defense",
                json={"ip": ip, "action": action, "limit": limit, "window": window},
                timeout=5.0,
            )
            return {"status_code": resp.status_code, "body": _truncate(resp.text)}

        return _with_retry(_do_request)
    except Exception as exc:
        return {"status_code": 0, "body": f"error: {exc}"}


def _http_get_impl(url: str, params_json: Optional[str] = None, headers_json: Optional[str] = None) -> Dict[str, Any]:
    """Make a real GET request and return status, headers, and body (truncated)."""
    try:
        params = _parse_json_arg(params_json)
        headers = _parse_json_arg(headers_json)
        resp = httpx.get(url, params=params, headers=headers, timeout=5.0)

        # OPTIMIZATION: Only return important headers to save tokens
        important_headers = {}
        for key in ["content-type", "set-cookie", "location", "www-authenticate"]:
            if key in resp.headers:
                important_headers[key] = resp.headers[key][:100]  # Truncate header values

        return {
            "status_code": resp.status_code,
            "headers": important_headers,
            "body": _truncate(resp.text),
        }
    except Exception as exc:
        return {"status_code": 0, "headers": {}, "body": f"error: {exc}"}


def _http_post_impl(
    url: str,
    body_json: Optional[str] = None,
    json_body_json: Optional[str] = None,
    headers_json: Optional[str] = None,
    files_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Make a real POST request and return status, headers, and body (truncated)."""
    try:
        body = _parse_json_arg(body_json)
        json_body = _parse_json_arg(json_body_json)
        headers = _parse_json_arg(headers_json)
        files = _parse_json_arg(files_json)
        resp = httpx.post(
            url,
            data=body,
            json=json_body,
            headers=headers,
            files=files,
            timeout=5.0,
        )

        # OPTIMIZATION: Only return important headers to save tokens
        important_headers = {}
        for key in ["content-type", "set-cookie", "location", "www-authenticate"]:
            if key in resp.headers:
                important_headers[key] = resp.headers[key][:100]  # Truncate header values

        return {
            "status_code": resp.status_code,
            "headers": important_headers,
            "body": _truncate(resp.text),
        }
    except Exception as exc:
        return {"status_code": 0, "headers": {}, "body": f"error: {exc}"}


@function_tool
def http_get(url: str, params_json: Optional[str] = None, headers_json: Optional[str] = None) -> Dict[str, Any]:
    return _http_get_impl(url, params_json=params_json, headers_json=headers_json)


@function_tool
def http_post(
    url: str,
    body_json: Optional[str] = None,
    json_body_json: Optional[str] = None,
    headers_json: Optional[str] = None,
    files_json: Optional[str] = None,
) -> Dict[str, Any]:
    return _http_post_impl(
        url,
        body_json=body_json,
        json_body_json=json_body_json,
        headers_json=headers_json,
        files_json=files_json,
    )

@function_tool
def http_response_to_string(response: Dict[str, Any]) -> str:
    return json.dumps(response, indent=2)


def _get_recent_logs_impl(since_timestamp: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
    """Fetch recent request logs from the sample app. OPTIMIZED: Returns only last 10 logs by default."""
    try:
        def _do_request():
            resp = httpx.get(
                f"{TARGET_URL}/internal/logs",
                params={"since": since_timestamp} if since_timestamp else None,
                timeout=5.0,
            )
            data = resp.json()
            logs = data.get("logs", [])

            # OPTIMIZATION: Limit to last N logs to save tokens
            if len(logs) > limit:
                logs = logs[-limit:]

            # OPTIMIZATION: Truncate each log entry
            for log in logs:
                if "path" in log and isinstance(log["path"], str):
                    log["path"] = log["path"][:100]
                if "ip" in log and isinstance(log["ip"], str):
                    log["ip"] = log["ip"][:100]
                if "body" in log and isinstance(log["body"], str):
                    log["body"] = _truncate(log["body"], 50)
                if "response" in log and isinstance(log["response"], str):
                    log["response"] = _truncate(log["response"], 50)

            return {"logs": logs, "total": len(logs), "truncated": len(data.get("logs", [])) > limit}

        return _with_retry(_do_request)
    except Exception as exc:
        return {"logs": [], "error": str(exc)}


def _get_source_file_impl(filename: str, max_lines: int = 100) -> Dict[str, Any]:
    """Fetch a source file from the sample app. OPTIMIZED: Returns max 100 lines by default."""
    try:
        def _do_request():
            resp = httpx.get(
                f"{TARGET_URL}/internal/source",
                params={"filename": filename},
                timeout=5.0,
            )
            data = resp.json()
            content = data.get("content", "")

            # OPTIMIZATION: Truncate large files to save massive tokens
            lines = content.split("\n")
            if len(lines) > max_lines:
                # Keep first 80% and last 20% for context
                keep_start = int(max_lines * 0.8)
                keep_end = max_lines - keep_start
                lines = lines[:keep_start] + [f"\n... {len(lines) - max_lines} lines omitted ...\n"] + lines[-keep_end:]
                content = "\n".join(lines)

            return {
                "filename": filename,
                "content": content,
                "total_lines": len(data.get("content", "").split("\n")),
                "truncated": len(data.get("content", "").split("\n")) > max_lines
            }

        return _with_retry(_do_request)
    except Exception as exc:
        return {"filename": filename, "content": "", "error": str(exc)}


def _apply_unidiff(original_text: str, diff_text: str) -> str:
    patch = PatchSet(diff_text)
    text = original_text
    for patched_file in patch:
        lines = text.splitlines(keepends=True)
        for hunk in patched_file:
            start = hunk.source_start - 1
            end = start + hunk.source_length
            new_lines = []
            source_index = start
            for line in hunk:
                if line.is_context:
                    new_lines.append(lines[source_index])
                    source_index += 1
                elif line.is_removed:
                    source_index += 1
                elif line.is_added:
                    new_lines.append(line.value)
            lines[start:end] = new_lines
        text = "".join(lines)
    return text


def _apply_patch_impl(filename: str, diff: str) -> Dict[str, Any]:
    """Apply a unified diff to a sample app file and reload it via /internal/reload."""
    try:
        def _do_request():
            source = _get_source_file_impl(filename)
            original = source.get("content", "")
            updated = _apply_unidiff(original, diff)
            resp = httpx.post(
                f"{TARGET_URL}/internal/reload",
                json={"filename": filename, "content": updated},
                timeout=5.0,
            )
            return {"status_code": resp.status_code, "body": _truncate(resp.text)}

        return _with_retry(_do_request)
    except Exception as exc:
        return {"status_code": 0, "body": f"error: {exc}"}


@function_tool
def get_recent_logs(since_timestamp: Optional[str] = None) -> Dict[str, Any]:
    return _get_recent_logs_impl(since_timestamp=since_timestamp)


@function_tool
def get_source_file(filename: str) -> Dict[str, Any]:
    return _get_source_file_impl(filename=filename)


@function_tool
def apply_patch(filename: str, diff: str) -> Dict[str, Any]:
    return _apply_patch_impl(filename=filename, diff=diff)


@function_tool
def block_ip(ip: str) -> Dict[str, Any]:
    return _defense_action_impl(ip=ip, action="block")


@function_tool
def rate_limit_ip(ip: str, limit: int = 30, window: int = 60) -> Dict[str, Any]:
    return _defense_action_impl(ip=ip, action="limit", limit=limit, window=window)


# ============================================================================
# RECON TOOLS - Scan once, store results, query later
# ============================================================================


def _analyze_response(url: str, status_code: int, headers: Dict[str, Any], body: str) -> Dict[str, Any]:
    """Analyze HTTP response for security indicators."""
    body_lower = body.lower()

    indicators = {
        "accessible": status_code in [200, 201, 204],
        "has_error": status_code >= 400,
        "has_sql_keywords": any(k in body_lower for k in ["select ", "insert ", "delete ", "update ", "union "]),
        "has_error_trace": "traceback" in body_lower or "exception" in body_lower or "error:" in body_lower,
        "has_admin_content": "admin" in body_lower,
        "has_user_content": "user" in body_lower or "profile" in body_lower,
        "has_auth_indicators": any(k in body_lower for k in ["login", "token", "jwt", "session", "cookie"]),
        "has_api_indicators": "api" in url.lower() or "application/json" in str(headers).lower(),
        "has_file_upload": "upload" in body_lower or "file" in body_lower,
        "has_sensitive_data": any(k in body_lower for k in ["password", "secret", "key", "credential"]),
        "has_cors_headers": "access-control-allow-origin" in str(headers).lower(),
        "has_security_headers": any(k in str(headers).lower() for k in ["x-frame-options", "content-security-policy"]),
        "response_size": len(body),
    }

    # Generate notes based on findings
    notes = []
    if indicators["has_sql_keywords"]:
        notes.append("SQL keywords detected - potential injection point")
    if indicators["has_error_trace"]:
        notes.append("Error traces exposed - information disclosure")
    if indicators["has_admin_content"]:
        notes.append("Admin content detected")
    if indicators["has_file_upload"]:
        notes.append("File upload functionality detected")
    if indicators["has_sensitive_data"]:
        notes.append("Sensitive data keywords found")
    if not indicators["has_security_headers"]:
        notes.append("Missing security headers")

    return {
        "indicators": indicators,
        "notes": "; ".join(notes) if notes else None
    }


@function_tool
def run_comprehensive_recon(
    base_url: str,
    paths_json: Optional[str] = None,
    store_results: bool = True
) -> Dict[str, Any]:
    """
    Run comprehensive recon scan and optionally store results in database.

    This tool scans multiple endpoints, analyzes responses for security indicators,
    and stores findings for other agents to query later.

    Args:
        base_url: Base URL to scan (e.g., "http://localhost:8001")
        paths_json: JSON array of paths to scan. If not provided, uses default common paths.
                   Example: '["/", "/api/users", "/admin"]'
        store_results: Whether to store results in database (default: True)

    Returns:
        Summary of recon findings with accessible endpoints, errors, and security indicators
    """
    if not _current_battle_id and store_results:
        return {"error": "No battle context set. Call set_battle_context() first."}

    # Default paths if none provided
    if paths_json:
        try:
            paths = json.loads(paths_json)
        except json.JSONDecodeError:
            return {"error": "Invalid paths_json format. Must be valid JSON array."}
    else:
        paths = [
            "/",
            "/api",
            "/api/products",
            "/api/users",
            "/api/orders",
            "/api/reviews",
            "/api/auth",
            "/api/auth/login",
            "/api/admin",
            "/api/admin/users",
            "/admin",
            "/auth",
            "/login",
            "/upload",
            "/api/image-proxy",
            "/api/users/avatar",
            "/internal",
        ]

    findings = []
    accessible_count = 0
    error_count = 0
    high_interest = []

    for path in paths:
        url = f"{base_url}{path}"
        try:
            resp = httpx.get(url, timeout=5.0, follow_redirects=False)
            status_code = resp.status_code
            headers = dict(resp.headers)
            body = resp.text

            # Analyze response
            analysis = _analyze_response(url, status_code, headers, body)

            # OPTIMIZATION: Compress finding to save tokens
            finding = {
                "endpoint": path,
                "status_code": status_code,
                "preview": _truncate(body, limit=50),  # Reduced from 200 to 50
                "notes": analysis["notes"][:100] if analysis["notes"] else None  # Truncate notes
            }

            findings.append(finding)

            if analysis["indicators"]["accessible"]:
                accessible_count += 1
            if analysis["indicators"]["has_error"]:
                error_count += 1

            # Track high-interest endpoints
            if (analysis["indicators"]["has_sql_keywords"] or
                analysis["indicators"]["has_error_trace"] or
                analysis["indicators"]["has_admin_content"] or
                analysis["indicators"]["has_file_upload"]):
                high_interest.append({
                    "endpoint": path,
                    "reason": analysis["notes"]
                })

            # Store in database if enabled
            if store_results and _current_battle_id:
                store_recon_result(
                    battle_id=_current_battle_id,
                    endpoint=path,
                    method="GET",
                    status_code=status_code,
                    response_preview=_truncate(body, limit=500),
                    headers=headers,
                    indicators=analysis["indicators"],
                    notes=analysis["notes"]
                )

        except Exception as exc:
            findings.append({
                "endpoint": path,
                "status_code": 0,
                "error": str(exc)
            })

    return {
        "total_scanned": len(findings),
        "accessible_endpoints": accessible_count,
        "error_endpoints": error_count,
        "high_interest_count": len(high_interest),
        "high_interest": high_interest,
        "summary": f"Scanned {len(findings)} endpoints: {accessible_count} accessible, {error_count} errors, {len(high_interest)} high-interest targets",
        "stored_in_db": store_results and _current_battle_id is not None
    }


@function_tool
def query_recon_data(
    filter_by: Optional[str] = None,
    endpoint_pattern: Optional[str] = None,
    min_status: Optional[int] = None,
    max_status: Optional[int] = None
) -> Dict[str, Any]:
    """
    Query previously stored recon results.

    This tool retrieves reconnaissance data collected by run_comprehensive_recon.
    Other agents can use this to build on existing knowledge without re-scanning.

    Args:
        filter_by: Filter type - "accessible" (2xx), "errors" (4xx/5xx), "interesting"
        endpoint_pattern: Filter endpoints containing this string (e.g., "api", "admin")
        min_status: Minimum HTTP status code
        max_status: Maximum HTTP status code

    Returns:
        List of matching recon results with indicators and notes
    """
    if not _current_battle_id:
        return {"error": "No battle context set."}

    # Apply filters based on filter_by parameter
    if filter_by == "accessible":
        min_status = 200
        max_status = 299
    elif filter_by == "errors":
        min_status = 400
        max_status = 599

    results = get_recon_results(
        battle_id=_current_battle_id,
        endpoint=endpoint_pattern,
        min_status=min_status,
        max_status=max_status
    )

    # Additional filtering for "interesting" results
    if filter_by == "interesting":
        results = [
            r for r in results
            if (r["indicators"].get("has_sql_keywords") or
                r["indicators"].get("has_error_trace") or
                r["indicators"].get("has_admin_content") or
                r["indicators"].get("has_file_upload") or
                r["indicators"].get("has_sensitive_data"))
        ]

    # OPTIMIZATION: Compress results to save tokens
    # Remove large response_preview from results
    compressed = []
    for r in results[:10]:  # Limit to 10 instead of 20
        compressed.append({
            "endpoint": r["endpoint"],
            "status": r["status_code"],
            "notes": r.get("notes", "")[:100]  # Truncate notes
        })

    summary = {
        "total_results": len(results),
        "endpoints": [r["endpoint"] for r in results][:15],  # Max 15 endpoints
        "results": compressed
    }

    if len(results) > 10:
        summary["note"] = f"Showing 10 of {len(results)}. Use specific filters."

    return summary


@function_tool
def get_recon_summary() -> Dict[str, Any]:
    """
    Get a high-level summary of all recon data.

    Returns overview statistics and most interesting findings without full details.
    Useful for quick context before diving deeper.
    """
    if not _current_battle_id:
        return {"error": "No battle context set."}

    all_results = get_recon_results(battle_id=_current_battle_id)

    if not all_results:
        return {
            "status": "no_recon_data",
            "message": "No recon data available. Run run_comprehensive_recon first."
        }

    accessible = [r for r in all_results if 200 <= r["status_code"] < 300]
    errors = [r for r in all_results if r["status_code"] >= 400]

    high_interest = [
        r for r in all_results
        if (r["indicators"].get("has_sql_keywords") or
            r["indicators"].get("has_error_trace") or
            r["indicators"].get("has_admin_content") or
            r["indicators"].get("has_file_upload"))
    ]

    return {
        "total_endpoints_scanned": len(all_results),
        "accessible_count": len(accessible),
        "error_count": len(errors),
        "high_interest_count": len(high_interest),
        "accessible_endpoints": [r["endpoint"] for r in accessible],
        "high_interest_endpoints": [
            {
                "endpoint": r["endpoint"],
                "notes": r.get("notes", "No notes")
            }
            for r in high_interest
        ],
        "api_endpoints": [r["endpoint"] for r in all_results if "/api/" in r["endpoint"]],
        "admin_endpoints": [r["endpoint"] for r in all_results if "admin" in r["endpoint"].lower()],
    }
