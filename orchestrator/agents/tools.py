import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
try:
    from orchestrator.oai_agents import function_tool
except ModuleNotFoundError:
    from oai_agents import function_tool
from unidiff import PatchSet


TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8001")


@dataclass
class HTTPResponse:
    status_code: int
    headers: Dict[str, Any]
    body: str


def _truncate(text: str, limit: int = 800) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"


def _parse_json_arg(value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _http_get_impl(url: str, params_json: Optional[str] = None, headers_json: Optional[str] = None) -> Dict[str, Any]:
    """Make a real GET request and return status, headers, and body (truncated)."""
    try:
        params = _parse_json_arg(params_json)
        headers = _parse_json_arg(headers_json)
        resp = httpx.get(url, params=params, headers=headers, timeout=5.0)
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
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
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
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


def _get_recent_logs_impl(since_timestamp: Optional[str] = None) -> Dict[str, Any]:
    """Fetch recent request logs from the sample app."""
    try:
        resp = httpx.get(
            f"{TARGET_URL}/internal/logs",
            params={"since": since_timestamp} if since_timestamp else None,
            timeout=5.0,
        )
        return resp.json()
    except Exception as exc:
        return {"logs": [], "error": str(exc)}


def _get_source_file_impl(filename: str) -> Dict[str, Any]:
    """Fetch a source file from the sample app."""
    try:
        resp = httpx.get(
            f"{TARGET_URL}/internal/source",
            params={"filename": filename},
            timeout=5.0,
        )
        return resp.json()
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
        source = _get_source_file_impl(filename)
        original = source.get("content", "")
        updated = _apply_unidiff(original, diff)
        resp = httpx.post(
            f"{TARGET_URL}/internal/reload",
            json={"filename": filename, "content": updated},
            timeout=5.0,
        )
        return {"status_code": resp.status_code, "body": _truncate(resp.text)}
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
