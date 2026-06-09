#!/usr/bin/env python3
"""
BloodHound CE helper CLI: ingest collection JSON, clear database, sync saved queries,
upload extension schema, and push custom node icons.

Credential precedence: CLI args, then .env, then process environment
(BLOODHOUND_URL, BLOODHOUND_USERNAME, BLOODHOUND_SECRET).
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# --- ingest job status (upload_ingest_files) ---
JOB_STATUS_NAMES = {
    -1: "invalid",
    0: "ready",
    1: "running",
    2: "complete",
    3: "canceled",
    4: "timed out",
    5: "failed",
    6: "ingesting",
    7: "analyzing",
    8: "partially complete",
}
TERMINAL_JOB_STATUSES = {2, 3, 4, 5, 8}
SUCCESS_JOB_STATUSES = {2}

# Default CiliumHound custom node icons (from push_icons.py)
DEFAULT_CUSTOM_NODE_ICONS: list[tuple[str, str, str]] = [
    ("Label", "tags", "#F27F0F"),
    ("Namespace", "box", "#1570F2"),
    ("FQDN", "at", "#2EDB1B"),
    ("FQDN-Pattern", "at", "#2EDB1B"),
    ("Port", "network-wired", "#D5DB16"),
    ("Entity", "id-badge", "#16A9F2"),
    ("CIDR", "arrow-down-1-9", "#AEC5EB"),
    ("CIDRSet", "arrow-down-1-9", "#AEC5EB"),
    ("EndpointSelector", "crosshairs", "#D8A7CA"),
]


def configure_logging(verbose: bool, debug: bool) -> None:
    log_level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
    if debug:
        logger.warning("Debug logging is enabled and may include sensitive API response bodies.")


def bloodhound_login(base_url: str, username: str, secret: str, timeout: int, verify: bool) -> Optional[str]:
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    body = {
        "login_method": "secret",
        "username": username,
        "secret": secret,
    }
    try:
        logger.info("Authenticating to BloodHound at %s", base_url.rstrip("/"))
        logger.debug("POST %s", api_url)
        resp = requests.post(api_url, json=body, timeout=timeout, verify=verify)
        logger.debug("Status: %s", resp.status_code)
        if not (200 <= resp.status_code < 300):
            logger.error("Login request failed with status %s.", resp.status_code)
            if resp.text:
                logger.debug("Body: %s", resp.text)
            return None
        data = resp.json()
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return None
    except json.JSONDecodeError as e:
        logger.error("Error parsing login response: %s", e)
        return None

    token = data.get("data", {}).get("session_token")
    auth_expired = data.get("data", {}).get("auth_expired", True)
    if auth_expired:
        logger.error("Login failed: credentials expired or invalid.")
        return None
    if not token:
        logger.error("Login succeeded but no session token found in response.")
        return None
    logger.info("Login succeeded.")
    logger.debug("Session token received.")
    return token


def list_source_kinds(
    base_url: str,
    token: str,
    timeout: int,
    verify: bool,
) -> Optional[list[dict]]:
    api_url = f"{base_url.rstrip('/')}/api/v2/graphs/source-kinds"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    try:
        logger.debug("GET %s", api_url)
        resp = requests.get(api_url, headers=headers, timeout=timeout, verify=verify)
        logger.debug("Status: %s", resp.status_code)
        if not (200 <= resp.status_code < 300):
            logger.error("source-kinds request failed with status %s.", resp.status_code)
            return None
        payload = resp.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error("Error fetching source kinds: %s", e)
        return None

    kinds = (payload.get("data") or {}).get("kinds") or []
    if not isinstance(kinds, list):
        logger.error("source-kinds response did not include data.kinds.")
        return None
    return [kind for kind in kinds if isinstance(kind, dict)]


def resolve_source_kind_id(
    base_url: str,
    token: str,
    kind_name: str,
    timeout: int,
    verify: bool,
) -> Optional[int]:
    kinds = list_source_kinds(base_url, token, timeout, verify)
    if kinds is None:
        return None
    for kind in kinds:
        if kind.get("name") == kind_name:
            kid = kind.get("id")
            if isinstance(kid, int):
                return kid
    logger.error("Source kind %r not found in BloodHound.", kind_name)
    return None


def prompt_source_kind_ids(kinds: list[dict]) -> Optional[list[int]]:
    options: list[tuple[int, str]] = []
    for kind in kinds:
        kind_id = kind.get("id")
        kind_name = kind.get("name")
        if isinstance(kind_id, int) and isinstance(kind_name, str) and kind_name:
            options.append((kind_id, kind_name))

    if not options:
        logger.error("No source kinds were available to select.")
        return None

    print("Available BloodHound source kinds:")
    for index, (kind_id, kind_name) in enumerate(options, start=1):
        print(f"  {index}. {kind_name} (id: {kind_id})")

    try:
        answer = input("Source kind(s) to delete by number, id, name, or 'all' [Enter to cancel]: ")
    except (EOFError, KeyboardInterrupt):
        print()
        logger.info("No source kind selected; clear database cancelled.")
        return None

    answer = answer.strip()
    if not answer:
        logger.info("No source kind selected; clear database cancelled.")
        return None
    if answer.lower() == "all":
        return [kind_id for kind_id, _ in options]

    by_number = {str(index): kind_id for index, (kind_id, _) in enumerate(options, start=1)}
    by_id = {str(kind_id): kind_id for kind_id, _ in options}
    by_name = {kind_name.lower(): kind_id for kind_id, kind_name in options}

    selected_ids: list[int] = []
    for raw_part in answer.split(","):
        part = raw_part.strip()
        if not part:
            continue
        kind_id = by_number.get(part)
        if kind_id is None:
            kind_id = by_id.get(part)
        if kind_id is None:
            kind_id = by_name.get(part.lower())
        if kind_id is None:
            logger.error("Unknown source kind selection: %s", part)
            return None
        if kind_id not in selected_ids:
            selected_ids.append(kind_id)

    if not selected_ids:
        logger.info("No source kind selected; clear database cancelled.")
        return None
    return selected_ids


def cmd_clear_database(args: argparse.Namespace, token: str) -> int:
    base_url = args.url.rstrip("/")
    payload: dict[str, Any] = {
        "deleteCollectedGraphData": args.delete_collected_graph_data,
        "deleteFileIngestHistory": args.delete_file_ingest_history,
        "deleteDataQualityHistory": args.delete_data_quality_history,
        "deleteAssetGroupSelectors": list(args.delete_asset_group_selectors),
    }

    kind_ids: list[int] = []
    if args.source_kind_ids:
        kind_ids.extend(args.source_kind_ids)
    if args.source_kind_name:
        kid = resolve_source_kind_id(base_url, token, args.source_kind_name, args.timeout, not args.insecure)
        if kid is None:
            return 1
        kind_ids.append(kid)
    if not kind_ids:
        kinds = list_source_kinds(base_url, token, args.timeout, not args.insecure)
        if kinds is None:
            return 1
        prompted_kind_ids = prompt_source_kind_ids(kinds)
        if prompted_kind_ids is None:
            return 1
        kind_ids.extend(prompted_kind_ids)
    if kind_ids:
        payload["deleteSourceKinds"] = kind_ids

    return 0 if clear_database(
        base_url,
        token,
        payload,
        timeout=args.timeout,
        wait=args.wait,
        verify=not args.insecure,
    ) else 1


def clear_database(
    base_url: str,
    token: str,
    payload: dict[str, Any],
    timeout: int,
    wait: int,
    verify: bool,
) -> bool:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Content-Type": "application/json",
        "Prefer": f"wait={wait}",
    }
    clear_url = f"{base_url}/api/v2/clear-database"
    try:
        logger.info("Clearing BloodHound database at %s", base_url)
        logger.debug("POST %s", clear_url)
        resp = requests.post(clear_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        logger.debug("Status: %s", resp.status_code)
        if resp.text:
            logger.debug("Body: %s", resp.text)
        if not (200 <= resp.status_code < 300):
            logger.error("Clear database request failed with status %s.", resp.status_code)
            return False
        logger.info("Clear database request completed successfully.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return False


def confirm_clear_database_before_ingest() -> bool:
    try:
        answer = input("Clear BloodHound database before ingesting new data? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        print()
        logger.info("No confirmation received; ingest will continue without clearing the database.")
        return False
    return answer.strip().lower() in ("y", "yes")


def validate_json_files(paths: list[str]) -> list[Path]:
    validated: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise SystemExit(f"[!] Error: {raw_path} is not a file")
        if path.suffix.lower() != ".json":
            raise SystemExit(f"[!] Error: {raw_path} must be a .json file")
        validated.append(path)
    return validated


def start_file_upload_job(base_url: str, token: str, timeout: int, wait: int, verify: bool) -> Optional[int]:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/start"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": f"wait={wait}",
    }
    try:
        logger.info("Starting BloodHound file upload job")
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error("Start file upload job failed with status %s.", resp.status_code)
            return None
        payload = resp.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error("Error starting upload job: %s", e)
        return None

    job_id = payload.get("data", {}).get("id")
    if not isinstance(job_id, int):
        logger.error("Start file upload job response did not include data.id.")
        return None
    logger.info("Started file upload job %s.", job_id)
    return job_id


def upload_file_to_job(
    base_url: str,
    token: str,
    job_id: int,
    path: Path,
    timeout: int,
    wait: int,
    verify: bool,
) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Content-Type": "application/json",
        "Prefer": f"wait={wait}",
        "X-File-Upload-Name": path.name,
    }
    try:
        logger.info("Uploading %s", path)
        with path.open("rb") as handle:
            resp = requests.post(api_url, headers=headers, data=handle, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error("Upload failed for %s with status %s.", path, resp.status_code)
            return False
        logger.info("Uploaded %s.", path.name)
        return True
    except OSError as e:
        logger.error("Error reading %s: %s", path, e)
        return False
    except requests.exceptions.RequestException as e:
        logger.error("Request error while uploading %s: %s", path, e)
        return False


def end_file_upload_job(base_url: str, token: str, job_id: int, timeout: int, wait: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}/end"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Prefer": f"wait={wait}",
    }
    try:
        logger.info("Ending BloodHound file upload job %s", job_id)
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error("End file upload job failed with status %s.", resp.status_code)
            return False
        logger.info("File upload job ended successfully.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return False


def get_file_upload_job(
    base_url: str,
    token: str,
    job_id: int,
    timeout: int,
    wait: int,
    verify: bool,
) -> Optional[dict]:
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": f"wait={wait}",
    }
    params = {"id": f"eq:{job_id}", "limit": 1}
    try:
        resp = requests.get(api_url, headers=headers, params=params, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            return None
        payload = resp.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error("Error checking file upload job %s: %s", job_id, e)
        return None

    jobs = payload.get("data")
    if not isinstance(jobs, list):
        return None
    for job in jobs:
        if isinstance(job, dict) and job.get("id") == job_id:
            return job
    return None


def job_status_name(status: object) -> str:
    if isinstance(status, int):
        return JOB_STATUS_NAMES.get(status, f"unknown ({status})")
    return "unknown"


def format_job_status(job: dict) -> str:
    status = job.get("status")
    parts = [f"status={job_status_name(status)}"]
    total_files = job.get("total_files")
    failed_files = job.get("failed_files")
    if isinstance(total_files, int):
        parts.append(f"total_files={total_files}")
    if isinstance(failed_files, int):
        parts.append(f"failed_files={failed_files}")
    if job.get("status_message"):
        parts.append(f"message={job['status_message']}")
    return ", ".join(parts)


def wait_for_ingest_completion(
    base_url: str,
    token: str,
    job_id: int,
    timeout: int,
    wait: int,
    verify: bool,
    poll_interval: int,
    poll_timeout: int,
) -> bool:
    deadline = time.monotonic() + poll_timeout if poll_timeout > 0 else None
    print(f"Waiting for BloodHound ingest job {job_id} to complete...", flush=True)
    while True:
        job = get_file_upload_job(base_url, token, job_id, timeout=timeout, wait=wait, verify=verify)
        if job is None:
            return False
        print(f"Job {job_id}: {format_job_status(job)}", flush=True)
        status = job.get("status")
        if status in TERMINAL_JOB_STATUSES:
            failed_files = job.get("failed_files")
            if status in SUCCESS_JOB_STATUSES and (not isinstance(failed_files, int) or failed_files == 0):
                print(f"Job {job_id}: ingest completed.", flush=True)
                return True
            print(f"Job {job_id}: ingest finished unsuccessfully.", flush=True)
            return False
        if deadline is not None and time.monotonic() >= deadline:
            logger.error("Timed out waiting for file upload job %s to complete.", job_id)
            return False
        time.sleep(poll_interval)


def upload_ingest_files(
    base_url: str,
    token: str,
    paths: list[Path],
    timeout: int,
    wait: int,
    verify: bool,
    poll_interval: int,
    poll_timeout: int,
) -> bool:
    job_id = start_file_upload_job(base_url, token, timeout=timeout, wait=wait, verify=verify)
    if job_id is None:
        return False
    for path in paths:
        if not upload_file_to_job(base_url, token, job_id, path, timeout=timeout, wait=wait, verify=verify):
            logger.error("Upload job %s was not ended because at least one file failed.", job_id)
            return False
    if not end_file_upload_job(base_url, token, job_id, timeout=timeout, wait=wait, verify=verify):
        return False
    return wait_for_ingest_completion(
        base_url,
        token,
        job_id,
        timeout=timeout,
        wait=wait,
        verify=verify,
        poll_interval=poll_interval,
        poll_timeout=poll_timeout,
    )


def cmd_ingest(args: argparse.Namespace, token: str) -> int:
    if args.wait < -1:
        raise SystemExit("--wait must be -1 or greater")
    if args.poll_interval < 1:
        raise SystemExit("--poll-interval must be 1 or greater")
    if args.poll_timeout < 0:
        raise SystemExit("--poll-timeout must be 0 or greater")
    paths = validate_json_files(args.files)
    if confirm_clear_database_before_ingest():
        clear_payload: dict[str, Any] = {
            "deleteCollectedGraphData": True,
            "deleteFileIngestHistory": False,
            "deleteDataQualityHistory": False,
            "deleteAssetGroupSelectors": [0],
        }
        if not clear_database(
            args.url.rstrip("/"),
            token,
            clear_payload,
            timeout=args.timeout,
            wait=0,
            verify=not args.insecure,
        ):
            return 1
    ok = upload_ingest_files(
        args.url,
        token,
        paths,
        timeout=args.timeout,
        wait=args.wait,
        verify=not args.insecure,
        poll_interval=args.poll_interval,
        poll_timeout=args.poll_timeout,
    )
    return 0 if ok else 1


def list_saved_queries(base_url: str, token: str, timeout: int, verify: bool) -> Optional[list[dict]]:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    params = {"scope": "owned"}
    try:
        resp = requests.get(api_url, headers=headers, params=params, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            return None
        data = resp.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error("Request error: %s", e)
        return None
    return data.get("data", [])


def delete_saved_query(base_url: str, token: str, query_id: str, timeout: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries/{query_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        resp = requests.delete(api_url, headers=headers, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return False


def load_saved_queries(folder: str) -> list[dict]:
    payloads: list[dict] = []
    pattern = os.path.join(folder, "*.json")
    for path in sorted(glob.glob(pattern)):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise SystemExit(f"[!] Payload in {path} must be a JSON object")
        name = data.get("name")
        query = data.get("query")
        if not name or not query:
            raise SystemExit(f"[!] Payload in {path} requires 'name' and 'query'")
        payload: dict[str, Any] = {"name": name, "query": query}
        if data.get("description"):
            payload["description"] = data["description"]
        if data.get("scope"):
            payload["scope"] = data["scope"]
        payloads.append(payload)
    return payloads


def create_saved_query(base_url: str, token: str, payload: dict, timeout: int, verify: bool) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return False


def confirm_delete_saved_queries(count: int) -> bool:
    try:
        answer = input(f"Delete {count} existing owned saved queries before upload? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        print()
        logger.info("No confirmation received; keeping existing saved queries in place.")
        return False
    return answer.strip().lower() in ("y", "yes")


def delete_saved_queries(base_url: str, token: str, queries: list[dict], timeout: int, verify: bool) -> bool:
    for item in queries:
        query_id = item.get("id")
        if not query_id:
            logger.warning("Skipping saved query without an id: %s", item.get("name", "<unnamed>"))
            continue
        if not delete_saved_query(base_url, token, query_id, timeout=timeout, verify=verify):
            logger.error("Failed to delete saved query id: %s", query_id)
            return False
    return True


def cmd_upload_queries(args: argparse.Namespace, token: str) -> int:
    verify = not args.insecure
    payloads = load_saved_queries(args.folder)
    if not payloads:
        logger.error("No saved queries found in folder: %s", args.folder)
        return 1

    existing = list_saved_queries(args.url, token, timeout=args.timeout, verify=verify)
    if existing is None:
        return 1
    if existing:
        if confirm_delete_saved_queries(len(existing)):
            logger.info("Deleting %s owned saved queries", len(existing))
            if not delete_saved_queries(args.url, token, existing, timeout=args.timeout, verify=verify):
                return 1
        else:
            logger.info("Keeping %s existing owned saved queries in place.", len(existing))

    logger.info("Uploading %s saved queries from %s", len(payloads), args.folder)
    for payload in payloads:
        if not create_saved_query(args.url, token, payload, timeout=args.timeout, verify=verify):
            logger.error("Failed to create saved query: %s", payload.get("name"))
            return 1
    logger.info("Saved queries sync complete.")
    return 0


def cmd_clear_queries(args: argparse.Namespace, token: str) -> int:
    verify = not args.insecure
    existing = list_saved_queries(args.url, token, timeout=args.timeout, verify=verify)
    if existing is None:
        return 1
    if not existing:
        logger.info("No owned saved queries found.")
        return 0

    logger.info("Deleting %s owned saved queries", len(existing))
    if not delete_saved_queries(args.url, token, existing, timeout=args.timeout, verify=verify):
        return 1
    logger.info("Deleted %s owned saved queries.", len(existing))
    return 0


def load_schema_payload(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise SystemExit(f"[!] Payload in {path} must be a JSON object")
    required_keys = ("schema", "node_kinds", "relationship_kinds")
    missing = [key for key in required_keys if key not in payload]
    if missing:
        raise SystemExit(f"[!] Payload in {path} is missing required key(s): {', '.join(missing)}")
    schema = payload.get("schema")
    if not isinstance(schema, dict) or not schema.get("name") or not schema.get("namespace"):
        raise SystemExit("[!] Payload schema must include at least 'name' and 'namespace'")
    if not isinstance(payload.get("node_kinds"), list):
        raise SystemExit("[!] Payload 'node_kinds' must be a list")
    if not isinstance(payload.get("relationship_kinds"), list):
        raise SystemExit("[!] Payload 'relationship_kinds' must be a list")
    return payload


def cmd_upload_schema(args: argparse.Namespace, token: str) -> int:
    payload = load_schema_payload(args.file)
    schema = payload.get("schema", {})
    logger.info(
        "Uploading schema %s (%s)",
        schema.get("name", "unknown"),
        schema.get("namespace", "unknown"),
    )
    api_url = f"{args.url.rstrip('/')}/api/v2/extensions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": f"wait={args.wait}",
    }
    try:
        resp = requests.put(
            api_url,
            headers=headers,
            json=payload,
            timeout=args.timeout,
            verify=not args.insecure,
        )
        if 200 <= resp.status_code < 300:
            logger.info("Schema upload complete.")
            return 0
        logger.error("Schema upload failed with status %s.", resp.status_code)
        if resp.text:
            logger.debug("Body: %s", resp.text)
        return 1
    except requests.exceptions.RequestException as e:
        logger.error("Request error: %s", e)
        return 1


def define_custom_node_icon(
    base_url: str,
    token: str,
    icon_type: str,
    icon_name: str,
    icon_color: str,
    timeout: int,
    verify: bool,
) -> bool:
    url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "custom_types": {
            icon_type: {
                "icon": {"type": "font-awesome", "name": icon_name, "color": icon_color},
            }
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout, verify=verify)
        if response.status_code == 409:
            put_payload = {
                "config": {
                    "icon": {"type": "font-awesome", "name": icon_name, "color": icon_color},
                }
            }
            response = requests.put(
                f"{url}/{icon_type}",
                headers=headers,
                json=put_payload,
                timeout=timeout,
                verify=verify,
            )
        logger.info("Icon %s: HTTP %s", icon_type, response.status_code)
        if logger.isEnabledFor(logging.DEBUG) and response.text:
            logger.debug("Response: %s", response.text)
        return 200 <= response.status_code < 300
    except requests.exceptions.RequestException as e:
        logger.error("Error uploading icon %s: %s", icon_type, e)
        return False


def cmd_push_icons(args: argparse.Namespace, token: str) -> int:
    verify = not args.insecure
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    icons: list[tuple[str, str, str]] = list(DEFAULT_CUSTOM_NODE_ICONS)
    for triple in args.icon or []:
        if len(triple) != 3:
            logger.error("Each --icon must be TYPE NAME COLOR (three values).")
            return 1
        icons.append((triple[0], triple[1], triple[2]))

    for icon_type, icon_name, icon_color in icons:
        if not define_custom_node_icon(
            args.url, token, icon_type, icon_name, icon_color, args.timeout, verify
        ):
            return 1
    logger.info("Custom node icons completed (%s types).", len(icons))
    return 0


def add_common_auth(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", help="BloodHound base URL (or set BLOODHOUND_URL)")
    p.add_argument("--username", help="Username (or set BLOODHOUND_USERNAME)")
    p.add_argument("--secret", help="Password/secret (or set BLOODHOUND_SECRET)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    p.add_argument("--verbose", action="store_true", help="Enable informational logging")
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (may log sensitive API bodies).",
    )
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")


def resolve_auth(args: argparse.Namespace) -> tuple[str, str, str, bool]:
    url = args.url or os.getenv("BLOODHOUND_URL") or ""
    username = args.username or os.getenv("BLOODHOUND_USERNAME") or ""
    secret = args.secret or os.getenv("BLOODHOUND_SECRET") or ""
    verify = not args.insecure
    return url, username, secret, verify


def main() -> None:
    parent = argparse.ArgumentParser(add_help=False)
    add_common_auth(parent)

    parser = argparse.ArgumentParser(
        parents=[parent],
        description="BloodHound CE utilities: ingest, clear DB, saved queries, schema, icons.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", parents=[parent], help="Upload collection JSON file(s) and wait for ingest")
    p_ingest.add_argument("files", nargs="+", help="Collection JSON file(s) to upload")
    p_ingest.add_argument("--wait", type=int, default=30, help="Prefer wait seconds (default: 30)")
    p_ingest.add_argument("--poll-interval", type=int, default=5, help="Seconds between status polls (default: 5)")
    p_ingest.add_argument(
        "--poll-timeout",
        type=int,
        default=0,
        help="Max seconds to wait for ingest; 0 = forever (default: 0)",
    )

    p_clear = sub.add_parser("clear-database", parents=[parent], help="POST /api/v2/clear-database")
    p_clear.add_argument("--wait", type=int, default=0, help="Prefer wait seconds (default: 0)")
    p_clear.add_argument(
        "--delete-collected-graph-data",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Delete collected graph data (default: false)",
    )
    p_clear.add_argument(
        "--delete-file-ingest-history",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Delete file ingest history (default: false)",
    )
    p_clear.add_argument(
        "--delete-data-quality-history",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Delete data quality history (default: false)",
    )
    p_clear.add_argument(
        "--delete-asset-group-selectors",
        type=int,
        nargs="*",
        default=[0],
        metavar="ID",
        help="Asset group selector IDs to delete (default: 0 if flag omitted). "
        "Pass flag with no IDs to send an empty list.",
    )
    p_clear.add_argument(
        "--source-kind-name",
        help="Graph source kind name to clear (e.g. TS_Base); resolved via API",
    )
    p_clear.add_argument(
        "--source-kind-id",
        type=int,
        action="append",
        dest="source_kind_ids",
        metavar="ID",
        help="Explicit source kind id(s); can be repeated",
    )

    p_queries = sub.add_parser(
        "upload-queries",
        parents=[parent],
        help="Upload saved queries from a folder of JSON; prompt before deleting existing owned queries",
    )
    p_queries.add_argument("--folder", default="saved-queries", help="Folder of *.json saved queries (default: saved-queries)")

    sub.add_parser(
        "clear-queries",
        aliases=["clear-saved-queries"],
        parents=[parent],
        help="Delete all owned saved queries",
    )

    p_schema = sub.add_parser("upload-schema", parents=[parent], help="PUT OpenGraph extension schema JSON")
    p_schema.add_argument("--file", default="schema.json", help="Schema JSON path (default: schema.json)")
    p_schema.add_argument("--wait", type=int, default=0, help="Prefer wait seconds (default: 0)")

    p_icons = sub.add_parser(
        "push-icons",
        parents=[parent],
        help="Upload default CiliumHound custom node icons (and optional extras)",
    )
    p_icons.add_argument(
        "--icon",
        action="append",
        nargs=3,
        metavar=("TYPE", "NAME", "COLOR"),
        help="Extra icon: Font Awesome name and hex color (repeatable)",
    )

    args = parser.parse_args()

    configure_logging(args.verbose, args.debug)

    url, username, secret, verify = resolve_auth(args)
    if not url:
        logger.error("Missing URL. Provide --url or set BLOODHOUND_URL (.env supported).")
        sys.exit(1)
    if not username or not secret:
        logger.error("Missing credentials. Use --username/--secret or BLOODHOUND_USERNAME/BLOODHOUND_SECRET.")
        sys.exit(1)

    token = bloodhound_login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    # Normalize URL on args for subcommands
    args.url = url.rstrip("/")

    if args.command == "ingest":
        rc = cmd_ingest(args, token)
    elif args.command == "clear-database":
        rc = cmd_clear_database(args, token)
    elif args.command == "upload-queries":
        rc = cmd_upload_queries(args, token)
    elif args.command in ("clear-queries", "clear-saved-queries"):
        rc = cmd_clear_queries(args, token)
    elif args.command == "upload-schema":
        if args.wait < 0:
            parser.error("--wait must be 0 or greater")
        rc = cmd_upload_schema(args, token)
    elif args.command == "push-icons":
        rc = cmd_push_icons(args, token)
    else:
        parser.error(f"Unknown command: {args.command}")

    sys.exit(rc)


if __name__ == "__main__":
    main()
