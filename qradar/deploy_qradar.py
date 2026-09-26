#!/usr/bin/env python3
"""QRadar API integration for repository-managed rule definitions.

Current supported mode:
- Read qradar/rules/*.json.
- Submit each rule's AQL expression to the QRadar Ariel Search API.
- Poll for completion and report the result count.

Important: Ariel searches validate/execute AQL; they do not create native CRE
correlation rules. Native CRE/content-extension deployment must be added after
the QRadar version and supported content-management API are confirmed.
"""

import glob
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = os.environ.get("QRADAR_HOST", "").rstrip("/")
TOKEN = os.environ.get("QRADAR_SEC_TOKEN", "")
VERIFY_SSL = os.environ.get("QRADAR_VERIFY_SSL", "false").lower() == "true"
API_VERSION = os.environ.get("QRADAR_API_VERSION", "").strip()
RULE_GLOB = os.environ.get("QRADAR_RULE_GLOB", "qradar/rules/*.json")

if not HOST or not TOKEN:
    print("QRadar API integration skipped: QRADAR_HOST or QRADAR_SEC_TOKEN is not configured.")
    sys.exit(0)

if not HOST.startswith(("https://", "http://")):
    HOST = "https://" + HOST

SSL_CONTEXT = ssl.create_default_context() if VERIFY_SSL else ssl._create_unverified_context()
HEADERS = {"SEC": TOKEN, "Accept": "application/json"}
if API_VERSION:
    HEADERS["Version"] = API_VERSION


def api(method, path, data=None, timeout=60):
    body = urllib.parse.urlencode(data).encode() if data else None
    headers = dict(HEADERS)
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(HOST + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, context=SSL_CONTEXT, timeout=timeout) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"message": raw[:500]}
        return error.code, payload


def submit_search(expression):
    return api("POST", "/api/ariel/searches", {"query_expression": expression})


def wait_for_search(search_id, attempts=30, delay=5):
    for _ in range(attempts):
        code, payload = api("GET", f"/api/ariel/searches/{search_id}")
        if code != 200:
            return False, f"status request returned HTTP {code}: {payload}"
        status = payload.get("status")
        if status == "COMPLETED":
            return True, status
        if status in {"ERROR", "CANCELED"}:
            return False, status
        time.sleep(delay)
    return False, "timeout"


def result_count(search_id):
    code, payload = api("GET", f"/api/ariel/searches/{search_id}/results")
    if code != 200:
        return None, f"results request returned HTTP {code}: {payload}"
    return len(payload.get("events", payload.get("flows", []))), None


def main():
    files = sorted(glob.glob(RULE_GLOB))
    if len(files) != 10:
        raise SystemExit(f"Expected 10 QRadar rule files, found {len(files)}")

    failures = []
    for path in files:
        with open(path, encoding="utf-8") as handle:
            rule = json.load(handle)
        name = rule["name"]
        code, payload = submit_search(rule["expression"])
        if code not in (200, 201):
            failures.append(f"{name}: submit HTTP {code}: {payload}")
            continue
        search_id = payload.get("search_id")
        if not search_id:
            failures.append(f"{name}: QRadar did not return search_id")
            continue
        ok, detail = wait_for_search(search_id)
        if not ok:
            failures.append(f"{name}: Ariel search failed: {detail}")
            continue
        count, error = result_count(search_id)
        if error:
            failures.append(f"{name}: {error}")
            continue
        print(f"{name}: AQL completed, results={count}, search_id={search_id}")

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"QRadar API validation completed for {len(files)} rules.")


if __name__ == "__main__":
    main()
