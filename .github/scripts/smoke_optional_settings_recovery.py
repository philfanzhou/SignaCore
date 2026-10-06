#!/usr/bin/env python3
"""Exercise legacy optional settings on an already installed disposable PostgreSQL container.

The SQL below constructs an older-release fixture only; every recovery operation uses the
protected management API. Token and database output remain in memory and are never printed.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


class SmokeFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def run(args):
    def docker(*arguments):
        result = subprocess.run(["docker", *arguments], capture_output=True, text=True)
        require(result.returncode == 0, "Container operation failed.")
        return result.stdout

    def sql(statement):
        return docker("exec", "-e", "PGPASSWORD", args.postgres, "psql", "-U", "postgres",
                      "-d", args.database, "-tAc", statement).strip()

    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        password = os.environ.get("ADMIN_PASSWORD")
        require(bool(password), "The fixture administrator password is missing.")
        request = urllib.request.Request(args.url + "/api/admin/session/bearer/login",
            json.dumps({"username": args.admin, "password": password}).encode(),
            {"Content-Type": "application/json", "X-ServiceMantle-Request": "1"}, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            token = json.load(response)["accessToken"]
    require(bool(token), "The fixture administrator token is missing.")

    def api(method="GET", changes=None, version=None, authenticated=True):
        headers = {"Content-Type": "application/json", "X-ServiceMantle-Request": "1"}
        if authenticated:
            headers["Authorization"] = "Bearer " + token
        body = None if changes is None else json.dumps({"expectedVersion": version,
            "changes": [{"key": key, "value": value} for key, value in changes.items()]}).encode()
        request = urllib.request.Request(args.url + "/management/v1/settings", body, headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as failure:
            response = failure
        with response:
            return response.status, json.load(response), response.headers

    def stored():
        return json.loads(sql("SELECT json_build_object('version',version,'values',values_json::jsonb) "
                              "FROM service_settings WHERE service_id='signacore'"))

    def audits():
        return int(sql("SELECT count(*) FROM service_audit_logs WHERE action='configuration.changed'"))

    def restart(loki_disabled=True, otlp_disabled=True):
        since = datetime.now(timezone.utc).isoformat()
        docker("restart", args.app)
        for _ in range(90):
            try:
                with urllib.request.urlopen(args.url + "/health/ready", timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        else:
            raise SmokeFailure("The restarted fixture did not become ready.")
        logs = docker("logs", "--since", since, args.app)
        require(("Remote log shipping to Loki is disabled" in logs) == loki_disabled,
                "The restart Loki classification did not match the saved fixture.")
        require(("OTLP trace export is disabled" in logs) == otlp_disabled,
                "The restart OTLP classification did not match the saved fixture.")
        return api()

    # Stop before constructing an older-release fixture. No production recovery writes SQL.
    docker("stop", args.app)
    sql("UPDATE service_settings SET values_json = ((values_json::jsonb - 'loki.authorization') "
        "|| '{\"loki.uri\":\"http://loki.example.com:3100\","
        "\"opentelemetry.otlp_endpoint\":\"http://collector.example.com:4317\"}'::jsonb)::text, "
        "version=version+1 WHERE service_id='signacore'")
    status, current, headers = restart()
    require(status == 200, "Legacy optional settings were not readable.")
    require(api(authenticated=False)[0] == 401, "Anonymous settings query was accepted.")
    for value in current["values"]:
        require(not value["isSensitive"] or value["value"] is None, "Sensitive setting projection was not redacted.")
    before, count = stored(), audits()
    running = headers["X-SignaCore-Running-Configuration-Version"]
    status, updated, _ = api("POST", {"sms.max_sends_per_hour": "8"}, before["version"])
    require(status == 200 and updated["version"] == before["version"] + 1, "Unrelated recovery update failed.")
    after = stored()
    require(audits() == count + 1, "Recovery did not write exactly one key audit.")
    for key, value in before["values"].items():
        if key != "sms.max_sends_per_hour":
            require(after["values"].get(key) == value, "Recovery changed an untouched persisted value.")
    require(api()[2]["X-SignaCore-Running-Configuration-Version"] == running,
            "An observation or update changed the running version.")
    require(api("POST", {"LOKI.URI": "http://loki.example.com:3100"}, after["version"])[0] == 400,
            "Explicit unchanged invalid Loki was accepted.")
    require(stored() == after and audits() == count + 1, "Invalid update left partial writes.")
    status, current, headers = restart()
    require(status == 200 and headers["X-SignaCore-Running-Configuration-Version"] == str(after["version"]),
            "Restart did not activate the saved version while leaving legacy sinks disabled.")
    status, repaired, _ = api("POST", {"loki.uri": "https://127.0.0.1:3100",
        "loki.authorization": "Basic dGVzdDpjYW5hcnk="}, current["version"])
    require(status == 200, "Loki repair was blocked by the other legacy optional group.")
    restart(loki_disabled=False)
    status, disabled, _ = api("POST", {"loki.uri": None, "loki.authorization": None,
        "opentelemetry.otlp_endpoint": None}, repaired["version"])
    require(status == 200, "Explicit optional group disable failed.")
    restart(loki_disabled=False, otlp_disabled=False)
    final = stored()
    require(final["version"] == disabled["version"] and all(key not in final["values"] for key in
        ["loki.uri", "loki.authorization", "opentelemetry.otlp_endpoint"]), "Disabled optional values remain stored.")
    print("Optional settings container recovery smoke passed: read/update/reject/restart/repair/disable.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file")
    parser.add_argument("--admin", default="smoke_admin")
    parser.add_argument("--postgres", default="signacore-smoke-pg")
    parser.add_argument("--app", default="signacore-smoke-app")
    parser.add_argument("--database", default="signacore")
    parser.add_argument("--url", default="http://localhost:5002")
    try:
        run(parser.parse_args())
    except SmokeFailure as failure:
        raise SystemExit(str(failure)) from None
    except (OSError, ValueError, KeyError):
        # No raw database, response, request, or subprocess details cross this output boundary.
        raise SystemExit("Optional settings container recovery smoke failed.") from None
