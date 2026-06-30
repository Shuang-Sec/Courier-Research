#!/usr/bin/env python3
"""Run direct_https baseline commands through the Adaptix HTTP API.

This script is intentionally a lab helper for the local AdaptixC2 workspace.
It logs in, selects the freshest direct_https agent, submits baseline commands,
and polls completed tasks. Upload/download require the agent to be actively
calling back; if no task completes, the report will mark the command pending.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Api:
    def __init__(self, base, username, password, version, insecure=True):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.version = version
        self.ctx = ssl._create_unverified_context() if insecure else None
        self.token = None

    def request(self, path, method="GET", data=None, timeout=30):
        headers = {}
        body = None
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            if not raw:
                return {"_status": resp.status, "_raw": ""}
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    obj.setdefault("_status", resp.status)
                return obj
            except Exception:
                return {"_status": resp.status, "_raw": raw}

    def login(self):
        old = self.token
        self.token = None
        obj = self.request("/login", "POST", {
            "username": self.username,
            "password": self.password,
            "version": self.version,
        })
        self.token = old
        if "access_token" not in obj:
            raise RuntimeError(f"login failed: {obj}")
        self.token = obj["access_token"]
        return obj

    def agents(self):
        return self.request("/agent/list")

    def tasks(self, agent_id, limit=200):
        qs = urllib.parse.urlencode({"agent_id": agent_id, "limit": limit})
        return self.request("/agent/task/list?" + qs)

    def raw(self, agent_id, cmdline):
        return self.request("/agent/command/raw", "POST", {"id": agent_id, "cmdline": cmdline})

    def execute(self, agent_id, cmdline, args, ui=False):
        return self.request("/agent/command/execute", "POST", {
            "id": agent_id,
            "ui": ui,
            "cmdline": cmdline,
            "data": json.dumps(args),
            "ax_hook_id": "",
            "ax_handler_id": "",
            "wait_answer": False,
        })


def summarize_task(task):
    return {
        "task_id": task.get("a_task_id"),
        "cmdline": task.get("a_cmdline"),
        "completed": task.get("a_completed"),
        "message_type": task.get("a_msg_type"),
        "message": task.get("a_message"),
        "text_preview": (task.get("a_text") or "")[:500],
        "finish_time": task.get("a_finish_time"),
    }


def find_completed_task(api, agent_id, cmdline, not_before, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        tasks = api.tasks(agent_id, limit=200)
        if isinstance(tasks, list):
            matches = [t for t in tasks
                       if t.get("a_cmdline") == cmdline
                       and t.get("a_completed")
                       and int(t.get("a_start_time") or 0) >= not_before]
            if matches:
                matches.sort(key=lambda t: int(t.get("a_start_time") or 0), reverse=True)
                return matches[0]
        time.sleep(1)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="https://127.0.0.1:4321/endpoint")
    parser.add_argument("--username", default="ctf")
    parser.add_argument("--password", default="CHANGE_ME_PASSWORD")
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--timeout", type=int, default=35)
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    api = Api(args.base, args.username, args.password, "direct-https-baseline-api")
    result = {
        "started_at": now_iso(),
        "base": args.base,
        "agent_id": None,
        "agent": None,
        "commands": [],
    }

    api.login()
    agents = api.agents()
    if not isinstance(agents, list) or not agents:
        raise RuntimeError(f"no agents returned: {agents}")
    direct = [a for a in agents if a.get("a_name") == "direct_https"]
    if not direct:
        raise RuntimeError("no direct_https agent found")
    direct.sort(key=lambda a: int(a.get("a_last_tick") or 0), reverse=True)
    agent = next((a for a in direct if a.get("a_id") == args.agent_id), direct[0]) if args.agent_id else direct[0]
    agent_id = agent["a_id"]
    result["agent_id"] = agent_id
    result["agent"] = agent

    # Use the agent's known cwd from previous pwd when available; otherwise a conservative user-writable path.
    test_root = rf"C:\Users\{agent.get('a_username','Public')}\Downloads\dh_baseline_{int(time.time())}"
    local_payload = "baseline-direct-https-upload-" + str(int(time.time())) + "\r\n"
    upload_b64 = base64.b64encode(local_payload.encode()).decode()

    cases = [
        ("hello", "raw", None),
        ("cmd echo ADAPTIX_BASELINE_CMD", "raw", None),
        ("powershell Write-Output ADAPTIX_BASELINE_PS", "raw", None),
        ("pwd", "raw", None),
        (f"mkdir {test_root}", "raw", None),
        (f"upload baseline.txt {test_root}\\baseline.txt", "execute", {"command":"upload", "local_file": upload_b64, "remote_path": test_root + r"\\baseline.txt"}),
        (f"ls {test_root}", "raw", None),
        (f"cat {test_root}\\baseline.txt", "raw", None),
        (f"cp {test_root}\\baseline.txt {test_root}\\copy.txt", "raw", None),
        (f"mv {test_root}\\copy.txt {test_root}\\moved.txt", "raw", None),
        (f"download {test_root}\\moved.txt", "raw", None),
        (f"rm {test_root}\\baseline.txt", "raw", None),
        (f"rm {test_root}\\moved.txt", "raw", None),
        (f"rm {test_root}", "raw", None),
    ]

    for cmdline, mode, payload in cases:
        not_before = int(time.time())
        entry = {"cmdline": cmdline, "mode": mode, "submitted_at": now_iso()}
        try:
            if mode == "raw":
                resp = api.raw(agent_id, cmdline)
            else:
                resp = api.execute(agent_id, cmdline, payload)
            entry["submit_response"] = resp
            task = find_completed_task(api, agent_id, cmdline, not_before, args.timeout)
            entry["status"] = "completed" if task else "pending_or_no_callback"
            if task:
                entry["task"] = summarize_task(task)
        except Exception as exc:
            entry["status"] = "error"
            entry["error"] = repr(exc)
        result["commands"].append(entry)
        print(json.dumps(entry, ensure_ascii=False, indent=2))

    result["finished_at"] = now_iso()
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
