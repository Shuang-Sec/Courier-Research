#!/usr/bin/env python3
"""Monitor a direct_https agent for short/long survival experiments.

这个脚本只做本地实验记录：

1. 选择最新的 direct_https agent，或使用 --agent-id 指定的 agent；
2. 按固定间隔下发 hello；
3. 按更长间隔下发 pwd 和 cmd echo；
4. 把每一次提交、完成情况、agent tick 记录成 JSON。

它不负责启动 loader。启动由 run-profile-only-loader-test.sh 完成。
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Api:
    def __init__(self, base: str, username: str, password: str):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.ctx = ssl._create_unverified_context()
        self.token: str | None = None

    def request(self, path: str, method: str = "GET", data=None, timeout: int = 30):
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
                return {"_status": resp.status}
            obj = json.loads(raw)
            if isinstance(obj, dict):
                obj.setdefault("_status", resp.status)
            return obj

    def login(self):
        self.token = None
        obj = self.request("/login", "POST", {
            "username": self.username,
            "password": self.password,
            "version": "direct-https-survival-monitor",
        })
        self.token = obj["access_token"]

    def agents(self):
        return self.request("/agent/list")

    def direct_agents(self):
        agents = self.agents()
        direct = [a for a in agents if a.get("a_name") == "direct_https"]
        direct.sort(key=lambda a: int(a.get("a_last_tick") or 0), reverse=True)
        return direct

    def tasks(self, agent_id: str, limit: int = 200):
        qs = urllib.parse.urlencode({"agent_id": agent_id, "limit": limit})
        return self.request("/agent/task/list?" + qs)

    def raw(self, agent_id: str, cmdline: str):
        return self.request("/agent/command/raw", "POST", {"id": agent_id, "cmdline": cmdline})


def summarize_task(task):
    if not task:
        return None
    return {
        "task_id": task.get("a_task_id"),
        "cmdline": task.get("a_cmdline"),
        "completed": task.get("a_completed"),
        "message_type": task.get("a_msg_type"),
        "message": task.get("a_message"),
        "text_preview": (task.get("a_text") or "")[:300],
        "start_time": task.get("a_start_time"),
        "finish_time": task.get("a_finish_time"),
    }


def wait_completed(api: Api, agent_id: str, cmdline: str, not_before: int, timeout: int):
    deadline = time.time() + timeout
    while time.time() < deadline:
        tasks = api.tasks(agent_id)
        if isinstance(tasks, list):
            matches = [
                t for t in tasks
                if t.get("a_cmdline") == cmdline
                and t.get("a_completed")
                and int(t.get("a_start_time") or 0) >= not_before
            ]
            if matches:
                matches.sort(key=lambda t: int(t.get("a_start_time") or 0), reverse=True)
                return matches[0]
        time.sleep(1)
    return None


def run_one(api: Api, agent_id: str, cmdline: str, timeout: int):
    not_before = int(time.time())
    entry = {
        "time": now_iso(),
        "cmdline": cmdline,
        "submit_response": None,
        "completed": False,
        "task": None,
        "error": None,
    }
    try:
        resp = api.raw(agent_id, cmdline)
        entry["submit_response"] = resp
        task = wait_completed(api, agent_id, cmdline, not_before, timeout) if resp.get("ok") else None
        entry["completed"] = bool(task)
        entry["task"] = summarize_task(task)
    except Exception as exc:  # noqa: BLE001 - 实验脚本要把异常写进报告
        entry["error"] = repr(exc)
    return entry


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("API_BASE", "https://127.0.0.1:4321/endpoint"))
    parser.add_argument("--username", default=os.environ.get("API_USER", "ctf"))
    parser.add_argument("--password", default=os.environ.get("API_PASS") or os.environ.get("ADAPTIX_PASSWORD", "CHANGE_ME_PASSWORD"))
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--duration-seconds", type=int, default=600)
    parser.add_argument("--hello-interval", type=int, default=300)
    parser.add_argument("--cmd-interval", type=int, default=600)
    parser.add_argument("--task-timeout", type=int, default=45)
    parser.add_argument("--tag", default="survival")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    api = Api(args.base, args.username, args.password)
    api.login()
    direct = api.direct_agents()
    if not direct:
        raise SystemExit("no direct_https agent")
    agent = next((a for a in direct if a.get("a_id") == args.agent_id), direct[0]) if args.agent_id else direct[0]
    agent_id = agent["a_id"]

    result = {
        "started_at": now_iso(),
        "tag": args.tag,
        "duration_seconds": args.duration_seconds,
        "hello_interval": args.hello_interval,
        "cmd_interval": args.cmd_interval,
        "agent_id": agent_id,
        "agent_start": agent,
        "events": [],
    }

    started = time.time()
    next_hello = 0.0
    next_cmd = 0.0
    counter = 0

    while time.time() - started < args.duration_seconds:
        elapsed = time.time() - started
        if elapsed >= next_hello:
            result["events"].append(run_one(api, agent_id, "hello", args.task_timeout))
            next_hello += max(args.hello_interval, 1)
        if elapsed >= next_cmd:
            counter += 1
            result["events"].append(run_one(api, agent_id, "pwd", args.task_timeout))
            result["events"].append(run_one(api, agent_id, f"cmd echo SURVIVAL_{args.tag}_{counter}", args.task_timeout))
            next_cmd += max(args.cmd_interval, 1)
        time.sleep(2)

    # 结束前再做一次 hello，避免刚好错过最后一轮 callback。
    result["events"].append(run_one(api, agent_id, "hello", args.task_timeout))
    latest = [a for a in api.direct_agents() if a.get("a_id") == agent_id]
    result["agent_end"] = latest[0] if latest else None
    result["finished_at"] = now_iso()
    result["completed_count"] = sum(1 for e in result["events"] if e.get("completed"))
    result["event_count"] = len(result["events"])
    result["all_completed"] = result["completed_count"] == result["event_count"]

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "agent_id": agent_id,
        "tag": args.tag,
        "event_count": result["event_count"],
        "completed_count": result["completed_count"],
        "all_completed": result["all_completed"],
        "report": str(out),
    }, ensure_ascii=False, indent=2))
    return 0 if result["completed_count"] == result["event_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
