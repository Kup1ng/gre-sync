#!/usr/bin/env python3
import asyncio
import ipaddress
import json
import os
import re
import signal
import subprocess
import time
import random
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Any

import aiohttp
from aiohttp import web

try:
    import yaml
except ImportError:
    print("Missing dependency: pyyaml. Install: pip install pyyaml aiohttp")
    raise

# ---------------------------
# Helpers: shell + parsing
# ---------------------------

def sh(cmd: List[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()

def now_ms() -> int:
    return int(time.time() * 1000)

IF_RE = re.compile(r"^(gre-(ir|kh)-(\d+))$")

@dataclass
class GreIface:
    name: str
    side: str   # "ir" or "kh" (based on name)
    num: str    # suffix number as string
    local_public: str
    peer_public: str
    local_private: str
    peer_private: str

def other_side(side: str) -> str:
    return "kh" if side == "ir" else "ir"

def peer_ifname(iface: GreIface) -> str:
    return f"gre-{other_side(iface.side)}-{iface.num}"

def parse_gre_ifaces() -> Dict[str, GreIface]:
    """
    Detect GRE interfaces by name pattern gre-ir-N / gre-kh-N
    Extract:
      - local_public + peer_public from `ip -o link show`
      - local_private from `ip -o -4 addr show dev`
      - peer_private computed from /30
    """
    link_out = sh(["ip", "-o", "link", "show"])
    link_lines = link_out.splitlines()

    pub_map: Dict[str, Tuple[str, str]] = {}
    for line in link_lines:
        m = re.search(r":\s+(\S+?)@.*\s+.*link/gre\s+(\S+)\s+peer\s+(\S+)", line)
        if not m:
            continue
        ifname = m.group(1)
        local_pub = m.group(2)
        peer_pub = m.group(3)
        if IF_RE.match(ifname):
            pub_map[ifname] = (local_pub, peer_pub)

    if not pub_map:
        return {}

    addr_out = sh(["ip", "-o", "-4", "addr", "show"])
    addr_lines = addr_out.splitlines()
    v4_map: Dict[str, str] = {}
    for line in addr_lines:
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        ifname = m.group(1)
        if IF_RE.match(ifname):
            ip = m.group(2)
            prefix = int(m.group(3))
            v4_map[ifname] = f"{ip}/{prefix}"

    res: Dict[str, GreIface] = {}
    for ifname, (local_pub, peer_pub) in pub_map.items():
        m = IF_RE.match(ifname)
        if not m:
            continue
        side = m.group(2)
        num = m.group(3)

        cidr = v4_map.get(ifname)
        if not cidr:
            continue

        iface_ip = ipaddress.ip_interface(cidr)
        net = iface_ip.network
        hosts = list(net.hosts())
        if len(hosts) < 2:
            continue
        local_priv = str(iface_ip.ip)
        peer_priv = str(hosts[0] if str(hosts[1]) == local_priv else hosts[1])

        res[ifname] = GreIface(
            name=ifname,
            side=side,
            num=num,
            local_public=local_pub,
            peer_public=peer_pub,
            local_private=local_priv,
            peer_private=peer_priv,
        )
    return res

async def ping_loss_percent(ip: str, count: int, timeout_sec: int) -> Optional[float]:
    cmd = ["ping", "-n", "-q", "-c", str(count), "-W", str(timeout_sec), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await proc.communicate()
        txt = out.decode(errors="ignore")
        m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", txt)
        if not m:
            return None
        return float(m.group(1))
    except Exception:
        return None

async def ip_link_set(ifname: str, state: str) -> bool:
    cmd = ["ip", "link", "set", "dev", ifname, state]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False

# ---------------------------
# Core daemon
# ---------------------------

class GreSyncD:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.role = cfg.get("role", "ir").strip()
        self.listen = cfg.get("listen", "0.0.0.0")
        self.port = int(cfg.get("port", 8787))
        self.token = cfg.get("token", "")

        self.check_interval = int(cfg.get("check_interval_sec", 30))
        self.ping_count = int(cfg.get("ping_count", 7))
        self.ping_timeout = int(cfg.get("ping_timeout_sec", 1))
        self.loss_ok = float(cfg.get("loss_ok_percent", 20))
        self.fail_rounds = int(cfg.get("fail_confirm_rounds", 3))
        self.reset_wait = int(cfg.get("reset_wait_sec", 300))

        # retry tuning (optional in config)
        self.http_tries = int(cfg.get("http_tries", 3))
        self.http_timeout = int(cfg.get("http_timeout_sec", 6))
        self.http_backoff_base = float(cfg.get("http_backoff_base", 0.7))
        self.http_backoff_cap = float(cfg.get("http_backoff_cap", 6.0))
        self.http_jitter_ratio = float(cfg.get("http_jitter_ratio", 0.25))

        # state
        self._stop = asyncio.Event()
        self._locks: Dict[str, asyncio.Lock] = {}
        self._bad_streak: Dict[str, int] = {}
        self._session: Optional[aiohttp.ClientSession] = None

    def log(self, *a):
        print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", *a, flush=True)

    def auth_ok(self, request: web.Request) -> bool:
        got = request.headers.get("Authorization", "")
        return got == f"Bearer {self.token}"

    def lock_for(self, key: str) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    # ----- API handlers -----

    async def api_status(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)
        ifaces = parse_gre_ifaces()
        return web.json_response({
            "ok": True,
            "role": self.role,
            "ts_ms": now_ms(),
            "ifaces": {k: {
                "side": v.side,
                "num": v.num,
                "peer_public": v.peer_public,
                "peer_private": v.peer_private,
            } for k, v in ifaces.items()}
        })

    async def api_action(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)

        data = await request.json()
        action = data.get("action")
        ifname = data.get("ifname")
        if not ifname or not IF_RE.match(ifname):
            return web.json_response({"ok": False, "err": "bad ifname"}, status=400)

        if action not in ("down", "up"):
            return web.json_response({"ok": False, "err": "bad action"}, status=400)

        ok = await ip_link_set(ifname, action)
        self.log(f"API action {action} on {ifname} -> {ok}")
        return web.json_response({"ok": ok, "ifname": ifname, "action": action})

    async def api_barrier(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)
        data = await request.json()
        ifname = data.get("ifname")
        if not ifname or not IF_RE.match(ifname):
            return web.json_response({"ok": False, "err": "bad ifname"}, status=400)

        ifaces = parse_gre_ifaces()
        ready = ifname in ifaces
        return web.json_response({"ok": True, "ready": ready, "ts_ms": now_ms()})

    # ----- Coordination (HTTP with retry) -----

    async def call_peer(self, peer_ip: str, path: str, payload: dict, timeout: int = 5) -> dict:
        if not self._session:
            raise RuntimeError("HTTP session not ready")
        url = f"http://{peer_ip}:{self.port}{path}"
        headers = {"Authorization": f"Bearer {self.token}"}
        async with self._session.post(url, json=payload, headers=headers, timeout=timeout) as r:
            return await r.json()

    async def call_peer_retry(
        self,
        peer_ip: str,
        path: str,
        payload: dict,
        timeout: Optional[int] = None,
        tries: Optional[int] = None,
        backoff_base: Optional[float] = None,
        backoff_cap: Optional[float] = None,
    ) -> dict:
        """
        Retry wrapper for peer HTTP calls with exponential backoff + jitter.
        If all tries fail, returns {"ok": False, ...}.
        """
        timeout = int(timeout if timeout is not None else self.http_timeout)
        tries = int(tries if tries is not None else self.http_tries)
        backoff_base = float(backoff_base if backoff_base is not None else self.http_backoff_base)
        backoff_cap = float(backoff_cap if backoff_cap is not None else self.http_backoff_cap)

        last_err = None
        for attempt in range(1, tries + 1):
            try:
                return await self.call_peer(peer_ip, path, payload, timeout=timeout)
            except Exception as e:
                last_err = str(e)
                if attempt >= tries:
                    break
                delay = min(backoff_cap, backoff_base * (2 ** (attempt - 1)))
                delay = delay + random.uniform(0, self.http_jitter_ratio * delay)
                self.log(f"peer retry {attempt}/{tries} {peer_ip}{path} err={e} sleep={delay:.2f}s")
                await asyncio.sleep(delay)

        return {"ok": False, "err": "peer_unreachable", "detail": last_err, "path": path, "peer": peer_ip}

    async def coordinated_reset_as_leader(self, iface: GreIface):
        """
        Leader (Iran) does:
          - barrier with peer (with retry)
          - DOWN local+peer (parallel) (peer DOWN must succeed or abort)
          - wait reset_wait
          - UP local
          - UP peer (with stronger retry)
        """
        key = f"{iface.peer_public}:{iface.num}"
        lock = self.lock_for(key)
        if lock.locked():
            self.log(f"[{iface.name}] reset already running, skip")
            return

        async with lock:
            peer_name = peer_ifname(iface)
            self.log(f"[{iface.name}] Coordinated reset START with {iface.peer_public} peer_if={peer_name}")

            # barrier (must succeed, otherwise abort)
            b = await self.call_peer_retry(iface.peer_public, "/barrier", {"ifname": peer_name}, timeout=6, tries=3)
            if not b.get("ok") or not b.get("ready"):
                self.log(f"[{iface.name}] peer barrier not ready -> {b}")
                return

            # down both (peer down must succeed or we abort and restore local up)
            down_peer_task = self.call_peer_retry(
                iface.peer_public, "/action", {"action": "down", "ifname": peer_name}, timeout=8, tries=3
            )
            down_local_task = ip_link_set(iface.name, "down")

            r_peer, r_local = await asyncio.gather(down_peer_task, down_local_task, return_exceptions=True)

            peer_down_ok = isinstance(r_peer, dict) and r_peer.get("ok") is True
            local_down_ok = (r_local is True)
            self.log(f"[{iface.name}] DOWN local={local_down_ok} peer={r_peer}")

            if not peer_down_ok:
                # prevent mismatch: bring local back up and abort
                self.log(f"[{iface.name}] peer DOWN failed -> abort reset, restoring local UP")
                await ip_link_set(iface.name, "up")
                return

            await asyncio.sleep(self.reset_wait)

            # up local first
            up_local_ok = await ip_link_set(iface.name, "up")
            self.log(f"[{iface.name}] UP local -> {up_local_ok}")

            # then peer up (more retries because peer may be slow)
            r_up = await self.call_peer_retry(
                iface.peer_public, "/action", {"action": "up", "ifname": peer_name},
                timeout=8, tries=5, backoff_base=1.0, backoff_cap=12.0
            )
            self.log(f"[{iface.name}] UP peer -> {r_up}")

            self.log(f"[{iface.name}] Coordinated reset END")

    async def follower_report(self, iface: GreIface):
        """
        On KH side when it detects "public ok but private gre bad",
        it tells IR leader to run reset. Use retry (transient outages).
        """
        leader_ip = iface.peer_public
        payload = {"ifnum": iface.num, "from_if": iface.name, "from_peer": iface.local_public}
        r = await self.call_peer_retry(
            leader_ip, "/report", payload,
            timeout=8, tries=5, backoff_base=1.0, backoff_cap=15.0
        )
        if not r.get("ok"):
            self.log(f"[{iface.name}] report leader failed -> {r}")

    # ----- Monitoring loop -----

    async def check_one(self, iface: GreIface) -> Tuple[bool, bool]:
        loss_pub = await ping_loss_percent(iface.peer_public, self.ping_count, self.ping_timeout)
        loss_prv = await ping_loss_percent(iface.peer_private, self.ping_count, self.ping_timeout)

        pub_ok = (loss_pub is not None) and (loss_pub < self.loss_ok)
        prv_ok = (loss_prv is not None) and (loss_prv < self.loss_ok)
        return pub_ok, prv_ok

    async def monitor_loop(self):
        self._session = aiohttp.ClientSession()

        try:
            while not self._stop.is_set():
                ifaces = parse_gre_ifaces()
                if not ifaces:
                    self.log("No GRE ifaces found. Sleeping...")
                    await asyncio.sleep(self.check_interval)
                    continue

                tasks = {name: asyncio.create_task(self.check_one(iface)) for name, iface in ifaces.items()}
                results: Dict[str, Tuple[bool, bool]] = {}
                for name, t in tasks.items():
                    try:
                        results[name] = await t
                    except Exception:
                        results[name] = (False, False)

                for name, (pub_ok, prv_ok) in results.items():
                    iface = ifaces[name]

                    if pub_ok and prv_ok:
                        self._bad_streak[name] = 0
                        continue

                    if (not pub_ok) and (not prv_ok):
                        # filtered / total outage -> do nothing
                        self._bad_streak[name] = 0
                        continue

                    if pub_ok and (not prv_ok):
                        self._bad_streak[name] = self._bad_streak.get(name, 0) + 1
                        streak = self._bad_streak[name]
                        self.log(f"[{name}] public OK, private BAD streak={streak}")

                        if streak >= self.fail_rounds:
                            self._bad_streak[name] = 0

                            if self.role == "ir" and iface.side == "ir":
                                asyncio.create_task(self.coordinated_reset_as_leader(iface))
                            elif self.role == "kh" and iface.side == "kh":
                                asyncio.create_task(self.follower_report(iface))
                    else:
                        self._bad_streak[name] = 0

                await asyncio.sleep(self.check_interval)
        finally:
            await self._session.close()

    # ----- Leader report endpoint -----

    async def api_report(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)

        if self.role != "ir":
            return web.json_response({"ok": False, "err": "not leader"}, status=400)

        data = await request.json()
        ifnum = str(data.get("ifnum", "")).strip()
        if not ifnum.isdigit():
            return web.json_response({"ok": False, "err": "bad ifnum"}, status=400)

        ifaces = parse_gre_ifaces()
        target_name = f"gre-ir-{ifnum}"
        iface = ifaces.get(target_name)
        if not iface:
            return web.json_response({"ok": False, "err": f"missing {target_name}"}, status=404)

        asyncio.create_task(self.coordinated_reset_as_leader(iface))
        return web.json_response({"ok": True, "scheduled": target_name})

    async def run(self):
        app = web.Application()
        app.router.add_post("/status", self.api_status)
        app.router.add_post("/action", self.api_action)
        app.router.add_post("/barrier", self.api_barrier)
        app.router.add_post("/report", self.api_report)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.listen, self.port)

        self.log(f"Starting API on {self.listen}:{self.port} role={self.role}")
        await site.start()

        self.log("Starting monitor loop")
        task = asyncio.create_task(self.monitor_loop())

        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, self._stop.set)

        await self._stop.wait()
        self.log("Stopping...")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await runner.cleanup()

def main():
    cfg_path = os.environ.get("GRE_SYNC_CONFIG", "/etc/gre-sync/config.yml")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    d = GreSyncD(cfg)
    asyncio.run(d.run())

if __name__ == "__main__":
    main()
