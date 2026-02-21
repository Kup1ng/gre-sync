#!/usr/bin/env python3
import asyncio
import ipaddress
import os
import re
import signal
import subprocess
import time
import random
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Any, Set

import aiohttp
from aiohttp import web

try:
    import yaml
except ImportError:
    print("Missing dependency: pyyaml. Install inside venv: pip install pyyaml aiohttp")
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
      - local_private from `ip -o -4 addr show`
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


async def ping_loss_percent(dest_ip: str, count: int, timeout_sec: int, source_ip: Optional[str] = None) -> Optional[float]:
    cmd = ["ping", "-n", "-q", "-c", str(count), "-W", str(timeout_sec)]
    if source_ip:
        cmd += ["-I", str(source_ip)]
    cmd += [dest_ip]
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


def is_iface_up(ifname: str) -> bool:
    """
    Returns True if the interface appears administratively UP.
    We treat "state DOWN" or missing "UP" flag as not-up.
    """
    try:
        line = sh(["ip", "-o", "link", "show", "dev", ifname])
    except Exception:
        return False

    # Example: "24: gre-ir-15@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> ... state UNKNOWN ..."
    flags = re.search(r"<([^>]+)>", line)
    if flags and "UP" in flags.group(1).split(","):
        # admin up
        return True

    # fallback: state UP
    if " state UP" in line:
        return True

    return False


async def ip_link_set(ifname: str, state: str) -> bool:
    cmd = ["ip", "link", "set", "dev", ifname, state]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False


# ---------------------------
# Core daemon
# ---------------------------

class GreSyncD:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.role = str(cfg.get("role", "ir")).strip().lower()
        self.listen = cfg.get("listen", "0.0.0.0")
        self.port = int(cfg.get("port", 8787))
        self.token = str(cfg.get("token", ""))

        # IR: full GRE healthcheck loop
        self.check_interval = int(cfg.get("check_interval_sec", 30))
        self.ping_count = int(cfg.get("ping_count", 7))
        self.ping_timeout = int(cfg.get("ping_timeout_sec", 1))
        self.loss_ok = float(cfg.get("loss_ok_percent", 20))
        self.fail_rounds = int(cfg.get("fail_confirm_rounds", 3))
        self.reset_wait = int(cfg.get("reset_wait_sec", 300))

        # KH: control-plane (ping IR public) before accepting actions
        self.kh_ctl_ping_count = int(cfg.get("kh_ctl_ping_count", 3))
        self.kh_ctl_ping_timeout = int(cfg.get("kh_ctl_ping_timeout_sec", 1))

        # retry tuning (optional in config)
        self.http_tries = int(cfg.get("http_tries", 3))
        self.http_timeout = int(cfg.get("http_timeout_sec", 6))
        self.http_backoff_base = float(cfg.get("http_backoff_base", 0.7))
        self.http_backoff_cap = float(cfg.get("http_backoff_cap", 6.0))
        self.http_jitter_ratio = float(cfg.get("http_jitter_ratio", 0.25))

        # explicit leader ip (recommended on KH)
        self.leader_public_ip = str(cfg.get("leader_public_ip", "")).strip() or None

        # state
        self._stop = asyncio.Event()
        self._locks: Dict[str, asyncio.Lock] = {}
        self._bad_streak: Dict[str, int] = {}
        self._resetting: Set[str] = set()  # local ifnames currently in reset window (IR only)
        self._session: Optional[aiohttp.ClientSession] = None

        # KH control-plane health
        self._kh_leader_ok: Optional[bool] = None
        self._kh_leader_loss: Optional[float] = None
        self._kh_leader_last_ts: Optional[int] = None

    def log(self, *a):
        print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", *a, flush=True)

    def auth_ok(self, request: web.Request) -> bool:
        got = request.headers.get("Authorization", "")
        return got == f"Bearer {self.token}"

    def lock_for(self, key: str) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    def get_leader_ip(self) -> Optional[str]:
        """
        For KH: determine Iran public IP.
        Priority:
          1) config leader_public_ip
          2) derive from any gre-kh-* interface peer_public
        """
        if self.leader_public_ip:
            return self.leader_public_ip
        ifaces = parse_gre_ifaces()
        for iface in ifaces.values():
            if iface.side == "kh":
                return iface.peer_public
        return None

    # ----- API handlers -----

    async def api_status(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)

        ifaces = parse_gre_ifaces()
        data: Dict[str, Any] = {
            "ok": True,
            "role": self.role,
            "ts_ms": now_ms(),
            "ifaces": {k: {
                "side": v.side,
                "num": v.num,
                "peer_public": v.peer_public,
                "peer_private": v.peer_private,
                "link_up": is_iface_up(k),
                "resetting": (k in self._resetting),
            } for k, v in ifaces.items()},
        }

        if self.role == "kh":
            data["leader_public_ip"] = self.get_leader_ip()
            data["leader_ping_ok"] = self._kh_leader_ok
            data["leader_ping_loss"] = self._kh_leader_loss
            data["leader_ping_ts_ms"] = self._kh_leader_last_ts

        return web.json_response(data)

    async def api_barrier(self, request: web.Request):
        """
        Leader calls follower to confirm follower is reachable and has the target iface.
        """
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)
        data = await request.json()
        ifname = data.get("ifname")
        if not ifname or not IF_RE.match(ifname):
            return web.json_response({"ok": False, "err": "bad ifname"}, status=400)

        ifaces = parse_gre_ifaces()
        ready = ifname in ifaces
        return web.json_response({"ok": True, "ready": ready, "ts_ms": now_ms()})

    async def api_action(self, request: web.Request):
        """
        IR sends DOWN/UP to KH. KH will refuse if it cannot ping IR public (control-plane unstable).
        """
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)

        data = await request.json()
        action = data.get("action")
        ifname = data.get("ifname")
        if not ifname or not IF_RE.match(ifname):
            return web.json_response({"ok": False, "err": "bad ifname"}, status=400)
        if action not in ("down", "up"):
            return web.json_response({"ok": False, "err": "bad action"}, status=400)

        # On KH: require control-plane ping to leader to be healthy
        if self.role == "kh":
            leader_ip = self.get_leader_ip()
            if not leader_ip:
                msg = "leader_public_ip not set and cannot be derived from gre-kh-*"
                self.log(f"[{ifname}] REFUSE {action}: {msg}")
                return web.json_response({"ok": False, "err": "leader_unknown", "detail": msg}, status=503)

            ifaces = parse_gre_ifaces()
            src_iface = ifaces.get(ifname)
            if not src_iface:
                msg = f"iface {ifname} not found for control-plane ping"
                self.log(f"[{ifname}] REFUSE {action}: {msg}")
                return web.json_response({"ok": False, "err": "iface_missing", "detail": msg}, status=503)
            loss = await ping_loss_percent(leader_ip, self.kh_ctl_ping_count, self.kh_ctl_ping_timeout, source_ip=src_iface.local_public)
            ok = (loss is not None) and (loss < self.loss_ok)
            self._kh_leader_ok = ok
            self._kh_leader_loss = loss
            self._kh_leader_last_ts = now_ms()

            if not ok:
                msg = f"control-plane ping to leader {leader_ip} not ok (loss={loss})"
                self.log(f"[{ifname}] REFUSE {action}: {msg}")
                return web.json_response({"ok": False, "err": "leader_unreachable", "loss": loss, "leader": leader_ip}, status=503)

        # Execute action
        ok = await ip_link_set(ifname, action)
        self.log(f"API action {action} on {ifname} -> {ok}")
        return web.json_response({"ok": ok, "ifname": ifname, "action": action})

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
        IR leader sequence (as requested):
          - barrier with KH (must succeed)
          - DOWN peer (KH) first; only if it confirms DOWN -> DOWN local (IR)
          - wait reset_wait
          - UP peer (KH) first; only if it confirms UP -> wait 3s -> UP local (IR)

        Notes:
          - local iface stays in self._resetting for the whole window, so monitoring skips it.
          - if peer DOWN/UP can't be confirmed, we abort to avoid desync.
        """
        if self.role != "ir":
            return

        key = f"{iface.peer_public}:{iface.num}"
        lock = self.lock_for(key)
        if lock.locked():
            self.log(f"[{iface.name}] reset already running, skip")
            return

        async with lock:
            if iface.name in self._resetting:
                self.log(f"[{iface.name}] already in resetting set, skip")
                return

            peer_name = peer_ifname(iface)
            self._resetting.add(iface.name)
            try:
                self.log(f"[{iface.name}] Coordinated reset START peer={iface.peer_public} peer_if={peer_name}")

                # barrier
                b = await self.call_peer_retry(iface.peer_public, "/barrier", {"ifname": peer_name}, timeout=6, tries=3)
                if not b.get("ok") or not b.get("ready"):
                    self.log(f"[{iface.name}] barrier failed/not-ready -> {b}")
                    return

                # 1) DOWN peer first
                r_peer_down = await self.call_peer_retry(
                    iface.peer_public, "/action", {"action": "down", "ifname": peer_name}, timeout=10, tries=3
                )
                peer_down_ok = isinstance(r_peer_down, dict) and (r_peer_down.get("ok") is True)
                self.log(f"[{iface.name}] DOWN peer -> {r_peer_down}")

                if not peer_down_ok:
                    self.log(f"[{iface.name}] peer DOWN not confirmed -> abort reset (local unchanged)")
                    return

                # 2) DOWN local only after peer DOWN confirmed
                local_down_ok = await ip_link_set(iface.name, "down")
                self.log(f"[{iface.name}] DOWN local -> {local_down_ok}")
                if not local_down_ok:
                    # try to bring peer back up to reduce mismatch
                    self.log(f"[{iface.name}] local DOWN failed; trying to restore peer UP")
                    await self.call_peer_retry(
                        iface.peer_public, "/action", {"action": "up", "ifname": peer_name},
                        timeout=10, tries=3, backoff_base=1.0, backoff_cap=10.0
                    )
                    return

                # wait configured time
                await asyncio.sleep(self.reset_wait)

                # 3) UP peer first (retry every 60s until confirmed)
                peer_up_ok = False
                while not self._stop.is_set():
                    r_peer_up = await self.call_peer_retry(
                        iface.peer_public, "/action", {"action": "up", "ifname": peer_name},
                        timeout=10, tries=5, backoff_base=1.0, backoff_cap=12.0
                    )
                    peer_up_ok = isinstance(r_peer_up, dict) and (r_peer_up.get("ok") is True)
                    self.log(f"[{iface.name}] UP peer -> {r_peer_up}")

                    if peer_up_ok:
                        break

                    # Do NOT bring local up; keep it DOWN and retry later
                    self.log(f"[{iface.name}] peer UP not confirmed; retrying in 60s (local stays DOWN)")
                    await asyncio.sleep(60)

                if not peer_up_ok:
                    # stop requested
                    self.log(f"[{iface.name}] stop requested while waiting for peer UP; aborting with local DOWN")
                    return

                # 4) wait 3 seconds then UP local
                await asyncio.sleep(3)
                local_up_ok = await ip_link_set(iface.name, "up")
                self.log(f"[{iface.name}] UP local -> {local_up_ok}")

                self.log(f"[{iface.name}] Coordinated reset END")

            finally:
                self._resetting.discard(iface.name)
    # ----- Leader-only reset endpoint -----

    async def api_reset(self, request: web.Request):
        if not self.auth_ok(request):
            return web.json_response({"ok": False, "err": "unauthorized"}, status=401)

        if self.role != "ir":
            return web.json_response({"ok": False, "err": "not_leader"}, status=400)

        data = await request.json()
        ifname = data.get("ifname")
        ifnum = str(data.get("ifnum", "")).strip()

        ifaces = parse_gre_ifaces()
        target: Optional[GreIface] = None

        if ifname and IF_RE.match(ifname):
            target = ifaces.get(ifname)
        elif ifnum.isdigit():
            target = ifaces.get(f"gre-ir-{ifnum}")

        if not target:
            return web.json_response({"ok": False, "err": "not_found", "detail": "missing target iface"}, status=404)

        asyncio.create_task(self.coordinated_reset_as_leader(target))
        return web.json_response({"ok": True, "scheduled": target.name})

    # ----- Monitoring loops -----

    async def check_one(self, iface: GreIface) -> Tuple[bool, bool]:
        loss_pub = await ping_loss_percent(iface.peer_public, self.ping_count, self.ping_timeout, source_ip=iface.local_public)
        loss_prv = await ping_loss_percent(iface.peer_private, self.ping_count, self.ping_timeout, source_ip=iface.local_private)

        pub_ok = (loss_pub is not None) and (loss_pub < self.loss_ok)
        prv_ok = (loss_prv is not None) and (loss_prv < self.loss_ok)
        return pub_ok, prv_ok

    async def monitor_loop_ir(self):
        """
        Only on IR:
        - check gre-ir-* interfaces concurrently
        - skip interfaces that are DOWN or currently in reset window
        """
        assert self._session is not None

        while not self._stop.is_set():
            ifaces = parse_gre_ifaces()
            if not ifaces:
                self.log("No GRE ifaces found. Sleeping...")
                await asyncio.sleep(self.check_interval)
                continue

            # only local IR gre
            ir_ifaces = {n: i for n, i in ifaces.items() if i.side == "ir"}

            # filter out resetting/down
            active_ifaces: Dict[str, GreIface] = {}
            for name, iface in ir_ifaces.items():
                if name in self._resetting:
                    self._bad_streak[name] = 0
                    continue
                if not is_iface_up(name):
                    self._bad_streak[name] = 0
                    continue
                active_ifaces[name] = iface

            # check all concurrently
            tasks = {name: asyncio.create_task(self.check_one(iface)) for name, iface in active_ifaces.items()}
            results: Dict[str, Tuple[bool, bool]] = {}

            for name, t in tasks.items():
                try:
                    results[name] = await t
                except Exception:
                    results[name] = (False, False)

            for name, (pub_ok, prv_ok) in results.items():
                iface = active_ifaces[name]

                # rule table (your original logic)
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
                        asyncio.create_task(self.coordinated_reset_as_leader(iface))
                else:
                    # odd states -> ignore
                    self._bad_streak[name] = 0

            await asyncio.sleep(self.check_interval)

    async def monitor_loop_kh(self):
        """
        Only on KH:
        - do NOT check GRE health
        - only keep a cached ping status to IR public (control-plane)
        """
        assert self._session is not None

        while not self._stop.is_set():
            leader_ip = self.get_leader_ip()
            if leader_ip:
                # pick a deterministic source IP from any local gre-kh-* (so ping uses correct src)
                ifaces = parse_gre_ifaces()
                src_ip = None
                for _n, _i in ifaces.items():
                    if _i.side == "kh":
                        src_ip = _i.local_public
                        break
                if not src_ip:
                    src_ip = None
                loss = await ping_loss_percent(leader_ip, self.kh_ctl_ping_count, self.kh_ctl_ping_timeout, source_ip=src_ip)
                ok = (loss is not None) and (loss < self.loss_ok)
                self._kh_leader_ok = ok
                self._kh_leader_loss = loss
                self._kh_leader_last_ts = now_ms()
            await asyncio.sleep(self.check_interval)

    async def monitor_loop(self):
        self._session = aiohttp.ClientSession()
        try:
            if self.role == "kh":
                self.log("Role=kh: GRE healthcheck disabled; running control-plane ping monitor only.")
                await self.monitor_loop_kh()
            else:
                self.log("Role=ir: running GRE healthcheck monitor.")
                await self.monitor_loop_ir()
        finally:
            await self._session.close()

    async def run(self):
        app = web.Application()
        app.router.add_post("/status", self.api_status)
        app.router.add_post("/action", self.api_action)
        app.router.add_post("/barrier", self.api_barrier)
        app.router.add_post("/reset", self.api_reset)

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
