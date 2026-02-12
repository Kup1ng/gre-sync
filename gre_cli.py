#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, Optional, Tuple

CFG = os.environ.get("GRE_SYNC_CONFIG", "/etc/gre-sync/config.yml")

DEFAULT_REPO_RAW = "https://raw.githubusercontent.com/Kup1ng/gre-sync/main"

def sh(cmd, check=False) -> str:
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode != 0:
        raise RuntimeError(p.stdout.strip())
    return (p.stdout or "").strip()

def load_cfg() -> Dict[str, Any]:
    try:
        import yaml
    except ImportError:
        print("pyyaml not installed. Run installer.")
        sys.exit(1)

    try:
        with open(CFG, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def api_call_local(path: str, payload: Dict[str, Any], cfg: Dict[str, Any], timeout=5) -> Dict[str, Any]:
    import urllib.request
    import urllib.error

    listen = cfg.get("listen", "127.0.0.1")
    host = "127.0.0.1" if listen == "0.0.0.0" else listen
    port = int(cfg.get("port", 8787))
    token = cfg.get("token", "")
    url = f"http://{host}:{port}{path}"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return {"ok": False, "err": f"http {e.code}", "body": body}
    except Exception as e:
        return {"ok": False, "err": str(e)}

def menu_title(cfg: Dict[str, Any]) -> str:
    role = cfg.get("role", "?")
    port = cfg.get("port", 8787)
    return f"GRE Menu (role={role}, api_port={port})"

def pause():
    input("\nPress Enter to go back... ")

def print_box(txt: str):
    print("\n" + "=" * 72)
    print(txt)
    print("=" * 72 + "\n")

def pick_iface(ifaces: Dict[str, Any]) -> Optional[str]:
    names = sorted(ifaces.keys())
    if not names:
        print("No GRE interfaces found.")
        return None
    for i, n in enumerate(names, 1):
        info = ifaces[n]
        print(f"{i}) {n}  peer_public={info.get('peer_public')}  peer_private={info.get('peer_private')}  link_up={info.get('link_up')}  resetting={info.get('resetting')}")
    print("0) Cancel")
    try:
        c = int(input("Select: ").strip() or "0")
    except ValueError:
        return None
    if c == 0:
        return None
    if 1 <= c <= len(names):
        return names[c-1]
    return None

def service_ctl(action: str):
    print(sh(["systemctl", action, "gre-syncd"]))

def service_status():
    print(sh(["systemctl", "status", "gre-syncd", "--no-pager"]))

def logs_follow():
    subprocess.run(["journalctl", "-u", "gre-syncd", "-f"])

def detect_repo_raw(cfg: Dict[str, Any]) -> str:
    return str(cfg.get("repo_raw_base", DEFAULT_REPO_RAW)).rstrip("/")

def download_to(path: str, url: str):
    if shutil_which("curl"):
        sh(["curl", "-fsSL", url, "-o", path], check=True)
    elif shutil_which("wget"):
        sh(["wget", "-qO", path, url], check=True)
    else:
        raise RuntimeError("Neither curl nor wget found")

def shutil_which(cmd: str) -> bool:
    return subprocess.call(["bash", "-lc", f"command -v {cmd} >/dev/null 2>&1"]) == 0

def do_update(cfg: Dict[str, Any]):
    repo = detect_repo_raw(cfg)
    app_dir = "/opt/gre-sync"
    gre_syncd = os.path.join(app_dir, "gre_syncd.py")
    gre_cli = os.path.join(app_dir, "gre_cli.py")

    print(f"Updating from: {repo}")
    tmp1 = gre_syncd + ".new"
    tmp2 = gre_cli + ".new"

    download_to(tmp1, f"{repo}/gre_syncd.py")
    download_to(tmp2, f"{repo}/gre_cli.py")

    os.replace(tmp1, gre_syncd)
    os.replace(tmp2, gre_cli)
    sh(["chmod", "+x", gre_syncd, gre_cli])

    print("Restarting service...")
    sh(["systemctl", "restart", "gre-syncd"], check=True)
    print("Done. (If you changed CLI too, re-run: gre)")

def main():
    cfg = load_cfg()
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print_box(menu_title(cfg))

        print("1) Daemon status (API /status)")
        print("2) List GRE interfaces")
        print("3) Schedule coordinated reset (leader only)")
        print("4) systemd: start")
        print("5) systemd: stop")
        print("6) systemd: restart")
        print("7) systemd: status")
        print("8) Follow logs (journalctl -f)")
        print("9) Update (download latest gre_syncd.py/gre_cli.py and restart)")
        print("0) Exit")

        choice = input("\nSelect: ").strip()

        if choice == "0":
            return

        elif choice == "1":
            r = api_call_local("/status", {}, cfg)
            print(json.dumps(r, indent=2))
            pause()

        elif choice == "2":
            r = api_call_local("/status", {}, cfg)
            if not r.get("ok"):
                print(json.dumps(r, indent=2))
                pause()
                continue
            ifaces = r.get("ifaces", {})
            for k in sorted(ifaces.keys()):
                v = ifaces[k]
                print(f"- {k} | peer_public={v.get('peer_public')} | peer_private={v.get('peer_private')} | link_up={v.get('link_up')} | resetting={v.get('resetting')}")
            if r.get("role") == "kh":
                print("")
                print(f"Leader IP: {r.get('leader_public_ip')}")
                print(f"Leader ping ok: {r.get('leader_ping_ok')} loss={r.get('leader_ping_loss')} ts_ms={r.get('leader_ping_ts_ms')}")
            pause()

        elif choice == "3":
            role = str(cfg.get("role", "ir")).lower()
            if role != "ir":
                print("Reset can only be scheduled on the leader (role=ir).")
                pause()
                continue

            r = api_call_local("/status", {}, cfg)
            if not r.get("ok"):
                print(json.dumps(r, indent=2))
                pause()
                continue

            ifaces = r.get("ifaces", {})
            target = pick_iface(ifaces)
            if not target:
                continue

            num = target.split("-")[-1]
            rr = api_call_local("/reset", {"ifnum": num}, cfg, timeout=8)
            print(json.dumps(rr, indent=2))
            print("\nIf scheduled, watch logs (option 8).")
            pause()

        elif choice == "4":
            service_ctl("start"); pause()
        elif choice == "5":
            service_ctl("stop"); pause()
        elif choice == "6":
            service_ctl("restart"); pause()
        elif choice == "7":
            service_status(); pause()
        elif choice == "8":
            logs_follow()
        elif choice == "9":
            try:
                do_update(cfg)
            except Exception as e:
                print(f"Update failed: {e}")
            pause()
        else:
            print("Invalid choice.")
            time.sleep(1)

if __name__ == "__main__":
    main()
