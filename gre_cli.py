#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import textwrap
import time
from typing import Any, Dict, Optional

CFG = os.environ.get("GRE_SYNC_CONFIG", "/etc/gre-sync/config.yml")

def sh(cmd, check=False) -> str:
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode != 0:
        raise RuntimeError(p.stdout.strip())
    return (p.stdout or "").strip()

def load_cfg() -> Dict[str, Any]:
    try:
        import yaml
    except ImportError:
        print("pyyaml not installed. Run installer or: pip3 install pyyaml")
        sys.exit(1)

    try:
        with open(CFG, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def curl_local(path: str, payload: Dict[str, Any], cfg: Dict[str, Any], timeout=5) -> Dict[str, Any]:
    import urllib.request
    import urllib.error

    listen = cfg.get("listen", "127.0.0.1")
    # If service is listening on 0.0.0.0, call localhost.
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
    input("\nEnter بزن برای برگشت... ")

def print_box(txt: str):
    print("\n" + "=" * 70)
    print(txt)
    print("=" * 70 + "\n")

def pick_iface(ifaces: Dict[str, Any]) -> Optional[str]:
    names = sorted(ifaces.keys())
    if not names:
        print("هیچ GRE پیدا نشد.")
        return None
    for i, n in enumerate(names, 1):
        info = ifaces[n]
        print(f"{i}) {n}  peer_public={info.get('peer_public')}  peer_private={info.get('peer_private')}")
    print("0) انصراف")
    try:
        c = int(input("انتخاب: ").strip() or "0")
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
    # interactive follow
    subprocess.run(["journalctl", "-u", "gre-syncd", "-f"])

def main():
    cfg = load_cfg()
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print_box(menu_title(cfg))

        print("1) وضعیت daemon (API status)")
        print("2) لیست GRE های سیستم (از API)")
        print("3) چک یک‌باره همه GRE ها (daemon خودش موازی چک می‌کند)")
        print("4) ریست هماهنگ یک GRE (Leader: reset / Follower: report)")
        print("5) systemd: start")
        print("6) systemd: stop")
        print("7) systemd: restart")
        print("8) systemd: status")
        print("9) لاگ زنده (journalctl -f)")
        print("0) خروج")

        choice = input("\nانتخاب: ").strip()

        if choice == "0":
            return

        elif choice == "1":
            r = curl_local("/status", {}, cfg)
            print(json.dumps(r, indent=2, ensure_ascii=False))
            pause()

        elif choice == "2":
            r = curl_local("/status", {}, cfg)
            if not r.get("ok"):
                print(json.dumps(r, indent=2, ensure_ascii=False))
                pause()
                continue
            ifaces = r.get("ifaces", {})
            for k in sorted(ifaces.keys()):
                v = ifaces[k]
                print(f"- {k} | peer_public={v.get('peer_public')} | peer_private={v.get('peer_private')}")
            pause()

        elif choice == "3":
            # One-shot check without modifying daemon: ask daemon status and show.
            # The daemon is continuously checking; user can just observe status and logs.
            print("این پروژه به صورت daemon دائم چک می‌کنه.")
            print("برای دیدن نتیجه‌ها: گزینه 9 لاگ زنده رو باز کن.")
            pause()

        elif choice == "4":
            r = curl_local("/status", {}, cfg)
            if not r.get("ok"):
                print(json.dumps(r, indent=2, ensure_ascii=False))
                pause()
                continue
            ifaces = r.get("ifaces", {})
            target = pick_iface(ifaces)
            if not target:
                continue

            role = cfg.get("role", "ir")
            if role == "ir":
                # Trigger by calling /report on itself with ifnum extracted from name
                # /report expects ifnum
                num = target.split("-")[-1]
                rr = curl_local("/report", {"ifnum": num, "from_if": "cli", "from_peer": "local"}, cfg, timeout=8)
                print(json.dumps(rr, indent=2, ensure_ascii=False))
                print("\nاگر ok شد، reset زمان‌بندی شد. لاگ رو ببین (گزینه 9).")
            else:
                # On follower, we don't know leader IP from config; ask from API iface data
                info = ifaces[target]
                leader_ip = info.get("peer_public")
                num = target.split("-")[-1]
                if not leader_ip:
                    print("leader ip پیدا نشد (peer_public خالیه).")
                    pause()
                    continue

                # call leader /report using curl command (no extra deps)
                token = cfg.get("token", "")
                port = int(cfg.get("port", 8787))
                payload = json.dumps({"ifnum": num, "from_if": target, "from_peer": "follower"}).encode()

                # Use curl for simplicity
                cmd = [
                    "curl", "-sS", "-m", "8",
                    "-H", f"Authorization: Bearer {token}",
                    "-H", "Content-Type: application/json",
                    "-d", payload.decode(),
                    f"http://{leader_ip}:{port}/report"
                ]
                out = sh(cmd)
                print(out)
                print("\nReport به leader ارسال شد. لاگ leader رو ببین.")
            pause()

        elif choice == "5":
            service_ctl("start")
            pause()
        elif choice == "6":
            service_ctl("stop")
            pause()
        elif choice == "7":
            service_ctl("restart")
            pause()
        elif choice == "8":
            service_status()
            pause()
        elif choice == "9":
            logs_follow()
        else:
            print("گزینه نامعتبر.")
            time.sleep(1)

if __name__ == "__main__":
    main()
