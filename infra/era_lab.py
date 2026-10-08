#!/usr/bin/env python3
"""Clone/boot/destroy an *era* lab VM from a datsu era template (B track: CVE replication).

An era template (build_template.py with DATSU_IMAGE=<old cloud image>) is an old-OS base; this
driver clones it, grows the disk, injects cloud-init (static mgmt IP + SSH key), boots it, and waits
for SSH. The vulnerable runtime (old docker/runc/etc) is then installed over SSH by a provisioner,
so datsu's host version-detector sees the vulnerable build and the documented PoC runs host-level.

API-only (clone + config + start are pure Proxmox API ops — no node SSH needed). Author: d3vn0mi.

Usage:
  era_lab.py up   <tid> <vmid> <ip>   # clone template <tid> -> <vmid>, cloud-init <ip>, boot, wait SSH
  era_lab.py down <vmid>              # stop + destroy
"""
import json, os, ssl, sys, time, urllib.parse, urllib.request

ROOT = "/home/d3vn0mi/Desktop/opt/acs_agentic_ctf_solver"
env = {k: v for k, v in (l.strip().split("=", 1) for l in open(f"{ROOT}/.env")
                         if l.strip().startswith("PVE_") and "=" in l)}
URL = env["PVE_URL"].rstrip("/"); NODE = env.get("PVE_NODE", "pve")
TOKEN = f"PVEAPIToken={env['PVE_TOKEN_ID']}={env['PVE_TOKEN_SECRET']}"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
PUBKEY = open(os.path.expanduser("~/.ssh/id_ed25519.pub")).read().strip()
GW = os.environ.get("DATSU_GW", "192.168.60.254")


def req(method, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    r = urllib.request.Request(f"{URL}/api2/json{path}", data=body, method=method,
                               headers={"Authorization": TOKEN,
                                        "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(r, context=CTX, timeout=60) as resp:
        return json.load(resp).get("data")


def wait_task(upid, label, secs=600):
    t0 = time.time()
    while time.time() - t0 < secs:
        st = req("GET", f"/nodes/{NODE}/tasks/{urllib.parse.quote(upid, safe='')}/status")
        if st and st.get("status") == "stopped":
            ok = st.get("exitstatus") == "OK"
            print(f"  [{label}] {st.get('exitstatus')}")
            return ok
        time.sleep(3)
    sys.exit(f"{label} timeout")


def up(tid, vmid, ip):
    print(f"clone template {tid} -> {vmid} …")
    wait_task(req("POST", f"/nodes/{NODE}/qemu/{tid}/clone",
                  {"newid": vmid, "full": 1, "name": f"datsu-era-{vmid}"}), "clone")
    print("grow disk +18G …")
    req("PUT", f"/nodes/{NODE}/qemu/{vmid}/resize", {"disk": "scsi0", "size": "+18G"})
    print("cloud-init (ip + ssh key) …")
    req("PUT", f"/nodes/{NODE}/qemu/{vmid}/config", {
        "ciuser": "root", "cipassword": "datsulab", "nameserver": "1.1.1.1",
        "sshkeys": urllib.parse.quote(PUBKEY, safe=""),
        "ipconfig0": f"ip={ip}/24,gw={GW}",
    })
    print("start …")
    wait_task(req("POST", f"/nodes/{NODE}/qemu/{vmid}/status/start", {}), "start")
    print(f"up: {vmid} @ {ip} (wait for SSH externally)")


def down(vmid):
    try:
        wait_task(req("POST", f"/nodes/{NODE}/qemu/{vmid}/status/stop", {}), "stop", 120)
    except Exception as e:
        print("  stop:", e)
    r = urllib.request.Request(
        f"{URL}/api2/json/nodes/{NODE}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=1",
        method="DELETE", headers={"Authorization": TOKEN})
    with urllib.request.urlopen(r, context=CTX, timeout=60) as resp:
        wait_task(json.load(resp).get("data"), "destroy")
    print(f"down: {vmid} destroyed")


if __name__ == "__main__":
    a = sys.argv
    if len(a) >= 5 and a[1] == "up":
        up(int(a[2]), int(a[3]), a[4])
    elif len(a) >= 3 and a[1] == "down":
        down(int(a[2]))
    else:
        sys.exit(__doc__)
