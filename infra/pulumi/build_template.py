#!/usr/bin/env python3
"""Build a Proxmox VM template from the Ubuntu cloud image, API-only (no node SSH needed) — the
'golden image' that the Pulumi program clones per run. One-time: run again only to refresh it.

Creates VMID 9000 'datsu-lab-template' with the cloud image imported as scsi0 + a cloud-init drive,
resizes, then converts it to a template. Clone (what Pulumi does) is a pure API op, so it works with
the API token alone — unlike disk import, which the bpg provider does over SSH to the node.
"""
import json, os, ssl, sys, time, urllib.parse, urllib.request

ROOT = "/home/d3vn0mi/Desktop/opt/acs_agentic_ctf_solver"
env = {k: v for k, v in (l.strip().split("=", 1) for l in open(f"{ROOT}/.env")
                         if l.strip().startswith("PVE_") and "=" in l)}
URL = env["PVE_URL"].rstrip("/"); NODE = env.get("PVE_NODE", "pve")
TOKEN = f"PVEAPIToken={env['PVE_TOKEN_ID']}={env['PVE_TOKEN_SECRET']}"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TID = int(os.environ.get("DATSU_TEMPLATE_VMID", "9000"))
IMAGE = "local:import/ubuntu-24.04-server-cloudimg-amd64.qcow2"


def req(method, path, data=None, raw=None):
    body = raw.encode() if raw is not None else (urllib.parse.urlencode(data).encode() if data else None)
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
            print(f"  [{label}] {st.get('exitstatus')}"); return st.get("exitstatus") == "OK"
        time.sleep(3)
    sys.exit(f"{label} timeout")


def exists(vmid):
    try:
        req("GET", f"/nodes/{NODE}/qemu/{vmid}/status/current"); return True
    except Exception:
        return False


def main():
    if exists(TID):
        print(f"template {TID} already exists — destroying to rebuild")
        r = urllib.request.Request(f"{URL}/api2/json/nodes/{NODE}/qemu/{TID}?purge=1&destroy-unreferenced-disks=1",
                                   method="DELETE", headers={"Authorization": TOKEN})
        with urllib.request.urlopen(r, context=CTX, timeout=60) as resp:
            wait_task(json.load(resp).get("data"), "destroy-old")
        for _ in range(20):
            if not exists(TID):
                break
            time.sleep(3)
    cfg = {
        "vmid": TID, "name": "datsu-lab-template", "cores": 4, "memory": 6144, "ostype": "l26",
        "scsihw": "virtio-scsi-single", "scsi0": f"local:0,import-from={IMAGE},discard=on",
        "ide2": "local:cloudinit", "net0": "virtio,bridge=vmbr1", "agent": "enabled=1",
        "boot": "order=scsi0", "ciupgrade": 0,   # no serial0/vga — the bpg provider needs Sys.Console to set them
    }
    print(f"create template {TID} (cloud-image import, server-side) …")
    wait_task(req("POST", f"/nodes/{NODE}/qemu", cfg), "create")
    # no resize here — keep the template at the image's native size; the Pulumi clone grows the disk
    # (a clone can only grow, not shrink, so the template must stay small).
    print("convert to template …")
    req("POST", f"/nodes/{NODE}/qemu/{TID}/template", {})
    print(f"template {TID} ready — Pulumi can now clone it (API-only).")


if __name__ == "__main__":
    main()
