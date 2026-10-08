"""Disposable Docker + k3s container-escape-validation lab VM on Proxmox, for datsu.

Pulumi replaces the imperative lab.py create/destroy: it declares the VM (cloud-image + cloud-init
+ mgmt NIC + SSH key) and manages its lifecycle with `pulumi up` / `pulumi destroy`. Config/software
(docker, k3s, datsu) is applied afterwards over SSH / Ansible — Pulumi owns VM-lifecycle-to-ssh-up.

Auth comes from env (never committed to state): PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN,
PROXMOX_VE_INSECURE — see run.sh. Author: d3vn0mi (RavenSec).
"""
import os
import pulumi
from pulumi_proxmoxve import Provider, vm

node = os.environ.get("PVE_NODE", "pve")
vmid = int(os.environ.get("DATSU_VMID", "9001"))
template_id = int(os.environ.get("DATSU_TEMPLATE_VMID", "9000"))
ssh_key = open(os.path.expanduser("~/.ssh/id_ed25519.pub")).read().strip()

prov = Provider("pve", endpoint=os.environ["PROXMOX_VE_ENDPOINT"],
                api_token=os.environ["PROXMOX_VE_API_TOKEN"], insecure=True)
ro = pulumi.ResourceOptions(provider=prov)

# Clone the golden template (build_template.py). Clone is a pure Proxmox API op, so it needs only
# the API token — unlike disk IMPORT, which the bpg provider performs over SSH to the node (which we
# don't have). This is the Packer-golden-image -> fast-clone model.
lab = vm.VirtualMachine("datsu-lab",
    node_name=node, vm_id=vmid, name="datsu-lab", on_boot=False, started=True,
    clone={"vm_id": template_id, "full": True},
    agent={"enabled": False},   # datsu drives over SSH; cloud image has no qemu-guest-agent (enabling
                                # would block `pulumi up`). Research-engine use: install it via cloud-init + flip True.
    network_devices=[{"bridge": "vmbr1", "model": "virtio"}],
    initialization={
        "datastore_id": "local",
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "ip_configs": [{"ipv4": {"address": "192.168.60.91/24", "gateway": "192.168.60.254"}}],
        "user_account": {"username": "root", "password": "datsulab", "keys": [ssh_key]},
    },
    opts=ro)

pulumi.export("vmid", lab.vm_id)
pulumi.export("mgmt_ip", "192.168.60.91")
