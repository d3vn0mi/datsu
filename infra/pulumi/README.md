# datsu lab — Pulumi provisioning

Pulumi (Python, `bpg`-based `pulumi-proxmoxve` provider) manages the disposable Docker + k3s
escape-validation lab VM's lifecycle on Proxmox, replacing the imperative `lab.py` create/destroy.
Config/software (docker, k3s, datsu) is applied afterwards over SSH — Pulumi owns **VM lifecycle to
SSH-up**, in the Packer-golden-image → fast-clone shape.

## Model: template + clone (not image import)

`build_template.py` builds a **golden template** (`VMID 9000`, `datsu-lab-template`) once from the
Ubuntu 24.04 cloud image, **API-only** (the import runs server-side on the node). The Pulumi program
then **clones** that template per run (`__main__.py`). Clone is a pure Proxmox-API operation, so it
needs only the API token — unlike disk *import*, which the provider performs over SSH to the node
(root on the node, which the current token/user don't have). Cloning sidesteps that entirely.

## Run

```bash
# 1. one-time: build the golden template (API only)
./venv/bin/python build_template.py            # creates/refreshes VMID 9000

# 2. per run: clone -> VM, then datsu drives it over SSH
./run.sh pulumi up --yes                        # clones template -> VMID 9001 (192.168.60.91)
#    ... run datsu validate over SSH ...
./run.sh pulumi destroy --yes                   # tears the lab down
```

`run.sh` loads the Proxmox endpoint + API token from the solver repo `.env`
(`PVE_URL` / `PVE_TOKEN_ID` / `PVE_TOKEN_SECRET`) and exports them as `PROXMOX_VE_*` for the provider
— **secrets stay in env, never in Pulumi state.** State is the local backend (`pulumi login --local`).

## ⚠️ Required token permission (the one gate)

The `bpg` VM resource always manages the VM's `vga`/`serial` console, so creating/cloning a VM needs
**`Sys.Console`** on the token — which the stock `claude@pve!cc` token lacks (the imperative `lab.py`
avoids it by calling only the exact VM.* APIs). Symptom:

```
error updating VM: received an HTTP 403 response - Reason: Permission check failed (/, Sys.Console)
```

Grant it once on the node (operator, needs root/sudo):

```bash
ssh d3vn0mi@pve.ravensec.eu
sudo pveum role add DatsuLab -privs "VM.Allocate VM.Clone VM.Config.Disk VM.Config.CPU \
  VM.Config.Memory VM.Config.Network VM.Config.Options VM.Config.Cloudinit VM.PowerMgmt \
  VM.Audit VM.Monitor Datastore.AllocateSpace Datastore.Audit Sys.Console Sys.Audit"
sudo pveum acl modify / --token 'claude@pve!cc' --role DatsuLab
# (or, blunt: sudo pveum acl modify / --token 'claude@pve!cc' --role Administrator)
```

After that, `pulumi up` provisions the VM end to end. (Disk *import* in `build_template.py` is
server-side API, so it does **not** need this — only the clone/config path does.)

## Status

Program validated to the permission wall: `pulumi preview` is clean (plans provider + VM), the
template builds API-only, and `pulumi up` clones + creates the VM, failing only on the `Sys.Console`
config update above. Grant the privilege and it completes.

## Author

**d3vn0mi** — RavenSec.
