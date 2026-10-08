#!/bin/bash
# Load Proxmox creds from the solver repo .env and export them for the Pulumi Proxmox provider,
# then exec the given pulumi command. Secrets live in env, never in Pulumi state.
set -e; cd "$(dirname "$0")"
ENVF="${PVE_ENV_FILE:-/home/d3vn0mi/Desktop/opt/acs_agentic_ctf_solver/.env}"
g(){ grep "^$1=" "$ENVF" | cut -d= -f2-; }
export PROXMOX_VE_ENDPOINT="$(g PVE_URL | sed 's#/api2/json/\?$##')"
export PVE_NODE="$(g PVE_NODE)"
export PROXMOX_VE_API_TOKEN="$(g PVE_TOKEN_ID)=$(g PVE_TOKEN_SECRET)"
export PROXMOX_VE_INSECURE=true
export PULUMI_CONFIG_PASSPHRASE="${PULUMI_CONFIG_PASSPHRASE:-datsu-lab}"
export PATH="$HOME/.pulumi/bin:$PATH"
exec "$@"
