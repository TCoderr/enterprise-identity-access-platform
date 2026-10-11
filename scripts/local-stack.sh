#!/usr/bin/env bash
# Manages the local Halka ID stack (Docker Compose). Linux/macOS equivalent of local-stack.ps1.
#
#   ./scripts/local-stack.sh init|up|down|status|logs|machine|reset [--project halka] [--port-base 9443]
#                            [--service iam] [--confirm-project halka] [--no-build]
#
# init    creates private local material (.local/), idempotent
# up      runs init if needed, builds, starts and waits until healthy
# down    stops and removes containers; volumes and .local/ are kept
# status  shows container state and URLs
# logs    shows recent logs (optionally for one service)
# machine runs the machine-to-machine demo once in its own container (the stack must be up)
# reset   DESTRUCTIVE: removes the database volume and the private directory; needs --confirm-project <name>
set -euo pipefail

command="${1:-}"
[ $# -gt 0 ] && shift
project="halka"
port_base=9443
service=""
confirm=""
build="--build"

while [ $# -gt 0 ]; do
  case "$1" in
    --project) project="$2"; shift 2 ;;
    --port-base) port_base="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --confirm-project) confirm="$2"; shift 2 ;;
    --no-build) build=""; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! [[ "$project" =~ ^halka(-[a-z0-9]+)?$ ]]; then
  echo "project must match ^halka(-[a-z0-9]+)?$" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$project" = "halka" ]; then local_name=".local"; else local_name=".local-${project#halka-}"; fi
local_path="$root/$local_name"
compose_file="$root/deploy/docker-compose.yml"

export HALKA_PROJECT="$project"
export HALKA_LOCAL_DIR="$local_path"
export HALKA_IAM_PORT="$port_base"
export HALKA_PANO_PORT="$((port_base + 1))"
export HALKA_RAPOR_PORT="$((port_base + 2))"
export HALKA_API_PORT="$((port_base + 3))"

compose() { docker compose -f "$compose_file" -p "$project" "$@"; }
init() { dotnet run --project "$root/tools/Halka.LocalInit" -c Release -- --target "$local_path"; }
urls() {
  echo
  echo "Halka ID   https://id.halka.localhost:$HALKA_IAM_PORT"
  echo "Pano       https://pano.localhost:$HALKA_PANO_PORT"
  echo "Rapor      https://rapor.localhost:$HALKA_RAPOR_PORT"
  echo "API        https://workspace-api.localhost:$HALKA_API_PORT"
  echo "Private    $local_path  (seed/credentials.json, mail-sink/, tls/ca.crt)"
}

case "$command" in
  init) init ;;
  up)
    [ -f "$local_path/manifest.json" ] || init
    # shellcheck disable=SC2086
    compose up -d $build --wait --wait-timeout 180
    urls ;;
  down)
    # Deliberately no "-v": the database volume and the private directory are preserved.
    compose down --remove-orphans ;;
  status) compose ps --all; urls ;;
  logs)
    if [ -n "$service" ]; then compose logs --no-color --tail 200 "$service"; else compose logs --no-color --tail 200; fi ;;
  machine) compose --profile machine run --rm --no-deps machine-demo ;;
  reset)
    if [ "$confirm" != "$project" ]; then
      echo "reset is destructive. Re-run with --confirm-project $project to delete the database volume and '$local_name'." >&2
      exit 1
    fi
    # Target guard: only a directory inside this repository that init created is ever deleted.
    case "$local_path" in "$root"/.local*) ;; *) echo "Refusing to reset: '$local_path' is not a private directory of this repository." >&2; exit 1 ;; esac
    compose down --volumes --remove-orphans
    if [ -d "$local_path" ]; then
      [ -f "$local_path/manifest.json" ] || { echo "Refusing to delete '$local_path': no manifest.json written by init." >&2; exit 1; }
      rm -rf -- "$local_path"
    fi
    echo "reset complete for project '$project'." ;;
  *) echo "usage: local-stack.sh init|up|down|status|logs|machine|reset [options]" >&2; exit 2 ;;
esac
