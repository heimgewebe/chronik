#!/usr/bin/env bash
set -euo pipefail
print_json=0
output_path=${WGX_METRICS_OUTPUT:-metrics.json}

usage() {
  cat <<'EOF'
wgx-metrics-snapshot.sh [--json] [--output PATH]
Erzeugt metrics.json (ts, host, updates, backup, drift).
  --json           zusätzlich JSON auf STDOUT
  --output PATH    Ziel-Datei (Default: metrics.json)
EOF
}

while (($#)); do
  case "$1" in
    --json) print_json=1;;
    --output)
      shift; [[ $# -gt 0 ]] || { echo "--output braucht einen Pfad" >&2; exit 1; }
      output_path="$1"
      ;;
    -h|--help) usage; exit 0;;
    *) echo "Unbekannte Option: $1" >&2; usage; exit 1;;
  esac
  shift || true
done

[[ -n "$output_path" ]] || { echo "Der Ausgabe-Pfad darf nicht leer sein" >&2; exit 1; }
outdir="$(dirname "$output_path")"; [[ -d "$outdir" ]] || mkdir -p "$outdir"

ts=$(date +%s)
host=$(hostname)
updates_os=${UPDATES_OS:-0}
updates_pkg=${UPDATES_PKG:-0}
updates_flatpak=${UPDATES_FLATPAK:-0}
if date -d "yesterday" +%F >/dev/null 2>&1; then
# Backup-Status konsistent: age_days steuert last_ok
age_days=${BACKUP_AGE_DAYS:-1}
if date -d "today" +%F >/dev/null 2>&1; then
  # GNU date
  last_ok=$(date -d "${age_days} day ago" +%F)
else
  # BSD/macOS date
  last_ok=$(date -v-"${age_days}"d +%F)
fi
else
  last_ok=$(date -v-1d +%F) # BSD/macOS
fi
age_days=${BACKUP_AGE_DAYS:-1}
drift_templates=${DRIFT_TEMPLATES:-0}

json=$(jq -n \
  --arg host "$host" \
  --arg last_ok "$last_ok" \
  --argjson ts "$ts" \
  --argjson uos "$updates_os" \
  --argjson upkg "$updates_pkg" \
  --argjson ufp "$updates_flatpak" \
  --argjson age "$age_days" \
  --argjson drift "$drift_templates" \
  '{
    ts: $ts,
    host: $host,
    updates: { os: $uos, pkg: $upkg, flatpak: $ufp },
    backup: { last_ok: $last_ok, age_days: $age },
    drift: { templates: $drift }
  }')

printf '%s\n' "$json" >"$output_path"
(( print_json )) && printf '%s\n' "$json"
