#!/usr/bin/env bash
# Optional: list Java processes inside running Podman containers.
# Emits JSON array: [{container,pid,cmdline,java_version_string,mitigations...}]
set -euo pipefail

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

if ! command -v podman >/dev/null 2>&1; then
  echo '[]'
  exit 0
fi

entries=()
while IFS= read -r cid; do
  [[ -n "${cid}" ]] || continue
  cname="$(podman inspect -f '{{.Name}}' "${cid}" 2>/dev/null || echo unknown)"
  # ps inside container
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    case "${line}" in
      *grep*) continue ;;
    esac
    pid="$(awk '{print $2}' <<<"${line}")"
    cmdline="$(awk '{for (i=11;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":""); print ""}' <<<"${line}")"
    has_base64=false
    has_useavx2=false
    if printf '%s' "${cmdline}" | grep -Fq -- '-XX:-UseBASE64Intrinsics'; then
      has_base64=true
    fi
    if printf '%s' "${cmdline}" | grep -Eq -- '-XX:UseAVX=2([[:space:]]|$)'; then
      has_useavx2=true
    fi
    version="$(podman exec "${cid}" java -version 2>&1 | head -n 1 | tr -d '\r' || true)"
    entries+=("$(printf '{"container":"%s","pid":"%s","cmdline":"%s","java_version_string":"%s","mitigation_UseBASE64Intrinsics":%s,"mitigation_UseAVX2":%s}' \
      "$(json_escape "${cname}")" \
      "$(json_escape "${pid}")" \
      "$(json_escape "${cmdline}")" \
      "$(json_escape "${version}")" \
      "${has_base64}" \
      "${has_useavx2}")")
  done < <(podman exec "${cid}" ps -eo user:20,pid,ppid,stime,tty,time,args 2>/dev/null | grep -E '[[:space:]]([^[:space:]]*/)?java([[:space:]]|$)' || true)
done < <(podman ps -q 2>/dev/null || true)

printf '['
first=1
for e in "${entries[@]+"${entries[@]}"}"; do
  if [[ ${first} -eq 1 ]]; then
    first=0
  else
    printf ','
  fi
  printf '%s' "${e}"
done
printf ']\n'
