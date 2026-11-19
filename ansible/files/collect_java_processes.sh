#!/usr/bin/env bash
# Collect running Java processes from /proc (preferred) with ps fallback.
# Emits JSON array to stdout. No secrets; cmdline only.
set -euo pipefail

json_escape() {
  # shellcheck disable=SC2001
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/'"$(printf '\t')"'/\\t/g'
}

emit_entry() {
  local pid="$1" user="$2" exe="$3" cmdline="$4" version="$5"
  local has_base64="false" has_useavx2="false"
  case " ${cmdline} " in
    *" -XX:-UseBASE64Intrinsics "*|*" -XX:-UseBASE64Intrinsics"*) has_base64="true" ;;
  esac
  # Also match glued forms in /proc cmdline (null-separated -> space)
  if printf '%s' "${cmdline}" | grep -Fq -- '-XX:-UseBASE64Intrinsics'; then
    has_base64="true"
  fi
  if printf '%s' "${cmdline}" | grep -Eq -- '-XX:UseAVX=2([[:space:]]|$)'; then
    has_useavx2="true"
  fi

  printf '{'
  printf '"pid":%s,' "${pid}"
  printf '"user":"%s",' "$(json_escape "${user}")"
  printf '"exe":"%s",' "$(json_escape "${exe}")"
  printf '"cmdline":"%s",' "$(json_escape "${cmdline}")"
  printf '"java_version_string":"%s",' "$(json_escape "${version}")"
  printf '"mitigation_UseBASE64Intrinsics":%s,' "${has_base64}"
  printf '"mitigation_UseAVX2":%s' "${has_useavx2}"
  printf '}'
}

entries=()

# Prefer /proc scan — reflects real running JVMs
for pid_dir in /proc/[0-9]*; do
  pid="${pid_dir##*/}"
  [[ -r "${pid_dir}/cmdline" ]] || continue
  cmdline_raw="$(tr '\0' ' ' < "${pid_dir}/cmdline" 2>/dev/null || true)"
  cmdline_raw="${cmdline_raw%"${cmdline_raw##*[![:space:]]}"}"
  [[ -n "${cmdline_raw}" ]] || continue

  # Match java interpreters / wrappers, skip grep noise
  case "${cmdline_raw}" in
    *grep*|*collect_java_processes*) continue ;;
  esac

  # First token or any path ending in /java or named java
  first_token="${cmdline_raw%% *}"
  base_first="${first_token##*/}"
  if [[ "${base_first}" != "java" && "${base_first}" != "java.exe" ]]; then
    # Some launchers: /usr/lib/jvm/.../bin/java already covered; also match -Dquarkus / jboss if exe is java
    if [[ ! -r "${pid_dir}/exe" ]]; then
      continue
    fi
    exe_link="$(readlink -f "${pid_dir}/exe" 2>/dev/null || true)"
    exe_base="${exe_link##*/}"
    if [[ "${exe_base}" != "java" ]]; then
      continue
    fi
  fi

  user="$(stat -c '%U' "${pid_dir}" 2>/dev/null || echo unknown)"
  exe="$(readlink -f "${pid_dir}/exe" 2>/dev/null || echo "${first_token}")"

  version=""
  if [[ -x "${exe}" ]]; then
    version="$("${exe}" -version 2>&1 | head -n 1 | tr -d '\r' || true)"
  fi

  entries+=("$(emit_entry "${pid}" "${user}" "${exe}" "${cmdline_raw}" "${version}")")
done

# Fallback: ps if /proc found nothing (rare / restricted)
if [[ ${#entries[@]} -eq 0 ]] && command -v ps >/dev/null 2>&1; then
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    case "${line}" in
      *grep*|*collect_java_processes*) continue ;;
    esac
    pid="$(awk '{print $2}' <<<"${line}")"
    user="$(awk '{print $1}' <<<"${line}")"
    # columns: USER PID ... CMD — recover cmd from field 11+
    cmdline="$(awk '{for (i=11;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":""); print ""}' <<<"${line}")"
    first_token="${cmdline%% *}"
    exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || echo "${first_token}")"
    version=""
    if [[ -x "${exe}" ]]; then
      version="$("${exe}" -version 2>&1 | head -n 1 | tr -d '\r' || true)"
    fi
    entries+=("$(emit_entry "${pid}" "${user}" "${exe}" "${cmdline}" "${version}")")
  done < <(ps -eo user:20,pid,ppid,stime,tty,time,args 2>/dev/null | grep -E '[[:space:]]([^[:space:]]*/)?java([[:space:]]|$)' || true)
fi

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
