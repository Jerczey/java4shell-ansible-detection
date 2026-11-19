#!/usr/bin/env bash
# Detect Java4Shell (CVE-2026-114938) indicators on OpenShift pods.
# Usage:
#   export KUBECONFIG=...
#   ./detect-ocp-java4shell.sh [ns1 ns2 ...]
# Default namespaces: datagrid-system rhsso rhbk + any ns with java-ish pods.

set -euo pipefail

FLAG_PREF='-XX:-UseBASE64Intrinsics'
FLAG_AVX='-XX:UseAVX=2'
AFFECTED_MAJOR_RE='^(17|21|25|27)$'

need_oc() {
  command -v oc >/dev/null || { echo "oc not found" >&2; exit 1; }
  oc whoami >/dev/null || { echo "oc not logged in / bad KUBECONFIG" >&2; exit 1; }
}

cpu_gate() {
  local node
  node="$(oc get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -z "${node}" ]]; then
    echo "CPU: (no nodes)"
    return
  fi
  echo -n "CPU avx512vbmi on ${node}: "
  if oc debug "node/${node}" --quiet -- chroot /host \
      grep -o avx512vbmi /proc/cpuinfo 2>/dev/null | head -1 | grep -q avx512vbmi; then
    echo "YES"
  else
    echo "NO (or debug failed)"
  fi
}

classify() {
  local major="$1" cmdline="$2" jflag="$3"
  local mitigated=0
  echo "${cmdline}" | grep -Fq -- "${FLAG_PREF}" && mitigated=1
  echo "${cmdline}" | grep -Fq -- "${FLAG_AVX}" && mitigated=1
  echo "${jflag}" | grep -Eq 'UseBASE64Intrinsics[[:space:]]*=[[:space:]]*false' && mitigated=1

  if [[ "${mitigated}" -eq 1 ]]; then
    echo "MITIGATED"
    return
  fi
  if [[ "${major}" =~ ^(8|11)$ ]]; then
    echo "NOT_THIS_PATH"
    return
  fi
  if [[ "${major}" =~ ${AFFECTED_MAJOR_RE} ]]; then
    echo "EXPOSED"
    return
  fi
  echo "UNKNOWN"
}

scan_pod() {
  local ns="$1" pod="$2"
  local containers
  containers="$(oc get pod -n "${ns}" "${pod}" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null || true)"
  [[ -z "${containers}" ]] && return

  local ctn
  for ctn in ${containers}; do
    # Skip obvious non-JVM helpers
    case "${ctn}" in
      *postgres*|*mysql*|*mariadb*|*redis*|*valkey*|*nginx*) continue ;;
    esac

    local out
    out="$(oc exec -n "${ns}" "${pod}" -c "${ctn}" -- bash -c '
      set +e
      for p in /proc/[0-9]*; do
        cmd=$(tr "\0" " " < "$p/cmdline" 2>/dev/null) || continue
        case "$cmd" in
          *"/bin/java "*|*" /usr/bin/java "*|java\ *|*/jre/bin/java*|*/java-*/bin/java*)
            ;;
          *) continue ;;
        esac
        # skip our own shell noise
        echo "$cmd" | grep -q "detect-ocp-java4shell\|VM.flags" && continue
        pid=$(basename "$p")
        java_bin=$(tr "\0" "\n" < "$p/cmdline" | head -1)
        ver=""
        if [ -x "$java_bin" ]; then
          ver=$("$java_bin" -version 2>&1 | head -1)
        elif command -v java >/dev/null 2>&1; then
          ver=$(java -version 2>&1 | head -1)
        fi
        major=$(echo "$ver" | sed -nE "s/.*version \"([0-9]+)(\.|_|\+).*/\1/p")
        [ -z "$major" ] && major=$(echo "$ver" | sed -nE "s/.*version \"1\.([0-9]+).*/\1/p")
        jflag=""
        if command -v jcmd >/dev/null 2>&1; then
          jflag=$(jcmd "$pid" VM.flags -all 2>/dev/null | grep -F UseBASE64Intrinsics | head -1)
        else
          for j in /usr/lib/jvm/*/bin/jcmd; do
            [ -x "$j" ] || continue
            jflag=$("$j" "$pid" VM.flags -all 2>/dev/null | grep -F UseBASE64Intrinsics | head -1)
            [ -n "$jflag" ] && break
          done
        fi
        envhint=$(env 2>/dev/null | grep -E "JAVA_OPTS_APPEND|JAVA_OPTIONS|JDK_JAVA_OPTIONS|JAVA_TOOL_OPTIONS|JAVA_ARGS_APPEND" | tr "\n" ";")
        printf "PID=%s|MAJOR=%s|VER=%s|JFLAG=%s|ENV=%s|CMD=%s\n" \
          "$pid" "${major:-?}" "${ver:-?}" "${jflag:-}" "${envhint:-}" "$cmd"
      done
    ' 2>/dev/null || true)"

    [[ -z "${out}" ]] && continue

    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      local pid major ver jflag envhint cmd
      pid="$(echo "${line}" | sed -n 's/.*PID=\([^|]*\).*/\1/p')"
      major="$(echo "${line}" | sed -n 's/.*MAJOR=\([^|]*\).*/\1/p')"
      ver="$(echo "${line}" | sed -n 's/.*VER=\([^|]*\).*/\1/p')"
      jflag="$(echo "${line}" | sed -n 's/.*JFLAG=\([^|]*\).*/\1/p')"
      envhint="$(echo "${line}" | sed -n 's/.*ENV=\([^|]*\).*/\1/p')"
      cmd="$(echo "${line}" | sed -n 's/.*CMD=//p')"
      local result
      result="$(classify "${major}" "${cmd}" "${jflag}")"
      printf '%-28s %-40s %-16s %-10s %-12s %s\n' \
        "${ns}" "${pod}/${ctn}" "${result}" "jdk${major}" "${pid}" "${ver}"
      if [[ -n "${jflag}" ]]; then
        echo "    jcmd: ${jflag}"
      fi
      if [[ -n "${envhint}" ]]; then
        echo "    env:  ${envhint}"
      fi
      if echo "${cmd}" | grep -Fq -- "${FLAG_PREF}"; then
        echo "    cmdline: has ${FLAG_PREF}"
      fi
    done <<< "${out}"
  done
}

default_namespaces() {
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@"
    return
  fi
  # Prefer known lab namespaces, then any ns matching middleware names
  local ns
  for ns in datagrid-system rhsso rhbk rhhi-demo; do
    oc get ns "${ns}" >/dev/null 2>&1 && echo "${ns}"
  done
  oc get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | grep -iE '^(eap|amq|fuse|camel|cryostat|apicurio|datagrid|rhsso|rhbk|keycloak)' \
    || true
}

main() {
  need_oc
  echo "=== Java4Shell OpenShift detection (CVE-2026-114938) ==="
  echo "cluster: $(oc whoami --show-server 2>/dev/null || echo '?')"
  cpu_gate
  echo
  printf '%-28s %-40s %-16s %-10s %-12s %s\n' \
    "NAMESPACE" "POD/CONTAINER" "RESULT" "JDK" "PID" "VERSION"
  printf '%-28s %-40s %-16s %-10s %-12s %s\n' \
    "----------------------------" "----------------------------------------" "----------------" "----------" "------------" "-------"

  local ns pod
  # unique namespaces
  mapfile -t namespaces < <(default_namespaces "$@" | awk 'NF' | sort -u)
  for ns in "${namespaces[@]}"; do
    while read -r pod; do
      [[ -z "${pod}" ]] && continue
      scan_pod "${ns}" "${pod}"
    done < <(oc get pods -n "${ns}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  done
  echo
  echo "Legend: EXPOSED = JDK 17+/21/25 without mitigation (confirm avx512vbmi)."
  echo "        MITIGATED = flag present or UseBASE64Intrinsics=false."
  echo "        NOT_THIS_PATH = OpenJDK 8/11."
}

main "$@"
