#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  collect-tuxedo-oci-info.sh <pid|exact-process-name>

Examples:
  sudo ./scripts/collect-tuxedo-oci-info.sh 23462
  sudo ./scripts/collect-tuxedo-oci-info.sh tux_fuzhai
  sudo ./scripts/collect-tuxedo-oci-info.sh 23462 > /tmp/tuxedo-oci-info.txt

The script is read-only. It prints process, symbol, Oracle connection, and
Tuxedo runtime information to standard output. It does not print credentials
or the contents of tnsnames.ora.
EOF
}

section() {
  printf '\n===== %s =====\n' "$1"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'ERROR: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

resolve_pid() {
  local target=$1

  if [[ $target =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$target"
    return
  fi

  local matches
  matches=$(pgrep -x "$target" || true)
  if [[ -z $matches ]]; then
    printf 'ERROR: no process found with exact name: %s\n' "$target" >&2
    exit 1
  fi

  if [[ $(wc -l <<<"$matches") -ne 1 ]]; then
    printf 'ERROR: process name %s matched multiple PIDs; rerun with one PID:\n%s\n' \
      "$target" "$matches" >&2
    exit 1
  fi

  printf '%s\n' "$matches"
}

mapped_library() {
  local pid=$1
  local pattern=$2

  awk -v pattern="$pattern" '
    $0 ~ pattern {
      print $NF == "(deleted)" ? $(NF - 1) : $NF
      exit
    }
  ' "/proc/$pid/maps"
}

print_targeted_symbols() {
  local path=$1
  local pattern=$2

  if [[ -z $path || ! -r $path ]]; then
    printf 'not available\n'
    return
  fi

  readelf -Ws "$path" 2>&1 | grep -Ei "$pattern" || printf 'no matching symbols\n'
}

print_defined_functions() {
  local path=$1

  if [[ -z $path || ! -r $path ]]; then
    printf 'not available\n'
    return
  fi

  readelf -Ws "$path" 2>&1 |
    awk '$4 == "FUNC" && $7 != "UND" && $8 != "" {print $8}' |
    sort -u
}

if [[ $# -ne 1 ]]; then
  usage
  section "candidate Tuxedo processes"
  ps -eo pid=,comm=,args= | awk '$2 ~ /^tux_/ {print}'
  exit 1
fi

for command_name in awk date file grep pgrep ps readelf readlink sed sort ss tr uname wc; do
  require_command "$command_name"
done

pid=$(resolve_pid "$1")
if [[ ! -d /proc/$pid ]]; then
  printf 'ERROR: process does not exist: %s\n' "$pid" >&2
  exit 1
fi

if [[ ! -r /proc/$pid/maps || ! -r /proc/$pid/environ ]]; then
  printf 'ERROR: cannot read /proc/%s; run as root or the process owner\n' "$pid" >&2
  exit 1
fi

exe=$(readlink -f "/proc/$pid/exe")
libtux=$(mapped_library "$pid" '(^|/)libtux[.]so')
liboci=$(mapped_library "$pid" '(^|/)libclntsh[.]so')

section "host"
date -Is
uname -a
if [[ -r /etc/os-release ]]; then
  sed -n '1,12p' /etc/os-release
fi

section "process"
printf 'PID=%s\n' "$pid"
printf 'EXE=%s\n' "$exe"
printf 'LIBTUX=%s\n' "${libtux:-not mapped}"
printf 'LIBOCI=%s\n' "${liboci:-not mapped}"
ps -p "$pid" -o pid=,ppid=,user=,lstart=,etime=,%cpu=,%mem=,rss=,vsz=,comm=

section "binary types"
file "$exe"
if [[ -n $libtux && -r $libtux ]]; then
  file "$libtux"
else
  warn "libtux.so is not mapped by PID $pid"
fi
if [[ -n $liboci && -r $liboci ]]; then
  file "$liboci"
else
  warn "libclntsh.so is not mapped by PID $pid"
fi

section "Tuxedo executable candidate symbols"
print_targeted_symbols "$exe" \
  'tmsvrargs|tmdsptch|dispatch|service|tpsvr|tpreturn|tpforward|tpsvrinit|tpsvrdone|tux_|fuzhai|zaxang'

section "Tuxedo library candidate symbols"
print_targeted_symbols "$libtux" \
  'tmsvrargs|tmdsptch|dispatch|service|tmrun|tpsvr|tpreturn|tpforward|tpsvrinit|tpsvrdone'

section "OCI library candidate symbols"
print_targeted_symbols "$liboci" \
  'OCIServerAttach|OCIServerDetach|OCIAttrSet|OCIAttrGet|OCIStmtPrepare|OCIStmtExecute|OCIStmtRelease|OCIHandleFree'

section "all executable defined functions"
print_defined_functions "$exe"

section "selected Oracle and Tuxedo environment"
oracle_home=''
tns_admin=''
while IFS= read -r entry; do
  case $entry in
    ORACLE_HOME=*)
      oracle_home=${entry#ORACLE_HOME=}
      printf '%s\n' "$entry"
      ;;
    TNS_ADMIN=*)
      tns_admin=${entry#TNS_ADMIN=}
      printf '%s\n' "$entry"
      ;;
    TWO_TASK=*|TUXDIR=*|TUXCONFIG=*|APPDIR=*|WSNADDR=*)
      printf '%s\n' "$entry"
      ;;
  esac
done < <(tr '\0' '\n' < "/proc/$pid/environ")

section "tnsnames.ora candidates and aliases"
tns_candidates=()
if [[ -n $tns_admin ]]; then
  tns_candidates+=("$tns_admin/tnsnames.ora")
fi
if [[ -n $oracle_home ]]; then
  tns_candidates+=("$oracle_home/network/admin/tnsnames.ora")
fi

if [[ ${#tns_candidates[@]} -eq 0 ]]; then
  printf 'no candidate path derived from TNS_ADMIN or ORACLE_HOME\n'
else
  found_tns=false
  for candidate in "${tns_candidates[@]}"; do
    if [[ -r $candidate ]]; then
      found_tns=true
      printf 'FILE=%s\n' "$candidate"
      printf 'ALIASES:\n'
      awk -F= '/^[[:alnum:]_.-]+[[:space:]]*=/{name=$1; gsub(/[[:space:]]/, "", name); print name}' \
        "$candidate" | sort -u
    else
      printf 'NOT_READABLE=%s\n' "$candidate"
    fi
  done
  if [[ $found_tns == false ]]; then
    printf 'no readable tnsnames.ora found in candidate paths\n'
  fi
fi

section "process TCP connections"
ss -ntp 2>&1 | grep -F "pid=$pid," || printf 'no TCP connection owned by PID %s found\n' "$pid"

section "relevant mapped libraries"
awk '$NF ~ /(libtux|libclntsh|libocci|libnnz|libons)\.so/ {print $NF}' "/proc/$pid/maps" |
  sed 's/ (deleted)$//' |
  sort -u

section "collection notes"
cat <<'EOF'
- Share this output together with the Tuxedo service names advertised by the server.
- If a TNS alias is used, share only that alias's redacted DESCRIPTION block.
- Do not share database usernames, passwords, wallet contents, or business payloads.
EOF
