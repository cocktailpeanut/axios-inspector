#!/usr/bin/env bash

set -u

detect_platform() {
  case "$(uname -s 2>/dev/null)" in
    Darwin)
      echo 'darwin'
      ;;
    Linux)
      echo 'linux'
      ;;
    CYGWIN*|MINGW*|MSYS*)
      echo 'win32'
      ;;
    *)
      echo 'unknown'
      ;;
  esac
}

SCAN_ROOT="${1:-${PINOKIO_SCAN_ROOT:-$(pwd)}}"
PINOKIO_PLATFORM="${PINOKIO_PLATFORM:-$(detect_platform)}"

CHECK_TOTAL=5
CHECK_INDEX=0
SPINNER_FRAMES='|/-\'

if [ -t 1 ]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
else
  C_RESET=''
  C_BOLD=''
  C_DIM=''
  C_BLUE=''
  C_CYAN=''
  C_GREEN=''
  C_YELLOW=''
fi

print_banner() {
  echo '------------------------------------------------------------'
  printf '%sAxios Inspector%s\n' "$C_BOLD$C_CYAN" "$C_RESET"
  printf '%sScan root:%s %s\n' "$C_DIM" "$C_RESET" "$SCAN_ROOT"
  printf '%sPlatform:%s %s\n' "$C_DIM" "$C_RESET" "$PINOKIO_PLATFORM"
  printf '%sChecks:%s %s\n' "$C_DIM" "$C_RESET" "$CHECK_TOTAL"
  echo '------------------------------------------------------------'
  echo
}

run_check() {
  local title="$1"
  local command="$2"
  local output=""
  local tmpfile=""
  local pid=""
  local frame=""
  local frame_index=0
  local match_count=0

  CHECK_INDEX=$((CHECK_INDEX + 1))
  printf '%s[%s/%s] %s%s\n' "$C_BOLD$C_BLUE" "$CHECK_INDEX" "$CHECK_TOTAL" "$title" "$C_RESET"

  tmpfile="$(mktemp)"
  (
    eval "$command"
  ) >"$tmpfile" 2>/dev/null &
  pid=$!

  while kill -0 "$pid" 2>/dev/null; do
    frame="${SPINNER_FRAMES:$((frame_index % 4)):1}"
    printf '\r%s[%s] scanning...%s' "$C_YELLOW" "$frame" "$C_RESET"
    sleep 0.12
    frame_index=$((frame_index + 1))
  done

  wait "$pid" || true
  printf '\r\033[K'
  output="$(cat "$tmpfile")"
  rm -f "$tmpfile"

  if [ -n "$output" ]; then
    match_count="$(printf '%s\n' "$output" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
    printf '%s[match]%s %s finding(s)\n' "$C_GREEN" "$C_RESET" "$match_count"
    printf '%s\n' "$output" | sed 's/^/  - /'
  else
    printf '%s[clear]%s none found\n' "$C_GREEN" "$C_RESET"
  fi

  echo
}

print_banner

run_check \
  'Malicious dependency' \
  "find \"$SCAN_ROOT\" -path '*/node_modules/plain-crypto-js' -type d 2>/dev/null"

run_check \
  'Bad axios versions' \
  "find \"$SCAN_ROOT\" -path '*/node_modules/axios/package.json' 2>/dev/null | xargs grep -l '\"1.14.1\"\\|\"0.30.4\"' 2>/dev/null"

run_check \
  'Lockfiles' \
  "find \"$SCAN_ROOT\" \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) 2>/dev/null | xargs grep -l 'plain-crypto-js' 2>/dev/null"

if [ "$PINOKIO_PLATFORM" = "win32" ]; then
  run_check \
    'RAT Artifacts' \
    "[ -n \"\${PROGRAMDATA:-}\" ] && ls -la \"\$PROGRAMDATA/wt.exe\" 2>/dev/null"
else
  run_check \
    'RAT Artifacts' \
    "ls -la /Library/Caches/com.apple.act.mond 2>/dev/null; ls -la /tmp/ld.py 2>/dev/null"
fi

run_check \
  'Global' \
  "npm ls -g axios 2>/dev/null | grep -E '1\.14\.1|0\.30\.4'"

printf '%s=== Done ===%s\n' "$C_BOLD$C_CYAN" "$C_RESET"
