#!/usr/bin/env bash
# Регрессии hardening v1.4.0: redact, --out owner/symlink, fleet AUDIT_ARGS / MOTD.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/audit-ubuntu.sh"
FLEET="$ROOT/run-fleet-audit.sh"
fail=0

assert_eq() {
  local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then
    echo "OK  $name"
  else
    echo "FAIL $name"
    echo "  got:  $got"
    echo "  want: $want"
    fail=1
  fi
}

assert_contains() {
  local name="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then
    echo "OK  $name"
  else
    echo "FAIL $name (нет: $needle)"
    echo "  got: $hay"
    fail=1
  fi
}

assert_not_contains() {
  local name="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then
    echo "OK  $name"
  else
    echo "FAIL $name (не должно быть: $needle)"
    echo "  got: $hay"
    fail=1
  fi
}

assert_exit() {
  local name="$1" want="$2"
  shift 2
  local rc=0
  "$@" >/dev/null 2>&1 || rc=$?
  if [[ "$rc" -eq "$want" ]]; then
    echo "OK  $name (exit $rc)"
  else
    echo "FAIL $name (exit $rc, ждали $want)"
    fail=1
  fi
}

# --- redact stdin -----------------------------------------------------------
yaml=$'network:\n  wifis:\n    wlan0:\n      password: hunter2\n'
got=$(printf '%s' "$yaml" | "$AUDIT" --redact-stdin 2>/dev/null) || got="COMMAND_FAILED"
assert_not_contains "yaml password value gone" "$got" "hunter2"
assert_contains "yaml password redacted" "$got" "<REDACTED>"

json='{"password":"s3cret","user":"x"}'
got=$(printf '%s' "$json" | "$AUDIT" --redact-stdin 2>/dev/null) || got="COMMAND_FAILED"
assert_not_contains "json password value gone" "$got" "s3cret"
assert_contains "json password redacted" "$got" "<REDACTED>"

sshd=$'PasswordAuthentication yes\nPermitRootLogin no\n'
got=$(printf '%s' "$sshd" | "$AUDIT" --redact-stdin 2>/dev/null) || got="COMMAND_FAILED"
assert_contains "sshd PasswordAuthentication intact" "$got" "PasswordAuthentication yes"

pem=$'-----BEGIN RSA PRIVATE KEY-----\nMIISECRET\n-----END RSA PRIVATE KEY-----\nvisible\n'
got=$(printf '%s' "$pem" | "$AUDIT" --redact-stdin 2>/dev/null) || got="COMMAND_FAILED"
assert_not_contains "pem body gone" "$got" "MIISECRET"
assert_contains "pem marker" "$got" "<PRIVATE-KEY-REMOVED>"
assert_contains "pem rest kept" "$got" "visible"

pgp=$'-----BEGIN PGP PRIVATE KEY BLOCK-----\nPGPSECRET\n-----END PGP PRIVATE KEY BLOCK-----\n'
got=$(printf '%s' "$pgp" | "$AUDIT" --redact-stdin 2>/dev/null) || got="COMMAND_FAILED"
assert_not_contains "pgp body gone" "$got" "PGPSECRET"

upgradable=$'### CMD: apt\n### HOST: x  TIME: t\n\nListing...\n=== apt list --upgradable ===\nfoo/jammy 1.2 amd64 [upgradable from: 1.1]\nbar/jammy 3.0 amd64 [upgradable from: 2.9]\n'
# контракт счётчика: grep -c \'\\[upgradable\' == 2, а не grep -c upgradable (== 3)
count_bad=$(printf '%s' "$upgradable" | grep -c upgradable || true)
count_good=$(printf '%s' "$upgradable" | grep -c '\[upgradable' || true)
assert_eq "upgradable grep word is noisy" "$count_bad" "3"
assert_eq "upgradable grep [upgradable is exact" "$count_good" "2"

# --- --out: symlink и чужой каталог ----------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ln -s "$tmp" "$tmp/link"
err=$("$AUDIT" --out "$tmp/link" --no-net 2>&1) || rc=$?
rc=${rc:-0}
if [[ "$rc" -ne 0 ]] && [[ "$err" == *symlink* || "$err" == *симлинк* || "$err" == *владел* || "$err" == *отказ* ]]; then
  echo "OK  --out symlink rejected (exit $rc)"
else
  echo "FAIL --out symlink (exit ${rc:-0})"
  echo "  $err"
  fail=1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  rc=0
  err=$("$AUDIT" --out /etc --no-net 2>&1) || rc=$?
  if [[ "$rc" -ne 0 ]] && [[ "$err" == *владел* || "$err" == *owner* || "$err" == *отказ* || "$err" == *чуж* || "$err" == *symlink* || "$err" == *симлинк* ]]; then
    echo "OK  --out /etc rejected (exit $rc)"
  else
    echo "FAIL --out /etc (exit $rc; ждали отказ по владельцу)"
    echo "  $err"
    fail=1
  fi
fi

# --- fleet: MOTD path (работает на bash 3.2) --------------------------------
motd=$'Welcome to Ubuntu\n/home/u/.cache/razbudimir-audit/run.abc123\n'
got=$(printf '%s' "$motd" | "$FLEET" --check-remote-dir) || got="COMMAND_FAILED"
assert_eq "motd stripped to mktemp path" "$got" "/home/u/.cache/razbudimir-audit/run.abc123"

bad=$'Welcome\n/tmp/evil\n'
assert_exit "motd junk path rejected" 1 bash -c 'printf "%s" "$1" | "$2" --check-remote-dir' _ "$bad" "$FLEET"

# --- fleet AUDIT_ARGS (нужен bash ≥4) --------------------------------------
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "SKIP fleet AUDIT_ARGS (нужен bash ≥4, сейчас $BASH_VERSION)"
else
  assert_exit "fleet --no-redact без ALLOW" 2 env AUDIT_ARGS="--no-redact" "$FLEET"
  assert_exit "fleet --out запрещён" 2 env AUDIT_ARGS="--out /tmp/x" "$FLEET"
fi

if (( fail )); then
  echo "FAILED"
  exit 1
fi
echo "ALL OK"
exit 0
