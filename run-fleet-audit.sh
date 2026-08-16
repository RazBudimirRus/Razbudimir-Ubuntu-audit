#!/usr/bin/env bash
# ============================================================================
#  run-fleet-audit.sh — запуск audit-ubuntu.sh на парке серверов и сбор архивов
#  Запускается с рабочей машины (Linux; macOS — нужен bash ≥4, напр. Homebrew).
#  Требует ssh-доступ с passwordless sudo (sudo -n).
#
#  1) Создайте servers.txt: одна строка = user@host  или  user@host:port
#     IPv6: user@[2001:db8::1]  или  user@[2001:db8::1]:2222
#  2) ./run-fleet-audit.sh
#  Результат: ./fleet-audit-<дата>/<host>.tar.gz + extracted/ + INDEX.md
#
#  Переменные окружения:
#    SCRIPT          путь к audit-ubuntu.sh (по умолчанию ./audit-ubuntu.sh)
#    AUDIT_ARGS      аргументы коллектора (по умолчанию: --deep --no-net)
#    PARALLEL        параллельность (по умолчанию 3)
#    SSH_STRICT      yes|accept-new (по умолчанию yes)
#    KEEP_REMOTE=1   не удалять архивы на удалённых хостах после scp
#    ALLOW_NO_REDACT=1  разрешить --no-redact в AUDIT_ARGS
# ============================================================================
set -uo pipefail
umask 077

fleet_remote_dir_from_ssh_stdout() {
  tr -d '\r' | awk 'NF { line = $0 } END { print line }'
}

valid_fleet_run_dir() {
  case "$1" in
    */.cache/razbudimir-audit/run.*) return 0 ;;
    *) return 1 ;;
  esac
}

# stdin: сырой stdout ssh (может содержать MOTD); stdout: путь mktemp
if [[ "${1:-}" == --check-remote-dir ]]; then
  path=$(fleet_remote_dir_from_ssh_stdout)
  if valid_fleet_run_dir "$path"; then
    printf '%s\n' "$path"
    exit 0
  fi
  echo "bad remote dir: $path" >&2
  exit 1
fi

# bash ≥4 (mapfile, ассоциативные массивы не обязательны, но mapfile нужен)
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "Нужен bash ≥4 (сейчас $BASH_VERSION). На macOS: brew install bash && /opt/homebrew/bin/bash $0" >&2
  exit 1
fi

SCRIPT="${SCRIPT:-./audit-ubuntu.sh}"
AUDIT_ARGS="${AUDIT_ARGS:---deep --no-net}"
PARALLEL="${PARALLEL:-3}"
SSH_STRICT="${SSH_STRICT:-yes}"
KEEP_REMOTE="${KEEP_REMOTE:-0}"
ALLOW_NO_REDACT="${ALLOW_NO_REDACT:-0}"

iso_now() { date -Is 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S%z"; }
LOCAL_DIR="fleet-audit-$(date +%Y%m%d-%H%M 2>/dev/null || date +%Y%m%d-%H%M)"

# --- whitelist AUDIT_ARGS (anti-injection на remote root) ---
validate_audit_args() {
  # shellcheck disable=SC2206
  local -a args=( $AUDIT_ARGS )
  local i=0
  while (( i < ${#args[@]} )); do
    case "${args[$i]}" in
      --deep|--no-net|--no-progress) ;;
      --no-redact)
        if [[ "$ALLOW_NO_REDACT" != "1" ]]; then
          echo "Запрещён --no-redact без ALLOW_NO_REDACT=1" >&2
          return 1
        fi
        ;;
      --progress)
        i=$((i+1))
        [[ "${args[$i]:-}" =~ ^(auto|on|off)$ ]] || { echo "Плохой --progress" >&2; return 1; }
        ;;
      --log-days|--timeout)
        i=$((i+1))
        [[ "${args[$i]:-}" =~ ^[0-9]+$ ]] || { echo "Плохой ${args[$((i-1))]}: ${args[$i]:-}" >&2; return 1; }
        ;;
      --out)
        echo "Запрещён --out во fleet (фиксированный /var/tmp/server-audit)" >&2
        return 1
        ;;
      *)
        echo "Недопустимый AUDIT_ARGS токен: ${args[$i]}" >&2
        return 1
        ;;
    esac
    i=$((i+1))
  done
  return 0
}

validate_audit_args || exit 2
[[ "$PARALLEL" =~ ^[1-9][0-9]*$ ]] || { echo "PARALLEL должен быть ≥1" >&2; exit 2; }

case "$SSH_STRICT" in
  yes) SSH_STRICT_OPT="yes" ;;
  accept-new) SSH_STRICT_OPT="accept-new" ;;
  *) echo "SSH_STRICT: yes|accept-new" >&2; exit 2 ;;
esac

# shellcheck disable=SC2206
SSH_OPTS_ARR=( -o "ConnectTimeout=10" -o "StrictHostKeyChecking=${SSH_STRICT_OPT}" -o "BatchMode=yes" )
if [[ -n "${SSH_OPTS:-}" ]]; then
  # дополнительные опции только как целые токены через пробел
  # shellcheck disable=SC2206
  SSH_OPTS_ARR+=( $SSH_OPTS )
fi

SERVERS=()
if [[ -f servers.txt ]]; then
  mapfile -t SERVERS < <(grep -vE '^\s*(#|$)' servers.txt)
fi

if [[ ${#SERVERS[@]} -eq 0 ]]; then
  echo "Список серверов пуст. Создайте servers.txt (user@host или user@[ipv6]:port)" >&2
  exit 1
fi

[[ -f "$SCRIPT" ]] || { echo "Не найден $SCRIPT" >&2; exit 1; }
[[ -x "$SCRIPT" ]] || chmod +x "$SCRIPT"

# sha256 локального скрипта для проверки на remote
if command -v sha256sum >/dev/null 2>&1; then
  LOCAL_SHA=$(sha256sum "$SCRIPT" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  LOCAL_SHA=$(shasum -a 256 "$SCRIPT" | awk '{print $1}')
else
  echo "Нужен sha256sum или shasum" >&2
  exit 1
fi

mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"

# --- разбор user@host[:port] / user@[ipv6]:port ---
parse_target() {
  # stdout: user@host_for_ssh \t port \t short_label
  local target="$1"
  local user host port=22 label

  if [[ "$target" != *@* ]]; then
    echo "Ожидается user@host: $target" >&2
    return 1
  fi
  user="${target%%@*}"
  host="${target#*@}"

  if [[ "$host" == \[* ]]; then
    # IPv6 в скобках: [addr] или [addr]:port
    local rest="${host#\[}"
    if [[ "$rest" != *\]* ]]; then
      echo "Незакрытая IPv6-скобка: $target" >&2
      return 1
    fi
    host="${rest%%\]*}"
    local after="${rest#*\]}"
    if [[ "$after" == :* ]]; then
      port="${after#:}"
      [[ "$port" =~ ^[0-9]+$ ]] || { echo "Плохой порт: $target" >&2; return 1; }
    elif [[ -n "$after" ]]; then
      echo "Мусор после IPv6: $target" >&2
      return 1
    fi
    label="${host}"
    printf '%s@%s\t%s\t%s\n' "$user" "$host" "$port" "$label"
    return 0
  fi

  # IPv4 / hostname: порт только если последний сегмент — чистое число
  if [[ "$host" == *:* ]]; then
    local maybe_port="${host##*:}"
    local maybe_host="${host%:*}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]] && [[ "$maybe_host" != *:* ]]; then
      host="$maybe_host"
      port="$maybe_port"
    elif [[ "$host" == *:*:* ]]; then
      echo "IPv6 указывайте в скобках: user@[2001:db8::1]:22" >&2
      return 1
    fi
  fi
  label="$host"
  printf '%s@%s\t%s\t%s\n' "$user" "$host" "$port" "$label"
}

audit_one() {
  local raw="$1"
  local parsed userhost port label
  parsed=$(parse_target "$raw") || return 1
  IFS=$'\t' read -r userhost port label <<<"$parsed"

  local safe_label="${label//\//_}"
  local logf="$LOCAL_DIR/${safe_label}.run.log"
  local remote_dir remote_script

  echo "[$safe_label] запуск..."
  {
    # безопасный каталог только для нашего пользователя (не world-writable /tmp)
    remote_raw=$(ssh -p "$port" "${SSH_OPTS_ARR[@]}" "$userhost" 'mkdir -p "$HOME/.cache/razbudimir-audit" && mktemp -d "$HOME/.cache/razbudimir-audit/run.XXXXXX"') \
      || return 1
    remote_dir=$(printf '%s\n' "$remote_raw" | fleet_remote_dir_from_ssh_stdout)
    if ! valid_fleet_run_dir "$remote_dir"; then
      echo "[$safe_label] ОШИБКА: неожиданный remote dir (MOTD?): $remote_dir"
      return 1
    fi
    remote_script="${remote_dir}/audit-ubuntu.sh"

    scp -P "$port" "${SSH_OPTS_ARR[@]}" "$SCRIPT" "${userhost}:${remote_script}" || return 1

    # проверить checksum и права, затем sudo -n (без интерактива)
    # shellcheck disable=SC2029
    ssh -p "$port" "${SSH_OPTS_ARR[@]}" "$userhost" \
      "chmod 700 '$remote_dir' && chmod 600 '$remote_script' && remote_sha=\$(sha256sum '$remote_script' | awk '{print \$1}') && \
       [[ \"\$remote_sha\" == '$LOCAL_SHA' ]] || { echo \"SHA mismatch: \$remote_sha != $LOCAL_SHA\" >&2; exit 3; } && \
       sudo -n bash '$remote_script' --out /var/tmp/server-audit $AUDIT_ARGS" \
      || { echo "[$safe_label] ОШИБКА: sudo -n / audit failed (нужен NOPASSWD)"; return 1; }

  } >"$logf" 2>&1

  local tarball
  tarball=$(grep -oE '/var/tmp/server-audit/[^[:space:]]+\.tar\.gz' "$logf" | head -1 || true)
  if [[ -z "$tarball" ]]; then
    echo "[$safe_label] ОШИБКА: архив не найден, смотрите $logf"
    ssh -p "$port" "${SSH_OPTS_ARR[@]}" "$userhost" "rm -rf '${remote_dir:-}'" >>"$logf" 2>&1 || true
    return 1
  fi
  # жёсткая проверка префикса пути
  case "$tarball" in
    /var/tmp/server-audit/*.tar.gz) ;;
    *) echo "[$safe_label] ОШИБКА: подозрительный путь архива: $tarball"; return 1 ;;
  esac

  scp -P "$port" "${SSH_OPTS_ARR[@]}" "${userhost}:${tarball}" "$LOCAL_DIR/${safe_label}.tar.gz" >>"$logf" 2>&1 \
    || { echo "[$safe_label] ОШИБКА копирования"; return 1; }
  chmod 600 "$LOCAL_DIR/${safe_label}.tar.gz"

  # cleanup remote: скрипт + (опционально) архивы аудита
  if [[ "$KEEP_REMOTE" == "1" ]]; then
    ssh -p "$port" "${SSH_OPTS_ARR[@]}" "$userhost" "rm -rf '$remote_dir'" >>"$logf" 2>&1 || true
  else
    # shellcheck disable=SC2029
    ssh -p "$port" "${SSH_OPTS_ARR[@]}" "$userhost" \
      "rm -rf '$remote_dir'; base='${tarball%.tar.gz}'; sudo -n rm -rf \"\$base\" \"${tarball}\" \"${tarball}.sha256\" 2>/dev/null || rm -rf \"\$base\" \"${tarball}\" \"${tarball}.sha256\" 2>/dev/null || true" \
      >>"$logf" 2>&1 || true
  fi

  mkdir -p "$LOCAL_DIR/extracted/${safe_label}"
  tar -xzf "$LOCAL_DIR/${safe_label}.tar.gz" -C "$LOCAL_DIR/extracted/${safe_label}" --strip-components=1
  echo "[$safe_label] OK -> $LOCAL_DIR/${safe_label}.tar.gz"
}

export -f audit_one parse_target iso_now fleet_remote_dir_from_ssh_stdout valid_fleet_run_dir
export LOCAL_DIR SCRIPT AUDIT_ARGS KEEP_REMOTE LOCAL_SHA
export SSH_OPTS_ARR PARALLEL
# SSH_OPTS_ARR не экспортируется как массив в bash — передаём через строку
export SSH_OPTS_EXPORT="${SSH_OPTS_ARR[*]}"

# обёртка для subshell: восстановить SSH_OPTS_ARR
audit_one_wrap() {
  # shellcheck disable=SC2206
  SSH_OPTS_ARR=( $SSH_OPTS_EXPORT )
  audit_one "$@"
}
export -f audit_one_wrap

fail=0
pids=()
for s in "${SERVERS[@]}"; do
  audit_one_wrap "$s" &
  pids+=($!)
  if (( ${#pids[@]} >= PARALLEL )); then
    for pid in "${pids[@]}"; do
      wait "$pid" || fail=1
    done
    pids=()
  fi
done
for pid in "${pids[@]}"; do
  wait "$pid" || fail=1
done

# сводный индекс по парку (через python3 → валидный разбор facts.json)
{
  echo "# Fleet audit — $(iso_now)"
  echo
  echo "| Хост | ОС | Ядро | Virt | vCPU | RAM(GB) | Пакетов | Обновлений | Failed units | Reboot | Изм. conffiles |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$LOCAL_DIR" <<'PY'
import json, os, sys
root = sys.argv[1]
ext = os.path.join(root, "extracted")
if not os.path.isdir(ext):
    sys.exit(0)
for name in sorted(os.listdir(ext)):
    f = os.path.join(ext, name, "00-meta", "facts.json")
    if not os.path.isfile(f):
        continue
    try:
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception as e:
        print(f"| {name} | (bad facts.json: {e}) | | | | | | | | | |")
        continue
    mem = int(d.get("mem_total_kb") or 0) // 1048576
    def g(k, default=""):
        v = d.get(k, default)
        return str(v).replace("|", "\\|")
    print("| {h} | {os} | {k} | {v} | {c} | {m} | {p} | {u} | {f} | {r} | {mc} |".format(
        h=g("hostname", name), os=g("os"), k=g("kernel"), v=g("virtualization"),
        c=g("cpu_count"), m=mem, p=g("packages_installed"), u=g("packages_upgradable"),
        f=g("failed_units"), r=g("reboot_required"), mc=g("modified_conffiles"),
    ))
PY
  else
    echo "| (python3 недоступен — INDEX без автозаполнения) | | | | | | | | | | |"
  fi
} > "$LOCAL_DIR/INDEX.md"
chmod 600 "$LOCAL_DIR/INDEX.md" 2>/dev/null || true

# diff-заготовки для стандартизации
mkdir -p "$LOCAL_DIR/compare"
for art in 04-packages/apt-mark-manual.txt 04-packages/apt-sources.txt \
           05-services/systemctl-enabled.txt 06-network/listening-ports.txt \
           01-system/sysctl-files.txt 16-scheduled/crontabs.txt; do
  name=$(basename "$art" .txt)
  : > "$LOCAL_DIR/compare/${name}.all.tsv"
  for d in "$LOCAL_DIR"/extracted/*/; do
    [[ -d "$d" ]] || continue
    h=$(basename "$d")
    if [[ -f "$d/$art" ]]; then
      # пропускаем 3-строчный заголовок CMD коллектора
      sed '1,3d' "$d/$art" | sed "s|^|$h\t|" >> "$LOCAL_DIR/compare/${name}.all.tsv"
    fi
  done
done

: > "$LOCAL_DIR/compare/packages-matrix.tsv"
for d in "$LOCAL_DIR"/extracted/*/; do
  [[ -d "$d" ]] || continue
  h=$(basename "$d")
  if [[ -f "$d/04-packages/dpkg-installed.tsv" ]]; then
    awk -F'\t' -v h="$h" 'NR>3{print h"\t"$1"\t"$2}' "$d/04-packages/dpkg-installed.tsv" \
      >> "$LOCAL_DIR/compare/packages-matrix.tsv"
  fi
done
if [[ -s "$LOCAL_DIR/compare/packages-matrix.tsv" ]]; then
  awk -F'\t' '{c[$2]++; v[$2]=v[$2]" "$1":"$3} END{for(p in c) print c[p]"\t"p"\t"v[p]}' \
    "$LOCAL_DIR/compare/packages-matrix.tsv" | sort -n > "$LOCAL_DIR/compare/package-presence-by-hostcount.tsv"
fi

echo
echo "Готово. Смотрите $LOCAL_DIR/INDEX.md и $LOCAL_DIR/compare/"
if (( fail )); then
  echo "ВНИМАНИЕ: один или несколько хостов завершились с ошибкой (см. *.run.log)" >&2
  exit 1
fi
exit 0
