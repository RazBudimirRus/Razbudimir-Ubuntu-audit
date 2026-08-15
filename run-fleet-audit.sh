#!/usr/bin/env bash
# ============================================================================
#  run-fleet-audit.sh — запуск audit-ubuntu.sh на парке серверов и сбор архивов
#  Запускается с рабочей машины (macOS/Linux), требует ssh-доступ с sudo.
#
#  1) Заполните SERVERS ниже (или создайте файл servers.txt: одна строка = один host)
#  2) ./run-fleet-audit.sh
#  Результат: ./fleet-audit-<дата>/<host>.tar.gz + распакованные каталоги + INDEX.md
# ============================================================================
set -uo pipefail

SCRIPT="${SCRIPT:-./audit-ubuntu.sh}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes}"
AUDIT_ARGS="${AUDIT_ARGS:---deep}"          # например: --deep --log-days 14
PARALLEL="${PARALLEL:-3}"                   # одновременных SSH-сессий
LOCAL_DIR="fleet-audit-$(date +%Y%m%d-%H%M)"

# Список серверов: user@host[:port] — правьте здесь или используйте servers.txt
SERVERS=(
  # "ubuntu@10.0.0.11"
  # "ubuntu@10.0.0.12"
)

if [[ -f servers.txt ]]; then
  mapfile -t SERVERS < <(grep -vE '^\s*(#|$)' servers.txt)
fi

if [[ ${#SERVERS[@]} -eq 0 ]]; then
  echo "Список серверов пуст. Заполните массив SERVERS в скрипте или создайте servers.txt" >&2
  exit 1
fi

[[ -f "$SCRIPT" ]] || { echo "Не найден $SCRIPT" >&2; exit 1; }
mkdir -p "$LOCAL_DIR"

audit_one() {
  local target="$1"
  local host="${target#*@}"; host="${host%%:*}"
  local port=22
  [[ "$target" == *:* ]] && port="${target##*:}" && target="${target%:*}"
  local logf="$LOCAL_DIR/${host}.run.log"

  echo "[$host] запуск..." 
  {
    scp -P "$port" $SSH_OPTS "$SCRIPT" "${target}:/tmp/audit-ubuntu.sh" || return 1
    # shellcheck disable=SC2029
    ssh -p "$port" $SSH_OPTS "$target" "sudo -n bash /tmp/audit-ubuntu.sh --out /var/tmp/server-audit $AUDIT_ARGS" \
      || ssh -p "$port" $SSH_OPTS -t "$target" "sudo bash /tmp/audit-ubuntu.sh --out /var/tmp/server-audit $AUDIT_ARGS"
  } >"$logf" 2>&1

  local tarball
  tarball=$(grep -oE '/var/tmp/server-audit/[^ ]+\.tar\.gz' "$logf" | head -1)
  if [[ -z "$tarball" ]]; then
    echo "[$host] ОШИБКА: архив не найден, смотрите $logf"
    return 1
  fi
  scp -P "$port" $SSH_OPTS "${target}:${tarball}" "$LOCAL_DIR/${host}.tar.gz" >>"$logf" 2>&1 \
    || { echo "[$host] ОШИБКА копирования"; return 1; }
  ssh -p "$port" $SSH_OPTS "$target" "rm -f /tmp/audit-ubuntu.sh" >>"$logf" 2>&1
  ( cd "$LOCAL_DIR" && mkdir -p "extracted/$host" && tar -xzf "${host}.tar.gz" -C "extracted/$host" --strip-components=1 )
  echo "[$host] OK -> $LOCAL_DIR/${host}.tar.gz"
}

export -f audit_one
export LOCAL_DIR SCRIPT SSH_OPTS AUDIT_ARGS

pids=()
i=0
for s in "${SERVERS[@]}"; do
  audit_one "$s" &
  pids+=($!)
  ((++i % PARALLEL == 0)) && wait
done
wait

# сводный индекс по парку
{
  echo "# Fleet audit — $(date -Is)"
  echo
  echo "| Хост | ОС | Ядро | Virt | vCPU | RAM(GB) | Пакетов | Обновлений | Failed units | Reboot | Изм. conffiles |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
  for d in "$LOCAL_DIR"/extracted/*/; do
    f="$d/00-meta/facts.json"
    [[ -f "$f" ]] || continue
    g() { grep -oE "\"$1\": *\"?[^,\"}]*" "$f" | head -1 | sed "s/.*: *\"*//"; }
    mem=$(( $(g mem_total_kb 2>/dev/null || echo 0) / 1048576 ))
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
      "$(g hostname)" "$(g os)" "$(g kernel)" "$(g virtualization)" "$(g cpu_count)" \
      "$mem" "$(g packages_installed)" "$(g packages_upgradable)" "$(g failed_units)" \
      "$(g reboot_required)" "$(g modified_conffiles)"
  done
} > "$LOCAL_DIR/INDEX.md"

# diff-заготовки для стандартизации: что отличается между серверами
mkdir -p "$LOCAL_DIR/compare"
for art in 04-packages/apt-mark-manual.txt 04-packages/apt-sources.txt \
           05-services/systemctl-enabled.txt 06-network/listening-ports.txt \
           01-system/sysctl-files.txt 16-scheduled/crontabs.txt; do
  name=$(basename "$art" .txt)
  for d in "$LOCAL_DIR"/extracted/*/; do
    h=$(basename "$d")
    [[ -f "$d/$art" ]] && sed '1,3d' "$d/$art" | sed "s|^|$h\t|"
  done > "$LOCAL_DIR/compare/${name}.all.tsv" 2>/dev/null
done

# общий/уникальный набор пакетов по парку
for d in "$LOCAL_DIR"/extracted/*/; do
  h=$(basename "$d")
  [[ -f "$d/04-packages/dpkg-installed.tsv" ]] && awk -F'\t' -v h="$h" 'NR>3{print h"\t"$1"\t"$2}' "$d/04-packages/dpkg-installed.tsv"
done > "$LOCAL_DIR/compare/packages-matrix.tsv"
awk -F'\t' '{c[$2]++; v[$2]=v[$2]" "$1":"$3} END{for(p in c) print c[p]"\t"p"\t"v[p]}' \
  "$LOCAL_DIR/compare/packages-matrix.tsv" | sort -n > "$LOCAL_DIR/compare/package-presence-by-hostcount.tsv"

echo
echo "Готово. Смотрите $LOCAL_DIR/INDEX.md и $LOCAL_DIR/compare/"
echo "Загрузите в чат: все *.tar.gz (или extracted/*/00-meta/summary.md для быстрого старта)."
