#!/usr/bin/env bash
# ============================================================================
#  audit-ubuntu.sh — полный инвентаризационно-диагностический сбор с Ubuntu
#  Назначение: собрать максимум машинно-читаемой информации об инсталляции
#  сервера (пакеты, конфиги, сеть, ФС, systemd, контейнеры, логи, ошибки,
#  безопасность, drift относительно пакетов) для последующего анализа
#  LLM-агентами и подготовки стандартизации через Ansible.
#
#  Использование:
#     sudo bash audit-ubuntu.sh                       # обычный сбор
#     sudo bash audit-ubuntu.sh --out /data/audit     # свой каталог
#     sudo bash audit-ubuntu.sh --deep                # + SMART, полный dpkg -V, fs-скан
#     sudo bash audit-ubuntu.sh --no-redact           # не маскировать секреты (НЕ рекомендуется)
#     sudo bash audit-ubuntu.sh --no-net              # без внешних сетевых проверок
#     sudo bash audit-ubuntu.sh --log-days 14         # глубина журналов (по умолчанию 7)
#
#  Результат: <out>/<hostname>-<timestamp>/  + тот же каталог в .tar.gz + .sha256
#  Скрипт read-only: ничего не устанавливает, не меняет конфиги, не рестартует сервисы.
#  Единственные записи — внутри каталога вывода.
# ============================================================================

set -uo pipefail
umask 077

VERSION="1.2.0"
START_EPOCH=$(date +%s)

# ---------------------------- параметры -------------------------------------
OUTBASE="/var/tmp/server-audit"
DEEP=0
REDACT=1
NETCHECKS=1
LOG_DAYS=7
CMD_TIMEOUT=180

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)        OUTBASE="${2:?}"; shift 2 ;;
    --deep)       DEEP=1; shift ;;
    --no-redact)  REDACT=0; shift ;;
    --no-net)     NETCHECKS=0; shift ;;
    --log-days)   LOG_DAYS="${2:?}"; shift 2 ;;
    --timeout)    CMD_TIMEOUT="${2:?}"; shift 2 ;;
    -h|--help)    sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

HOST="$(hostname -f 2>/dev/null || hostname)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUTBASE}/${HOST}-${TS}"
mkdir -p "$OUT" || { echo "Не могу создать $OUT" >&2; exit 1; }

for d in 00-meta 01-system 02-hardware 03-kernel 04-packages 05-services \
         06-network 07-storage 08-security 09-performance 10-logs 11-containers \
         12-apps 13-configs 14-drift 15-monitoring 16-scheduled; do
  mkdir -p "$OUT/$d"
done

MANIFEST="$OUT/00-meta/manifest.tsv"
printf 'section\tartifact\tcommand\texit_code\tbytes\tduration_ms\n' > "$MANIFEST"
LOGFILE="$OUT/00-meta/collector.log"
: > "$LOGFILE"

IS_ROOT=0; [[ "$(id -u)" -eq 0 ]] && IS_ROOT=1

# ---------------------------- хелперы --------------------------------------
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOGFILE" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# redact: маскирование очевидных секретов в текстовых артефактах
redact_stream() {
  if [[ "$REDACT" -eq 0 ]]; then cat; return; fi
  sed -E \
    -e 's/((PASSWORD|PASSWD|PASS|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET|BEARER|AUTH_TOKEN|DB_PASS|MYSQL_PWD|PGPASSWORD|psk|pre-shared-key)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1<REDACTED>/Ig' \
    -e 's/((community|rocommunity|rwcommunity|passphrase|credentials|auth-user-pass)[[:space:]]+)[^[:space:]]+/\1<REDACTED>/Ig' \
    -e 's#(://[^:/@[:space:]]+):[^@[:space:]]+@#\1:<REDACTED>@#g' \
    -e 's/(ssh-(rsa|ed25519|dss)[[:space:]]+)[A-Za-z0-9+\/=]{40,}/\1<PUBKEY-TRUNCATED>/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----/<PRIVATE-KEY-REMOVED>/g' \
    -e 's/(x-api-key|authorization)([[:space:]]*[:=][[:space:]]*).*/\1\2<REDACTED>/Ig'
}

# run <section> <artifact-file> <описание-команды...>
run() {
  local section="$1"; local artifact="$2"; shift 2
  local target="$OUT/$section/$artifact"
  local t0 t1 rc bytes
  t0=$(( $(date +%s%N 2>/dev/null || echo 0) / 1000000 ))
  {
    printf '### CMD: %s\n### HOST: %s  TIME: %s\n\n' "$*" "$HOST" "$(date -Is)"
  } > "$target"
  if have timeout; then
    timeout -k 5 "$CMD_TIMEOUT" bash -c "$*" 2>&1 | redact_stream >> "$target"
    rc=${PIPESTATUS[0]}
  else
    bash -c "$*" 2>&1 | redact_stream >> "$target"
    rc=${PIPESTATUS[0]}
  fi
  t1=$(( $(date +%s%N 2>/dev/null || echo 0) / 1000000 ))
  bytes=$(stat -c %s "$target" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$section" "$artifact" "$*" "$rc" "$bytes" "$((t1-t0))" >> "$MANIFEST"
  return 0
}

# runif <cmd> <section> <artifact> <команда...>
runif() {
  local req="$1"; shift
  if have "$req"; then run "$@"; else
    printf '%s\t%s\tSKIPPED (нет %s)\t127\t0\t0\n' "$1" "$2" "$req" >> "$MANIFEST"
  fi
}

# copy_cfg <источник> — безопасно копирует файл/каталог в 13-configs с маскированием
copy_cfg() {
  local src="$1"
  [[ -e "$src" ]] || return 0
  local dst="$OUT/13-configs${src}"
  if [[ -d "$src" ]]; then
    while IFS= read -r -d '' f; do
      copy_cfg "$f"
    done < <(find "$src" -maxdepth 4 -type f -size -512k \
              ! -name '*.key' ! -name '*.pem' ! -name '*_key' ! -name 'id_*' \
              ! -name '*.p12' ! -name '*.pfx' ! -name '*.jks' ! -name '*.db' \
              ! -name '*.sqlite*' ! -name '*.gz' ! -name '*.jpg' ! -name '*.png' \
              -print0 2>/dev/null)
    return 0
  fi
  # пропускаем бинарные файлы
  if file -b --mime-encoding "$src" 2>/dev/null | grep -q binary; then return 0; fi
  [[ -r "$src" ]] || { echo "UNREADABLE (нет прав): $src" >> "$OUT/13-configs/_unreadable.txt"; return 0; }
  mkdir -p "$(dirname "$dst")" 2>/dev/null || return 0
  { redact_stream < "$src" > "$dst"; } 2>/dev/null
  # права/владелец важны для аудита
  stat -c '%A %U:%G %n' "$src" >> "$OUT/13-configs/_permissions.txt" 2>/dev/null
}

log "audit-ubuntu.sh v$VERSION → $OUT (root=$IS_ROOT, deep=$DEEP, redact=$REDACT)"
[[ "$IS_ROOT" -eq 1 ]] || log "ВНИМАНИЕ: запуск не от root — часть данных будет недоступна. Рекомендуется sudo."

# ============================== 00 META =====================================
{
  echo "collector_version: $VERSION"
  echo "collected_at: $(date -Is)"
  echo "collected_at_utc: $(date -u -Is)"
  echo "hostname: $HOST"
  echo "hostname_short: $(hostname -s 2>/dev/null)"
  echo "uptime: $(uptime -p 2>/dev/null)"
  echo "boot_time: $(uptime -s 2>/dev/null)"
  echo "run_as_root: $IS_ROOT"
  echo "deep_mode: $DEEP"
  echo "redaction: $REDACT"
  echo "log_days: $LOG_DAYS"
  echo "machine_id: $(cat /etc/machine-id 2>/dev/null)"
  echo "product_uuid: $(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo n/a)"
} > "$OUT/00-meta/collection-info.txt"

# ============================== 01 SYSTEM ===================================
run 01-system os-release.txt              'cat /etc/os-release; echo; cat /etc/lsb-release 2>/dev/null'
run 01-system lsb-hostnamectl.txt         'lsb_release -a 2>/dev/null; echo; hostnamectl 2>/dev/null'
run 01-system uname.txt                   'uname -a; echo; cat /proc/version'
run 01-system uptime-loadavg.txt          'uptime; echo; cat /proc/loadavg; echo; who -b 2>/dev/null; last -x -n 30 reboot shutdown 2>/dev/null'
run 01-system timedate.txt                'timedatectl 2>/dev/null; echo; date -Is; echo; cat /etc/timezone 2>/dev/null'
runif chronyc 01-system chrony.txt        'chronyc tracking; echo; chronyc sources -v; echo; chronyc sourcestats'
run 01-system timesync.txt                'timedatectl show-timesync 2>/dev/null; systemctl status systemd-timesyncd --no-pager 2>/dev/null; systemctl status ntp chrony chronyd --no-pager 2>/dev/null'
run 01-system locale-env.txt              'locale; echo "--- /etc/default/locale"; cat /etc/default/locale 2>/dev/null; echo "--- env(root shell)"; env | sort'
run 01-system release-upgrade.txt         'cat /etc/update-motd.d/91-release-upgrade 2>/dev/null | head -5; do-release-upgrade -c 2>&1 | head -20; ubuntu-support-status 2>&1 | head -40'
run 01-system cloud-init.txt              'cloud-init status --long 2>/dev/null; echo; cloud-id 2>/dev/null; ls -la /etc/cloud/cloud.cfg.d/ 2>/dev/null; cat /etc/cloud/cloud.cfg.d/*.cfg 2>/dev/null | head -100'
run 01-system virt-what.txt               'systemd-detect-virt 2>/dev/null; echo "---"; virt-what 2>/dev/null; echo "--- dmi"; cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/board_vendor 2>/dev/null; echo "--- hypervisor flags"; grep -o "hypervisor" /proc/cpuinfo | head -1; ls /dev/virtio-ports 2>/dev/null; lsmod | grep -Ei "virtio|vmw|hv_|xen|kvm" '
run 01-system limits-sysctl.txt           'ulimit -a; echo "=== sysctl -a (non-default relevant) ==="; sysctl -a 2>/dev/null | sort'
run 01-system sysctl-files.txt            'ls -la /etc/sysctl.d/ /etc/sysctl.conf 2>/dev/null; echo; grep -rHv "^[[:space:]]*#" /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null | grep -v "^[[:space:]]*$"'

# ============================== 02 HARDWARE =================================
run 02-hardware cpuinfo.txt               'lscpu; echo "=== /proc/cpuinfo (первое ядро) ==="; awk "/^processor/{n++} n<2" /proc/cpuinfo; echo "=== cores total ==="; nproc --all; echo "=== vulnerabilities ==="; grep -r . /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null'
run 02-hardware cpu-freq-governor.txt     'cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c; cpupower frequency-info 2>/dev/null | head -30'
run 02-hardware memory.txt                'free -h; echo; free -b; echo "=== /proc/meminfo ==="; cat /proc/meminfo; echo "=== hugepages ==="; grep -i huge /proc/meminfo; cat /proc/sys/vm/nr_hugepages 2>/dev/null'
runif dmidecode 02-hardware dmidecode.txt 'dmidecode -t system -t baseboard -t bios -t processor -t memory 2>/dev/null'
runif lshw 02-hardware lshw-short.txt     'lshw -short 2>/dev/null'
run 02-hardware pci-usb.txt               'lspci -nnk 2>/dev/null; echo "=== USB ==="; lsusb 2>/dev/null'
run 02-hardware numa.txt                  'numactl --hardware 2>/dev/null; lscpu | grep -i numa'
run 02-hardware sensors-ipmi.txt          'sensors 2>/dev/null; echo "=== ipmitool sdr ==="; ipmitool sdr list 2>/dev/null | head -60; echo "=== ipmi chassis ==="; ipmitool chassis status 2>/dev/null'

# ============================== 03 KERNEL / BOOT ============================
run 03-kernel kernel-cmdline.txt          'cat /proc/cmdline; echo "=== running kernel ==="; uname -r; echo "=== installed kernels ==="; dpkg -l | grep -E "linux-(image|headers|modules)" ; echo "=== needrestart/reboot ==="; ls -la /var/run/reboot-required* 2>/dev/null; cat /var/run/reboot-required.pkgs 2>/dev/null'
run 03-kernel modules.txt                 'lsmod; echo "=== /etc/modules ==="; cat /etc/modules 2>/dev/null; echo "=== modprobe.d ==="; grep -rH . /etc/modprobe.d/ 2>/dev/null'
run 03-kernel boot-config.txt             'ls -la /boot; echo "=== grub default ==="; grep -v "^#" /etc/default/grub 2>/dev/null; echo "=== grub.cfg menuentries ==="; grep -E "^menuentry|^\s+linux" /boot/grub/grub.cfg 2>/dev/null | head -40; echo "=== initramfs conf ==="; cat /etc/initramfs-tools/initramfs.conf 2>/dev/null | grep -v "^#"'
run 03-kernel secureboot-efi.txt          'mokutil --sb-state 2>/dev/null; ls /sys/firmware/efi >/dev/null 2>&1 && echo "boot mode: UEFI" || echo "boot mode: BIOS/legacy"; efibootmgr -v 2>/dev/null'
run 03-kernel systemd-analyze.txt         'systemd-analyze 2>/dev/null; echo; systemd-analyze blame 2>/dev/null | head -40; echo "=== critical-chain ==="; systemd-analyze critical-chain 2>/dev/null'
runif kdump-config 03-kernel kdump.txt    'kdump-config show 2>/dev/null; ls -la /var/crash 2>/dev/null'
run 03-kernel livepatch.txt               'canonical-livepatch status --verbose 2>/dev/null; pro status --all 2>/dev/null || ua status --all 2>/dev/null'

# ============================== 04 PACKAGES =================================
run 04-packages dpkg-list-full.txt        'dpkg -l'
run 04-packages dpkg-installed.tsv        'dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\t\${Status}\t\${Priority}\t\${Section}\t\${Installed-Size}\t\${Maintainer}\n" | sort'
run 04-packages dpkg-count.txt            'dpkg-query -W -f="\${Status}\n" | sort | uniq -c; echo "=== всего установлено ==="; dpkg-query -W -f="\${Status}\n" | grep -c "install ok installed"'
run 04-packages apt-mark-manual.txt       'apt-mark showmanual | sort'
run 04-packages apt-mark-auto.txt         'apt-mark showauto | sort'
run 04-packages apt-mark-hold.txt         'apt-mark showhold; echo "=== dpkg holds ==="; dpkg --get-selections | grep -v "install$"'
run 04-packages apt-sources.txt           'cat /etc/apt/sources.list 2>/dev/null | grep -v "^\s*#"; echo "=== sources.list.d ==="; for f in /etc/apt/sources.list.d/*; do [ -f "$f" ] && { echo "--- $f"; grep -v "^\s*#" "$f" | grep -v "^$"; }; done'
run 04-packages apt-keys.txt              'apt-key list 2>/dev/null; echo "=== trusted.gpg.d ==="; ls -la /etc/apt/trusted.gpg.d/ /etc/apt/keyrings/ 2>/dev/null'
run 04-packages apt-config.txt            'apt-config dump | sort; echo "=== apt.conf.d ==="; grep -rH . /etc/apt/apt.conf.d/ 2>/dev/null | grep -v "^\s*//"'
run 04-packages apt-policy.txt            'apt-cache policy'
run 04-packages apt-upgradable.txt        'apt-get -s -o Debug::NoLocking=1 upgrade 2>&1 | tail -40; echo "=== apt list --upgradable ==="; apt list --upgradable 2>/dev/null'
run 04-packages apt-security-updates.txt  '/usr/lib/update-notifier/apt-check --human-readable 2>&1; echo "=== unattended-upgrades config ==="; grep -rHv "^\s*//" /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -v "^\s*$"'
run 04-packages apt-history.txt           "zcat -f /var/log/apt/history.log* 2>/dev/null | tail -2000"
run 04-packages dpkg-log-recent.txt       "zcat -f /var/log/dpkg.log* 2>/dev/null | grep -E ' (install|upgrade|remove|purge) ' | tail -2000"
run 04-packages ppa-and-thirdparty.txt    'grep -rhoE "https?://[^ ]+" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sort -u'
run 04-packages residual-config.txt       'dpkg -l | awk "/^rc/{print \$2}"'
run 04-packages snap.txt                  'snap list --all 2>/dev/null; echo "=== snap changes ==="; snap changes 2>/dev/null | tail -20; echo "=== snap connections ==="; snap connections 2>/dev/null | head -60'
run 04-packages flatpak.txt               'flatpak list 2>/dev/null'
run 04-packages pip-python.txt            'python3 -V; which -a python3 python3.* 2>/dev/null; echo "=== pip freeze (system) ==="; pip3 freeze 2>/dev/null || python3 -m pip freeze 2>/dev/null; echo "=== pipx ==="; pipx list 2>/dev/null; echo "=== venvs (поиск) ==="; find /opt /srv /home /root /usr/local -maxdepth 4 -name pyvenv.cfg 2>/dev/null | head -50'
run 04-packages node-npm.txt              'node -v 2>/dev/null; npm -v 2>/dev/null; echo "=== npm -g ==="; npm ls -g --depth=0 2>/dev/null; echo "=== yarn/pnpm ==="; yarn --version 2>/dev/null; pnpm --version 2>/dev/null'
run 04-packages other-langs.txt           'for c in go java javac ruby gem perl php php-fpm rustc cargo docker kubectl helm terraform ansible ansible-playbook git make gcc g++ cmake; do printf "%-16s " "$c"; command -v $c >/dev/null 2>&1 && $c --version 2>&1 | head -1 || echo "not installed"; done'
run 04-packages gem-cpan.txt              'command -v gem >/dev/null 2>&1 && gem list --local 2>/dev/null | head -100; echo "=== perl модули (из пакетов) ==="; dpkg -l | grep -c "^ii  lib.*-perl" 2>/dev/null'
run 04-packages manual-installs.txt       'echo "=== файлы в /usr/local (не принадлежат dpkg) ==="; find /usr/local -maxdepth 3 -type f -executable 2>/dev/null | head -200; echo "=== /opt ==="; ls -la /opt 2>/dev/null; echo "=== /srv ==="; ls -la /srv 2>/dev/null'

# определение источника (repo/origin) для каждого пакета — очень полезно для поиска "левых" пакетов
if have python3 && python3 -c "import apt" 2>/dev/null; then
  python3 - <<'PY' > "$OUT/04-packages/package-origins.tsv" 2>>"$LOGFILE"
import apt
c = apt.Cache()
print("package\tversion\torigin\tarchive\tsite\tcomponent\ttrusted")
for p in c:
    if not p.is_installed: continue
    v = p.installed
    o = v.origins[0] if v.origins else None
    print("\t".join([p.name, v.version,
                     getattr(o,'origin','') or 'LOCAL/UNKNOWN',
                     getattr(o,'archive','') or '',
                     getattr(o,'site','') or '',
                     getattr(o,'component','') or '',
                     str(getattr(o,'trusted',''))]))
PY
  printf '04-packages\tpackage-origins.tsv\tpython3-apt origins\t0\t%s\t0\n' \
    "$(stat -c %s "$OUT/04-packages/package-origins.tsv" 2>/dev/null || echo 0)" >> "$MANIFEST"
  run 04-packages packages-not-from-ubuntu.txt "awk -F'\t' 'NR>1 && \$3!=\"Ubuntu\" {print \$3\"\t\"\$1\"\t\"\$2\"\t\"\$5}' '$OUT/04-packages/package-origins.tsv' | sort"
fi

# ============================== 05 SERVICES =================================
run 05-services systemctl-units.txt       'systemctl list-units --all --no-pager --no-legend'
run 05-services systemctl-unit-files.txt  'systemctl list-unit-files --no-pager --no-legend'
run 05-services systemctl-enabled.txt     'systemctl list-unit-files --state=enabled --no-pager'
run 05-services systemctl-failed.txt      'systemctl --failed --no-pager; echo "=== degraded? ==="; systemctl is-system-running'
run 05-services systemctl-services-running.txt 'systemctl list-units --type=service --state=running --no-pager'
run 05-services systemctl-masked.txt      'systemctl list-unit-files --state=masked --no-pager; echo "=== static ==="; systemctl list-unit-files --state=static --no-pager | head -60'
run 05-services custom-units.txt          'ls -la /etc/systemd/system/ /etc/systemd/system/*.d/ 2>/dev/null; echo "=== содержимое кастомных unit-файлов ==="; for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.socket /etc/systemd/system/*.mount /etc/systemd/system/*.target; do [ -f "$f" ] && { echo "----- $f"; cat "$f"; }; done'
run 05-services systemd-dropins.txt       'systemd-delta --no-pager 2>/dev/null'
run 05-services sysv-initd.txt            'ls -la /etc/init.d/ 2>/dev/null; echo "=== rc.local ==="; cat /etc/rc.local 2>/dev/null; echo "=== upstart ==="; ls /etc/init/ 2>/dev/null'
run 05-services service-resources.txt     'systemd-cgtop -n 1 -b --no-pager 2>/dev/null | head -40; echo "=== slice/limits ==="; systemctl show "*.service" -p Id -p MemoryMax -p CPUQuotaPerSecUSec -p Restart -p User 2>/dev/null | head -300'

# ============================== 06 NETWORK ==================================
run 06-network ip-addr.txt                'ip -d addr show; echo "=== JSON ==="; ip -j -d addr show 2>/dev/null'
run 06-network ip-link.txt                'ip -d link show; echo "=== statistics ==="; ip -s link'
run 06-network ip-route.txt               'ip route show table all; echo "=== rules ==="; ip rule show; echo "=== v6 ==="; ip -6 route show table all'
run 06-network ip-neigh.txt               'ip neigh show; echo "=== v6 ==="; ip -6 neigh show'
run 06-network netplan.txt                'ls -la /etc/netplan/ 2>/dev/null; echo; grep -rH "" /etc/netplan/*.yaml 2>/dev/null; echo "=== netplan get ==="; netplan get 2>/dev/null; echo "=== generated backends ==="; ls -la /run/systemd/network/ 2>/dev/null; cat /run/systemd/network/*.network 2>/dev/null'
run 06-network networkd-nm.txt            'networkctl status --all --no-pager 2>/dev/null; echo "=== NetworkManager ==="; nmcli -t device status 2>/dev/null; nmcli -t connection show 2>/dev/null; echo "=== ifupdown legacy ==="; cat /etc/network/interfaces 2>/dev/null; ls /etc/network/interfaces.d/ 2>/dev/null'
run 06-network dns.txt                    'cat /etc/resolv.conf; echo "=== symlink? ==="; ls -la /etc/resolv.conf; echo "=== resolvectl ==="; resolvectl status 2>/dev/null; echo "=== nsswitch ==="; cat /etc/nsswitch.conf 2>/dev/null; echo "=== hosts ==="; cat /etc/hosts; echo "=== hostname ==="; cat /etc/hostname'
run 06-network listening-ports.txt        'ss -tulpnH 2>/dev/null | sort -k1,1 -k5,5; echo "=== все сокеты сводно ==="; ss -s; echo "=== unix ==="; ss -xlp 2>/dev/null | head -80'
run 06-network established-conns.txt      'ss -tanp state established 2>/dev/null | head -200; echo "=== по процессам ==="; ss -tanp 2>/dev/null | awk "{print \$NF}" | grep -o "users:((\"[^\"]*\"" | sort | uniq -c | sort -rn | head -40'
run 06-network firewall-iptables.txt      'iptables-save 2>/dev/null; echo "=== v6 ==="; ip6tables-save 2>/dev/null; echo "=== counters filter ==="; iptables -L -n -v 2>/dev/null; echo "=== nat ==="; iptables -t nat -L -n -v 2>/dev/null'
run 06-network firewall-nft.txt           'nft list ruleset 2>/dev/null'
run 06-network firewall-ufw.txt           'ufw status verbose 2>/dev/null; echo "=== ufw app list ==="; ufw app list 2>/dev/null; echo "=== ufw конфиги ==="; cat /etc/ufw/*.rules 2>/dev/null | head -200; grep -v "^#" /etc/default/ufw 2>/dev/null'
run 06-network firewall-firewalld.txt     'firewall-cmd --list-all-zones 2>/dev/null'
run 06-network conntrack-sysctl.txt       'sysctl -a 2>/dev/null | grep -E "net\.(ipv4|ipv6|core|netfilter|bridge)" | sort; echo "=== conntrack count ==="; cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null'
run 06-network interface-details.txt      'for i in $(ls /sys/class/net); do echo "===== $i"; ethtool "$i" 2>/dev/null | head -25; ethtool -i "$i" 2>/dev/null; ethtool -k "$i" 2>/dev/null | head -25; ethtool -S "$i" 2>/dev/null | grep -Ei "err|drop|discard|fail" ; cat /sys/class/net/$i/mtu /sys/class/net/$i/operstate 2>/dev/null; done'
run 06-network bonding-vlan-bridge.txt    'cat /proc/net/bonding/* 2>/dev/null; echo "=== bridges ==="; bridge link show 2>/dev/null; bridge vlan show 2>/dev/null; brctl show 2>/dev/null; echo "=== vlan ==="; cat /proc/net/vlan/config 2>/dev/null; echo "=== ip -d link (типы) ==="; ip -d link show | grep -E "vlan|bond|bridge|vxlan|gre|wg|tun|tap"'
run 06-network tunnels-vpn.txt            'ip -d tunnel show 2>/dev/null; ip link show type gre 2>/dev/null; ip link show type wireguard 2>/dev/null; wg show all 2>/dev/null | sed "s/\(PresharedKey\|PrivateKey\).*/\1: <REDACTED>/"; ipsec status 2>/dev/null; swanctl --list-sas 2>/dev/null; openvpn --version 2>/dev/null | head -1; ls /etc/openvpn 2>/dev/null'
run 06-network arp-mac-lldp.txt           'arp -an 2>/dev/null | head -100; echo "=== lldp ==="; lldpctl 2>/dev/null | head -80; lldpcli show neighbors 2>/dev/null | head -80'
run 06-network net-stats-errors.txt       'netstat -s 2>/dev/null || nstat -az 2>/dev/null; echo "=== /proc/net/dev ==="; cat /proc/net/dev; echo "=== softnet ==="; cat /proc/net/softnet_stat'
run 06-network proxy-config.txt           'env | grep -i proxy; echo "=== /etc/environment ==="; cat /etc/environment 2>/dev/null; echo "=== apt proxy ==="; grep -ri proxy /etc/apt/apt.conf.d/ 2>/dev/null; echo "=== docker proxy ==="; cat /etc/systemd/system/docker.service.d/*.conf 2>/dev/null'

if [[ "$NETCHECKS" -eq 1 ]]; then
  run 06-network connectivity.txt 'echo "=== default gw ping ==="; GW=$(ip route | awk "/^default/{print \$3; exit}"); [ -n "$GW" ] && ping -c 3 -W 2 "$GW"; echo "=== 8.8.8.8 ==="; ping -c 3 -W 2 8.8.8.8; echo "=== 1.1.1.1 ==="; ping -c 3 -W 2 1.1.1.1; echo "=== DNS resolve ==="; for h in archive.ubuntu.com security.ubuntu.com github.com; do echo "--- $h"; getent hosts $h; done; echo "=== HTTPS ==="; for u in https://archive.ubuntu.com https://security.ubuntu.com https://github.com; do printf "%-40s " "$u"; curl -sS -o /dev/null -w "%{http_code} %{time_total}s\n" --max-time 8 "$u" 2>&1; done; echo "=== traceroute 8.8.8.8 ==="; (traceroute -n -w 1 -q 1 -m 12 8.8.8.8 2>/dev/null || tracepath -n -m 12 8.8.8.8 2>/dev/null) | head -20; echo "=== MTU path ==="; ping -c 2 -M do -s 1472 8.8.8.8 2>&1 | tail -3; echo "=== apt reachability ==="; apt-get -s update 2>&1 | tail -20'
fi

# ============================== 07 STORAGE ==================================
run 07-storage lsblk.txt                  'lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINT,ROTA,SCHED,MODEL,SERIAL,STATE 2>/dev/null; echo "=== JSON ==="; lsblk -J -O 2>/dev/null'
run 07-storage df.txt                     'df -hT; echo "=== inodes ==="; df -i; echo "=== по mountpoint (POSIX) ==="; df -P'
run 07-storage mounts-fstab.txt           'cat /etc/fstab; echo "=== /proc/mounts ==="; cat /proc/mounts; echo "=== findmnt ==="; findmnt -A -o TARGET,SOURCE,FSTYPE,OPTIONS; echo "=== swap ==="; swapon --show; cat /proc/swaps'
run 07-storage lvm.txt                    'pvs -o+pv_used 2>/dev/null; echo; vgs 2>/dev/null; echo; lvs -a -o+devices,lv_layout 2>/dev/null; echo "=== lvm.conf (без комментов) ==="; grep -v "^\s*#" /etc/lvm/lvm.conf 2>/dev/null | grep -v "^\s*$" | head -80'
run 07-storage raid.txt                   'cat /proc/mdstat 2>/dev/null; mdadm --detail --scan 2>/dev/null; for d in /dev/md*; do [ -b "$d" ] && mdadm --detail "$d" 2>/dev/null; done; echo "=== hw raid ==="; storcli64 /call show 2>/dev/null | head -60; megacli -LDInfo -Lall -aALL 2>/dev/null | head -60; perccli64 /call show 2>/dev/null | head -40'
run 07-storage zfs-btrfs.txt              'zpool status 2>/dev/null; zpool list 2>/dev/null; zfs list 2>/dev/null; echo "=== btrfs ==="; btrfs filesystem show 2>/dev/null; btrfs filesystem usage / 2>/dev/null'
run 07-storage disk-usage-top.txt         'du -xhd1 / 2>/dev/null | sort -rh | head -30; echo "=== /var ==="; du -xhd2 /var 2>/dev/null | sort -rh | head -30; echo "=== топ-30 больших файлов (>200M) ==="; find / -xdev -type f -size +200M -printf "%s\t%p\n" 2>/dev/null | sort -rn | head -30'
run 07-storage io-stats.txt               'iostat -xz 1 3 2>/dev/null || cat /proc/diskstats; echo "=== io schedulers ==="; for d in /sys/block/*/queue/scheduler; do echo "$d: $(cat $d 2>/dev/null)"; done; echo "=== readahead/rotational ==="; for d in /sys/block/*/queue/rotational; do echo "$d: $(cat $d)"; done'
run 07-storage nfs-cifs-iscsi.txt         'showmount -e localhost 2>/dev/null; cat /etc/exports 2>/dev/null; echo "=== nfs mounts ==="; findmnt -t nfs,nfs4,cifs 2>/dev/null; echo "=== iscsi ==="; iscsiadm -m session 2>/dev/null; iscsiadm -m node 2>/dev/null; echo "=== multipath ==="; multipath -ll 2>/dev/null'
run 07-storage fs-tune.txt                'for m in $(findmnt -rno TARGET -t ext4,xfs 2>/dev/null); do echo "===== $m"; findmnt -no SOURCE "$m"; done; echo "=== tune2fs ==="; for d in $(findmnt -rno SOURCE -t ext4 2>/dev/null | sort -u); do tune2fs -l "$d" 2>/dev/null | head -30; done; echo "=== xfs_info ==="; for m in $(findmnt -rno TARGET -t xfs 2>/dev/null); do xfs_info "$m" 2>/dev/null; done'
if [[ "$DEEP" -eq 1 ]]; then
  run 07-storage smart.txt 'for d in $(lsblk -dno NAME,TYPE | awk "\$2==\"disk\"{print \$1}"); do echo "===== /dev/$d"; smartctl -i -H -A /dev/$d 2>/dev/null | head -60; done; nvme list 2>/dev/null; for n in /dev/nvme?n1; do [ -b "$n" ] && nvme smart-log "$n" 2>/dev/null; done'
fi

# ============================== 08 SECURITY =================================
run 08-security users-groups.txt          'getent passwd | sort -t: -k3 -n; echo "=== группы ==="; getent group | sort; echo "=== пользователи с UID>=1000 ==="; awk -F: "\$3>=1000 && \$3<65534 {print}" /etc/passwd; echo "=== пользователи с shell ==="; grep -vE "(nologin|false)$" /etc/passwd'
run 08-security passwd-policy.txt         'chage -l root 2>/dev/null; echo "=== аккаунты без пароля/заблокированные ==="; awk -F: "{print \$1\": \"substr(\$2,1,3)}" /etc/shadow 2>/dev/null; echo "=== login.defs ==="; grep -vE "^\s*(#|$)" /etc/login.defs 2>/dev/null; echo "=== pam ==="; grep -rvE "^\s*(#|$)" /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/sshd 2>/dev/null'
run 08-security sudoers.txt               'cat /etc/sudoers 2>/dev/null | grep -vE "^\s*(#|$)"; echo "=== sudoers.d ==="; grep -rvE "^\s*(#|$)" /etc/sudoers.d/ 2>/dev/null; echo "=== члены sudo/admin ==="; getent group sudo admin adm wheel 2>/dev/null'
run 08-security ssh-config.txt            'sshd -T 2>/dev/null | sort; echo "=== sshd_config (raw) ==="; grep -vE "^\s*(#|$)" /etc/ssh/sshd_config 2>/dev/null; echo "=== sshd_config.d ==="; grep -rvE "^\s*(#|$)" /etc/ssh/sshd_config.d/ 2>/dev/null; echo "=== ssh_config клиент ==="; grep -vE "^\s*(#|$)" /etc/ssh/ssh_config 2>/dev/null; echo "=== host keys (fingerprints) ==="; for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k" 2>/dev/null; done'
run 08-security authorized-keys.txt       'for h in /root /home/*; do f="$h/.ssh/authorized_keys"; [ -f "$f" ] && { echo "===== $f"; ls -la "$f"; ssh-keygen -lf "$f" 2>/dev/null; }; done'
run 08-security apparmor-selinux.txt      'aa-status 2>/dev/null; echo "=== профили ==="; ls /etc/apparmor.d/ 2>/dev/null; echo "=== selinux ==="; sestatus 2>/dev/null'
run 08-security fail2ban.txt              'fail2ban-client status 2>/dev/null; for j in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed "s/.*:\s*//;s/,//g"); do fail2ban-client status "$j" 2>/dev/null; done; echo "=== конфиг ==="; grep -rvE "^\s*(#|$)" /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null'
run 08-security auth-failures.txt         "zcat -f /var/log/auth.log* 2>/dev/null | grep -Ei 'failed password|invalid user|authentication failure|Failed publickey' | awk '{print \$(NF-3)}' | sort | uniq -c | sort -rn | head -40; echo '=== последние 100 строк с ошибками ==='; zcat -f /var/log/auth.log* 2>/dev/null | grep -Ei 'failed|invalid|error' | tail -100; echo '=== успешные входы ==='; last -F -n 50 2>/dev/null; echo '=== sudo usage ==='; zcat -f /var/log/auth.log* 2>/dev/null | grep -i 'sudo:.*COMMAND' | tail -80"
run 08-security suid-sgid.txt             'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%M %u %g %p\n" 2>/dev/null | sort'
run 08-security world-writable.txt        'find / -xdev -type d -perm -0002 ! -perm -1000 -printf "%M %p\n" 2>/dev/null | head -50; echo "=== world-writable файлы ==="; find /etc /usr /opt /srv -xdev -type f -perm -0002 -printf "%M %p\n" 2>/dev/null | head -50'
run 08-security certificates.txt          'ls -la /etc/ssl/certs 2>/dev/null | head -20; echo "=== локальные CA ==="; ls -la /usr/local/share/ca-certificates/ 2>/dev/null; echo "=== срок действия сертификатов сервисов ==="; for f in $(find /etc -maxdepth 4 -name "*.crt" -o -maxdepth 4 -name "*.pem" 2>/dev/null | grep -v /etc/ssl/certs | head -40); do echo "--- $f"; openssl x509 -in "$f" -noout -subject -issuer -dates 2>/dev/null; done'
run 08-security audit-lynis-hints.txt     'auditctl -l 2>/dev/null; echo "=== auditd rules ==="; grep -rvE "^\s*(#|$)" /etc/audit/rules.d/ /etc/audit/auditd.conf 2>/dev/null; echo "=== aide/tripwire ==="; which aide tripwire 2>/dev/null; echo "=== lynis ==="; which lynis 2>/dev/null'
run 08-security root-history-hint.txt     'ls -la /root/.bash_history /home/*/.bash_history 2>/dev/null; echo "(содержимое history НЕ собирается умышленно — может содержать секреты; при необходимости соберите вручную)"'

# ============================== 09 PERFORMANCE ==============================
run 09-performance top-processes.txt      'ps -eo pid,ppid,user,pcpu,pmem,rss,vsz,nlwp,stat,etime,cmd --sort=-pcpu | head -40; echo "=== по памяти ==="; ps -eo pid,user,pcpu,pmem,rss,cmd --sort=-rss | head -40; echo "=== всего процессов ==="; ps -e | wc -l'
run 09-performance vmstat-mpstat.txt      'vmstat 1 5; echo "=== mpstat ==="; mpstat -P ALL 1 3 2>/dev/null; echo "=== pressure ==="; cat /proc/pressure/* 2>/dev/null'
run 09-performance memory-pressure.txt    'cat /proc/vmstat | grep -E "pgmajfault|pgscan|oom|swap"; echo "=== slabtop ==="; slabtop -o -s c 2>/dev/null | head -20; echo "=== swappiness/overcommit ==="; sysctl vm.swappiness vm.overcommit_memory vm.overcommit_ratio vm.dirty_ratio vm.dirty_background_ratio vm.min_free_kbytes 2>/dev/null'
run 09-performance open-files.txt         'echo "fd usage: $(cat /proc/sys/fs/file-nr)"; echo "max: $(cat /proc/sys/fs/file-max)"; echo "=== топ процессов по fd ==="; for p in /proc/[0-9]*; do n=$(ls $p/fd 2>/dev/null | wc -l); [ "$n" -gt 100 ] && echo "$n $(cat $p/comm 2>/dev/null) ${p#/proc/}"; done | sort -rn | head -20'
run 09-performance sar-history.txt        'sar -u 1 3 2>/dev/null | tail -10; echo "=== sar доступен исторически? ==="; ls /var/log/sysstat/ 2>/dev/null | head'
run 09-performance zombie-defunct.txt     'ps -eo pid,ppid,stat,cmd | awk "\$3 ~ /Z/"; echo "=== процессы в D-state ==="; ps -eo pid,stat,wchan:20,cmd | awk "\$2 ~ /D/"'

# ============================== 10 LOGS =====================================
run 10-logs journal-errors.txt            "journalctl --no-pager -p err -S '-${LOG_DAYS} days' 2>/dev/null | tail -1500"
run 10-logs journal-warnings-summary.txt  "journalctl --no-pager -p warning -S '-${LOG_DAYS} days' -o short 2>/dev/null | sed -E 's/^[A-Za-z]{3} [0-9]{2} [0-9:]+ [^ ]+ //' | sed -E 's/[0-9]{2,}/N/g' | sort | uniq -c | sort -rn | head -120"
run 10-logs journal-boot-errors.txt       'journalctl -b -p err --no-pager 2>/dev/null | tail -400; echo "=== список загрузок ==="; journalctl --list-boots --no-pager 2>/dev/null | tail -20'
run 10-logs journal-disk-usage.txt        'journalctl --disk-usage 2>/dev/null; echo "=== journald.conf ==="; grep -vE "^\s*(#|$)" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null'
run 10-logs dmesg-errors.txt              'dmesg -T --level=err,crit,alert,emerg 2>/dev/null | tail -400; echo "=== warn ==="; dmesg -T --level=warn 2>/dev/null | tail -200'
run 10-logs dmesg-full-tail.txt           'dmesg -T 2>/dev/null | tail -600'
run 10-logs oom-and-panic.txt             "journalctl --no-pager -k -S '-30 days' 2>/dev/null | grep -Ei 'out of memory|oom-kill|killed process|panic|BUG:|call trace|segfault|hung_task|blocked for more than|I/O error|EXT4-fs error|XFS.*error|md/raid.*fail|link is down|nfs.*not responding' | tail -300"
run 10-logs syslog-errors.txt             "zcat -f /var/log/syslog* 2>/dev/null | grep -Ei 'error|critical|fail|denied|refused|timeout' | tail -600"
run 10-logs kern-log-errors.txt           "zcat -f /var/log/kern.log* 2>/dev/null | grep -Ei 'error|fail|drop|reject' | tail -300"
run 10-logs log-inventory.txt             'ls -laSh /var/log | head -60; echo "=== размер /var/log ==="; du -sh /var/log; echo "=== крупнейшие логи рекурсивно ==="; find /var/log -type f -printf "%s\t%p\n" 2>/dev/null | sort -rn | head -30'
run 10-logs logrotate.txt                 'grep -vE "^\s*(#|$)" /etc/logrotate.conf 2>/dev/null; echo "=== logrotate.d ==="; for f in /etc/logrotate.d/*; do echo "--- $f"; grep -vE "^\s*(#|$)" "$f"; done 2>/dev/null; echo "=== состояние ==="; tail -40 /var/lib/logrotate/status 2>/dev/null'
run 10-logs unattended-upgrades-log.txt   'tail -200 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null; tail -100 /var/log/unattended-upgrades/unattended-upgrades-dpkg.log 2>/dev/null'
run 10-logs failed-units-logs.txt         'for u in $(systemctl --failed --no-legend --plain 2>/dev/null | awk "{print \$1}"); do echo "===== $u"; systemctl status "$u" --no-pager -l 2>/dev/null | head -20; journalctl -u "$u" -n 60 --no-pager 2>/dev/null; done'

# ============================== 11 CONTAINERS ===============================
run 11-containers docker-info.txt         'docker version 2>/dev/null; echo; docker info 2>/dev/null; echo "=== daemon.json ==="; cat /etc/docker/daemon.json 2>/dev/null'
run 11-containers docker-ps.txt           'docker ps -a --no-trunc --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.RunningFor}}" 2>/dev/null; echo "=== stats ==="; docker stats --no-stream 2>/dev/null'
run 11-containers docker-images-volumes.txt 'docker images -a --digests 2>/dev/null; echo "=== volumes ==="; docker volume ls 2>/dev/null; echo "=== networks ==="; docker network ls 2>/dev/null; for n in $(docker network ls -q 2>/dev/null); do docker network inspect "$n" 2>/dev/null | head -40; done; echo "=== disk usage ==="; docker system df -v 2>/dev/null | head -60'
run 11-containers docker-inspect-all.json 'for c in $(docker ps -aq 2>/dev/null); do docker inspect "$c" 2>/dev/null; done'
run 11-containers docker-compose-files.txt 'find / -xdev -maxdepth 6 \( -name "docker-compose*.y*ml" -o -name "compose.y*ml" \) ! -path "*/node_modules/*" 2>/dev/null | head -40; echo "=== содержимое найденных ==="; for f in $(find /opt /srv /root /home /etc -xdev -maxdepth 5 \( -name "docker-compose*.y*ml" -o -name "compose.y*ml" \) 2>/dev/null | head -15); do echo "----- $f"; cat "$f"; done'
run 11-containers podman-lxd.txt          'podman ps -a 2>/dev/null; podman images 2>/dev/null; echo "=== lxd/lxc ==="; lxc list 2>/dev/null; lxc-ls -f 2>/dev/null; echo "=== systemd-nspawn ==="; machinectl list 2>/dev/null'
run 11-containers kubernetes.txt          'kubectl version --short 2>/dev/null; kubectl get nodes -o wide 2>/dev/null; kubectl get pods -A -o wide 2>/dev/null | head -80; echo "=== kubelet ==="; systemctl status kubelet --no-pager 2>/dev/null | head -15; ls /etc/kubernetes 2>/dev/null; echo "=== containerd ==="; crictl info 2>/dev/null | head -30; crictl ps -a 2>/dev/null | head -40; cat /etc/containerd/config.toml 2>/dev/null'
run 11-containers libvirt-vms.txt         'virsh list --all 2>/dev/null; virsh net-list --all 2>/dev/null; virsh pool-list --all 2>/dev/null; for d in $(virsh list --all --name 2>/dev/null); do echo "===== $d"; virsh dominfo "$d" 2>/dev/null; virsh dumpxml "$d" 2>/dev/null; done'

# ============================== 12 APPS =====================================
run 12-apps web-servers.txt               'nginx -v 2>&1; nginx -T 2>/dev/null | head -400; echo "=== apache ==="; apache2ctl -v 2>/dev/null; apache2ctl -S 2>/dev/null; apache2ctl -M 2>/dev/null; echo "=== haproxy ==="; haproxy -v 2>/dev/null; grep -vE "^\s*(#|$)" /etc/haproxy/haproxy.cfg 2>/dev/null'
run 12-apps databases.txt                 'echo "=== PostgreSQL ==="; psql --version 2>/dev/null; pg_lsclusters 2>/dev/null; ls /etc/postgresql/*/*/postgresql.conf 2>/dev/null; grep -vE "^\s*(#|$)" /etc/postgresql/*/*/postgresql.conf 2>/dev/null | head -80; grep -vE "^\s*(#|$)" /etc/postgresql/*/*/pg_hba.conf 2>/dev/null; echo "=== MySQL/MariaDB ==="; mysql --version 2>/dev/null; mysqld --version 2>/dev/null; grep -rvE "^\s*(#|$)" /etc/mysql/ 2>/dev/null | head -80; echo "=== Redis ==="; redis-server --version 2>/dev/null; redis-cli info server 2>/dev/null | head -20; grep -vE "^\s*(#|$)" /etc/redis/redis.conf 2>/dev/null | head -60; echo "=== MongoDB ==="; mongod --version 2>/dev/null | head -3; echo "=== ClickHouse ==="; clickhouse-server --version 2>/dev/null'
run 12-apps message-queues.txt            'rabbitmqctl status 2>/dev/null | head -40; rabbitmq-diagnostics status 2>/dev/null | head -40; echo "=== Kafka ==="; ls /opt/kafka /usr/local/kafka 2>/dev/null; ps aux | grep -i "[k]afka" | head -5; echo "=== Zookeeper ==="; ps aux | grep -i "[z]ookeeper" | head -5'
run 12-apps app-processes.txt             'ps -eo user,pid,pcpu,pmem,cmd --sort=-pmem | grep -vE "^\s*(root\s+[0-9]+\s+0\.0\s+0\.0\s+\[)" | head -60; echo "=== слушающие демоны и их пакеты ==="; ss -tulpnH 2>/dev/null | grep -oE "users:\(\(\"[^\"]+" | sed "s/.*\"//" | sort -u | while read -r p; do bin=$(command -v "$p" 2>/dev/null); pkg=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1); echo "$p -> ${bin:-?} -> ${pkg:-НЕ ИЗ ПАКЕТА}"; done'
run 12-apps backup-tools.txt              'for c in restic borg borgmatic duplicity bacula-fd rsync rclone veeam pgbackrest barman; do printf "%-14s " "$c"; command -v $c >/dev/null 2>&1 && echo present || echo absent; done; echo "=== backup-подобные cron/timers ==="; grep -riE "backup|dump|restic|borg|rsync" /etc/cron* /etc/systemd/system 2>/dev/null | head -40'
run 12-apps mail-and-misc.txt             'postconf -n 2>/dev/null | head -40; exim4 -bV 2>/dev/null | head -3; echo "=== ssmtp/msmtp ==="; grep -vE "^\s*(#|$)" /etc/ssmtp/ssmtp.conf /etc/msmtprc 2>/dev/null; echo "=== samba ==="; testparm -s 2>/dev/null | head -60'

# ============================== 13 CONFIGS (копии) ==========================
log "Копирую и маскирую конфиги в 13-configs/ ..."
for p in /etc/fstab /etc/hosts /etc/hostname /etc/resolv.conf /etc/nsswitch.conf \
         /etc/environment /etc/default /etc/sysctl.conf /etc/sysctl.d /etc/security \
         /etc/ssh /etc/netplan /etc/network /etc/systemd /etc/apt /etc/modprobe.d \
         /etc/udev/rules.d /etc/ufw /etc/fail2ban /etc/logrotate.conf /etc/logrotate.d \
         /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
         /etc/cron.monthly /etc/docker /etc/containerd /etc/nginx /etc/apache2 \
         /etc/haproxy /etc/postgresql /etc/mysql /etc/redis /etc/zabbix /etc/prometheus \
         /etc/grafana /etc/telegraf /etc/node_exporter /etc/chrony /etc/ntp.conf \
         /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/rsyslog.conf /etc/rsyslog.d \
         /etc/multipath.conf /etc/lvm/lvm.conf /etc/mdadm /etc/iptables /etc/nftables.conf \
         /etc/wireguard /etc/openvpn /etc/kubernetes/manifests /etc/apparmor.d/local ; do
  copy_cfg "$p"
done
run 13-configs etc-tree.txt      'find /etc -maxdepth 3 -printf "%M %u:%g %10s %TY-%Tm-%Td %p\n" 2>/dev/null | sort -k6'
run 13-configs etc-recent-changes.txt 'find /etc -type f -mtime -90 -printf "%TY-%Tm-%Td %TH:%TM %p\n" 2>/dev/null | sort -r | head -200'

# ============================== 14 DRIFT (главное для стандартизации) =======
run 14-drift modified-conffiles.txt  'echo "=== conffiles, изменённые относительно пакета (dpkg) ==="; for f in /var/lib/dpkg/info/*.conffiles; do pkg=$(basename "$f" .conffiles); while read -r conf; do [ -f "$conf" ] || continue; md5now=$(md5sum "$conf" 2>/dev/null | cut -d" " -f1); md5pkg=$(grep -E "^[0-9a-f]{32}  ${conf#/}$" /var/lib/dpkg/info/${pkg}.md5sums 2>/dev/null | cut -d" " -f1); [ -n "$md5pkg" ] && [ "$md5now" != "$md5pkg" ] && echo "MODIFIED  $pkg  $conf"; done < "$f"; done | sort'
run 14-drift dpkg-verify.txt         'dpkg -V 2>/dev/null | head -400'
run 14-drift dpkg-not-owned-etc.txt  'comm -23 <(find /etc -type f 2>/dev/null | sort) <(cat /var/lib/dpkg/info/*.list 2>/dev/null | grep "^/etc/" | sort -u) | head -300'
run 14-drift dpkg-audit.txt          'dpkg --audit; echo "=== half-installed/unpacked ==="; dpkg -l | awk "!/^ii/ && /^[a-z]/ {print}"'
run 14-drift needrestart.txt         'needrestart -b 2>/dev/null; echo "=== устаревшие библиотеки у процессов ==="; lsof 2>/dev/null | grep -E "DEL|deleted" | awk "{print \$1}" | sort | uniq -c | sort -rn | head -20'
run 14-drift alternatives.txt        'update-alternatives --get-selections 2>/dev/null'
run 14-drift ansible-facts.json      'command -v ansible >/dev/null 2>&1 && ansible -m setup -c local -i localhost, localhost 2>/dev/null | sed "1s/.*=> //" || echo "{\"note\":\"ansible не установлен на хосте\"}"'

# ============================== 15 MONITORING / AGENTS ======================
run 15-monitoring agents.txt         'for s in zabbix-agent zabbix-agent2 node_exporter prometheus-node-exporter telegraf collectd datadog-agent netdata filebeat metricbeat auditbeat promtail vector fluentbit td-agent osquery wazuh-agent falcon-sensor; do printf "%-28s " "$s"; systemctl is-active "$s" 2>/dev/null || echo "-"; done; echo "=== zabbix conf ==="; grep -vE "^\s*(#|$)" /etc/zabbix/zabbix_agent*.conf 2>/dev/null; ls /etc/zabbix/zabbix_agent*.d/ 2>/dev/null; cat /etc/zabbix/zabbix_agent*.d/*.conf 2>/dev/null | head -100'
run 15-monitoring exporters-ports.txt 'ss -tulpnH 2>/dev/null | grep -E ":(9[0-9]{3}|10050|10051|8125|8086|3000|9090|9093|9100)\b"'
run 15-monitoring node-exporter-textfile.txt 'ls -la /var/lib/node_exporter/textfile_collector/ 2>/dev/null; cat /var/lib/node_exporter/textfile_collector/*.prom 2>/dev/null | head -50'

# ============================== 16 SCHEDULED ================================
run 16-scheduled crontabs.txt        'echo "=== /etc/crontab ==="; grep -vE "^\s*(#|$)" /etc/crontab 2>/dev/null; echo "=== /etc/cron.d ==="; for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "--- $f"; grep -vE "^\s*(#|$)" "$f"; }; done; echo "=== пользовательские crontab ==="; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && { echo "--- user: $u"; echo "$c" | grep -vE "^\s*(#|$)"; }; done; echo "=== cron.{hourly,daily,weekly,monthly} ==="; ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; echo "=== at jobs ==="; atq 2>/dev/null'
run 16-scheduled systemd-timers.txt  'systemctl list-timers --all --no-pager 2>/dev/null; echo "=== кастомные timer-юниты ==="; for f in /etc/systemd/system/*.timer; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done'
run 16-scheduled anacron.txt         'cat /etc/anacrontab 2>/dev/null; cat /var/spool/anacron/* 2>/dev/null'

# ============================== СВОДКА ======================================
log "Формирую сводку summary.md ..."
MODCONF=$(grep -c '^MODIFIED' "$OUT/14-drift/modified-conffiles.txt" 2>/dev/null | head -1); MODCONF=${MODCONF:-0}
OOMCNT=$(grep -ciE 'out of memory|oom-kill|panic|call trace' "$OUT/10-logs/oom-and-panic.txt" 2>/dev/null | head -1); OOMCNT=${OOMCNT:-0}
SUM="$OUT/00-meta/summary.md"
{
  echo "# Аудит сервера: $HOST"
  echo
  echo "- Дата сбора: $(date -Is)"
  echo "- Collector: audit-ubuntu.sh v$VERSION (root=$IS_ROOT, deep=$DEEP)"
  echo "- ОС: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  echo "- Ядро: $(uname -r)  |  Архитектура: $(uname -m)"
  echo "- Виртуализация: $(systemd-detect-virt 2>/dev/null || echo unknown)"
  echo "- Uptime: $(uptime -p 2>/dev/null)  (загрузка с $(uptime -s 2>/dev/null))"
  echo "- CPU: $(nproc --all) vCPU / $(lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2; exit}')"
  echo "- RAM: $(free -h | awk '/^Mem:/{print $2" всего, "$3" занято, "$7" доступно"}')"
  echo "- Swap: $(free -h | awk '/^Swap:/{print $2" всего, "$3" занято"}')"
  echo "- Load average: $(cat /proc/loadavg | cut -d' ' -f1-3)"
  echo
  echo "## Пакеты"
  echo "- Установлено (dpkg): $(dpkg-query -W -f='${Status}\n' 2>/dev/null | grep -c 'install ok installed')"
  echo "- Помечено manual: $(apt-mark showmanual 2>/dev/null | wc -l)"
  echo "- На hold: $(apt-mark showhold 2>/dev/null | wc -l)"
  echo "- Остаточные конфиги (rc): $(dpkg -l 2>/dev/null | awk '/^rc/' | wc -l)"
  echo "- Доступно обновлений: $(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  echo "- Snap-пакетов: $(snap list 2>/dev/null | tail -n +2 | wc -l)"
  echo "- Сторонних apt-репозиториев: $(ls /etc/apt/sources.list.d/ 2>/dev/null | wc -l)"
  if [[ -s "$OUT/04-packages/package-origins.tsv" ]]; then
    echo "- Пакетов НЕ из Ubuntu-репозиториев: $(awk -F'\t' 'NR>1 && $3!="Ubuntu"' "$OUT/04-packages/package-origins.tsv" | wc -l)"
  fi
  echo
  echo "## Состояние системы"
  echo "- systemd: $(systemctl is-system-running 2>/dev/null)"
  echo "- Failed units: $(systemctl --failed --no-legend --plain 2>/dev/null | wc -l)"
  systemctl --failed --no-legend --plain 2>/dev/null | awk '{print "    - "$1}'
  echo "- Требуется перезагрузка: $([[ -f /var/run/reboot-required ]] && echo "ДА ($(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null))" || echo нет)"
  echo "- Изменённых conffiles: $MODCONF"
  echo "- Ошибок в журнале за ${LOG_DAYS}д: $(journalctl -p err -S "-${LOG_DAYS} days" --no-pager 2>/dev/null | wc -l)"
  echo "- OOM/kernel-инцидентов найдено: $OOMCNT"
  echo
  echo "## Диски"
  df -hT -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR==1{print "```"} {print} END{print "```"}'
  echo "- Разделы >85%: $(df -hP -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1 && int($5)>85 {printf "%s(%s) ", $6, $5}')"
  echo
  echo "## Сеть"
  echo '```'
  ip -br addr show 2>/dev/null
  echo '```'
  echo "- Default route: $(ip route 2>/dev/null | awk '/^default/{print}' | tr '\n' ';')"
  echo "- DNS: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
  echo "- Firewall: ufw=$(ufw status 2>/dev/null | head -1 | sed 's/Status: //'), iptables-правил=$(iptables -S 2>/dev/null | wc -l), nft-таблиц=$(nft list tables 2>/dev/null | wc -l)"
  echo "- Слушающих TCP-портов: $(ss -tlnH 2>/dev/null | wc -l)"
  echo '```'
  ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | sed 's/users:((//' | sort -u | head -40
  echo '```'
  echo
  echo "## Сервисы и агенты"
  echo "- Docker: $(docker --version 2>/dev/null || echo нет) | контейнеров: $(docker ps -aq 2>/dev/null | wc -l) (запущено $(docker ps -q 2>/dev/null | wc -l))"
  echo "- Мониторинг-агенты активны: $(for s in zabbix-agent zabbix-agent2 prometheus-node-exporter node_exporter telegraf netdata filebeat promtail; do systemctl is-active "$s" >/dev/null 2>&1 && printf "%s " "$s"; done)"
  echo "- Time sync: $(timedatectl show -p NTPSynchronized --value 2>/dev/null) / $(timedatectl show -p NTP --value 2>/dev/null)"
  echo "- Unattended-upgrades: $(systemctl is-enabled unattended-upgrades 2>/dev/null)"
  echo
  echo "## Пользователи"
  echo "- Локальных с UID>=1000: $(awk -F: '$3>=1000 && $3<65534' /etc/passwd | wc -l)"
  echo "- В группе sudo: $(getent group sudo 2>/dev/null | cut -d: -f4)"
  echo "- SSH: PermitRootLogin=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}') PasswordAuthentication=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}') Port=$(sshd -T 2>/dev/null | awk '/^port/{print $2}' | tr '\n' ',')"
  echo
  echo "## Собранные артефакты"
  echo "Всего файлов: $(find "$OUT" -type f | wc -l), объём: $(du -sh "$OUT" 2>/dev/null | cut -f1)"
  echo "Полный перечень с кодами возврата: 00-meta/manifest.tsv"
} > "$SUM" 2>/dev/null

# машинно-читаемый краткий факт-файл для агентов
{
  printf '{\n'
  printf '  "hostname": "%s",\n' "$HOST"
  printf '  "collected_at": "%s",\n' "$(date -Is)"
  printf '  "collector_version": "%s",\n' "$VERSION"
  printf '  "os": "%s",\n' "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  printf '  "os_version_id": "%s",\n' "$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"
  printf '  "kernel": "%s",\n' "$(uname -r)"
  printf '  "arch": "%s",\n' "$(uname -m)"
  printf '  "virtualization": "%s",\n' "$(systemd-detect-virt 2>/dev/null || echo unknown)"
  printf '  "cpu_count": %s,\n' "$(nproc --all)"
  printf '  "mem_total_kb": %s,\n' "$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  printf '  "uptime_seconds": %s,\n' "$(cut -d. -f1 /proc/uptime)"
  printf '  "packages_installed": %s,\n' "$(dpkg-query -W -f='${Status}\n' 2>/dev/null | grep -c 'install ok installed')"
  printf '  "packages_upgradable": %s,\n' "$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  printf '  "third_party_repos": %s,\n' "$(ls /etc/apt/sources.list.d/ 2>/dev/null | wc -l)"
  printf '  "failed_units": %s,\n' "$(systemctl --failed --no-legend --plain 2>/dev/null | wc -l)"
  printf '  "reboot_required": %s,\n' "$([[ -f /var/run/reboot-required ]] && echo true || echo false)"
  printf '  "listening_tcp_ports": %s,\n' "$(ss -tlnH 2>/dev/null | wc -l)"
  printf '  "docker_containers": %s,\n' "$(docker ps -aq 2>/dev/null | wc -l)"
  printf '  "journal_errors_window": %s,\n' "$(journalctl -p err -S "-${LOG_DAYS} days" --no-pager 2>/dev/null | wc -l)"
  printf '  "modified_conffiles": %s\n' "$MODCONF"
  printf '}\n'
} > "$OUT/00-meta/facts.json"

# ============================== УПАКОВКА ====================================
DURATION=$(( $(date +%s) - START_EPOCH ))
echo "collection_duration_seconds: $DURATION" >> "$OUT/00-meta/collection-info.txt"

TARBALL="${OUTBASE}/${HOST}-${TS}.tar.gz"
tar -czf "$TARBALL" -C "$OUTBASE" "${HOST}-${TS}" 2>/dev/null
sha256sum "$TARBALL" > "${TARBALL}.sha256" 2>/dev/null
chmod 600 "$TARBALL" "${TARBALL}.sha256" 2>/dev/null

log "Готово за ${DURATION}s."
echo
echo "==================================================================="
echo " Каталог:  $OUT"
echo " Архив:    $TARBALL  ($(du -h "$TARBALL" 2>/dev/null | cut -f1))"
echo " Сводка:   $OUT/00-meta/summary.md"
echo " Факты:    $OUT/00-meta/facts.json"
echo " Файлов:   $(find "$OUT" -type f | wc -l)"
echo "==================================================================="
echo " Забрать с рабочей машины:"
echo "   scp $(whoami)@${HOST}:${TARBALL} ./"
echo "==================================================================="
