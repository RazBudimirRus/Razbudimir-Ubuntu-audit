# Razbudimir-Ubuntu-audit

**Версия: 1.4.0** — hardening (redact PEM/WG, fleet TOCTOU fix, `--deep` gating, `facts.json` schema).

Полновесный read-only сборщик инвентаризационно-диагностических данных с Ubuntu-серверов для последующего анализа AI-агентами и стандартизации через Ansible.

Скрипт заходит на сервер, собирает всё — от `dpkg` и `sshd -T` до `ethtool`, `journalctl -p err`, изменённых относительно пакета конфигов и статусов мониторинг-агентов — и упаковывает в архив, готовый к скармливанию LLM.

**Ничего не устанавливает, не правит конфиги, не рестартует сервисы. Запись только в свой каталог вывода.**

## Зачем

Когда в парке 6+ серверов и каждый настраивался в своё время, накапливается дрейф: где-то PPA, где-то ручная сборка из `/usr/local`, разные версии агентов мониторинга, разные `sysctl`, разные ключи в `authorized_keys`. Перед тем как загонять всё в единую Ansible-роль, нужно снять полный слепок текущего состояния и понять:

- что уехало от дефолтов пакета (изменённые conffiles)
- какие пакеты пришли не из репозиториев Ubuntu
- какие демоны слушают порты и из какого они пакета (или не из пакета вообще)
- какие ошибки в журнале и есть ли OOM/IO-инциденты
- где различается firewall, DNS, NTP, cron, systemd-таймеры

## Быстрый старт

### Один сервер

```bash
scp audit-ubuntu.sh user@server:/tmp/
ssh user@server 'sudo bash /tmp/audit-ubuntu.sh --deep'
# в конце скрипт напечатает путь к .tar.gz
scp user@server:/var/tmp/server-audit/<host>-<ts>.tar.gz ./
```

### Весь парк

```bash
cat > servers.txt <<'EOF'
ubuntu@10.0.0.11
ubuntu@10.0.0.12
ubuntu@10.0.0.13
ubuntu@10.0.0.14
ubuntu@10.0.0.15
ubuntu@10.0.0.16
EOF
chmod +x run-fleet-audit.sh
# по умолчанию: --deep --no-net; нужен passwordless sudo (sudo -n) и bash ≥4
AUDIT_ARGS="--deep --log-days 14 --no-net" ./run-fleet-audit.sh
```

Формат `servers.txt`: `user@host`, `user@host:port`, IPv6 — `user@[2001:db8::1]:22`.

На выходе: `fleet-audit-YYYYMMDD-HHMM/` с архивами всех серверов, распакованными каталогами, сводным `INDEX.md` (таблица по парку) и `compare/` — заготовками diff'ов по ключевым артефактам. После успешного копирования remote-архивы удаляются (оставить: `KEEP_REMOTE=1`).

## Ключи `audit-ubuntu.sh`

| Ключ | Назначение |
|---|---|
| `--deep` | SMART/NVMe; полный `dpkg -V`; deep `du`/`find` больших файлов; полные SUID/SGID и world-writable сканы |
| `--log-days N` | Глубина журналов, по умолчанию 7 (только целое число) |
| `--no-net` | Без внешних ping/curl/traceroute (закрытый контур) |
| `--no-redact` | Отключить маскирование секретов (не рекомендуется) |
| `--out DIR` | Каталог вывода, по умолчанию `/var/tmp/server-audit` |
| `--timeout N` | Лимит на одну команду в секундах, по умолчанию 180 (нужен GNU `timeout`) |
| `--progress on\|off\|auto` | Прогресс-бар. По умолчанию `auto` — включается, если stderr — терминал |
| `--no-progress` | То же, что `--progress off` (для cron/pipe) |

Без `--deep` тяжёлые FS-сканы заменяются лёгкими сэмплами (быстрее и безопаснее для prod).

### Ожидаемое время работы

Число шагов динамическое (~152 базово; `+1` за сетевые проверки, `+2` за `--deep`, `+1` при наличии `python3-apt`). Реальное время зависит от размера парка пакетов, количества контейнеров/дисков и глубины журналов.

| Профиль сервера | `--no-net` | Обычный | `--deep` |
|---|---|---|---|
| Небольшой (десктоп/минимальный VM) | 30–60 с | 1–2 мин | 2–3 мин |
| Типовой (сервисы, apt-пакеты, journald) | 1–2 мин | 2–4 мин | 4–7 мин |
| Нагруженный (Docker, RAID, много LVM) | 2–4 мин | 4–8 мин | 8–15 мин |

Во время прогона в терминале виден бар с процентом, ETA, текущей секцией и артефактом. Медленные команды (>10 с) подсвечиваются жёлтым ⚠, таймауты (`rc=124`) — красным ⏱. В финальном сообщении печатается общее время и, если были аномалии, топ-5 самых медленных шагов.

При запуске через cron/пайп бар автоматически отключается — вывод останется стабильным для логов.

Объём архива обычно 0.5–5 МБ.

## Что внутри архива

17 секций, машинно-читаемый `facts.json` и человекочитаемая `summary.md`.

```
00-meta/       collection-info.txt, summary.md, facts.json,
               manifest.tsv — все артефакты с кодами возврата и размерами
01-system/     os-release, hostnamectl, uptime и reboot-история, время и NTP/chrony,
               locale, LTS/ESM-статус, cloud-init, определение виртуализации, sysctl
02-hardware/   lscpu + CPU-уязвимости, cpufreq governor, память/hugepages, dmidecode,
               lshw, lspci/lsusb, NUMA, sensors/IPMI
03-kernel/     cmdline, установленные ядра, модули и modprobe.d, GRUB/initramfs,
               UEFI/SecureBoot, systemd-analyze blame, kdump, livepatch/pro
04-packages/   dpkg -l и TSV с версиями/размерами, manual/auto/hold, apt sources и
               ключи, apt policy, доступные обновления и security-апдейты,
               история apt/dpkg, snap/flatpak, pip/npm/gem, версии тулинга,
               package-origins.tsv + packages-not-from-ubuntu.txt
05-services/   все юниты, enabled/masked/failed, кастомные unit-файлы целиком,
               systemd-delta (drop-in переопределения), SysV/rc.local, лимиты сервисов
06-network/    ip addr/link/route/rule/neigh, netplan + сгенерированные бэкенды,
               networkd/NetworkManager/ifupdown, DNS и resolv.conf, слушающие порты,
               established-соединения, iptables/nft/ufw/firewalld целиком, conntrack,
               ethtool по каждому интерфейсу (ошибки/дропы/оффлоады/MTU),
               bond/vlan/bridge, GRE/WireGuard/IPsec/OpenVPN, LLDP/ARP,
               netstat -s, proxy, connectivity.txt (ping/DNS/HTTPS/traceroute/MTU/apt)
07-storage/    lsblk, df + inodes, fstab vs /proc/mounts, LVM, mdraid и HW-RAID,
               ZFS/btrfs, топ потребителей места, iostat и планировщики,
               NFS/CIFS/iSCSI/multipath, tune2fs/xfs_info, SMART (в --deep)
08-security/   пользователи/группы/UID, парольные политики и PAM, sudoers,
               sshd -T (эффективный конфиг!), authorized_keys (фингерпринты),
               AppArmor, fail2ban, статистика неудачных логинов, SUID/SGID,
               world-writable, сроки действия сертификатов, auditd
09-performance/топ по CPU/RSS, vmstat/mpstat, PSI-давление, swappiness/overcommit,
               fd-usage, зомби и D-state процессы
10-logs/       journalctl -p err, нормализованная частотка warning'ов,
               ошибки текущей загрузки, dmesg err/warn, OOM/panic/I-O errors/
               EXT4-XFS errors/hung_task за 30 дней, syslog/kern.log, размеры логов,
               logrotate, unattended-upgrades, логи упавших юнитов
11-containers/ docker info/ps/images/volumes/networks/inspect всех контейнеров,
               найденные docker-compose файлы, podman/LXD/nspawn,
               kubernetes/kubelet/containerd/crictl, libvirt VM + dumpxml
12-apps/       nginx -T, apache2ctl -S/-M, haproxy.cfg, PostgreSQL/MySQL/Redis/
               Mongo/ClickHouse конфиги и версии, RabbitMQ/Kafka/ZK,
               слушающие демоны с привязкой к пакету («НЕ ИЗ ПАКЕТА» = ручная сборка),
               бэкап-инструменты, postfix/exim/samba
13-configs/    копии ключевых /etc с маскированием + _permissions.txt,
               дерево /etc и файлы, менявшиеся за 90 дней
14-drift/      modified-conffiles.txt — конфиги, изменённые относительно пакета,
               dpkg -V, файлы в /etc не принадлежащие ни одному пакету,
               dpkg --audit, needrestart, update-alternatives, ansible facts
15-monitoring/ статус агентов (zabbix/node_exporter/telegraf/filebeat/...),
               порты экспортёров, zabbix конфиги, textfile-коллекторы
16-scheduled/  /etc/crontab, cron.d, пользовательские crontab, cron.*-каталоги,
               at, systemd-таймеры (включая кастомные), anacron
```

Ключевые для стандартизации разделы: `14-drift/`, `04-packages/packages-not-from-ubuntu.txt`, `05-services/custom-units.txt`, `12-apps/app-processes.txt`, `13-configs/_permissions.txt`.

## Что нового по сравнению с типовым инвентарём

- **`14-drift/modified-conffiles.txt`** — сравнение md5 каждого conffile с `/var/lib/dpkg/info/*.md5sums`. Сразу видно, где админ руками менял конфиг из пакета
- **`04-packages/package-origins.tsv`** через `python3-apt` — источник (Origin/Site) каждого установленного пакета, отдельно `packages-not-from-ubuntu.txt`
- **`14-drift/dpkg-not-owned-etc.txt`** — файлы в `/etc`, которые не принадлежат ни одному пакету
- **`12-apps/app-processes.txt`** — резолвинг слушающих демонов до пакета: строки вида `nginx -> /usr/sbin/nginx -> nginx-full` или `custom-app -> /usr/local/bin/... -> НЕ ИЗ ПАКЕТА`
- **`10-logs/journal-warnings-summary.txt`** — нормализованная (числа → `N`) частотка warning-строк из журнала. Сразу видно, что реально шумит
- **`06-network/interface-details.txt`** — `ethtool` по каждому интерфейсу с фильтром на ошибки/дропы/discard
- **`00-meta/facts.json`** — компактный JSON для агентов и дашбордов

## Приватность и маскирование

Маскирование включено по умолчанию:

- Пароли и токены в `KEY=value` — `PASSWORD/PASSWD/PASS/SECRET/TOKEN/APIKEY/API_KEY/ACCESS_KEY/SECRET_KEY/PRIVATE_KEY/CLIENT_SECRET/BEARER/AUTH_TOKEN/DB_PASS/MYSQL_PWD/PGPASSWORD/psk/pre-shared-key`
- Credentials в URL: `https://user:pass@host` → `https://user:<REDACTED>@host`
- SNMP community, WireGuard PSK, `passphrase`, `auth-user-pass`, `Authorization` и `x-api-key` заголовки
- Публичные SSH-ключи усекаются; приватные PEM/OpenSSH-блоки вырезаются **целиком** (от BEGIN до END)
- WireGuard `PrivateKey`/`PresharedKey`, JSON `"password":"…"`, URL-query `token=`/`api_key=`
- Приватные ключи (`*.key`, `*.pem`, `id_*`, `*.p12`, `*.pfx`, `*.jks`) не копируются вообще
- `bash_history` умышленно не собирается — часто содержит секреты в открытом виде
- Из `/etc/shadow` — только статус `empty|locked|hashed|unknown` (без префикса хеша)

Перед загрузкой архива в LLM всё равно стоит глазами пройтись по `13-configs/` — в кастомных конфигах могут быть нестандартные имена полей с секретами. Ключ `--no-redact` отключает маскирование (не рекомендуется).

## Требования

- Ubuntu 20.04 / 22.04 / 24.04 / 26.04 (smoke на 24.04 в CI-агенте; matrix на всех LTS — в планах)
- `bash`, GNU `timeout` (coreutils), `systemd`; для `facts.json` желателен `python3`
- Права `sudo` (без root часть данных недоступна — DMI, `dpkg -V`, `sshd -T`, `/etc/shadow`, конфиги некоторых сервисов)
- Fleet-раннер: bash ≥4, `sha256sum`/`shasum`, SSH BatchMode + `sudo -n`
- Опционально: `python3-apt` (для `package-origins.tsv`), `perl` (лучший PEM-redact), `smartmontools` (для `--deep`), `dmidecode`, `lshw`, `ethtool`, `chrony`, `lldpd`

Скрипт работает и без опциональных пакетов — соответствующие артефакты помечаются как SKIPPED в `manifest.tsv`, остальной сбор продолжается.

## Анализ агентами и стандартизация в Ansible

После сбора парка загружаешь `INDEX.md` + `summary.md` каждого сервера (быстрый обзор) или архивы целиком (глубокий разбор) в LLM и просишь:

```
Вот аудиты 6 Ubuntu-серверов (audit-ubuntu.sh). Проведи анализ командой агентов,
по одному агенту на область: (1) ОС/ядро/пакеты, (2) сеть и firewall,
(3) storage и ФС, (4) systemd/сервисы/контейнеры, (5) безопасность и доступ,
(6) логи/ошибки/надёжность.

От каждого агента нужно:
- дрифт между серверами: что где отличается, где какая версия/конфиг «уехал»
- ошибки и антипаттерны конфигурации с указанием файла и хоста
- лишнее: пакеты, сервисы, порты, cron-задачи, которые не нужны или дублируются
- пакеты и демоны не из репозиториев Ubuntu (ручные сборки, PPA, /usr/local)
- риски: EOL-версии, отсутствующие обновления безопасности, слабые настройки SSH/
  sudo/firewall, диски >85%, отсутствие бэкапов и мониторинга, OOM/IO-ошибки

Затем сведи всё в:
1. Матрицу дрифта (строки — параметр, колонки — 6 серверов, подсветить расхождения)
2. Приоритизированный список проблем: критично / важно / гигиена, с трудозатратами
3. Целевой baseline: единая версия ОС/ядра, набор пакетов, sysctl, sshd, firewall,
   мониторинг, логротейт, таймеры
4. Черновик Ansible-роли под этот baseline: структура каталогов, tasks, defaults,
   handlers, шаблоны конфигов, + отдельно перечень того, что НЕЛЬЗЯ загонять в
   единый шаблон (уникальное на каждом хосте) и почему
5. План внедрения: порядок применения, что проверять до/после, откат
```

## Регулярный запуск

Аудит полезно снимать периодически, чтобы видеть дрифт во времени:

```bash
# на сервере, раз в неделю
sudo install -m 0755 audit-ubuntu.sh /usr/local/sbin/audit-ubuntu.sh
sudo tee /etc/cron.weekly/server-audit >/dev/null <<'EOF'
#!/bin/sh
/usr/local/sbin/audit-ubuntu.sh --out /var/backups/server-audit --log-days 7 >/dev/null 2>&1
find /var/backups/server-audit -maxdepth 1 -name '*.tar.gz' -mtime +90 -delete
find /var/backups/server-audit -maxdepth 1 -type d -mtime +14 -exec rm -rf {} +
EOF
sudo chmod +x /etc/cron.weekly/server-audit
```

## Структура репозитория

```
audit-ubuntu.sh        основной сборщик, кладётся на каждый сервер
run-fleet-audit.sh     раннер по парку с рабочей машины (SSH + сбор архивов + сводный INDEX)
CHANGELOG.md           история версий
LICENSE                MIT
README.md              этот файл
```

## Лицензия

MIT
