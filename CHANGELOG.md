# Changelog

Все значимые изменения в этом проекте будут документироваться в этом файле.
Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии по [SemVer](https://semver.org/lang/ru/).

## [1.4.0] - 2026-08-16

### Безопасность

- Redact WireGuard `PrivateKey` / `PresharedKey` / `SharedKey`, JSON `"password":"…"`, YAML `password:`, query `?token=`
- PEM/OpenSSH/PGP private key блоки вырезаются целиком (от BEGIN до END)
- `--out`: отказ от symlink и каталога, которым владеет другой uid (anti-TOCTOU в `/var/tmp`)
- Валидация `--log-days` / `--timeout` / `--out` (anti-injection)
- Fleet: отказ от `/tmp`+sudo (TOCTOU) — копирование в `~/.cache/…/mktemp` + проверка sha256 перед `sudo -n`
- Fleet: whitelist `AUDIT_ARGS`, запрет `--no-redact` без `ALLOW_NO_REDACT=1`
- Fleet: cleanup remote-архивов после scp (отключается `KEEP_REMOTE=1`)
- Fleet: `umask 077`, `StrictHostKeyChecking=yes` по умолчанию
- Shadow: enum `empty|locked|hashed|unknown` вместо префикса хеша
- Обязателен GNU `timeout` (иначе exit 1)

### Исправлено

- `--deep` реально включает SMART/NVMe, полный `dpkg -V`, deep disk-usage и полные SUID/WW-сканы; без `--deep` — лёгкие сэмплы
- Динамический `TOTAL_STEPS` (`+net` / `+deep` / `+python3-apt`)
- `facts.json` через python3 + `schema_version: 1.1` (валидный JSON); `packages_upgradable` считает только строки `[upgradable`, не заголовок
- `journal_errors_window` без трёх строк заголовка CMD коллектора
- `docker inspect` → один вызов → валидный JSON-массив
- Connectivity: убран `apt-get -s update`; проверка источников через curl
- Manifest TSV: escape табов/переводов строк в команде
- Fleet: парсинг IPv6 `user@[addr]:port`, ненулевой exit при ошибках хостов
- Fleet: stdout ssh с MOTD — берётся последняя строка и проверяется префикс `~/.cache/razbudimir-audit/run.*`
- Fleet INDEX.md через python3/json вместо grep
- Портативный `now_ms` / `iso_now` (без поломки на `%N`)
- Проверка успеха `tar` при упаковке

### Изменено

- Fleet по умолчанию: `AUDIT_ARGS="--deep --no-net"`
- Требуется bash ≥4 для `run-fleet-audit.sh` (на macOS — Homebrew bash)

## [1.3.0] - 2026-08-16

### Добавлено

- Прогресс-бар с ETA, счётчиком шагов, текущей секцией и артефактом (по умолчанию включается автоматически при TTY, `--progress on` / `--no-progress` для явного управления)
- Подсветка «медленных» команд (>10с — жёлтый ⚠) и таймаутов (`rc=124` — красный ⏱) прямо во время выполнения
- Финальный `top-5` самых медленных шагов в консольной сводке
- Заголовки секций печатаются отдельной строкой над баром
- Совместимость с пайпами: при `stderr != tty` бар автоматически отключается

### Изменено

- Заголовок и финальная строка теперь оформлены рамкой с версией и подсказкой `scp` для копирования архива
- В сводке хоста печатается фактическая длительность прогона

## [1.2.0] - 2026-08-15

Первый публичный релиз.

### Добавлено

- `audit-ubuntu.sh` — read-only сборщик в 17 секций (system, hardware, kernel, packages, services, network, storage, security, performance, logs, containers, apps, configs, drift, monitoring, scheduled)
- Определение источника (Origin) каждого установленного пакета через `python3-apt`, отдельный список пакетов не из репозиториев Ubuntu
- Сравнение md5 conffiles с `/var/lib/dpkg/info/*.md5sums` — детект изменённых относительно пакета конфигов
- Резолвинг слушающих демонов до пакета, пометка «НЕ ИЗ ПАКЕТА» для ручных сборок
- Маскирование секретов (пароли/токены/community/URL-credentials/приватные ключи) с возможностью отключения через `--no-redact`
- Машинно-читаемый `facts.json` и человекочитаемая `summary.md` в каждом сборе
- `manifest.tsv` со всеми артефактами, кодами возврата и таймингами
- `run-fleet-audit.sh` — параллельный запуск по парку через SSH, сбор архивов, сводный `INDEX.md` и заготовки diff'ов в `compare/`
- Ключи `--deep`, `--log-days`, `--no-net`, `--no-redact`, `--out`, `--timeout`
