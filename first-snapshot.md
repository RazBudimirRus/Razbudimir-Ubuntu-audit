# Первый слепок парка: временный пользователь `auditor`

Не для weekly-cron и не часть `run-fleet-audit.sh`. Это ручной gate перед первым массовым прогоном: завести одноразовый канал доступа, прогнать fleet, сразу снести пользователя.

Зачем не `ubuntu` / личный админ: отдельный ключ, пустой home, запись в `auth.log` как `auditor`, sudoers только на коллектор — не `NOPASSWD: ALL`.

Коллектору root всё равно нужен (`shadow`, `sshd -T`, `dpkg -V`). Изолируется ключ и sudo, не сам сбор.

---

## 0. На рабочей машине — ключ кампании

Один ключ на дату слепка. Не кладите его в агент ssh по умолчанию навсегда.

```bash
STAMP=$(date +%Y%m%d)
KEY="$HOME/.ssh/razbudimir-audit-$STAMP"
ssh-keygen -t ed25519 -f "$KEY" -C "razbudimir-audit-$STAMP" -N ""
cat "$KEY.pub"
```

Публичную часть копируете на каждый хост на шаге 2.

---

## 1. На каждом сервере — заведение (под существующим админом)

Подставьте свой `ssh-ed25519 AAAA…` вместо плейсхолдера. Имя пользователя везде одно: `auditor`.

```bash
sudo useradd --create-home --shell /bin/bash --user-group auditor
sudo passwd -l auditor
sudo install -d -m 700 -o auditor -g auditor /home/auditor/.ssh
sudo install -d -m 700 -o auditor -g auditor /home/auditor/.cache/razbudimir-audit

sudo tee /home/auditor/.ssh/authorized_keys >/dev/null <<'EOF'
ssh-ed25519 AAAA...REPLACE_ME razbudimir-audit-YYYYMMDD
EOF
sudo chown auditor:auditor /home/auditor/.ssh/authorized_keys
sudo chmod 600 /home/auditor/.ssh/authorized_keys
```

Sudoers — только bash коллектора, который fleet кладёт в `mktemp` (`run.XXXXXX`). Не `ALL`. Cleanup архивов в этом режиме ручной (`KEEP_REMOTE=1`), чтобы не выдавать `rm -rf`.

```bash
sudo tee /etc/sudoers.d/razbudimir-audit >/dev/null <<'EOF'
Defaults:auditor !requiretty
auditor ALL=(root) NOPASSWD: /usr/bin/bash /home/auditor/.cache/razbudimir-audit/run.*/audit-ubuntu.sh
EOF
sudo chmod 440 /etc/sudoers.d/razbudimir-audit
sudo visudo -cf /etc/sudoers.d/razbudimir-audit
```

`sshd` не меняйте (`PermitRootLogin` и глобальный `PasswordAuthentication` оставьте как были). Пароль у `auditor` уже залочен.

Проверка с рабочей машины (должен быть `auditor` и в `sudo -l` — строка с `audit-ubuntu.sh`, не `(ALL) ALL`):

```bash
ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes auditor@HOST 'id; sudo -n -l'
```

---

## 2. Fleet

`servers.txt` — уже `auditor@…`, не `ubuntu@`.

```bash
cat > servers.txt <<'EOF'
auditor@10.0.0.11
auditor@10.0.0.12
EOF

# bash ≥4; на macOS: /opt/homebrew/bin/bash
KEEP_REMOTE=1 \
SSH_OPTS="-i $HOME/.ssh/razbudimir-audit-YYYYMMDD -o IdentitiesOnly=yes" \
AUDIT_ARGS="--deep --no-net" \
./run-fleet-audit.sh
```

`KEEP_REMOTE=1` — архивы на серверах не удаляются через `sudo rm` (для узкого sudoers это сознательно). После копирования на рабочую машину сносите их на шаге 3.

Если `sudo -n` падает: на хосте `sudo -n -l` под `auditor` и сверка, что путь — `/usr/bin/bash` (не `/bin/bash`). При необходимости поправьте drop-in и снова `visudo -cf`.

---

## 3. Снятие — сразу после слепка

На каждом сервере:

```bash
sudo rm -f /etc/sudoers.d/razbudimir-audit
sudo visudo -c
sudo userdel -r auditor
sudo rm -rf /var/tmp/server-audit
```

На рабочей машине:

```bash
rm -f "$HOME/.ssh/razbudimir-audit-YYYYMMDD" "$HOME/.ssh/razbudimir-audit-YYYYMMDD.pub"
```

Пользователь без снятия хуже постоянного `ubuntu`: через месяц это забытый NOPASSWD-канал.

---

## Чего не делать

- Не `auditor ALL=(root) NOPASSWD: ALL` — тогда это просто переименованный `ubuntu`.
- Не один бессрочный ключ на все будущие прогоны.
- Не оставлять `auditor` «на следующий раз».
- Не автоматизировать заведение из самого fleet: ручной шаг и есть подтверждение, что хост ваш.
