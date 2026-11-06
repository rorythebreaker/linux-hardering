#!/usr/bin/env bash
# =============================================================================
#  linux-harden.sh — first-time hardening for Debian / Ubuntu servers (TUI, RU/EN)
#  Первичная настройка безопасности Linux-сервера
#
#  Based on the "fresh Linux server checklist" + checks of nuver-labs/vps-audit
#
#  Usage / Запуск:
#    sudo ./linux-harden.sh                          interactive TUI
#    sudo ./linux-harden.sh --save-config my.conf    TUI, then save answers to a config
#    sudo ./linux-harden.sh --config my.conf --yes   non-interactive, no TUI
#    sudo ./linux-harden.sh --rollback [DIR]         undo a previous run (latest by default)
#    sudo ./linux-harden.sh --list-backups           list previous runs
#    sudo ./linux-harden.sh --print-config           print an example config
#
#  Options:
#    --lang ru|en     interface language
#    --dry-run        show what would be done, change nothing
#    --yes, -y        no confirmation (risky extras such as deleting users stay "no")
# =============================================================================
set -uo pipefail

VERSION="2.2"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/linux-harden-${STAMP}.log"
BACKUP_ROOT="/root"
BACKUP_DIR="${BACKUP_ROOT}/linux-harden-backup-${STAMP}"
VPS_AUDIT_URL="https://raw.githubusercontent.com/Nuver-Labs/vps-audit/main/vps-audit.sh"
SELF="$(readlink -f "$0")"

# Execution order is also the list of valid modules
ALL_MODULES="update time user logging firewall docker ssh fail2ban autoupd pwquality sudolog auditd sysctl services aide vpsaudit"

MODE="interactive"          # interactive | config | rollback | list | example
DRY_RUN=0
APT_UPDATED=0
ASSUME_YES=0
USE_TUI=0
UI_LANG=""
CONFIG_FILE=""
SAVE_CONFIG=""
ROLLBACK_DIR=""

# ---------------------------------------------------------------- parameters
MODULES=""
UTILS="curl wget git vim unzip htop"
TIMEZONE=""
ADMIN_USER="admin"
ADMIN_PASS=""
ADMIN_PASS_HASH=""
KEY_SOURCE="skip"           # root | paste | skip
PUBKEY=""
PUBKEYS="" # Multiple public keys separated by |; never store private keys
CURRENT_SSH_PORT="22"
SSH_PORT=""
SSH_ROOT="no"               # no | prohibit-password
SSH_PASSAUTH="no"
SSH_MAXAUTH="3"
SSH_ALIVE="300"
SSH_ALLOWUSERS="no"
EXTRA_PORTS=""
DOCKER_MODE="ufw-docker"    # ufw-docker | localhost | skip
DOCKER_PORTS=""
DOCKER_RESTART="no"
F2B_BANTIME="1h"
F2B_MAXRETRY="5"
AUTO_REBOOT="no"
PW_MINLEN="12"
DISABLE_SERVICES=""
HAS_DOCKER=0

CONFIG_KEYS="LANG_UI MODULES UTILS TIMEZONE ADMIN_USER ADMIN_PASS ADMIN_PASS_HASH KEY_SOURCE PUBKEY PUBKEYS SSH_PORT SSH_ROOT SSH_PASSAUTH SSH_MAXAUTH SSH_ALIVE SSH_ALLOWUSERS EXTRA_PORTS DOCKER_MODE DOCKER_PORTS DOCKER_RESTART F2B_BANTIME F2B_MAXRETRY AUTO_REBOOT PW_MINLEN DISABLE_SERVICES"

declare -a RESULTS=()

# ================================================================= helpers
tr_() { if [[ $UI_LANG == ru ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }

log()  { echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"; }
say()  { printf '\n\e[1;36m==> %s\e[0m\n' "$*"; log "== $*"; }
ok()   { printf '\e[32m[OK]\e[0m %s\n' "$*";   log "OK: $*"; }
warn() { printf '\e[33m[WARN]\e[0m %s\n' "$*"; log "WARN: $*"; }
err()  { printf '\e[31m[FAIL]\e[0m %s\n' "$*"; log "FAIL: $*"; }
die()  { ((USE_TUI)) && clear; printf '\e[31mERROR:\e[0m %s\n' "$*" >&2; log "DIE: $*"; exit 1; }
abort() { ((USE_TUI)) && clear; echo "$(tr_ 'Отменено.' 'Cancelled.')"; exit 1; }

result() { RESULTS+=("$1|$2"); }
has()    { [[ " $MODULES " == *" $1 "* ]]; }

run() {
    log "+ $*"
    if ((DRY_RUN)); then printf '\e[33m[dry-run]\e[0m %s\n' "$*"; return 0; fi
    "$@" 2>&1 | tee -a "$LOG_FILE"
    return "${PIPESTATUS[0]}"
}

# ---- rollback bookkeeping: originals are copied once, new files are listed
record_created() {
    ((DRY_RUN)) && return 0
    grep -qxF -- "$1" "$BACKUP_DIR/.created" 2>/dev/null || echo "$1" >> "$BACKUP_DIR/.created"
}
record_action() {
    ((DRY_RUN)) && return 0
    grep -qxF -- "$*" "$BACKUP_DIR/.actions" 2>/dev/null || echo "$*" >> "$BACKUP_DIR/.actions"
}
backup() {
    ((DRY_RUN)) && return 0
    local f=$1
    grep -qxF -- "$f" "$BACKUP_DIR/.created" 2>/dev/null && return 0   # we created it
    if [[ -e $f || -L $f ]]; then
        [[ -e ${BACKUP_DIR}$f ]] && return 0                             # keep the first original
        mkdir -p "${BACKUP_DIR}$(dirname "$f")"
        cp -a "$f" "${BACKUP_DIR}$f"
    else
        record_created "$f"
    fi
}

# write_file PATH [MODE]  — content from stdin
write_file() {
    local path=$1 mode=${2:-644} content
    content="$(cat)"
    log "write $path"
    if ((DRY_RUN)); then
        printf '\e[33m[dry-run]\e[0m write %s:\n' "$path"
        printf '%s\n' "$content" | sed 's/^/    /'
        return 0
    fi
    backup "$path"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" > "$path"
    chmod "$mode" "$path"
}

apt_install() {
    local p new=()
    for p in "$@"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || new+=("$p")
    done
    ((${#new[@]})) || return 0
    if ! run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${new[@]}"; then
        # empty or stale package lists on a fresh VPS: refresh once and retry
        ((APT_UPDATED)) && return 1
        APT_UPDATED=1
        run env DEBIAN_FRONTEND=noninteractive apt-get update -q || return 1
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${new[@]}" || return 1
    fi
    for p in "${new[@]}"; do record_action "pkg_installed $p"; done
}

# set_kv FILE KEY VALUE — "key = value" style config
set_kv() {
    local f=$1 k=$2 v=$3
    log "set $k = $v in $f"
    if ((DRY_RUN)); then printf '\e[33m[dry-run]\e[0m %s: %s = %s\n' "$f" "$k" "$v"; return; fi
    backup "$f"; touch "$f"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]*=" "$f"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${k}[[:space:]]*=.*|${k} = ${v}|" "$f"
    else
        echo "${k} = ${v}" >> "$f"
    fi
}

restart_ssh() {
    # Ubuntu 22.10+ may use socket activation: the port lives in ssh.socket
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        run systemctl daemon-reload && run systemctl restart ssh.socket
    else
        local unit=ssh
        systemctl cat ssh.service &>/dev/null || unit=sshd
        run systemctl restart "$unit"
    fi
}

ufw_active() { ufw status 2>/dev/null | grep -q 'Status: active'; }

# ---- validators
num()        { [[ $1 =~ ^[0-9]+$ ]]; }
yn()         { [[ $1 == yes || $1 == no ]]; }
valid_port() { num "$1" && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_pubkeys() {
    local item
    local -a items
    IFS='|' read -r -a items <<< "$1"
    ((${#items[@]} > 0)) || return 1
    for item in "${items[@]}"; do
        [[ -n $item ]] && valid_pubkey "$item" || return 1
    done
}
valid_pubkey() { [[ $1 =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9@.-]+)\ [A-Za-z0-9+/=]+ ]]; }
valid_user() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ && $1 != root ]]; }
valid_portlist() {   # "80/tcp,443/tcp,8000:8010/tcp" (empty is fine)
    local p a=() start range proto
    IFS=',' read -ra a <<< "$1"
    for p in "${a[@]}"; do
        p=${p// /}; [[ -z $p ]] && continue
        [[ $p =~ ^([0-9]{1,5})(:([0-9]{1,5}))?(/(tcp|udp))?$ ]] || return 1
        start=${BASH_REMATCH[1]}; range=${BASH_REMATCH[3]:-}; proto=${BASH_REMATCH[5]:-}
        valid_port "$start" || return 1
        [[ -n $range ]] && { valid_port "$range" || return 1; }
        [[ -n $range && -z $proto ]] && return 1   # ranges need /tcp or /udp
    done
    return 0
}
port_busy() { [[ $1 != "$CURRENT_SSH_PORT" ]] && ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }

# ================================================================= TUI
size_ui() {
    local th tw
    read -r th tw < <(stty size 2>/dev/null || echo "24 80")
    W=$(( tw > 92 ? 88 : tw - 4 )); H=$(( th > 32 ? 28 : th - 2 )); LH=$(( H - 9 ))
    (( LH < 4 )) && LH=4
}
W=78; H=22; LH=12
BT="linux-harden v${VERSION}"
ui_msg()   { whiptail --backtitle "$BT" --title "$1" --msgbox "$2" "$H" "$W"; }
ui_yesno() { whiptail --backtitle "$BT" --title "$1" --yes-button "$(tr_ Да Yes)" --no-button "$(tr_ Нет No)" ${3:+--defaultno} --yesno "$2" "$H" "$W"; }
ui_input() { whiptail --backtitle "$BT" --title "$1" --inputbox "$2" "$H" "$W" "$3" 3>&1 1>&2 2>&3; }
ui_pass()  { whiptail --backtitle "$BT" --title "$1" --passwordbox "$2" "$H" "$W" 3>&1 1>&2 2>&3; }
ui_menu()  { local t=$1 x=$2; shift 2; whiptail --backtitle "$BT" --title "$t" --menu "$x" "$H" "$W" "$LH" "$@" 3>&1 1>&2 2>&3; }
ui_check() { local t=$1 x=$2; shift 2; whiptail --backtitle "$BT" --title "$t" --separate-output --checklist "$x" "$H" "$W" "$LH" "$@" 3>&1 1>&2 2>&3; }

# ask "question" [defaultno] — TUI, terminal or --yes
ask() {
    local defno=${2:-} a
    if ((ASSUME_YES)); then [[ -z $defno ]]; return; fi
    if ((USE_TUI)); then ui_yesno "linux-harden" "$1" "$defno"; return; fi
    [[ -t 0 ]] || { [[ -z $defno ]]; return; }
    read -rp "$1 [$( [[ -n $defno ]] && echo y/N || echo Y/n )] " a || return 1
    [[ -z $a ]] && { [[ -z $defno ]]; return; }
    [[ $a =~ ^[YyДд] ]]
}

ensure_whiptail() {
    command -v whiptail >/dev/null && return 0
    echo "Installing whiptail..."
    if ((DRY_RUN)); then
        die "whiptail is required for interactive dry-run; install it manually or use --config"
    fi
    apt-get update -q >>"$LOG_FILE" 2>&1 && apt-get install -y -q whiptail >>"$LOG_FILE" 2>&1 \
        || die "Cannot install whiptail"
}

choose_lang() {
    [[ $UI_LANG == ru || $UI_LANG == en ]] && return 0
    if ((USE_TUI)); then
        UI_LANG=$(whiptail --backtitle "$BT" --title "Language / Язык" --menu "Choose language / Выберите язык" 12 50 2 \
            ru "Русский" en "English" 3>&1 1>&2 2>&3) || abort
    elif [[ ${LANG:-} == ru* ]]; then UI_LANG=ru
    else UI_LANG=en; fi
}

# ================================================================= config
example_config() {
cat <<'EOF'
# linux-harden config. Only KEY=VALUE lines, nothing is executed.
# Run:  sudo ./linux-harden.sh --config linux-harden.conf --yes
# Many servers:
#   for h in srv1 srv2; do
#     scp linux-harden.sh linux-harden.conf root@$h:/root/ &&
#     ssh -t root@$h 'bash /root/linux-harden.sh --config /root/linux-harden.conf --yes'
#   done

LANG_UI='ru'                       # ru | en
# update time user logging firewall docker ssh fail2ban autoupd pwquality sudolog auditd sysctl services aide vpsaudit
MODULES='update time user logging firewall ssh fail2ban autoupd pwquality sudolog auditd vpsaudit'
UTILS='curl wget git vim unzip htop'
TIMEZONE='Europe/Moscow'

ADMIN_USER='admin'
# Hash, not the password itself:  openssl passwd -6
ADMIN_PASS_HASH='$6$CHANGE_ME'
KEY_SOURCE='paste'                 # root | paste | skip
PUBKEY='ssh-ed25519 AAAA...your-key... you@pc'
PUBKEYS='' # Optional: ssh-ed25519 AAAA... pc1|ssh-ed25519 AAAA... pc2

SSH_PORT='822'                     # <1024, otherwise vps-audit reports FAIL
SSH_ROOT='no'                      # no | prohibit-password
SSH_PASSAUTH='no'                  # yes | no (forced to yes if no keys are found)
SSH_MAXAUTH='3'
SSH_ALIVE='300'
SSH_ALLOWUSERS='no'                # yes = AllowUsers ADMIN_USER

EXTRA_PORTS='80/tcp,443/tcp'       # extra UFW ports for host services

DOCKER_MODE='ufw-docker'           # ufw-docker | localhost | skip
DOCKER_PORTS='80/tcp,443/tcp'      # container ports to expose (ufw route allow)
DOCKER_RESTART='no'                # localhost mode: restart dockerd now

F2B_BANTIME='1h'
F2B_MAXRETRY='5'
AUTO_REBOOT='no'                   # reboot at 04:00 when updates need it
PW_MINLEN='12'
DISABLE_SERVICES=''                # e.g. 'cups.service avahi-daemon.service'
EOF
}

load_config() {
    local f=$1 line key val n=0
    [[ -r $f ]] || die "Config not readable: $f"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z $line || $line == \#* ]] && continue
        [[ $line =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]] || die "$f:$n: expected KEY=VALUE"
        key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[2]}
        [[ " $CONFIG_KEYS " == *" $key "* ]] || die "$f:$n: unknown key $key"
        if   [[ $val =~ ^\'([^\']*)\'[[:space:]]*(#.*)?$ ]]; then val=${BASH_REMATCH[1]}
        elif [[ $val =~ ^\"([^\"]*)\"[[:space:]]*(#.*)?$ ]]; then val=${BASH_REMATCH[1]}
        else
            val=${val%%[[:space:]]#*}
            val="${val%"${val##*[![:space:]]}"}"
        fi
        if [[ $key == LANG_UI ]]; then
            [[ -z $UI_LANG ]] && UI_LANG=$val
            continue
        fi
        printf -v "$key" '%s' "$val"
    done < "$f"
    log "config loaded: $f"
}

quote_val() { if [[ $1 != *\'* ]]; then printf "'%s'" "$1"; else printf '"%s"' "$1"; fi; }

save_config() {
    local f=$1 k v hash=$ADMIN_PASS_HASH
    if [[ -n $ADMIN_PASS ]]; then
        hash=$(openssl passwd -6 -stdin <<< "$ADMIN_PASS" 2>/dev/null) \
            || { hash=""; warn "openssl: $(tr_ 'пароль не сохранён в конфиг' 'password not saved to config')"; }
    fi
    {
        echo "# linux-harden ${VERSION} config — $(date '+%F %T') — $(hostname)"
        echo "# sudo ./linux-harden.sh --config $(basename "$f") --yes"
        for k in $CONFIG_KEYS; do
            case $k in
                LANG_UI)         v=$UI_LANG ;;
                ADMIN_PASS)      continue ;;
                ADMIN_PASS_HASH) v=$hash ;;
                *)               v=${!k} ;;
            esac
            printf '%s=%s\n' "$k" "$(quote_val "$v")"
        done
    } > "$f" || { warn "save config $f"; return 1; }
    chmod 600 "$f"
    ok "$(tr_ 'Конфиг сохранён' 'Config saved'): $f"
}

validate_params() {
    local e=() m
    MODULES=$(echo "$MODULES" | tr ',\n' '  ' | xargs)
    [[ -n $MODULES ]] || e+=("MODULES: $(tr_ 'пусто' 'empty')")
    for m in $MODULES; do
        [[ " $ALL_MODULES " == *" $m "* ]] || e+=("MODULES: $(tr_ 'неизвестный модуль' 'unknown module') '$m'")
    done
    num "$PW_MINLEN" && (( PW_MINLEN >= 8 && PW_MINLEN <= 64 )) || e+=("PW_MINLEN: 8..64")
    if has user || [[ $SSH_ALLOWUSERS == yes ]]; then
        valid_user "$ADMIN_USER" || e+=("ADMIN_USER: '$ADMIN_USER'")
    fi
    if has user; then
        if ! id "$ADMIN_USER" &>/dev/null && [[ -z $ADMIN_PASS && -z $ADMIN_PASS_HASH ]]; then
            e+=("ADMIN_PASS_HASH: $(tr_ 'нужен пароль для нового пользователя (sudo)' 'a new user needs a password (sudo)')")
        fi
        [[ -z $ADMIN_PASS_HASH || $ADMIN_PASS_HASH == \$* ]] || e+=("ADMIN_PASS_HASH: $(tr_ 'ожидается хэш из openssl passwd -6' 'expected a hash from openssl passwd -6')")
        [[ $ADMIN_PASS_HASH == *CHANGE_ME* ]] && e+=("ADMIN_PASS_HASH: $(tr_ 'замените пример' 'replace the example')")
        case $KEY_SOURCE in
            root|skip) ;;
            paste) { valid_pubkey "$PUBKEY" || [[ -z $PUBKEY && -n $PUBKEYS ]]; } || e+=("PUBKEY: $(tr_ 'не похоже на публичный ключ' 'not a public key')") ;;
            *) e+=("KEY_SOURCE: root | paste | skip") ;;
        esac
        [[ -z $PUBKEYS ]] || valid_pubkeys "$PUBKEYS" || e+=("PUBKEYS: invalid public key list")
    fi
    if has ssh; then
        if ! valid_port "$SSH_PORT"; then e+=("SSH_PORT: '$SSH_PORT'")
        elif port_busy "$SSH_PORT"; then e+=("SSH_PORT: $(tr_ 'порт занят' 'port in use') $SSH_PORT"); fi
        [[ $SSH_ROOT == no || $SSH_ROOT == prohibit-password ]] || e+=("SSH_ROOT: no | prohibit-password")
        yn "$SSH_PASSAUTH"   || e+=("SSH_PASSAUTH: yes | no")
        yn "$SSH_ALLOWUSERS" || e+=("SSH_ALLOWUSERS: yes | no")
        num "$SSH_MAXAUTH" && (( SSH_MAXAUTH >= 1 && SSH_MAXAUTH <= 10 )) || e+=("SSH_MAXAUTH: 1..10")
        num "$SSH_ALIVE" || e+=("SSH_ALIVE")
    fi
    has firewall && { valid_portlist "$EXTRA_PORTS" || e+=("EXTRA_PORTS: '$EXTRA_PORTS'"); }
    if has docker; then
        [[ $DOCKER_MODE =~ ^(ufw-docker|localhost|skip)$ ]] || e+=("DOCKER_MODE: ufw-docker | localhost | skip")
        valid_portlist "$DOCKER_PORTS" || e+=("DOCKER_PORTS: '$DOCKER_PORTS'")
        yn "$DOCKER_RESTART" || e+=("DOCKER_RESTART: yes | no")
    fi
    if has fail2ban; then
        [[ $F2B_BANTIME =~ ^[0-9]+[smhdw]?$ ]] || e+=("F2B_BANTIME: 10m, 1h, 1d")
        num "$F2B_MAXRETRY" || e+=("F2B_MAXRETRY")
    fi
    has autoupd && { yn "$AUTO_REBOOT" || e+=("AUTO_REBOOT: yes | no"); }
    has time && { [[ -n $TIMEZONE && -f /usr/share/zoneinfo/$TIMEZONE ]] || e+=("TIMEZONE: '$TIMEZONE'"); }
    has ssh || SSH_PORT=$CURRENT_SSH_PORT

    ((${#e[@]} == 0)) && return 0
    local msg; msg="$(tr_ 'Ошибки в параметрах:' 'Invalid parameters:')"$'\n'"$(printf ' - %s\n' "${e[@]}")"
    ((USE_TUI)) && ui_msg "!" "$msg"
    die "$msg"
}

build_summary() {
    local s
    s="$(tr_ 'Режим' 'Mode'): $( ((DRY_RUN)) && echo DRY-RUN || tr_ 'ПРИМЕНЕНИЕ' 'APPLY' )
$(tr_ 'Модули' 'Modules'): $MODULES
"
    has update    && s+="$(tr_ 'Утилиты' 'Utilities'): ${UTILS:-—}
"
    has time      && s+="$(tr_ 'Часовой пояс' 'Timezone'): $TIMEZONE
"
    has user      && s+="$(tr_ 'Пользователь' 'User'): $ADMIN_USER, $(tr_ 'ключ' 'key'): $KEY_SOURCE
"
    has ssh       && s+="SSH: Port $SSH_PORT, PermitRootLogin $SSH_ROOT, PasswordAuthentication $SSH_PASSAUTH, MaxAuthTries $SSH_MAXAUTH, AllowUsers $SSH_ALLOWUSERS
"
    has firewall  && s+="UFW: $SSH_PORT/tcp ${EXTRA_PORTS}
"
    has docker    && s+="Docker: $DOCKER_MODE ${DOCKER_PORTS:+(route allow $DOCKER_PORTS)}$( [[ $DOCKER_MODE == localhost ]] && echo ", restart $DOCKER_RESTART")
"
    has fail2ban  && s+="Fail2ban: bantime $F2B_BANTIME, maxretry $F2B_MAXRETRY
"
    has autoupd   && s+="$(tr_ 'Автоперезагрузка' 'Auto reboot'): $AUTO_REBOOT
"
    has pwquality && s+="pwquality minlen: $PW_MINLEN
"
    has services  && s+="$(tr_ 'Отключить' 'Disable'): ${DISABLE_SERVICES:-—}
"
    printf '%s' "$s"
}

# ================================================================= interactive
collect_interactive() {
    local p1 p2 def_port items unit keep

    ui_msg "$(tr_ 'Добро пожаловать' 'Welcome')" "$(tr_ \
"Первичная настройка безопасности сервера.

Система: $OS_NAME
Текущий порт SSH: $CURRENT_SSH_PORT
Docker: $( ((HAS_DOCKER)) && echo найден || echo 'не найден')
Режим: $( ((DRY_RUN)) && echo 'DRY-RUN (без изменений)' || echo 'ПРИМЕНЕНИЕ ИЗМЕНЕНИЙ')

Выберите модули и параметры, затем подтвердите запуск.
Оригиналы файлов: $BACKUP_DIR
Откат: $SELF --rollback

ВАЖНО: не закрывайте текущую SSH-сессию до проверки входа в новой." \
"First-time server security hardening.

System: $OS_NAME
Current SSH port: $CURRENT_SSH_PORT
Docker: $( ((HAS_DOCKER)) && echo found || echo 'not found')
Mode: $( ((DRY_RUN)) && echo 'DRY-RUN (no changes)' || echo 'APPLY CHANGES')

Pick modules and parameters, then confirm.
Original files: $BACKUP_DIR
Undo: $SELF --rollback

IMPORTANT: keep this SSH session open until you verify login in a new one.")"

    local dk; dk=$( ((HAS_DOCKER)) && echo ON || echo OFF )
    MODULES=$(ui_check "$(tr_ 'Модули' 'Modules')" "$(tr_ 'Пробел — выбрать, Enter — далее' 'Space — toggle, Enter — continue')" \
        update    "$(tr_ '1. Обновление системы и утилиты'         '1. System update and base utilities')" ON \
        time      "$(tr_ '   Часовой пояс и синхронизация времени' '   Timezone and time sync (NTP)')" ON \
        user      "$(tr_ '4. Пользователь-администратор + SSH-ключ' '4. Admin user + SSH key')" ON \
        firewall  "$(tr_ '2. Файрвол UFW'                          '2. UFW firewall')" ON \
        docker    "$(tr_ '2. Docker: закрыть обход UFW'            '2. Docker: stop it bypassing UFW')" "$dk" \
        ssh       "$(tr_ '3. Защита SSH'                           '3. SSH hardening')" ON \
        fail2ban  "$(tr_ '6. Fail2ban (защита от брутфорса)'       '6. Fail2ban (brute-force protection)')" ON \
        autoupd   "$(tr_ '6. Автообновления безопасности'          '6. Automatic security updates')" ON \
        pwquality "$(tr_ '   Политика паролей (pwquality)'         '   Password policy (pwquality)')" ON \
        sudolog   "$(tr_ '5. Логирование sudo'                     '5. Sudo logging')" ON \
        logging   "$(tr_ '5. rsyslog + постоянный журнал journald' '5. rsyslog + persistent journald')" ON \
        auditd    "$(tr_ '5. Аудит auditd'                         '5. auditd audit rules')" ON \
        sysctl    "$(tr_ '   Защита ядра и сети (sysctl)'          '   Kernel/network hardening (sysctl)')" OFF \
        services  "$(tr_ '7. Отключение лишних служб'              '7. Disable unneeded services')" OFF \
        aide      "$(tr_ '6. AIDE — контроль целостности (долго)'  '6. AIDE file integrity (slow)')" OFF \
        vpsaudit  "$(tr_ '7. Итоговая проверка vps-audit'          '7. Final vps-audit check')" ON \
    ) || abort
    MODULES=$(echo "$MODULES" | tr '\n' ' ')
    [[ -n ${MODULES// /} ]] || abort

    if has update; then
        UTILS=$(ui_check "$(tr_ 'Утилиты' 'Utilities')" "$(tr_ 'Какие пакеты установить' 'Packages to install')" \
            curl "" ON  wget "" ON  git "" ON  vim "" ON  unzip "" ON  htop "" ON \
            tmux "" OFF  net-tools "netstat" OFF  ncdu "" OFF  rsync "" OFF) || abort
        UTILS=$(echo "$UTILS" | tr '\n' ' ')
    fi

    if has time; then
        while :; do
            TIMEZONE=$(ui_input "$(tr_ 'Часовой пояс' 'Timezone')" "$(tr_ 'Например Europe/Moscow, UTC' 'E.g. Europe/Moscow, UTC')" "$TIMEZONE") || abort
            [[ -f /usr/share/zoneinfo/$TIMEZONE ]] && break
            ui_msg "!" "$(tr_ 'Неизвестный часовой пояс' 'Unknown timezone')"
        done
    fi

    if has user; then
        while :; do
            ADMIN_USER=$(ui_input "$(tr_ 'Пользователь' 'User')" "$(tr_ 'Имя пользователя-администратора (sudo)' 'Admin (sudo) user name')" "$ADMIN_USER") || abort
            valid_user "$ADMIN_USER" && break
            ui_msg "!" "$(tr_ 'Недопустимое имя пользователя' 'Invalid user name')"
        done
        if ! id "$ADMIN_USER" &>/dev/null; then
            while :; do
                p1=$(ui_pass "$(tr_ 'Пароль' 'Password')" "$(tr_ "Пароль для $ADMIN_USER (нужен для sudo), от $PW_MINLEN символов" "Password for $ADMIN_USER (used by sudo), $PW_MINLEN+ chars")") || abort
                p2=$(ui_pass "$(tr_ 'Пароль' 'Password')" "$(tr_ 'Повторите пароль' 'Repeat password')") || abort
                [[ $p1 == "$p2" && ${#p1} -ge $PW_MINLEN ]] && { ADMIN_PASS=$p1; break; }
                ui_msg "!" "$(tr_ 'Пароли не совпадают или слишком короткие' 'Passwords do not match or are too short')"
            done
        fi
        KEY_SOURCE=$(ui_menu "$(tr_ 'SSH-ключ' 'SSH key')" "$(tr_ "Откуда взять публичный ключ для $ADMIN_USER?" "Where to get the public key for $ADMIN_USER?")" \
            root  "$(tr_ 'Скопировать из /root/.ssh/authorized_keys' 'Copy from /root/.ssh/authorized_keys')" \
            paste "$(tr_ 'Вставить ключ (ssh-ed25519 AAAA...)' 'Paste a key (ssh-ed25519 AAAA...)')" \
            skip  "$(tr_ 'Пропустить (ключ уже есть / добавлю сам)' 'Skip (already there / will add myself)')") || abort
        if [[ $KEY_SOURCE == paste ]]; then
            while :; do
                PUBKEY=$(ui_input "$(tr_ 'SSH-ключ' 'SSH key')" "$(tr_ 'Вставьте публичный ключ одной строкой' 'Paste the public key as one line')" "") || abort
                valid_pubkey "$PUBKEY" && break
                ui_msg "!" "$(tr_ 'Это не похоже на публичный SSH-ключ' 'That does not look like a public SSH key')"
            done
        fi
        if [[ $KEY_SOURCE == paste ]]; then
            while ui_yesno "$(tr_ 'SSH-ключи' 'SSH keys')" "$(tr_ 'Добавить ещё один публичный ключ?' 'Add another public key?')"; do
                while :; do
                    local_key=$(ui_input "$(tr_ 'SSH-ключ' 'SSH key')" "$(tr_ 'Вставьте следующий публичный ключ' 'Paste the next public key')" "") || abort
                    valid_pubkey "$local_key" && break
                    ui_msg "!" "$(tr_ 'Недопустимый ключ' 'Invalid public key')"
                done
                PUBKEYS+="${PUBKEYS:+|}$local_key"
            done
        fi
    fi

    if has ssh; then
        def_port=$CURRENT_SSH_PORT; [[ $def_port == 22 ]] && def_port=822
        while :; do
            SSH_PORT=$(ui_input "SSH" "$(tr_ \
"Порт SSH. vps-audit считает порт ≥1024 ошибкой (непривилегированный порт может занять обычный пользователь), поэтому лучше порт <1024, например 822." \
"SSH port. vps-audit flags ports ≥1024 as FAIL (any user could bind an unprivileged port), so prefer a port <1024, e.g. 822.")" "$def_port") || abort
            if ! valid_port "$SSH_PORT"; then ui_msg "!" "$(tr_ 'Неверный номер порта' 'Invalid port number')"; continue; fi
            if port_busy "$SSH_PORT"; then ui_msg "!" "$(tr_ "Порт $SSH_PORT уже занят" "Port $SSH_PORT is already in use")"; continue; fi
            break
        done
        SSH_ROOT=$(ui_menu "SSH" "PermitRootLogin" \
            no                "$(tr_ 'Запретить вход root (рекомендуется)' 'Deny root login (recommended)')" \
            prohibit-password "$(tr_ 'Root только по ключу' 'Root with key only')") || abort
        if ui_yesno "SSH" "$(tr_ 'Отключить вход по паролю (только ключи)?
Если у пользователя не окажется ключа, скрипт оставит пароли включёнными.' \
'Disable password login (keys only)?
If no key is found for the user, password login will be left enabled.')"; then SSH_PASSAUTH=no; else SSH_PASSAUTH=yes; fi
        SSH_MAXAUTH=$(ui_input "SSH" "MaxAuthTries (1-10)" "$SSH_MAXAUTH") || abort
        SSH_ALIVE=$(ui_input "SSH" "$(tr_ 'ClientAliveInterval (сек), отключение неактивной сессии' 'ClientAliveInterval (sec), idle session timeout')" "$SSH_ALIVE") || abort
        if has user && ui_yesno "SSH" "$(tr_ "Разрешить вход по SSH только пользователю $ADMIN_USER (AllowUsers)?" "Allow SSH login only for $ADMIN_USER (AllowUsers)?")" defaultno; then
            SSH_ALLOWUSERS=yes
        fi
    fi

    if has firewall; then
        while :; do
            EXTRA_PORTS=$(ui_input "UFW" "$(tr_ \
"SSH-порт откроется автоматически ($SSH_PORT).
Порты служб на самом хосте через запятую, например: 80/tcp,443/tcp
Порты контейнеров Docker задаются отдельно в модуле Docker.
Пусто — больше ничего не открывать." \
"The SSH port is opened automatically ($SSH_PORT).
Ports of host services, comma-separated, e.g.: 80/tcp,443/tcp
Docker container ports are set separately in the Docker module.
Empty — open nothing else.")" "$EXTRA_PORTS") || abort
            valid_portlist "$EXTRA_PORTS" && break
            ui_msg "!" "$(tr_ 'Формат: 80/tcp,443/tcp,8000:8010/tcp' 'Format: 80/tcp,443/tcp,8000:8010/tcp')"
        done
    fi

    if has docker; then
        DOCKER_MODE=$(ui_menu "Docker" "$(tr_ \
"Docker пишет свои правила iptables раньше правил UFW, поэтому порт из 'docker run -p 8080:80' открыт в интернет, даже если UFW его запрещает. Как закрыть?" \
"Docker inserts its iptables rules before UFW, so a port from 'docker run -p 8080:80' is reachable from the internet even if UFW denies it. How to fix?")" \
            ufw-docker "$(tr_ 'Правила DOCKER-USER в UFW (рекомендуется)' 'DOCKER-USER rules via UFW (recommended)')" \
            localhost  "$(tr_ 'Публиковать порты только на 127.0.0.1'     'Publish ports on 127.0.0.1 only')" \
            skip       "$(tr_ 'Ничего не менять'                          'Change nothing')") || abort
        if [[ $DOCKER_MODE == ufw-docker ]]; then
            while :; do
                DOCKER_PORTS=$(ui_input "Docker" "$(tr_ \
"Порты контейнеров, которые нужно открыть наружу (ufw route allow), через запятую. Например: 80/tcp,443/tcp
Это порты ВНУТРИ контейнера (для -p 8080:80 укажите 80/tcp).
Пусто — все опубликованные порты контейнеров закрыты извне." \
"Container ports to expose to the internet (ufw route allow), comma-separated. E.g.: 80/tcp,443/tcp
These are ports INSIDE the container (for -p 8080:80 use 80/tcp).
Empty — all published container ports are closed from outside.")" "$DOCKER_PORTS") || abort
                valid_portlist "$DOCKER_PORTS" && break
                ui_msg "!" "$(tr_ 'Формат: 80/tcp,443/tcp' 'Format: 80/tcp,443/tcp')"
            done
        elif [[ $DOCKER_MODE == localhost ]]; then
            if ui_yesno "Docker" "$(tr_ \
"Перезапустить Docker сейчас, чтобы применить настройку?
Контейнеры без restart-политики остановятся. Уже созданные контейнеры сохранят старую привязку портов до пересоздания." \
"Restart Docker now to apply the setting?
Containers without a restart policy will stop. Existing containers keep their old port binding until recreated.")" defaultno; then
                DOCKER_RESTART=yes
            fi
        fi
    fi

    if has fail2ban; then
        F2B_BANTIME=$(ui_input "Fail2ban" "$(tr_ 'Время бана (bantime): 10m, 1h, 1d' 'Ban time (bantime): 10m, 1h, 1d')" "$F2B_BANTIME") || abort
        F2B_MAXRETRY=$(ui_input "Fail2ban" "$(tr_ 'Попыток до бана (maxretry)' 'Attempts before ban (maxretry)')" "$F2B_MAXRETRY") || abort
    fi

    if has autoupd && ui_yesno "$(tr_ 'Автообновления' 'Auto updates')" \
        "$(tr_ 'Разрешить автоматическую перезагрузку в 04:00, если её требуют обновления?' 'Allow automatic reboot at 04:00 when updates require it?')" defaultno; then
        AUTO_REBOOT=yes
    fi

    if has pwquality; then
        PW_MINLEN=$(ui_input "pwquality" "$(tr_ 'Минимальная длина пароля (vps-audit требует ≥12)' 'Minimum password length (vps-audit wants ≥12)')" "$PW_MINLEN") || abort
    fi

    if has services; then
        keep='^(ssh|sshd|systemd-.*|dbus|cron|rsyslog|ufw|fail2ban|auditd|docker|containerd|getty@.*|serial-getty@.*|networking|NetworkManager|chrony|polkit|unattended-upgrades|user@.*|qemu-guest-agent|cloud-.*)\.service$'
        items=()
        while read -r unit; do
            [[ $unit =~ $keep ]] && continue
            items+=("$unit" "" OFF)
        done < <(systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}')
        if ((${#items[@]})); then
            DISABLE_SERVICES=$(ui_check "$(tr_ 'Службы' 'Services')" "$(tr_ 'Отметьте службы для ОТКЛЮЧЕНИЯ (системные скрыты)' 'Select services to DISABLE (core ones hidden)')" "${items[@]}") || abort
            DISABLE_SERVICES=$(echo "$DISABLE_SERVICES" | tr '\n' ' ')
        fi
    fi
}

# ================================================================= modules
mod_update() {
    say "$(tr_ 'Обновление системы' 'System update')"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -q || return 1
    APT_UPDATED=1
    run env DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade -y -q || return 1
    local -a u; read -ra u <<< "$UTILS"
    ((${#u[@]})) && { apt_install "${u[@]}" || return 1; }
    ok "$(tr_ 'Ядро' 'Kernel'): $(uname -r)"
    [[ -f /var/run/reboot-required ]] && { warn "$(tr_ 'Требуется перезагрузка' 'Reboot required')"; return 2; }
    return 0
}

mod_time() {
    say "$(tr_ 'Время' 'Time')"
    local old; old=$(timedatectl show -p Timezone --value 2>/dev/null)
    if [[ -n $old && $old != "$TIMEZONE" ]]; then
        record_action "timezone $old"
        run timedatectl set-timezone "$TIMEZONE" || return 1
    fi
    if ! systemctl list-unit-files 2>/dev/null | grep -qE '^(chrony|ntp|ntpsec)\.service'; then
        apt_install systemd-timesyncd
    fi
    run timedatectl set-ntp true || return 2
}

mod_user() {
    say "$(tr_ 'Пользователь' 'User') $ADMIN_USER"
    if ! id "$ADMIN_USER" &>/dev/null; then
        run adduser --disabled-password --gecos "" "$ADMIN_USER" || return 1
        record_action "user_created $ADMIN_USER"
        if ((DRY_RUN)); then echo "[dry-run] chpasswd $ADMIN_USER"
        elif [[ -n $ADMIN_PASS_HASH ]]; then echo "${ADMIN_USER}:${ADMIN_PASS_HASH}" | chpasswd -e || return 1
        else echo "${ADMIN_USER}:${ADMIN_PASS}" | chpasswd || return 1; fi
    fi
    if ! id -nG "$ADMIN_USER" 2>/dev/null | grep -qw sudo; then
        run usermod -aG sudo "$ADMIN_USER" || return 1
        record_action "group_added $ADMIN_USER sudo"
    fi
    ((DRY_RUN)) && ! id "$ADMIN_USER" &>/dev/null && { ok "[dry-run] $ADMIN_USER"; return 0; }

    local home old ak
    home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    old=$(stat -c %a "$home")
    [[ $old != 700 ]] && record_action "home_mode $home $old"
    run chmod 700 "$home"
    ak="$home/.ssh/authorized_keys"
    if [[ $KEY_SOURCE != skip ]]; then
        [[ -d $home/.ssh ]] || record_created "$home/.ssh"
        backup "$ak"
        run install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
    fi
    case $KEY_SOURCE in
        root)
            if [[ -s /root/.ssh/authorized_keys ]]; then
                if ((DRY_RUN)); then echo "[dry-run] append /root/.ssh/authorized_keys -> $ak"
                else cat /root/.ssh/authorized_keys >> "$ak"; sort -u -o "$ak" "$ak"; fi
            else
                warn "$(tr_ '/root/.ssh/authorized_keys пуст или отсутствует' '/root/.ssh/authorized_keys is empty or missing')"; return 2
            fi ;;
        paste)
            local key
            local -a keys=()
            [[ -z $PUBKEY ]] || keys+=("$PUBKEY")
            if [[ -n $PUBKEYS ]]; then
                local -a extra_keys
                IFS='|' read -r -a extra_keys <<< "$PUBKEYS"
                keys+=("${extra_keys[@]}")
            fi
            for key in "${keys[@]}"; do
                valid_pubkey "$key" || return 1
                if ((DRY_RUN)); then echo "[dry-run] append public key -> $ak"
                else grep -qxF -- "$key" "$ak" 2>/dev/null || printf '%s\n' "$key" >> "$ak" || return 1; fi
            done ;;
    esac
    if [[ -f $ak ]] && ! ((DRY_RUN)); then chown "$ADMIN_USER:$ADMIN_USER" "$ak"; chmod 600 "$ak"; fi
    ok "$ADMIN_USER: sudo, $home 700"
}

mod_logging() {
    say "rsyslog + journald"
    apt_install rsyslog logrotate || return 1
    run systemctl enable --now rsyslog
    write_file /etc/systemd/journald.conf.d/50-linux-harden.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
EOF
    if [[ ! -d /var/log/journal ]] && ! ((DRY_RUN)); then
        record_created /var/log/journal
        mkdir -p /var/log/journal
    fi
    run systemctl restart systemd-journald
}

mod_firewall() {
    say "UFW"
    command -v ufw >/dev/null || apt_install ufw || return 1
    local f p rc=0 ports=()
    for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ufw/after.rules /etc/ufw/after6.rules /etc/ufw/ufw.conf /etc/default/ufw; do
        backup "$f"
    done
    ufw_active || record_action "ufw_was_inactive"
    run ufw default deny incoming || return 1
    run ufw default allow outgoing || return 1
    run ufw allow "${SSH_PORT}/tcp" comment 'SSH' || return 1
    if [[ $SSH_PORT != "$CURRENT_SSH_PORT" ]]; then
        # keep the old port open so the current session survives; remove after testing
        run ufw allow "${CURRENT_SSH_PORT}/tcp" comment 'SSH old - remove after check' || return 1
        warn "$(tr_ "Старый порт $CURRENT_SSH_PORT оставлен открытым. После проверки: ufw delete allow $CURRENT_SSH_PORT/tcp" \
                    "Old port $CURRENT_SSH_PORT left open. After testing: ufw delete allow $CURRENT_SSH_PORT/tcp")"
        rc=2
    fi
    IFS=',' read -ra ports <<< "$EXTRA_PORTS"
    for p in "${ports[@]}"; do p=${p// /}; if [[ -n $p ]]; then run ufw allow "$p" || return 1; fi; done
    run ufw --force enable || return 1
    run ufw status verbose || return 1
    if ((HAS_DOCKER)) && ! has docker; then
        warn "$(tr_ 'Docker найден: опубликованные порты контейнеров обходят UFW. Запустите модуль docker.' \
                    'Docker found: published container ports bypass UFW. Run the docker module.')"
        rc=2
    fi
    return $rc
}

mod_docker() {
    say "Docker + UFW ($DOCKER_MODE)"
    case $DOCKER_MODE in
        skip)       ok "$(tr_ 'пропущено' 'skipped')"; return 0 ;;
        ufw-docker) docker_ufw ;;
        localhost)  docker_localhost ;;
    esac
}

# Same approach as github.com/chaifeng/ufw-docker: filter forwarded traffic in
# DOCKER-USER (processed before Docker's own rules) through UFW route rules.
docker_ufw() {
    local ar=/etc/ufw/after.rules rc=0 p port proto list=()
    command -v ufw >/dev/null || ((DRY_RUN)) || { err "$(tr_ 'ufw не установлен — включите модуль firewall' 'ufw is not installed — enable the firewall module')"; return 1; }
    if ! ((DRY_RUN)) && ! ufw_active; then
        err "$(tr_ 'UFW не активен — включите модуль firewall' 'UFW is inactive — enable the firewall module')"; return 1
    fi
    ((HAS_DOCKER)) || { warn "$(tr_ 'Docker не найден — правила добавлены заранее' 'Docker not found — rules added in advance')"; rc=2; }
    backup "$ar"; backup /etc/ufw/user.rules; backup /etc/ufw/user6.rules
    if grep -q '^# BEGIN UFW AND DOCKER' "$ar" 2>/dev/null; then
        ok "$(tr_ 'правила уже есть в' 'rules already present in') $ar"
    elif ((DRY_RUN)); then
        echo "[dry-run] append DOCKER-USER block to $ar"
    else
        cat >> "$ar" <<'EOF'

# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
EOF
        record_action "docker_ufw_rules"
    fi
    run ufw reload || return 1

    IFS=',' read -ra list <<< "$DOCKER_PORTS"
    for p in "${list[@]}"; do
        p=${p// /}; [[ -z $p ]] && continue
        port=${p%%/*}; proto=""
        [[ $p == */* ]] && proto=${p#*/}
        if [[ -n $proto ]]; then run ufw route allow proto "$proto" from any to any port "$port"
        else run ufw route allow from any to any port "$port"; fi
    done
    ok "$(tr_ 'Проверка' 'Check'): iptables -L DOCKER-USER -n ; ufw status (Anywhere on FORWARD)"
    warn "$(tr_ 'Правила покрывают только IPv4. Если в Docker включён IPv6, настройте after6.rules отдельно.' \
                'Rules cover IPv4 only. If Docker IPv6 is enabled, handle after6.rules separately.')"
    return $rc
}

docker_localhost() {
    local dj=/etc/docker/daemon.json tmp
    ((HAS_DOCKER)) || { warn "$(tr_ 'Docker не установлен — пропуск' 'Docker is not installed — skipped')"; return 2; }
    apt_install jq || return 1
    backup "$dj"
    if ((DRY_RUN)); then
        echo '[dry-run] set "ip": "127.0.0.1" in '"$dj"
    else
        mkdir -p /etc/docker
        tmp=$(mktemp)
        if [[ -s $dj ]]; then
            jq '. + {"ip": "127.0.0.1"}' "$dj" > "$tmp" \
                || { rm -f "$tmp"; err "$dj: $(tr_ 'некорректный JSON' 'invalid JSON')"; return 1; }
        else
            echo '{"ip": "127.0.0.1"}' | jq . > "$tmp"
        fi
        install -m 644 "$tmp" "$dj"; rm -f "$tmp"
        record_action "docker_daemon_changed"
    fi
    warn "$(tr_ 'Чтобы опубликовать порт наружу, укажите адрес явно: -p 0.0.0.0:80:80 — такой порт снова будет в обход UFW.' \
                'To publish a port publicly, set it explicitly: -p 0.0.0.0:80:80 — such a port bypasses UFW again.')"
    if [[ $DOCKER_RESTART == yes ]]; then
        run systemctl restart docker || return 1
        warn "$(tr_ 'Пересоздайте контейнеры, чтобы они получили новую привязку портов' 'Recreate containers so they pick up the new port binding')"
    else
        warn "$(tr_ 'Применится после: systemctl restart docker и пересоздания контейнеров' 'Applies after: systemctl restart docker and recreating containers')"
        return 2
    fi
}

mod_ssh() {
    say "SSH"
    local main=/etc/ssh/sshd_config dropin=/etc/ssh/sshd_config.d/00-linux-harden.conf rc=0 home
    local passauth=$SSH_PASSAUTH root=$SSH_ROOT

    # lockout guard: keys must exist before passwords are switched off
    if [[ $passauth == no ]]; then
        local keys_ok=0
        if id "$ADMIN_USER" &>/dev/null; then
            home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
            [[ -s $home/.ssh/authorized_keys ]] && keys_ok=1
        fi
        [[ $root != no && $SSH_ALLOWUSERS != yes && -s /root/.ssh/authorized_keys ]] && keys_ok=1
        ((DRY_RUN)) && [[ $KEY_SOURCE != skip ]] && keys_ok=1
        if ((keys_ok == 0)); then
            warn "$(tr_ 'Ключи не найдены — вход по паролю ОСТАВЛЕН включённым' 'No keys found — password login is LEFT enabled')"
            passauth=yes; rc=2
        fi
    fi
    # lockout guard: someone must be able to sudo before root login is denied
    if [[ $root == no ]] && ! ((DRY_RUN)) && ! { id "$ADMIN_USER" &>/dev/null && id -nG "$ADMIN_USER" | grep -qw sudo; }; then
        warn "$(tr_ 'Нет пользователя с sudo — root оставлен с входом по ключу' 'No sudo user — root left with key-only login')"
        root=prohibit-password; rc=2
    fi

    backup "$main"
    if ! grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main"; then
        if ((DRY_RUN)); then echo "[dry-run] add Include to $main"
        else sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$main"; fi
    fi
    # 00- prefix: sshd uses the FIRST value it sees, so this file beats
    # 50-cloud-init.conf (which often sets PasswordAuthentication yes)
    write_file "$dropin" 600 <<EOF
# linux-harden ${STAMP}
Port ${SSH_PORT}
PermitRootLogin ${root}
PasswordAuthentication ${passauth}
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries ${SSH_MAXAUTH}
LoginGraceTime 30
ClientAliveInterval ${SSH_ALIVE}
ClientAliveCountMax 2
X11Forwarding no
$( [[ $SSH_ALLOWUSERS == yes ]] && echo "AllowUsers ${ADMIN_USER}" )
EOF
    if ! ((DRY_RUN)); then
        mkdir -p /run/sshd
        if ! sshd -t 2>&1 | tee -a "$LOG_FILE"; then
            err "$(tr_ 'Ошибка конфигурации sshd — изменения откатаны' 'sshd config error — changes rolled back')"
            if [[ -f ${BACKUP_DIR}${dropin} ]]; then cp -a "${BACKUP_DIR}${dropin}" "$dropin"; else rm -f "$dropin"; fi
            [[ -f ${BACKUP_DIR}${main} ]] && cp -a "${BACKUP_DIR}${main}" "$main"
            return 1
        fi
    fi
    restart_ssh || return 1
    ok "sshd: Port $SSH_PORT, PermitRootLogin $root, PasswordAuthentication $passauth"
    return $rc
}

mod_fail2ban() {
    say "Fail2ban"
    apt_install fail2ban python3-systemd || return 1
    # vps-audit reads [sshd] enabled/port from jail.local
    write_file /etc/fail2ban/jail.local <<EOF
# linux-harden ${STAMP}
[DEFAULT]
bantime  = ${F2B_BANTIME}
findtime = 10m
maxretry = ${F2B_MAXRETRY}
bantime.increment = true
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ${SSH_PORT}
backend = systemd
EOF
    if ! ((DRY_RUN)) && ! fail2ban-client -t >>"$LOG_FILE" 2>&1; then
        err "fail2ban-client -t"; return 1
    fi
    run systemctl enable fail2ban || return 1
    run systemctl restart fail2ban || return 1
    ((DRY_RUN)) || { sleep 2; fail2ban-client status sshd; }
}

mod_autoupd() {
    say "$(tr_ 'Автообновления' 'Unattended upgrades')"
    apt_install unattended-upgrades apt-listchanges || return 1
    write_file /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    if [[ $AUTO_REBOOT == yes ]]; then
        write_file /etc/apt/apt.conf.d/52linux-harden-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
    fi
    run systemctl enable --now unattended-upgrades || return 1
}

mod_pwquality() {
    say "$(tr_ 'Политика паролей' 'Password policy')"
    apt_install libpam-pwquality || return 1
    set_kv /etc/security/pwquality.conf minlen "$PW_MINLEN"
    set_kv /etc/security/pwquality.conf minclass 3
    set_kv /etc/security/pwquality.conf maxrepeat 3
    ok "minlen = $PW_MINLEN"
}

mod_sudolog() {
    say "$(tr_ 'Логирование sudo' 'Sudo logging')"
    # vps-audit greps only /etc/sudoers, so the line goes there (validated)
    if grep -qE '^Defaults.*logfile' /etc/sudoers; then ok "$(tr_ 'уже настроено' 'already set')"; return 0; fi
    if ((DRY_RUN)); then echo '[dry-run] append to /etc/sudoers: Defaults logfile="/var/log/sudo.log"'; return 0; fi
    local tmp; tmp=$(mktemp)
    cp /etc/sudoers "$tmp"
    printf '\n# linux-harden\nDefaults logfile="/var/log/sudo.log"\nDefaults use_pty\n' >> "$tmp"
    if visudo -cf "$tmp" >>"$LOG_FILE" 2>&1; then
        backup /etc/sudoers
        install -m 440 -o root -g root "$tmp" /etc/sudoers
        rm -f "$tmp"
        write_file /etc/logrotate.d/sudo-log <<'EOF'
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    create 600 root root
}
EOF
        ok "/var/log/sudo.log"
    else
        rm -f "$tmp"; err "visudo"; return 1
    fi
}

mod_auditd() {
    say "auditd"
    apt_install auditd audispd-plugins || return 1
    write_file /etc/audit/rules.d/50-linux-harden.rules 640 <<'EOF'
## linux-harden
-w /etc/passwd  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config   -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/sudo.log -p wa -k sudolog
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmds
EOF
    run systemctl enable --now auditd || { warn "$(tr_ 'auditd не запускается (контейнер LXC/OpenVZ?)' 'auditd fails to start (LXC/OpenVZ container?)')"; return 2; }
    run augenrules --load || return 2
    ok "$(tr_ 'Поиск событий' 'Search events'): ausearch -k identity ; ausearch -k root_cmds"
}

mod_sysctl() {
    say "sysctl"
    write_file /etc/sysctl.d/99-linux-harden.conf <<'EOF'
# linux-harden
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
    run sysctl --system >/dev/null || return 2
}

mod_services() {
    say "$(tr_ 'Службы' 'Services')"
    local s
    for s in $DISABLE_SERVICES; do
        record_action "service_disabled $s"
        run systemctl disable --now "$s"
    done
    ok "$(tr_ 'Запущено служб' 'Running services'): $(systemctl list-units --type=service --state=running --no-legend | wc -l)"
}

mod_aide() {
    say "AIDE"
    apt_install aide aide-common || return 1
    echo "$(tr_ 'Создание базы AIDE, это может занять несколько минут...' 'Building the AIDE database, this may take a few minutes...')"
    run aideinit -y -f || return 1
    ok "$(tr_ 'Проверка' 'Check'): aide --check --config /etc/aide/aide.conf"
}

mod_vpsaudit() {
    say "vps-audit"
    ((DRY_RUN)) && { echo "[dry-run] curl $VPS_AUDIT_URL && bash vps-audit.sh"; return 0; }
    command -v curl >/dev/null || apt_install curl
    mkdir -p /root/vps-audit && cd /root/vps-audit || return 1
    warn "Executing third-party code as root from an unpinned URL; review the source before enabling this module."
    curl -fsSL "$VPS_AUDIT_URL" -o vps-audit.sh || return 1
    bash vps-audit.sh | tee -a "$LOG_FILE"
    cd - >/dev/null || true
}

# ================================================================= rollback
meta_get() { grep -m1 "^$2=" "$1/.meta" 2>/dev/null | cut -d= -f2-; }

list_backups() {
    local d dirs=()
    mapfile -t dirs < <(ls -1dt "$BACKUP_ROOT"/linux-harden-backup-* 2>/dev/null)
    for d in "${dirs[@]}"; do
        [[ -f $d/.meta ]] || continue
        printf '%s  %s  [%s]%s\n' "$d" "$(meta_get "$d" DATE)" "$(meta_get "$d" MODULES)" \
            "$([[ -f $d/.rolledback ]] && echo "  ROLLED BACK")"
    done
}

do_rollback() {
    local dir=$1 d f a b c n_files n_created users=() pkgs=() items=() dirs=()
    local ufw_off=0 docker_rules=0 docker_daemon=0 ssh_touched=0

    if [[ -z $dir ]]; then
        mapfile -t dirs < <(ls -1dt "$BACKUP_ROOT"/linux-harden-backup-* 2>/dev/null)
        for d in "${dirs[@]}"; do [[ -f $d/.meta ]] && items+=("$d"); done
        ((${#items[@]})) || die "$(tr_ 'Бэкапы не найдены' 'No backups found') ($BACKUP_ROOT/linux-harden-backup-*)"
        if ((USE_TUI)) && ((${#items[@]} > 1)); then
            local menu=()
            for d in "${items[@]}"; do
                menu+=("$d" "$(meta_get "$d" DATE)$([[ -f $d/.rolledback ]] && echo ' (rolled back)')")
            done
            dir=$(ui_menu "Rollback" "$(tr_ 'Какой запуск откатить?' 'Which run to undo?')" "${menu[@]}") || abort
        else
            dir=${items[0]}
        fi
    fi
    dir=${dir%/}
    [[ -f $dir/.meta ]] || die "$dir: $(tr_ 'не бэкап linux-harden' 'not a linux-harden backup')"

    n_files=$(find "$dir" -mindepth 2 \( -type f -o -type l \) | wc -l)
    n_created=$(grep -c . "$dir/.created" 2>/dev/null)
    local info
    info="$(tr_ 'Откат запуска' 'Undo run'): $(meta_get "$dir" DATE)
$(tr_ 'Модули' 'Modules'): $(meta_get "$dir" MODULES)
$(tr_ 'Восстановить файлов' 'Files to restore'): $n_files
$(tr_ 'Удалить созданных файлов' 'Created files to remove'): ${n_created:-0}
$(tr_ 'Порт SSH вернётся на' 'SSH port returns to'): $(meta_get "$dir" SSH_PORT_BEFORE)

$(tr_ 'Не откатывается: обновления пакетов (apt upgrade).' 'Not reverted: package upgrades (apt upgrade).')"
    [[ -f $dir/.rolledback ]] && info+=$'\n\n'"$(tr_ 'ВНИМАНИЕ: этот запуск уже откатывали.' 'WARNING: this run was already rolled back.')"
    if ((USE_TUI)); then ui_yesno "Rollback" "$info

$(tr_ 'Продолжить?' 'Continue?')" || abort
    else
        printf '%s\n\n' "$info"
        ask "$(tr_ 'Продолжить откат?' 'Proceed with rollback?')" || abort
    fi
    ((USE_TUI)) && clear
    say "Rollback $dir"
    [[ -n $(find "$dir" -mindepth 2 -path '*/etc/ssh/*' -print -quit) ]] && ssh_touched=1
    grep -q '^/etc/ssh/' "$dir/.created" 2>/dev/null && ssh_touched=1

    say "$(tr_ 'Восстановление файлов' 'Restoring files')"
    while IFS= read -r -d '' f; do
        run cp -a "$f" "${f#"$dir"}"
    done < <(find "$dir" -mindepth 2 \( -type f -o -type l \) -print0)

    say "$(tr_ 'Удаление созданных файлов' 'Removing created files')"
    if [[ -s $dir/.created ]]; then
        while IFS= read -r f; do
            [[ -z $f ]] && continue
            if [[ -d $f && ! -L $f ]]; then run rmdir --ignore-fail-on-non-empty "$f"
            elif [[ -e $f || -L $f ]]; then run rm -f "$f"; fi
        done < <(tac "$dir/.created")
    fi

    say "$(tr_ 'Отмена действий' 'Undoing actions')"
    if [[ -s $dir/.actions ]]; then
        while read -r a b c; do
            case $a in
                service_disabled)      run systemctl enable --now "$b" ;;
                group_added)           id "$b" &>/dev/null && run gpasswd -d "$b" "$c" ;;
                home_mode)             [[ -d $b ]] && run chmod "$c" "$b" ;;
                timezone)              run timedatectl set-timezone "$b" ;;
                ufw_was_inactive)      ufw_off=1 ;;
                docker_ufw_rules)      docker_rules=1 ;;
                docker_daemon_changed) docker_daemon=1 ;;
                user_created)          users+=("$b") ;;
                pkg_installed)         pkgs+=("$b") ;;
            esac
        done < <(tac "$dir/.actions")
    fi

    say "$(tr_ 'Перезапуск служб' 'Reloading services')"
    if command -v ufw >/dev/null; then
        if ((ufw_off)); then run ufw --force disable
        elif ufw_active; then run ufw reload; fi
    fi
    if ((docker_rules)); then
        warn "Docker firewall rollback requires verification of DOCKER-USER rules; no chain is flushed automatically."
    fi
    ((docker_daemon)) && warn "$(tr_ 'daemon.json восстановлен. Примените: systemctl restart docker' 'daemon.json restored. Apply: systemctl restart docker')"
    if ((ssh_touched)); then
        mkdir -p /run/sshd
        if ((DRY_RUN)) || sshd -t 2>&1 | tee -a "$LOG_FILE"; then
            restart_ssh
        else
            err "$(tr_ 'sshd -t: ошибка конфигурации — SSH НЕ перезапущен, проверьте вручную' 'sshd -t failed — SSH NOT restarted, check manually')"
        fi
    fi
    systemctl is-active --quiet fail2ban 2>/dev/null && run systemctl restart fail2ban
    systemctl is-active --quiet systemd-journald 2>/dev/null && run systemctl restart systemd-journald
    command -v augenrules >/dev/null && systemctl is-active --quiet auditd 2>/dev/null && run augenrules --load
    run sysctl --system >/dev/null
    warn "$(tr_ 'Удалённые параметры sysctl сохранят значения до перезагрузки' 'Removed sysctl keys keep their values until reboot')"

    for u in "${users[@]}"; do
        id "$u" &>/dev/null || continue
        if [[ $u == "${SUDO_USER:-}" ]]; then
            warn "$(tr_ "Пользователь $u не удалён — вы вошли под ним" "User $u kept — you are logged in as it")"; continue
        fi
        if ask "$(tr_ "Удалить пользователя $u (создан скриптом) вместе с домашним каталогом?" "Delete user $u (created by the script) with its home?")" defaultno; then
            run deluser --remove-home "$u"
        else
            warn "$(tr_ "Пользователь $u оставлен" "User $u kept")"
        fi
    done
    if ((${#pkgs[@]})); then
        if ask "$(tr_ "Удалить пакеты, установленные скриптом: ${pkgs[*]}?" "Purge packages installed by the script: ${pkgs[*]}?")" defaultno; then
            run env DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "${pkgs[@]}"
            warn "$(tr_ 'Зависимости остались, проверьте: apt-get autoremove --purge' 'Dependencies remain, review: apt-get autoremove --purge')"
        else
            warn "$(tr_ 'Пакеты оставлены' 'Packages kept'): apt-get purge ${pkgs[*]}"
        fi
    fi

    ((DRY_RUN)) || date '+%F %T' > "$dir/.rolledback"
    ok "$(tr_ 'Откат завершён' 'Rollback finished'). $(tr_ 'Лог' 'Log'): $LOG_FILE"
    ((ssh_touched)) && warn "$(tr_ "Проверьте вход в НОВОЙ сессии: ssh -p $(meta_get "$dir" SSH_PORT_BEFORE) user@host" \
                                   "Test login in a NEW session: ssh -p $(meta_get "$dir" SSH_PORT_BEFORE) user@host")"
}

# ================================================================= main
usage() { awk 'NR>2 && /^# =====/{exit} NR>2{sub(/^# ?/,""); print}' "$SELF"; exit 0; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --lang)          UI_LANG=${2:-}; shift 2 ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -y|--yes)        ASSUME_YES=1; shift ;;
        --config)        MODE=config; CONFIG_FILE=${2:-}; shift 2 ;;
        --save-config)   SAVE_CONFIG=${2:-}; shift 2 ;;
        --rollback)      MODE=rollback; if [[ ${2:-} && ${2:-} != -* ]]; then ROLLBACK_DIR=$2; shift; fi; shift ;;
        --list-backups)  MODE=list; shift ;;
        --print-config)  MODE=example; shift ;;
        -h|--help)       usage ;;
        *) echo "Unknown option: $1 (see --help)"; exit 1 ;;
    esac
done

[[ $MODE == example ]] && { example_config; exit 0; }
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 / Запустите от root: sudo $0"; exit 1; }
[[ $MODE == list ]] && { list_backups; exit 0; }
grep -qiE '^(ID|ID_LIKE)=.*(debian|ubuntu)' /etc/os-release 2>/dev/null \
    || { echo "Only Debian/Ubuntu are supported / Поддерживаются только Debian/Ubuntu"; exit 1; }

# Cyrillic in whiptail needs a UTF-8 locale (fresh VPS often has POSIX)
[[ "$(locale charmap 2>/dev/null)" == "UTF-8" ]] || export LANG=C.UTF-8 LC_ALL=C.UTF-8
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"

CURRENT_SSH_PORT=$(mkdir -p /run/sshd; sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}
TIMEZONE=$(timedatectl show -p Timezone --value 2>/dev/null); TIMEZONE=${TIMEZONE:-UTC}
OS_NAME=$(. /etc/os-release; echo "$PRETTY_NAME")
if command -v docker >/dev/null || systemctl cat docker.service &>/dev/null; then HAS_DOCKER=1; fi

case $MODE in
    rollback)
        if [[ -t 0 && -t 1 ]] && ! ((ASSUME_YES)) && command -v whiptail >/dev/null; then USE_TUI=1; size_ui; fi
        choose_lang
        do_rollback "$ROLLBACK_DIR"
        exit 0 ;;
    config)
        [[ -n $CONFIG_FILE ]] || die "--config FILE"
        load_config "$CONFIG_FILE"
        choose_lang ;;
    interactive)
        [[ -t 0 && -t 1 ]] || die "No terminal: use --config FILE --yes"
        USE_TUI=1
        ensure_whiptail; size_ui; choose_lang
        collect_interactive ;;
esac

[[ -z $SSH_PORT ]] && SSH_PORT=$CURRENT_SSH_PORT
validate_params

SUMMARY=$(build_summary)
if ((USE_TUI)); then
    ((ASSUME_YES)) || ui_yesno "$(tr_ 'Подтверждение' 'Confirm')" "${SUMMARY}

$(tr_ 'Запустить?' 'Run now?')" || abort
    clear
else
    printf '%s\n' "$SUMMARY"
    if ! ((ASSUME_YES)); then
        [[ -t 0 ]] || die "$(tr_ 'Нет терминала для подтверждения: добавьте --yes' 'No terminal to confirm: add --yes')"
        ask "$(tr_ 'Запустить?' 'Run now?')" || abort
    fi
fi
[[ -n $SAVE_CONFIG ]] && save_config "$SAVE_CONFIG"

if ! ((DRY_RUN)); then
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    {
        echo "VERSION=$VERSION"
        echo "DATE=$(date '+%F %T')"
        echo "MODULES=$MODULES"
        echo "SSH_PORT_BEFORE=$CURRENT_SSH_PORT"
        echo "SSH_PORT_AFTER=$SSH_PORT"
    } > "$BACKUP_DIR/.meta"
    : > "$BACKUP_DIR/.created"; : > "$BACKUP_DIR/.actions"
fi

say "linux-harden v$VERSION — $( ((DRY_RUN)) && echo DRY-RUN || echo APPLY ) — $OS_NAME"
for m in $ALL_MODULES; do
    has "$m" || continue
    "mod_$m"; rc=$?
    case $rc in
        0) result OK   "$m" ;;
        2) result WARN "$m" ;;
        *) result FAIL "$m"; err "$m" ;;
    esac
done

# ---------------------------------------------------------------- report
report=""
for r in "${RESULTS[@]}"; do
    IFS='|' read -r st mod <<< "$r"
    report+=$(printf '%-5s %s' "$st" "$mod")$'\n'
done
host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
final="${report}
$(tr_ 'Лог' 'Log'): $LOG_FILE"
((DRY_RUN)) || final+="
$(tr_ 'Откат' 'Undo'): $SELF --rollback $BACKUP_DIR"
if has ssh; then
    final+="

$(tr_ 'ПРОВЕРЬТЕ ВХОД В НОВОМ ТЕРМИНАЛЕ, не закрывая этот:' 'TEST LOGIN IN A NEW TERMINAL before closing this one:')
  ssh -p ${SSH_PORT} ${ADMIN_USER}@${host_ip}"
fi
[[ -f /var/run/reboot-required ]] && final+="

$(tr_ 'Нужна перезагрузка: reboot' 'Reboot required: reboot')"

log "$report"
overall_rc=0
for r in "${RESULTS[@]}"; do
    case $r in FAIL\|*) overall_rc=1 ;; esac
done
echo; printf '%s\n' "$final"
((USE_TUI)) && ui_msg "$(tr_ 'Готово' 'Done')" "$final"
exit "$overall_rc"