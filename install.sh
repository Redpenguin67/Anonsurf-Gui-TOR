#!/bin/bash

#===============================================================================
#   AnonSurf GUI Control Panel - Installer v3.3
#   
#   CARATTERISTICHE:
#   - Installazione COMPLETA in /opt/anonsurf-gui
#   - Integrazione nel MENU DI SISTEMA (due voci)
#   - Ambiente Python isolato con venv
#   - Link simbolici in /usr/local/bin
#   - Icona personalizzata
#
#   Compatibile con: Kali Linux / Parrot OS / LMDE / Debian / Ubuntu
#===============================================================================

VERSION="3.3"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Directory di installazione
INSTALL_DIR="/opt/anonsurf-gui"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.ini"
VENV_DIR="$INSTALL_DIR/venv"
LOG_FILE="$SCRIPT_DIR/install.log"

# File del menu
DESKTOP_DIR="/usr/share/applications"
DESKTOP_FILE_FULL="$DESKTOP_DIR/anonsurf-gui.desktop"
DESKTOP_FILE_MINI="$DESKTOP_DIR/anonsurf-gui-mini.desktop"
ICON_DIR="/usr/share/icons/hicolor/128x128/apps"
ICON_FILE="$ICON_DIR/anonsurf-gui.png"

# Pacchetti predefiniti
DEFAULT_SYSTEM_PACKAGES="python3 python3-venv python3-tk git tor torsocks curl"
DEFAULT_PYTHON_PACKAGES="requests"
DEFAULT_ANONSURF_REPO="https://github.com/Und3rf10w/kali-anonsurf.git"

# Funzione per leggere config.ini
read_config() {
    local section="$1"
    local key="$2"
    local default="$3"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "$default"
        return
    fi
    
    local in_section=0
    local value=""
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        
        if [[ "$line" =~ ^\[([^\]]+)\]$ ]]; then
            if [[ "${BASH_REMATCH[1]}" == "$section" ]]; then
                in_section=1
            else
                in_section=0
            fi
            continue
        fi
        
        if [[ $in_section -eq 1 ]] && [[ "$line" =~ ^${key}[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            value="${BASH_REMATCH[1]}"
            break
        fi
    done < "$CONFIG_FILE"
    
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# Funzione log
log_msg() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "INFO")  echo -e "  ${GREEN}✓${NC} $message" ;;
        "WARN")  echo -e "  ${YELLOW}!${NC} $message" ;;
        "ERROR") echo -e "  ${RED}✗${NC} $message" ;;
        "STEP")  echo -e "${CYAN}$message${NC}" ;;
        *)       echo "  $message" ;;
    esac
}

# Verifica root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERRORE] Questo script deve essere eseguito come root${NC}"
        echo "Usa: sudo ./install.sh"
        exit 1
    fi
}

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║        AnonSurf GUI Control Panel v3.3 — WireGuard & Bridge Edition           ║"
    echo "║                                                                    ║"
    echo "║  • Installazione in /opt/anonsurf-gui                             ║"
    echo "║  • Integrazione nel MENU DI SISTEMA                               ║"
    echo "║  • Due voci: GUI Completa + GUI Mini                              ║"
    echo "║  • Ambiente Python isolato (venv)                                 ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Crea icona PNG embedded (base64)
create_icon() {
    log_msg "INFO" "Creazione icona..."
    
    mkdir -p "$ICON_DIR"
    
    # Icona 128x128 - Scudo con Tor/Onion stilizzato
    cat > /tmp/anonsurf-gui-icon.svg << 'SVGICON'
<?xml version="1.0" encoding="UTF-8"?>
<svg width="128" height="128" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shield" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#7B68EE"/>
      <stop offset="100%" style="stop-color:#4B0082"/>
    </linearGradient>
    <linearGradient id="onion" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#9370DB"/>
      <stop offset="100%" style="stop-color:#6A0DAD"/>
    </linearGradient>
  </defs>
  <!-- Scudo -->
  <path d="M64 8 L112 28 L112 64 C112 96 88 116 64 120 C40 116 16 96 16 64 L16 28 Z" 
        fill="url(#shield)" stroke="#2E0854" stroke-width="3"/>
  <!-- Cerchi concentrici (onion) -->
  <circle cx="64" cy="60" r="36" fill="none" stroke="url(#onion)" stroke-width="6" opacity="0.4"/>
  <circle cx="64" cy="60" r="26" fill="none" stroke="url(#onion)" stroke-width="6" opacity="0.6"/>
  <circle cx="64" cy="60" r="16" fill="none" stroke="url(#onion)" stroke-width="6" opacity="0.8"/>
  <circle cx="64" cy="60" r="6" fill="#9370DB"/>
  <!-- Testo A -->
  <text x="64" y="100" text-anchor="middle" font-family="Arial Black, sans-serif" 
        font-size="18" font-weight="bold" fill="#E6E6FA">ANON</text>
</svg>
SVGICON

    # Converti SVG in PNG usando Python
    python3 << 'PYICON'
import base64
# Icona PNG 128x128 pre-generata (viola/purple theme)
icon_b64 = """
iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAK
T2lDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjanVNnVFPpFj333vRCS4iAlEtvUhUIIFJCi4AU
kSYqIQkQSoghodkVUcERRUUEG8igiAOOjoCMFVEsDIoK2AfkIaKOg6OIisr74Xuja9a89+bN/rXX
Pues852zzwfACAyWSDNRNYAMqUIeEeCDx8TG4eQuQIEKJHAAEAizZCFz/SMBAPh+PDwrIsAHvgAB
eNMLCADATZvAMByH/w/qQplcAYCEAcB0kThLCIAUAEB6jkKmAEBGAYCdmCZTAKAEAGDLY2LjAFAt
AGAnf+bTAICd+Jl7AQBblCEVAaCRACATZYhEAGg7AKzPVopFAFgwABRmS8Q5ANgtADBJV2ZIALC3
AMDOEAuyAAgMADBRiIUpAAR7AGDIIyN4AISZABRG8lc88SuuEOcqAAB4mbI8uSQ5RYFbCC1xB1dX
Lh4ozkkXKxQ2YQJhmkAuwnmZGTKBNA/g88wAAKCRFRHgg/P9eM4Ors7ONo62,, l8t8/V
5dYFteli6AAAAAElFTkSuQmCC
"""
# Scriviamo un'icona semplice ma funzionante
import struct
import zlib

def create_simple_png():
    width, height = 128, 128
    
    # Crea immagine viola con gradiente
    pixels = []
    for y in range(height):
        row = []
        for x in range(width):
            # Calcola se siamo dentro lo scudo
            cx, cy = 64, 64
            # Forma scudo semplificata
            in_shield = False
            if y < 100:
                shield_width = 48 - abs(y - 40) * 0.4
                if abs(x - cx) < shield_width and y > 10:
                    in_shield = True
            
            if in_shield:
                # Gradiente viola
                r = int(75 + (y / height) * 30)
                g = int(0 + (y / height) * 50)
                b = int(130 + (y / height) * 30)
                a = 255
            else:
                r, g, b, a = 0, 0, 0, 0
            
            row.extend([r, g, b, a])
        pixels.append(bytes([0] + row))  # filter byte + row
    
    raw = b''.join(pixels)
    
    def png_chunk(chunk_type, data):
        chunk = chunk_type + data
        return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)
    
    png = b'\x89PNG\r\n\x1a\n'
    png += png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    png += png_chunk(b'IDAT', zlib.compress(raw, 9))
    png += png_chunk(b'IEND', b'')
    
    return png

with open('/usr/share/icons/hicolor/128x128/apps/anonsurf-gui.png', 'wb') as f:
    f.write(create_simple_png())
PYICON

    # Fallback: usa un'icona di sistema se disponibile
    if [[ ! -f "$ICON_FILE" ]] || [[ ! -s "$ICON_FILE" ]]; then
        # Cerca icone esistenti
        for icon in /usr/share/icons/hicolor/128x128/apps/preferences-system-network.png \
                    /usr/share/icons/Papirus/128x128/apps/network-vpn.png \
                    /usr/share/icons/gnome/256x256/status/network-vpn.png; do
            if [[ -f "$icon" ]]; then
                cp "$icon" "$ICON_FILE" 2>/dev/null
                break
            fi
        done
    fi
    
    # Se ancora non c'è, crea un placeholder
    if [[ ! -f "$ICON_FILE" ]]; then
        # Usa ImageMagick se disponibile
        if command -v convert &>/dev/null; then
            convert -size 128x128 xc:'#7B68EE' -fill '#4B0082' \
                -draw "polygon 64,8 112,28 112,64 64,120 16,64 16,28" \
                -fill white -pointsize 24 -gravity center -annotate 0 "AS" \
                "$ICON_FILE" 2>/dev/null || true
        fi
    fi
    
    log_msg "INFO" "Icona creata"
}

# Installa dipendenze di sistema
install_system_deps() {
    log_msg "STEP" "[FASE 1/6] Installazione dipendenze di sistema..."
    echo ""

    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none

    # ── apt-get update con timeout esplicito ──────────────────────────
    # Senza timeout, apt-get update aspetta ogni repo non raggiungibile
    # per ~2 minuti ciascuno (timeout TCP). Con 15+ repo configurati
    # può bloccarsi per mezz'ora senza mostrare nulla (stderr su /dev/null).
    log_msg "INFO" "Aggiornamento lista pacchetti (timeout 60s)..."
    if timeout 60 apt-get update -qq >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "Lista pacchetti aggiornata"
    else
        log_msg "WARN" "apt-get update timeout/errore — uso lista esistente"
    fi

    # ── Lista pacchetti: separata manualmente per evitare bug regex ───
    # NON usare ${packages//tor/} perché corrompe "torsocks" -> "socks"
    local BASE_PKGS="python3 python3-venv python3-tk git curl"
    local TOR_PKGS="tor torsocks"

    log_msg "INFO" "Pacchetti base: $BASE_PKGS"
    log_msg "INFO" "Pacchetti Tor:  $TOR_PKGS"
    echo ""
    echo -e "  Installazione in corso..."

    # ── Blocca avvio automatico servizi durante apt install ───────────
    # Senza questo, postinst di tor esegue: systemctl start tor
    # che su alcuni sistemi aspetta network-online.target → blocco.
    printf '#!/bin/sh
exit 101
' > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d

    # ── Installa pacchetti base (timeout 180s) ────────────────────────
    if timeout 180 apt-get install -y $BASE_PKGS >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "Pacchetti base installati"
    else
        log_msg "WARN" "Pacchetti base: installazione parziale (vedi log)"
    fi

    # ── Installa tor e torsocks separatamente (timeout 120s) ──────────
    log_msg "INFO" "Installazione tor e torsocks..."
    if timeout 120 apt-get install -y --no-install-recommends $TOR_PKGS >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "tor e torsocks installati"
    else
        log_msg "WARN" "tor/torsocks: installazione parziale (vedi log)"
    fi

    # ── Ripristina avvio servizi ──────────────────────────────────────
    rm -f /usr/sbin/policy-rc.d

    # ── Abilita tor ma avvialo con timeout ────────────────────────────
    # systemctl start tor può bloccare ~90s se Tor non riesce a
    # raggiungere le directory authorities (blocco ISP/Cisco).
    systemctl enable tor >> "$LOG_FILE" 2>/dev/null || true
    log_msg "INFO" "Avvio tor (timeout 15s)..."
    timeout 15 systemctl start tor >> "$LOG_FILE" 2>/dev/null ||         log_msg "WARN" "Tor non avviato ora — si avvierà alla prima cascata"
    
    echo ""
    echo -e "  ${CYAN}Verifica dipendenze critiche:${NC}"
    
    local critical_ok=true
    
    if command -v python3 >/dev/null 2>&1; then
        local pyver=$(python3 --version 2>&1)
        echo -e "  ${GREEN}✓${NC} $pyver"
    else
        echo -e "  ${RED}✗${NC} Python3 NON INSTALLATO"
        critical_ok=false
    fi
    
    if python3 -c "import tkinter" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Tkinter OK"
    else
        echo -e "  ${RED}✗${NC} Tkinter NON DISPONIBILE"
        critical_ok=false
    fi
    
    if python3 -c "import venv" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} venv OK"
    else
        echo -e "  ${RED}✗${NC} venv NON DISPONIBILE"
        critical_ok=false
    fi
    
    if command -v git >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Git OK"
    else
        echo -e "  ${RED}✗${NC} Git NON INSTALLATO"
        critical_ok=false
    fi
    
    if command -v tor >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Tor OK"
    else
        echo -e "  ${YELLOW}!${NC} Tor non trovato (verrà installato con AnonSurf)"
    fi
    
    if ! $critical_ok; then
        echo ""
        log_msg "ERROR" "Dipendenze critiche mancanti. Impossibile continuare."
        echo -e "${YELLOW}Installa manualmente: sudo apt install $packages${NC}"
        exit 1
    fi
    
    echo ""
}

# Copia file in /opt
install_files() {
    log_msg "STEP" "[FASE 2/6] Installazione file in $INSTALL_DIR..."
    echo ""
    
    # Rimuovi installazione precedente
    if [[ -d "$INSTALL_DIR" ]]; then
        log_msg "INFO" "Rimozione installazione precedente..."
        rm -rf "$INSTALL_DIR"
    fi
    
    # Crea directory
    mkdir -p "$INSTALL_DIR"
    
    # Copia file
    cp "$SCRIPT_DIR/anonsurf_gui.py" "$INSTALL_DIR/" 2>/dev/null && \
        log_msg "INFO" "anonsurf_gui.py copiato"
    
    cp "$SCRIPT_DIR/anonsurf_gui_mini.py" "$INSTALL_DIR/" 2>/dev/null && \
        log_msg "INFO" "anonsurf_gui_mini.py copiato"
    
    cp "$SCRIPT_DIR/config.ini" "$INSTALL_DIR/" 2>/dev/null && \
        log_msg "INFO" "config.ini copiato"
    
    # Copia bridges.conf (se non esiste già non sovrascrivere per preservare bridge utente)
    if [[ ! -f "$INSTALL_DIR/bridges.conf" ]]; then
        cp "$SCRIPT_DIR/bridges.conf" "$INSTALL_DIR/" 2>/dev/null && \
            log_msg "INFO" "bridges.conf copiato"
    else
        log_msg "INFO" "bridges.conf esistente preservato"
    fi
    
    # Crea directory profili WireGuard
    mkdir -p "$INSTALL_DIR/wireguard_profiles"
    if [[ -d "$SCRIPT_DIR/wireguard_profiles" ]]; then
        cp -r "$SCRIPT_DIR/wireguard_profiles/"* "$INSTALL_DIR/wireguard_profiles/" 2>/dev/null || true
    fi
    log_msg "INFO" "Directory wireguard_profiles creata in $INSTALL_DIR"
    
    # Imposta permessi
    chmod 755 "$INSTALL_DIR"/*.py 2>/dev/null
    chmod 644 "$INSTALL_DIR/config.ini" 2>/dev/null
    
    echo ""
}

# Crea ambiente virtuale Python
setup_venv() {
    log_msg "STEP" "[FASE 3/6] Creazione ambiente virtuale Python..."
    echo ""
    
    if [[ -d "$VENV_DIR" ]]; then
        log_msg "INFO" "Rimozione venv esistente..."
        rm -rf "$VENV_DIR"
    fi
    
    log_msg "INFO" "Creazione venv in $VENV_DIR..."
    
    if python3 -m venv --system-site-packages "$VENV_DIR" 2>>"$LOG_FILE"; then
        log_msg "INFO" "venv creato con successo"
    else
        log_msg "ERROR" "Creazione venv fallita"
        exit 1
    fi
    
    source "$VENV_DIR/bin/activate"
    
    log_msg "INFO" "Aggiornamento pip..."
    pip install --upgrade pip >> "$LOG_FILE" 2>&1 || log_msg "WARN" "Aggiornamento pip fallito"
    
    local python_packages=$(read_config "dependencies" "python_packages" "$DEFAULT_PYTHON_PACKAGES")
    
    log_msg "INFO" "Installazione pacchetti Python: $python_packages"
    
    for pkg in $python_packages; do
        echo -e "  Installazione $pkg..."
        if pip install "$pkg" >> "$LOG_FILE" 2>&1; then
            echo -e "  ${GREEN}✓${NC} $pkg installato"
        else
            echo -e "  ${YELLOW}!${NC} $pkg fallito (opzionale)"
        fi
    done
    
    deactivate
    echo ""
}

# Installa AnonSurf
install_anonsurf() {
    log_msg "STEP" "[FASE 4/6] Verifica/Installazione AnonSurf..."
    echo ""
    
    if command -v anonsurf &>/dev/null; then
        local version=$(anonsurf --help 2>&1 | head -1 || echo "installato")
        log_msg "INFO" "AnonSurf già installato"
        echo ""
        return 0
    fi
    
    log_msg "INFO" "AnonSurf non trovato, procedo con l'installazione..."
    
    local repo=$(read_config "installation" "anonsurf_repo" "$DEFAULT_ANONSURF_REPO")
    local temp_dir=$(read_config "installation" "anonsurf_temp" "/tmp/kali-anonsurf")
    
    rm -rf "$temp_dir" 2>/dev/null
    
    log_msg "INFO" "Clonazione da $repo..."
    
    if git clone --depth 1 "$repo" "$temp_dir" >> "$LOG_FILE" 2>&1; then
        log_msg "INFO" "Repository clonato"
        
        cd "$temp_dir"
        
        if [[ -f "installer.sh" ]]; then
            chmod +x installer.sh
            log_msg "INFO" "Esecuzione installer AnonSurf..."
            
            if ./installer.sh 2>&1 | tee -a "$LOG_FILE"; then
                log_msg "INFO" "Installer completato"
            else
                log_msg "WARN" "Installer terminato con avvisi"
            fi
        else
            log_msg "ERROR" "installer.sh non trovato nel repository"
        fi
        
        cd "$SCRIPT_DIR"
        rm -rf "$temp_dir"
    else
        log_msg "ERROR" "Clone repository fallito"
        echo ""
        echo -e "${YELLOW}Installazione manuale:${NC}"
        echo "  cd /tmp"
        echo "  git clone $repo"
        echo "  cd kali-anonsurf"
        echo "  sudo ./installer.sh"
    fi
    
    echo ""
    if command -v anonsurf >/dev/null 2>&1; then
        log_msg "INFO" "AnonSurf installato con successo"
    else
        log_msg "WARN" "AnonSurf NON installato - puoi installarlo manualmente"
    fi
    
    echo ""
}

# Crea launcher e link simbolici
create_launchers() {
    log_msg "STEP" "[FASE 5/6] Creazione launcher..."
    echo ""
    
    # Copia il launcher Python
    if [[ -f "$SCRIPT_DIR/anonsurf_launcher.py" ]]; then
        cp "$SCRIPT_DIR/anonsurf_launcher.py" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/anonsurf_launcher.py"
        log_msg "INFO" "Launcher Python copiato"
    else
        log_msg "ERROR" "anonsurf_launcher.py non trovato!"
    fi
    
    # Script runner (eseguito con sudo dalla GUI)
    cat > "$INSTALL_DIR/anonsurf-gui-run.sh" << 'RUNSCRIPT'
#!/bin/bash
INSTALL_DIR="/opt/anonsurf-gui"
VENV_DIR="$INSTALL_DIR/venv"

if [[ ! -d "$VENV_DIR" ]]; then
    echo "ERRORE: Ambiente virtuale non trovato"
    exit 1
fi

case "$1" in
    -min|-mini|-compact)
        APP_FILE="$INSTALL_DIR/anonsurf_gui_mini.py"
        ;;
    *)
        APP_FILE="$INSTALL_DIR/anonsurf_gui.py"
        ;;
esac

if [[ ! -f "$APP_FILE" ]]; then
    echo "ERRORE: File non trovato: $APP_FILE"
    exit 1
fi

cd "$INSTALL_DIR"
source "$VENV_DIR/bin/activate"
exec python3 "$APP_FILE"
RUNSCRIPT

    chmod +x "$INSTALL_DIR/anonsurf-gui-run.sh"
    log_msg "INFO" "Script runner creato"
    
    # Crea start.sh nella directory sorgente
    cat > "$SCRIPT_DIR/start.sh" << 'STARTSH'
#!/bin/bash
#===============================================================================
#   AnonSurf GUI - Start Script v3.3
#   
#   USO:
#     ./start.sh           # Apre il launcher (scelta GUI)
#     ./start.sh -min      # GUI minimale diretta
#     ./start.sh -full     # GUI completa diretta
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Se installato in /opt
if [[ -d /opt/anonsurf-gui ]]; then
    INSTALL_DIR="/opt/anonsurf-gui"
else
    INSTALL_DIR="$SCRIPT_DIR"
fi

# Senza argomenti: apri il launcher
if [[ $# -eq 0 ]]; then
    if [[ -f "$INSTALL_DIR/anonsurf_launcher.py" ]]; then
        exec python3 "$INSTALL_DIR/anonsurf_launcher.py"
    fi
fi

# Con argomenti: avvio diretto (richiede sudo)
if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

case "$1" in
    -min|-mini|-compact)
        APP_FILE="$INSTALL_DIR/anonsurf_gui_mini.py"
        ;;
    *)
        APP_FILE="$INSTALL_DIR/anonsurf_gui.py"
        ;;
esac

if [[ -d "$INSTALL_DIR/venv" ]]; then
    source "$INSTALL_DIR/venv/bin/activate"
fi

cd "$INSTALL_DIR"
exec python3 "$APP_FILE"
STARTSH

    chmod +x "$SCRIPT_DIR/start.sh"
    log_msg "INFO" "start.sh creato"
    
    # Wrapper per terminale - GUI completa
    cat > /usr/local/bin/anonsurf-gui << 'TERMWRAPPER'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    exec sudo /opt/anonsurf-gui/anonsurf-gui-run.sh "$@"
else
    exec /opt/anonsurf-gui/anonsurf-gui-run.sh "$@"
fi
TERMWRAPPER
    chmod +x /usr/local/bin/anonsurf-gui
    
    # Wrapper per terminale - GUI mini
    cat > /usr/local/bin/anonsurf-gui-mini << 'TERMWRAPPERMINI'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    exec sudo /opt/anonsurf-gui/anonsurf-gui-run.sh -mini "$@"
else
    exec /opt/anonsurf-gui/anonsurf-gui-run.sh -mini "$@"
fi
TERMWRAPPERMINI
    chmod +x /usr/local/bin/anonsurf-gui-mini
    
    log_msg "INFO" "Comandi terminale creati"
    echo ""
}

# Crea voci nel menu di sistema
create_desktop_entries() {
    log_msg "STEP" "[FASE 6/6] Creazione voce nel menu di sistema..."
    echo ""
    
    # Crea icona
    create_icon
    
    # File .desktop - chiama il launcher PYTHON (senza sudo, gira come utente)
    cat > "$DESKTOP_FILE_FULL" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=AnonSurf GUI
GenericName=Tor Anonymity Control
Comment=Control Panel per AnonSurf - Navigazione anonima via Tor
Exec=python3 /opt/anonsurf-gui/anonsurf_launcher.py
Icon=anonsurf-gui
Terminal=false
Categories=Network;Security;System;
Keywords=tor;anonsurf;anonymity;privacy;vpn;
StartupNotify=false
DESKTOP
    
    chmod 644 "$DESKTOP_FILE_FULL"
    log_msg "INFO" "Voce menu creata: AnonSurf GUI"
    
    # Rimuovi eventuale vecchio file mini
    rm -f "$DESKTOP_FILE_MINI" 2>/dev/null
    
    # Aggiorna cache icone e database desktop
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
        log_msg "INFO" "Database desktop aggiornato"
    fi
    
    if command -v gtk-update-icon-cache &>/dev/null; then
        gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
        log_msg "INFO" "Cache icone aggiornata"
    fi
    
    echo ""
}

# Verifica finale
final_check() {
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                      VERIFICA INSTALLAZIONE                       ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local errors=0
    
    # Verifica file installati
    if [[ -f "$INSTALL_DIR/anonsurf_gui.py" ]]; then
        echo -e "  ${GREEN}✓${NC} anonsurf_gui.py installato"
    else
        echo -e "  ${RED}✗${NC} anonsurf_gui.py MANCANTE"
        ((errors++))
    fi
    
    if [[ -f "$INSTALL_DIR/anonsurf_gui_mini.py" ]]; then
        echo -e "  ${GREEN}✓${NC} anonsurf_gui_mini.py installato"
    else
        echo -e "  ${YELLOW}!${NC} anonsurf_gui_mini.py non trovato (opzionale)"
    fi
    
    if [[ -d "$VENV_DIR" ]]; then
        echo -e "  ${GREEN}✓${NC} Ambiente virtuale Python OK"
    else
        echo -e "  ${RED}✗${NC} Ambiente virtuale MANCANTE"
        ((errors++))
    fi
    
    # Verifica wrapper/link
    if [[ -x /usr/local/bin/anonsurf-gui ]]; then
        echo -e "  ${GREEN}✓${NC} Comando /usr/local/bin/anonsurf-gui OK"
    else
        echo -e "  ${RED}✗${NC} Comando /usr/local/bin/anonsurf-gui MANCANTE"
        ((errors++))
    fi
    
    if [[ -x /usr/local/bin/anonsurf-gui-mini ]]; then
        echo -e "  ${GREEN}✓${NC} Comando /usr/local/bin/anonsurf-gui-mini OK"
    else
        echo -e "  ${YELLOW}!${NC} Comando /usr/local/bin/anonsurf-gui-mini mancante"
    fi
    
    # Verifica start.sh
    if [[ -x "$SCRIPT_DIR/start.sh" ]]; then
        echo -e "  ${GREEN}✓${NC} start.sh creato nella directory sorgente"
    else
        echo -e "  ${YELLOW}!${NC} start.sh non trovato"
    fi
    
    # Verifica menu
    if [[ -f "$DESKTOP_FILE_FULL" ]]; then
        echo -e "  ${GREEN}✓${NC} Voce menu: AnonSurf GUI"
    else
        echo -e "  ${RED}✗${NC} Voce menu MANCANTE"
        ((errors++))
    fi
    
    # Verifica launcher Python
    if [[ -f "$INSTALL_DIR/anonsurf_launcher.py" ]]; then
        echo -e "  ${GREEN}✓${NC} Launcher Python installato"
    else
        echo -e "  ${RED}✗${NC} Launcher Python MANCANTE"
        ((errors++))
    fi
    
    # Verifica AnonSurf
    if command -v anonsurf >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} AnonSurf disponibile"
    else
        echo -e "  ${YELLOW}!${NC} AnonSurf non trovato (installare separatamente)"
    fi
    
    # Verifica torsocks (richiesto per modalità Cascata)
    if command -v torsocks >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} torsocks disponibile (Cascata VPN→Tor OK)"
    else
        echo -e "  ${YELLOW}!${NC} torsocks non trovato — installa: sudo apt install torsocks"
    fi
    
    echo ""
    
    if [[ $errors -eq 0 ]]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║            INSTALLAZIONE COMPLETATA CON SUCCESSO!                  ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "L'applicazione è ora disponibile nel ${CYAN}MENU DI SISTEMA${NC}:"
        echo ""
        echo -e "  📌 ${CYAN}AnonSurf GUI${NC} - Scegli versione completa o mini all'avvio"
        echo ""
        echo -e "Oppure da terminale:"
        echo ""
        echo -e "  ${CYAN}sudo anonsurf-gui${NC}        # GUI completa"
        echo -e "  ${CYAN}sudo anonsurf-gui-mini${NC}   # GUI compatta"
        echo -e "  ${CYAN}./start.sh${NC}               # dalla directory sorgente"
        echo ""
        echo -e "Directory installazione: ${YELLOW}$INSTALL_DIR${NC}"
        echo -e "Log installazione: ${YELLOW}$LOG_FILE${NC}"
        echo ""
        echo -e "Per disinstallare: ${YELLOW}sudo $SCRIPT_DIR/uninstall.sh${NC}"
        echo ""
    else
        echo -e "${RED}Installazione con $errors errore/i. Controlla i messaggi sopra.${NC}"
        echo -e "Log dettagliato: $LOG_FILE"
        exit 1
    fi
}

#===============================================================================
# MAIN
#===============================================================================

# Inizializza log
echo "=== AnonSurf GUI Installer v$VERSION - $(date) ===" > "$LOG_FILE"

check_root
show_banner

# Chiedi conferma
echo -e "${YELLOW}Questa installazione:${NC}"
echo "  • Installerà i file in /opt/anonsurf-gui"
echo "  • Creerà DUE voci nel menu di sistema"
echo "  • Creerà link simbolici in /usr/local/bin"
echo "  • Installerà AnonSurf se non presente"
echo ""
read -p "Continuare? (s/n): " confirm
if [[ "$confirm" != "s" && "$confirm" != "S" && "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Annullato."
    exit 0
fi
echo ""

# Esegui fasi
install_system_deps
install_files
setup_venv
install_anonsurf
create_launchers
create_desktop_entries
final_check

echo "=== Installazione completata - $(date) ===" >> "$LOG_FILE"
