#!/bin/bash

#===============================================================================
#   AnonSurf GUI Control Panel - Uninstaller v2.1
#   
#   RIMUOVE AUTOMATICAMENTE:
#   - File installati in /opt/anonsurf-gui
#   - Voci dal menu di sistema
#   - Link simbolici in /usr/local/bin
#   - Icona applicazione
#   - AnonSurf e Tor (opzionale, con flag --full)
#   
#   USO:
#     sudo ./uninstall.sh           # Rimuove solo GUI
#     sudo ./uninstall.sh --full    # Rimuove anche AnonSurf e Tor
#     sudo ./uninstall.sh --help    # Mostra aiuto
#===============================================================================

VERSION="2.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Directory
INSTALL_DIR="/opt/anonsurf-gui"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/uninstall.log"

# File del menu
DESKTOP_DIR="/usr/share/applications"
DESKTOP_FILE_FULL="$DESKTOP_DIR/anonsurf-gui.desktop"
DESKTOP_FILE_MINI="$DESKTOP_DIR/anonsurf-gui-mini.desktop"
ICON_FILE="/usr/share/icons/hicolor/128x128/apps/anonsurf-gui.png"

# Modalità full
FULL_UNINSTALL=false

# Parse argomenti
while [[ $# -gt 0 ]]; do
    case $1 in
        --full|-f)
            FULL_UNINSTALL=true
            shift
            ;;
        --help|-h)
            echo "AnonSurf GUI Uninstaller v$VERSION"
            echo ""
            echo "Uso: sudo ./uninstall.sh [opzioni]"
            echo ""
            echo "Opzioni:"
            echo "  --full, -f    Rimuove anche AnonSurf e Tor"
            echo "  --help, -h    Mostra questo messaggio"
            echo ""
            echo "Senza opzioni rimuove solo la GUI e i file correlati."
            exit 0
            ;;
        *)
            echo "Opzione sconosciuta: $1"
            echo "Usa --help per vedere le opzioni disponibili"
            exit 1
            ;;
    esac
done

# Funzione log
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO")  echo -e "  ${GREEN}✓${NC} $message" ;;
        "WARN")  echo -e "  ${YELLOW}!${NC} $message" ;;
        "ERROR") echo -e "  ${RED}✗${NC} $message" ;;
        *)       echo "  $message" ;;
    esac
}

# Verifica root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERRORE] Esegui come root: sudo ./uninstall.sh${NC}"
    exit 1
fi

# Inizializza log
echo "=== AnonSurf GUI Uninstaller v$VERSION - $(date) ===" > "$LOG_FILE"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║      AnonSurf GUI Control Panel - Disinstallazione v$VERSION          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if $FULL_UNINSTALL; then
    echo -e "${YELLOW}Modalità FULL: Rimozione GUI + AnonSurf + Tor${NC}"
else
    echo -e "${CYAN}Modalità STANDARD: Rimozione solo GUI${NC}"
    echo -e "${CYAN}Usa --full per rimuovere anche AnonSurf e Tor${NC}"
fi
echo ""

#===============================================================================
# FASE 1: Arresto processi
#===============================================================================
echo -e "${CYAN}[1/6] Arresto processi...${NC}"

if pgrep -f "anonsurf_gui" > /dev/null 2>&1; then
    pkill -f "anonsurf_gui" 2>/dev/null
    sleep 1
    pkill -9 -f "anonsurf_gui" 2>/dev/null || true
    log "INFO" "GUI terminata"
else
    log "INFO" "GUI non in esecuzione"
fi

if $FULL_UNINSTALL; then
    if command -v anonsurf &> /dev/null; then
        anonsurf stop 2>/dev/null || true
        sleep 3
        log "INFO" "AnonSurf fermato"
    fi
    
    systemctl stop tor 2>/dev/null || true
    service tor stop 2>/dev/null || true
    log "INFO" "Tor fermato"
fi

echo ""

#===============================================================================
# FASE 2: Rimozione voce menu
#===============================================================================
echo -e "${CYAN}[2/6] Rimozione voce dal menu di sistema...${NC}"

if [[ -f "$DESKTOP_FILE_FULL" ]]; then
    rm -f "$DESKTOP_FILE_FULL"
    log "INFO" "Voce menu 'AnonSurf GUI' rimossa"
else
    log "INFO" "Voce menu 'AnonSurf GUI' non presente"
fi

# Rimuovi anche eventuale vecchio file mini (versioni precedenti)
if [[ -f "$DESKTOP_FILE_MINI" ]]; then
    rm -f "$DESKTOP_FILE_MINI"
    log "INFO" "Voce menu 'AnonSurf GUI Mini' rimossa (legacy)"
fi

# Aggiorna database desktop
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

echo ""

#===============================================================================
# FASE 3: Rimozione link simbolici
#===============================================================================
echo -e "${CYAN}[3/6] Rimozione link simbolici...${NC}"

for link in /usr/local/bin/anonsurf-gui /usr/local/bin/anonsurf-gui-mini; do
    if [[ -L "$link" ]] || [[ -f "$link" ]]; then
        rm -f "$link"
        log "INFO" "Link rimosso: $link"
    fi
done

# Rimuovi eventuale file PolicyKit (versioni precedenti)
if [[ -f /usr/share/polkit-1/actions/org.anonsurf.gui.policy ]]; then
    rm -f /usr/share/polkit-1/actions/org.anonsurf.gui.policy
    log "INFO" "PolicyKit action rimosso (legacy)"
fi

echo ""

#===============================================================================
# FASE 4: Rimozione directory installazione
#===============================================================================
echo -e "${CYAN}[4/6] Rimozione file installati...${NC}"

if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    log "INFO" "Directory $INSTALL_DIR rimossa"
else
    log "INFO" "Directory $INSTALL_DIR non presente"
fi

# Rimuovi icona
if [[ -f "$ICON_FILE" ]]; then
    rm -f "$ICON_FILE"
    log "INFO" "Icona rimossa"
    
    # Aggiorna cache icone
    if command -v gtk-update-icon-cache &>/dev/null; then
        gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
    fi
fi

# Pulizia file temporanei
rm -f /tmp/anonsurf_real_ip.txt 2>/dev/null
rm -rf /tmp/anonsurf_gui_state 2>/dev/null
rm -rf /tmp/kali-anonsurf 2>/dev/null
log "INFO" "File temporanei rimossi"

echo ""

#===============================================================================
# FASE 5: Rimozione AnonSurf e Tor (solo con --full)
#===============================================================================
echo -e "${CYAN}[5/6] Rimozione componenti di sistema...${NC}"

if $FULL_UNINSTALL; then
    # Rimuovi AnonSurf
    if command -v anonsurf &> /dev/null || [[ -d /usr/share/anonsurf ]]; then
        log "INFO" "Rimozione AnonSurf..."
        
        rm -f /usr/bin/anonsurf 2>/dev/null
        rm -f /usr/local/bin/anonsurf 2>/dev/null
        rm -f /usr/sbin/anonsurf 2>/dev/null
        rm -f /usr/bin/pandora 2>/dev/null
        rm -rf /usr/share/anonsurf 2>/dev/null
        rm -rf /etc/anonsurf 2>/dev/null
        rm -f /etc/init.d/anonsurf 2>/dev/null
        
        systemctl stop anonsurf 2>/dev/null || true
        systemctl disable anonsurf 2>/dev/null || true
        rm -f /etc/systemd/system/anonsurf.service 2>/dev/null
        rm -f /lib/systemd/system/anonsurf.service 2>/dev/null
        systemctl daemon-reload 2>/dev/null || true
        
        log "INFO" "AnonSurf rimosso"
    else
        log "INFO" "AnonSurf non presente"
    fi
    
    # Rimuovi Tor
    if command -v tor &> /dev/null || dpkg -l tor 2>/dev/null | grep -q "^ii"; then
        log "INFO" "Rimozione Tor..."
        
        export DEBIAN_FRONTEND=noninteractive
        
        systemctl stop tor 2>/dev/null || true
        systemctl disable tor 2>/dev/null || true
        
        apt-get remove --purge -y tor tor-geoipdb torsocks 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        
        rm -rf /etc/tor 2>/dev/null
        rm -rf /var/lib/tor 2>/dev/null
        rm -rf /var/log/tor 2>/dev/null
        rm -f /etc/default/tor 2>/dev/null
        
        log "INFO" "Tor rimosso"
    else
        log "INFO" "Tor non presente"
    fi
else
    log "INFO" "Modalità standard - AnonSurf e Tor mantenuti"
fi

echo ""

#===============================================================================
# FASE 6: Ripristino rete (solo con --full)
#===============================================================================
echo -e "${CYAN}[6/6] Ripristino configurazione rete...${NC}"

if $FULL_UNINSTALL; then
    # Flush iptables
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    log "INFO" "Regole iptables ripristinate"
    
    # Ripristina DNS
    if [[ -f /etc/resolv.conf.backup ]]; then
        cp /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null
        rm -f /etc/resolv.conf.backup
        log "INFO" "DNS ripristinati da backup"
    elif [[ -f /run/systemd/resolve/stub-resolv.conf ]]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null
        log "INFO" "DNS ripristinati (systemd-resolved)"
    fi
    
    # Riavvia servizi di rete
    for service in NetworkManager networking systemd-networkd; do
        if systemctl is-active --quiet "$service" 2>/dev/null || \
           systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl restart "$service" 2>/dev/null && \
                log "INFO" "Servizio $service riavviato" && break
        fi
    done
else
    log "INFO" "Configurazione rete mantenuta"
fi

echo ""

#===============================================================================
# Verifica finale
#===============================================================================
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                    VERIFICA DISINSTALLAZIONE                      ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

errors=0

# Verifica GUI
if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "  ${RED}✗${NC} Directory $INSTALL_DIR ancora presente"
    ((errors++))
else
    echo -e "  ${GREEN}✓${NC} Directory installazione rimossa"
fi

if [[ -f "$DESKTOP_FILE_FULL" ]] || [[ -f "$DESKTOP_FILE_MINI" ]]; then
    echo -e "  ${RED}✗${NC} Voce menu ancora presente"
    ((errors++))
else
    echo -e "  ${GREEN}✓${NC} Voce menu rimossa"
fi

if [[ -L /usr/local/bin/anonsurf-gui ]] || [[ -f /usr/local/bin/anonsurf-gui-mini ]]; then
    echo -e "  ${RED}✗${NC} Link simbolici ancora presenti"
    ((errors++))
else
    echo -e "  ${GREEN}✓${NC} Link simbolici rimossi"
fi

if $FULL_UNINSTALL; then
    if command -v anonsurf &> /dev/null; then
        echo -e "  ${RED}✗${NC} AnonSurf ancora presente"
        ((errors++))
    else
        echo -e "  ${GREEN}✓${NC} AnonSurf rimosso"
    fi
    
    if command -v tor &> /dev/null; then
        echo -e "  ${RED}✗${NC} Tor ancora presente"
        ((errors++))
    else
        echo -e "  ${GREEN}✓${NC} Tor rimosso"
    fi
fi

echo ""

if [[ $errors -eq 0 ]]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          DISINSTALLAZIONE COMPLETATA CON SUCCESSO!                ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}Disinstallazione completata con $errors avviso/i${NC}"
    echo -e "${YELLOW}Alcuni componenti potrebbero richiedere un riavvio${NC}"
fi

echo ""
echo -e "File rimanenti nella cartella sorgente (rimuovere manualmente se desiderato):"
echo "  - anonsurf_gui.py"
echo "  - anonsurf_gui_mini.py"
echo "  - config.ini"
echo "  - install.sh"
echo "  - uninstall.sh"
echo "  - README.md"
echo ""
echo -e "Per rimuovere completamente: ${YELLOW}rm -rf $SCRIPT_DIR${NC}"
echo ""

if $FULL_UNINSTALL; then
    echo -e "La rete è stata ripristinata alla configurazione originale."
fi

echo -e "Log disinstallazione: ${YELLOW}$LOG_FILE${NC}"
echo ""

log "INFO" "Disinstallazione completata"
