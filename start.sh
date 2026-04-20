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
