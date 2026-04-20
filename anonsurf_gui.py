#!/usr/bin/env python3
"""
AnonSurf GUI Control Panel v3.3
VPN Detection & Cascade Edition

NOVITÀ v3.3:
- Firefox: usa xdg-open (rispetta proxy GNOME, no conflitti)
- NEWNYM via debian-tor (autenticazione cookie corretta)
- IP cascata via torsocks (mostra vero exit Tor, non VPN)
- Finestra si allarga dinamicamente a cascata attiva
- Pannello cascata sopra il log (log sempre visibile)
- Rilevamento automatico VPN di terze parti installate sul sistema
  (Surfshark, NordVPN, ProtonVPN, ExpressVPN, Mullvad, CyberGhost, PIA, IVPN)
- Selettore tipo VPN: WireGuard oppure VPN rilevata
- Modalità CASCATA: VPN attiva + Tor sopra (VPN → Tor)
  ISP vede solo traffico VPN cifrato, nessuna firma Tor visibile
- Indicatore modalità: DIRETTA / TOR / VPN / CASCATA
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import os
import sys
import json
import ssl
import urllib.request
import threading
import subprocess
import shutil
import atexit
import signal
import configparser
import logging
import re
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
import time

BASE_DIR = Path(__file__).parent.absolute()

# ============================================================================
# BANDIERE PNG EMBEDDED (Base64) - 32x24 pixel
# ============================================================================
FLAGS_BASE64 = {
    "AE": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAL0lEQVR4nGNk6HFloCVgoqnpoxaMWkAVwPj//3+aWjD0g2jUghFgwSgYBaOAgQEARg0D7Wn50FQAAAAASUVORK5CYII=",
    "AR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAMUlEQVR4nGNkCFrKQEvARFPTRy0YtYAqgPH///80tWDoB9GoBSPAAsbR+mDUglELGAChkgUZyuU5UgAAAABJRU5ErkJggg==",
    "AT": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAL0lEQVR4nGP8z0BbwERj80ctGLWACoCF4T9tc8LQD6JRC0aABYyj9cGoBaMWMAAADq4ELZ4GLhcAAAAASUVORK5CYII=",
    "AU": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAJklEQVR4nGNkUKlloCVgoqnpoxaMWjBqwagFoxaMWjBqwagFVAMAmgsA0bAdUPoAAAAASUVORK5CYII=",
    "BE": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAMElEQVR4nGNkwAv+n8UrbYxfNwMDAwMTYSWUgVELRi0YtWDUglELRi0YtWDUAuoAAMZzAi+aQA43AAAAAElFTkSuQmCC",
    "BR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAMklEQVR4nGNk6HFloCVgoqnpoxaMWkAVwPj/LG0tGPpBNGrBCLCAhXH/aH0wasGItwAARlQD012oiyQAAAAASUVORK5CYII=",
    "CA": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAL0lEQVR4nO3NsREAAAjCQHD/nXUDLLRMWuXerVjHu53Xkmr9OAYAAAAAAAAA8NMA4ZoDL2N5Cq8AAAAASUVORK5CYII=",
    "CH": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAS0lEQVR4nGP8z0BbwERj80ctGAQWsJCg9j9qimNkJEbT0A8imlvAiDMn/ycxj+OIkqEfREPfAtyRjAlGMxptAClxQBYY+kE09C0AALACCiuvs936AAAAAElFTkSuQmCC",
    "CN": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAJElEQVR4nGP8z0BbwERj80ctGLVg1IJRC0YtGLVg1IJRC6gEAPHIAS8Wxt4fAAAAAElFTkSuQmCC",
    "DE": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAK0lEQVR4nGNgGAWjYBQw/qexBUw0Nn/UglELqABYGM7S1oKhH0SjFowACwDlXwHuaIlc7wAAAABJRU5ErkJggg==",
    "DK": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAPElEQVR4nGP8z4AD/EeSYWTEpYogYCJb56gFoxaMWkA0YPz/H2depgoY+kFEhzjAJTNamo5aMGrB0LEAAN52CSl9AuS6AAAAAElFTkSuQmCC",
    "ES": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAALklEQVR4nGP8z0BbwERj80ctGLWACoCF4SxtLRj6QTRqwQiwgHG0Phi1YNQCBgDYhwL8DyvpsQAAAABJRU5ErkJggg==",
    "FI": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAPklEQVR4nGP8//8/AzbAGLwMzv6/NgqrGmIAE9k6Ry0YtWDUAqIBI0PQUppaQDDHv2MAACAASURBVEM/iGgfB6Ol6agFoxYMAwsAAR5MNHw8P/GIAAAAASUVORK5CYII=",
    "FR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAN0lEQVR4nGNkUKllwA3+327CI8vAyIhPloGBgYGBiaAKCsGoBaMWjFowasGoBaMWjFowagF1AADWlgMv2avmuQAAAABJRU5ErkJggg==",
    "GB": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAJklEQVR4nGNkUKlloCVgoqnpoxaMWjBqwagFoxaMWjBqwagFVAMAmgsA0bAdUPoAAAAASUVORK5CYII=",
    "GR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAOklEQVR4nGNkCFrKQEvARFPTGRgYGP///09TC2jvg9E4IARG44AgGI0DgmA0DgiCoR8HoxaMWkA5AABNgxDvX1sPCgAAAABJRU5ErkJggg==",
    "HU": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAANElEQVR4nGP8z0BbwERj80ctGLWACoCF4T9tc8LQD6JRC0aABYwMPa40tWDoB9GoBSPAAgCCRwP/kxcb+AAAAABJRU5ErkJggg==",
    "IE": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAN0lEQVR4nGNk6HFlwA3+F+/CI8vQy4hPloGBgYGBiaAKCsGoBaMWjFowasGoBaMWjFowagF1AACzuQO7jF+TGgAAAABJRU5ErkJggg==",
    "IL": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAMUlEQVR4nGP8//8/Ay0BE01NH7Vg1AKqAEYGlVqaWjD0g2jUghFgAeNofTBqwagFDADalQbJA1E9uwAAAABJRU5ErkJggg==",
    "IN": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAANklEQVR4nGP838NAU8BEW+NHLRi1gBqA8f///zS1YOgH0agFI8ACRoYeV5paMPSDaNSCEWABAHG1BYfTQCZwAAAAAElFTkSuQmCC",
    "IT": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAN0lEQVR4nGNk6HFlwA3+F+/CI8vAyIhPloGBgYGBiaAKCsGoBaMWjFowasGoBaMWjFowagF1AADcNgMv1W1gqgAAAABJRU5ErkJggg==",
    "JP": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAb0lEQVR4nO2VQQ7AIAgEu03//2U81ZswmNraKCcOZEdYgjKzY2ScQ9U34KcAKVV+9ejWHKw466D1atANAPgqEWNCkx8GkJ1xayIAOYVuzecjegPgTymaIeugpQIcwqeiaknI+TvyHiS/2BlMXh1QAHrHFzG5L0uyAAAAAElFTkSuQmCC",
    "KR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAJklEQVR4nO3NMQEAAAjDMMC/52ECvlRA00nqs3m9AwAAAAAAAJy1C7oDLV5LB/0AAAAASUVORK5CYII=",
    "MX": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAN0lEQVR4nGNk6HFlwA3+F+/CI8vAyIhPloGBgYGBiaAKCsGoBaMWjFowasGoBaMWjFowagF1AADcNgMv1W1gqgAAAABJRU5ErkJggg==",
    "NL": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAANElEQVR4nGP8z0BbwERj80ctGLWACoCF4T9tc8LQD6JRC0aABYwMKrU0tWDoB9GoBSPAAgDw4APPxZnTvQAAAABJRU5ErkJggg==",
    "NO": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAO0lEQVR4nGP8z4AdMCpEw9n/HyzFoYowYCJb56gFoxaMWkA0YGRAyrG0AEM/iGgfB6Ol6agFoxYMAwsACVMIpwUa+RAAAAAASUVORK5CYII=",
    "PL": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAALUlEQVR4nGP8//8/Ay0BE01NH7Vg1IJRC4aJBYy0LYmGQxCNWjBqwagFdLAAAI3fBCtjrH6FAAAAAElFTkSuQmCC",
    "PT": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAALklEQVR4nGNk6HFlwA3+l+zGI0sMYKJQ/6gFoxaMWjBqwagFoxaMWjBqAZ0sAADccgMvytfIggAAAABJRU5ErkJggg==",
    "RO": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAM0lEQVR4nGNkUKllwA3+r2zGI8tgjE8SApgIK6EMjFowasGoBaMWjFowasGoBaMWUAcAANDYAy92gKBFAAAAAElFTkSuQmCC",
    "RU": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAANElEQVR4nGP8//8/Ay0BE01NH7Vg1AKqAEYGlVqaWjD0g2jUghFgASNta4PhEESjFowACwDVRgTLejW+TAAAAABJRU5ErkJggg==",
    "SE": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAP0lEQVR4nGNkyFrOgA38T46EsxnnYldDDGAiW+eoBaMWjFpANGD8f5a2Fgz9IKK5BSy4SsrR0nTUglELhpAFANZoClOH1rXNAAAAAElFTkSuQmCC",
    "TR": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAJElEQVR4nGP8z0BbwERj80ctGLVg1IJRC0YtGLVg1IJRC6gEAPHIAS8Wxt4fAAAAAElFTkSuQmCC",
    "UA": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAALklEQVR4nGNkCFrKQEvARFPTRy0YtWDUgmFiAeP/s7S1YOgH0agFoxaMWkAHCwDMVwLyEM5jTAAAAABJRU5ErkJggg==",
    "US": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAANUlEQVR4nGP8z0BbwERj82lvAQvDf9oG0tAPIsbRVEQIjKYigmA0FREEo6mIIBhNRaMWUA4AhWIKKRD7uykAAAAASUVORK5CYII=",
    "ZA": "iVBORw0KGgoAAAANSUhEUgAAACAAAAAYCAIAAAAUMWhjAAAAQUlEQVR4nGP8z0BbwERj84eBBSwM/2kbC0M/iGhuASNDjytNLRj6QUT7OPg/mg8G2gJGBpVamlow9INo1IIRYAEAcRkHm+Bynt0AAAAASUVORK5CYII=",
}

# ============================================================================
# MODALITÀ OPERATIVE
# ============================================================================
MODE_DIRECT  = "DIRECT"
MODE_TOR     = "TOR"
MODE_VPN     = "VPN"
MODE_CASCADE = "CASCADE"   # VPN + Tor attivi simultaneamente

REAL_IP_FILE = Path('/tmp/anonsurf_real_ip.txt')

# ============================================================================
# PROVIDER VPN DI TERZE PARTI
# ============================================================================
# needs_user=True: il CLI va eseguito come utente originale (non root)
# Alcuni daemon (NordVPN, PIA) registrano la sessione per utente
VPN_PROVIDERS = {
    'surfshark': {
        'display':           'Surfshark',
        # binary principale + nomi alternativi da provare
        'binary':            'surfshark-vpn',
        'alt_binaries':      ['surfshark'],
        # servizio systemd da cercare se il binary non è nel PATH
        'service':           'surfshark-vpn',
        # "attack" è il vero comando connect ufficiale Surfshark Linux
        'connect':           ['surfshark-vpn', 'attack'],
        'disconnect':        ['surfshark-vpn', 'down'],
        'status':            ['surfshark-vpn', 'status'],
        'connected_pattern': r'(?i)(status[:\s]+connected|connected|vpn\s+is\s+(up|active|on))',
        'needs_user':        False,  # gira come root va bene
    },
    'nordvpn': {
        'display':           'NordVPN',
        'binary':            'nordvpn',
        'alt_binaries':      [],
        'service':           'nordvpnd',
        'connect':           ['nordvpn', 'connect'],
        'disconnect':        ['nordvpn', 'disconnect'],
        'status':            ['nordvpn', 'status'],
        'connected_pattern': r'(?i)Status:\s*Connected',
        'needs_user':        True,
    },
    'protonvpn-cli': {
        'display':           'ProtonVPN',
        'binary':            'protonvpn-cli',
        'alt_binaries':      ['protonvpn'],
        'service':           'protonvpn-app',
        'connect':           ['protonvpn-cli', 'connect', '--fastest'],
        'disconnect':        ['protonvpn-cli', 'disconnect'],
        'status':            ['protonvpn-cli', 'status'],
        'connected_pattern': r'(?i)Status:\s*Connected',
        'needs_user':        True,
    },
    'expressvpn': {
        'display':           'ExpressVPN',
        'binary':            'expressvpn',
        'alt_binaries':      [],
        'service':           'expressvpn',
        'connect':           ['expressvpn', 'connect'],
        'disconnect':        ['expressvpn', 'disconnect'],
        'status':            ['expressvpn', 'status'],
        'connected_pattern': r'(?i)Connected',
        'needs_user':        False,
    },
    'mullvad': {
        'display':           'Mullvad',
        'binary':            'mullvad',
        'alt_binaries':      ['mullvad-vpn'],
        'service':           'mullvad-daemon',
        'connect':           ['mullvad', 'connect'],
        'disconnect':        ['mullvad', 'disconnect'],
        'status':            ['mullvad', 'status'],
        'connected_pattern': r'(?i)(Connected|Secured)',
        'needs_user':        False,
    },
    'cyberghostvpn': {
        'display':           'CyberGhost',
        'binary':            'cyberghostvpn',
        'alt_binaries':      [],
        'service':           'cgpd',
        'connect':           ['cyberghostvpn', '--connect'],
        'disconnect':        ['cyberghostvpn', '--stop'],
        'status':            ['cyberghostvpn', '--status'],
        'connected_pattern': r'(?i)Connected',
        'needs_user':        False,
    },
    'piactl': {
        'display':           'PIA',
        'binary':            'piactl',
        'alt_binaries':      [],
        'service':           'piavpn',
        'connect':           ['piactl', 'connect'],
        'disconnect':        ['piactl', 'disconnect'],
        'status':            ['piactl', 'get', 'connectionstate'],
        'connected_pattern': r'(?i)Connected',
        'needs_user':        True,
    },
    'ivpn': {
        'display':           'IVPN',
        'binary':            'ivpn',
        'alt_binaries':      [],
        'service':           'ivpn-service',
        'connect':           ['ivpn', 'connect'],
        'disconnect':        ['ivpn', 'disconnect'],
        'status':            ['ivpn', 'status'],
        'connected_pattern': r'(?i)Connected',
        'needs_user':        False,
    },
}

WG_DISPLAY = "WireGuard"


# ============================================================================
# VPN DETECTOR  — ricerca robusta indipendente dal PATH
# ============================================================================
class VPNDetector:
    """
    Rileva VPN di terze parti nel sistema con strategia multi-livello:
      1. shutil.which() — PATH corrente
      2. Percorsi filesystem fissi (/usr/bin, /usr/local/bin, ecc.)
      3. Snap: /snap/bin/ e /snap/<n>/current/bin/
      4. Flatpak: /var/lib/flatpak/exports/bin/
      5. Servizio systemd attivo/presente (fallback senza binary)
    """

    EXTRA_PATHS = [
        '/usr/bin', '/usr/local/bin', '/usr/sbin', '/usr/local/sbin',
        '/bin', '/sbin', '/snap/bin', '/opt/local/bin',
        '/var/lib/flatpak/exports/bin',
    ]

    @classmethod
    def _find_binary(cls, binary_name: str):
        """Cerca binary_name in PATH + EXTRA_PATHS + snap. Ritorna path o None."""
        # 1. PATH corrente
        p = shutil.which(binary_name)
        if p:
            return p
        # 2. Percorsi fissi
        for d in cls.EXTRA_PATHS:
            candidate = Path(d) / binary_name
            if candidate.exists() and os.access(str(candidate), os.X_OK):
                return str(candidate)
        # 3. Snap packages
        snap_root = Path('/snap')
        if snap_root.is_dir():
            try:
                for snap_pkg in snap_root.iterdir():
                    if snap_pkg.name == 'bin':
                        continue
                    snap_bin = snap_pkg / 'current' / 'bin' / binary_name
                    if snap_bin.exists() and os.access(str(snap_bin), os.X_OK):
                        return str(snap_bin)
            except Exception:
                pass
        return None

    @classmethod
    def _service_exists(cls, service_name: str) -> bool:
        """True se il servizio systemd esiste (anche se disabilitato/fermo)."""
        try:
            r = subprocess.run(
                ['systemctl', 'list-unit-files', f'{service_name}.service'],
                capture_output=True, text=True, timeout=4,
            )
            return service_name in (r.stdout or '')
        except Exception:
            return False

    @classmethod
    def detect(cls, logger=None) -> dict:
        """
        Scansiona tutti i provider. Ritorna {key: display_name}.
        Logga in dettaglio ogni step per facilitare il debug.
        """
        found = {}

        def log(msg):
            if logger:
                logger.debug(msg)

        for key, info in VPN_PROVIDERS.items():
            display  = info['display']
            binaries = [info['binary']] + info.get('alt_binaries', [])
            resolved = None

            for bin_name in binaries:
                path = cls._find_binary(bin_name)
                if path:
                    resolved = path
                    log(f"VPN detect OK: {display} → {path}")
                    break
                else:
                    log(f"VPN detect: {display} → '{bin_name}' non in PATH/filesystem")

            if not resolved:
                # Fallback: servizio systemd
                svc = info.get('service', '')
                if svc and cls._service_exists(svc):
                    resolved = info['binary']   # usa binary name, funzionerà via daemon
                    log(f"VPN detect OK: {display} → servizio '{svc}' presente")
                else:
                    log(f"VPN detect: {display} → non trovata")
                    continue

            # Se trovato con percorso diverso dal binary originale, aggiorna i comandi
            if resolved and resolved != info['binary'] and Path(resolved).is_absolute():
                info['connect'][0]    = resolved
                info['disconnect'][0] = resolved
                info['status'][0]     = resolved
                info['binary']        = resolved

            found[key] = display

        return found

    @classmethod
    def run_diagnostics(cls) -> str:
        """Stringa diagnostica completa per debug rilevamento mancato."""
        lines = [
            "=== Diagnostica rilevamento VPN ===",
            f"PATH: {os.environ.get('PATH','(vuoto)')}",
            f"SUDO_USER: {os.environ.get('SUDO_USER','(non impostato)')}",
            f"UID: {os.geteuid()}",
            "",
        ]
        for key, info in VPN_PROVIDERS.items():
            lines.append(f"[{info['display']}]")
            for b in [info['binary']] + info.get('alt_binaries', []):
                p = cls._find_binary(b)
                lines.append(f"  binary '{b}': {'✓ ' + p if p else '✗ non trovato'}")
            svc = info.get('service', '')
            if svc:
                ex = cls._service_exists(svc)
                lines.append(f"  servizio '{svc}': {'✓ presente' if ex else '✗ assente'}")
            lines.append("")
        return "\n".join(lines)


# ============================================================================
# EXTERNAL VPN MANAGER
# ============================================================================
class ExternalVPNManager:
    """Gestisce VPN di terze parti (Surfshark, NordVPN, ecc.) tramite CLI"""

    def __init__(self, logger):
        self.logger = logger

    def _user_prefix(self):
        """Prefisso sudo -u <utente> per CLI che richiedono contesto utente"""
        if os.geteuid() == 0:
            sudo_user = os.environ.get('SUDO_USER', '')
            if sudo_user:
                return ['sudo', '-u', sudo_user]
        return []

    def _build_cmd(self, cmd_list, provider_key):
        info = VPN_PROVIDERS.get(provider_key, {})
        if info.get('needs_user'):
            return self._user_prefix() + cmd_list
        return cmd_list

    def _run(self, cmd_list, provider_key, timeout=30):
        cmd = self._build_cmd(cmd_list, provider_key)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = (r.stdout + r.stderr).strip()
            return r.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)

    def connect(self, provider_key) -> bool:
        info = VPN_PROVIDERS.get(provider_key)
        if not info:
            return False
        self.logger.info(f"Connessione {info['display']}...")
        ok, out = self._run(info['connect'], provider_key, timeout=60)
        if ok or self.is_connected(provider_key):
            self.logger.success(f"{info['display']} connessa")
            return True
        self.logger.error(f"Connessione {info['display']} fallita: {out[:100]}")
        return False

    def disconnect(self, provider_key) -> bool:
        info = VPN_PROVIDERS.get(provider_key)
        if not info:
            return False
        self.logger.info(f"Disconnessione {info['display']}...")
        ok, out = self._run(info['disconnect'], provider_key, timeout=30)
        if ok or not self.is_connected(provider_key):
            self.logger.success(f"{info['display']} disconnessa")
            return True
        self.logger.error(f"Disconnessione {info['display']} fallita: {out[:100]}")
        return False

    # Nomi di interfacce di rete tipicamente create da VPN commerciali
    _VPN_IFACE_PATTERNS = ['tun', 'utun', 'vpn', 'surfshark', 'nord', 'proton',
                            'expressvpn', 'mullvad', 'cyberghost', 'pia', 'ivpn']

    @staticmethod
    def _get_active_ifaces() -> list[str]:
        """
        Legge le interfacce di rete attive direttamente da /proc/net/dev —
        nessun processo esterno, nessun rischio di interferenza con il daemon VPN.
        """
        ifaces = []
        try:
            with open('/proc/net/dev') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        ifaces.append(line.split(':')[0].strip().lower())
        except Exception:
            try:
                r = subprocess.run(['ip', 'link', 'show', 'up'],
                                   capture_output=True, text=True, timeout=3)
                for line in r.stdout.split('\n'):
                    m = re.match(r'\d+:\s+(\S+):', line)
                    if m:
                        ifaces.append(m.group(1).lower().rstrip('@'))
            except Exception:
                pass
        return ifaces

    def _has_vpn_interface(self) -> bool:
        """
        Ritorna True se c'è almeno un'interfaccia di rete che sembra una VPN.
        Metodo leggero — nessuna chiamata CLI.
        """
        for iface in self._get_active_ifaces():
            if any(iface.startswith(p) for p in self._VPN_IFACE_PATTERNS):
                return True
        return False

    def is_connected(self, provider_key) -> bool:
        """
        Check leggero: usa interfacce kernel, NON chiama surfshark-vpn status.
        Evita il problema delle disconnessioni causate da polling CLI frequente.
        """
        if not VPN_PROVIDERS.get(provider_key):
            return False
        return self._has_vpn_interface()

    def is_connected_verified(self, provider_key) -> bool:
        """
        Check approfondito via CLI status — usare solo quando necessario
        (connessione/disconnessione), non nel loop di refresh.
        """
        info = VPN_PROVIDERS.get(provider_key)
        if not info:
            return False
        try:
            _, output = self._run(info['status'], provider_key, timeout=8)
            return bool(re.search(info.get('connected_pattern', 'connected'),
                                  output, re.IGNORECASE))
        except Exception:
            return False

    def get_status_text(self, provider_key) -> str:
        info = VPN_PROVIDERS.get(provider_key)
        if not info:
            return ""
        _, output = self._run(info['status'], provider_key, timeout=8)
        return output[:120]


# ============================================================================
# CONFIG
# ============================================================================
class Config:
    DEFAULT_CONFIG = {
        'network': {
            'tor_check_api': 'https://check.torproject.org/api/ip',
            'ip_apis':       'https://api.ipify.org,https://icanhazip.com,https://checkip.amazonaws.com',
            'geo_api':       'http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,isp,reverse,query',
        },
        'timing': {
            'api_timeout':        '10',
            'api_timeout_fast':   '5',
            'anonsurf_timeout':   '60',
            'tor_stop_wait':      '8',
            'refresh_interval':   '15000',
            'auto_change_interval': '100000',
            'tor_verify_attempts':  '15',
            'tor_verify_interval':  '3',
        },
        'gui': {
            'window_width':  '700',
            'window_height': '900',
            'max_log_lines': '100',
        },
        'logging': {
            'enable_file_log':  'true',
            'log_filename':     'anonsurf_gui.log',
            'log_level':        'INFO',
            'max_log_size':     '5242880',
            'log_backup_count': '3',
        },
        'wireguard': {
            'profiles_dir': 'wireguard_profiles',
        },
    }

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = BASE_DIR / 'config.ini'
        self._load_config()

    def _load_config(self):
        for section, values in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for key, value in values.items():
                self.config.set(section, key, value)
        if self.config_file.exists():
            try:
                self.config.read(self.config_file)
            except Exception as e:
                print(f"Errore config.ini: {e}")

    def get(self, section, key, fallback=None):
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_int(self, section, key, fallback=0):
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_bool(self, section, key, fallback=False):
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_list(self, section, key, fallback=None):
        try:
            return [x.strip() for x in self.config.get(section, key).split(',')]
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback or []


CONFIG = Config()


# ============================================================================
# LOGGER
# ============================================================================
class AppLogger:
    def __init__(self, gui_callback=None):
        self.gui_callback = gui_callback
        self.file_logger = None
        self._setup_file_logger()

    def _setup_file_logger(self):
        if not CONFIG.get_bool('logging', 'enable_file_log', True):
            return
        log_file   = BASE_DIR / CONFIG.get('logging', 'log_filename', 'anonsurf_gui.log')
        log_level  = getattr(logging, CONFIG.get('logging', 'log_level', 'INFO').upper(), logging.INFO)
        max_size   = CONFIG.get_int('logging', 'max_log_size', 5242880)
        backup_cnt = CONFIG.get_int('logging', 'log_backup_count', 3)
        self.file_logger = logging.getLogger('AnonSurfGUI')
        self.file_logger.setLevel(log_level)
        self.file_logger.handlers.clear()
        handler = (RotatingFileHandler(log_file, maxBytes=max_size, backupCount=backup_cnt)
                   if max_size > 0 else logging.FileHandler(log_file))
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        self.file_logger.addHandler(handler)

    def _file(self, level, msg):
        if self.file_logger:
            getattr(self.file_logger, level.lower(), self.file_logger.info)(msg)

    def _gui(self, msg):
        if self.gui_callback:
            self.gui_callback(msg)

    def info(self, msg, gui=True):
        self._file('INFO', msg)
        if gui: self._gui(msg)

    def warning(self, msg, gui=True):
        self._file('WARNING', msg)
        if gui: self._gui(f"⚠ {msg}")

    def error(self, msg, diagnostic_key=None, gui=True):
        self._file('ERROR', msg)
        if gui: self._gui(f"✗ {msg}")

    def debug(self, msg):
        self._file('DEBUG', msg)

    def success(self, msg, gui=True):
        self._file('INFO', f"SUCCESS: {msg}")
        if gui: self._gui(f"✓ {msg}")


# ============================================================================
# NETWORK STATE MANAGER
# ============================================================================
class NetworkStateManager:
    def __init__(self, logger):
        self.state_dir = Path('/tmp/anonsurf_gui_state')
        self.tor_was_active_on_start = False
        self.network_saved = False
        self.logger = logger
        self.original_ip = None

    def save_network_state(self):
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            resolv = Path('/etc/resolv.conf')
            if resolv.exists():
                shutil.copy2(resolv, self.state_dir / 'resolv.conf.backup')
            try:
                r = subprocess.run(['iptables-save'], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    (self.state_dir / 'iptables.backup').write_text(r.stdout)
            except Exception:
                pass
            (self.state_dir / 'state.json').write_text(json.dumps({
                'timestamp':      datetime.now().isoformat(),
                'tor_was_active': self.tor_was_active_on_start,
                'original_ip':    self.original_ip,
            }))
            self.network_saved = True
            return True
        except Exception as e:
            self.logger.debug(f"Errore salvataggio stato rete: {e}")
            return False

    def restore_network_state(self):
        if not self.network_saved or not self.state_dir.exists():
            return False
        try:
            backup = self.state_dir / 'resolv.conf.backup'
            if backup.exists():
                shutil.copy2(backup, '/etc/resolv.conf')
            for cmd in [
                ['iptables', '-F'], ['iptables', '-t', 'nat', '-F'],
                ['iptables', '-t', 'mangle', '-F'],
                ['iptables', '-P', 'INPUT', 'ACCEPT'],
                ['iptables', '-P', 'FORWARD', 'ACCEPT'],
                ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
            ]:
                subprocess.run(cmd, capture_output=True, timeout=10)
            for svc in ['NetworkManager', 'networking', 'systemd-networkd']:
                try:
                    r = subprocess.run(['systemctl', 'restart', svc],
                                       capture_output=True, timeout=30)
                    if r.returncode == 0:
                        break
                except Exception:
                    continue
            return True
        except Exception as e:
            self.logger.debug(f"Errore ripristino rete: {e}")
            return False

    def cleanup(self):
        try:
            if self.state_dir.exists():
                shutil.rmtree(self.state_dir)
        except Exception:
            pass


# ============================================================================
# WIREGUARD MANAGER
# ============================================================================
class WireGuardManager:
    def __init__(self, logger):
        self.logger = logger
        profiles_subdir = CONFIG.get('wireguard', 'profiles_dir', 'wireguard_profiles')
        self.profiles_dir = BASE_DIR / profiles_subdir
        self.profiles_dir.mkdir(exist_ok=True)
        self._active_profile = None

    def is_available(self):
        return shutil.which('wg-quick') is not None and shutil.which('wg') is not None

    def get_profiles(self):
        return sorted([p.stem for p in self.profiles_dir.glob("*.conf")])

    def get_profiles_dir(self):
        return self.profiles_dir

    def _find_active(self):
        try:
            r = subprocess.run(['wg', 'show', 'interfaces'],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().split()[0]
        except Exception:
            pass
        return None

    def is_connected(self):
        return self._find_active() is not None

    def connect(self, profile_name) -> bool:
        conf = self.profiles_dir / f"{profile_name}.conf"
        if not conf.exists():
            self.logger.error(f"Profilo WG non trovato: {profile_name}")
            return False
        try:
            r = subprocess.run(['wg-quick', 'up', str(conf)],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                self._active_profile = profile_name
                self.logger.success(f"WireGuard attivo: {profile_name}")
                return True
            self.logger.error(f"wg-quick up fallito: {(r.stderr or '').strip()[:100]}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout connessione WireGuard")
            return False
        except Exception as e:
            self.logger.error(f"Errore WireGuard: {e}")
            return False

    def disconnect(self) -> bool:
        target = self._active_profile or self._find_active()
        if not target:
            return True
        try:
            conf = self.profiles_dir / f"{target}.conf"
            cmd = ['wg-quick', 'down', str(conf) if conf.exists() else target]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                self._active_profile = None
                self.logger.success("WireGuard disconnesso")
                return True
            self.logger.error(f"wg-quick down fallito: {(r.stderr or '').strip()[:100]}")
            return False
        except Exception as e:
            self.logger.error(f"Errore disconnessione WG: {e}")
            return False


# ============================================================================
# BRIDGE MANAGER
# ============================================================================
class BridgeManager:
    TORRC_PATH   = Path('/etc/tor/torrc')
    TORRC_BACKUP = BASE_DIR / 'torrc.backup'
    BRIDGES_FILE = BASE_DIR / 'bridges.conf'

    TRANSPORT_PLUGINS = {
        'obfs4':      'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy',
        'snowflake':  'ClientTransportPlugin snowflake exec /usr/bin/snowflake-client',
        'meek-azure': 'ClientTransportPlugin meek_lite,obfs4 exec /usr/bin/obfs4proxy',
        'webtunnel':  'ClientTransportPlugin webtunnel exec /usr/bin/webtunnel-client',
    }

    def __init__(self, logger):
        self.logger = logger

    def has_bridges(self):
        return self.BRIDGES_FILE.exists() and self.BRIDGES_FILE.stat().st_size > 10

    def load_bridges(self):
        if not self.BRIDGES_FILE.exists():
            return 'obfs4', ''
        try:
            transport, bridge_lines = 'obfs4', []
            for line in self.BRIDGES_FILE.read_text().strip().split('\n'):
                if line.startswith('#transport:'):
                    transport = line.split(':', 1)[1].strip()
                elif line.strip() and not line.startswith('#'):
                    bridge_lines.append(line.strip())
            return transport, '\n'.join(bridge_lines)
        except Exception:
            return 'obfs4', ''

    def save_bridges(self, transport, bridges_text):
        try:
            self.BRIDGES_FILE.write_text(f"#transport:{transport}\n{bridges_text.strip()}\n")
            return True
        except Exception as e:
            self.logger.error(f"Errore salvataggio bridge: {e}")
            return False

    def apply_to_torrc(self, transport, bridges_text):
        if not self.TORRC_PATH.exists():
            self.logger.error("/etc/tor/torrc non trovato")
            return False
        try:
            if not self.TORRC_BACKUP.exists():
                shutil.copy2(self.TORRC_PATH, self.TORRC_BACKUP)
                self.logger.info("Backup torrc creato")
            base = self.TORRC_BACKUP.read_text()
            cleaned = self._strip_bridge_block(base)
            lines = [l.strip() for l in bridges_text.strip().split('\n') if l.strip()]
            block = "\n# === AnonSurf GUI — Bridge Config ===\nUseBridges 1\n"
            if transport in self.TRANSPORT_PLUGINS:
                block += self.TRANSPORT_PLUGINS[transport] + "\n"
            for line in lines:
                block += (line if line.startswith('Bridge ') else f"Bridge {line}") + "\n"
            block += "# === Fine Bridge Config ===\n"
            self.TORRC_PATH.write_text(cleaned + block)
            self.logger.success(f"Bridge {transport} applicati")
            return True
        except PermissionError:
            self.logger.error("Permesso negato — serve root")
            return False
        except Exception as e:
            self.logger.error(f"Errore torrc: {e}")
            return False

    def remove_from_torrc(self):
        try:
            if self.TORRC_BACKUP.exists():
                shutil.copy2(self.TORRC_BACKUP, self.TORRC_PATH)
            else:
                self.TORRC_PATH.write_text(
                    self._strip_bridge_block(self.TORRC_PATH.read_text()))
            self.logger.success("torrc ripristinato")
            return True
        except Exception as e:
            self.logger.error(f"Errore ripristino torrc: {e}")
            return False

    def _strip_bridge_block(self, content):
        result, skip = [], False
        for line in content.split('\n'):
            if '=== AnonSurf GUI — Bridge Config ===' in line:
                skip = True
            elif '=== Fine Bridge Config ===' in line:
                skip = False
                continue
            elif not skip:
                s = line.strip()
                if not (s.startswith('UseBridges') or
                        s.startswith('ClientTransportPlugin') or
                        s.startswith('Bridge ')):
                    result.append(line)
        return '\n'.join(result)

    def bridges_active(self):
        if not self.TORRC_PATH.exists():
            return False
        try:
            return '=== AnonSurf GUI — Bridge Config ===' in self.TORRC_PATH.read_text()
        except Exception:
            return False

    def check_obfs4proxy(self):
        return shutil.which('obfs4proxy') is not None

    def check_snowflake(self):
        return shutil.which('snowflake-client') is not None

    def get_bridge_lines(self) -> list:
        """
        Legge bridges.conf e ritorna lista di bridge lines attive
        (ignora righe vuote e commenti).
        """
        if not self.BRIDGES_FILE.exists():
            return []
        result = []
        transport = 'obfs4'
        try:
            for line in self.BRIDGES_FILE.read_text().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('transport:'):
                    transport = line.split(':', 1)[1].strip()
                    continue
                result.append((transport, line))
        except Exception:
            pass
        return result

    def try_bridges_in_sequence(self, progress_cb=None) -> bool:
        """
        Prova i bridge di bridges.conf in sequenza.
        Applica il primo che permette a Tor di bootstrappare.
        Ritorna True se un bridge funziona, False se nessuno funziona.
        """
        bridges = self.get_bridge_lines()
        if not bridges:
            self.logger.info("Nessun bridge configurato in bridges.conf")
            return False

        self.logger.info(f"Provo {len(bridges)} bridge in sequenza...")

        for idx, (transport, bridge_line) in enumerate(bridges, 1):
            if progress_cb:
                progress_cb(idx, len(bridges), bridge_line[:50])
            self.logger.info(f"Bridge {idx}/{len(bridges)}: {bridge_line[:40]}...")

            # Applica questo bridge al torrc
            ok = self.apply_to_torrc(transport, bridge_line)
            if not ok:
                continue

            # Riavvia Tor con questo bridge
            try:
                subprocess.run(['systemctl', 'restart', 'tor'],
                               capture_output=True, timeout=20)
            except Exception:
                try:
                    subprocess.run(['pkill', '-x', 'tor'],
                                   capture_output=True, timeout=5)
                    time.sleep(2)
                    subprocess.Popen(
                        [shutil.which('tor') or '/usr/bin/tor'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

            # Aspetta bootstrap (max 30s)
            import socket as _sock
            for _ in range(10):
                time.sleep(3)
                try:
                    s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex(('127.0.0.1', 9050)) == 0:
                        s.close()
                        self.logger.success(
                            f"Bridge {idx} funziona: {bridge_line[:40]}")
                        return True
                    s.close()
                except Exception:
                    pass

            self.logger.debug(f"Bridge {idx} non risponde, provo il prossimo...")

        self.logger.warning(
            "Nessun bridge ha funzionato.\n"
            "Verifica le bridge lines in bridges.conf.")
        return False



# ============================================================================
# CASCADE MANAGER v2 — NO iptables, GNOME proxy + torsocks
# ============================================================================
class CascadeManager:
    """
    Modalità Cascata VPN → Tor — implementazione SENZA iptables.

    Architettura:
      App/Browser → GNOME System Proxy (SOCKS5 127.0.0.1:9050)
                  → Tor daemon locale (porta 9050)
                  → Tunnel VPN Surfshark (intatto, non modificato)
                  → Server Surfshark → Internet → Exit node Tor

    Cosa fa:
      1. Configura torrc (SocksPort 9050 + ControlPort 9051)
      2. Avvia demone Tor via systemctl (usa VPN come default route)
      3. Aspetta bootstrap Tor (socket 9050)
      4. Imposta proxy GNOME di sistema come utente originale (SUDO_USER)
      5. Setta variabili ambiente ALL_PROXY per terminale
      6. Verifica la catena con torsocks (IP diverso da VPN = tutto ok)

    Cosa NON fa: toccare iptables, routing, interfacce di rete.
    Nessun conflitto con Surfshark.
    """

    SOCKS_PORT   = 9050
    CTRL_PORT    = 9051
    TORRC_PATH   = Path('/etc/tor/torrc')
    TORRC_BACKUP = Path('/etc/tor/torrc.anonsurf.bak')

    def __init__(self, logger):
        self.logger        = logger
        self._active       = False
        self._sudo_user    = os.environ.get('SUDO_USER', '')
        self._proxy_set    = False

    # ── Helpers utente / DBUS ──────────────────────────────────────────────

    def _get_user_dbus(self) -> str:
        """
        Trova l'indirizzo DBUS della sessione utente originale.
        Su systemd: /run/user/<uid>/bus è il percorso standard.
        """
        if not self._sudo_user:
            return ''
        try:
            r = subprocess.run(['id', '-u', self._sudo_user],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                uid = r.stdout.strip()
                bus = f'/run/user/{uid}/bus'
                if Path(bus).exists():
                    return f'unix:path={bus}'
        except Exception:
            pass
        # Fallback: leggi da /proc di un processo utente
        try:
            r = subprocess.run(['pgrep', '-u', self._sudo_user, '-n'],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                pid = r.stdout.strip().split()[0]
                with open(f'/proc/{pid}/environ', 'rb') as f:
                    for item in f.read().split(b'\x00'):
                        if item.startswith(b'DBUS_SESSION_BUS_ADDRESS='):
                            return item.split(b'=', 1)[1].decode()
        except Exception:
            pass
        return ''

    def _run_as_user(self, cmd: list) -> tuple[bool, str]:
        """Esegue comando come utente originale con sessione DBUS corretta."""
        if not self._sudo_user or self._sudo_user == 'root':
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return r.returncode == 0, (r.stdout + r.stderr).strip()
            except Exception as e:
                return False, str(e)
        dbus = self._get_user_dbus()
        env_prefix = ['env', f'DBUS_SESSION_BUS_ADDRESS={dbus}'] if dbus else []
        full = ['sudo', '-u', self._sudo_user] + env_prefix + cmd
        try:
            r = subprocess.run(full, capture_output=True, text=True, timeout=10)
            return r.returncode == 0, (r.stdout + r.stderr).strip()
        except Exception as e:
            return False, str(e)

    # ── torrc ──────────────────────────────────────────────────────────────

    def _configure_torrc(self) -> bool:
        """
        Assicura che torrc abbia SocksPort 9050 e ControlPort 9051.
        Crea backup prima di modificare.
        """
        if not self.TORRC_PATH.exists():
            self.logger.warning("torrc non trovato — uso configurazione Tor di default")
            return True  # Tor ha default ragionevoli

        try:
            content = self.TORRC_PATH.read_text()
            needed  = []

            # Controlla se le porte sono già attive (non commentate)
            socks_active = bool(re.search(r'^\s*SocksPort\s+9050', content, re.MULTILINE))
            ctrl_active  = bool(re.search(r'^\s*ControlPort\s+9051', content, re.MULTILINE))

            if not socks_active:
                needed.append('SocksPort 9050')
            if not ctrl_active:
                needed.append('ControlPort 9051')
                needed.append('CookieAuthentication 1')

            if needed:
                if not self.TORRC_BACKUP.exists():
                    shutil.copy2(self.TORRC_PATH, self.TORRC_BACKUP)
                    self.logger.info("Backup torrc creato")
                block = '\n# -- AnonSurf Cascade --\n' + '\n'.join(needed) + '\n'
                self.TORRC_PATH.write_text(content + block)
                self.logger.info(f"torrc aggiornato: {', '.join(needed)}")
            else:
                self.logger.debug("torrc già configurato correttamente")
            return True
        except PermissionError:
            self.logger.warning("torrc: permesso negato — Tor userà configurazione esistente")
            return True
        except Exception as e:
            self.logger.warning(f"torrc: {e}")
            return True

    def _restore_torrc(self):
        """Ripristina torrc dal backup."""
        if self.TORRC_BACKUP.exists():
            try:
                shutil.copy2(self.TORRC_BACKUP, self.TORRC_PATH)
                self.logger.info("torrc ripristinato")
            except Exception as e:
                self.logger.warning(f"Ripristino torrc: {e}")

    # ── Tor daemon ─────────────────────────────────────────────────────────

    def _start_tor(self) -> bool:
        """Avvia Tor via systemctl. Fallback: binario diretto."""
        # Prima prova: systemctl
        try:
            r = subprocess.run(['systemctl', 'start', 'tor'],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                self.logger.info("Tor avviato via systemctl")
                return True
            self.logger.debug(f"systemctl start tor: {r.stderr.strip()[:80]}")
        except Exception as e:
            self.logger.debug(f"systemctl: {e}")

        # Fallback: binario diretto
        tor_bin = shutil.which('tor') or '/usr/bin/tor'
        if Path(tor_bin).exists():
            try:
                subprocess.Popen(
                    [tor_bin,
                     '--SocksPort',   str(self.SOCKS_PORT),
                     '--ControlPort', str(self.CTRL_PORT),
                     '--CookieAuthentication', '1',
                     '--Log', 'notice syslog'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.logger.info(f"Tor avviato direttamente: {tor_bin}")
                return True
            except Exception as e:
                self.logger.error(f"Avvio Tor diretto: {e}")

        self.logger.error(
            "Impossibile avviare Tor.\n"
            "Verifica: sudo apt install tor")
        return False

    def _stop_tor(self):
        """Ferma il demone Tor."""
        try:
            subprocess.run(['systemctl', 'stop', 'tor'],
                           capture_output=True, timeout=15)
        except Exception:
            pass
        try:
            subprocess.run(['pkill', '-x', 'tor'], capture_output=True, timeout=5)
        except Exception:
            pass

    def _wait_for_socks(self, attempts: int = 20,
                         callback=None) -> bool:
        """Aspetta che Tor apra la porta SOCKS (max ~60s)."""
        import socket
        for i in range(1, attempts + 1):
            if callback:
                callback(i, attempts)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex(('127.0.0.1', self.SOCKS_PORT)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
            time.sleep(3)
        return False

    def is_running_locally(self) -> bool:
        """Tor è in ascolto su porta 9050?"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(('127.0.0.1', self.SOCKS_PORT))
            s.close()
            return result == 0
        except Exception:
            return False

    # ── GNOME proxy ────────────────────────────────────────────────────────

    def _set_gnome_proxy(self):
        """Imposta proxy GNOME di sistema come utente originale."""
        settings = [
            ['gsettings', 'set', 'org.gnome.system.proxy',
             'mode', 'manual'],
            ['gsettings', 'set', 'org.gnome.system.proxy.socks',
             'host', '127.0.0.1'],
            ['gsettings', 'set', 'org.gnome.system.proxy.socks',
             'port', '9050'],
            ['gsettings', 'set', 'org.gnome.system.proxy',
             'use-same-proxy', 'false'],
        ]
        ok_count = 0
        for cmd in settings:
            ok, out = self._run_as_user(cmd)
            if ok:
                ok_count += 1
            else:
                self.logger.debug(f"gsettings warn: {' '.join(cmd[3:])} → {out[:60]}")

        if ok_count == len(settings):
            self.logger.success("Proxy GNOME impostato: SOCKS5 127.0.0.1:9050")
            self._proxy_set = True
        elif ok_count > 0:
            self.logger.warning(
                f"Proxy GNOME parzialmente impostato ({ok_count}/{len(settings)})\n"
                "Configura manualmente: Impostazioni → Rete → Proxy")
            self._proxy_set = True
        else:
            self.logger.warning(
                "Proxy GNOME non configurabile automaticamente.\n"
                "Vai in Impostazioni → Rete → Proxy → Manuale\n"
                "SOCKS Host: 127.0.0.1  Porta: 9050")

    def _unset_gnome_proxy(self):
        """Ripristina proxy GNOME a 'nessuno'."""
        ok, _ = self._run_as_user(
            ['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none'])
        if ok:
            self.logger.success("Proxy GNOME rimosso")
        self._proxy_set = False

    # ── Verifica cascata ───────────────────────────────────────────────────

    @staticmethod
    def _is_valid_ip(s: str) -> bool:
        """
        Verifica che la stringa sia un indirizzo IPv4 o IPv6 valido.
        Rifiuta qualsiasi risposta JSON, HTML, messaggi di errore, ecc.
        """
        if not s or len(s) > 45:
            return False
        # IPv4: 4 gruppi di 1-3 cifre separati da punti
        ipv4 = re.match(
            r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', s.strip())
        if ipv4:
            return all(0 <= int(g) <= 255 for g in ipv4.groups())
        # IPv6: almeno due segmenti esadecimali separati da :
        if ':' in s and re.match(r'^[0-9a-fA-F:]+$', s.strip()):
            return True
        return False

    def verify(self) -> tuple[bool, str]:
        """
        Verifica che il traffico passi per Tor via torsocks.
        Prova più API con validazione IP rigorosa — ignora rate-limit,
        errori JSON, HTML e qualsiasi risposta non-IP.
        """
        if not shutil.which('torsocks'):
            self.logger.warning(
                "torsocks non installato — verifica manuale.\n"
                "sudo apt install torsocks")
            return False, ""

        # API ordinate per affidabilità su exit node Tor:
        # - ifconfig.me e ipinfo.io/ip hanno limiti meno aggressivi
        # - icanhazip.com è gestito da Cloudflare, spesso blocca Tor
        # - api.ipify.org a volte restituisce {"error":"Too Many Requests"}
        apis = [
            'https://ifconfig.me/ip',
            'https://ipinfo.io/ip',
            'https://icanhazip.com',
            'https://api.ipify.org',
            'https://checkip.amazonaws.com',
            'https://ipecho.net/plain',
        ]

        for api in apis:
            try:
                r = subprocess.run(
                    ['torsocks', 'curl', '-s', '--max-time', '12',
                     '--user-agent', 'curl/7.68.0', api],
                    capture_output=True, text=True, timeout=18,
                )
                if r.returncode != 0:
                    self.logger.debug(f"torsocks {api}: returncode {r.returncode}")
                    continue

                ip = (r.stdout or '').strip()

                # Validazione rigorosa: deve essere un IP, non JSON/HTML/errore
                if not self._is_valid_ip(ip):
                    self.logger.debug(
                        f"torsocks {api}: risposta non-IP: {ip[:40]}")
                    continue

                self.logger.success(f"Tor exit IP verificato: {ip}")
                return True, ip

            except Exception as e:
                self.logger.debug(f"torsocks {api}: {e}")

        self.logger.warning("Nessuna API ha restituito un IP valido via torsocks.")
        return False, ""

    def get_tor_exit_ip_via_check(self) -> tuple[bool, str]:
        """
        Controlla check.torproject.org tramite torsocks.
        Restituisce (is_tor, ip).
        """
        if not shutil.which('torsocks'):
            return False, ''
        try:
            r = subprocess.run(
                ['torsocks', 'curl', '-s', '--max-time', '15',
                 'https://check.torproject.org/api/ip'],
                capture_output=True, text=True, timeout=20,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                return data.get('IsTor', False), data.get('IP', '')
        except Exception as e:
            self.logger.debug(f"check.torproject via torsocks: {e}")
        return False, ''

    # ── Tor Circuit Info ───────────────────────────────────────────────────

    def get_circuit_info(self) -> list:
        """
        Si connette alla control port di Tor e legge il circuito attivo.
        Ritorna lista di dict con info sui relay.
        """
        import socket
        relays = []
        try:
            # Leggi cookie di autenticazione
            cookie_path = Path('/var/run/tor/control.authcookie')
            if not cookie_path.exists():
                cookie_path = Path('/run/tor/control.authcookie')
            if not cookie_path.exists():
                return relays

            with open(cookie_path, 'rb') as f:
                cookie = f.read().hex()

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(('127.0.0.1', self.CTRL_PORT))

            def send_recv(cmd: str) -> str:
                s.send((cmd + '\r\n').encode())
                buf = b''
                while not buf.endswith(b'\r\n'):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode('utf-8', errors='replace')

            # Autenticazione
            resp = send_recv(f'AUTHENTICATE {cookie}')
            if '250 OK' not in resp:
                s.close()
                return relays

            # Circuiti attivi
            resp = send_recv('GETINFO circuit-status')
            s.send(b'QUIT\r\n')
            s.close()

            # Parsing: cerca relay con country info
            for line in resp.split('\n'):
                line = line.strip()
                if 'BUILT' in line or 'EXTENDED' in line:
                    # Estrai fingerprints
                    parts = line.split()
                    for part in parts:
                        if part.startswith('$') and '~' in part:
                            fp, name = part[1:].split('~', 1)
                            relays.append({
                                'fingerprint': fp[:8] + '...',
                                'name': name,
                            })
                    break  # Prendi solo il primo circuito BUILT

        except Exception as e:
            self.logger.debug(f"Circuit info: {e}")
        return relays

    # ── API pubblica ───────────────────────────────────────────────────────

    def start(self, progress_callback=None) -> bool:
        """
        Avvia cascata VPN→Tor:
        1. Configura torrc
        2. Avvia demone Tor (usa VPN come default route → bootstrap OK)
        3. Aspetta porta 9050
        4. Imposta proxy GNOME di sistema
        """
        self.logger.info("=== Avvio Cascata VPN→Tor ===")
        self.logger.info("Approccio: SOCKS5 proxy, NO iptables")

        # 1. Configura torrc
        self._configure_torrc()

        # 2. Avvia Tor
        if not self._start_tor():
            return False

        # 3. Aspetta bootstrap
        self.logger.info(
            "Tor si connette tramite tunnel VPN...\n"
            "(bootstrap ~ 15-45s, dipende dalla velocità VPN)")
        if not self._wait_for_socks(attempts=20, callback=progress_callback):
            self.logger.error(
                "Timeout bootstrap Tor.\n"
                "Possibili cause: Tor non installato, "
                "porta 9050 bloccata localmente.")
            self._stop_tor()
            return False

        # 4. GNOME proxy
        self._set_gnome_proxy()

        self._active = True
        self.logger.success(
            "╔══════════════════════════════════════╗\n"
            "║  CASCATA ATTIVA: VPN → TOR           ║\n"
            "║  Proxy: SOCKS5 127.0.0.1:9050        ║\n"
            "║  Browser e app GTK: protetti         ║\n"
            "║  Terminale: usa torsocks <comando>   ║\n"
            "╚══════════════════════════════════════╝")
        return True

    def stop(self) -> bool:
        """Ferma cascata: rimuove proxy GNOME, ferma Tor, ripristina torrc."""
        self.logger.info("Arresto cascata...")
        self._unset_gnome_proxy()
        self._stop_tor()
        self._restore_torrc()
        self._active = False
        self.logger.success("Cascata fermata — connessione diretta ripristinata")
        return True

    def is_active(self) -> bool:
        return self._active and self.is_running_locally()


# TOR MANAGER
# ============================================================================
class TorManager:
    def __init__(self, logger):
        self.logger = logger
        self.anonsurf_path = None
        self._find_anonsurf()
        self._cancel_flag = threading.Event()
        self._operation_lock = threading.Lock()
        self._current_operation = None

    def _find_anonsurf(self):
        for path in ['/usr/bin/anonsurf', '/usr/local/bin/anonsurf', '/usr/sbin/anonsurf']:
            if os.path.exists(path) and os.access(path, os.X_OK):
                self.anonsurf_path = path
                return
        try:
            r = subprocess.run(['which', 'anonsurf'], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                self.anonsurf_path = r.stdout.strip()
        except Exception:
            pass

    def is_available(self):
        if not self.anonsurf_path:
            self._find_anonsurf()
        return self.anonsurf_path is not None

    def cancel_operation(self):
        self._cancel_flag.set()
        self.logger.info("Annullamento operazione...")

    def is_cancelled(self):
        return self._cancel_flag.is_set()

    def _reset_cancel(self):
        self._cancel_flag.clear()

    def execute(self, command, timeout=None):
        if not self.is_available():
            self.logger.error("AnonSurf non trovato")
            return False, "", "non trovato", -1
        if timeout is None:
            timeout = CONFIG.get_int('timing', 'anonsurf_timeout', 60)
        try:
            process = subprocess.Popen(
                f"{self.anonsurf_path} {command}", shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                rc = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.logger.error(f"Timeout '{command}'")
                return False, stdout, stderr, -1
            if rc == 0:
                self.logger.success(f"Comando '{command}' OK")
            else:
                self.logger.warning(f"Comando '{command}' codice {rc}")
            return rc == 0, stdout, stderr, rc
        except Exception as e:
            self.logger.error(f"Errore esecuzione: {e}")
            return False, "", str(e), -1

    def start(self, progress_callback=None, cascade_mode: bool = False):
        """
        Avvia AnonSurf/Tor.
        cascade_mode=True: verifica il bootstrap localmente (porta 9050)
                           invece di check.torproject.org, necessario quando
                           tutto il traffico esce dalla VPN e IsTor=False sempre.
        """
        with self._operation_lock:
            if self._current_operation:
                self.logger.warning("Operazione già in corso")
                return False
            self._current_operation = "start"
        self._reset_cancel()
        try:
            mode_str = "Cascata VPN→Tor" if cascade_mode else "standard"
            self.logger.info(f"Avvio AnonSurf [{mode_str}]...")
            ok, _, _, _ = self.execute('start')
            if not ok:
                self.logger.error("Comando start fallito")
                return False
            attempts = CONFIG.get_int('timing', 'tor_verify_attempts', 15)
            interval = CONFIG.get_int('timing', 'tor_verify_interval', 3)
            if cascade_mode:
                self.logger.info(
                    f"Verifica bootstrap locale porta 9050 ({attempts} tentativi)...")
            else:
                self.logger.info(f"Verifica bootstrap remoto ({attempts} tentativi)...")
            for attempt in range(1, attempts + 1):
                if self.is_cancelled():
                    return False
                if progress_callback:
                    progress_callback(attempt, attempts)
                is_tor, ip = self._check_tor_status(fast=True, cascade_mode=cascade_mode)
                if is_tor:
                    if cascade_mode:
                        self.logger.success("Tor ATTIVO in cascata! (porta 9050 aperta)")
                    else:
                        self.logger.success(f"Tor ATTIVO! IP: {ip}")
                    return True
                for _ in range(interval):
                    if self.is_cancelled():
                        return False
                    time.sleep(1)
            self.logger.error(f"Tor non attivo dopo {attempts * interval}s")
            return False
        finally:
            with self._operation_lock:
                self._current_operation = None

    def stop(self):
        if self._current_operation == "start":
            self.cancel_operation()
            time.sleep(1)
        with self._operation_lock:
            self._current_operation = "stop"
        try:
            self.logger.info("Arresto AnonSurf...")
            ok, _, _, _ = self.execute('stop')
            if ok:
                time.sleep(CONFIG.get_int('timing', 'tor_stop_wait', 8))
                self.logger.success("AnonSurf fermato")
                return True
            return False
        finally:
            with self._operation_lock:
                self._current_operation = None

    def change_identity(self):
        self.logger.info("Cambio identità...")
        ok, _, _, _ = self.execute('change', timeout=30)
        if ok:
            time.sleep(3)
            self.logger.success("Identità cambiata")
        return ok

    def is_running_locally(self) -> bool:
        """
        Verifica se Tor è attivo localmente controllando:
          1. Porta SOCKS 9050 in ascolto (metodo più affidabile)
          2. Porta controllo 9051 (fallback)
          3. Processo 'tor' attivo (ultimo fallback)
        Non fa richieste HTTP — funziona anche quando tutto il traffico
        passa per la VPN in modalità cascata.
        """
        import socket
        for port in (9050, 9051):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex(('127.0.0.1', port))
                s.close()
                if result == 0:
                    self.logger.debug(f"Tor locale: porta {port} aperta")
                    return True
            except Exception:
                pass
        # Fallback: controlla processo
        try:
            r = subprocess.run(['pgrep', '-x', 'tor'],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                self.logger.debug("Tor locale: processo attivo")
                return True
        except Exception:
            pass
        return False

    def _check_tor_status(self, fast=False, cascade_mode=False):
        """
        In modalità cascade_mode usa is_running_locally() per il bootstrap
        (check.torproject.org non è raggiungibile via Tor quando il traffico
        esce dalla VPN — IsTor risulterebbe sempre False).
        In modalità normale usa l'API remota come prima.
        """
        if cascade_mode:
            running = self.is_running_locally()
            # In cascata non possiamo ottenere l'IP Tor facilmente, usiamo stringa vuota
            return running, ''

        url = CONFIG.get('network', 'tor_check_api', 'https://check.torproject.org/api/ip')
        timeout = CONFIG.get_int('timing', 'api_timeout_fast' if fast else 'api_timeout',
                                  5 if fast else 10)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                data = json.loads(r.read().decode())
                return data.get('IsTor', False), data.get('IP', '')
        except Exception as e:
            self.logger.debug(f"Check Tor remoto: {e}")
            return False, ""

    def get_status(self):
        is_tor, ip = self._check_tor_status()
        if not ip:
            ip = self._get_simple_ip()
        result = {'is_tor': is_tor, 'ip': ip or '-'}
        if ip and ip != '-':
            result.update(self._get_geo_info(ip))
        return result

    def _get_simple_ip(self):
        apis = CONFIG.get_list('network', 'ip_apis', ['https://api.ipify.org'])
        timeout = CONFIG.get_int('timing', 'api_timeout_fast', 5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for url in apis:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    ip = r.read().decode().strip()
                    if ip and len(ip) < 50:
                        return ip
            except Exception:
                continue
        return None

    def _get_geo_info(self, ip):
        result = {'city': '-', 'country': '-', 'country_code': '-',
                  'region': '-', 'isp': '-', 'hostname': '-'}
        try:
            geo_api = CONFIG.get('network', 'geo_api', 'http://ip-api.com/json/{ip}')
            url = geo_api.replace('{ip}', ip)
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.68.0'})
            with urllib.request.urlopen(req, timeout=CONFIG.get_int('timing', 'api_timeout', 10)) as r:
                data = json.loads(r.read().decode())
                if data.get('status') == 'success':
                    result.update({
                        'city':         data.get('city', '-') or '-',
                        'country':      data.get('country', '-') or '-',
                        'country_code': data.get('countryCode', '-') or '-',
                        'region':       data.get('regionName', '-') or '-',
                        'isp':          data.get('isp', '-') or '-',
                        'hostname':     data.get('reverse', '-') or '-',
                    })
        except Exception:
            pass
        return result


# ============================================================================
# ISP TOR BLOCK CHECKER
# ============================================================================
class ISPTorBlockChecker:
    TOR_DIRECTORY_AUTHORITIES = [
        ("128.31.0.34", 9101), ("86.59.21.38", 443),
        ("194.109.206.212", 443), ("199.58.81.140", 443),
        ("204.13.164.118", 443),
    ]
    TOR_CHECK_ENDPOINTS = [
        "https://check.torproject.org",
        "https://bridges.torproject.org",
        "https://www.torproject.org",
    ]
    INTERNET_CHECK_ENDPOINTS = [
        "https://www.google.com",
        "https://www.cloudflare.com",
        "https://www.amazon.com",
    ]

    def __init__(self, logger=None):
        self.logger = logger
        self.check_timeout = 5

    def _check_tcp(self, host, port, timeout=3):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def _check_https(self, url, timeout=5):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status == 200
        except Exception:
            return False

    def run_full_check(self):
        results = {'internet_ok': False, 'tor_sites_ok': False,
                   'tor_authorities_ok': False, 'likely_blocked': False, 'details': []}
        for url in self.INTERNET_CHECK_ENDPOINTS:
            if self._check_https(url, self.check_timeout):
                results['internet_ok'] = True
                results['details'].append(f"✓ Internet OK ({url})")
                break
        if not results['internet_ok']:
            results['details'].append("✗ Connessione internet non disponibile")
            return False, results
        reachable = sum(1 for u in self.TOR_CHECK_ENDPOINTS if self._check_https(u, self.check_timeout))
        results['tor_sites_ok'] = reachable > 0
        results['details'].append(f"{'✓' if reachable else '✗'} Siti Tor: {reachable}/{len(self.TOR_CHECK_ENDPOINTS)}")
        auth_ok = sum(1 for h, p in self.TOR_DIRECTORY_AUTHORITIES if self._check_tcp(h, p, 3))
        results['tor_authorities_ok'] = auth_ok >= 2
        results['details'].append(f"{'✓' if auth_ok >= 2 else '✗'} Directory Authorities: {auth_ok}/5")
        if not results['tor_sites_ok'] and not results['tor_authorities_ok']:
            results['likely_blocked'] = True
        elif not results['tor_authorities_ok']:
            results['likely_blocked'] = True
        return results['likely_blocked'], results


# ============================================================================
# BRIDGE SETTINGS WINDOW
# ============================================================================
class BridgeSettingsWindow:
    """
    Finestra semplice per visualizzare e modificare bridges.conf.
    Il file contiene bridge lines una per riga.
    Formato:
      # commento
      transport:<tipo>        (opzionale — default obfs4)
      <bridge line completa>
      <bridge line completa>
      ...
    """

    def __init__(self, parent, bridge_manager, on_close_callback=None):
        self.bridge_manager    = bridge_manager
        self.on_close_callback = on_close_callback

        self.win = tk.Toplevel(parent)
        self.win.title("⚙ Bridge Tor — bridges.conf")
        self.win.configure(bg="#2b2b2b")
        self.win.geometry("620x480")
        self.win.resizable(True, True)
        self.win.minsize(500, 380)
        self.win.transient(parent)
        self.win.grab_set()
        x = (self.win.winfo_screenwidth() - 620) // 2
        y = (self.win.winfo_screenheight() - 480) // 2
        self.win.geometry(f"+{x}+{y}")
        if on_close_callback:
            self.win.protocol("WM_DELETE_WINDOW",
                              lambda: (self.win.destroy(), on_close_callback()))

        self._build()
        self._load()

    def _build(self):
        bg = "#2b2b2b"

        tk.Label(self.win, text="⚙ Bridge Tor",
                 font=("Arial", 14, "bold"), bg=bg, fg="#00bcd4").pack(pady=(14, 2))

        # Path del file
        path_f = tk.Frame(self.win, bg=bg)
        path_f.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(path_f, text="File:",
                 font=("Arial", 8), bg=bg, fg="#888").pack(side="left")
        tk.Label(path_f,
                 text=str(self.bridge_manager.BRIDGES_FILE),
                 font=("Courier", 8), bg=bg, fg="#90caf9").pack(side="left", padx=4)

        # Info formato
        info_f = tk.Frame(self.win, bg="#3a3a3a", pady=5)
        info_f.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(info_f,
                 text="Inserisci una bridge line per riga. Righe con # sono commenti. "
                      "Opzionale: riga 'transport:obfs4' prima delle bridge lines.",
                 font=("Arial", 8), bg="#3a3a3a", fg="#aaa",
                 justify="left").pack(anchor="w", padx=8)

        # Editor testo
        self.text = scrolledtext.ScrolledText(
            self.win, bg="#1e1e1e", fg="#ddd",
            font=("Courier", 9), wrap="none",
            insertbackground="#ddd")
        self.text.pack(fill="both", expand=True, padx=16, pady=(0, 6))

        # Stato bridge attivi
        active = self.bridge_manager.bridges_active()
        self.status_lbl = tk.Label(
            self.win,
            text="● Bridge ATTIVI in torrc" if active else "○ Bridge non applicati a torrc",
            font=("Arial", 8, "bold"), bg=bg,
            fg="#81c784" if active else "#888")
        self.status_lbl.pack(pady=(0, 4))

        # Pulsanti
        bf = tk.Frame(self.win, bg=bg)
        bf.pack(fill="x", padx=16, pady=(0, 14))

        tk.Button(bf, text="💾 Salva", command=self._save,
                  bg="#2196f3", fg="#fff",
                  font=("Arial", 10, "bold"), width=10).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="✗ Rimuovi da torrc", command=self._remove_torrc,
                  bg="#f44336", fg="#fff",
                  font=("Arial", 10, "bold"), width=18).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="Chiudi", command=self.win.destroy,
                  bg="#555", fg="#fff",
                  font=("Arial", 10), width=8).pack(side="right")

    def _load(self):
        """Carica bridges.conf nell'editor."""
        try:
            if self.bridge_manager.BRIDGES_FILE.exists():
                content = self.bridge_manager.BRIDGES_FILE.read_text()
            else:
                content = (
                    "# Bridge Tor — una bridge line per riga\n"
                    "# Ottieni bridge: https://bridges.torproject.org\n"
                    "# Formato: obfs4 <IP:PORT> <FINGERPRINT> cert=... iat-mode=0\n"
                    "#\n"
                    "# Linea opzionale per specificare il trasporto:\n"
                    "# transport:obfs4\n"
                    "#\n"
                )
            self.text.delete("1.0", "end")
            self.text.insert("1.0", content)
        except Exception as e:
            self.text.insert("1.0", f"# Errore lettura file: {e}\n")

    def _save(self):
        """Salva il testo corrente in bridges.conf."""
        try:
            content = self.text.get("1.0", "end")
            self.bridge_manager.BRIDGES_FILE.write_text(content)
            messagebox.showinfo("Salvato",
                                f"Bridge salvati in:\n"
                                f"{self.bridge_manager.BRIDGES_FILE}",
                                parent=self.win)
        except Exception as e:
            messagebox.showerror("Errore", f"Salvataggio fallito:\n{e}",
                                 parent=self.win)

    def _remove_torrc(self):
        """Rimuove la configurazione bridge da torrc."""
        if not messagebox.askyesno("Conferma",
                                   "Rimuovere la configurazione bridge da torrc\n"
                                   "e ripristinare l'originale?",
                                   parent=self.win):
            return
        if self.bridge_manager.remove_from_torrc():
            self.status_lbl.config(text="○ Bridge rimossi da torrc", fg="#888")
            messagebox.showinfo("OK", "torrc ripristinato.", parent=self.win)
        else:
            messagebox.showerror("Errore",
                                 "Impossibile modificare torrc.\n"
                                 "Verifica i permessi root.", parent=self.win)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("AnonSurf Control Panel v3.3")

        w = CONFIG.get_int('gui', 'window_width', 700)
        h = CONFIG.get_int('gui', 'window_height', 900)
        self.root.geometry(f"{w}x{h}")
        self.root.configure(bg="#2b2b2b")
        # Responsive: ridimensionabile in entrambe le direzioni
        # minsize impedisce di comprimere la finestra fino a renderla inutile
        self.root.resizable(True, True)
        self.root.minsize(640, 780)

        # Stato
        self.current_mode       = MODE_DIRECT
        self.real_ip            = "Non rilevato"
        self.current_ip         = "..."
        self.auto_change_var    = tk.BooleanVar(value=False)
        self.cascade_var        = tk.BooleanVar(value=False)
        self.closing            = False
        self.operation_in_progress = False
        self.flag_images        = {}

        # VPN tracking
        self.detected_vpns      = {}     # {key: display_name} rilevate all'avvio
        self.active_vpn_type    = WG_DISPLAY  # tipo VPN attualmente selezionato nella UI

        # Manager
        self.logger          = AppLogger(gui_callback=self.log)
        self.network_manager  = NetworkStateManager(self.logger)
        self.tor_manager      = TorManager(self.logger)
        self.cascade_manager  = CascadeManager(self.logger)
        self.wg_manager       = WireGuardManager(self.logger)
        self.ext_vpn_manager  = ExternalVPNManager(self.logger)
        self.bridge_manager   = BridgeManager(self.logger)
        self.isp_checker      = ISPTorBlockChecker(self.logger)

        self.build_ui()
        self.load_saved_ip()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)
        atexit.register(self._cleanup_on_exit)

        self.root.after(100, self._initial_startup)

    # ------------------------------------------------------------------
    # STARTUP
    # ------------------------------------------------------------------
    def _signal_handler(self, signum, frame):
        self.on_closing()

    def _cleanup_on_exit(self):
        if not self.closing:
            self._perform_cleanup()

    def _initial_startup(self):
        self.logger.info("Inizializzazione AnonSurf GUI v3.3...")

        # Rileva VPN installate
        self.detected_vpns = VPNDetector.detect(logger=self.logger)
        if self.detected_vpns:
            names = ", ".join(v for v in self.detected_vpns.values())
            self.logger.success(f"VPN rilevate: {names}")
        else:
            self.logger.info("Nessuna VPN di terze parti rilevata")

        self._populate_vpn_type_selector()
        self._refresh_wg_profiles()

        # Controlla disponibilità WireGuard
        if not self.wg_manager.is_available():
            self.logger.warning("wg-quick non trovato — WireGuard non disponibile")

        threading.Thread(target=self._check_isp_and_start, daemon=True).start()

    def _populate_vpn_type_selector(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

    def _check_isp_and_start(self):
        self.root.after(0, lambda: self.logger.info("Verifica accessibilità rete Tor..."))
        is_blocked, results = self.isp_checker.run_full_check()

        if not results['internet_ok']:
            self.root.after(0, lambda: self.logger.warning("Connessione internet non disponibile"))
            self.root.after(0, self._proceed_with_startup)
            return

        if is_blocked:
            if self.bridge_manager.has_bridges():
                self.root.after(0, lambda: self._offer_saved_bridges(results))
            else:
                self.root.after(0, lambda: self._show_isp_block_dialog(results))
        else:
            self.root.after(0, lambda: self.logger.success("Rete Tor accessibile"))
            self.root.after(0, self._proceed_with_startup)

    def _offer_saved_bridges(self, results):
        """
        Tor bloccato — prova i bridge di bridges.conf in sequenza automaticamente.
        Se non ci sono bridge salvati, mostra il dialogo informativo.
        """
        bridges = self.bridge_manager.get_bridge_lines()
        if bridges:
            self.logger.info(
                f"Tor bloccato — provo {len(bridges)} bridge da bridges.conf...")
            self._try_bridges_fallback()
        else:
            self._show_isp_block_dialog(results)

    def _show_isp_block_dialog(self, results):
        dialog = tk.Toplevel(self.root)
        dialog.title("⚠ Possibile Blocco Tor")
        dialog.configure(bg="#2b2b2b")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("580x500")
        dialog.resizable(False, False)
        x = (dialog.winfo_screenwidth() - 580) // 2
        y = (dialog.winfo_screenheight() - 500) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="⚠️", font=("Arial", 40), bg="#2b2b2b", fg="#ff9800").pack(pady=(12, 3))
        tk.Label(dialog, text="Possibile Blocco Tor Rilevato",
                 font=("Arial", 13, "bold"), bg="#2b2b2b", fg="#ff9800").pack(pady=(0, 8))

        det = tk.LabelFrame(dialog, text="Diagnostica", font=("Arial", 9, "bold"),
                            bg="#3a3a3a", fg="#aaa", padx=10, pady=5)
        det.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(det, text="\n".join(results.get('details', [])),
                 font=("Courier", 8), bg="#3a3a3a", fg="#90caf9",
                 justify="left", anchor="w").pack(anchor="w")

        # Suggerimento cascata se VPN disponibile
        vpn_hint = ""
        if self.detected_vpns or self.wg_manager.get_profiles():
            vpn_hint = ("\n💡 HAI UNA VPN DISPONIBILE!\n"
                        "   Usa la Modalità CASCATA: attiva prima la VPN,\n"
                        "   poi avvia Tor sopra. L'ISP vedrà solo traffico VPN.\n")

        msg = scrolledtext.ScrolledText(dialog, height=10, bg="#1e1e1e", fg="#ddd",
                                         font=("Courier", 9), wrap="word")
        msg.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        msg.insert("1.0",
                   f"{vpn_hint}\n"
                   "ALTRE SOLUZIONI:\n\n"
                   "1. Configura Bridge → pulsante ⚙ Bridge Tor\n"
                   "2. Usa la Modalità CASCATA (VPN → Tor)\n"
                   "   Attiva la VPN nella sezione VPN, poi\n"
                   "   spunta 'Cascata VPN→Tor' e avvia Tor.\n\n"
                   "Puoi continuare comunque (Tor potrebbe non funzionare).")
        msg.config(state="disabled")

        continue_var = tk.BooleanVar(value=False)
        bridge_var   = tk.BooleanVar(value=False)

        def on_continue():
            continue_var.set(True)
            dialog.destroy()

        def on_bridges():
            bridge_var.set(True)
            dialog.destroy()

        bf = tk.Frame(dialog, bg="#2b2b2b")
        bf.pack(fill="x", padx=20, pady=(0, 12))
        tk.Button(bf, text="⚙ Bridge Tor", command=on_bridges,
                  bg="#9c27b0", fg="#fff", font=("Arial", 10, "bold"),
                  width=14).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="🚀 Continua", command=on_continue,
                  bg="#ff9800", fg="#000", font=("Arial", 10, "bold"),
                  width=12).pack(side="left", padx=(0, 6))
        tk.Button(bf, text="✗ Annulla", command=dialog.destroy,
                  bg="#555", fg="#fff", font=("Arial", 10),
                  width=10).pack(side="right")

        dialog.wait_window()

        if bridge_var.get():
            self._open_bridge_settings(on_close_callback=self._proceed_with_startup)
        elif continue_var.get():
            self.logger.warning("Avvio nonostante blocco ISP")
            self._proceed_with_startup()
        else:
            self.status_lbl.config(text="○ CONFIGURAZIONE RICHIESTA", bg="#ff9800")
            self.status_frame.config(bg="#ff9800")

    def _proceed_with_startup(self):
        threading.Thread(target=self._check_and_handle_tor_on_start, daemon=True).start()

    def _try_bridges_fallback(self):
        """
        Chiamato quando Tor non riesce ad avviarsi senza bridge.
        Prova i bridge di bridges.conf in sequenza.
        """
        self.logger.warning(
            "Tor non accessibile direttamente.\n"
            "Tentativo con bridge da bridges.conf...")

        def do_try():
            def progress(idx, total, line):
                self.root.after(0, lambda: self.logger.info(
                    f"Bridge {idx}/{total}: {line}..."))

            ok = self.bridge_manager.try_bridges_in_sequence(progress_cb=progress)
            if ok:
                self.root.after(0, lambda: self.logger.success(
                    "Bridge attivo — avvio Tor..."))
                # Procede con lo startup normale: Tor è ora configurato
                threading.Thread(
                    target=self._check_and_handle_tor_on_start, daemon=True).start()
            else:
                self.root.after(0, lambda: self.logger.warning(
                    "Nessun bridge funzionante.\n"
                    "Apri ⚙ Bridge Tor per aggiornare le bridge lines."))
                self.root.after(0, lambda: self.status_lbl.config(
                    text="○ NESSUN BRIDGE FUNZIONANTE", bg="#b71c1c"))
                self.root.after(0, lambda: self.status_frame.config(bg="#b71c1c"))

        threading.Thread(target=do_try, daemon=True).start()

    def _check_and_handle_tor_on_start(self):
        self.root.after(0, lambda: self.logger.info("Verifica stato rete..."))
        status = self.tor_manager.get_status()
        tor_was_active = status.get('is_tor', False)
        current_ip = status.get('ip', '-')

        self.network_manager.tor_was_active_on_start = tor_was_active
        self.network_manager.original_ip = current_ip if not tor_was_active else None
        self.network_manager.save_network_state()

        if tor_was_active:
            self.root.after(0, lambda: self.logger.warning("Tor attivo — riavvio sessione..."))
            self.tor_manager.stop()
            time.sleep(3)

            def progress(a, t):
                self.root.after(0, lambda: self.logger.info(f"Bootstrap {a}/{t}..."))

            ok = self.tor_manager.start(progress_callback=progress)
            if not ok:
                self.root.after(0, lambda: self.logger.warning("Problema avvio sessione Tor"))
        else:
            self.root.after(0, lambda: self.logger.success("Rete normale — stato salvato"))

        self.root.after(2000, self.schedule_refresh)
        self.root.after(100000, self.schedule_auto_change)

    # ------------------------------------------------------------------
    # UI BUILD
    # ------------------------------------------------------------------
    def build_ui(self):
        bg = "#2b2b2b"

        # Titolo
        tf = tk.Frame(self.root, bg=bg)
        tf.pack(pady=8)
        tk.Label(tf, text="ANONSURF CONTROL PANEL",
                 font=("Arial", 18, "bold"), bg=bg, fg="#00bcd4").pack()
        tk.Label(tf, text="v3.3 — VPN Detection & Cascade Edition",
                 font=("Arial", 9), bg=bg, fg="#666").pack()

        # Indicatore modalità
        mf = tk.Frame(self.root, bg=bg)
        mf.pack(fill="x", padx=20, pady=(0, 5))
        tk.Label(mf, text="Modalità:", font=("Arial", 9, "bold"),
                 bg=bg, fg="#888").pack(side="left")
        self.mode_lbl = tk.Label(mf, text="● DIRETTA",
                                  font=("Arial", 10, "bold"), bg=bg, fg="#9e9e9e")
        self.mode_lbl.pack(side="left", padx=8)

        # Status bar
        self.status_frame = tk.Frame(self.root, bg="#666666", pady=10)
        self.status_frame.pack(fill="x", padx=20)
        self.status_lbl = tk.Label(self.status_frame, text="Inizializzazione...",
                                   font=("Arial", 12, "bold"), bg="#666666", fg="white")
        self.status_lbl.pack()

        # IP frame
        ip_frame = tk.Frame(self.root, bg=bg)
        ip_frame.pack(fill="x", padx=20, pady=8)

        left = tk.LabelFrame(ip_frame, text="IP REALE", font=("Arial", 10, "bold"),
                             bg="#3a3a3a", fg="#ffc107", padx=10, pady=8)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.real_ip_lbl = tk.Label(left, text=self.real_ip,
                                    font=("Courier", 14, "bold"), bg="#3a3a3a", fg="#ffc107")
        self.real_ip_lbl.pack(pady=5)
        tk.Button(left, text="Salva IP", command=self.save_ip,
                  bg="#ffc107", fg="#000", font=("Arial", 9, "bold")).pack()

        right = tk.LabelFrame(ip_frame, text="IP CORRENTE", font=("Arial", 10, "bold"),
                              bg="#3a3a3a", fg="#00bcd4", padx=10, pady=8)
        right.pack(side="left", fill="both", expand=True)
        self.curr_ip_lbl = tk.Label(right, text=self.current_ip,
                                    font=("Courier", 14, "bold"), bg="#3a3a3a", fg="#00bcd4")
        self.curr_ip_lbl.pack(pady=3)
        loc_f = tk.Frame(right, bg="#3a3a3a")
        loc_f.pack()
        tk.Label(loc_f, text="Posizione: ", font=("Arial", 9), bg="#3a3a3a", fg="#81c784").pack(side="left")
        self.loc_flag_lbl = tk.Label(loc_f, text="", bg="#3a3a3a")
        self.loc_flag_lbl.pack(side="left", padx=(0, 4))
        self.loc_lbl = tk.Label(loc_f, text="-", font=("Arial", 9), bg="#3a3a3a", fg="#81c784")
        self.loc_lbl.pack(side="left")
        self.isp_lbl = tk.Label(right, text="ISP: -", font=("Arial", 8), bg="#3a3a3a", fg="#90caf9")
        self.isp_lbl.pack()

        # Endpoint attivo
        exit_frame = tk.LabelFrame(self.root, text="ENDPOINT ATTIVO",
                                   font=("Arial", 10, "bold"),
                                   bg="#3a3a3a", fg="#4caf50", padx=15, pady=8)
        exit_frame.pack(fill="x", padx=20, pady=(0, 8))
        grid = tk.Frame(exit_frame, bg="#3a3a3a")
        grid.pack()
        self.exit_labels = {}
        self.exit_flag_lbl = None
        for i, name in enumerate(["IP", "Hostname", "Paese", "Città", "Regione", "ISP"]):
            r, c = i // 2, (i % 2) * 2
            tk.Label(grid, text=name + ":", font=("Arial", 9, "bold"),
                     bg="#3a3a3a", fg="#9e9e9e", width=10, anchor="e").grid(row=r, column=c, padx=4, pady=2)
            if name == "Paese":
                pf = tk.Frame(grid, bg="#3a3a3a")
                pf.grid(row=r, column=c + 1, padx=4, pady=2, sticky="w")
                self.exit_flag_lbl = tk.Label(pf, text="", bg="#3a3a3a")
                self.exit_flag_lbl.pack(side="left", padx=(0, 4))
                lbl = tk.Label(pf, text="-", font=("Courier", 9, "bold"), bg="#3a3a3a", fg="#4caf50")
                lbl.pack(side="left")
            else:
                lbl = tk.Label(grid, text="-", font=("Courier", 9, "bold"),
                               bg="#3a3a3a", fg="#4caf50", width=22, anchor="w")
                lbl.grid(row=r, column=c + 1, padx=4, pady=2)
            self.exit_labels[name] = lbl

        # ---- SEZIONE VPN ----
        # ── VPN: solo spunta cascata, la VPN viene avviata manualmente ───
        vpn_frame = tk.LabelFrame(self.root, text="VPN / Cascata",
                                  font=("Arial", 10, "bold"),
                                  bg="#3a3a3a", fg="#7e57c2", padx=12, pady=8)
        vpn_frame.pack(fill="x", padx=20, pady=(0, 8))

        self.cascade_check = tk.Checkbutton(
            vpn_frame,
            text="⛓ Modalità CASCATA: avvia Tor sopra alla VPN attiva (VPN → Tor)",
            variable=self.cascade_var,
            bg="#3a3a3a", fg="#ffcc02",
            selectcolor="#2b2b2b",
            activebackground="#3a3a3a",
            font=("Arial", 9, "bold"),
            command=self._on_cascade_toggle,
        )
        self.cascade_check.pack(anchor="w")

        # Semaforo VPN — riga con indicatore stato
        vpn_status_row = tk.Frame(vpn_frame, bg="#3a3a3a")
        vpn_status_row.pack(fill="x", pady=(6, 0))

        self.vpn_semaforo = tk.Label(
            vpn_status_row,
            text="●", font=("Arial", 14), bg="#3a3a3a", fg="#f44336")
        self.vpn_semaforo.pack(side="left", padx=(0, 6))

        self.vpn_semaforo_lbl = tk.Label(
            vpn_status_row,
            text="Nessuna VPN attiva",
            font=("Arial", 9, "bold"), bg="#3a3a3a", fg="#f44336")
        self.vpn_semaforo_lbl.pack(side="left")

        self.cascade_info_lbl = tk.Label(
            vpn_frame,
            text="  → Attiva prima la VPN manualmente, poi premi AVVIA TOR",
            font=("Arial", 8), bg="#3a3a3a", fg="#aaa",
        )

        # Pannello stato cascata — figlio di root, inserito prima del log
        self.cascade_status_frame = tk.Frame(self.root, bg="#004d40", pady=4)

        # ── Contenuto pannello cascata ─────────────────────────────────────
        # Riga 1: VPN IP + Tor Exit IP affiancati
        cas_row1 = tk.Frame(self.cascade_status_frame, bg="#004d40")
        cas_row1.pack(fill="x", padx=8, pady=(2, 0))

        tk.Label(cas_row1, text="VPN IP:", font=("Arial", 8, "bold"),
                 bg="#004d40", fg="#80cbc4").pack(side="left")
        self.cascade_vpn_ip_lbl = tk.Label(cas_row1, text="-",
                 font=("Courier", 8, "bold"), bg="#004d40", fg="#fff")
        self.cascade_vpn_ip_lbl.pack(side="left", padx=(4, 16))

        tk.Label(cas_row1, text="Tor Exit IP:", font=("Arial", 8, "bold"),
                 bg="#004d40", fg="#80cbc4").pack(side="left")
        self.cascade_vpn_flag = tk.Label(cas_row1, text="", bg="#004d40")
        self.cascade_vpn_flag.pack(side="left", padx=(4, 2))
        self.cascade_tor_ip_lbl = tk.Label(cas_row1, text="? (premi Verifica)",
                 font=("Courier", 8, "bold"), bg="#004d40", fg="#ffcc02")
        self.cascade_tor_ip_lbl.pack(side="left", padx=(0, 8))

        # Riga 2: pulsanti azione cascata
        cas_row2 = tk.Frame(self.cascade_status_frame, bg="#004d40")
        cas_row2.pack(fill="x", padx=8, pady=(3, 0))

        tk.Button(cas_row2, text="🔬 Verifica Cascata",
                  command=self._verify_cascade,
                  bg="#00695c", fg="#fff", font=("Arial", 8, "bold"),
                  width=16, relief="flat").pack(side="left", padx=(0, 6))
        tk.Button(cas_row2, text="🦊 Apri Browser",
                  command=self._launch_firefox_tor,
                  bg="#e65100", fg="#fff", font=("Arial", 8, "bold"),
                  width=14, relief="flat").pack(side="left", padx=(0, 6))
        tk.Button(cas_row2, text="🖥 Terminale Tor",
                  command=self._launch_terminal_tor,
                  bg="#1565c0", fg="#fff", font=("Arial", 8, "bold"),
                  width=14, relief="flat").pack(side="left")

        # Riga 3: circuito Tor relay
        self.cascade_circuit_lbl = tk.Label(
            self.cascade_status_frame, text="",
            font=("Courier", 7), bg="#004d40", fg="#4db6ac",
            justify="left", anchor="w")
        self.cascade_circuit_lbl.pack(anchor="w", padx=8, pady=(2, 4))
        # ──────────────────────────────────────────────────────────────────

        self._vpn_action_widgets = []

        # ---- PULSANTI TOR ----
        btn_frame = tk.Frame(self.root, bg=bg)
        btn_frame.pack(fill="x", padx=20, pady=(0, 6))
        self.buttons = []
        for text, color, cmd in [
            ("AVVIA TOR",  "#4caf50", self.start_tor),
            ("FERMA TOR",  "#f44336", self.stop_tor),
            ("CAMBIA ID",  "#9c27b0", self.change_id),
            ("AGGIORNA",   "#2196f3", self.manual_refresh),
        ]:
            b = tk.Button(btn_frame, text=text, command=cmd,
                          bg=color, fg="#fff", font=("Arial", 10, "bold"),
                          width=12, height=2)
            b.pack(side="left", expand=True, padx=3)
            self.buttons.append(b)

        # Auto-change + Bridge
        bot_frame = tk.Frame(self.root, bg=bg)
        bot_frame.pack(fill="x", padx=20, pady=(0, 5))
        tk.Checkbutton(bot_frame, text="Cambio automatico ID ogni 100s",
                       variable=self.auto_change_var, bg=bg, fg="#ffb74d",
                       selectcolor="#3a3a3a", activebackground=bg,
                       font=("Arial", 9, "bold")).pack(side="left")
        self.auto_status_lbl = tk.Label(bot_frame, text="", font=("Arial", 9),
                                         bg=bg, fg="#888")
        self.auto_status_lbl.pack(side="left", padx=8)
        tk.Button(bot_frame, text="🔍 VPN Scan", command=self._open_vpn_diagnostics,
                  bg="#37474f", fg="#80cbc4", font=("Arial", 9, "bold"),
                  width=11).pack(side="right", padx=(4, 0))
        tk.Button(bot_frame, text="⚙ Bridge Tor", command=self._open_bridge_settings,
                  bg="#455a64", fg="#90caf9", font=("Arial", 9, "bold"),
                  width=12).pack(side="right")

        # Progress
        self.progress_lbl = tk.Label(self.root, text="",
                                      font=("Arial", 9), bg=bg, fg="#aaa")
        self.progress_lbl.pack()

        # Pannello cascata (visibile solo quando attiva) — prima del log
        self.cascade_status_frame.pack(fill="x", padx=20, pady=(0, 4))
        self.cascade_status_frame.pack_forget()   # nascosto di default

        # ── Regola fondamentale tkinter per layout responsivo ─────────────
        # side="bottom" va dichiarato IN CODICE prima di side="top"/expand.
        # Ordine corretto: footer (bottom) → log label (top) → log box (expand)

        self.footer = tk.Label(self.root, text="", font=("Arial", 8), bg=bg, fg="#555")
        self.footer.pack(side="bottom")
        tk.Label(self.root, text="Creato da Red-Penguin — MIT License",
                 font=("Arial", 8), bg=bg, fg="#666").pack(side="bottom", pady=(0, 6))

        # Log label e log box — dopo il footer nel codice, sopra nella GUI
        self.log_section_label = tk.Label(
            self.root, text="LOG OPERAZIONI",
            font=("Arial", 9, "bold"), bg=bg, fg="#757575")
        self.log_section_label.pack(anchor="w", padx=20)

        self.log_box = scrolledtext.ScrolledText(
            self.root, height=7,
            bg="#1e1e1e", fg="#aaa", font=("Courier", 9))
        self.log_box.pack(fill="both", expand=True, padx=20, pady=(0, 5))


    # ------------------------------------------------------------------
    # VPN UI CALLBACKS
    # ------------------------------------------------------------------
    def _on_vpn_type_changed(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

    def _on_cascade_toggle(self):
        if self.cascade_var.get():
            self.cascade_info_lbl.pack(anchor="w", padx=8, pady=(0, 4))
            self.logger.info(
                "Cascata attivata — SOCKS5 proxy, NO iptables\n"
                "Ordine: 1) Connetti VPN  2) AVVIA TOR  3) premi Verifica")
        else:
            self.cascade_info_lbl.pack_forget()
            self.cascade_status_frame.pack_forget()
            self.logger.info("Cascata disattivata")

    def _populate_vpn_type_selector(self):
        types = [WG_DISPLAY] + list(self.detected_vpns.values())
    def _refresh_wg_profiles(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

    def _open_profiles_folder(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

    def _get_active_vpn_key(self):
        """Ritorna la chiave provider per la VPN attualmente selezionata nella UI"""
        selected = self.active_vpn_type
        if selected == WG_DISPLAY:
            return WG_DISPLAY
        for key, display in VPN_PROVIDERS.items():
            if display['display'] == selected:
                return key
        return WG_DISPLAY

    def _is_any_vpn_connected(self):
        """Controlla se una qualsiasi VPN è attiva (WG o esterna)"""
        if self.wg_manager.is_connected():
            return True
        for key in self.detected_vpns:
            if self.ext_vpn_manager.is_connected(key):
                return True
        return False

    # ------------------------------------------------------------------
    # BRIDGE
    # ------------------------------------------------------------------
    def _open_vpn_diagnostics(self):
        """Mostra finestra diagnostica con dettaglio rilevamento VPN."""
        diag_text = VPNDetector.run_diagnostics()

        win = tk.Toplevel(self.root)
        win.title("🔍 Diagnostica Rilevamento VPN")
        win.configure(bg="#2b2b2b")
        win.geometry("580x440")
        win.resizable(False, False)
        win.transient(self.root)
        x = (win.winfo_screenwidth() - 580) // 2
        y = (win.winfo_screenheight() - 440) // 2
        win.geometry(f"+{x}+{y}")

        tk.Label(win, text="🔍 Diagnostica Rilevamento VPN",
                 font=("Arial", 13, "bold"), bg="#2b2b2b", fg="#80cbc4").pack(pady=(14, 4))
        tk.Label(win,
                 text="Mostra dove il programma ha cercato i binary VPN e cosa ha trovato.",
                 font=("Arial", 9), bg="#2b2b2b", fg="#888").pack(pady=(0, 8))

        txt = scrolledtext.ScrolledText(win, height=16, bg="#1e1e1e", fg="#ddd",
                                         font=("Courier", 8), wrap="word")
        txt.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        txt.insert("1.0", diag_text)
        txt.config(state="disabled")

        bf = tk.Frame(win, bg="#2b2b2b")
        bf.pack(fill="x", padx=16, pady=(0, 12))

        def rescan():
            txt.config(state="normal")
            txt.delete("1.0", "end")
            self.detected_vpns = VPNDetector.detect(logger=self.logger)
            new_diag = VPNDetector.run_diagnostics()
            txt.insert("1.0", new_diag)
            txt.config(state="disabled")
            self._rebuild_vpn_type_list()
            if self.detected_vpns:
                names = ", ".join(self.detected_vpns.values())
                self.logger.success(f"Riscan: trovate {names}")
            else:
                self.logger.warning("Riscan: nessuna VPN esterna trovata")

        tk.Button(bf, text="↺ Riscansiona", command=rescan,
                  bg="#00695c", fg="#fff", font=("Arial", 9, "bold"),
                  width=14).pack(side="left", padx=(0, 8))
        tk.Button(bf, text="Chiudi", command=win.destroy,
                  bg="#555", fg="#fff", font=("Arial", 9),
                  width=10).pack(side="right")

    def _show_cascade_panel(self):
        """
        Mostra il pannello cascata prima del log usando before= per
        garantire la posizione corretta anche dopo pack_forget/pack.
        """
        # before= inserisce il frame subito prima dell'etichetta LOG
        self.cascade_status_frame.pack(
            fill="x", padx=20, pady=(0, 4),
            before=self.log_section_label)
        # Allarga la finestra per il pannello cascata.
        # Necessario anche con layout responsivo: il pannello ha altezza
        # fissa e senza allargamento comprime il log sotto la soglia minima.
        w = CONFIG.get_int('gui', 'window_width', 700)
        h = CONFIG.get_int('gui', 'window_height', 900)
        self.root.geometry(f"{w}x{h + 115}")
        # Aggiorna IP VPN corrente nel pannello
        ip = self.current_ip if self.current_ip not in ('...', '-', '') else '-'
        self.cascade_vpn_ip_lbl.config(text=ip)
        self.cascade_tor_ip_lbl.config(text="? (premi Verifica)")

    def _verify_cascade(self):
        """Verifica cascata VPN→Tor con torsocks. Mostra IP Tor exit."""
        # Controlla sia current_mode (aggiornato dal refresh periodico)
        # che cascade_manager.is_active() (aggiornato subito dopo il bootstrap).
        # Evita la race condition nei ~15s tra avvio cascata e primo refresh.
        if self.current_mode != MODE_CASCADE and not self.cascade_manager.is_active():
            messagebox.showinfo("Info",
                "Attiva prima la cascata (VPN + AVVIA TOR).", parent=self.root)
            return
        # Allinea current_mode se il cascade manager è già attivo
        if self.cascade_manager.is_active():
            self.current_mode = MODE_CASCADE
        self.cascade_tor_ip_lbl.config(text="⏳ verifica...", fg="#ffcc02")
        self.logger.info("🔬 Verifica cascata in corso...")

        def do_verify():
            # 1. Verifica con torsocks
            ok, tor_ip = self.cascade_manager.verify()

            # 2. Se torsocks non disponibile, prova check.torproject via torsocks
            if not ok and not tor_ip:
                ok, tor_ip = self.cascade_manager.get_tor_exit_ip_via_check()

            # 3. Aggiorna IP Tor e recupera geo
            if ok and tor_ip:
                geo = self.tor_manager._get_geo_info(tor_ip)
                cc  = geo.get('country_code', '-')
                isp = geo.get('isp', '-')[:30]
                label = f"{tor_ip}  ({cc} — {isp})"

                def update_ui():
                    self.cascade_tor_ip_lbl.config(text=label, fg="#69f0ae")
                    img = self._get_flag_image(cc)
                    if img:
                        self.cascade_vpn_flag.config(image=img, text="")
                    # Mostra circuito Tor se disponibile
                    relays = self.cascade_manager.get_circuit_info()
                    if relays:
                        circuit_str = " → ".join(
                            f"{r['name']}" for r in relays[:3])
                        self.cascade_circuit_lbl.config(
                            text=f"Circuito: Guard -> {circuit_str}")
                    self.logger.success(
                        "Cascata verificata! "
                        f"VPN IP: {self.current_ip} | "
                        f"Tor Exit: {tor_ip} ({cc}) | "
                        "Il Cisco vede solo Surfshark")
                self.root.after(0, update_ui)
            else:
                def update_err():
                    self.cascade_tor_ip_lbl.config(
                        text="⚠ Verifica fallita — controlla torsocks",
                        fg="#ef5350")
                    self.logger.warning(
                        "Verifica cascata fallita.\n"
                        "Assicurati che torsocks sia installato:\n"
                        "  sudo apt install torsocks")
                self.root.after(0, update_err)

        threading.Thread(target=do_verify, daemon=True).start()

    def _launch_firefox_tor(self):
        """
        Apre il browser su check.torproject.org tramite xdg-open.
        Il proxy GNOME SOCKS5 e' gia' impostato — qualsiasi browser
        lo rispetta automaticamente. Nessun conflitto con istanze aperte.
        """
        if self.current_mode != MODE_CASCADE:
            messagebox.showinfo("Info", "Attiva prima la cascata.", parent=self.root)
            return

        url       = 'https://check.torproject.org'
        sudo_user = os.environ.get('SUDO_USER', '')
        display   = os.environ.get('DISPLAY', ':0')
        xauth     = f'/home/{sudo_user}/.Xauthority'
        dbus      = self.cascade_manager._get_user_dbus()

        try:
            if sudo_user and sudo_user != 'root':
                env_args = ['env',
                            f'DISPLAY={display}',
                            f'XAUTHORITY={xauth}']
                if dbus:
                    env_args.append(f'DBUS_SESSION_BUS_ADDRESS={dbus}')
                cmd = ['sudo', '-u', sudo_user] + env_args + ['xdg-open', url]
            else:
                cmd = ['xdg-open', url]

            subprocess.Popen(cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            self.logger.success(
                f"Browser aperto su {url}\n"
                "Proxy GNOME SOCKS5 attivo — cerca banner verde di conferma.")
        except Exception as e:
            self.logger.error(f"Errore apertura browser: {e}")


    def _launch_terminal_tor(self):
        """Apre terminale con torsocks preconfigurato."""
        if self.current_mode != MODE_CASCADE:
            messagebox.showinfo("Info", "Attiva prima la cascata.", parent=self.root)
            return
        sudo_user = os.environ.get('SUDO_USER', '')
        dbus = self.cascade_manager._get_user_dbus()
        env_str = (f'DBUS_SESSION_BUS_ADDRESS={dbus} ' if dbus else '')

        # Script wrapper — scritto con triple quote per evitare escape issues
        wrapper_lines = [
            '#!/bin/bash',
            'export ALL_PROXY="socks5h://127.0.0.1:9050"',
            'export http_proxy="socks5h://127.0.0.1:9050"',
            'export https_proxy="socks5h://127.0.0.1:9050"',
            'echo "=== TERMINALE TOR — AnonSurf Cascade ==="',
            'echo "    Proxy: socks5h://127.0.0.1:9050"',
            'echo "    Usa: torsocks <comando>"',
            'echo "    Test: torsocks curl https://api.ipify.org"',
            'echo "=========================================="',
            'exec bash',
        ]
        wrapper = '\n'.join(wrapper_lines) + '\n'
        wrapper_path = Path('/tmp/anonsurf_tor_terminal.sh')
        wrapper_path.write_text(wrapper)
        wrapper_path.chmod(0o755)

        # Prova vari emulatori di terminale
        for term_cmd in [
            ['x-terminal-emulator', '-e', str(wrapper_path)],
            ['gnome-terminal', '--', str(wrapper_path)],
            ['xterm', '-e', str(wrapper_path)],
            ['lxterminal', '-e', str(wrapper_path)],
            ['xfce4-terminal', '-e', str(wrapper_path)],
        ]:
            if not shutil.which(term_cmd[0]):
                continue
            try:
                full = term_cmd
                if sudo_user and sudo_user != 'root':
                    display = os.environ.get('DISPLAY', ':0')
                    xauth   = f'/home/{sudo_user}/.Xauthority'
                    t_env   = ['env', f'DISPLAY={display}',
                               f'XAUTHORITY={xauth}']
                    if dbus:
                        t_env.append(f'DBUS_SESSION_BUS_ADDRESS={dbus}')
                    full = ['sudo', '-u', sudo_user] + t_env + term_cmd
                subprocess.Popen(full, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                self.logger.success(
                    f"Terminale Tor aperto ({term_cmd[0]})\n"
                    "ALL_PROXY e torsocks già configurati")
                return
            except Exception:
                continue
        messagebox.showwarning(
            "Terminale",
            "Nessun emulatore terminale trovato.\n\nApri un terminale e usa:\n  export ALL_PROXY=socks5h://127.0.0.1:9050\n  torsocks curl https://api.ipify.org",
            parent=self.root)

    def _open_bridge_settings(self, on_close_callback=None):
        win = BridgeSettingsWindow(self.root, self.bridge_manager,
                                   on_apply_callback=lambda: self.logger.success(
                                       "Bridge configurati — riavvia AnonSurf"))
        if on_close_callback:
            win.win.protocol("WM_DELETE_WINDOW",
                             lambda: (win.win.destroy(), on_close_callback()))

    # ------------------------------------------------------------------
    # FLAG / LOG HELPERS
    # ------------------------------------------------------------------
    def _get_flag_image(self, code):
        if not code or code == '-':
            return None
        code = code.upper()
        if code in self.flag_images:
            return self.flag_images[code]
        if code in FLAGS_BASE64:
            try:
                img = tk.PhotoImage(data=FLAGS_BASE64[code])
                self.flag_images[code] = img
                return img
            except Exception:
                pass
        return None

    def _update_flag(self, label, code):
        img = self._get_flag_image(code)
        if img:
            label.config(image=img, text="")
        else:
            label.config(image="", text=code if code and code != '-' else "")

    def log(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {message}\n")
        self.log_box.see("end")
        max_lines = CONFIG.get_int('gui', 'max_log_lines', 100)
        lines = int(self.log_box.index('end-1c').split('.')[0])
        if lines > max_lines:
            self.log_box.delete('1.0', f'{lines - max_lines}.0')

    # ------------------------------------------------------------------
    # IP SAVE / REFRESH
    # ------------------------------------------------------------------
    def load_saved_ip(self):
        if REAL_IP_FILE.exists():
            try:
                self.real_ip = REAL_IP_FILE.read_text().strip()
                self.real_ip_lbl.config(text=self.real_ip)
            except Exception:
                pass

    def save_ip(self):
        if self.current_mode != MODE_DIRECT:
            messagebox.showwarning("Attenzione", "Disattiva Tor/VPN prima di salvare l'IP reale")
            return
        threading.Thread(target=self._do_save_ip, daemon=True).start()

    def _do_save_ip(self):
        ip = self.tor_manager._get_simple_ip()
        if ip:
            try:
                REAL_IP_FILE.write_text(ip)
                self.real_ip = ip
                self.root.after(0, lambda: self.real_ip_lbl.config(text=ip))
                self.root.after(0, lambda: self.logger.success(f"IP reale salvato: {ip}"))
            except Exception as e:
                self.root.after(0, lambda: self.logger.error(f"Errore: {e}"))

    def manual_refresh(self):
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def schedule_refresh(self):
        if self.closing:
            return
        threading.Thread(target=self._do_refresh, daemon=True).start()
        self.root.after(CONFIG.get_int('timing', 'refresh_interval', 15000), self.schedule_refresh)

    def schedule_auto_change(self):
        if self.closing:
            return
        if (self.auto_change_var.get() and
                self.current_mode in (MODE_TOR, MODE_CASCADE) and
                not self.operation_in_progress):
            threading.Thread(target=self._do_auto_change, daemon=True).start()
        self.root.after(100000, self.schedule_auto_change)

    def _do_auto_change(self):
        ok = self.tor_manager.change_identity()
        ts = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: self.auto_status_lbl.config(
            text=f"OK: {ts}" if ok else "Errore",
            fg="#81c784" if ok else "#ef5350"))
        time.sleep(2)
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _get_ip_via_torsocks(self) -> str:
        """
        Recupera l'IP Tor exit via torsocks con validazione rigorosa.
        Ignora risposte JSON/HTML/rate-limit — ritorna solo IP validi.
        """
        if not shutil.which('torsocks'):
            return ''
        apis = [
            'https://ifconfig.me/ip',
            'https://ipinfo.io/ip',
            'https://icanhazip.com',
            'https://api.ipify.org',
            'https://ipecho.net/plain',
        ]
        for api in apis:
            try:
                r = subprocess.run(
                    ['torsocks', 'curl', '-s', '--max-time', '10',
                     '--user-agent', 'curl/7.68.0', api],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode != 0:
                    continue
                ip = (r.stdout or '').strip()
                # Usa lo stesso validatore della CascadeManager
                if CascadeManager._is_valid_ip(ip):
                    return ip
                self.logger.debug(f"_get_ip_via_torsocks {api}: {ip[:40]}")
            except Exception:
                continue
        return ''

    def _do_refresh(self):
        # VPN check: usa interfacce kernel, NON chiama surfshark-vpn status
        wg_conn  = self.wg_manager.is_connected()
        ext_conn = {k: self.ext_vpn_manager.is_connected(k) for k in self.detected_vpns}
        any_vpn  = wg_conn or any(ext_conn.values())

        cascade_active = any_vpn and self.cascade_var.get()

        if cascade_active or self.current_mode == MODE_CASCADE:
            # In cascata urllib usa VPN come gateway — mostrerebbe sempre IP VPN.
            # Usiamo torsocks per ottenere il vero Tor exit IP.
            # Se torsocks non disponibile, mostriamo IP VPN con nota.
            is_tor = self.cascade_manager.is_active()
            ip = self._get_ip_via_torsocks()
            if not ip:
                # Fallback: IP VPN (non è l'exit Tor ma almeno mostra qualcosa)
                ip = self.tor_manager._get_simple_ip() or '-'
            status = {'is_tor': is_tor, 'ip': ip}
            if ip and ip != '-':
                status.update(self.tor_manager._get_geo_info(ip))
        else:
            # Modalità normale: check remoto completo
            status = self.tor_manager.get_status()
            is_tor = status.get('is_tor', False)

        self.root.after(0, lambda: self._update_ui(status, is_tor, any_vpn, wg_conn, ext_conn))

    def _update_ui(self, info, is_tor, any_vpn, wg_conn, ext_conn):
        ip       = info.get('ip', '-')
        cc       = info.get('country_code', '-')
        city     = info.get('city', '-')
        isp      = info.get('isp', '-')
        hostname = info.get('hostname', '-')
        region   = info.get('region', '-')

        self.current_ip = ip
        self.curr_ip_lbl.config(text=ip)

        # Determina modalità
        if is_tor and any_vpn:
            self.current_mode = MODE_CASCADE
        elif is_tor:
            self.current_mode = MODE_TOR
        elif any_vpn:
            self.current_mode = MODE_VPN
        else:
            self.current_mode = MODE_DIRECT

        # Aggiorna stato VPN nella UI
        if wg_conn:
            vpn_name = self.wg_manager._active_profile or "WireGuard"
        else:
            active_ext = next((k for k, v in ext_conn.items() if v), None)
            if active_ext:
                name = VPN_PROVIDERS[active_ext]['display']
            else:
                pass
        # Status bar + mode label
        cfg = {
            MODE_CASCADE: ("● CASCATA: VPN + TOR", "#00897b", "#00bcd4", "⛓ VPN+TOR"),
            MODE_TOR:     ("● TOR ATTIVO — Anonimizzato", "#4caf50", "#4caf50", "● TOR"),
            MODE_VPN:     ("● VPN ATTIVA", "#7e57c2", "#ce93d8", "● VPN"),
            MODE_DIRECT:  ("○ DIRETTA — Nessuna protezione", "#f44336", "#9e9e9e", "○ DIRETTA"),
        }
        bar_text, bar_color, mode_color, mode_text = cfg[self.current_mode]
        self.status_lbl.config(text=bar_text, bg=bar_color)
        self.status_frame.config(bg=bar_color)
        self.mode_lbl.config(text=mode_text, fg=mode_color)

        # Aggiorna semaforo VPN
        if any_vpn:
            vpn_label = ""
            if wg_conn and self.wg_manager._active_profile:
                vpn_label = f"VPN attiva — WireGuard [{self.wg_manager._active_profile}]"
            elif wg_conn:
                vpn_label = "VPN attiva — WireGuard"
            else:
                active_key = next((k for k, v in ext_conn.items() if v), None)
                if active_key and active_key in VPN_PROVIDERS:
                    vpn_label = f"VPN attiva — {VPN_PROVIDERS[active_key]['display']}"
                else:
                    vpn_label = "VPN attiva"
            self.vpn_semaforo.config(fg="#4caf50")
            self.vpn_semaforo_lbl.config(text=vpn_label, fg="#4caf50")
        else:
            self.vpn_semaforo.config(fg="#f44336")
            self.vpn_semaforo_lbl.config(text="Nessuna VPN attiva", fg="#f44336")

        # Posizione IP corrente
        self._update_flag(self.loc_flag_lbl, cc)
        self.loc_lbl.config(text=f"{city}, {cc}" if city != '-' else cc)
        isp_d = isp[:38] + "..." if len(isp) > 38 else isp
        self.isp_lbl.config(text=f"ISP: {isp_d}")

        # Endpoint attivo
        if self.current_mode in (MODE_TOR, MODE_VPN, MODE_CASCADE):
            color = {"TOR": "#4caf50", "VPN": "#ce93d8", "CASCADE": "#00bcd4"}[self.current_mode]
            self.exit_labels["IP"].config(text=ip, fg=color)
            hn = hostname[:24] if len(hostname) > 24 else hostname
            self.exit_labels["Hostname"].config(text=hn, fg=color)
            if self.exit_flag_lbl:
                self._update_flag(self.exit_flag_lbl, cc)
            self.exit_labels["Paese"].config(text=cc, fg=color)
            self.exit_labels["Città"].config(text=city, fg=color)
            self.exit_labels["Regione"].config(text=region, fg=color)
            isp_s = isp[:24] if len(isp) > 24 else isp
            self.exit_labels["ISP"].config(text=isp_s, fg=color)
        else:
            for lbl in self.exit_labels.values():
                lbl.config(text="-", fg="#666")
            if self.exit_flag_lbl:
                self.exit_flag_lbl.config(image="", text="")
            if self.real_ip == "Non rilevato" and ip != '-':
                try:
                    REAL_IP_FILE.write_text(ip)
                    self.real_ip = ip
                    self.real_ip_lbl.config(text=ip)
                    self.logger.info(f"IP reale auto-salvato: {ip}")
                except Exception:
                    pass

        self.footer.config(text=f"Aggiornato: {datetime.now().strftime('%H:%M:%S')}")

    # ------------------------------------------------------------------
    # AZIONI TOR
    # ------------------------------------------------------------------
    def _set_buttons_state(self, state):
        for b in self.buttons:
            b.config(state=state)

    def _set_vpn_widgets_state(self, state):
        # VPN widgets rimossi dalla UI v3.3 — metodo mantenuto per compatibilità
        pass

    def start_tor(self):
        if self.operation_in_progress:
            return

        cascade = self.cascade_var.get()

        if cascade:
            # Modalità cascata: la VPN deve essere già attiva
            if not self._is_any_vpn_connected():
                messagebox.showwarning(
                    "Cascata non possibile",
                    "Nessuna VPN attiva.\n\n"
                    "Per la modalità Cascata:\n"
                    "1. Connetti prima la VPN\n"
                    "2. Poi avvia Tor\n\n"
                    "Vuoi avviare Tor senza VPN?",
                )
                return
            self.logger.info("Modalità CASCATA: VPN attiva, avvio Tor sopra...")
        else:
            # Modalità esclusiva: ferma VPN se attiva
            if self._is_any_vpn_connected():
                if not messagebox.askyesno("Conferma",
                                            "VPN attiva.\n"
                                            "Disconnetterla per avviare Tor in modalità esclusiva?\n\n"
                                            "(Oppure attiva 'Modalità CASCATA' per usarle insieme)"):
                    return
                self.logger.info("Disconnessione VPN per modalità esclusiva...")
                self._perform_vpn_disconnect()
                time.sleep(1)

        self.operation_in_progress = True
        self._set_buttons_state(tk.DISABLED)
        self._set_vpn_widgets_state(tk.DISABLED)
        self.logger.info("Avvio AnonSurf...")
        self.status_lbl.config(text="● AVVIO IN CORSO...", bg="#ff9800")
        self.status_frame.config(bg="#ff9800")

        def do_start():
            try:
                def progress(a, t):
                    self.root.after(0, lambda: self.progress_lbl.config(
                        text=f"Bootstrap Tor: {a}/{t}"))

                if cascade:
                    ok = self.cascade_manager.start(progress_callback=progress)
                else:
                    ok = self.tor_manager.start(progress_callback=progress)

                self.root.after(0, lambda: self.progress_lbl.config(text=""))
                if ok:
                    msg = "Cascata VPN+Tor ATTIVA" if cascade else "AnonSurf ATTIVO"
                    self.root.after(0, lambda: self.logger.success(msg))
                    if cascade:
                        self.root.after(0, self._show_cascade_panel)
                else:
                    if cascade:
                        msg = ("Avvio cascata fallito.\n"
                               "Verifica: VPN connessa? Tor installato? "
                               "(sudo apt install tor)")
                    else:
                        msg = ("Avvio annullato"
                               if self.tor_manager.is_cancelled()
                               else "Avvio Tor fallito")
                    self.root.after(0, lambda: self.logger.warning(msg))
            except Exception as exc:
                # Catch-all: impedisce che eccezioni nel thread uccidano la GUI
                self.root.after(0, lambda: self.logger.error(
                    f"Errore avvio: {exc}"))
            finally:
                self.operation_in_progress = False
                self.root.after(0, lambda: self._set_buttons_state(tk.NORMAL))
                self.root.after(0, lambda: self._set_vpn_widgets_state(tk.NORMAL))
                self.root.after(500, lambda: threading.Thread(
                    target=self._do_refresh, daemon=True).start())

        threading.Thread(target=do_start, daemon=True).start()

    def stop_tor(self):
        if self.operation_in_progress:
            self.tor_manager.cancel_operation()
            return
        self.operation_in_progress = True
        self._set_buttons_state(tk.DISABLED)
        self._set_vpn_widgets_state(tk.DISABLED)
        self.logger.info("Arresto AnonSurf...")
        self.status_lbl.config(text="● ARRESTO IN CORSO...", bg="#ff9800")
        self.status_frame.config(bg="#ff9800")

        def do_stop():
            if self.current_mode == MODE_CASCADE:
                ok = self.cascade_manager.stop()
                msg = "Cascata fermata" if ok else "Problema arresto cascata"
                def hide_and_resize():
                    self.cascade_status_frame.pack_forget()
                    w = CONFIG.get_int('gui', 'window_width', 700)
                    h = CONFIG.get_int('gui', 'window_height', 900)
                    self.root.geometry(f"{w}x{h}")
                self.root.after(0, hide_and_resize)
            else:
                ok = self.tor_manager.stop()
                msg = "AnonSurf fermato" if ok else "Problema arresto"
            fn = self.logger.success if ok else self.logger.warning
            self.root.after(0, lambda: fn(msg))
            self.operation_in_progress = False
            self.root.after(0, lambda: self._set_buttons_state(tk.NORMAL))
            self.root.after(0, lambda: self._set_vpn_widgets_state(tk.NORMAL))
            self.root.after(500, lambda: threading.Thread(
                target=self._do_refresh, daemon=True).start())

        threading.Thread(target=do_stop, daemon=True).start()

    def _newnym_via_control_port(self) -> bool:
        """
        Richiede nuovo circuito Tor (SIGNAL NEWNYM) via control port 9051.

        Il cookie di autenticazione appartiene a debian-tor (rw-r-----).
        Root puo' leggerlo ma Tor verifica che il processo connesso sia
        nello stesso gruppo del cookie owner. Soluzione: esegui il mini
        script Python come utente debian-tor via sudo.
        """
        self.logger.info("Cambio circuito Tor (NEWNYM)...")

        # Mini script che gira come debian-tor
        script = (
            "import socket,sys;"
            "f=open('/run/tor/control.authcookie','rb');"
            "c=f.read().hex();f.close();"
            "s=socket.socket();"
            "s.settimeout(5);"
            "s.connect(('127.0.0.1',9051));"
            "s.sendall(('AUTHENTICATE '+c+'\\r\\n').encode());"
            "r=s.recv(256);"
            "if b'250' not in r:sys.exit(1);"
            "s.sendall(b'SIGNAL NEWNYM\\r\\n');"
            "r=s.recv(256);"
            "s.sendall(b'QUIT\\r\\n');"
            "s.close();"
            "print('OK' if b'250 OK' in r else 'FAIL:'+r.decode())"
        )

        try:
            r = subprocess.run(
                ['sudo', '-u', 'debian-tor', 'python3', '-c', script],
                capture_output=True, text=True, timeout=12,
            )
            output = (r.stdout + r.stderr).strip()
            self.logger.debug(f"NEWNYM output: {output[:80]}")

            if 'OK' in r.stdout:
                self.logger.success(
                    "Nuovo circuito Tor richiesto.\n"
                    "Attendi 10-15s, poi premi Verifica per confermare il nuovo IP.")
                return True

            # Fallback: invia SIGHUP al processo Tor (ricarica config + nuovi circuiti)
            self.logger.warning(
                f"Control port: {output[:60]}\n"
                "Tentativo SIGHUP...")
            return self._newnym_via_sighup()

        except Exception as e:
            self.logger.warning(f"NEWNYM: {e} — tentativo SIGHUP...")
            return self._newnym_via_sighup()

    def _newnym_via_sighup(self) -> bool:
        """Fallback: SIGHUP al processo Tor per forzare nuovi circuiti."""
        try:
            pid_file = Path('/run/tor/tor.pid')
            if not pid_file.exists():
                pid_file = Path('/var/run/tor/tor.pid')
            if pid_file.exists():
                pid = int(pid_file.read_text().strip())
                import signal as _signal
                os.kill(pid, _signal.SIGHUP)
                self.logger.success(
                    "SIGHUP inviato a Tor — nuovi circuiti in corso.\n"
                    "Attendi 15-20s prima di verificare il nuovo IP.")
                return True
        except Exception as e:
            self.logger.debug(f"SIGHUP: {e}")
        # Ultimo fallback: pkill
        try:
            r = subprocess.run(['pkill', '-HUP', '-x', 'tor'],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                self.logger.success("SIGHUP inviato a Tor (pkill)")
                return True
        except Exception:
            pass
        self.logger.error(
            "Cambio circuito fallito.\n"
            "Verifica che ControlPort 9051 sia attiva in /etc/tor/torrc")
        return False

    def change_id(self):
        if self.current_mode not in (MODE_TOR, MODE_CASCADE):
            messagebox.showwarning("Attenzione", "Avvia prima AnonSurf / Tor")
            return
        if self.operation_in_progress:
            return

        def do_change():
            try:
                if self.current_mode == MODE_CASCADE:
                    ok = self._newnym_via_control_port()
                else:
                    ok = self.tor_manager.change_identity()

                fn = self.logger.success if ok else self.logger.warning
                self.root.after(0, lambda: fn(
                    "Identita cambiata" if ok else "Problema cambio identita"))

                if ok and self.current_mode == MODE_CASCADE:
                    # In cascata: auto-verifica dopo che Tor ha costruito
                    # il nuovo circuito (~12s). Aggiorna IP nel pannello.
                    self.root.after(0, lambda: self.cascade_tor_ip_lbl.config(
                        text="⏳ nuovo circuito...", fg="#ffcc02"))
                    self.root.after(0, lambda: self.logger.info(
                        "Attendo costruzione nuovo circuito Tor (~12s)..."))
                    time.sleep(12)
                    if not self.closing:
                        self.root.after(0, self._auto_verify_after_newnym)
                else:
                    time.sleep(2)
                    self.root.after(500, lambda: threading.Thread(
                        target=self._do_refresh, daemon=True).start())
            except Exception as e:
                self.root.after(0, lambda: self.logger.error(
                    f"Errore cambio ID: {e}"))

        threading.Thread(target=do_change, daemon=True).start()

    def _auto_verify_after_newnym(self):
        """
        Eseguita automaticamente ~12s dopo SIGNAL NEWNYM.
        Lancia la verifica cascata che aggiorna l'exit IP nel pannello.
        """
        self.logger.info("Verifica automatica nuovo exit node...")
        # Riusa _verify_cascade ma senza il guard sulla modalità
        # (siamo già sicuri di essere in CASCADE)
        self.cascade_tor_ip_lbl.config(text="⏳ verifica...", fg="#ffcc02")

        def do_verify():
            try:
                ok, tor_ip = self.cascade_manager.verify()
                if not ok and not tor_ip:
                    ok, tor_ip = self.cascade_manager.get_tor_exit_ip_via_check()

                if ok and tor_ip:
                    geo   = self.tor_manager._get_geo_info(tor_ip)
                    cc    = geo.get('country_code', '-')
                    isp   = geo.get('isp', '-')[:28]
                    label = f"{tor_ip}  ({cc} — {isp})"

                    def update():
                        self.cascade_tor_ip_lbl.config(text=label, fg="#69f0ae")
                        img = self._get_flag_image(cc)
                        if img:
                            self.cascade_vpn_flag.config(image=img, text="")
                        relays = self.cascade_manager.get_circuit_info()
                        if relays:
                            circuit_str = " → ".join(r['name'] for r in relays[:3])
                            self.cascade_circuit_lbl.config(
                                text=f"Circuito: Guard -> {circuit_str}")
                        self.logger.success(
                            f"Nuovo exit: {tor_ip} ({cc}) — {isp}")
                    self.root.after(0, update)
                else:
                    self.root.after(0, lambda: self.cascade_tor_ip_lbl.config(
                        text="? (premi Verifica manuale)", fg="#ffb74d"))
            except Exception as e:
                self.root.after(0, lambda: self.logger.error(
                    f"Auto-verifica: {e}"))

        threading.Thread(target=do_verify, daemon=True).start()

    # ------------------------------------------------------------------
    # AZIONI VPN
    # ------------------------------------------------------------------
    def connect_vpn(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

        def do_connect():
            if vpn_key == WG_DISPLAY:
                profile = self.vpn_profile_var.get()
                if not profile:
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Attenzione",
                        f"Nessun profilo WG selezionato.\n"
                        f"Copia file .conf in:\n{self.wg_manager.get_profiles_dir()}"))
                    self.operation_in_progress = False
                    self.root.after(0, lambda: self._set_buttons_state(tk.NORMAL))
                    self.root.after(0, lambda: self._set_vpn_widgets_state(tk.NORMAL))
                    return
                ok = self.wg_manager.connect(profile)
            else:
                ok = self.ext_vpn_manager.connect(vpn_key)

            if not ok:
                self.root.after(0, lambda: self.logger.error("Connessione VPN fallita"))
            self.operation_in_progress = False
            self.root.after(0, lambda: self._set_buttons_state(tk.NORMAL))
            self.root.after(0, lambda: self._set_vpn_widgets_state(tk.NORMAL))
            self.root.after(1000, lambda: threading.Thread(
                target=self._do_refresh, daemon=True).start())

        threading.Thread(target=do_connect, daemon=True).start()

    def disconnect_vpn(self, *args, **kwargs):
        """Rimosso in v3.3 — VPN gestita manualmente."""
        pass

        def do_disconnect():
            self._perform_vpn_disconnect()
            self.operation_in_progress = False
            self.root.after(0, lambda: self._set_buttons_state(tk.NORMAL))
            self.root.after(0, lambda: self._set_vpn_widgets_state(tk.NORMAL))
            self.root.after(1000, lambda: threading.Thread(
                target=self._do_refresh, daemon=True).start())

        threading.Thread(target=do_disconnect, daemon=True).start()

    def _perform_vpn_disconnect(self):
        """Disconnette qualsiasi VPN attiva (WG o esterna)"""
        vpn_key = self._get_active_vpn_key()
        if vpn_key == WG_DISPLAY:
            self.wg_manager.disconnect()
        else:
            self.ext_vpn_manager.disconnect(vpn_key)
        # Disconnetti anche eventuali altre VPN attive in background
        for key in self.detected_vpns:
            if key != vpn_key and self.ext_vpn_manager.is_connected(key):
                self.ext_vpn_manager.disconnect(key)
        if self.wg_manager.is_connected():
            self.wg_manager.disconnect()

    # ------------------------------------------------------------------
    # CHIUSURA
    # ------------------------------------------------------------------
    def on_closing(self):
        if self.closing:
            return
        self.closing = True
        if messagebox.askyesno("Chiusura",
                                "Chiudere AnonSurf GUI?\n\n"
                                "Tor verrà fermato.\n"
                                "La VPN rimarrà attiva."):
            self.logger.info("Chiusura in corso...")
            self.tor_manager.cancel_operation()
            threading.Thread(target=self._cleanup_and_destroy, daemon=True).start()
        else:
            self.closing = False

    def _cleanup_and_destroy(self):
        self._perform_cleanup()
        self.root.after(0, self.root.destroy)

    def _perform_cleanup(self):
        try:
            if self.current_mode == MODE_CASCADE or self.cascade_manager.is_active():
                self.cascade_manager.stop()
            else:
                self.tor_manager.stop()
            # La VPN NON viene disconnessa: è gestita manualmente dall'utente
            time.sleep(2)
            self.network_manager.restore_network_state()
            self.network_manager.cleanup()
        except Exception as e:
            print(f"Errore cleanup: {e}")


# ============================================================================
# MAIN
# ============================================================================
def main():
    if os.geteuid() != 0:
        print("\033[1;33m[NOTA] Richiesti privilegi root\033[0m")
        print("Riavvio con sudo...")
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    root = tk.Tk()
    root.update_idletasks()
    w = CONFIG.get_int('gui', 'window_width', 700)
    h = CONFIG.get_int('gui', 'window_height', 900)
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")

    app = App(root)

    # Override del handler di default di tkinter per le eccezioni nelle callback.
    # Senza questo, qualsiasi eccezione non catturata in root.after() o in un
    # evento tkinter CHIUDE l'applicazione. Con questo, viene solo loggata.
    def _safe_exception_handler(exc_type, exc_value, exc_tb):
        import traceback
        tb_str = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            app.logger.error(
                f"Eccezione interna (GUI non chiusa):\n{exc_value}\n"
                f"Dettaglio nel log: {tb_str[:200]}")
        except Exception:
            print(f"[INTERNAL ERROR] {exc_value}\n{tb_str[:300]}", flush=True)

    root.report_callback_exception = _safe_exception_handler

    root.mainloop()


if __name__ == "__main__":
    main()
