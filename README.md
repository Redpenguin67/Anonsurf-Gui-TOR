# AnonSurf GUI Control Panel v3.3
### WireGuard & Bridge & Cascade Edition

**Red-Penguin** — MIT License

---

## Descrizione

AnonSurf GUI è un pannello di controllo grafico per la gestione dell'anonimato di rete su Linux (LMDE / Debian / Kali / Parrot OS). Permette di gestire AnonSurf/Tor, configurare bridge Tor, rilevare VPN installate nel sistema e attivare la **Modalità Cascata VPN→Tor** per bypassare blocchi DPI enterprise (es. Cisco Firepower con Talos Intelligence).

---

## Funzionalità

### Gestione Tor
- Avvio e arresto AnonSurf/Tor con verifica bootstrap automatica
- Cambio identità (nuovo circuito) via SIGNAL NEWNYM sulla control port 9051
- Cambio automatico ID ogni 100 secondi (opzionale)
- IP corrente, geolocalizzazione, bandiera nazionale, ISP, hostname

### VPN e Modalità Cascata
- **Semaforo VPN** — indicatore verde/rosso dello stato VPN rilevato in tempo reale
- **Modalità Cascata VPN→Tor** — avvia Tor sopra alla VPN attiva usando SOCKS5 proxy
  - Nessuna modifica a iptables, nessun conflitto con la VPN
  - Proxy GNOME di sistema impostato automaticamente a `SOCKS5 127.0.0.1:9050`
  - Il Cisco/DPI vede solo traffico VPN cifrato — Tor è invisibile
- Verifica cascata con `torsocks` — mostra il vero Tor exit IP (non l'IP VPN)
- Auto-verifica exit node dopo ogni cambio identità
- Apertura browser su `check.torproject.org` con proxy pre-configurato
- Terminale con `ALL_PROXY` e `torsocks` già impostati

### Bridge Tor
- File `bridges.conf` nella directory del programma — una bridge line per riga
- Prova automatica in sequenza all'avvio se Tor è bloccato dall'ISP
- Il primo bridge funzionante viene applicato automaticamente a `/etc/tor/torrc`
- Pulsante **⚙ Bridge Tor** — editor diretto del file `bridges.conf`
- Trasporti supportati: `obfs4`, `snowflake`, `meek-azure`, `webtunnel`
- Backup automatico del `torrc` originale prima di qualsiasi modifica

### Rilevamento VPN
- Scansione all'avvio: PATH, `/snap/bin`, flatpak, servizi systemd
- VPN supportate: **Surfshark**, NordVPN, ProtonVPN, ExpressVPN, Mullvad, CyberGhost, PIA, IVPN
- La VPN è gestita manualmente dall'utente — non viene disconnessa alla chiusura

### Interfaccia
- Tema scuro, finestra responsiva (ridimensionabile, min 640×780px)
- 68 bandiere nazionali embedded (PNG base64, zero dipendenze esterne)
- Log operazioni in tempo reale con rotazione automatica
- Versione Mini compatta (300×260px, always-on-top)

---

## Requisiti

- **OS:** LMDE, Debian 12+, Kali Linux, Parrot OS, Ubuntu 22.04+
- **Python:** 3.10+

**Dipendenze installate automaticamente dall'installer:**
```
python3  python3-venv  python3-tk  git  tor  torsocks  curl
```

**Dipendenze opzionali:**
```bash
sudo apt install obfs4proxy          # bridge obfs4 e meek-azure
sudo apt install snowflake-client    # bridge snowflake
```

---

## Installazione

```bash
unzip Anonsurf-gui-v3.3.zip
cd anonsurf_v31
sudo ./install.sh
```

**L'installer esegue 6 fasi:**
1. Dipendenze di sistema (con timeout anti-blocco e `policy-rc.d`)
2. Copia file in `/opt/anonsurf-gui`
3. Ambiente virtuale Python
4. Verifica/installazione AnonSurf
5. Launcher e link simbolici
6. Integrazione menu desktop

---

## Avvio

```bash
sudo anonsurf-gui          # GUI completa
sudo anonsurf-gui-mini     # GUI minimale
./start.sh                 # dalla directory sorgente
```

Oppure dal **menu di sistema** → cerca *AnonSurf GUI*.

---

## Utilizzo

### Tor normale
1. Clicca **AVVIA TOR** — attende bootstrap (~45s max)
2. Clicca **CAMBIA ID** per nuovo circuito
3. Clicca **FERMA TOR** per tornare alla connessione diretta

### Cascata VPN→Tor (bypass DPI/Cisco)

```
PC → SOCKS5 127.0.0.1:9050 → Tor daemon locale
                                    ↓
                           Tunnel VPN (es. Surfshark)
                                    ↓
                             Internet / Exit Node
```

1. Connetti la VPN manualmente (tray icon)
2. Attendi semaforo **verde** nella GUI
3. Spunta **⛓ Modalità CASCATA**
4. Clicca **AVVIA TOR**
5. Clicca **🔬 Verifica Cascata** — mostra l'exit IP Tor reale

### Bridge Tor
1. Ottieni bridge: [bridges.torproject.org](https://bridges.torproject.org)
   oppure email `bridges@torproject.org` (oggetto: `get transport obfs4`)
2. Clicca **⚙ Bridge Tor** — incolla le bridge lines — **💾 Salva**
3. Al prossimo avvio vengono provati automaticamente in sequenza

**Formato `bridges.conf`:**
```
# Commento
transport:obfs4
obfs4 1.2.3.4:443 FINGERPRINT cert=XXXX iat-mode=0
obfs4 5.6.7.8:9001 FINGERPRINT cert=YYYY iat-mode=0
```

---

## Struttura file

```
/opt/anonsurf-gui/
├── anonsurf_gui.py          GUI completa
├── anonsurf_gui_mini.py     GUI minimale
├── anonsurf_launcher.py     launcher
├── config.ini               configurazione
├── bridges.conf             bridge lines (editabile dalla GUI)
├── wireguard_profiles/      profili WireGuard .conf (opzionale)
├── torrc.backup             backup torrc originale
└── venv/                    ambiente Python isolato

/usr/local/bin/
├── anonsurf-gui
└── anonsurf-gui-mini
```

---

## Configurazione (`config.ini`)

```ini
[timing]
refresh_interval = 15000       # ms tra aggiornamenti IP
tor_verify_attempts = 15       # tentativi bootstrap (×3s = 45s max)

[gui]
window_width = 700
window_height = 900
max_log_lines = 100

[wireguard]
profiles_dir = wireguard_profiles
```

---

## Diagnostica

```bash
# Tor non si avvia
systemctl status tor
ss -tlnp | grep 9051
ls -la /run/tor/control.authcookie

# Cascata non funziona
which torsocks || sudo apt install torsocks
torsocks curl https://ifconfig.me/ip

# Bridge non funzionano
which obfs4proxy || sudo apt install obfs4proxy
# Aggiorna bridges.conf con nuove bridge lines
```

Il pulsante **🔍 VPN Scan** mostra la diagnostica completa del rilevamento VPN.

---

## Disinstallazione

```bash
sudo /path/to/anonsurf_v31/uninstall.sh
```

---

## Changelog

| Versione | Novità principali |
|----------|-------------------|
| **v3.3** | Semaforo VPN, `bridges.conf` con prova automatica, VPN non disconnessa alla chiusura, fix race condition verifica cascata |
| **v3.2** | Rilevamento VPN esterne, fix bootstrap cascata (check porta 9050), fix polling VPN (interfacce kernel), installer anti-blocco |
| **v3.1** | CascadeManager SOCKS5 (no iptables), proxy GNOME automatico, auto-verifica exit dopo NEWNYM, exception handler GUI |
| **v3.0** | WireGuard VPN, bridge dalla GUI, rilevamento blocco ISP all'avvio, modalità CASCATA |
| **v2.1** | 68 bandiere embedded, menu di sistema, launcher grafico |

---

## Crediti

**Red-Penguin** — MIT License  
Python 3.10+ · tkinter · AnonSurf · Tor · torsocks
