# VELA — Plan de diseño (histórico)

> Este fue el plan inicial. La implementación real está descrita en [README.md](README.md)
> (uso y estado) y [ARCHITECTURE.md](ARCHITECTURE.md) (diseño). Diferencias principales respecto a
> este plan: núcleo solo con biblioteca estándar (curses en vez de Textual, cliente Tor propio en vez
> de stem, GUI web local propia en vez de FastAPI/Leaflet) porque el sistema no tenía esas librerías.

Herramienta (CLI + TUI + GUI) para registrar y controlar tu **identidad de red de salida**:
IP pública del router, VPNs, proxies, circuitos Tor y DNS. Guarda cuándo y cuánto tiempo
usas cada salida, la pinta en un mapa mundi y rota automáticamente cuando una salida lleva
demasiado tiempo en uso, sin repetir combinaciones recientes.

---

## 1. Arquitectura

```
                    ┌──────────────────────────────────────────┐
                    │              velad (daemon)             │
                    │                                          │
  Collectors ──────▶│  Event bus ─▶ State engine ─▶ SQLite DB  │
  (sondas)          │                  │                       │
                    │            Rotation engine ─▶ Drivers    │
                    │            Leak/alert engine             │
                    │                  │                       │
                    │           API local (unix socket)        │
                    └──────────────────┬───────────────────────┘
                     ┌─────────────────┼─────────────────┐
                    CLI              TUI               GUI
                  (Typer)         (Textual)    (web local: FastAPI + Leaflet,
                                                o Tauri/pywebview como app)
```

- **Un solo núcleo (daemon)** y tres interfaces delgadas: así CLI, TUI y GUI ven
  siempre los mismos datos y el demonio sigue monitorizando aunque cierres la interfaz.
- API solo por **unix socket** (`/run/user/$UID/vela.sock`, permisos 0600). Nada
  escucha en TCP salvo que la GUI web lo pida, y entonces solo en `127.0.0.1` con token.
- **Lenguaje:** Python 3.12+ (asyncio). Librerías: `stem` (Tor), `dnspython`,
  `httpx[socks]`, `textual`, `typer`, `fastapi`, `sqlite` + `sqlcipher` (opcional),
  `geoip2` (MaxMind GeoLite2 / DB-IP **offline**).

## 2. Modelo de datos

Concepto central: una **Sesión de salida** = periodo de tiempo con la misma "huella de red".

| Tabla | Campos clave |
|---|---|
| `exit_layer` | id, tipo (`isp`/`vpn`/`proxy`/`tor`), identificador (IP, servidor, fingerprint del nodo), proveedor, país, ASN |
| `session` | id, inicio, fin, duración, cadena de capas (p. ej. `isp → vpn:se-12 → tor:exit-ABC`), IP pública visible, motivo de cierre (rotación auto, manual, caída, cambio del ISP) |
| `dns_observation` | timestamp, resolvers configurados, resolver real visto desde fuera, consulta, respuesta, ¿vía túnel? |
| `leak_event` | timestamp, tipo (DNS, IPv6, WebRTC, fallo del kill-switch), severidad, detalle |
| `rotation_policy` | capa, TTL máx., jitter, ventana sin repetición, pool, países excluidos |
| `usage_counter` | capa+identificador → nº de veces usado, tiempo total, último uso |

Con esto salen solas las métricas pedidas: **intervalos** (sesiones con inicio/fin),
**contadores** (veces que usaste cada IP/nodo/servidor) y **tiempo acumulado**.

## 3. Collectors (qué se mide y cómo)

| Capa | Fuente | Frecuencia |
|---|---|---|
| IP pública del router | Fuera del túnel: consulta vía interfaz física (`SO_BINDTODEVICE`) a 2–3 servicios elegidos al azar (ipify, icanhazip, ifconfig.co, servidor propio) y comparar | 5 min |
| IP de salida real | Lo mismo pero a través de la ruta por defecto / del SOCKS | 60 s + en cada evento de red |
| VPN | `wg show`, interfaces `tun*`/`wg*`, NetworkManager por D-Bus, management interface de OpenVPN | por eventos (netlink) + sondeo |
| Proxy | Config propia (lista de proxies) + comprobación de IP a través de cada proxy | por demanda |
| Tor | `stem` en el ControlPort: `CIRC`, `STREAM`, `GUARD`; relays del circuito (guard/middle/exit), fingerprint, país, flags | por eventos |
| DNS | `/etc/resolv.conf`, `resolvectl status`, **leak test** (resolver tu subdominio único y ver qué resolver llega al autoritativo) | 5 min + al cambiar de sesión |
| Red local | netlink: cambios de ruta, interfaz, SSID/BSSID WiFi, MAC actual | por eventos |

**Geolocalización siempre offline** (base de datos local). Consultar IPs a un servicio de
geolocalización externo es en sí una fuga de información.

## 4. Rotación automática

Motor por capa con política configurable:

```toml
[rotation.vpn]
max_ttl      = "45m"
jitter       = "±10m"        # evita patrones horarios fáciles de correlacionar
no_repeat    = 10            # no reutilizar los últimos 10 servidores
exclude_countries = ["ES", "US"]   # p. ej. no salir por tu país ni por 14-eyes
pool         = "mullvad-wg"  # driver + lista de servidores

[rotation.tor]
max_ttl   = "10m"            # NEWNYM respetando el rate-limit de Tor
no_repeat_exit = 20
exclude_exit_countries = ["{es}"]

[rotation.proxy]
max_ttl = "20m"
strategy = "least-recently-used"
```

- **No repetición:** selección ponderada que penaliza lo usado recientemente
  (LRU + ventana deslizante + aleatoriedad criptográfica `secrets`). Opción de no
  repetir tampoco la **combinación** de cadena (VPN X + exit Y).
- **Rotación segura:** pausar el tráfico (kill-switch nftables) → cambiar → verificar
  la nueva IP/DNS → reanudar. Si la verificación falla, se queda bloqueado y avisa.
- **Drivers** intercambiables: `wireguard` (wg-quick / NetworkManager), `openvpn`,
  CLI de proveedores (mullvad, protonvpn), `tor` (NEWNYM / `ExitNodes`), `proxy`
  (lista + reescritura de config de proxychains o un SOCKS local que reenvía).
- La IP del ISP normalmente no se puede rotar a demanda; se **registra** y, opcionalmente,
  se reinicia el módem/router si este expone una API (driver opcional).

## 5. Mapa mundi

- **GUI:** Leaflet con teselas **offline** (o mapa vectorial Natural Earth incluido)
  para no filtrar tu ubicación a un servidor de mapas.
  - Marcadores por capa (ISP / VPN / proxy / guard / middle / exit) unidos con arcos
    → se ve la cadena completa.
  - Slider temporal para reproducir el historial; mapa de calor de países usados.
- **TUI:** mapa ASCII/braille (proyección equirectangular sobre un mapa de bits
  pequeño) con los puntos de la cadena actual.

## 6. Interfaces

**CLI**
```
vela status                  # cadena actual, IP, país, tiempo en sesión, próxima rotación
vela history --since 24h     # sesiones con intervalos
vela stats --by country      # contadores y tiempo acumulado
vela rotate [vpn|tor|proxy|all]
vela leaktest                # DNS / IPv6 / WebRTC
vela policy edit
vela export --format json|csv
vela panic                   # ver §7
```

**TUI (Textual):** paneles con la cadena en vivo, cuenta atrás de rotación, minimapa,
timeline de sesiones, log de alertas y DNS.

**GUI:** dashboard web local (o empaquetado con Tauri/pywebview): mapa, gráficos de
duración por sesión, tabla filtrable, editor de políticas.

## 7. Features extra de OPSEC

**Detección de fugas y anomalías**
- Leak test continuo de **DNS**, **IPv6** (salida por IPv6 fuera del túnel) y **WebRTC**
  (página local de prueba).
- **Alerta de caída del túnel** y kill-switch nftables gestionado por la propia herramienta.
- Detección de **cambio inesperado de IP** de salida en mitad de una sesión
  (posible fallo del túnel o de la ruta).
- Aviso de **resolver DNS no esperado** (el de tu ISP en lugar del de la VPN).
- **Captive portal / MITM:** comparar certificados TLS de un par de sitios con pins conocidos.
- Comprobación de que el **guard de Tor** no cambia con demasiada frecuencia
  (rotar guards rápido debilita el anonimato; la herramienta debe avisar, no forzarlo).

**Higiene de la identidad**
- **Randomización de MAC** por red/conexión (NetworkManager) y registro de la MAC usada.
- **Hostname/DHCP** aleatorio o genérico al conectarse a redes ajenas.
- **Perfiles/compartimentación:** cada "persona" o actividad con su propia cadena,
  país, horario y política; alerta si dos perfiles comparten una IP de salida
  (**contaminación cruzada**).
- **Desfase de zona horaria:** avisar si la zona horaria/idioma del sistema no
  encaja con el país de salida (el navegador lo revela).
- **Detección de patrones propios:** analizar tu historial y avisar si siempre
  rotas a la misma hora, usas el mismo país los lunes, etc.

**Seguridad de la propia herramienta** (el log es material sensible: describe todo tu rastro)
- Base de datos cifrada (SQLCipher) con contraseña o clave en el keyring.
- **Retención configurable** (p. ej. borrar automáticamente lo de más de 7 días).
- `vela panic`: kill-switch total + borrado seguro de la DB + parar el daemon.
- Modo **amnésico**: todo en RAM (`tmpfs`), nada en disco.
- Sin telemetría, sin peticiones a terceros salvo los ecos de IP configurados,
  hechos aleatoriamente y a través de la capa que se está midiendo.

**Integraciones opcionales**
- Notificaciones de escritorio (libnotify) y webhook propio.
- Exportar el historial (JSON/CSV) para tus propios análisis.
- Consulta de reputación de IP de salida contra **listas descargadas** (blocklists,
  lista de exits de Tor), nunca en línea.

## 8. Estructura del repositorio

```
vela/
  core/        models.py  db.py  events.py  state.py
  collectors/  publicip.py  vpn.py  tor.py  proxy.py  dns.py  netlink.py
  rotation/    engine.py  selector.py  drivers/{wireguard,openvpn,mullvad,tor,proxy}.py
  security/    killswitch.py  leaks.py  vault.py  panic.py
  geo/         geoip.py  data/ (GeoLite2, Natural Earth)
  api/         server.py (unix socket)  client.py
  ui/          cli.py  tui/  gui/ (FastAPI + static Leaflet)
  daemon.py
config.example.toml
systemd/velad.service   # unidad de usuario; solo kill-switch/rotación con privilegios vía polkit
tests/
```

## 9. Fases

| Fase | Entregable |
|---|---|
| **0. Autodetección** ✅ | `vela discover`: inventario del sistema, avisos y `config.toml` generado (§10) |
| **1. MVP de monitorización** | daemon, collectors de IP pública + VPN + Tor + DNS, SQLite, CLI `status/history/stats` |
| **2. TUI** | dashboard Textual en vivo + minimapa ASCII |
| **3. Rotación** | motor de políticas, no repetición, drivers WireGuard/Tor/proxy, kill-switch durante el cambio |
| **4. Fugas y alertas** | leak tests DNS/IPv6/WebRTC, alerta de caída, cambios inesperados de IP |
| **5. GUI + mapa** | dashboard web local, Leaflet offline, timeline reproducible |
| **6. Endurecimiento** | DB cifrada, retención, modo amnésico, `panic`, perfiles y contaminación cruzada |

## 10. Autodetección (fase 0, implementada en `vela/discovery.py`)

La herramienta no pregunta qué usas: lo averigua. **No hace ninguna conexión fuera
de 127.0.0.1**: solo lee `/proc` y `/sys`, consulta ficheros de configuración, ejecuta
comandos locales de solo lectura y sondea puertos de loopback.

| Qué | Cómo lo detecta |
|---|---|
| Interfaces y tipo (WireGuard, tun, ppp, WiFi, Ethernet) | `/sys/class/net/*` (`uevent`, `tun_flags`, `wireless`) |
| Por dónde sale realmente el tráfico | `ip route get` (respeta el policy routing de wg-quick) |
| Fugas IPv6 | `/proc/net/if_inet6` + ruta IPv6 frente a ruta IPv4 |
| Clientes VPN de proveedor | binarios mullvad, nordvpn, protonvpn, piactl, ivpn, expressvpn… y su `status` |
| VPN de NetworkManager | `nmcli` (tipos `vpn`/`wireguard`, plugin usado) |
| WireGuard / OpenVPN sueltos | `/etc/wireguard/*.conf`, `*.ovpn` en las rutas habituales |
| Tor | ControlPort/ControlSocket (`PROTOCOLINFO`: versión y método de auth), SocksPort (huella HTTP 501), `torrc`, bridges, Tor Browser |
| Proxies | puertos de loopback que responden como SOCKS5/HTTP, túneles `ssh -D`, proxychains, variables `*_proxy`, proxy de GNOME |
| DNS | `resolv.conf`, `resolvectl` (por enlace, DoT, DNSSEC), resolvers locales |
| Kill-switch | nft / iptables, ufw / firewalld, privilegios (root, sudo, pkexec) |
| Identidad | origen de la MAC (permanente/aleatoria), política de MAC de NM, hostname, zona horaria, idioma |
| GeoIP offline | `.mmdb` (GeoLite2/DB-IP) o, si no hay, la base `geoip` que trae Tor |
| Interfaces de usuario | módulos de Python instalados, entorno gráfico |

Con esto elige solo los **collectors**, el **driver de rotación** de cada capa
(cliente del proveedor → NetworkManager → wg-quick → openvpn; Tor por `NEWNYM` o, sin
ControlPort, por aislamiento de credenciales SOCKS) y el backend del kill-switch, y
genera `config.toml`.

El daemon repetirá la detección **al arrancar y en cada cambio de red** (eventos
netlink), de modo que si abres Tor Browser o levantas una VPN nueva se activa sola
la monitorización correspondiente.
