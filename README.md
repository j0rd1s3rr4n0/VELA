<p align="center"><img src="vela/data/vela.svg" width="112" alt="VELA"></p>

<h1 align="center">VELA</h1>
<p align="center"><b>V</b>igilant <b>E</b>gress &amp; <b>L</b>eak <b>A</b>nalyst<br>
<i>Tu identidad de red, siempre en vela.</i></p>

| Letra | Qué hace |
|---|---|
| **V**igilant | Vigila sin descanso: daemon, vigilante de fugas cada 2 s, eventos del kernel y avisos en la bandeja |
| **E**gress | Sigue cada salida de tu tráfico: router, VPN, proxies, Tor y DNS, con tiempos, sesiones y rotación |
| **L**eak | Detecta lo que te expone: conexiones fuera del túnel, DNS en claro, IPv6, WebRTC, kill-switch |
| **A**nalyst | Analiza y enriquece: geolocalización, VirusTotal, Shodan, GreyNoise, Censys, ExoneraTor y rutas |

*Vela* es la llama que queda encendida cuando todo duerme: **estar en vela** es quedarse vigilando.

VELA supervisa, registra y audita:

- la IP local, la IP WAN del router y la IP pública;
- los túneles VPN;
- los proxies;
- los circuitos de Tor;
- el DNS.

Guarda sesiones con tiempos y contadores, dibuja la cadena en un mapa mundial, detecta fugas y rota
salidas según políticas, siempre con verificación y rollback.

**Autodescubrimiento:** al arrancar inspecciona el sistema y activa solo lo que existe. Ver
[ARCHITECTURE.md](ARCHITECTURE.md).

Requisitos: Linux y Python ≥ 3.10. **No necesita dependencias externas.**

## Instalación

```bash
git clone https://github.com/j0rd1s3rr4n0/VELA.git && cd VELA
git config core.hooksPath .githooks    # guardián contra secretos y datos personales
python3 -m pip install --user .        # instala los comandos `vela` y `velad`
```

También funciona sin instalar, con `python3 -m vela <comando>`.

Opcionales:

- `pip install geoip2`, junto con las bases GeoLite2-City/ASN `.mmdb` en `~/.local/share/GeoIP/`, para
  obtener ciudad y ASN;
- `pip install sqlcipher3` para cifrado real de la base de datos.

Para observar Tor hace falta poder leer su cookie de control:

```bash
sudo usermod -aG debian-tor $USER
```

## Uso rápido

```bash
vela discover          # capacidades detectadas y su estado
vela daemon start      # monitorización continua en segundo plano
vela status            # cadena, IPs, Tor, DNS, sesión, contadores, rotación, alertas
vela tui               # terminal interactiva (curses)
vela gui               # dashboard + mapa en el navegador (solo 127.0.0.1)
```

| Comando | Qué hace |
|---|---|
| `vela tray [--install \| --remove]` | **Icono en la bandeja** (AppIndicator): estado de VPN, IP, exposición y fugas; abrir la app, comprobar IP/fugas, perfil, Tor, emergencia, ajustes rápidos y notificaciones |
| `vela daemon enable\|disable` | Arrancar el daemon con la sesión (servicio de usuario de systemd) para no perder historial |
| `vela app [--install]` | **Aplicación nativa de escritorio** (GTK 4 + libadwaita); `--install` añade el lanzador al menú |
| `vela leakwatch [--once] [--all]` | **IP pública y fugas de IP en tiempo real**: cada conexión clasificada como protegida / fuga / directa, con el programa responsable |
| `vela networks [-n]` | Todas tus redes (WiFi, LAN, VPN, Docker, VMs): tráfico, gateway, SSID, dispositivos vistos, aislamiento de VMs |
| `vela fix` | Comandos concretos para corregir cada problema detectado (no ejecuta nada) |
| `vela intel scan [IP…] [--file f] [--history]` | GreyNoise / VirusTotal / Shodan / Censys sobre tu historial o un listado (`intel keys`, `intel set-key`, `intel show`, `intel targets`) |
| `vela map [status\|build]` | **Mapa propio de OpenStreetMap, incorporado en la app** (`vela/data/`, funciona sin conexión en la app nativa, la TUI y la GUI web). `build` lo actualiza con datos recientes: descarga por Tor o la VPN (`--via direct` solo si lo pides, `--file` para un zip ya descargado); mirar el mapa no pide teselas a nadie |
| `vela network` | Interfaces, direcciones clasificadas (privada, CGNAT, ULA…), rutas y policy routing |
| `vela vpn list` / `vela proxy list` | VPN y proxies detectados, con su estado |
| `vela tor status` | Circuitos con guard, middle y exit; guards; comprobación externa |
| `vela dns check [--active]` | Resolvers por enlace, split DNS, DoT y fugas |
| `vela ip [--route tor]` | IP pública por vía (con consentimiento) e IP WAN por UPnP |
| `vela sessions` / `vela counters` / `vela history` | Sesiones, contadores `00d 00h 00m 00s` y timeline |
| `vela watch` | Eventos en tiempo real (requiere el daemon) |
| `vela rotate [tor\|proxy\|vpn] [--dry-run]` | Rotación segura o estado de la rotación |
| `vela leaks check [--active]` | Diagnósticos con evidencia, método, limitaciones y confianza |
| `vela profiles [activate X \| correlation \| generate [--write]]` | Perfiles, riesgo de correlación y generación de perfiles adaptados al sistema |
| `vela audit [--html f.html]` | Privacy Audit |
| `vela stats --period day\|week\|month` | Estadísticas y anomalías |
| `vela export --format json\|csv\|html --out …` | Exportar el histórico |
| `vela killswitch preview\|apply --yes\|release` | Kill-switch nftables (tabla propia) |
| `vela panic` / `vela resume` | Modo de emergencia (no borra datos) |
| `vela purge --days N --yes` | Borrar el histórico antiguo |
| `vela config show\|init\|edit` / `vela doctor` | Configuración y diagnóstico de la instalación |

Cualquier comando acepta `--json`. Sin el daemon, la CLI, la TUI y la GUI usan el motor en su propio
proceso, pero no registran sesiones.

## Consentimiento

Por defecto la herramienta solo observa. Estas acciones se activan en `[consent]`; ver
[config.example.toml](config.example.toml):

| Clave | Por qué está desactivada |
|---|---|
| `direct_ip_checks` | El servicio de eco vería tu IP real |
| `active_dns_leak_test` | Un servicio externo ve tu IP y tus resolvers |
| `allow_rotation_changes` | Cambia conexiones reales |
| `allow_killswitch` | Aplica reglas nftables (con `sudo -n` o pkexec) |

## Pruebas

```bash
python3 -m unittest discover -s tests -t .
```

Son 121 pruebas con mocks y backends simulados: un servidor de control de Tor falso con SAFECOOKIE
real, adaptadores de rotación con fallos, rollback y fail-closed, fugas simuladas, IPC, la seguridad
de la GUI y un proxy SOCKS5 falso. Ninguna prueba toca la conectividad real.

## Estado (validado el 2026-10-09 en Ubuntu 26.04, Python 3.14)

Leyenda:

- ✅ implementado y probado (pruebas automáticas y/o ejecución real en este equipo);
- 🟡 implementado pero pendiente de validación real;
- ⛔ no disponible por limitación del entorno;
- ⏳ pendiente.

| Funcionalidad | Estado | Evidencia |
|---|---|---|
| Descubrimiento de capacidades (5 estados) | ✅ | pruebas + `vela discover` real |
| Interfaces, rutas, ruta efectiva, clasificación IPv4/IPv6/CGNAT/ULA | ✅ | pruebas + `vela network` real |
| Eventos netlink | ✅ | daemon real: "netlink: eventos activos" |
| Tor: SAFECOOKIE, circuitos, guard/middle/exit, streams, guards | ✅ | servidor falso + 22 circuitos reales |
| Tor: IP de salida vía check.torproject.org (IsTor) | ✅ | real: 185.220.101.140 confirmado |
| Tor: NEWNYM con rate-limit y no repetición de exit | ✅ / 🟡 | probado con mocks y dry-run real; NEWNYM real no ejecutado (sin consentimiento) |
| DNS por enlace (systemd-resolved), split DNS, DoT | ✅ | pruebas + `vela dns check` real |
| DNS efectivo y cifrado: WARP DoH, cloudflared, dnscrypt/stubby, DoT, DoH de Firefox/Chromium; ruta del DoH | ✅ | pruebas + real: WARP DoH por `proton0` |
| Kill-switch de clientes (ProtonVPN, Mullvad, NordVPN) + verificación por rutas «¿y si cae el túnel?» | ✅ / 🟡 | ProtonVPN real verificado (IPv4/IPv6); Mullvad/NordVPN sin validar (no instalados) |
| Clientes VPN en snap/flatpak (ProtonVPN) y servidor VPN desde el nombre de la conexión | ✅ | real: `ProtonVPN CH-DE#2` |
| Generación de perfiles (diario, privado, anónimo, alto riesgo, laboratorio) y políticas `require_killswitch`/`dns_policy` | ✅ | pruebas + perfiles reales evaluados en vivo |
| Fugas pasivas: IPv6, túnel, DNS, proxy expuesto, zona horaria, MAC, kill-switch | ✅ | pruebas + hallazgos reales |
| Monitorización de todas las redes: tráfico, vecinos ARP (sin escanear), huella de red, cambio de MAC del gateway (ARP spoofing), dispositivos nuevos, WiFi abierta, aislamiento de redes libvirt | ✅ | pruebas + real: detectó `pentest-isolated` con NAT |
| IP pública solo por túnel (`public_ip.require_tunnel`) | ✅ | pruebas + real: omitida al caer la VPN |
| IP pública en tiempo real (cada 60 s con túnel + inmediata al cambiar la ruta) y detección de «Internet ve tu IP real» | ✅ / 🟡 | pruebas; validación real pendiente de reconectar la VPN |
| Vigilante de fugas en tiempo real (sockets del kernel cada 2 s, programa responsable, fugas DNS, reacción automática con kill-switch) | ✅ | pruebas + real: 29 conexiones directas detectadas con la VPN caída |
| Remediación con comandos (`vela fix`, GUI con botón copiar) | ✅ | pruebas + ejecución real |
| Threat intel: GreyNoise | ✅ | pruebas + consulta real vía Tor |
| Threat intel: VirusTotal / Shodan | ✅ | validados con las claves reales del usuario (puntuación VT, puertos Shodan) |
| Threat intel: Censys | 🟡 | implementado y probado con respuestas simuladas; sin clave para validar |
| Geolocalización con bandera, organización y puntuación VT en Tiempo real y Threat intel | ✅ | pruebas + datos reales |
| Icono de bandeja con estado y controles + notificaciones de escritorio | ✅ | real: registrado en la bandeja de GNOME y menú verificado por D-Bus |
| Persistencia: daemon con la sesión (systemd), ajustes desde la app, API keys desde la app | ✅ | pruebas + servicio activo |
| GUI nativa GTK 4 + libadwaita (panel, redes, mapa cairo, historial, alertas, intel, perfiles, notificaciones) | ✅ | capturas reales renderizadas por GTK |
| Test activo de fugas DNS (bash.ws) | 🟡 | implementado; no ejecutado (requiere consentimiento) |
| Prueba WebRTC en la GUI | 🟡 | implementado; no ejecutado en un navegador |
| IP pública directa / por proxy | 🟡 | implementado; desactivado sin consentimiento |
| IP WAN por UPnP-IGD + CGNAT/doble NAT | 🟡 | implementado; tu router no responde a UPnP |
| Sesiones, intervalos, contadores, persistencia, recuperación | ✅ | pruebas + daemon real |
| Motor de rotación (selector, cooldown, exclusiones, límites, rollback, fail-closed) | ✅ | 12 pruebas con backend simulado |
| Adaptadores VPN NetworkManager / wg-quick / Mullvad | 🟡 | implementados; sin validar. ProtonVPN (app gráfica v4) no tiene CLI para cambiar de servidor: solo se observa |
| Forwarder para rotar proxies | ✅ | prueba con upstreams locales |
| Kill-switch nftables | ✅ / 🟡 | reglas probadas y vista previa real; no aplicado (consentimiento y sudo) |
| Perfiles, Correlation Risk Engine, anomalías, estadísticas, Exposure Score | ✅ | pruebas |
| Exportación JSON/CSV/HTML, Privacy Audit, doctor | ✅ | ejecución real |
| IPC (0600, SO_PEERCRED, lista blanca, eventos) | ✅ | pruebas + permisos reales |
| CLI | ✅ | todos los comandos ejecutados contra el sistema real |
| TUI (curses) | ✅ / 🟡 | arranque y renderizado reales; navegación interactiva no verificada por mí |
| GUI (token, Host/Origin, CSP, dashboard, mapa, timeline) | ✅ | pruebas + navegador real sin errores de consola |
| Rutas del tráfico (programa → proxy/Tor/directo → VPN → destino), `vela routes` + diagrama en Tiempo real | ✅ / 🟡 | pruebas + datos reales (Tor y directo sin VPN); proxy local real y proxy encadenado solo con pruebas simuladas (no hay proxy en el equipo) |
| Proxy HTTP vs servidor web (sonda CONNECT) | ✅ | pruebas + :8080 real identificado como servidor web |
| Mapa base OpenStreetMap incorporado (Mercator, 4 niveles de detalle, costa, países, capitales y ciudades; offline; también TUI y GUI web) | ✅ | pruebas + datos OSM reales descargados por Tor y capturas de la app nativa; GUI web comprobada solo con pruebas y `node --check` |
| Fronteras entre países en el mapa | ⏳ | no incluidas (los datos de fronteras de OSM pesan cientos de MB) |
| Ciudad / ASN | ⛔ | sin base `.mmdb` en el sistema (opcional) |
| Cifrado de la base de datos | ⛔ | SQLCipher no instalado: la base **no** está cifrada, solo protegida por permisos 0600 |
| Plataformas Windows y macOS | ⏳ | el núcleo es específico de Linux (/proc, /sys, netlink, nftables) |
| Proxies PAC/WPAD: evaluación del script | ⏳ | se detecta que existen, pero no se evalúa el script PAC |

## Limitaciones conocidas

- La geolocalización es local y aproximada (país). **No es la ubicación física real** de los servidores.
- `NEWNYM` no garantiza un exit distinto. La herramienta nunca toca los guards ni fija `ExitNodes`.
- Tor Browser, si se detecta en el puerto 9151, solo se observa: su rotación es "Nueva identidad".
- Separar perfiles de red no evita la correlación por cookies, cuentas o la huella del navegador.

## Repositorio git seguro

El repositorio trae un guardián (`vela/gitguard.py`) que se ejecuta solo con los hooks de `.githooks/`
(`git config core.hooksPath .githooks` tras clonar):

- **pre-commit**: bloquea ficheros personales (`.devlogs/`, bases de datos, `secrets.toml`, `config.toml`,
  ajustes de la app, cookies de Tor, configuraciones de VPN, claves…), patrones de secretos (claves privadas,
  PrivateKey de WireGuard, tokens de GitHub/AWS/Google/Slack, `api_key = "…"`) y los **valores exactos de tu
  equipo**: tus claves de API y tus IPs reales, sin guardarlos en ningún sitio.
- **pre-push**: revisa cada commit que se va a publicar (también lo borrado después, porque sigue en el
  historial) y bloquea si el correo del autor no es anónimo (`…@users.noreply.github.com`).
- `python3 -m vela.gitguard all`: revisa todo lo que ya está en el repositorio.

Nunca muestra el secreto encontrado, solo fichero, línea y tipo. `user.useConfigOnly=true` impide que git
invente tu identidad a partir del usuario y el nombre del equipo.

## Migración desde OPSecTools

VELA se llamaba *OPSecTools* (comandos `opsec`/`opsecd`). El primer comando de `vela` mueve tus datos
(`~/.config`, `~/.local/share`, `~/.local/state` y `~/.cache` de `opsectools` a `vela`, con `opsec.db` → `vela.db`),
sustituye el servicio `opsecd` por `velad` si estaba habilitado y renueva el autoarranque de la bandeja y el
lanzador. Nunca sobrescribe datos nuevos y no actúa mientras el daemon antiguo siga en marcha.
