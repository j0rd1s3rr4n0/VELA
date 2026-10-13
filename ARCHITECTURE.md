# VELA — Arquitectura

## Principios

1. **Autodescubrimiento.** Nada se presupone: cada integración se activa solo si se detecta y se
   clasifica como `operativa`, `detectada_inactiva`, `sin_permisos`, `no_disponible` o `no_verificable`.
2. **Solo lectura por defecto.** Todo lo que modifica el sistema (rotaciones, kill-switch) o genera
   tráfico hacia terceros (IP pública directa, test activo de DNS) exige un consentimiento explícito
   en `[consent]`, y su ejecución queda registrada en la auditoría.
3. **Núcleo sin dependencias.** Solo la biblioteca estándar de Python ≥ 3.10. Las librerías externas son
   mejoras opcionales (`geoip2` para ciudad/ASN, `sqlcipher3` para cifrado real).
4. **Honestidad.** Ningún resultado se inventa: lo que no se puede comprobar se marca `unknown` con su
   limitación; la base de datos no se declara cifrada si solo la protegen los permisos de fichero.

## Componentes

```
                ┌──────────────────────── velad (daemon.py) ─────────────────────────┐
 netlink ──────▶│ NetlinkWatcher ─┐                                                   │
 Tor CIRC/STREAM▶│ TorObserver ────┤                                                   │
                │                 ▼                                                   │
                │   Engine (engine.py) ── tick() cada 1 s, sondeos de respaldo         │
                │     ├─ discovery   capacidades del sistema                           │
                │     ├─ network     interfaces, rutas, policy routing, ruta efectiva   │
                │     ├─ dns         resolvers por enlace, split DNS, DoT, test activo  │
                │     ├─ torctl      cliente propio del protocolo de control            │
                │     ├─ publicip    IP pública (directa/Tor/proxy) + WAN por UPnP      │
                │     ├─ geo         GeoIP local (base de Tor / .mmdb)                  │
                │     ├─ sessions    sesiones e intervalos por capa                     │
                │     ├─ leaks       diagnósticos con evidencia                         │
                │     ├─ rotation    políticas, selector, adaptadores, ciclo seguro     │
                │     ├─ killswitch  tabla nftables propia                              │
                │     ├─ forwarder   proxy local para rotar upstreams                   │
                │     ├─ analytics   stats, exposure score, correlación, anomalías      │
                │     └─ store       SQLite (0600) — history                            │
                │                 │                                                   │
                │   IPCServer (ipc.py) — socket UNIX 0600, SO_PEERCRED, lista blanca    │
                └─────────────────┬───────────────────────────────────────────────────┘
          ┌───────────────────────┼─────────────────────────┐
     vela (cli.py)          vela tui (tui.py)        vela gui (gui/server.py)
     argparse                curses                    HTTP 127.0.0.1 + token + CSP
                                                       SVG/JS propios, sin CDN
```

Si el daemon no está en marcha, la CLI, la TUI y la GUI crean el mismo `Engine` en su proceso
(`ipc.LocalBackend`) con `track=False`. Funcionan igual, pero no escriben sesiones en el historial.

| Requisito del diseño | Módulo |
|---|---|
| `velad` | `daemon.py` |
| `vela-cli` / `vela-tui` / `vela-gui` | `cli.py` / `tui.py` / `gui/` |
| discovery | `discovery.py` |
| network | `network.py` |
| vpn | `rotation.py` (adaptadores NetworkManager, wg-quick, Mullvad) + `discovery.py` |
| proxy | `forwarder.py` + `discovery.py` |
| tor | `torctl.py` |
| dns | `dns.py` |
| rotation | `rotation.py` |
| leak_detection | `leaks.py` |
| geo | `geo.py`, `worldmap.py` |
| history | `store.py`, `sessions.py` |
| analytics | `analytics.py`, `report.py` |
| profiles | `config.py` (`[profiles.*]`) + `engine.api_profile_activate` + `analytics.correlation` |
| security | `killswitch.py`, `ipc.py`, `util.redact`, permisos en `store.py` |

## Modelo de sesiones

Una **sesión** es la topología de salida observable durante un intervalo.

**Abren una sesión nueva** los cambios que alteran tu identidad de red:

- el perfil activo;
- la interfaz de salida;
- la VPN o su servidor;
- el proxy de la cadena;
- la IP WAN o la IP pública. Para estas dos, solo cuenta el paso de un valor conocido a otro distinto.

**Solo actualizan la sesión actual**, con un evento y un intervalo propio:

- los circuitos y exits de Tor, que Tor renueva por diseño;
- cambios de DNS;
- cambios de estado de las interfaces;
- conocer por primera vez un dato o perderlo.

Cada elemento observado se guarda en `intervals` con inicio y fin. Esas capas son: IP pública, IP WAN,
IP local, interfaz, VPN, servidor VPN, proxy, exit, guard y circuito de Tor, país, ASN, resolver,
perfil y combinación completa. **Todos los contadores salen de ahí** (tiempo total, usos, tiempo en
curso), con el formato `00d 00h 00m 00s`.

Si el daemon se detiene de forma brusca, al arrancar cierra lo que quedó abierto con la hora del
último latido (`heartbeat`).

## Rotación segura

`RotationEngine.rotate()` sigue estos pasos y registra cada uno:

1. Comprueba que hay un destino válido: sin repetir los últimos N, con cooldown, exclusiones de
   destino y de país, y exclusión de ASN solo si hay alternativas verificadas.
2. Comprueba que el adaptador es compatible y que hay consentimiento.
3. Comprueba que hay protección contra fugas si la política la exige y conoce los endpoints a permitir.
4. Aplica el kill-switch.
5. Rota.
6. Verifica el resultado.
7. Valida la política (país, ASN y exit repetido en Tor, con reintentos dentro del rate-limit).
8. Si todo va bien, libera el tráfico. Si falla, hace rollback. Si el rollback también falla, el
   kill-switch **se mantiene activo** (`failed_closed`) y se emite una alerta crítica.

Además se aplican límites de frecuencia: `min_ttl`, `max_per_hour` y una duración variable entre
`max_ttl - jitter` y `max_ttl`.

**Tor** tiene un trato especial. Solo se usa `SIGNAL NEWNYM`: no se tocan los guards ni se fija
`ExitNodes`, porque ambas cosas empeoran el anonimato. Tampoco se garantiza obtener un exit distinto.
Tor Browser, si se detecta en el 9151, queda en modo solo observación.

## Seguridad de la propia herramienta

- **IPC:** socket UNIX `0600` dentro de un directorio `0700`. El cliente se autentica por UID con
  `SO_PEERCRED` y solo se aceptan los métodos de una lista blanca.
- **GUI:**
  - escucha solo en loopback;
  - usa un token aleatorio en el fragmento `#` de la URL, que no viaja en las peticiones;
  - valida `Host` y `Origin` contra DNS rebinding y CSRF;
  - aplica una CSP sin orígenes externos;
  - construye el DOM sin `innerHTML` con datos observados;
  - no registra las peticiones.
- **Datos:**
  - SQLite con permisos `0600`, `secure_delete` y retención configurable;
  - modo memoria disponible;
  - los secretos se redactan antes de guardarse o mostrarse;
  - la auditoría registra los cambios de configuración y las acciones del usuario.
- **Kill-switch:** usa su propia tabla `inet vela_ks` y nunca toca reglas ajenas. Las reglas son
  solo IP (nunca nombres, que necesitarían DNS). Retirarlo equivale a borrar la tabla.
- **Emergencia** (`vela panic`): detiene las rotaciones y aplica el kill-switch si está permitido.
  No borra datos ni cambia la configuración.
