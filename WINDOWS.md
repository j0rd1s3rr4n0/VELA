# VELA en Windows — encargo para un agente de IA (rama `windows-lite`)

Este documento es un **encargo completo** para una IA de programación (por ejemplo, Claude Code) que trabaje
**en un Windows real**, con el repositorio clonado y la rama `windows-lite` activa. Desde Linux no se puede
probar nada de Windows; por eso este trabajo se hace allí.

**Cómo usarlo:** abre una terminal en la carpeta del repositorio (`git switch windows-lite`), arranca el
agente y pégale esto:

> Lee `WINDOWS.md` entero y ejecútalo de principio a fin, fase por fase, siguiendo sus reglas.

Todo lo que viene a continuación va dirigido al agente.

---

## 0. Qué es VELA y qué tienes que conseguir

**VELA — Vigilant Egress & Leak Analyst** vigila la identidad de red del equipo:
- IP pública e interfaces;
- VPN, proxies y Tor;
- DNS y si va cifrado;
- conexiones que salen fuera del túnel (fugas) y conexiones directas que muestran la IP real;
- inteligencia de amenazas;
- un mapa OpenStreetMap propio que funciona sin conexión.

La rama `master` es solo para Linux: núcleo en Python 3 sin dependencias, app GTK 4, bandeja, daemon con
systemd y GUI web local.

**Tu objetivo en esta rama es la versión ligera para Windows:**
- Funciona con Python 3.10 o superior **sin instalar paquetes de pip**.
- Ofrece la CLI (`vela status`, `vela leakwatch`, `vela dns`, `vela routes`, `vela networks`…) y la GUI web
  (`vela gui`, en el navegador o en una ventana de Edge en modo app).
- Tiene un proceso en segundo plano opcional que guarda el historial y arranca al iniciar sesión.
- Se instala con `install.cmd` / `install.ps1`, sin permisos de administrador.
- Se actualiza con `vela update`.

**Fuera de alcance** (es la futura rama `windows`, que saldrá de esta cuando la ligera funcione):
- kill-switch con el Firewall de Windows;
- servicio de Windows;
- icono en la bandeja;
- app nativa;
- rotación de VPN y remediación automática.

En la versión ligera, **no** modifiques el firewall, las rutas, el DNS ni los adaptadores.

## 1. Reglas obligatorias (no negociables)

Estas reglas vienen del autor del proyecto y mandan sobre cualquier otra consideración:

1. Prioriza operaciones de inspección de solo lectura.
2. No cambies rutas, reglas de firewall, DNS ni túneles existentes sin autorización explícita.
3. No interrumpas la conectividad del equipo para hacer pruebas.
4. No leas ni almacenes credenciales innecesariamente.
5. No envíes información sensible a servicios externos sin consentimiento.
6. No abras servicios de administración a interfaces públicas: todo escucha en `127.0.0.1` y nunca en `0.0.0.0`.
7. No introduzcas puertas traseras ni mecanismos ocultos.
8. Cualquier cambio persistente o potencialmente disruptivo debe requerir una acción explícita del usuario.
9. **No inventes resultados de pruebas.** Si algo no se ha podido verificar, dilo.
10. Nunca afirmes que algo está cifrado si solo está protegido por permisos (ACL) de archivo.
11. No generes tráfico que exponga la IP de origen fuera de una VPN o proxy sin autorización previa.
    Las descargas y consultas de VELA salen por Tor si está disponible, si no por la VPN, y solo
    directamente si el usuario lo pide (`--via direct`).
12. Preserva los mecanismos de seguridad de Tor. No fuerces la rotación de nodos guard.
13. No uses CDN externas de manera implícita: la GUI web no carga nada de fuera.
14. No preguntes qué herramientas hay instaladas: **descúbrelo automáticamente**.

**Reglas del repositorio:**
- **Identidad de git:** haz todos los commits como
  `j0rd1s3rr4n0 <44474715+j0rd1s3rr4n0@users.noreply.github.com>`. Configúrala solo en este repositorio
  (`git config user.name` / `user.email`, sin `--global`).
- **Nada personal en el repositorio:** nunca subas IPs reales, MACs, SSIDs, nombres de usuario o de equipo,
  claves de API ni correos. Las capturas y los fixtures deben ir anonimizados. Usa los rangos de
  documentación `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` y MACs
  `02:00:5e:00:00:xx`.
- **Hooks de commit:** los hooks de `.githooks/` (gitguard) deben estar activos:
  `git config core.hooksPath .githooks`. Git for Windows trae `bash`, así que funcionan. Si un hook
  bloquea un commit, corrige la causa; no uses `--no-verify`.
- **Ramas:** trabaja solo en `windows-lite`. No toques `master`. Haz commits pequeños, con mensajes en
  español, y `git push origin windows-lite` al cerrar cada fase que funcione.
- **Traducciones:** todo texto visible va en español dentro de `_("…")` (o `N_()` en constantes) y se
  traduce en `vela/locale/{en,ca,pt,fr,de}.json`. `python3 -m vela.i18n check` debe terminar sin faltas.
- **Cambios en el sistema:** antes de instalar algo en el equipo (Python, Tor…) o de cambiar algo fuera
  del repositorio, pregunta al usuario.
- **Estilo:** mantén el del código existente: comentarios en español, funciones `parse_*` / `build_*` puras
  y probables, y nada de dependencias externas.

## 2. Estado actual de la rama (lo que ya está hecho, sin probar en Windows)

| Pieza | Dónde | Estado |
|---|---|---|
| Capa de datos de Windows | `vela/winsys.py` | Escrita y probada **solo con datos simulados** (`tests/test_windows.py`) |
| Conexiones TCP y su PID | `winsys.parse_tcp4/6`, `tcp_rows()` (ctypes `GetExtendedTcpTable`) | Parsers probados con binario sintético |
| Nombres de proceso | `winsys.process_names()` (Toolhelp32) | Sin probar |
| Interfaces, rutas y salida efectiva | `winsys.build_network()` + `NET_SCRIPT` (PowerShell → JSON) | Constructor probado con JSON inventado; el script de PowerShell **no se ha ejecutado nunca** |
| DNS y DoH | `winsys.build_dns()` + `DNS_SCRIPT` | Igual que el anterior |
| Inventario de redes y Wi-Fi | `winsys.build_inventory()`, `parse_wlan()` (netsh) | `parse_wlan` probado con texto en español e inglés |
| Descubrimiento | `winsys.discover()` | Sin probar |
| Desvíos a Windows | `network.snapshot`, `dns.snapshot`, `leakwatch.read_sockets/owners`, `discovery.discover`, `protection.detect_killswitches`, `networks.inventory` (usan `winsys` si `util.WINDOWS`) | Hechos; en Linux todo sigue igual |
| Rutas de usuario | `util.xdg_dir`: configuración en `%APPDATA%\vela`; datos y estado en `%LOCALAPPDATA%\vela\{data,state}`; `util.runtime_dir` | Hecho |
| Idioma | `i18n._from_env` usa `GetUserDefaultLocaleName` | Hecho |
| Módulos solo de Unix | `grp`, `pwd`, `SO_BINDTODEVICE` protegidos | Hecho |
| Icono | `vela/data/brand/vela.ico` (16–256 px, del Brand Kit) | Listo para el acceso directo |
| Actualizador | `vela/updater.py` (`vela update`) | `run_installer()` todavía llama a `bash install.sh`: **hay que adaptarlo** |
| **Bloqueo** | `vela/cli.py`, `main()`: si no es Linux, sale con «VELA solo funciona en Linux» | **Pendiente de quitar en esta rama** |

## 3. Fase 0 — Reconocimiento (solo lectura)

1. Descubre el entorno sin preguntar y anótalo, sin datos personales, en tu informe final:
   - versión de Windows (`[Environment]::OSVersion`, `Get-ComputerInfo -Property OsName,OsVersion`);
   - PowerShell (`$PSVersionTable`);
   - Python (`py -3 --version`, `python --version`; cuidado con el alias de la Microsoft Store que abre la
     tienda) y git;
   - si hay Tor Browser o `tor.exe`, clientes VPN (procesos y adaptadores) y Edge o Chrome.
2. Ejecuta las pruebas existentes: `py -3 -m unittest discover -t . -s tests`. Clasifica cada fallo:
   - (a) fallo real de VELA en Windows → corrígelo;
   - (b) prueba que solo tiene sentido en Linux → márcala con `@unittest.skipUnless(sys.platform.startswith("linux"), …)`
     y explica por qué;
   - (c) diferencia de entorno (rutas, finales de línea, codificación) → corrígela en el código, no en la prueba.

   No borres pruebas.
3. **Valida `winsys` contra la realidad.** Para cada función, compárala con una fuente independiente:

   | Función | Contrastar con |
   |---|---|
   | `tcp_rows()` y `read_sockets()` | `netstat -ano` y `Get-NetTCPConnection` |
   | `process_names()` | `Get-Process` |
   | `network_snapshot()` | `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute -DestinationPrefix 0.0.0.0/0`, `Find-NetRoute -RemoteIPAddress 1.1.1.1` |
   | `dns_snapshot()` | `Get-DnsClientServerAddress`, `Get-DnsClientDohServerAddress`, `ipconfig /all` |
   | `inventory()` | `Get-NetAdapterStatistics`, `Get-NetNeighbor`, `netsh wlan show interfaces` |
   | `discover()` | revisión clave por clave |

   - Si una salida real no coincide con lo que espera el parser (nombres de propiedad, enumeraciones como
     números en vez de texto, Windows en otro idioma, un solo objeto en vez de una lista…), corrige el parser.
   - **Guarda la salida real anonimizada como fixture** (`tests/fixtures/windows/*.json` o `*.txt`) y
     añade la prueba correspondiente a `tests/test_windows.py`.
   - Mide cuánto tarda cada script de PowerShell. Si `NET_SCRIPT` + `DNS_SCRIPT` superan unos 3 s, el
     motor no puede llamarlos en cada ciclo: añade una caché con caducidad corta y una invalidación barata
     (por ejemplo, la tabla de rutas por ctypes `GetIpForwardTable2`, o `NotifyIpInterfaceChange`).
4. Comprueba la clasificación de adaptadores (`winsys.classify_adapter`) con los adaptadores reales:
   WireGuard/WinTUN, TAP, Hyper-V/WSL, Wi-Fi, Ethernet y Bluetooth. Un falso «VPN» o un túnel no detectado
   cambian los veredictos de fuga: es crítico.

## 4. Fase 1 — Que VELA arranque en Windows

1. **`vela/cli.py`:**
   - En esta rama, permite `win32` en `main()`.
   - Mantén un mensaje claro (traducido) en los comandos que no existen en la versión ligera: `app`
     (nativa GTK), `tray`, `killswitch apply/remove`, `rotate` con cambios reales y `fix --apply`.
     En `app`, sugiere `vela gui`.
   - `tui` solo funciona si `curses` se puede importar; si no, explica que hace falta `windows-curses`
     (no lo instales tú).
2. **Comunicación con el proceso de fondo (`vela/ipc.py`):** en Windows no hay `AF_UNIX` (en CPython) ni
   `SO_PEERCRED`. Implementa un transporte TCP:
   - escucha **solo** en `127.0.0.1`, en un puerto aleatorio;
   - genera un token aleatorio de 32 bytes con `secrets.token_urlsafe`;
   - guarda el puerto y el token en `runtime_dir()/ipc.json`, creado solo para el usuario (en Windows
     hereda la ACL del perfil; documéntalo y **no** digas que está cifrado);
   - el cliente envía el token en la primera línea y el servidor lo compara con `hmac.compare_digest`;
   - si el token falla, cierra la conexión sin más.

   El protocolo JSON por líneas es el mismo que ahora; `subscribe` debe seguir funcionando. En Linux
   no cambia nada. Pruebas: token correcto, token incorrecto, conexión desde otra dirección rechazada y
   fichero ausente → `connect()` cae a `LocalBackend`.
3. **Proceso de fondo (`vela/daemon.py`, `vela/autostart.py`):**
   - En Windows no hay `os.fork` ni `resource` (protégelos).
   - `vela daemon start` lanza `pythonw.exe -m vela daemon run` desacoplado
     (`DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`).
   - `vela daemon stop` lo para por IPC.
   - `vela daemon enable/disable/status` gestiona un acceso directo o un `.vbs` en la carpeta Inicio del
     usuario (`shell:startup`), sin tareas programadas de sistema, sin servicio y sin permisos de
     administrador.

   Es un cambio persistente: solo cuando el usuario lo pide (`vela daemon enable`, una opción de la GUI
   web o del instalador).
4. **Motor (`vela/engine.py`):** recorre cada método que usa la GUI web y la CLI y busca supuestos de
   Linux:
   - lecturas de `/proc`, `/sys` o `/etc`;
   - comandos `ip`, `nmcli`, `resolvectl`, `systemctl` o `nft`;
   - `os.getuid` y señales POSIX.

   Lo que no tenga equivalente debe devolver «no disponible en Windows», nunca un dato inventado ni un
   cero engañoso. Ejecuta `vela doctor`, `vela status`, `vela leakwatch --once`, `vela dns`, `vela routes`,
   `vela networks` y `vela tor`, y corrige lo que falle.
5. **GUI web (`vela gui`):**
   - Debe arrancar el servidor en `127.0.0.1` y abrir el navegador (ya lo hace).
   - Añade `--window`: abre Edge (o Chrome) en modo app con `--app=<url>` y un perfil temporal propio
     (`--user-data-dir` en `%LOCALAPPDATA%\vela\state\webview`), para no mezclarse con el navegador
     del usuario.
   - Comprueba en Windows todas las pestañas, el mapa sin conexión y que `/theme.css` aplica el tema
     elegido.
6. **Tráfico de la interfaz:** la GUI nativa de Linux lee `/sys/class/net`, pero en Windows solo se usa la
   GUI web. Si la GUI web muestra tráfico, obtén los contadores de `GetIfEntry2` o de
   `Get-NetAdapterStatistics`.

## 5. Fase 2 — Instalador `install.cmd` + `install.ps1`

`install.sh` (Linux) es la referencia de comportamiento y de mensajes. Crea en la raíz:

- **`install.cmd`:**
  `@powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*`. Sirve para que baste con un
  doble clic; no cambia la política de ejecución del sistema.
- **`install.ps1`:** guárdalo en UTF-8 **con BOM** (PowerShell 5.1 lo necesita para leer acentos). Debe
  funcionar en Windows PowerShell 5.1 y en PowerShell 7.

**Comportamiento:**
1. **Parámetros:**
   - `-Uninstall`, `-Purge`, `-Yes`, `-NoAutostart`, `-NoShortcut`;
   - `-Prefix <dir>`, por defecto `%LOCALAPPDATA%\Programs\VELA`;
   - `-Lang es|en`, que por defecto sale de `(Get-Culture).TwoLetterISOLanguageName`.

   Todos los mensajes en español e inglés, como `install.sh`.
2. **Sin administrador.** Si detecta que se ejecuta elevado, avisa: instalaría para la cuenta de
   administrador.
3. **Python:**
   - Busca Python ≥ 3.10 con `py -3`, luego `python` y luego `python3`, descartando el alias de la
     Microsoft Store (`WindowsApps\python.exe` sin intérprete real).
   - Si no hay, **pregunta** (salvo con `-Yes`) y ofrece `winget install --id Python.Python.3.12 -e --scope user`.
   - Si `winget` no existe, explica cómo instalarlo a mano y termina sin hacer nada más.
   - Usa la ruta absoluta del intérprete encontrado, y `pythonw.exe` al lado para lo que no deba abrir
     consola.
4. **Copia** `vela\` a `<Prefix>\vela.new` sin `__pycache__` y cámbiala por `<Prefix>\vela` (como
   `install.sh`). Después escribe el manifiesto que usa `vela update`:
   `<python> -m vela.updater write-manifest <Prefix> <carpeta del repositorio>` con `PYTHONPATH=<Prefix>`.
5. **Comando `vela`:** crea `<Prefix>\bin\vela.cmd` con este contenido:

   ```
   @"<python>" -c "import sys; sys.path.insert(0, r'<Prefix>'); from vela.cli import main; sys.exit(main())" %*
   ```

   Añade `<Prefix>\bin` al PATH **del usuario**:
   - en `HKCU\Environment`, con `[Environment]::SetEnvironmentVariable(..., 'User')`;
   - sin duplicar la entrada;
   - y avisa de que hay que abrir una terminal nueva.
6. **Acceso directo** en el menú Inicio (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\VELA.lnk`):
   - lo crea `WScript.Shell`;
   - ejecuta `pythonw.exe` con `-c "…" gui --window`;
   - el directorio de trabajo es `<Prefix>`;
   - el icono es `<Prefix>\vela\data\brand\vela.ico`;
   - la descripción es «Vigilant Egress & Leak Analyst».
7. **Arranque con la sesión:** el proceso de fondo solo se registra si el usuario lo acepta (pregunta;
   con `-NoAutostart` nunca). Arráncalo al terminar con `vela daemon start`.
8. **Reinstalar** encima de una versión anterior **actualiza**:
   - para el proceso de fondo antes de copiar y lo vuelve a arrancar después;
   - conserva los datos y ajustes de `%APPDATA%\vela` y `%LOCALAPPDATA%\vela`.
9. **`-Uninstall`:**
   - para el proceso de fondo;
   - quita el acceso directo, el arranque automático, la entrada del PATH y `<Prefix>`.

   Con `-Purge` borra también `%APPDATA%\vela` y `%LOCALAPPDATA%\vela`, **después de preguntar** salvo
   con `-Yes`, y lista qué se borra.
10. **Al final:** «VELA instalado. Ábrelo desde el menú Inicio o con `vela gui`; en la terminal: `vela status`»,
    y cómo actualizar (`vela update`) y desinstalar (`install.cmd -Uninstall`).

**Adapta `vela/updater.py`:**
- `run_installer()` en Windows ejecuta
  `powershell -NoProfile -ExecutionPolicy Bypass -File <src>\install.ps1 -Yes -NoAutostart` y respeta la
  elección de arranque automático que ya hubiera.
- `vela update` sigue sin ser automático, va por Tor o la VPN y solo hace *fast-forward*.
- Prueba la ruta por Tor con Tor Browser: su SocksPort está en `127.0.0.1:9150`, así que `discover()` debe
  detectarlo.

**Valida el instalador de verdad**, en este orden:
1. instalación limpia;
2. `vela status` en una terminal nueva;
3. el acceso directo abre la GUI;
4. reinstalación encima;
5. `vela update --check`;
6. `-Uninstall`;
7. `-Uninstall -Purge`.

Comprueba después que no queda nada: ni ficheros, ni PATH, ni accesos directos, ni entradas de inicio.
Si puedes, prueba también con una ruta de usuario con espacios y acentos (por ejemplo
`C:\Users\José Pérez`).

## 6. Fase 3 — Verificación de extremo a extremo

Escenarios a comprobar. En cada uno anota lo que VELA dice y lo que es verdad (contrastado con
herramientas de Windows), sin datos personales.

| Escenario | Qué debe ocurrir |
|---|---|
| Sin VPN | Las conexiones salen como «directa», la exposición sube y el veredicto de «fugas» explica que no aplica sin túnel |
| VPN WireGuard o OpenVPN conectada | El túnel se detecta, la salida efectiva va por él y las conexiones salen «protegidas» |
| VPN conectada + un programa fuera del túnel (split tunneling del cliente) | Aparece como «fuga» |
| Tor Browser abierto | Tor se detecta (puerto 9150 y proceso) y sus circuitos solo se muestran si hay ControlPort |
| DoH activado en Windows (Configuración → Red → DNS cifrado) | DNS «cifrado»; con *fallback* a texto plano, no se afirma que esté cifrado |
| Proxy del sistema configurado | Se detecta en `discover()["proxy"]["desktop"]` |
| Windows en inglés y en español | Los parsers no dependen del idioma de las salidas (o soportan ambos) |

No desconectes la red ni cambies la VPN del usuario para probar: pídele que lo haga, o prueba solo los
escenarios que ya estén así.

## 7. Fase 4 — Documentación y cierre

1. **README de la rama** (`README.md` y `README.es.md`): sustituye el aviso «en desarrollo» por una sección
   «Windows (versión ligera)» con:
   - instalación (`install.cmd`), requisitos y uso (`vela gui`, `vela status`);
   - actualización y desinstalación;
   - una **tabla honesta** de qué funciona en Windows y qué no (kill-switch, bandeja, app nativa,
     rotaciones: no).

   Quita el aviso solo si las fases 1 a 3 están verificadas.
2. `python3 -m vela.i18n check` sin faltas, y todas las pruebas en verde en Windows **y** en Linux. Si no
   tienes Linux, que nada del código de Linux haya cambiado de comportamiento: revisa el diff.
3. **Informe final** al usuario con:
   - lo que se ha verificado en Windows real (con la evidencia);
   - lo que solo se ha probado con datos simulados;
   - lo que no se ha podido probar;
   - los riesgos conocidos y los siguientes pasos para la rama `windows`.
4. `git push origin windows-lite`.

## 8. Errores típicos que debes evitar

- **`ConvertTo-Json`:**
  - devuelve un objeto suelto en vez de una lista cuando solo hay un elemento (usa `winsys._list`);
  - corta la anidación con `-Depth` bajo;
  - en PowerShell 5.1, las enumeraciones salen como números (`AddressFamily` 2/23, `State`).
- **`powershell.exe` tarda** entre 0,3 y 1 s en arrancar: agrupa las consultas en un solo script por
  ciclo y cachea.
- **Codificación:** fuerza UTF-8 en la salida de PowerShell (ya se hace en `winsys.ps`) y lee `netsh` con
  la codificación de la consola (`chcp`) o pide su salida por PowerShell.
- **`os.getuid`, `os.fork`, `signal.SIGHUP`, `fcntl`, `resource`, `pwd`, `grp`** no existen en Windows:
  protégelos.
- **`subprocess` sin `CREATE_NO_WINDOW`** abre ventanas negras cuando se ejecuta desde `pythonw`.
- **Rutas:** usa `pathlib` y no concatenes `/`; cuidado con rutas con espacios en `.cmd`, `.lnk` y `.vbs`.
- **Windows Defender** puede tardar en dejar ejecutar un `.vbs` o `.cmd` recién creado: documéntalo; no
  lo desactives.
- **Nunca** escuches en `0.0.0.0`, no abras puertos en el firewall y no pidas elevar privilegios en la
  versión ligera.
