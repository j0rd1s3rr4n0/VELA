# Motor de temas de VELA

[English](THEMES.md)

VELA trae cinco temas visuales, cada uno en versión clara y oscura, y un modo **Seguir al sistema**.
Los colores se definen una sola vez, como *design tokens*, y todas las interfaces los leen de ahí: la app
GTK, sus gráficos y el mapa en cairo, y la GUI web.

![Todos los temas](screenshots/themes/gallery.png)

## Temas

| Tema | Identidad | Notas |
|---|---|---|
| **VELA Signature** (predeterminado) | Oficial: azul marino, azul de marca y el cian del emblema | Paleta sacada del logotipo aprobado (Brand Kit) |
| **VELA Obsidian** | SOC / threat intel: grafito, acero y azul | Superficies neutras y máxima legibilidad de tablas |
| **VELA Glacier** | Analítico: pizarra, azul hielo y grises azulados | Pensado para mapas y estadísticas |
| **VELA Sentinel** | Vigilancia: verde petróleo, carbón y turquesa | El turquesa de la marca nunca indica «protegido»: protegido es otro verde, más amarillo (probado) |
| **VELA High Contrast** | Accesibilidad | Texto ≥ 7:1 (WCAG AAA), bordes fuertes y foco muy visible |

## Elegir el tema

En la app, **Ajustes → Apariencia**:

* **Tema:** pulsa una vista previa. Cada una está dibujada con los tokens reales de ese tema.
* **Modo:** *Seguir al sistema*, *Claro* u *Oscuro*. *Seguir al sistema* cambia solo cuando cambia el
  escritorio, mediante `Adw.StyleManager`.
* **Densidad:** *Cómoda* o *Compacta*. Compacta reduce márgenes y el relleno de las filas; el texto mantiene
  su tamaño.
* **Animaciones:** *Según el sistema*, *Reducido* o *Completo*. Ajusta `gtk-enable-animations` solo para VELA.

Los cambios se aplican al instante, en unos 50 ms. No se reconstruye la ventana y no se tocan ni el daemon
ni las conexiones. Se guardan en `~/.config/vela/app-settings.toml`, en `[ui]` (`theme`, `appearance`,
`density`, `motion`), igual que el idioma. Si un valor es desconocido o está corrupto, se usa el
predeterminado.

Para probar sin cambiar lo guardado: `VELA_THEME=glacier VELA_APPEARANCE=light vela app`.

## Arquitectura

```
vela/themes.py          ← fuente única (sin GTK): tokens, registro, preferencias, cálculo de
                          contraste WCAG, comprobaciones y CSS web
vela/native/theme.py    ← ThemeManager: Adw.StyleManager + un único Gtk.CssProvider generado de los tokens
vela/native/charts.py   ← P: la paleta activa, actualizada en sitio; los gráficos pintan por nombre de token
vela/gui/server.py      ← GET /theme.css: los mismos tokens como variables CSS del navegador
```

* `ThemeManager.apply(theme=…, appearance=…, density=…, motion=…)` normaliza las preferencias y fija el
  esquema de color (`FORCE_LIGHT`, `FORCE_DARK` o `DEFAULT`). Después resuelve si toca claro u oscuro,
  recarga el proveedor CSS, actualiza `charts.P` y avisa a sus listeners.
* Los widgets GTK siguen la CSS nueva por sí solos. Las áreas de dibujo (gráficos, mapa, muestras de la
  leyenda, vistas previas de temas) se redibujan con `redraw_tree()`. La capa base del mapa, que está en
  caché, se indexa por tema, así que se regenera una sola vez.
* Los colores con nombre de libadwaita (`window_bg_color`, `accent_bg_color`, `card_bg_color`…) apuntan a
  los tokens de VELA, de modo que los widgets estándar (interruptores, desplegables, diálogos, avisos)
  también siguen el tema. En GTK ≥ 4.16 se definen como variables CSS, y en GTK 4 más antiguo con
  `@define-color`. Las clases propias de VELA usan siempre valores literales, así que funcionan en
  cualquier GTK 4.

## Tokens

Cada modo de cada tema define todos estos (`themes.TOKEN_GROUPS`):

| Grupo | Tokens |
|---|---|
| Superficies | `bg` `sidebar` `header` `surface` `elevated` `overlay` `selected` `inset` |
| Texto | `ink` `ink2` `muted` `inverse` `link` |
| Bordes | `border` `border_strong` `focus` `separator` |
| Acciones | `accent` `accent_fg` `accent_hover` `accent_text` `destructive` `destructive_fg` `destructive_text` `disabled` |
| Semánticos | `success` `warning` `serious` `danger` `info` `neutral` |
| Red | `net_protected` `net_direct` `net_proxy` `net_tor` `net_leak` `net_unknown` |
| Visualización | `grid` `axis` `tooltip` `tooltip_fg` `highlight` `series1`…`series4` |
| Mapa | `map_ocean` `map_land` `map_coast` `map_grid` `map_label` `map_label_strong` `map_dot` |
| Marca | `brand_navy` `brand_blue` `brand_cyan` |

### El significado no cambia; solo cambia la luminosidad

| Significado | Token | Tono | Siempre con |
|---|---|---|---|
| Protegida (por el túnel) | `net_protected` = `success` | verde | ✔ + texto |
| Directa (tu IP real) | `net_direct` = `serious` | naranja | ◆ + texto |
| Proxy | `net_proxy` | azul índigo (no el azul de la marca) | etiqueta |
| Tor | `net_tor` | violeta | etiqueta |
| Fuga confirmada | `net_leak` = `danger` | rojo | ✖ + texto |
| Desconocido | `net_unknown` | gris | ● + texto |
| Aviso | `warning` | ámbar | ▲ + texto |

Los colores de marca (`brand_*`) y el acento de interacción (`accent*`) nunca indican un estado. Una prueba
comprueba que el acento está al menos a ΔE 15 de todos los colores de estado en todos los temas.

## Contraste verificado

`python3 -m vela.themes` imprime el informe, y `tests/test_themes.py` falla si alguna comprobación baja de
su mínimo. Cada una de las 10 combinaciones de tema y modo pasa **79 comprobaciones**. Las 790 cumplen:

* **Texto a 4,5:1:**
  * Texto principal y secundario, texto atenuado y el acento usado como texto, sobre todos los fondos
    (`bg`, `sidebar`, `header`, `surface`, `elevated`).
  * Cada color de estado como texto, tanto sobre las superficies como sobre su propia píldora tintada.
  * El texto sobre la fila seleccionada, sobre el fondo de los bloques de código y en los tooltips.
* **Etiquetas de botón a 4,5:1:** en el botón principal, en su estado hover y en el destructivo.
* **Gráficos a 3:1:**
  * El anillo de foco y el borde fuerte.
  * Cada color de tipo de conexión sobre la superficie, el océano y la tierra del mapa.
  * Las series de los gráficos.
* **Etiquetas del mapa a 4,5:1** sobre tierra y sobre océano.
* **Alto contraste:** texto ≥ 7:1.

Además, los seis tipos de conexión deben distar al menos ΔE 10 (OKLab) entre sí. Nunca se distinguen solo
por el color: siempre llevan icono, etiqueta o entrada en la leyenda.

## Añadir o cambiar un tema

1. Añade una entrada a `THEMES` en `vela/themes.py` con `name`, `description` (envuelta en `N_()`), y
   `light` y `dark` construidos con `_mode(dark, bg=…, sidebar=…, surface=…, elevated=…, border=…, ink=…,
   ink2=…, muted=…, accent=…, accent_text=…)`. El resto de tokens se deduce, y puedes sobrescribir
   cualquiera (por ejemplo `success=…`).
2. Ejecuta `python3 -m vela.themes` y ajusta hasta que no quede ninguna línea `FALLA`.
3. Ejecuta `python3 -m unittest tests.test_themes`.
4. Traduce la descripción en `vela/locale/*.json` y compruébalo con `python3 -m vela.i18n check`.

Nunca escribas un color fijo en una vista. Usa una clase CSS (`.card`, `.pill-good`, `.callout-critical`,
`.cmd`, `.mono`…) o, en código cairo, un nombre de token: `set_rgb(cr, "net_tor")`, `text(…, color="muted")`.

## Componentes reutilizables (clases CSS de GTK)

| Clase | Uso |
|---|---|
| `.card`, `.card-title`, `.kpi-value`, `.kpi-sub`, `.kpi-hint` | Tarjetas y métricas |
| `.pill` + `.pill-good/-warning/-serious/-critical/-info/-neutral` | Insignias de estado y severidad (icono + texto) |
| `.callout` + `.callout-<estado>` | Borde izquierdo de severidad (alertas, franja de estado del panel) |
| `.vtable`, `.th`, `.td`, `.td-strong`, `.cell`, `.rowsep` | Tablas (el relleno de fila sigue la densidad) |
| `.mono` | IPs, puertos, MAC y hashes (se aplica sola en las tablas) |
| `.cmd`, `.cmd-tag-root`, `.cmd-tag-disruptive`, `.cmd-tag-read` | Bloques de comandos y sus etiquetas |
| `.empty` | Estados vacíos |
| `button.emergency` | Acción de Emergencia: destructiva en todos los temas y siempre con confirmación |

## Recursos de marca

El Brand Kit está en `vela/data/brand/` y se instala con la app:

* `vela-symbol-*.png`: el emblema de 16 a 256 px.
* `vela-app-*.png`: la tesela del lanzador de 16 a 512 px.
* `vela-wordmark-on-dark.png` y `vela-wordmark-on-light.png`: el logotipo «VELA», que cambia solo con el modo.
* `vela-symbol-mono-*.svg`: símbolos vectoriales monocromos.

Los banners del README están en `docs/brand/`.

## Otras interfaces

* **GUI web:** lee `/theme.css`, generado a partir del tema elegido en Ajustes (claro y oscuro, con
  `prefers-color-scheme` como antes).
* **TUI (curses):** mantiene los 8 colores ANSI con los mismos significados (Tor magenta, fallos en rojo,
  correcto en verde; ANSI no tiene naranja, así que las conexiones directas y los avisos usan amarillo).
* **CLI:** los colores de la salida no cambian. Solo se usan en un TTY y respetan `NO_COLOR`.
* **Bandeja:** el indicador conserva sus iconos de estado (ok, aviso, alerta, apagado), porque comunican
  el estado. Las notificaciones usan el icono de la marca.

## Limitaciones conocidas

* *Seguir al sistema* depende de que el escritorio publique su preferencia de color mediante el portal de
  ajustes XDG o GNOME. Si no lo hace, VELA usa claro.
* El ajuste de alto contraste del sistema no cambia el tema por sí solo: elige **VELA High Contrast**.
* El logotipo «VELA» y el emblema en color son imágenes rasterizadas del Brand Kit. La versión en color no
  tiene fuente vectorial.
* El contraste se calcula por pares de colores. No se ha medido con lectores de pantalla ni en pantallas
  físicas.
* En esta rama no hay soporte para Windows ni macOS.
