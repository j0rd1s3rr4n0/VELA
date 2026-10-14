# VELA theme engine

[Español](THEMES.es.md)

VELA ships five visual themes, each with a light and a dark variant, plus a **Follow system** mode.
Colors are defined once, as *design tokens*, and every interface reads them from there: the GTK app,
its cairo charts and map, and the web GUI.

![All themes](screenshots/themes/gallery.png)

## Themes

| Theme | Identity | Notes |
|---|---|---|
| **VELA Signature** (default) | Official: navy, brand blue and the cyan of the emblem | Palette taken from the approved logo (Brand Kit) |
| **VELA Obsidian** | SOC / threat intel: graphite, steel, blue | Neutral surfaces, maximum table legibility |
| **VELA Glacier** | Analytical: slate, ice blue, bluish greys | Made for maps and statistics |
| **VELA Sentinel** | Surveillance: petrol green, charcoal, turquoise | The brand turquoise is never used for “protected”: protected is a distinct, yellower green (tested) |
| **VELA High Contrast** | Accessibility | Body text ≥ 7:1 (WCAG AAA), strong borders, highly visible focus ring |

## Choosing a theme

**Settings → Appearance** in the app:

* **Theme**: click a preview. Each preview is drawn with that theme's real tokens.
* **Mode**: *Follow system*, *Light* or *Dark*. *Follow system* switches by itself when the desktop does,
  through `Adw.StyleManager`.
* **Density**: *Comfortable* or *Compact*. Compact tightens margins and row padding; text keeps its size.
* **Animations**: *System setting*, *Reduced* or *Full*. This sets `gtk-enable-animations` for VELA only.

Changes apply instantly, in about 50 ms. The window is not rebuilt and the daemon and connections are not touched.
They are saved in `~/.config/vela/app-settings.toml` under `[ui]` (`theme`, `appearance`, `density`, `motion`),
just like the language. If a value is unknown or corrupted, the default is used.

For testing, `VELA_THEME=glacier VELA_APPEARANCE=light vela app` overrides the saved choice without changing it.

## Architecture

```
vela/themes.py          ← single source of truth (no GTK): tokens, registry, preferences,
                          WCAG contrast math, checks, web CSS
vela/native/theme.py    ← ThemeManager: Adw.StyleManager + one Gtk.CssProvider generated from tokens
vela/native/charts.py   ← P: the active palette, updated in place; charts paint by token name
vela/gui/server.py      ← GET /theme.css: same tokens as browser CSS variables
```

* `ThemeManager.apply(theme=…, appearance=…, density=…, motion=…)` normalizes the preferences and sets
  the color scheme (`FORCE_LIGHT`, `FORCE_DARK` or `DEFAULT`). It then resolves light or dark, reloads the
  CSS provider, updates `charts.P` and calls its listeners.
* GTK widgets follow the new CSS by themselves. Drawing areas (charts, map, legend swatches, theme
  previews) are redrawn with `redraw_tree()`. The map's cached base layer is keyed on the theme, so it is
  rebuilt only once.
* libadwaita's named colors (`window_bg_color`, `accent_bg_color`, `card_bg_color`…) are mapped to VELA
  tokens, so standard widgets (switches, combo rows, dialogs, toasts) match the theme. On GTK ≥ 4.16 they
  are set as CSS variables, and on older GTK 4 with `@define-color`. VELA's own classes always use literal
  values, so they work on any GTK 4.

## Tokens

Every mode of every theme defines all of these (`themes.TOKEN_GROUPS`):

| Group | Tokens |
|---|---|
| Surfaces | `bg` `sidebar` `header` `surface` `elevated` `overlay` `selected` `inset` |
| Text | `ink` `ink2` `muted` `inverse` `link` |
| Borders | `border` `border_strong` `focus` `separator` |
| Actions | `accent` `accent_fg` `accent_hover` `accent_text` `destructive` `destructive_fg` `destructive_text` `disabled` |
| Semantic | `success` `warning` `serious` `danger` `info` `neutral` |
| Network | `net_protected` `net_direct` `net_proxy` `net_tor` `net_leak` `net_unknown` |
| Visualization | `grid` `axis` `tooltip` `tooltip_fg` `highlight` `series1`…`series4` |
| Map | `map_ocean` `map_land` `map_coast` `map_grid` `map_label` `map_label_strong` `map_dot` |
| Brand | `brand_navy` `brand_blue` `brand_cyan` |

### Meanings are fixed; only lightness changes

| Meaning | Token | Hue | Always shown with |
|---|---|---|---|
| Protected (through the tunnel) | `net_protected` = `success` | green | ✔ + text |
| Direct (your real IP) | `net_direct` = `serious` | orange | ◆ + text |
| Proxy | `net_proxy` | indigo blue (not the brand blue) | label |
| Tor | `net_tor` | violet | label |
| Confirmed leak | `net_leak` = `danger` | red | ✖ + text |
| Unknown | `net_unknown` | grey | ● + text |
| Warning | `warning` | amber | ▲ + text |

Brand colors (`brand_*`) and the interaction accent (`accent*`) never mean a state. A test checks that the
accent is at least ΔE 15 away from every state color in every theme.

## Verified contrast

`python3 -m vela.themes` prints the report, and `tests/test_themes.py` fails if any check drops below its
minimum. Each of the 10 theme/mode combinations runs **79 checks**. All 790 pass:

* **Text at 4.5:1:**
  * Primary and secondary text, muted text and the accent used as text, on every background
    (`bg`, `sidebar`, `header`, `surface`, `elevated`).
  * Every state color as text, both on surfaces and on its own tinted pill background.
  * Text on the selected row, on the code-block background and in tooltips.
* **Button labels at 4.5:1:** on the primary, hover and destructive buttons.
* **Graphics at 3:1:**
  * The focus ring and the strong border.
  * Every connection-type color on the surface, the map's ocean and the map's land.
  * The chart series.
* **Map labels at 4.5:1** on both land and ocean.
* **High Contrast:** body text at ≥ 7:1.

The six connection types must also be at least ΔE 10 apart (OKLab) from each other. They are never told
apart by color alone: they always carry an icon, a label or a legend entry.

## Adding or changing a theme

1. Add an entry to `THEMES` in `vela/themes.py` with `name`, `description` (wrapped in `N_()`), and `light`
   and `dark` built with `_mode(dark, bg=…, sidebar=…, surface=…, elevated=…, border=…, ink=…, ink2=…,
   muted=…, accent=…, accent_text=…)`. Every other token is derived, and you can override any of them
   (for example `success=…`).
2. Run `python3 -m vela.themes` and adjust until there are no `FALLA` (fail) lines.
3. Run `python3 -m unittest tests.test_themes`.
4. Translate the description in `vela/locale/*.json`, then check with `python3 -m vela.i18n check`.

Never hard-code a color in a view. Use a CSS class (`.card`, `.pill-good`, `.callout-critical`, `.cmd`,
`.mono`…), or a token name in cairo code: `set_rgb(cr, "net_tor")`, `text(…, color="muted")`.

## Reusable components (GTK CSS classes)

| Class | Use |
|---|---|
| `.card`, `.card-title`, `.kpi-value`, `.kpi-sub`, `.kpi-hint` | Cards and metric cards |
| `.pill` + `.pill-good/-warning/-serious/-critical/-info/-neutral` | State and severity badges (icon + text) |
| `.callout` + `.callout-<state>` | Severity accent on the left edge (alerts, dashboard status strip) |
| `.vtable`, `.th`, `.td`, `.td-strong`, `.cell`, `.rowsep` | Tables (row padding follows density) |
| `.mono` | IPs, ports, MACs and hashes (applied automatically in tables) |
| `.cmd`, `.cmd-tag-root`, `.cmd-tag-disruptive`, `.cmd-tag-read` | Command blocks and their labels |
| `.empty` | Empty states |
| `button.emergency` | The Emergency action, destructive in every theme and always confirmed |

## Brand assets

The Brand Kit is in `vela/data/brand/` and is installed with the app:

* `vela-symbol-*.png`: the emblem at 16 to 256 px.
* `vela-app-*.png`: the launcher tile at 16 to 512 px.
* `vela-wordmark-on-dark.png` and `vela-wordmark-on-light.png`: the wordmark, swapped automatically with the mode.
* `vela-symbol-mono-*.svg`: monochrome vector symbols.

The README banners are in `docs/brand/`.

## Other interfaces

* **Web GUI:** reads `/theme.css`, generated from the theme chosen in Settings (light and dark, with
  `prefers-color-scheme` as before).
* **TUI (curses):** keeps the 8 ANSI colors with the same meanings (Tor magenta, failures red, OK green;
  ANSI has no orange, so direct traffic and warnings use yellow).
* **CLI:** output colors are unchanged. They are only used on a TTY and respect `NO_COLOR`.
* **Tray:** the indicator keeps its state icons (ok, warning, alert, off), because they convey state.
  Notifications use the brand icon.

## Known limitations

* *Follow system* depends on the desktop exposing its color-scheme preference through the XDG settings
  portal or GNOME. If it does not, VELA uses light.
* The system high-contrast setting does not switch the theme by itself: choose **VELA High Contrast**.
* The wordmark and the color emblem are raster images from the Brand Kit. The color version has no
  vector source.
* Contrast is computed per color pair. It was not measured with a screen reader or on physical screens.
* Windows and macOS are not supported on this branch.
