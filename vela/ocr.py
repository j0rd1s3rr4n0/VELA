"""OCR de una región de la pantalla y traducción del texto reconocido.

La captura usa el portal XDG (`org.freedesktop.portal.Screenshot`) cuando PyGObject está
disponible, que es la vía correcta en Wayland/GNOME y muestra el selector del sistema. Si no,
prueba herramientas habituales en orden: gnome-screenshot, spectacle, grim+slurp, maim.

La imagen se guarda en un temporal 0600 y se borra siempre. El OCR se hace con tesseract en
local; el texto reconocido solo se envía al LLM si el usuario pulsa traducir.
"""

from __future__ import annotations

from .i18n import _

import os
import shutil
import tempfile
import urllib.parse
from pathlib import Path

from .util import run, which


class OcrError(RuntimeError):
    pass


def available_languages() -> list[str]:
    exe = which("tesseract")
    if not exe:
        return []
    code, out, _ign = run(["tesseract", "--list-langs"], timeout=10)
    if code != 0:
        return []
    return [x.strip() for x in out.splitlines() if x.strip() and ":" not in x and x.strip() != "osd"]


def uri_list(value) -> list[str]:
    """Normaliza la respuesta `uri` del portal: cadena, lista o GLib.Variant."""
    if hasattr(value, "unpack"):
        value = value.unpack()
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    return []


def _copy_uri(uri: str, dest: Path) -> None:
    uri = str(uri or "").strip()
    if uri.startswith("file://"):
        src = Path(urllib.parse.unquote(urllib.parse.urlparse(uri).path))
    elif uri.startswith("file:"):
        src = Path(urllib.parse.unquote(uri[5:]))
    elif uri and "://" not in uri:
        src = Path(uri)                     # algunos portales devuelven una ruta directa
    else:
        raise OcrError(_("el portal devolvió una URI no soportada: {uri}", uri=uri))
    if not src.exists():
        raise OcrError(_("el portal devolvió una imagen que no existe: {uri}", uri=uri))
    shutil.copyfile(src, dest)
    try:
        src.unlink()
    except OSError:
        pass


def _portal_capture(dest: Path) -> bool:
    """Selector interactivo del portal. Devuelve True si capturó; False si no hay portal."""
    try:
        from gi.repository import Gio, GLib
    except (ImportError, ValueError):
        return False
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        loop = GLib.MainLoop()
        state: dict = {}

        def on_response(_conn, _sender, obj, _iface, _signal, params):
            if state.get("request") and obj != state["request"]:
                return
            code, results = params.unpack()
            state.update(code=code, results=results or {})
            loop.quit()

        sub = bus.signal_subscribe("org.freedesktop.portal.Desktop", "org.freedesktop.portal.Request",
                                   "Response", None, None, Gio.DBusSignalFlags.NONE, on_response)
        opts = {"interactive": GLib.Variant("b", True), "modal": GLib.Variant("b", True)}
        ret = bus.call_sync("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
                            "org.freedesktop.portal.Screenshot", "Screenshot",
                            GLib.Variant("(sa{sv})", ("", opts)), GLib.VariantType.new("(o)"),
                            Gio.DBusCallFlags.NONE, 15000, None)
        state["request"] = ret.unpack()[0]
        GLib.timeout_add_seconds(180, lambda: (loop.quit(), False)[1])
        loop.run()
        bus.signal_unsubscribe(sub)
        if state.get("code") != 0:
            if state.get("code") == 1:
                raise OcrError(_("captura cancelada"))
            raise OcrError(_("el portal no pudo capturar la pantalla (código {n})", n=state.get("code")))
        # El portal puede devolver una lista de URIs o una sola cadena. Si es una cadena,
        # iterarla daría caracteres sueltos (el error «URI no soportada: f»).
        uris = uri_list(state.get("results", {}).get("uri"))
        if not uris:
            raise OcrError(_("el portal no devolvió ninguna imagen"))
        _copy_uri(uris[0], dest)
        return dest.exists() and dest.stat().st_size > 0
    except OcrError:
        raise
    except Exception:  # noqa: BLE001 - sin portal se prueba la siguiente vía
        return False


def _tool_capture(dest: Path) -> str | None:
    cmds = []
    if which("gnome-screenshot"):
        cmds.append(["gnome-screenshot", "-a", "-f", str(dest)])
    if which("spectacle"):
        cmds.append(["spectacle", "-r", "-b", "-n", "-o", str(dest)])
    if which("maim"):
        cmds.append(["maim", "-s", str(dest)])
    if which("scrot"):
        cmds.append(["scrot", "-s", str(dest)])
    for cmd in cmds:
        code, _out, _err = run(cmd, timeout=180)
        if code == 0 and dest.exists() and dest.stat().st_size > 0:
            return cmd[0]
    if which("grim") and which("slurp"):
        code, geo, _err = run(["slurp"], timeout=180)
        if code == 0 and geo.strip():
            code, _out, _err = run(["grim", "-g", geo.strip(), str(dest)], timeout=30)
            if code == 0 and dest.exists() and dest.stat().st_size > 0:
                return "grim"
    return None


def capture_region(dest: str | Path | None = None) -> dict:
    """Abre el selector y guarda la región. Devuelve {path, method}."""
    if dest:
        path = Path(dest).expanduser()
    else:
        fd, name = tempfile.mkstemp(prefix="vela-ocr-", suffix=".png")
        os.close(fd)
        path = Path(name)
    os.chmod(path, 0o600)
    if _portal_capture(path):
        return {"path": str(path), "method": "portal"}
    tool = _tool_capture(path)
    if tool:
        return {"path": str(path), "method": tool}
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    missing = [x for x in ("gnome-screenshot", "grim", "slurp", "spectacle", "maim", "scrot") if not which(x)]
    raise OcrError(_("no puedo capturar la pantalla: instala el portal XDG o una herramienta de captura "
                     "(faltan: {missing})", missing=", ".join(missing) or "?" ))


def _preprocess(path: Path) -> Path | None:
    """Amplía y mejora el contraste de una captura pequeña u oscura.

    Es opcional: si no hay PIL ni GdkPixbuf se usa la imagen original. Las capturas de
    pantalla suelen tener texto de 10-14 px; duplicar el tamaño antes de tesseract mejora
    mucho el reconocimiento sin cambiar el texto que ve el usuario.
    """
    out = path.with_name(path.stem + "-prep.png")
    try:
        from PIL import Image, ImageOps
        img = Image.open(path).convert("L")
        w, h = img.size
        if w < 1600:
            img = img.resize((w * 2, h * 2), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        img.save(out, optimize=True)
        os.chmod(out, 0o600)
        return out
    except Exception:  # noqa: BLE001 - PIL es opcional
        pass
    try:
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf
        pb = GdkPixbuf.Pixbuf.new_from_file(str(path))
        w, h = pb.get_width(), pb.get_height()
        if w < 1600:
            pb = pb.scale_simple(w * 2, h * 2, GdkPixbuf.InterpType.BILINEAR)
        pb.savev(str(out), "png", [], [])
        os.chmod(out, 0o600)
        return out
    except Exception:  # noqa: BLE001
        return None


def _run_tesseract(path: Path, langs: list[str], psm: int) -> str:
    last = ""
    for oem in ("1", None):
        args = ["tesseract", str(path), "stdout", "-l", "+".join(langs)]
        if oem:
            args += ["--oem", oem]
        args += ["--psm", str(psm), "--dpi", "300"]
        code, out, err = run(args, timeout=180)
        if code == 0:
            return out.strip()
        last = (err or out).strip()[:400]
    raise OcrError(_("tesseract falló: {e}", e=last))


def ocr_image(path: str | Path, languages: list[str] | None = None) -> dict:
    """Reconoce texto con tesseract probando varias segmentaciones.

    Una captura de pantalla no es un documento: `--psm 6` (bloque uniforme) suele fallar.
    Se prueban PSM 3 (diseño automático), 11 (texto disperso) y, si hace falta, 6 sobre
    una versión ampliada y con más contraste.
    """
    if not which("tesseract"):
        raise OcrError(_("tesseract no está instalado"))
    p = Path(path).expanduser()
    if not p.exists():
        raise OcrError(_("la imagen no existe: {path}", path=str(p)))
    avail = available_languages()
    wanted = languages or ["spa", "eng"]
    use = [x for x in wanted if x in avail] or (["eng"] if "eng" in avail else avail[:1])
    if not use:
        raise OcrError(_("tesseract no tiene ningún idioma instalado"))
    attempts: list[tuple[str, int]] = []
    errors: list[str] = []
    for psm in (3, 11):
        try:
            text = _run_tesseract(p, use, psm)
            if text:
                attempts.append((text, psm))
        except OcrError as e:
            errors.append(str(e))
    # Si no hay texto (o es muy corto), probar la imagen ampliada y PSM 6.
    prep = None
    if not attempts or max(len(t) for t, _psm in attempts) < 12:
        prep = _preprocess(p)
        if prep:
            for psm in (11, 3, 6):
                try:
                    text = _run_tesseract(prep, use, psm)
                    if text:
                        attempts.append((text, psm))
                except OcrError as e:
                    errors.append(str(e))
    if prep:
        try:
            prep.unlink(missing_ok=True)
        except OSError:
            pass
    if not attempts:
        detail = "; ".join(dict.fromkeys(errors))[:300]
        raise OcrError(_("no se reconoció texto en la imagen") + (f" ({detail})" if detail else ""))
    text, psm = max(attempts, key=lambda x: len(x[0]))
    return {"text": text, "languages": use, "available": avail, "psm": psm}


def scan_and_translate(target: str = "es", source: str = "auto", languages: list[str] | None = None,
                       cfg: dict | None = None) -> dict:
    """Captura, OCR y traduce. Borra la imagen temporal al terminar.

    Si el OCR funciona pero la traducción falla, devuelve el texto reconocido para que la
    interfaz pueda mostrarlo igualmente.
    """
    from . import translate as tr
    cap = capture_region()
    try:
        ocr = ocr_image(cap["path"], languages)
        if not ocr["text"]:
            return {"captured": cap, "ocr": ocr, "translation": None,
                    "error": _("no se reconoció texto; selecciona una región con texto más grande o con más contraste")}
        try:
            res = tr.translate(ocr["text"], target=target, source=source, cfg=cfg)
            return {"captured": cap, "ocr": ocr, "translation": res, "error": None}
        except Exception as e:  # noqa: BLE001 - el texto reconocido sigue siendo útil
            return {"captured": cap, "ocr": ocr, "translation": None,
                    "error": _("texto reconocido, pero no se pudo traducir: {e}", e=e)}
    finally:
        try:
            Path(cap["path"]).unlink(missing_ok=True)
        except OSError:
            pass
