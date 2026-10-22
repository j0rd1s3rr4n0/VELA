"""Traducción local con un LLM pequeño (Ollama o llama.cpp) y API compatible OpenAI.

Por defecto no sale nada de la máquina: se habla con `http://127.0.0.1:11434` (Ollama) o con
un servidor llama.cpp local. Una API remota solo se usa si el usuario la configura y da su
consentimiento (`[consent] llm_remote = true`).

El texto se trocea por párrafos para no desbordar el contexto. El prompt pide únicamente la
traducción, conservando saltos de línea y marcas simples; si el modelo añade preámbulos, se
limpian de forma conservadora.
"""

from __future__ import annotations

from .i18n import _

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import config as config_mod

LANGUAGES = {
    "auto": _("Detectar automáticamente"),
    "es": "Español", "en": "English", "ca": "Català", "pt": "Português", "fr": "Français", "de": "Deutsch",
    "it": "Italiano", "nl": "Nederlands", "sv": "Svenska", "no": "Norsk", "da": "Dansk", "fi": "Suomi",
    "pl": "Polski", "cs": "Čeština", "sk": "Slovenčina", "hu": "Magyar", "ro": "Română", "bg": "Български",
    "el": "Ελληνικά", "tr": "Türkçe", "ru": "Русский", "uk": "Українська", "ar": "العربية", "he": "עברית",
    "fa": "فارسی", "hi": "हिन्दी", "bn": "বাংলা", "ta": "தமிழ்", "th": "ไทย", "vi": "Tiếng Việt",
    "id": "Bahasa Indonesia", "ms": "Bahasa Melayu", "zh": "中文", "ja": "日本語", "ko": "한국어",
    "sw": "Kiswahili", "af": "Afrikaans", "sq": "Shqip", "hy": "Հայերեն", "ka": "ქართული",
}

PROMPT = ("You are a precise translation engine. Translate the user's text into {language}. "
          "Return ONLY the translation, without explanations, quotes or markdown fences. "
          "Preserve line breaks, lists, URLs, code, numbers and placeholders exactly. "
          "If the text is already in {language}, return it unchanged.")


class TranslationError(RuntimeError):
    pass


def _base(cfg: dict | None = None) -> dict:
    cfg = cfg or config_mod.load()
    return cfg.get("translate") or {}


def _is_local(endpoint: str) -> bool:
    try:
        host = urllib.parse.urlparse(endpoint).hostname or ""
    except ValueError:
        return False
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def _get(url: str, timeout: float = 2.0, key: str | None = None) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "VELA"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - endpoint configurado/local
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _post(url: str, payload: dict, timeout: float = 120.0, key: str | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "VELA"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode("utf-8", errors="replace"))


def status(cfg: dict | None = None) -> dict:
    """Comprueba qué motor local responde. No genera tráfico salvo a localhost."""
    t = _base(cfg)
    endpoint = str(t.get("endpoint") or "http://127.0.0.1:11434").rstrip("/")
    engine = str(t.get("engine") or "auto")
    result = {"engine": engine, "endpoint": endpoint, "model": t.get("model"), "ok": False,
              "models": [], "error": None, "local": _is_local(endpoint)}
    candidates = []
    if engine in ("auto", "ollama"):
        candidates.append(("ollama", endpoint))
    if engine in ("auto", "llamacpp"):
        candidates.append(("llamacpp", str(t.get("llamacpp_endpoint") or "http://127.0.0.1:8080").rstrip("/")))
    if engine in ("auto", "openai"):
        candidates.append(("openai", str(t.get("remote_endpoint") or "").rstrip("/")))
    for name, base in candidates:
        if not base:
            continue
        try:
            if name == "ollama":
                data = _get(base + "/api/tags", timeout=2)
                models = [m.get("name") for m in data.get("models") or [] if m.get("name")]
            else:
                key = None
                if name == "openai":
                    try:
                        from . import intel
                        key = intel.load_keys().get("translate")
                    except Exception:  # noqa: BLE001
                        key = None
                data = _get(base + "/v1/models", timeout=2, key=key)
                models = [m.get("id") for m in data.get("data") or [] if m.get("id")]
            result.update({"ok": True, "engine": name, "endpoint": base, "models": models, "error": None})
            break
        except (OSError, ValueError, urllib.error.URLError) as e:
            result["error"] = str(e)
    if result["ok"]:
        models = result.get("models") or []
        if models and result.get("model") not in models:
            result["model"] = models[0]
        elif not result.get("model"):
            result["model"] = (models or [None])[0]
    return result


def _language_name(code: str) -> str:
    return LANGUAGES.get(code, code)


def _chunks(text: str, max_chars: int) -> list[str]:
    text = text.strip()
    if len(text) <= max_chars:
        return [text]
    parts, current = [], ""
    for para in re.split(r"(\n\s*\n)", text):
        if len(current) + len(para) <= max_chars:
            current += para
            continue
        if current.strip():
            parts.append(current.strip())
        while len(para) > max_chars:
            cut = para.rfind("\n", 0, max_chars)
            cut = cut if cut > max_chars // 3 else para.rfind(" ", 0, max_chars)
            cut = cut if cut > 0 else max_chars
            parts.append(para[:cut].strip())
            para = para[cut:]
        current = para
    if current.strip():
        parts.append(current.strip())
    return [p for p in parts if p]


def _clean(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = re.sub(r"^(translation|traducción)\s*:\s*", "", text, flags=re.I)
    return text.strip()


def _call(text: str, target: str, source: str, cfg: dict, st: dict) -> str:
    t = cfg.get("translate") or {}
    endpoint, engine = st["endpoint"], st["engine"]
    model = st.get("model") or t.get("model") or (st.get("models") or ["qwen2.5:1.5b"])[0]
    lang = _language_name(target)
    system = PROMPT.format(language=lang)
    user = text if source == "auto" else f"[source: {_language_name(source)}]\n{text}"
    timeout = float(config_mod.parse_duration(t.get("timeout", "120s")))
    if engine == "ollama":
        data = _post(endpoint + "/api/chat", {
            "model": model, "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0.1},
        }, timeout=timeout)
        return _clean((data.get("message") or {}).get("content") or data.get("response") or "")
    if engine in ("llamacpp", "openai"):
        url = endpoint + "/v1/chat/completions"
        payload = {"model": model, "temperature": 0.1,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        key = None
        if engine == "openai":
            try:
                from . import intel
                key = t.get("api_key") or intel.load_keys().get("translate")
            except Exception:  # noqa: BLE001
                key = t.get("api_key")
        data = _post(url, payload, timeout=timeout, key=key)
        choices = data.get("choices") or []
        return _clean(((choices[0] if choices else {}).get("message") or {}).get("content") or "")
    raise TranslationError(_("motor de traducción no disponible"))


def translate(text: str, target: str = "es", source: str = "auto", cfg: dict | None = None) -> dict:
    """Traduce `text`. Devuelve {text, target, source, engine, model, chunks}."""
    text = (text or "").strip()
    if not text:
        return {"text": "", "target": target, "source": source, "engine": None, "model": None, "chunks": 0}
    if target not in LANGUAGES or target == "auto":
        raise TranslationError(_("idioma de destino no válido: {target}", target=target))
    cfg = cfg or config_mod.load()
    t = cfg.get("translate") or {}
    st = status(cfg)
    if not st["ok"]:
        raise TranslationError(_("no hay un LLM local disponible. Instala Ollama y descarga un modelo "
                                "(Ajustes → Utilidades → Traductor). Detalle: {e}", e=st.get("error") or "?"))
    if not st["local"] and not (cfg.get("consent") or {}).get("llm_remote"):
        raise TranslationError(_("la API remota está desactivada: activa el consentimiento para enviar texto "
                                "fuera de tu máquina"))
    max_chars = int(t.get("max_chars") or 3000)
    parts = _chunks(text, max_chars)
    out = [_call(part, target, source, cfg, st) for part in parts]
    return {"text": "\n\n".join(out), "target": target, "source": source,
            "engine": st["engine"], "model": st.get("model"), "chunks": len(parts)}
