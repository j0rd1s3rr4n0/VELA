"""Las pruebas comparan textos en español (el idioma fuente): se fijan en español sea cual sea el sistema."""
import os

os.environ["VELA_LANG"] = "es"
# Las pruebas no deben dejar entradas en el audit.log real del usuario.
os.environ.setdefault("VELA_NO_AUDIT_FILE", "1")
