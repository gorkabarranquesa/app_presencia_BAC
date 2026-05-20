"""
APP PRESENCIA ACTUAL POR PLANTA — CRECE PERSONAS + JOTFORM
==========================================================

Misma app para P2 COMARCA II y P3 UHARTE. Lo único que cambia entre
app_presencia_p2.py y app_presencia_p3.py es la constante PLANTA_OBJETIVO
en la sección "CONFIGURACIÓN".

Fuentes de datos
----------------
- Empleados: CRECE Personas (/exportacion/fichajes).
- Externos:  Jotform (formulario de registro de entrada de personal externo).
             Cada submission es una entrada; las salidas se registran en un
             segundo formulario de Jotform como POST con el ID de la entrada.

Esta versión incluye la LECTURA de externos desde Jotform. La marca de SALIDA
y el modo emergencia completo se completan en la siguiente iteración, cuando
exista el segundo formulario "Salida de personal externo".

Secrets esperados (.streamlit/secrets.toml)
-------------------------------------------
    # CRECE
    API_TOKEN            = "..."
    APP_KEY_B64          = "..."
    CRECE_BASE_URL       = "https://sincronizaciones.crecepersonas.es/api"

    # Jotform (endpoint EU)
    JOTFORM_API_KEY        = "..."
    JOTFORM_BASE_URL       = "https://eu-api.jotform.com"   # opcional
    JOTFORM_FORM_ENTRADAS  = "260152580203041"              # opcional, viene por defecto
    JOTFORM_FORM_SALIDAS   = ""                             # rellenar cuando exista

    # Debug
    SHOW_DEBUG_PRESENCIA = false   # opcional
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests
import streamlit as st

try:
    import phpserialize
except ImportError:
    phpserialize = None

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


# ============================================================
# CONFIGURACIÓN
# ============================================================

# Cambiar este valor en cada app:
#   app_presencia_p2.py -> "P2"
#   app_presencia_p3.py -> "P3"
PLANTA_OBJETIVO = "P2"

PLANTAS = {
    "P2": {
        "titulo": "P2 COMARCA II",
        "keywords": ("P2", "COMARCA", "ESQUIROZ"),
        "coords": (42.7656803, -1.6615654),
    },
    "P3": {
        "titulo": "P3 UHARTE",
        "keywords": ("P3", "UHARTE", "HUARTE"),
        "coords": (42.9201789, -1.9821119),
    },
}

TIMEZONE = ZoneInfo("Europe/Madrid")
NOCTURNAL_LOOKBACK_DAYS = 1
GEOFENCE_RADIUS_METERS = 350

EMPLEADOS_TTL = 60 * 60      # 1 h: cambian poco
ULTIMO_FICHAJE_TTL = 5       # 5 s: agrupa ráfagas de pulsaciones simultáneas
PRESENCIA_TTL = 60           # 1 min: red de seguridad si ultimo-fichaje no es fiable
HOY_TTL = 60                 # 1 min: máximo tiempo que un fichaje nuevo puede tardar en aparecer
DIA_CERRADO_TTL = 60 * 60 * 24   # 24 h: días pasados ya no cambian
EXTERNOS_TTL = 30            # 30 s: refresco de la lista de externos en planta
JOTFORM_QUESTIONS_TTL = 60 * 60   # 1 h: la estructura del form cambia poco
REQUEST_TIMEOUT = 20

# Endpoint europeo y form de entradas por defecto.
# Se pueden sobrescribir vía secrets si en algún momento cambian.
JOTFORM_BASE_URL_DEFAULT = "https://eu-api.jotform.com"
JOTFORM_FORM_ENTRADAS_DEFAULT = "260152580203041"

# Mapeo del campo "Planta visitada" del Jotform a los códigos internos.
JOTFORM_PLANTA_KEYWORDS = {
    "P2": ("ESQUIROZ", "COMARCA"),
    "P3": ("UHARTE", "HUARTE", "ARAKIL"),
}


# ============================================================
# SECRETS
# ============================================================

def get_secret(name: str, default: str | None = None) -> str | None:
    try:
        v = st.secrets.get(name)
        if v is not None:
            return str(v)
    except Exception:
        pass
    return os.getenv(name, default)


def get_bool_secret(name: str, default: bool = False) -> bool:
    v = get_secret(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "si", "sí"}


# ============================================================
# UTILIDADES
# ============================================================

_NORM_TABLE = str.maketrans("ÁÉÍÓÚÜÑ", "AEIOUUN")


def norm_text(value) -> str:
    if value is None:
        return ""
    return str(value).upper().translate(_NORM_TABLE).strip()


def norm_nif(value) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value)).upper().strip()


def parse_dt(value) -> datetime | None:
    """Parsea fecha/hora a datetime naive. Devuelve None si no se reconoce."""
    if not value:
        return None
    s = str(value).strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def parse_float(value) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(str(value).replace(",", ".").strip())
    except (ValueError, TypeError):
        return None


def now_madrid() -> datetime:
    return datetime.now(TIMEZONE)


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ============================================================
# DESENCRIPTADO PAYLOAD CRECE
# ============================================================

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _deserialize(raw: str):
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw[:1] in "{[":
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    if phpserialize is None:
        raise RuntimeError("Falta phpserialize")
    kwargs = {"decode_strings": True}
    if hasattr(phpserialize, "phpobject"):
        kwargs["object_hook"] = phpserialize.phpobject
    return phpserialize.loads(raw.encode("utf-8"), **kwargs)


def decrypt_payload(payload_text: str, app_key_b64: str):
    """Desencripta y deserializa una respuesta cifrada de CRECE. Valida MAC primero."""
    if AES is None:
        raise RuntimeError("Falta pycryptodome")
    if not payload_text:
        return None

    payload = json.loads(base64.b64decode(payload_text).decode("utf-8"))
    if not isinstance(payload, dict) or not {"iv", "value", "mac"} <= payload.keys():
        raise RuntimeError("Payload CRECE inválido")

    key = base64.b64decode(app_key_b64)
    iv_b64, value_b64, mac_recv = payload["iv"], payload["value"], str(payload["mac"])

    # Seguridad: validación MAC ANTES de desencriptar
    mac_calc = hmac.new(
        key,
        msg=(str(iv_b64) + str(value_b64)).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(mac_calc, mac_recv):
        raise RuntimeError("MAC inválido")

    iv = base64.b64decode(iv_b64)
    encrypted = base64.b64decode(value_b64)
    decrypted = _pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted))
    try:
        text = decrypted.decode("utf-8")
    except UnicodeDecodeError:
        text = decrypted.decode("latin-1", errors="ignore")
    return _deserialize(text)


def to_records(data) -> list[dict]:
    if data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        vs = list(data.values())
        if vs and all(isinstance(v, dict) for v in vs):
            return vs
        return [data]
    return []


# ============================================================
# CLIENTE API CRECE
# ============================================================

class CreceClient:
    def __init__(self) -> None:
        self.base_url = get_secret(
            "CRECE_BASE_URL", "https://sincronizaciones.crecepersonas.es/api"
        ).rstrip("/")
        self.api_token = get_secret("API_TOKEN")
        self.app_key_b64 = get_secret("APP_KEY_B64")
        if not self.api_token or not self.app_key_b64:
            raise RuntimeError("Faltan credenciales CRECE")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_token}",
        })

    def _post(self, endpoint: str, data: dict):
        r = self.session.post(
            f"{self.base_url}/{endpoint.lstrip('/')}",
            data=data,
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return decrypt_payload(r.text, self.app_key_b64)

    def empleados(self) -> list[dict]:
        return to_records(self._post("exportacion/empleados", {"solo_nif": 0}))

    def fichajes(self, desde: str, hasta: str, order: str = "asc") -> list[dict]:
        return to_records(self._post("exportacion/fichajes", {
            "fecha_inicio": desde, "fecha_fin": hasta, "order": order,
        }))

    def fichajes_por_nif(self, desde: str, hasta: str, nif: str, order: str = "asc") -> list[dict]:
        return to_records(self._post("exportacion/fichajes", {
            "fecha_inicio": desde, "fecha_fin": hasta, "nif": nif, "order": order,
        }))

    def ultimo_fichaje(self) -> str:
        """
        Marca de tiempo (string) del último fichaje conocido por CRECE.
        Se usa como 'ETag barato': si no cambia, no hace falta recargar fichajes.
        Se aceptan tres formas de respuesta por si la API varía:
        cifrada (igual que el resto), JSON plano o texto plano.
        Si todo falla, devuelve "" y se usa fallback temporal en la caché.
        """
        r = self.session.get(
            f"{self.base_url}/exportacion/ultimo-fichaje",
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        text = r.text.strip()

        data = None
        try:
            data = decrypt_payload(text, self.app_key_b64)
        except Exception:
            try:
                data = json.loads(text)
            except Exception:
                data = text

        if isinstance(data, dict):
            for k in ("fecha", "ultimo", "ultimo_fichaje", "last", "value", "data"):
                v = data.get(k)
                if v:
                    return str(v).strip()
            return ""
        if data is None:
            return ""
        return str(data).strip()


# ============================================================
# CLIENTE API JOTFORM (entrada de externos, endpoint EU)
# ============================================================

class JotformClient:
    """
    Cliente mínimo para Jotform. Lee submissions del formulario de entrada
    y descubre el qid del campo "ID de entrada" del formulario de salidas
    (cuando exista) automáticamente, para no tener que configurarlo a mano.
    """

    def __init__(self) -> None:
        self.base_url = get_secret("JOTFORM_BASE_URL", JOTFORM_BASE_URL_DEFAULT).rstrip("/")
        self.api_key = get_secret("JOTFORM_API_KEY")
        self.form_entradas = get_secret("JOTFORM_FORM_ENTRADAS", JOTFORM_FORM_ENTRADAS_DEFAULT)
        self.form_salidas = get_secret("JOTFORM_FORM_SALIDAS", "")
        if not self.api_key:
            raise RuntimeError("Falta JOTFORM_API_KEY")
        self.session = requests.Session()
        # La API key va por cabecera, no por URL: no aparece en logs ni proxies.
        self.session.headers.update({
            "APIKEY": self.api_key,
            "Accept": "application/json",
        })

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self.session.get(
            f"{self.base_url}/{path.lstrip('/')}",
            params=params or {},
            timeout=REQUEST_TIMEOUT,
        )
        if not r.ok:
            raise RuntimeError(f"GET {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json() or {}

    def _post(self, path: str, data: dict) -> dict:
        # Cinturón y tirantes: además del header APIKEY, mandamos la key como
        # query param. Algunos endpoints de Jotform prefieren la segunda forma
        # para escrituras y devuelven 401 si sólo va por header.
        url = f"{self.base_url}/{path.lstrip('/')}"
        params = {"apiKey": self.api_key} if self.api_key else None
        r = self.session.post(
            url,
            params=params,
            data=data,
            timeout=REQUEST_TIMEOUT,
        )
        if not r.ok:
            raise RuntimeError(f"POST {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json() or {}

    def submissions_desde(self, form_id: str, fecha_desde: str, limit: int = 200) -> list[dict]:
        """
        Submissions de un form creadas a partir de 'fecha_desde' (YYYY-MM-DD).
        Filtra por created_at en servidor para no descargar histórico.
        """
        params = {
            "limit": limit,
            "orderby": "created_at",
            "filter": json.dumps({"created_at:gt": f"{fecha_desde} 00:00:00"}),
        }
        data = self._get(f"form/{form_id}/submissions", params)
        content = data.get("content") if isinstance(data, dict) else None
        return content if isinstance(content, list) else []

    def questions(self, form_id: str) -> dict:
        """Estructura de preguntas del form: {qid: {text, name, type, ...}}."""
        data = self._get(f"form/{form_id}/questions")
        content = data.get("content") if isinstance(data, dict) else None
        return content if isinstance(content, dict) else {}

    def crear_salida(self, submission_id_entrada: str) -> dict:
        """
        Registra una salida: POST al formulario de salidas con el ID de la
        entrada original como único campo. Descubrimos el qid del campo
        automáticamente para no tener que configurarlo en secrets.
        """
        if not self.form_salidas:
            raise RuntimeError("Falta JOTFORM_FORM_SALIDAS (id del form de salidas)")
        qid = qid_campo_id_entrada(self.form_salidas)
        if not qid:
            raise RuntimeError("No se encuentra el campo de texto en el form de salidas")
        return self._post(
            f"form/{self.form_salidas}/submissions",
            {f"submission[{qid}]": submission_id_entrada},
        )


# ============================================================
# LÓGICA DE EXTERNOS (parseo de submissions Jotform)
# ============================================================

# Cómo encontramos campos por su 'text' o 'name' dentro del Jotform.
JF_FIELD_NOMBRE       = ("Nombre completo del visitante", "Visitor")
JF_FIELD_EMPRESA      = ("empresa externa", "External company")
JF_FIELD_PLANTA       = ("Planta visitada", "Site")
JF_FIELD_MOTIVO       = ("Motivo de la visita", "visit reason")
JF_FIELD_REFERENCIA   = ("Persona de referencia",)


def _jf_value_to_str(value) -> str:
    """
    Convierte una respuesta de Jotform a string legible.
    Maneja los tres formatos que devuelve la API:
      - string plano:            "Esquiroz"
      - lista (radio, checkbox): ["Javier Mendinueta"]
      - dict (campo nombre):     {"first": "Juan", "last": "García"}
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_jf_value_to_str(v) for v in value if v not in (None, "")).strip()
    if isinstance(value, dict):
        # Campo de nombre completo
        if any(k in value for k in ("first", "last", "middle")):
            parts = [value.get("first", ""), value.get("middle", ""), value.get("last", "")]
            return " ".join(str(p).strip() for p in parts if p).strip()
        # Cualquier otro dict: unimos los valores no vacíos
        return " ".join(str(v).strip() for v in value.values() if v).strip()
    return str(value).strip()


def _jf_find_answer(answers: dict, texts_buscados: tuple) -> object:
    """Busca un campo por coincidencia (case-insensitive) en su 'text' o 'name'."""
    if not isinstance(answers, dict):
        return None
    targets = tuple(t.lower() for t in texts_buscados)
    for _qid, q in answers.items():
        if not isinstance(q, dict):
            continue
        text = (str(q.get("text") or "") + " " + str(q.get("name") or "")).lower()
        if any(t in text for t in targets):
            return q.get("answer")
    return None


def parse_externo_submission(sub: dict) -> dict:
    """Convierte una submission cruda de Jotform en un registro de externo."""
    answers = sub.get("answers", {}) if isinstance(sub, dict) else {}
    nombre = _jf_value_to_str(_jf_find_answer(answers, JF_FIELD_NOMBRE))
    empresa = _jf_value_to_str(_jf_find_answer(answers, JF_FIELD_EMPRESA))
    planta_raw = _jf_value_to_str(_jf_find_answer(answers, JF_FIELD_PLANTA))
    motivo = _jf_value_to_str(_jf_find_answer(answers, JF_FIELD_MOTIVO))
    referencia = _jf_value_to_str(_jf_find_answer(answers, JF_FIELD_REFERENCIA))
    return {
        "id": str(sub.get("id", "")),
        "created_at": sub.get("created_at", ""),
        "nombre": nombre or "(sin nombre)",
        "empresa": empresa,
        "planta_raw": planta_raw,
        "planta": planta_externo_to_id(planta_raw),
        "motivo": motivo,
        "referencia": referencia,
    }


def planta_externo_to_id(planta_raw: str) -> str:
    """Mapea el valor del Jotform ('Esquiroz', 'Uharte-Arakil', ...) a 'P2'/'P3'."""
    n = norm_text(planta_raw)
    if not n:
        return ""
    for pid, keywords in JOTFORM_PLANTA_KEYWORDS.items():
        for kw in keywords:
            if kw in n:
                return pid
    return ""


# ============================================================
# LÓGICA DE PRESENCIA (sin pandas: dicts y listas)
# ============================================================

NIF_EMPLEADO_KEYS = ("nif", "Nif", "NIF", "dni", "documento")
NIF_FICHAJE_KEYS  = ("nif", "NIF", "dni", "documento", "nif_empleado", "empleado_nif")
NAME_KEYS         = ("name", "nombre", "Name")
AP1_KEYS          = ("primer_apellido", "Primer_apellido", "primerApellido")
AP2_KEYS          = ("segundo_apellido", "Segundo_apellido", "segundoApellido")
SEDE_KEYS         = ("sede", "Sede", "sede_id", "Sede_id")
TIPO_KEYS         = ("tipo", "Tipo", "tipo_fichaje", "tipoFichaje", "nombre_tipo", "tipo_nombre")


def first_value(d: dict, keys: tuple) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "None"):
            return str(v).strip()
    return ""


def get_nif(d: dict, keys: tuple) -> str:
    for k in keys:
        v = d.get(k)
        if v:
            return norm_nif(v)
    return ""


def full_name(emp: dict) -> str:
    return " ".join(
        p for p in (
            first_value(emp, NAME_KEYS),
            first_value(emp, AP1_KEYS),
            first_value(emp, AP2_KEYS),
        ) if p
    ).strip()


def extract_lat_lon(record: dict):
    lat = lon = None
    for k in ("latitud", "Latitud", "lat", "latitude", "Latitude"):
        if k in record:
            lat = parse_float(record.get(k))
            break
    for k in ("longitud", "Longitud", "lon", "lng", "longitude", "Longitude"):
        if k in record:
            lon = parse_float(record.get(k))
            break
    # Caso de coordenadas cruzadas (lat en longitud y viceversa)
    if lat is not None and lon is not None and abs(lat) < 10 and 35 <= abs(lon) <= 45:
        lat, lon = lon, lat
    return lat, lon


def detect_planta_text(text: str) -> str:
    n = norm_text(text)
    if not n:
        return ""
    for pid, cfg in PLANTAS.items():
        for kw in cfg["keywords"]:
            if norm_text(kw) in n:
                return pid
    return ""


def detect_planta_gps(lat, lon) -> str:
    if lat is None or lon is None:
        return ""
    best, dmin = "", None
    for pid, cfg in PLANTAS.items():
        d = haversine_m(lat, lon, *cfg["coords"])
        if dmin is None or d < dmin:
            best, dmin = pid, d
    return best if dmin is not None and dmin <= GEOFENCE_RADIUS_METERS else ""


def detect_planta(fichaje: dict, emp: dict | None) -> str:
    """Prioridad: tipo > centro/ubicación/terminal > GPS > sede empleado."""
    p = detect_planta_text(first_value(fichaje, TIPO_KEYS))
    if p:
        return p
    p = detect_planta_text(" ".join(
        str(fichaje.get(k, "")) for k in ("centro", "ubicacion", "terminal")
    ))
    if p:
        return p
    p = detect_planta_gps(*extract_lat_lon(fichaje))
    if p:
        return p
    if emp:
        p = detect_planta_text(first_value(emp, SEDE_KEYS))
        if p:
            return p
    return ""


def calcular_presencia(fichajes: list[dict], empleados: list[dict], planta_objetivo: str):
    """
    Devuelve (lista_nombres_ordenada, debug_rows).
    Recorre fichajes una sola vez quedándose con el último fichaje por NIF
    (sin ordenar 100k filas en pandas).
    """
    emp_by_nif = {}
    for e in empleados:
        nif = get_nif(e, NIF_EMPLEADO_KEYS)
        if nif:
            emp_by_nif[nif] = e

    seen_ids: set[str] = set()
    ultimo_por_nif: dict[str, tuple[datetime, dict]] = {}

    for f in fichajes:
        fid = str(f.get("id") or f.get("ID") or "")
        if fid:
            if fid in seen_ids:
                continue
            seen_ids.add(fid)

        nif = get_nif(f, NIF_FICHAJE_KEYS)
        dt = parse_dt(f.get("fecha"))
        direccion = norm_text(f.get("direccion"))
        if not nif or dt is None or not direccion:
            continue

        prev = ultimo_por_nif.get(nif)
        if prev is None or dt > prev[0]:
            ultimo_por_nif[nif] = (dt, f)

    presentes: list[str] = []
    debug: list[dict] = []
    for nif, (dt, f) in ultimo_por_nif.items():
        emp = emp_by_nif.get(nif, {})
        nombre = full_name(emp) or nif
        direccion = norm_text(f.get("direccion"))
        planta = detect_planta(f, emp)

        if direccion == "ENTRADA" and planta == planta_objetivo:
            presentes.append(nombre)

        debug.append({
            "Empleado": nombre,
            "NIF": nif,
            "Movimiento": direccion.lower(),
            "Planta": planta or "?",
        })

    presentes.sort(key=norm_text)
    return presentes, debug


# ============================================================
# CACHÉS STREAMLIT (compartidas entre usuarios del mismo proceso)
# ============================================================

@st.cache_resource(show_spinner=False)
def get_crece_client() -> CreceClient:
    """
    Cliente HTTP único por proceso.
    Reutiliza la sesión de requests (HTTP keep-alive, sin reabrir TLS en cada llamada).
    """
    return CreceClient()


@st.cache_data(ttl=EMPLEADOS_TTL, show_spinner=False)
def cached_empleados() -> list[dict]:
    return get_crece_client().empleados()


@st.cache_data(ttl=ULTIMO_FICHAJE_TTL, show_spinner=False)
def cached_ultimo_fichaje() -> str:
    """TTL muy corto: agrupa ráfagas de pulsaciones simultáneas en una sola llamada."""
    return get_crece_client().ultimo_fichaje()


def _fetch_fichajes_dia(fecha: str) -> tuple[list[dict], str]:
    """Función interna: descarga fichajes de un día concreto, con fallback NIF a NIF."""
    client = get_crece_client()
    try:
        return client.fichajes(fecha, fecha), "global"
    except Exception:
        empleados_local = cached_empleados()
        nifs = sorted({
            n for n in (get_nif(e, NIF_EMPLEADO_KEYS) for e in empleados_local) if n
        })
        result: list[dict] = []
        for nif in nifs:
            try:
                fs = client.fichajes_por_nif(fecha, fecha, nif)
                for f in fs:
                    if not get_nif(f, NIF_FICHAJE_KEYS):
                        f["nif"] = nif
                result.extend(fs)
            except Exception:
                continue
        return result, "por_empleado"


@st.cache_data(ttl=DIA_CERRADO_TTL, show_spinner=False, max_entries=8)
def cached_fichajes_cerrado(fecha: str, version_dia: str) -> tuple[list[dict], str]:
    """
    Fichajes de un día ya pasado. TTL 24 h.
    version_dia = today_str: cambia 1 vez al día (al pasar la medianoche),
    obligando a una sola re-consulta para consolidar fichajes tardíos.
    """
    return _fetch_fichajes_dia(fecha)


@st.cache_data(ttl=HOY_TTL, show_spinner=False, max_entries=4)
def cached_fichajes_hoy(fecha: str, version: str) -> tuple[list[dict], str]:
    """
    Fichajes del día en curso.
    Idealmente version = ultimo-fichaje, que cambia cuando alguien ficha.
    TTL corto (60 s) como RED DE SEGURIDAD: aunque ultimo-fichaje falle o
    devuelva siempre el mismo valor, este TTL garantiza que los datos se
    refrescan al menos cada minuto.
    """
    return _fetch_fichajes_dia(fecha)


@st.cache_data(ttl=PRESENCIA_TTL, show_spinner=False, max_entries=8)
def cached_presencia(hoy_str: str, ayer_str: str, ultimo_fichaje: str, planta_objetivo: str):
    """
    Calcula presencia partiendo la consulta en dos:
      - Fichajes de AYER: cacheados con version = hoy_str → se piden 1 vez al día.
      - Fichajes de HOY:  cacheados con version = ultimo_fichaje + TTL corto.

    Cuando alguien ficha y pulsa "Actualizar", sólo se descarga el día en curso
    (mucho más pequeño que ayer+hoy completos).
    """
    fichajes_ayer, modo_ayer = cached_fichajes_cerrado(ayer_str, hoy_str)
    fichajes_hoy, modo_hoy = cached_fichajes_hoy(hoy_str, ultimo_fichaje)
    fichajes = fichajes_ayer + fichajes_hoy

    empleados = cached_empleados()
    presentes, debug = calcular_presencia(fichajes, empleados, planta_objetivo)
    modo = "global" if modo_ayer == "global" and modo_hoy == "global" else "por_empleado"
    return presentes, debug, modo


# ============================================================
# CACHÉS JOTFORM
# ============================================================

@st.cache_resource(show_spinner=False)
def get_jotform_client() -> "JotformClient":
    """Cliente único por proceso; comparte sesión HTTP entre llamadas."""
    return JotformClient()


@st.cache_data(ttl=JOTFORM_QUESTIONS_TTL, show_spinner=False)
def qid_campo_id_entrada(form_salidas_id: str) -> str:
    """
    Descubre el qid del campo de texto del form de salidas.
    El form debe tener UN SOLO campo de tipo 'control_textbox'.
    Cacheado 1h porque la estructura del form rara vez cambia.
    """
    if not form_salidas_id:
        return ""
    questions = get_jotform_client().questions(form_salidas_id)
    # Buscar primer campo "rellenable" (no de cabecera/separador).
    rellenables = {"control_textbox", "control_textarea", "control_number"}
    for qid, q in questions.items():
        if not isinstance(q, dict):
            continue
        if q.get("type") in rellenables:
            return str(qid)
    return ""


@st.cache_data(ttl=EXTERNOS_TTL, show_spinner=False, max_entries=4)
def cached_externos_hoy(hoy_str: str, planta_objetivo: str) -> list[dict]:
    """
    Lista de externos que han entrado HOY y siguen sin marca de salida,
    ya filtrados por la planta del Jotform que coincide con planta_objetivo.

    El TTL corto (30 s) actúa como red de seguridad: si la API de Jotform
    queda inaccesible momentáneamente, la app sigue mostrando el último
    listado conocido durante medio minuto.

    La lógica de "sigue dentro" (cuando exista el form de salidas) se aplica
    aquí cruzando con las submissions del form de salidas. Hasta que se
    configure JOTFORM_FORM_SALIDAS, todos los externos del día se consideran
    "presentes" — eso es lo prudente para una lista de evacuación.
    """
    client = get_jotform_client()
    crudos = client.submissions_desde(client.form_entradas, hoy_str)
    externos = [parse_externo_submission(s) for s in crudos]

    # Filtrado por planta de la app
    externos = [e for e in externos if e["planta"] == planta_objetivo]

    # IDs ya marcados como salida (si hay form de salidas configurado)
    salidos: set[str] = set()
    if client.form_salidas:
        try:
            salidas = client.submissions_desde(client.form_salidas, hoy_str)
            qid_id = qid_campo_id_entrada(client.form_salidas)
            for s in salidas:
                ans = s.get("answers", {}) if isinstance(s, dict) else {}
                if qid_id and isinstance(ans, dict):
                    val = ans.get(qid_id, {})
                    if isinstance(val, dict):
                        sid = str(val.get("answer", "")).strip()
                        if sid:
                            salidos.add(sid)
        except Exception:
            # Si falla la lectura de salidas, mejor mostrar TODAS las entradas
            # del día que perder un externo de la lista de emergencia.
            pass

    externos = [e for e in externos if e["id"] not in salidos]
    externos.sort(key=lambda e: e.get("created_at", ""))
    return externos


def clear_caches() -> None:
    """Invalida todas las cachés. Sólo se usa desde 'Forzar refresco'."""
    cached_empleados.clear()
    cached_ultimo_fichaje.clear()
    cached_fichajes_cerrado.clear()
    cached_fichajes_hoy.clear()
    cached_presencia.clear()
    cached_externos_hoy.clear()
    qid_campo_id_entrada.clear()


# ============================================================
# UI STREAMLIT
# ============================================================

def df_height(rows: int) -> int:
    """Altura calculada para que la tabla CREZCA en lugar de mostrar scroll interno."""
    if rows <= 0:
        return 80
    return min(900, 44 + rows * 36)


def cargar_datos(planta_objetivo: str, hoy_str: str, ayer_str: str) -> dict:
    """
    Carga todo lo necesario para una pulsación de 'Actualizar':
    empleados presentes (CRECE) + externos en planta (Jotform).
    Cada bloque captura su propia excepción para que un fallo en Jotform
    no esconda los empleados de CRECE, y viceversa.
    """
    out: dict = {
        "presentes": [],
        "debug_emp": [],
        "modo_emp": "",
        "version": "",
        "externos": [],
        "errores": [],
    }

    # --- Empleados (CRECE) ---
    try:
        try:
            ultimo = cached_ultimo_fichaje() or f"fb-{int(time.time() // 60)}"
        except Exception:
            ultimo = f"fb-{int(time.time() // 60)}"
        presentes, debug_emp, modo_emp = cached_presencia(
            hoy_str, ayer_str, ultimo, planta_objetivo,
        )
        out.update({
            "presentes": presentes,
            "debug_emp": debug_emp,
            "modo_emp": modo_emp,
            "version": ultimo,
        })
    except Exception:
        out["errores"].append("empleados")

    # --- Externos (Jotform) ---
    try:
        out["externos"] = cached_externos_hoy(hoy_str, planta_objetivo)
    except Exception:
        out["errores"].append("externos")

    out["updated_at"] = now_madrid()
    return out


def render_externos_tabla(externos: list[dict]) -> None:
    """Tabla compacta de externos en planta, con hora local de entrada."""
    if not externos:
        st.info("No hay personal externo registrado en planta hoy.")
        return
    filas = []
    for e in externos:
        hora = ""
        ts = parse_dt(e.get("created_at"))
        if ts is not None:
            hora = ts.strftime("%H:%M")
        filas.append({
            "Hora entrada": hora,
            "Visitante": e.get("nombre", ""),
            "Empresa": e.get("empresa", ""),
            "Motivo": e.get("motivo", ""),
            "Referencia": e.get("referencia", ""),
        })
    st.dataframe(
        filas,
        use_container_width=True,
        hide_index=True,
        height=df_height(len(filas)),
    )


def render_emergencia(planta_objetivo: str, res: dict) -> None:
    """
    Vista para usar EN UNA EMERGENCIA.
    Lista única, fuente grande, una sola página, sin distracciones.
    """
    cfg = PLANTAS[planta_objetivo]
    st.markdown(
        f"<h1 style='color:#b00020;margin-bottom:0;'>🚨 EVACUACIÓN — {cfg['titulo']}</h1>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Listado a las {res['updated_at'].strftime('%H:%M:%S')}. "
        "Marca a cada persona conforme aparezca en el punto de encuentro."
    )

    empleados = res.get("presentes", [])
    externos = res.get("externos", [])
    total = len(empleados) + len(externos)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total a localizar", total)
    c2.metric("Empleados", len(empleados))
    c3.metric("Externos", len(externos))

    if res.get("errores"):
        st.warning(
            "Atención: hay datos que no se han podido cargar ("
            + ", ".join(res["errores"]) + "). "
            "La lista puede estar incompleta. Usa el plan B en papel si lo tienes."
        )

    if st.button("← Volver a la vista normal", use_container_width=False):
        st.session_state["modo_pantalla"] = "normal"
        st.rerun()

    st.divider()

    filas: list[dict] = []
    for nombre in empleados:
        filas.append({
            "✔": False,
            "Persona": nombre,
            "Categoría": "Empleado",
            "Detalle": "",
        })
    for e in externos:
        ts = parse_dt(e.get("created_at"))
        hora = ts.strftime("%H:%M") if ts is not None else ""
        detalle_partes = [p for p in [
            e.get("empresa"),
            f"visita a {e['referencia']}" if e.get("referencia") else "",
            f"entró {hora}" if hora else "",
        ] if p]
        filas.append({
            "✔": False,
            "Persona": e.get("nombre", ""),
            "Categoría": "Externo",
            "Detalle": " · ".join(detalle_partes),
        })

    if not filas:
        st.success("No hay nadie registrado actualmente en planta.")
        return

    # data_editor para que el coordinador pueda ir tachando con checkboxes.
    st.data_editor(
        filas,
        use_container_width=True,
        hide_index=True,
        disabled=("Persona", "Categoría", "Detalle"),
        height=df_height(len(filas)),
        column_config={
            "✔": st.column_config.CheckboxColumn(width="small"),
        },
        key="emergencia_editor",
    )


def render(planta_objetivo: str, show_debug: bool) -> None:
    cfg = PLANTAS[planta_objetivo]
    st.set_page_config(page_title=cfg["titulo"], page_icon="🏭", layout="wide")

    today_md = now_madrid().replace(hour=0, minute=0, second=0, microsecond=0)
    hoy_str = today_md.strftime("%Y-%m-%d")
    ayer_str = (today_md - timedelta(days=NOCTURNAL_LOOKBACK_DAYS)).strftime("%Y-%m-%d")

    # ----- Modo pantalla: normal | emergencia -----
    modo_pantalla = st.session_state.get("modo_pantalla", "normal")

    if modo_pantalla == "emergencia":
        res = st.session_state.get("resultado")
        if not res:
            # Si entran directos en modo emergencia (sin haber pulsado Actualizar),
            # cargamos en el momento.
            res = cargar_datos(planta_objetivo, hoy_str, ayer_str)
            st.session_state["resultado"] = res
        render_emergencia(planta_objetivo, res)
        return

    # ----- Vista normal -----
    st.title(cfg["titulo"])

    cols = st.columns([2, 6, 2])
    refresh = cols[0].button("Actualizar ahora", type="primary", use_container_width=True)
    if cols[2].button("🚨 Emergencia", use_container_width=True, help="Vista de evacuación"):
        if "resultado" not in st.session_state:
            st.session_state["resultado"] = cargar_datos(planta_objetivo, hoy_str, ayer_str)
        st.session_state["modo_pantalla"] = "emergencia"
        st.rerun()

    if refresh:
        with st.spinner("Actualizando presencia..."):
            st.session_state["resultado"] = cargar_datos(planta_objetivo, hoy_str, ayer_str)

    res = st.session_state.get("resultado")
    if not res:
        st.info("Pulsa **Actualizar ahora** para ver quién está en planta.")
        return

    empleados = res["presentes"]
    externos = res["externos"]

    if res.get("errores"):
        st.warning(
            "No se han podido cargar algunos datos: "
            + ", ".join(res["errores"]) + ". La lista puede estar incompleta."
        )

    c1, c2, c3 = st.columns(3)
    c1.metric("Empleados", len(empleados))
    c2.metric("Externos", len(externos))
    c3.metric("Última actualización", res["updated_at"].strftime("%H:%M:%S"))

    st.divider()

    st.subheader("Empleados trabajando ahora")
    if not empleados:
        st.success(f"No hay empleados trabajando ahora mismo en {cfg['titulo']}.")
    else:
        st.dataframe(
            [{"Empleado": n} for n in empleados],
            use_container_width=True,
            hide_index=True,
            height=df_height(len(empleados)),
        )

    st.subheader("Personal externo en planta")
    render_externos_tabla(externos)

    if show_debug:
        with st.expander("Validación técnica del cálculo", expanded=False):
            st.caption(
                f"Modo consulta empleados: {res.get('modo_emp', '?')}  ·  "
                f"Valor ultimo-fichaje: {repr(res.get('version'))[:64]}"
            )
            st.caption(
                "Si pulsando varias veces tras nuevos fichajes ves siempre el "
                "mismo valor de ultimo-fichaje, ese endpoint no está sirviendo "
                "como cheap-check; la red de seguridad (TTL hoy) refresca "
                f"como mucho cada {HOY_TTL}s."
            )
            if st.button("Forzar refresco completo", help="Ignora todas las cachés."):
                clear_caches()
                st.session_state.pop("resultado", None)
                st.rerun()
            debug_emp = res.get("debug_emp") or []
            if debug_emp:
                st.markdown("**Fichajes empleados (último de cada NIF):**")
                st.dataframe(debug_emp, use_container_width=True, hide_index=True)
            if externos:
                st.markdown("**Externos crudos (Jotform):**")
                st.dataframe(
                    [{
                        "id": e["id"],
                        "created_at": e.get("created_at"),
                        "nombre": e.get("nombre"),
                        "empresa": e.get("empresa"),
                        "planta_raw": e.get("planta_raw"),
                        "planta_id": e.get("planta"),
                    } for e in externos],
                    use_container_width=True, hide_index=True,
                )


# ============================================================
# PÁGINA DE SALIDA (la abre el visitante al escanear el QR)
# ============================================================

def render_salida(planta_objetivo: str) -> None:
    """
    Página accesible vía URL ?modo=salida.
    El visitante ve la lista de externos actualmente en planta
    (sólo de SU planta) y pulsa su nombre. La app hace POST al
    formulario de salidas con su submission_id de entrada.
    Pantalla optimizada para móvil: layout centrado, botones grandes.
    """
    cfg = PLANTAS[planta_objetivo]
    st.set_page_config(
        page_title=f"Salida — {cfg['titulo']}",
        page_icon="📋",
        layout="centered",
    )
    show_debug = get_bool_secret("SHOW_DEBUG_PRESENCIA", False)

    # Si acaba de marcar salida, mostramos confirmación y nada más.
    confirmacion = st.session_state.get("salida_confirmada")
    if confirmacion:
        st.markdown(
            "<h1 style='text-align:center;color:#1a7f37;margin-top:2rem;'>"
            "✅ Salida registrada</h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<h3 style='text-align:center;font-weight:normal;'>"
            f"Hasta pronto, {confirmacion}</h3>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<p style='text-align:center;color:#666;'>"
            f"{cfg['titulo']} · {now_madrid().strftime('%H:%M')}</p>",
            unsafe_allow_html=True,
        )
        st.markdown("&nbsp;")
        if st.button("Registrar otra salida", use_container_width=True):
            st.session_state.pop("salida_confirmada", None)
            st.rerun()
        return

    st.markdown(
        f"<h2 style='text-align:center;'>Salida de personal externo</h2>"
        f"<p style='text-align:center;color:#666;margin-top:-0.5rem;'>{cfg['titulo']}</p>",
        unsafe_allow_html=True,
    )

    today_md = now_madrid().replace(hour=0, minute=0, second=0, microsecond=0)
    hoy_str = today_md.strftime("%Y-%m-%d")

    try:
        externos = cached_externos_hoy(hoy_str, planta_objetivo)
    except Exception as exc:
        st.error(
            "No se ha podido cargar la lista. Inténtalo de nuevo en unos "
            "segundos o avisa al personal de planta."
        )
        if show_debug:
            st.caption(f"Detalle técnico: {exc}")
        return

    if not externos:
        st.info(
            "No hay registros de entrada pendientes de marcar salida en "
            f"{cfg['titulo']}."
        )
        st.caption(
            "Si has entrado hoy y no aparece tu nombre, comprueba que estás "
            "usando el QR de la planta correcta o avisa al personal."
        )
        return

    st.markdown("**Pulsa tu nombre para registrar la salida:**")
    st.markdown("&nbsp;")

    for e in externos:
        ts = parse_dt(e.get("created_at"))
        hora = ts.strftime("%H:%M") if ts is not None else "?"
        partes_detalle = [e.get("empresa") or "", f"entrada {hora}"]
        if e.get("referencia"):
            partes_detalle.insert(1, f"visita a {e['referencia']}")
        label = f"{e['nombre']}\n\n{' · '.join(p for p in partes_detalle if p)}"

        if st.button(label, use_container_width=True, key=f"sal_{e['id']}"):
            try:
                get_jotform_client().crear_salida(e["id"])
                # Refrescamos la caché para que ya no aparezca en próximas pulsaciones.
                cached_externos_hoy.clear()
                st.session_state["salida_confirmada"] = e["nombre"]
                st.rerun()
            except Exception as exc:
                st.error(
                    "No se ha podido registrar la salida. Inténtalo otra vez "
                    "o avisa al personal de planta."
                )
                if show_debug:
                    st.caption(f"Detalle técnico: {exc}")

    st.divider()
    st.caption(
        "¿No encuentras tu nombre? Verifica que estás escaneando el QR de "
        "esta planta. Si has olvidado registrar la entrada, avisa al "
        "personal antes de irte."
    )


def main() -> None:
    planta = norm_text(PLANTA_OBJETIVO)
    if planta not in PLANTAS:
        st.error("Configuración de planta inválida.")
        st.stop()

    # Routing por query param. Una URL única por planta sirve para:
    #   - vista principal (la tablet en la pared):       /
    #   - pantalla de salida (el QR del visitante):      /?modo=salida
    modo = ""
    try:
        modo = str(st.query_params.get("modo", "")).lower()
    except Exception:
        # Compatibilidad con Streamlit antiguo
        try:
            qp = st.experimental_get_query_params()
            modo = str((qp.get("modo") or [""])[0]).lower()
        except Exception:
            pass

    if modo == "salida":
        render_salida(planta)
        return

    show_debug = get_bool_secret("SHOW_DEBUG_PRESENCIA", False)
    render(planta, show_debug)


if __name__ == "__main__":
    main()
