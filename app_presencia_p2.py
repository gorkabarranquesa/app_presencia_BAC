"""
APP PRESENCIA ACTUAL POR PLANTA — CRECE PERSONAS
================================================

Misma app para P2 COMARCA II y P3 UHARTE. Lo único que cambia entre
app_presencia_p2.py y app_presencia_p3.py es la constante PLANTA_OBJETIVO
en la sección "CONFIGURACIÓN".

Optimización clave
------------------
Antes de pedir todos los fichajes (consulta pesada: descarga + descifrado +
deserialización), llamamos al endpoint barato GET /exportacion/ultimo-fichaje
y lo usamos como "ETag":
    - Si su valor NO ha cambiado desde la última pulsación, devolvemos al
      instante la presencia ya calculada que tenemos en caché.
    - Si SÍ ha cambiado (alguien acaba de fichar), invalidamos esa entrada y
      sólo entonces recalculamos.

Cuando muchos empleados pulsan "Actualizar ahora" en pocos segundos —el caso
real de las primeras horas en planta— sólo se llama a /exportacion/fichajes
las veces que de verdad ha entrado o salido alguien.

Secrets esperados (.streamlit/secrets.toml)
-------------------------------------------
    API_TOKEN            = "..."
    APP_KEY_B64          = "..."
    CRECE_BASE_URL       = "https://sincronizaciones.crecepersonas.es/api"
    SHOW_DEBUG_PRESENCIA = false    # opcional
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
PRESENCIA_TTL = 60 * 5       # 5 min: tope de seguridad si todo lo demás fallase
DIA_CERRADO_TTL = 60 * 60 * 24   # 24 h: días pasados ya no cambian
REQUEST_TIMEOUT = 20


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


@st.cache_data(ttl=DIA_CERRADO_TTL, show_spinner=False, max_entries=8)
def cached_fichajes_dia(fecha: str, version: str) -> tuple[list[dict], str]:
    """
    Fichajes de un único día concreto, cacheados por (fecha, version).

    Esta es la pieza clave para acelerar el caso "alguien acaba de fichar":
    - Días pasados se cachean con version estable (no cambian más en todo el día).
    - El día en curso se cachea con version = ultimo-fichaje, así sólo se
      vuelve a descargar cuando alguien ficha de verdad.
    """
    client = get_crece_client()
    try:
        return client.fichajes(fecha, fecha), "global"
    except Exception:
        # Fallback documentado: si la consulta global falla, vamos NIF a NIF.
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


@st.cache_data(ttl=PRESENCIA_TTL, show_spinner=False, max_entries=8)
def cached_presencia(hoy_str: str, ayer_str: str, ultimo_fichaje: str, planta_objetivo: str):
    """
    Calcula presencia partiendo la consulta en dos:
      - Fichajes de AYER: cacheados con version = hoy_str → se piden 1 vez al día.
      - Fichajes de HOY:  cacheados con version = ultimo_fichaje → se piden sólo
        cuando alguien ficha de verdad.

    Cuando alguien ficha y pulsa "Actualizar", sólo se descarga el día en curso
    (mucho más pequeño que ayer+hoy completos).
    """
    fichajes_ayer, modo_ayer = cached_fichajes_dia(ayer_str, hoy_str)
    fichajes_hoy, modo_hoy = cached_fichajes_dia(hoy_str, ultimo_fichaje)
    fichajes = fichajes_ayer + fichajes_hoy

    empleados = cached_empleados()
    presentes, debug = calcular_presencia(fichajes, empleados, planta_objetivo)
    modo = "global" if modo_ayer == "global" and modo_hoy == "global" else "por_empleado"
    return presentes, debug, modo


def clear_caches() -> None:
    """Invalida todas las cachés. Sólo se usa desde 'Forzar refresco'."""
    cached_empleados.clear()
    cached_ultimo_fichaje.clear()
    cached_fichajes_dia.clear()
    cached_presencia.clear()


# ============================================================
# UI STREAMLIT
# ============================================================

def df_height(rows: int) -> int:
    """Altura calculada para que la tabla CREZCA en lugar de mostrar scroll interno."""
    if rows <= 0:
        return 80
    return min(900, 44 + rows * 36)


def render(planta_objetivo: str, show_debug: bool) -> None:
    cfg = PLANTAS[planta_objetivo]
    st.set_page_config(page_title=cfg["titulo"], page_icon="🏭", layout="wide")
    st.title(cfg["titulo"])

    today_md = now_madrid().replace(hour=0, minute=0, second=0, microsecond=0)
    hoy_str = today_md.strftime("%Y-%m-%d")
    ayer_str = (today_md - timedelta(days=NOCTURNAL_LOOKBACK_DAYS)).strftime("%Y-%m-%d")

    refresh = st.button("Actualizar ahora", type="primary")

    if refresh:
        try:
            with st.spinner("Actualizando presencia..."):
                # Cheap-check: invalida sólo el día EN CURSO cuando alguien ficha.
                # Los fichajes de ayer permanecen cacheados hasta que cambia el día.
                # Si /exportacion/ultimo-fichaje fallase, usamos un cubo de 1 minuto
                # como versión sintética: peor caso = recalcular cada minuto.
                try:
                    ultimo = cached_ultimo_fichaje() or f"fb-{int(time.time() // 60)}"
                except Exception:
                    ultimo = f"fb-{int(time.time() // 60)}"

                presentes, debug, modo = cached_presencia(
                    hoy_str, ayer_str, ultimo, planta_objetivo,
                )

            st.session_state["resultado"] = {
                "presentes": presentes,
                "debug": debug,
                "modo": modo,
                "version": ultimo,
                "updated_at": now_madrid(),
            }
        except Exception:
            # Sin trazas técnicas hacia el usuario final.
            st.error("No se ha podido actualizar la presencia. Inténtalo de nuevo en unos segundos.")
            return

    res = st.session_state.get("resultado")
    if not res:
        st.info("Pulsa **Actualizar ahora** para ver quién está en planta.")
        return

    presentes = res["presentes"]
    c1, c2 = st.columns(2)
    c1.metric("Trabajando ahora", len(presentes))
    c2.metric("Última actualización", res["updated_at"].strftime("%H:%M:%S"))

    st.divider()

    if not presentes:
        st.success(f"No hay empleados trabajando ahora mismo en {cfg['titulo']}.")
    else:
        st.dataframe(
            [{"Empleado": n} for n in presentes],
            use_container_width=True,
            hide_index=True,
            height=df_height(len(presentes)),
        )

    if show_debug:
        with st.expander("Validación técnica del cálculo", expanded=False):
            st.caption(
                f"Modo consulta: {res['modo']}  ·  "
                f"Versión caché: {str(res['version'])[:32]}"
            )
            if st.button("Forzar refresco completo", help="Ignora todas las cachés."):
                clear_caches()
                st.session_state.pop("resultado", None)
                st.rerun()
            if not res["debug"]:
                st.warning("No hay fichajes válidos en la ventana consultada.")
            else:
                st.dataframe(res["debug"], use_container_width=True, hide_index=True)


def main() -> None:
    planta = norm_text(PLANTA_OBJETIVO)
    if planta not in PLANTAS:
        st.error("Configuración de planta inválida.")
        st.stop()
    show_debug = get_bool_secret("SHOW_DEBUG_PRESENCIA", False)
    render(planta, show_debug)


if __name__ == "__main__":
    main()
