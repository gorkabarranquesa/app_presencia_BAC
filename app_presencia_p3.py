"""
APP PRESENCIA ACTUAL POR PLANTA - CRECE PERSONAS

Versión optimizada para usuario final:
- Pantalla limpia.
- Solo muestra el nombre del empleado.
- La tabla crece según el número de empleados, sin scroll interno.
- Carga más rápida usando caché para empleados.
- Mantiene seguridad: secrets, HTTPS, payload cifrado, validación MAC y sin trazas técnicas visibles.
- Consulta fichajes desde ayer hasta hoy para cubrir posibles turnos nocturnos.
- Coordenadas exactas de P2/P3 fijadas manualmente.

Secrets esperados en .streamlit/secrets.toml:
API_TOKEN = "..."
APP_KEY_B64 = "..."
CRECE_BASE_URL = "https://sincronizaciones.crecepersonas.es/api"

Opcional:
SHOW_DEBUG_PRESENCIA = false
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
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
# app_presencia_p2.py -> "P2"
# app_presencia_p3.py -> "P3"
PLANTA_OBJETIVO = "P3"

PLANTAS = {
    "P2": {
        "titulo": "P2 COMARCA II",
        "nombre": "P2 COMARCA II",
        "keywords": ["P2", "COMARCA", "COMARCA II", "ESQUIROZ", "ESQUÍROZ"],
        "coords": (42.7656803, -1.6615654),
    },
    "P3": {
        "titulo": "P3 UHARTE",
        "nombre": "P3 UHARTE",
        "keywords": ["P3", "UHARTE", "HUARTE", "UHARTE-ARAKIL", "UHARTE ARAKIL"],
        "coords": (42.9201789, -1.9821119),
    },
}

TIMEZONE = "Europe/Madrid"
NOCTURNAL_LOOKBACK_DAYS = 1
GEOFENCE_RADIUS_METERS = 350

# Empleados cambia poco. Lo cacheamos para que al pulsar actualizar normalmente solo consulte fichajes.
EMPLEADOS_CACHE_TTL_SECONDS = 60 * 60

# Si el endpoint global de fichajes no funcionase y hubiera que consultar empleado a empleado,
# este límite evita que la app se quede eternamente bloqueada. En condiciones normales no aplica.
REQUEST_TIMEOUT_SECONDS = 20


# ============================================================
# UTILIDADES
# ============================================================

def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    try:
        value = st.secrets.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass
    return os.getenv(name, default)


def get_bool_secret(name: str, default: bool = False) -> bool:
    value = get_secret(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "si", "sí"}


def normalize_nif(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value)).upper().strip()


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).upper().strip()
    replacements = {
        "Á": "A",
        "É": "E",
        "Í": "I",
        "Ó": "O",
        "Ú": "U",
        "Ñ": "N",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


def parse_datetime(value: Any) -> Optional[pd.Timestamp]:
    if value is None or value == "":
        return None
    try:
        return pd.to_datetime(value, errors="coerce")
    except Exception:
        return None


def now_madrid() -> pd.Timestamp:
    return pd.Timestamp.now(tz=TIMEZONE)


def date_str(ts: pd.Timestamp) -> str:
    return ts.strftime("%Y-%m-%d")


def human_full_name(emp: Dict[str, Any]) -> str:
    parts = [
        emp.get("name") or emp.get("nombre") or emp.get("Name"),
        emp.get("primer_apellido") or emp.get("Primer_apellido") or emp.get("primerApellido"),
        emp.get("segundo_apellido") or emp.get("Segundo_apellido") or emp.get("segundoApellido"),
    ]
    return " ".join(str(p).strip() for p in parts if p not in [None, "", "None"]).strip()


def parse_float(value: Any) -> Optional[float]:
    if value in [None, "", "None"]:
        return None
    try:
        return float(str(value).replace(",", ".").strip())
    except Exception:
        return None


def normalize_lat_lon(lat: Optional[float], lon: Optional[float]) -> Tuple[Optional[float], Optional[float]]:
    if lat is None or lon is None:
        return lat, lon

    # Caso de coordenadas cruzadas: longitud en campo latitud y latitud en campo longitud.
    if abs(lat) < 10 and 35 <= abs(lon) <= 45:
        return lon, lat

    return lat, lon


def extract_lat_lon(record: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    lat = None
    lon = None

    for key in ["latitud", "Latitud", "lat", "latitude", "Latitude"]:
        if key in record:
            lat = parse_float(record.get(key))
            break

    for key in ["longitud", "Longitud", "lon", "lng", "longitude", "Longitude"]:
        if key in record:
            lon = parse_float(record.get(key))
            break

    return normalize_lat_lon(lat, lon)


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371000
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius * c


# ============================================================
# DESENCRIPTADO CRECE
# ============================================================

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def deserialize_php_or_json(raw_text: str) -> Any:
    if raw_text is None:
        return None

    raw_text = raw_text.strip()
    if raw_text == "":
        return None

    if raw_text.startswith("{") or raw_text.startswith("["):
        try:
            return json.loads(raw_text)
        except Exception:
            pass

    if phpserialize is None:
        raise RuntimeError("Falta phpserialize")

    return phpserialize.loads(
        raw_text.encode("utf-8"),
        decode_strings=True,
        object_hook=phpserialize.phpobject,
    )


def decrypt_crece_payload(payload_text: str, app_key_b64: str) -> Any:
    if AES is None:
        raise RuntimeError("Falta pycryptodome")

    if not payload_text:
        return None

    payload = json.loads(base64.b64decode(payload_text).decode("utf-8"))

    if not isinstance(payload, dict) or not all(k in payload for k in ["iv", "value", "mac"]):
        raise RuntimeError("Payload CRECE inválido")

    key = base64.b64decode(app_key_b64)
    iv_b64 = payload["iv"]
    value_b64 = payload["value"]
    mac_received = str(payload["mac"])

    # Seguridad: validación MAC antes de desencriptar.
    mac_expected = hmac.new(
        key,
        msg=(str(iv_b64) + str(value_b64)).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(mac_expected, mac_received):
        raise RuntimeError("MAC inválido")

    iv = base64.b64decode(iv_b64)
    encrypted_value = base64.b64decode(value_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = pkcs7_unpad(cipher.decrypt(encrypted_value))

    try:
        raw_text = decrypted.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = decrypted.decode("latin-1", errors="ignore")

    return deserialize_php_or_json(raw_text)


def to_records(data: Any) -> List[Dict[str, Any]]:
    if data is None:
        return []

    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        values = list(data.values())
        if values and all(isinstance(v, dict) for v in values):
            return values
        return [data]

    return []


# ============================================================
# CLIENTE API CRECE
# ============================================================

class CreceClient:
    def __init__(self) -> None:
        self.base_url = get_secret("CRECE_BASE_URL", "https://sincronizaciones.crecepersonas.es/api").rstrip("/")
        self.api_token = get_secret("API_TOKEN")
        self.app_key_b64 = get_secret("APP_KEY_B64")

        if not self.api_token:
            raise RuntimeError("Falta API_TOKEN")
        if not self.app_key_b64:
            raise RuntimeError("Falta APP_KEY_B64")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_token}",
            }
        )

    def post_export(self, endpoint: str, data: Dict[str, Any], timeout: int = REQUEST_TIMEOUT_SECONDS) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = self.session.post(url, data=data, timeout=timeout)
        response.raise_for_status()
        decrypted = decrypt_crece_payload(response.text, self.app_key_b64)
        return to_records(decrypted)

    def export_empleados(self) -> List[Dict[str, Any]]:
        return self.post_export("exportacion/empleados", {"solo_nif": 0})

    def export_fichajes(self, fecha_inicio: str, fecha_fin: str, order: str = "asc") -> List[Dict[str, Any]]:
        return self.post_export(
            "exportacion/fichajes",
            {
                "fecha_inicio": fecha_inicio,
                "fecha_fin": fecha_fin,
                "order": order,
            },
        )

    def export_fichajes_empleado(self, fecha_inicio: str, fecha_fin: str, nif: str, order: str = "asc") -> List[Dict[str, Any]]:
        return self.post_export(
            "exportacion/fichajes",
            {
                "fecha_inicio": fecha_inicio,
                "fecha_fin": fecha_fin,
                "nif": nif,
                "order": order,
            },
        )

    def export_fichajes_con_fallback(
        self,
        fecha_inicio: str,
        fecha_fin: str,
        empleados: List[Dict[str, Any]],
        order: str = "asc",
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Primero intenta consulta global.
        Si CRECE no lo permite, consulta empleado a empleado.
        """
        try:
            fichajes = self.export_fichajes(fecha_inicio, fecha_fin, order=order)
            return fichajes, "global"
        except Exception:
            all_fichajes: List[Dict[str, Any]] = []
            nifs = sorted({get_empleado_nif(emp) for emp in empleados if get_empleado_nif(emp)})

            for nif in nifs:
                try:
                    fichajes_emp = self.export_fichajes_empleado(fecha_inicio, fecha_fin, nif, order=order)

                    for fichaje in fichajes_emp:
                        if not get_fichaje_nif(fichaje):
                            fichaje["nif"] = nif

                    all_fichajes.extend(fichajes_emp)
                except Exception:
                    continue

            return all_fichajes, "por_empleado"


@st.cache_data(ttl=EMPLEADOS_CACHE_TTL_SECONDS, show_spinner=False)
def load_empleados_cached() -> List[Dict[str, Any]]:
    client = CreceClient()
    return client.export_empleados()


# ============================================================
# LÓGICA DE PRESENCIA
# ============================================================

def get_fichaje_nif(fichaje: Dict[str, Any]) -> str:
    for key in ["nif", "NIF", "dni", "documento", "nif_empleado", "empleado_nif"]:
        value = fichaje.get(key)
        if value:
            return normalize_nif(value)
    return ""


def get_empleado_nif(emp: Dict[str, Any]) -> str:
    for key in ["nif", "Nif", "NIF", "dni", "documento"]:
        value = emp.get(key)
        if value:
            return normalize_nif(value)
    return ""


def get_tipo_fichaje_value(fichaje: Dict[str, Any]) -> str:
    for key in ["tipo", "Tipo", "tipo_fichaje", "tipoFichaje", "nombre_tipo", "tipo_nombre"]:
        value = fichaje.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def get_sede_value(emp: Dict[str, Any]) -> str:
    for key in ["sede", "Sede", "sede_id", "Sede_id"]:
        value = emp.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def build_employee_lookup(empleados: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for emp in empleados:
        nif = get_empleado_nif(emp)
        if nif:
            lookup[nif] = emp
    return lookup


def detectar_planta_en_texto(text: str) -> str:
    normalized = normalize_text(text)

    for planta_id, cfg in PLANTAS.items():
        for keyword in cfg["keywords"]:
            if normalize_text(keyword) in normalized:
                return planta_id

    return "DESCONOCIDA"


def detectar_planta_por_gps(lat: Optional[float], lon: Optional[float]) -> Tuple[str, Optional[float]]:
    if lat is None or lon is None:
        return "DESCONOCIDA", None

    nearest_planta = "DESCONOCIDA"
    nearest_distance = None

    for planta_id, cfg in PLANTAS.items():
        plant_lat, plant_lon = cfg["coords"]
        distance = haversine_meters(lat, lon, plant_lat, plant_lon)

        if nearest_distance is None or distance < nearest_distance:
            nearest_distance = distance
            nearest_planta = planta_id

    if nearest_distance is not None and nearest_distance <= GEOFENCE_RADIUS_METERS:
        return nearest_planta, nearest_distance

    return "DESCONOCIDA", nearest_distance


def detectar_planta_fichaje(fichaje: Dict[str, Any], emp: Optional[Dict[str, Any]] = None) -> Tuple[str, str, Optional[float]]:
    """
    Prioridad:
    1) Tipo de fichaje si viene como texto P2/P3.
    2) Centro / ubicación / terminal.
    3) GPS del fichaje móvil.
    4) Sede del empleado como último fallback.
    """
    tipo = get_tipo_fichaje_value(fichaje)
    planta_tipo = detectar_planta_en_texto(tipo)
    if planta_tipo != "DESCONOCIDA":
        return planta_tipo, "tipo", None

    text = " ".join(
        [
            str(fichaje.get("centro", "")),
            str(fichaje.get("ubicacion", "")),
            str(fichaje.get("terminal", "")),
        ]
    )
    planta_texto = detectar_planta_en_texto(text)
    if planta_texto != "DESCONOCIDA":
        return planta_texto, "texto", None

    lat, lon = extract_lat_lon(fichaje)
    planta_gps, distancia = detectar_planta_por_gps(lat, lon)
    if planta_gps != "DESCONOCIDA":
        return planta_gps, "gps", distancia

    if emp:
        sede = get_sede_value(emp)
        planta_sede = detectar_planta_en_texto(sede)
        if planta_sede != "DESCONOCIDA":
            return planta_sede, "sede", None

    return "DESCONOCIDA", "sin_detectar", distancia


def calcular_presencia_actual(
    fichajes: List[Dict[str, Any]],
    empleados: List[Dict[str, Any]],
    planta_objetivo: str,
    include_debug: bool = False,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    emp_lookup = build_employee_lookup(empleados)

    rows = []
    seen_ids = set()

    for fichaje in fichajes:
        fichaje_id = str(fichaje.get("id") or fichaje.get("ID") or "")
        if fichaje_id:
            if fichaje_id in seen_ids:
                continue
            seen_ids.add(fichaje_id)

        nif = get_fichaje_nif(fichaje)
        fecha = parse_datetime(fichaje.get("fecha"))
        direccion = normalize_text(fichaje.get("direccion"))

        if not nif or fecha is None or pd.isna(fecha) or not direccion:
            continue

        emp = emp_lookup.get(nif, {})
        planta, fuente, distancia = detectar_planta_fichaje(fichaje, emp)

        rows.append(
            {
                "nif": nif,
                "fecha": fecha,
                "direccion": direccion,
                "planta": planta,
                "fuente": fuente,
                "distancia": distancia,
                "raw": fichaje,
            }
        )

    if not rows:
        return pd.DataFrame(columns=["Empleado"]), pd.DataFrame()

    df = pd.DataFrame(rows)
    df = df.sort_values(["nif", "fecha"], ascending=[True, True])

    ultimos = df.groupby("nif", as_index=False).tail(1).copy()

    output_rows = []
    debug_rows = []

    for _, row in ultimos.iterrows():
        nif = row["nif"]
        emp = emp_lookup.get(nif, {})
        nombre = human_full_name(emp) or nif

        if row["direccion"] == "ENTRADA" and row["planta"] == planta_objetivo:
            output_rows.append({"Empleado": nombre})

        if include_debug:
            debug_rows.append(
                {
                    "Empleado": nombre,
                    "NIF": nif,
                    "Último movimiento": str(row["direccion"]).lower(),
                    "Planta detectada": row["planta"],
                    "Fuente": row["fuente"],
                    "Distancia": row["distancia"],
                }
            )

    df_presencia = pd.DataFrame(output_rows, columns=["Empleado"])
    df_debug = pd.DataFrame(debug_rows)

    if not df_presencia.empty:
        df_presencia = df_presencia.sort_values(["Empleado"], ascending=True).reset_index(drop=True)

    return df_presencia, df_debug


# ============================================================
# UI STREAMLIT
# ============================================================

def render_header(planta_objetivo: str) -> None:
    cfg = PLANTAS[planta_objetivo]
    st.set_page_config(
        page_title=cfg["titulo"],
        page_icon="🏭",
        layout="wide",
    )
    st.title(cfg["titulo"])


def render_status_cards(total: int, updated_at: pd.Timestamp) -> None:
    c1, c2 = st.columns(2)
    c1.metric("Trabajando ahora", total)
    c2.metric("Última actualización", updated_at.strftime("%H:%M:%S"))


def dataframe_height(num_rows: int) -> int:
    # Altura dinámica para evitar scroll interno.
    # Cabecera ~38 px, cada fila ~35 px, margen extra.
    if num_rows <= 0:
        return 80
    return min(900, 44 + (num_rows * 36))


def main() -> None:
    planta_objetivo = normalize_text(PLANTA_OBJETIVO)
    if planta_objetivo not in PLANTAS:
        st.error("Configuración de planta inválida.")
        st.stop()

    show_debug = get_bool_secret("SHOW_DEBUG_PRESENCIA", False)

    render_header(planta_objetivo)

    today = now_madrid().normalize()
    fecha_hasta = today
    fecha_desde = today - pd.Timedelta(days=NOCTURNAL_LOOKBACK_DAYS)

    desde_str = date_str(fecha_desde)
    hasta_str = date_str(fecha_hasta)

    refresh = st.button("Actualizar ahora", use_container_width=False)

    if refresh:
        try:
            with st.spinner("Actualizando presencia..."):
                empleados = load_empleados_cached()

                client = CreceClient()
                fichajes, modo_consulta = client.export_fichajes_con_fallback(
                    desde_str,
                    hasta_str,
                    empleados,
                    order="asc",
                )

                df_presencia, df_debug = calcular_presencia_actual(
                    fichajes=fichajes,
                    empleados=empleados,
                    planta_objetivo=planta_objetivo,
                    include_debug=show_debug,
                )

            st.session_state["presencia_resultado"] = {
                "df_presencia": df_presencia,
                "df_debug": df_debug,
                "updated_at": now_madrid(),
                "modo_consulta": modo_consulta,
            }

        except Exception:
            st.error("No se ha podido actualizar la presencia. Inténtalo de nuevo en unos segundos.")
            return

    resultado = st.session_state.get("presencia_resultado")
    if not resultado:
        return

    df_presencia = resultado["df_presencia"]
    df_debug = resultado["df_debug"]
    updated_at = resultado["updated_at"]

    total = 0 if df_presencia.empty else len(df_presencia)
    render_status_cards(total, updated_at)

    st.divider()

    if df_presencia.empty:
        st.success(f"No hay empleados trabajando ahora mismo en {PLANTAS[planta_objetivo]['nombre']}.")
    else:
        st.dataframe(
            df_presencia[["Empleado"]],
            use_container_width=True,
            hide_index=True,
            height=dataframe_height(len(df_presencia)),
        )

    if show_debug:
        with st.expander("Validación técnica del cálculo", expanded=False):
            st.caption(f"Modo consulta: {resultado.get('modo_consulta')}")
            if df_debug.empty:
                st.warning("No hay fichajes válidos en la ventana consultada.")
            else:
                st.dataframe(df_debug, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
