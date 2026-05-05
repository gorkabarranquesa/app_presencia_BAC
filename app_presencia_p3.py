"""
APP PRESENCIA ACTUAL POR PLANTA - CRECE PERSONAS

Objetivo:
- Mostrar qué empleados están trabajando ahora mismo en una planta concreta.
- No usa filtros visibles.
- La planta se calcula por el último fichaje abierto.
- Prioridad de detección de planta:
  1) tipo de fichaje / nombre del tipo de fichaje
  2) centro / ubicacion / terminal del fichaje
  3) coordenadas GPS del fichaje móvil contra la geocerca de P2/P3
  4) sede asignada del empleado como último fallback
- Preparada para turnos nocturnos: consulta desde ayer hasta hoy.

Secrets esperados en .streamlit/secrets.toml:
API_TOKEN = "..."
APP_KEY_B64 = "..."
CRECE_BASE_URL = "https://sincronizaciones.crecepersonas.es/api"
"""

from __future__ import annotations

import base64
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
# CONFIGURACIÓN DE LA APP
# ============================================================

# Cambiar este valor en cada app.
# app_presencia_p2.py -> "P2"
# app_presencia_p3.py -> "P3"
PLANTA_OBJETIVO = "P3"

PLANTAS = {
    "P2": {
        "titulo": "P2 COMARCA II",
        "nombre": "P2 COMARCA II",
        "keywords": ["P2", "COMARCA", "COMARCA II"],
    },
    "P3": {
        "titulo": "P3 UHARTE",
        "nombre": "P3 UHARTE",
        "keywords": ["P3", "UHARTE", "HUARTE"],
    },
}

TIMEZONE = "Europe/Madrid"

# Ventana de seguridad para turnos nocturnos.
NOCTURNAL_LOOKBACK_DAYS = 1

# Radio de geocerca. Ajustable según precisión real del GPS en móvil.
GEOFENCE_RADIUS_METERS = 500

# Coordenadas manuales de planta.
# Importante: si aquí hay coordenadas, tienen prioridad sobre /exportacion/sedes.
# P3 queda fijada con la ubicación real que has verificado en CRECE/Google Maps.
PLANT_COORDS_MANUAL: Dict[str, Optional[Tuple[float, float]]] = {
    "P2": None,
    "P3": (42.920013, -1.982135),
}

MAX_OPEN_SHIFT_HOURS_WARNING = 18


# ============================================================
# UTILIDADES GENERALES
# ============================================================

def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    try:
        value = st.secrets.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass
    return os.getenv(name, default)


def normalize_nif(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value)).upper().strip()


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).upper().strip()
    text = text.replace("Á", "A").replace("É", "E").replace("Í", "I").replace("Ó", "O").replace("Ú", "U")
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


def get_record_id(record: Dict[str, Any]) -> str:
    for key in ["id", "ID", "Id"]:
        value = record.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def get_record_name(record: Dict[str, Any]) -> str:
    for key in ["nombre", "Nombre", "name", "Name"]:
        value = record.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def build_id_name_lookup(records: List[Dict[str, Any]]) -> Dict[str, str]:
    lookup: Dict[str, str] = {}
    for record in records:
        record_id = get_record_id(record)
        record_name = get_record_name(record)
        if record_id and record_name:
            lookup[record_id] = record_name
    return lookup


def resolve_lookup_value(value: Any, lookup: Dict[str, str]) -> str:
    if value in [None, "", "None"]:
        return ""
    value_str = str(value).strip()
    return lookup.get(value_str, value_str)


def parse_float(value: Any) -> Optional[float]:
    if value in [None, "", "None"]:
        return None
    try:
        return float(str(value).replace(",", ".").strip())
    except Exception:
        return None


def normalize_lat_lon(lat: Optional[float], lon: Optional[float]) -> Tuple[Optional[float], Optional[float]]:
    """
    Normaliza coordenadas.
    En el manual aparece una posible inversión de texto en sede:
    - latitud: Longitud
    - longitud: Latitud
    Para Navarra, normalmente latitud ronda 42.x y longitud ronda -1.x.
    Si detectamos valores claramente cruzados, los intercambiamos.
    """
    if lat is None or lon is None:
        return lat, lon

    # Caso probable de coordenadas cruzadas en Navarra / España norte.
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
        raise RuntimeError("Falta la dependencia phpserialize. Instala: pip install phpserialize")

    try:
        return phpserialize.loads(
            raw_text.encode("utf-8"),
            decode_strings=True,
            object_hook=phpserialize.phpobject,
        )
    except Exception as exc:
        raise RuntimeError(f"No se pudo deserializar la respuesta de CRECE: {exc}") from exc


def decrypt_crece_payload(payload_text: str, app_key_b64: str) -> Any:
    if AES is None:
        raise RuntimeError("Falta pycryptodome. Instala: pip install pycryptodome")

    if not payload_text:
        return None

    try:
        payload_json = base64.b64decode(payload_text)
        payload = json.loads(payload_json.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Respuesta CRECE no tiene formato encriptado esperado: {exc}") from exc

    if not isinstance(payload, dict) or not all(k in payload for k in ["iv", "value", "mac"]):
        raise RuntimeError("Payload CRECE inválido: faltan iv, value o mac")

    try:
        key = base64.b64decode(app_key_b64)
        iv = base64.b64decode(payload["iv"])
        encrypted_value = base64.b64decode(payload["value"])
    except Exception as exc:
        raise RuntimeError(f"No se pudo decodificar payload/key CRECE: {exc}") from exc

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_value)
    decrypted = pkcs7_unpad(decrypted)

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
            raise RuntimeError("Falta API_TOKEN en secrets.toml o variable de entorno")
        if not self.app_key_b64:
            raise RuntimeError("Falta APP_KEY_B64 en secrets.toml o variable de entorno")

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_token}",
        })

    def post_export(self, endpoint: str, data: Dict[str, Any], timeout: int = 60) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        resp = self.session.post(url, data=data, timeout=timeout)
        resp.raise_for_status()
        decrypted = decrypt_crece_payload(resp.text, self.app_key_b64)
        return to_records(decrypted)

    def get_export(self, endpoint: str, timeout: int = 60) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        resp = self.session.get(url, timeout=timeout)
        resp.raise_for_status()
        decrypted = decrypt_crece_payload(resp.text, self.app_key_b64)
        return to_records(decrypted)

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

    def export_empleados(self) -> List[Dict[str, Any]]:
        return self.post_export("exportacion/empleados", {"solo_nif": 0})

    def export_departamentos(self) -> List[Dict[str, Any]]:
        return self.get_export("exportacion/departamentos")

    def export_sedes(self) -> List[Dict[str, Any]]:
        return self.get_export("exportacion/sedes")

    def export_tipos_fichaje(self) -> List[Dict[str, Any]]:
        # El manual documenta este endpoint como POST sin parámetros obligatorios.
        return self.post_export("exportacion/tipos-fichaje", {})

    def export_fichajes_con_fallback(
        self,
        fecha_inicio: str,
        fecha_fin: str,
        empleados: List[Dict[str, Any]],
        order: str = "asc",
    ) -> Tuple[List[Dict[str, Any]], str]:
        try:
            fichajes = self.export_fichajes(fecha_inicio, fecha_fin, order=order)
            return fichajes, "global"
        except Exception:
            all_fichajes: List[Dict[str, Any]] = []
            nifs = sorted({get_empleado_nif(emp) for emp in empleados if get_empleado_nif(emp)})

            for nif in nifs:
                try:
                    fichajes_emp = self.export_fichajes_empleado(fecha_inicio, fecha_fin, nif, order=order)
                    for f in fichajes_emp:
                        if not get_fichaje_nif(f):
                            f["nif"] = nif
                    all_fichajes.extend(fichajes_emp)
                except Exception:
                    continue

            return all_fichajes, "por_empleado"


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


def get_num_empleado(emp: Dict[str, Any]) -> str:
    for key in ["num_empleado", "Num_empleado", "Nº empleado", "Nº Empleado", "numero_empleado"]:
        value = emp.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def get_departamento_value(emp: Dict[str, Any]) -> str:
    for key in ["departamento", "Departamento", "departamento_id", "Departamento_id"]:
        value = emp.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def get_sede_value(emp: Dict[str, Any]) -> str:
    for key in ["sede", "Sede", "sede_id", "Sede_id"]:
        value = emp.get(key)
        if value not in [None, "", "None"]:
            return str(value).strip()
    return ""


def detectar_planta_en_texto(text: str) -> str:
    normalized = normalize_text(text)
    for planta_id, cfg in PLANTAS.items():
        for keyword in cfg["keywords"]:
            if normalize_text(keyword) in normalized:
                return planta_id
    return "DESCONOCIDA"


def get_tipo_fichaje_value(fichaje: Dict[str, Any]) -> str:
    for key in ["tipo", "Tipo", "tipo_id", "id_tipo", "tipo_fichaje", "Tipo fichaje"]:
        value = fichaje.get(key)
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


def build_plant_coords_from_sedes(sedes: List[Dict[str, Any]]) -> Dict[str, Tuple[float, float]]:
    """
    Intenta obtener coordenadas P2/P3 desde /exportacion/sedes.
    Si no existen o no coinciden nombres, usa PLANT_COORDS_MANUAL.
    """
    result: Dict[str, Tuple[float, float]] = {}

    for sede in sedes:
        name = get_record_name(sede)
        planta = detectar_planta_en_texto(name)

        if planta == "DESCONOCIDA":
            continue

        lat, lon = extract_lat_lon(sede)
        if lat is None or lon is None:
            continue

        result[planta] = (lat, lon)

    # Las coordenadas manuales tienen prioridad sobre las de /exportacion/sedes.
    # Así evitamos que una sede mal configurada haga calcular distancias erróneas.
    for planta, coords in PLANT_COORDS_MANUAL.items():
        if coords is not None:
            result[planta] = coords

    return result


def detectar_planta_por_gps(
    lat: Optional[float],
    lon: Optional[float],
    plant_coords: Dict[str, Tuple[float, float]],
) -> Tuple[str, Optional[float]]:
    if lat is None or lon is None or not plant_coords:
        return "DESCONOCIDA", None

    nearest_planta = "DESCONOCIDA"
    nearest_distance = None

    for planta, (plant_lat, plant_lon) in plant_coords.items():
        distance = haversine_meters(lat, lon, plant_lat, plant_lon)
        if nearest_distance is None or distance < nearest_distance:
            nearest_distance = distance
            nearest_planta = planta

    if nearest_distance is not None and nearest_distance <= GEOFENCE_RADIUS_METERS:
        return nearest_planta, nearest_distance

    return "DESCONOCIDA", nearest_distance


def detectar_planta_fichaje(
    fichaje: Dict[str, Any],
    emp: Optional[Dict[str, Any]],
    sedes_lookup: Dict[str, str],
    plant_coords: Dict[str, Tuple[float, float]],
    tipos_fichaje_lookup: Dict[str, str],
) -> Tuple[str, str, Optional[float]]:
    """
    Prioridad:
    1) Tipo de fichaje / nombre del tipo de fichaje.
    2) Texto del fichaje: centro / ubicación / terminal.
    3) GPS del fichaje móvil.
    4) Sede asignada del empleado.
    """
    tipo_raw = get_tipo_fichaje_value(fichaje)
    tipo_nombre = resolve_lookup_value(tipo_raw, tipos_fichaje_lookup)

    planta_tipo = detectar_planta_en_texto(f"{tipo_raw} {tipo_nombre}")
    if planta_tipo != "DESCONOCIDA":
        return planta_tipo, "tipo_fichaje", None

    text_fichaje = " ".join([
        str(fichaje.get("centro", "")),
        str(fichaje.get("ubicacion", "")),
        str(fichaje.get("terminal", "")),
    ])

    planta = detectar_planta_en_texto(text_fichaje)
    if planta != "DESCONOCIDA":
        return planta, "fichaje_texto", None

    lat, lon = extract_lat_lon(fichaje)
    planta_gps, distancia = detectar_planta_por_gps(lat, lon, plant_coords)
    if planta_gps != "DESCONOCIDA":
        return planta_gps, "gps_fichaje", distancia

    if emp:
        sede_raw = get_sede_value(emp)
        sede_nombre = resolve_lookup_value(sede_raw, sedes_lookup)
        planta_sede = detectar_planta_en_texto(f"{sede_raw} {sede_nombre}")
        if planta_sede != "DESCONOCIDA":
            return planta_sede, "sede_empleado", None

    return "DESCONOCIDA", "sin_detectar", distancia


def calcular_presencia_actual(
    fichajes: List[Dict[str, Any]],
    empleados: List[Dict[str, Any]],
    departamentos_lookup: Dict[str, str],
    sedes_lookup: Dict[str, str],
    plant_coords: Dict[str, Tuple[float, float]],
    tipos_fichaje_lookup: Dict[str, str],
    planta_objetivo: str,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    emp_lookup = build_employee_lookup(empleados)

    rows = []
    for f in fichajes:
        nif = get_fichaje_nif(f)
        fecha = parse_datetime(f.get("fecha"))
        direccion = normalize_text(f.get("direccion"))

        if not nif or fecha is None or pd.isna(fecha) or not direccion:
            continue

        emp = emp_lookup.get(nif, {})
        planta, fuente, distancia = detectar_planta_fichaje(
            fichaje=f,
            emp=emp,
            sedes_lookup=sedes_lookup,
            plant_coords=plant_coords,
            tipos_fichaje_lookup=tipos_fichaje_lookup,
        )

        lat, lon = extract_lat_lon(f)
        tipo_raw = get_tipo_fichaje_value(f)
        tipo_nombre = resolve_lookup_value(tipo_raw, tipos_fichaje_lookup)

        rows.append({
            "nif": nif,
            "fecha": fecha,
            "direccion": direccion,
            "planta_fichaje": planta,
            "fuente_planta": fuente,
            "distancia_m": distancia,
            "tipo": tipo_raw,
            "tipo_nombre": tipo_nombre,
            "centro": f.get("centro", ""),
            "ubicacion": f.get("ubicacion", ""),
            "terminal": f.get("terminal", ""),
            "latitud": lat,
            "longitud": lon,
            "raw": f,
        })

    if not rows:
        return pd.DataFrame(), pd.DataFrame()

    df = pd.DataFrame(rows)
    df = df.sort_values(["nif", "fecha"], ascending=[True, True])
    ultimos = df.groupby("nif", as_index=False).tail(1).copy()

    now_naive = pd.Timestamp.now()
    output_rows = []
    debug_rows = []

    for _, row in ultimos.iterrows():
        nif = row["nif"]
        emp = emp_lookup.get(nif, {})
        direccion = row["direccion"]
        planta_actual = row["planta_fichaje"]
        fecha_entrada = row["fecha"]

        nombre = human_full_name(emp) or nif
        num_empleado = get_num_empleado(emp)

        departamento_raw = get_departamento_value(emp)
        departamento = resolve_lookup_value(departamento_raw, departamentos_lookup)

        sede_raw = get_sede_value(emp)
        sede_ficha = resolve_lookup_value(sede_raw, sedes_lookup)

        aviso = ""
        if direccion == "ENTRADA":
            try:
                horas_abierto = round((now_naive - fecha_entrada).total_seconds() / 3600, 2)
                if horas_abierto > MAX_OPEN_SHIFT_HOURS_WARNING:
                    aviso = f"Entrada abierta > {MAX_OPEN_SHIFT_HOURS_WARNING}h"
            except Exception:
                pass

        distancia = row.get("distancia_m")
        if pd.notna(distancia) and distancia is not None:
            distancia_texto = f"{round(float(distancia), 0)} m"
        else:
            distancia_texto = ""

        debug_rows.append({
            "Empleado": nombre,
            "NIF": nif,
            "Nº empleado": num_empleado,
            "Último movimiento": direccion.lower(),
            "Planta detectada": planta_actual,
            "Fuente planta": row.get("fuente_planta", ""),
            "Tipo": row.get("tipo", ""),
            "Tipo nombre": row.get("tipo_nombre", ""),
            "Distancia GPS": distancia_texto,
            "Sede ficha": sede_ficha,
            "Departamento": departamento,
            "Centro": row.get("centro", ""),
            "Ubicación": row.get("ubicacion", ""),
            "Terminal": row.get("terminal", ""),
            "Latitud": row.get("latitud", ""),
            "Longitud": row.get("longitud", ""),
            "Aviso": aviso,
        })

        if direccion == "ENTRADA" and planta_actual == planta_objetivo:
            output_rows.append({
                "Empleado": nombre,
                "Nº empleado": num_empleado,
                "Departamento": departamento,
            })

    df_presencia = pd.DataFrame(output_rows)
    df_debug = pd.DataFrame(debug_rows)

    if not df_presencia.empty:
        df_presencia = df_presencia.sort_values(["Empleado"], ascending=True)

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


def main() -> None:
    planta_objetivo = normalize_text(PLANTA_OBJETIVO)
    if planta_objetivo not in PLANTAS:
        st.error(f"PLANTA_OBJETIVO inválida: {PLANTA_OBJETIVO}. Usa P2 o P3.")
        st.stop()

    render_header(planta_objetivo)

    today = now_madrid().normalize()
    fecha_hasta = today
    fecha_desde = today - pd.Timedelta(days=NOCTURNAL_LOOKBACK_DAYS)

    desde_str = date_str(fecha_desde)
    hasta_str = date_str(fecha_hasta)

    refresh = st.button("Actualizar ahora", use_container_width=False)

    if refresh:
        try:
            with st.spinner("Consultando CRECE Personas..."):
                client = CreceClient()

                empleados = client.export_empleados()
                departamentos = client.export_departamentos()
                sedes = client.export_sedes()
                tipos_fichaje = client.export_tipos_fichaje()

                departamentos_lookup = build_id_name_lookup(departamentos)
                sedes_lookup = build_id_name_lookup(sedes)
                tipos_fichaje_lookup = build_id_name_lookup(tipos_fichaje)
                plant_coords = build_plant_coords_from_sedes(sedes)

                fichajes, modo_consulta = client.export_fichajes_con_fallback(
                    desde_str,
                    hasta_str,
                    empleados,
                    order="asc",
                )

                df_presencia, df_debug = calcular_presencia_actual(
                    fichajes=fichajes,
                    empleados=empleados,
                    departamentos_lookup=departamentos_lookup,
                    sedes_lookup=sedes_lookup,
                    plant_coords=plant_coords,
                    tipos_fichaje_lookup=tipos_fichaje_lookup,
                    planta_objetivo=planta_objetivo,
                )

            st.session_state["presencia_resultado"] = {
                "df_presencia": df_presencia,
                "df_debug": df_debug,
                "updated_at": now_madrid(),
                "modo_consulta": modo_consulta,
                "plant_coords": plant_coords,
                "tipos_fichaje_lookup": tipos_fichaje_lookup,
            }

        except requests.HTTPError as exc:
            st.error("CRECE Personas ha devuelto un error HTTP.")
            st.exception(exc)
            return
        except Exception as exc:
            st.error("No se pudo calcular la presencia actual.")
            st.exception(exc)
            return

    resultado = st.session_state.get("presencia_resultado")
    if not resultado:
        return

    df_presencia = resultado["df_presencia"]
    df_debug = resultado["df_debug"]
    updated_at = resultado["updated_at"]
    plant_coords = resultado.get("plant_coords", {})

    total = 0 if df_presencia.empty else len(df_presencia)
    render_status_cards(total, updated_at)

    st.divider()

    if df_presencia.empty:
        st.success(f"No hay empleados trabajando ahora mismo en {PLANTAS[planta_objetivo]['nombre']}.")
    else:
        visible_cols = ["Empleado", "Nº empleado", "Departamento"]
        existing_cols = [c for c in visible_cols if c in df_presencia.columns]
        st.dataframe(
            df_presencia[existing_cols],
            use_container_width=True,
            hide_index=True,
        )

    with st.expander("Validación técnica del cálculo", expanded=False):
        st.write("Esta tabla sirve para comprobar el último movimiento detectado por empleado.")
        if not plant_coords:
            st.warning(
                "No se han encontrado coordenadas de P2/P3 en /exportacion/sedes ni en PLANT_COORDS_MANUAL. "
                "Los fichajes móviles sin terminal no podrán asignarse por GPS."
            )
        else:
            st.caption(f"Coordenadas de planta usadas: {plant_coords}")
            st.caption(f"Tipos de fichaje cargados: {resultado.get('tipos_fichaje_lookup', {})}")

        if df_debug.empty:
            st.warning("No hay fichajes válidos en la ventana consultada.")
        else:
            st.dataframe(df_debug, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
