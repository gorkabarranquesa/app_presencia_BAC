"""
APP PRESENCIA ACTUAL POR PLANTA - CRECE PERSONAS

Objetivo:
- Mostrar qué empleados están trabajando ahora mismo en una planta concreta.
- No usa filtros visibles.
- La planta se calcula por el último fichaje abierto.
- Si el fichaje no trae centro/ubicación/terminal identificable, se usa como fallback la sede asignada del empleado.
- Preparada para turnos nocturnos: consulta desde ayer hasta hoy.

Uso recomendado:
1) Copiar este archivo como:
   - app_presencia_p2.py
   - app_presencia_p3.py

2) En cada archivo cambiar PLANTA_OBJETIVO:
   - P2 para COMARCA II
   - P3 para UHARTE

Secrets esperados en .streamlit/secrets.toml:
API_TOKEN = "..."
APP_KEY_B64 = "..."
CRECE_BASE_URL = "https://sincronizaciones.crecepersonas.es/api"
"""

from __future__ import annotations

import base64
import json
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

# Aviso interno en la validación técnica si queda una entrada abierta demasiadas horas.
MAX_OPEN_SHIFT_HOURS_WARNING = 18


# ============================================================
# UTILIDADES GENERALES
# ============================================================

def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    """Obtiene un valor desde st.secrets o variables de entorno."""
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
    """CRECE suele devolver datos serializados PHP. Dejamos fallback a JSON por seguridad."""
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
    """Desencripta payload CRECE: base64(JSON{iv,value,mac}) + AES-256-CBC."""
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
    """Normaliza respuestas de CRECE a lista de diccionarios."""
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
        """
        Intenta traer todos los fichajes del periodo.

        El manual documenta el parámetro nif. En algunas instalaciones CRECE permite no enviarlo
        para devolver todos los fichajes; si no lo permite, usamos fallback por empleado.
        """
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
        return self.post_export(
            "exportacion/empleados",
            {
                "solo_nif": 0,
            },
        )

    def export_departamentos(self) -> List[Dict[str, Any]]:
        return self.get_export("exportacion/departamentos")

    def export_sedes(self) -> List[Dict[str, Any]]:
        return self.get_export("exportacion/sedes")

    def export_fichajes_con_fallback(
        self,
        fecha_inicio: str,
        fecha_fin: str,
        empleados: List[Dict[str, Any]],
        order: str = "asc",
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Devuelve fichajes y modo de consulta:
        - "global": CRECE aceptó consulta sin NIF.
        - "por_empleado": CRECE obligó a consultar por NIF.
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


def detectar_planta_fichaje(
    fichaje: Dict[str, Any],
    emp: Optional[Dict[str, Any]] = None,
    sede_lookup: Optional[Dict[str, str]] = None,
) -> Tuple[str, str]:
    """
    Detecta P2/P3.

    Prioridad:
    1) Datos del fichaje: centro, ubicación o terminal.
    2) Fallback: sede asignada del empleado.

    Devuelve:
    - planta detectada
    - fuente usada para detectarla
    """
    text_fichaje = " ".join([
        str(fichaje.get("centro", "")),
        str(fichaje.get("ubicacion", "")),
        str(fichaje.get("terminal", "")),
    ])

    planta = detectar_planta_en_texto(text_fichaje)
    if planta != "DESCONOCIDA":
        return planta, "fichaje"

    if emp:
        sede_raw = get_sede_value(emp)
        sede_nombre = resolve_lookup_value(sede_raw, sede_lookup or {})
        planta = detectar_planta_en_texto(f"{sede_raw} {sede_nombre}")
        if planta != "DESCONOCIDA":
            return planta, "sede_empleado"

    return "DESCONOCIDA", "sin_detectar"


def build_employee_lookup(empleados: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for emp in empleados:
        nif = get_empleado_nif(emp)
        if nif:
            lookup[nif] = emp
    return lookup


def calcular_presencia_actual(
    fichajes: List[Dict[str, Any]],
    empleados: List[Dict[str, Any]],
    departamentos_lookup: Dict[str, str],
    sedes_lookup: Dict[str, str],
    planta_objetivo: str,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Devuelve:
    - df_presencia: empleados actualmente dentro de la planta objetivo.
    - df_debug: últimos fichajes de todos los empleados, útil para validar si algo no cuadra.
    """
    emp_lookup = build_employee_lookup(empleados)

    rows = []
    for f in fichajes:
        nif = get_fichaje_nif(f)
        fecha = parse_datetime(f.get("fecha"))
        direccion = normalize_text(f.get("direccion"))

        if not nif or fecha is None or pd.isna(fecha) or not direccion:
            continue

        emp = emp_lookup.get(nif, {})
        planta_fichaje, fuente_planta = detectar_planta_fichaje(f, emp, sedes_lookup)

        rows.append({
            "nif": nif,
            "fecha": fecha,
            "direccion": direccion,
            "planta_fichaje": planta_fichaje,
            "fuente_planta": fuente_planta,
            "centro": f.get("centro", ""),
            "ubicacion": f.get("ubicacion", ""),
            "terminal": f.get("terminal", ""),
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

        debug_rows.append({
            "Empleado": nombre,
            "NIF": nif,
            "Nº empleado": num_empleado,
            "Último movimiento": direccion.lower(),
            "Planta detectada": planta_actual,
            "Fuente planta": row.get("fuente_planta", ""),
            "Sede ficha": sede_ficha,
            "Departamento": departamento,
            "Centro": row.get("centro", ""),
            "Ubicación": row.get("ubicacion", ""),
            "Terminal": row.get("terminal", ""),
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

                departamentos_lookup = build_id_name_lookup(departamentos)
                sedes_lookup = build_id_name_lookup(sedes)

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
                    planta_objetivo=planta_objetivo,
                )

            st.session_state["presencia_resultado"] = {
                "df_presencia": df_presencia,
                "df_debug": df_debug,
                "updated_at": now_madrid(),
                "modo_consulta": modo_consulta,
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
        if df_debug.empty:
            st.warning("No hay fichajes válidos en la ventana consultada.")
        else:
            st.dataframe(df_debug, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
