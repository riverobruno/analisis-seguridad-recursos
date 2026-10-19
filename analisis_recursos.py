
import argparse
import base64
import json
import os
import re
import socket
import ipaddress
import stat
import hashlib
import zipfile
import zlib
import contextlib
import io
import sys
import threading
import time
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from functools import wraps
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from datetime import datetime, timezone


# ==========================================
# CONFIGURACIÓN VIRUSTOTAL
# ==========================================

def cargar_configuracion_env(path=None):
    """Read only known key/value pairs from a local .env; never execute or expand content."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            for line in stream:
                match = re.match(r"^\s*(VT_API_KEY|URLSCAN_API_KEY)\s*=\s*(.*?)\s*$", line)
                if not match:
                    continue
                value = match.group(2)
                if value and value[:1] in "\"'":
                    quote_char = value[0]
                    closing = value.find(quote_char, 1)
                    if closing >= 0:
                        value = value[1:closing]
                else:
                    value = value.split("#", 1)[0].strip()
                values[match.group(1)] = value
    except OSError:
        pass
    return {key: os.environ.get(key, values.get(key, "")) for key in ("VT_API_KEY", "URLSCAN_API_KEY")}


_CONFIG = {key: os.environ.get(key, "") for key in ("VT_API_KEY", "URLSCAN_API_KEY")}
VT_API_KEY = _CONFIG["VT_API_KEY"]
VT_BASE_URL = "https://www.virustotal.com/api/v3"
MAX_URLS = 5  # Límite de URLs derivadas desde un EML
MAX_DOMAIN_LOOKUPS = 5
MAX_VT_REQUESTS = 4
MAX_INTEL_BYTES = 2 * 1024 * 1024
LOOKUP_TIMEOUT = 10
CRT_SH_URL = "https://crt.sh/"
WHOIS_IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43
WHOIS_MAX_BYTES = 65536
VT_WINDOW_SECONDS = 60
_vt_lock = threading.Lock()
_vt_request_times = []
MAX_LOCAL_FILE_BYTES = 25 * 1024 * 1024
MAX_DKIM_SIGNATURES = 10
MAX_AUTHENTICATION_RESULTS_HEADERS = 20
MAX_AUTHENTICATION_RESULTS_BYTES = 4096
MAX_EML_ATTACHMENTS = 20
MAX_EML_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_OOXML_MEMBER_BYTES = 2 * 1024 * 1024
MAX_MACRO_ZIP_ENTRIES = 1000
MAX_MACRO_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
MAX_MACRO_ZIP_MEMBER_BYTES = 25 * 1024 * 1024
MAX_MACRO_ZIP_RATIO = 1000
MAX_DECODE_DEPTH = 3
MAX_DECODE_BYTES = 1024 * 1024
MAX_EML_DECODE_CANDIDATES = 20
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
URLSCAN_MAX_RESPONSE_BYTES = 2 *  1024 * 1024
# Policy: malicious-engine consensus is per resource, never summed across resources.
MALICIOUS_CONSENSUS_THRESHOLD = 2
ESTABLISHED_DOMAIN_DAYS = 180
VERDICT_CLEAN = "LIMPIO / LEGÍTIMO"
VERDICT_SUSPICIOUS = "SOSPECHOSO"
VERDICT_INFECTED = "INFECTADO"


def _notificar_consulta(servicio):
    """Show provider progress on stderr without changing the structured report."""
    print(f"CONSULTANDO: {servicio}", file=sys.stderr, flush=True)


_vt_analysis_depth = 0


@contextlib.contextmanager
def _vt_analysis_context():
    """Share one bounded VirusTotal cache across nested resource analyses."""
    global _vt_analysis_depth
    root = _vt_analysis_depth == 0
    if root:
        _vt_cache.clear()
    _vt_analysis_depth += 1
    try:
        yield
    finally:
        _vt_analysis_depth -= 1


def _analysis_entrypoint(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _vt_analysis_context():
            return function(*args, **kwargs)
    return wrapped


# ==========================================
# EXTRACCIÓN DE ENLACES HTML
# ==========================================

class ExtractorEnlaces(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in ("a", "form"):
            atributos = dict(attrs)
            href = atributos.get("action" if tag.lower() == "form" else "href", "") or ""
            if href.lower().startswith(("http://", "https://")):
                self.urls.append(href)


# ==========================================
# VIRUSTOTAL
# ==========================================

def consultar_virustotal(url):
    """
    Consulta un informe de URL existente en VirusTotal.
    No envía la URL para iniciar un análisis nuevo.
    """

    if url_contiene_secretos(url):
        return {"error": "Consulta remota omitida: URL con credenciales o parámetros sensibles"}
    cache_key = ("url", _normalizar_url_cache_key(url))
    if cache_key in _vt_cache:
        return _vt_cache[cache_key]
    if not VT_API_KEY:
        return {"error": "API key de VirusTotal no configurada"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        datos = _provider_json(
            endpoint,
            {"x-apikey": VT_API_KEY, "accept": "application/json"},
        )

        attributes = datos["data"]["attributes"]
        if not isinstance(attributes, dict) or not validar_informe_vt(attributes):
            result = _service_error("VirusTotal", "Informe de VirusTotal incompleto o no válido")
        else:
            result = attributes

    except HTTPError as error:
        if error.code == 404:
            result = {"error": "URL sin informe disponible en VirusTotal"}
        elif error.code == 401:
            result = _service_error("VirusTotal", "API key inválida o no autorizada")
        elif error.code == 403:
            result = _service_error("VirusTotal", "Acceso denegado por VirusTotal")
        elif error.code == 429:
            result = _service_error("VirusTotal", "Límite de consultas de la API alcanzado")
        else:
            result = _service_error("VirusTotal", f"Error HTTP {error.code}")

    except _LocalResponseLimit:
        result = _service_error("VirusTotal", "Respuesta de VirusTotal excede el límite local")
    except (URLError, TimeoutError):
        result = _service_error("VirusTotal", "Error de conexión con VirusTotal")

    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        result = _service_error("VirusTotal", "Respuesta de VirusTotal no válida")
    _vt_cache[cache_key] = result
    return result



def consultar_virustotal_archivo(sha256):
    """Fetch an existing VirusTotal file report by SHA-256; never upload a file."""
    sha256 = _normalizar_sha256(sha256)
    cache_key = ("file", sha256)
    if cache_key in _vt_cache:
        return _vt_cache[cache_key]
    if not VT_API_KEY:
        return {"error": "API key de VirusTotal no configurada"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}
    return _consultar_virustotal_archivo_con_cuota(sha256)


def _consultar_virustotal_archivo_con_cuota(sha256):
    sha256 = _normalizar_sha256(sha256)
    cache_key = ("file", sha256)
    if cache_key in _vt_cache:
        return _vt_cache[cache_key]
    try:
        data = _provider_json(
            f"{VT_BASE_URL}/files/{sha256}",
            {"x-apikey": VT_API_KEY, "accept": "application/json"},
        )
        attributes = data["data"]["attributes"]
        if not isinstance(attributes, dict) or not validar_informe_vt(attributes):
            result = _service_error("VirusTotal", "Informe de VirusTotal incompleto o no válido")
        else:
            result = attributes
    except _LocalResponseLimit:
        result = _service_error("VirusTotal", "Respuesta de VirusTotal excede el límite local")
    except HTTPError as error:
        messages = {404: "Archivo sin informe disponible en VirusTotal", 401: "API key inválida o no autorizada", 403: "Acceso denegado por VirusTotal", 429: "Límite de consultas de la API alcanzado"}
        result = {"error": messages.get(error.code, f"Error HTTP {error.code}")} if error.code == 404 else _service_error("VirusTotal", messages.get(error.code, f"Error HTTP {error.code}"))
    except (URLError, TimeoutError, OSError):
        result = _service_error("VirusTotal", "Error de conexión con VirusTotal")
    except (ValueError, KeyError, TypeError):
        result = _service_error("VirusTotal", "Respuesta de VirusTotal no válida")
    _vt_cache[cache_key] = result
    return result



def validar_url(url):
    try:
        parsed = urlparse(url)
        parsed.port  # Force validation of malformed/out-of-range ports.
        return parsed.scheme.lower() in ("http", "https") and extraer_dominio(url) is not None
    except (ValueError, UnicodeError):
        return False


def url_contiene_secretos(url):
    """Conservatively block remote lookups for URLs containing sensitive components."""
    try:
        parsed = urlparse(url)
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            return True
        return "?" in url.split("#", 1)[0]
    except (ValueError, UnicodeError):
        return True


def validar_informe_vt(attributes):
    """Require coherent VT stats and engine results before treating a report as evidence."""
    stats = attributes.get("last_analysis_stats")
    results = attributes.get("last_analysis_results")
    required_categories = ("malicious", "suspicious", "harmless", "undetected", "timeout")
    if not isinstance(stats, dict) or not isinstance(results, dict) or not results:
        return False
    if any(category not in stats for category in required_categories):
        return False
    if any(not isinstance(k, str) or isinstance(v, bool) or not isinstance(v, int) or v < 0 for k, v in stats.items()):
        return False
    for field in ("last_analysis_date", "first_submission_date"):
        value = attributes.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            return False
    if any(not isinstance(k, str) or not isinstance(v, dict) or v.get("category") not in ("malicious", "suspicious", "harmless", "undetected", "timeout", "confirmed-timeout", "failure", "type-unsupported") for k, v in results.items()):
        return False
    for category in required_categories:
        observed = sum(item.get("category") == category for item in results.values())
        if stats[category] != observed:
            return False
    return True


@contextlib.contextmanager
def abrir_archivo_seguro(path):
    """Open a bounded regular file without following links where the OS supports it."""
    path = os.fspath(path)
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("El archivo debe ser regular y no ser un enlace")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = os.lstat(path)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("El archivo cambió durante su apertura")
        if getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError("No se admiten puntos de reanálisis")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def criterio(status, evidence):
    return {"status": status, "evidence": evidence}


def combinar_criterios(checks, empty="na"):
    checks = [check for check in checks if isinstance(check, dict)]
    states = {check.get("status", "unknown") for check in checks}
    state = "fail" if "fail" in states else "unknown" if "unknown" in states else "pass" if "pass" in states else empty
    return criterio(state, "; ".join(str(check.get("evidence", "sin evidencia")) for check in checks) or "no aplica a este recurso")


def criterio_detecciones(report):
    if not isinstance(report, dict) or not validar_informe_vt(report):
        return criterio("unknown", f"VirusTotal no disponible: {report.get('error', 'informe inválido') if isinstance(report, dict) else 'sin informe'}")
    stats = report["last_analysis_stats"]
    count = stats["malicious"] + stats["suspicious"]
    usable = sum(item.get("category") in ("harmless", "undetected") for item in report["last_analysis_results"].values())
    if not count and not usable:
        return criterio("unknown", "VirusTotal: sin detecciones utilizables; motores incompletos")
    return criterio("fail" if count else "pass", f"VirusTotal: {stats['malicious']} maliciosos, {stats['suspicious']} sospechosos; motores={len(report['last_analysis_results'])}")


def _community_reputation_check(report):
    reputation = report.get("reputation")
    numeric = isinstance(reputation, int) and not isinstance(reputation, bool)
    state = "fail" if numeric and reputation < 0 else "pass" if numeric and reputation > 0 else "unknown"
    return criterio(state, f"reputación VT={reputation if numeric else 'desconocida'}")


def evaluar_dominio(domain, report, registry):
    report = report if isinstance(report, dict) else {}
    registry = registry if isinstance(registry, dict) else {}
    detection = criterio_detecciones(report)
    reputation = report.get("reputation")
    positive_reputation = isinstance(reputation, int) and not isinstance(reputation, bool) and reputation > 0
    negative = isinstance(reputation, int) and not isinstance(reputation, bool) and reputation < 0
    age = None
    age_value = registry.get("registration_age_days")
    if isinstance(age_value, int) and not isinstance(age_value, bool) and age_value >= 0:
        age = age_value
    try:
        if age is None:
            registration = registry.get("registration_date")
            created = datetime.fromisoformat(registration.replace("Z", "+00:00")) if isinstance(registration, str) else None
            if created is None:
                raise ValueError("WHOIS registration date unavailable")
            created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            if age < 0:
                age = None
    except (ValueError, TypeError, AttributeError):
        pass
    age_ok = age is not None and age >= ESTABLISHED_DOMAIN_DAYS
    state = "fail" if detection["status"] == "fail" or negative else "pass" if detection["status"] == "pass" and age_ok and positive_reputation else "unknown"
    age_detail = f"{age} días" if age is not None else "desconocida"
    reputation_detail = reputation if isinstance(reputation, int) and not isinstance(reputation, bool) else "desconocida"
    return criterio(state, f"Dominio {domain}: detecciones={detection['status']}; edad={age_detail}; reputación={reputation_detail}")


def evaluar_comportamiento_url(url, attributes, scan):
    attributes = attributes if isinstance(attributes, dict) else {}
    scan = scan if isinstance(scan, dict) else {}
    source = extraer_dominio(url)
    targets = []
    chain = attributes.get("redirection_chain", [])
    if isinstance(chain, list):
        targets.extend(item.get("url") if isinstance(item, dict) else item for item in chain)
    if isinstance(attributes.get("last_final_url"), str):
        targets.append(attributes["last_final_url"])
    vt_external = any(isinstance(target, str) and extraer_dominio(target) not in (None, source) for target in targets)
    vt_phishing = validar_informe_vt(attributes) and any(item.get("category") == "malicious" and re.search("phish", str(item.get("result", "")), re.I) for item in attributes["last_analysis_results"].values())
    redirects = scan.get("redirects", [])
    scan_targets = list(redirects) if isinstance(redirects, list) else []
    scan_targets.append(scan.get("final_url"))
    scan_external = any(isinstance(target, str) and extraer_dominio(target) not in (None, source) for target in scan_targets)
    external = vt_external or scan_external
    credential = scan.get("credentials", "unknown")
    scan_phishing = scan.get("phishing") is True
    credential_risk = credential == "password_input"
    confirmed = bool(vt_phishing and vt_external) or bool(scan_phishing and (scan_external or credential_risk))
    risk = confirmed or scan.get("malicious") is True or scan_phishing or credential_risk
    observed = bool(scan.get("behavior_observed") and scan.get("uuid") and not scan.get("reason"))
    normal = bool(observed and scan.get("malicious") is False and scan.get("phishing") is False and credential == "not_observed" and not external and extraer_dominio(scan.get("final_url", "")) == source)
    state = "fail" if risk or credential == "password_input" or external else "pass" if normal else "unknown"
    detail = f"urlscan: observado={observed}, malicioso={scan.get('malicious', 'desconocido')}, phishing={scan.get('phishing', 'desconocido')}, credenciales={credential}, redirección externa={external}; VT phishing malicioso+redirección externa={bool(vt_phishing and vt_external)}"
    return {"behavior_check": criterio(state, detail), "confirmed_phishing": confirmed,
            "high_phishing_risk": confirmed, "concrete_causes": [detail] if risk else []}


def evaluar_evidencia(evidencia):
    """Return a conservative resource-aware triage verdict from normalized evidence."""
    if not isinstance(evidencia, dict):
        return VERDICT_SUSPICIOUS, ["evidencia no disponible"]

    def _count(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    raw_resources = evidencia.get("resources", [])
    if not isinstance(raw_resources, (list, tuple, set)):
        raw_resources = []
    resources = [evidencia]
    resources.extend(resource for resource in raw_resources if isinstance(resource, dict))
    raw_auth_failures = evidencia.get("auth_failed_checks", [])
    if not isinstance(raw_auth_failures, (list, tuple, set)):
        raw_auth_failures = [raw_auth_failures]
    auth_failed_checks = sorted({str(check).upper() for check in raw_auth_failures
                                 if str(check).upper() in {"SPF", "DKIM", "DMARC"}})
    if evidencia.get("resource_type") == "eml" and len(auth_failed_checks) >= 2:
        return VERDICT_INFECTED, ["fallos múltiples de autenticación: " + ", ".join(auth_failed_checks)]

    detections = False
    for resource in resources:
        malicious = _count(resource.get("malicious", 0))
        suspicious = _count(resource.get("suspicious", 0))
        detections = detections or bool(malicious or suspicious)
        if malicious >= MALICIOUS_CONSENSUS_THRESHOLD:
            return VERDICT_INFECTED, ["múltiples detecciones maliciosas en el mismo recurso"]
        if resource.get("executable") is True and resource.get("report_available") is True and malicious > 0:
            return VERDICT_INFECTED, ["hash de ejecutable reportado como malicioso"]
        if resource.get("confirmed_phishing") or resource.get("high_phishing_risk"):
            return VERDICT_INFECTED, ["phishing corroborado por redirección o credenciales"]

    checks = evidencia.get("criteria", {})
    checks = checks if isinstance(checks, dict) else {}
    optional = evidencia.get("optional_criteria", {})
    optional = optional if isinstance(optional, dict) else {}
    failed_keys = [key for key, check in list(checks.items()) + list(optional.items())
                   if isinstance(check, dict) and check.get("status") == "fail"]
    if detections:
        return VERDICT_SUSPICIOUS, ["detecciones aisladas o mixtas en la evidencia"]
    if auth_failed_checks or evidencia.get("auth_failure"):
        return VERDICT_SUSPICIOUS, ["fallo de autenticación"]
    if evidencia.get("mixed"):
        return VERDICT_SUSPICIOUS, ["identidad o evidencia de origen incoherente"]
    if failed_keys:
        return VERDICT_SUSPICIOUS, ["criterios con resultado desfavorable: " + ", ".join(failed_keys[:3])]
    local_inspection = evidencia.get("local_inspection")
    if isinstance(local_inspection, dict) and local_inspection.get("status") == "unknown":
        return VERDICT_SUSPICIOUS, ["inspección local incompleta"]

    kind = evidencia.get("resource_type")
    status = {key: value.get("status") for key, value in checks.items() if isinstance(value, dict)}
    if kind == "eml":
        clean = (status.get("authentication") == "pass" and status.get("domain") == "pass"
                 and status.get("detections") == "pass" and status.get("behavior") == "pass")
    elif kind == "url":
        clean = (status.get("authentication") == "na" and status.get("domain") == "pass"
                 and status.get("detections") == "pass" and status.get("behavior") == "na")
    elif kind == "file":
        clean = (status.get("authentication") == "na" and status.get("domain") == "na"
                 and status.get("detections") == "pass" and status.get("behavior") == "pass")
    else:
        clean = False
    if clean:
        return VERDICT_CLEAN, ["criterios aplicables limpios y completos"]
    expected = ("authentication", "domain", "detections", "behavior")
    unknown = [key for key in expected if status.get(key) in (None, "unknown")]
    if unknown:
        return VERDICT_SUSPICIOUS, ["evidencia no verificada: " + ", ".join(unknown)]
    return VERDICT_SUSPICIOUS, ["criterios aplicables incompletos"]


class _LocalResponseLimit(ValueError):
    """A local safety bound, not evidence of an unavailable provider."""


def _service_error(service, reason, **fields):
    """Attach diagnostics only at a contacted provider's failure boundary."""
    return dict(fields, error=reason, service_issues=[{"service": service, "reason": reason}])


def _service_issues(result):
    return result.get("service_issues", []) if isinstance(result, dict) else getattr(result, "service_issues", [])


def _dns_transport_error(error):
    return isinstance(error, (TimeoutError, OSError)) or type(error).__name__ in ("Timeout", "LifetimeTimeout", "NoNameservers")


class _AuthResult(tuple):
    """Keep the existing two-value authentication API with provider diagnostics."""
    def __new__(cls, status, reason, issues):
        result = super().__new__(cls, (status, reason))
        result.service_issues = issues
        return result


def _compact_report_value(value, limit=220):
    """Render report values without turning provider data into a narrative."""
    if isinstance(value, dict):
        pieces = []
        for key, item in value.items():
            if isinstance(item, (dict, list, tuple)):
                item = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            pieces.append(f"{key}={item}")
        value = "; ".join(pieces)
    elif isinstance(value, (list, tuple, set)):
        value = json.dumps(list(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    safe = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    safe = re.sub(r"\s+", " ", safe).strip()
    return safe[:limit] or "desconocido"


def _meaningful_report_value(value):
    """Return a display-only copy with empty containers removed."""
    if value is None:
        return None
    if isinstance(value, dict):
        meaningful = {}
        for key, item in value.items():
            item = _meaningful_report_value(item)
            if item is not None:
                meaningful[key] = item
        return meaningful or None
    if isinstance(value, (list, tuple, set)):
        values = sorted(value, key=lambda item: _compact_report_value(item)) if isinstance(value, set) else value
        meaningful = []
        for item in values:
            item = _meaningful_report_value(item)
            if item is not None:
                meaningful.append(item)
        return meaningful or None
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _report_value_is_container(value):
    return isinstance(value, (dict, list, tuple, set))


_REPORT_FIELD_LABELS = {
    "report_available": "Informe disponible",
    "reputation": "Reputación",
    "sha256": "SHA-256",
    "hash": "Hash",
    "domain": "Dominio",
    "domains": "Dominios",
    "url": "URL",
    "urls": "URLs",
    "registration": "Registro",
    "registration_date": "Fecha de registro",
    "registration_age_days": "Antigüedad del registro (días)",
    "certificate": "Certificado",
    "certificates": "Certificados",
    "certificate_chain": "Cadena de certificados",
    "file": "Archivo",
    "files": "Archivos",
    "script": "Script",
    "scripts": "Scripts",
    "script_status": "Estado del script",
    "macro": "Macro",
    "macros": "Macros",
    "macro_status": "Estado de macros",
    "relationship": "Relación",
    "relationships": "Relaciones",
    "last_serving_ip_address": "Última dirección IP de servicio",
    "service": "Servicio",
    "service_issues": "Incidencias del servicio",
    "reason": "Motivo",
    "status": "Estado",
    "report": "Informe",
    "source": "Origen",
    "check": "Comprobación",
    "result": "Resultado",
    "category": "Categoría",
    "error": "Error",
    "name": "Nombre",
    "names": "Nombres",
    "size": "Tamaño",
    "type": "Tipo",
    "type_basis": "Base del tipo",
    "extension_type": "Tipo de extensión",
    "mime": "Tipo MIME",
    "requirements": "Requisitos",
    "count": "Cantidad",
    "last_analysis_stats": "Estadísticas del último análisis",
    "last_analysis_results": "Resultados del último análisis",
    "first_submission_date": "Fecha del primer envío",
    "first_seen": "Visto por primera vez",
    "last_analysis_date": "Fecha del último análisis",
    "authentication": "Autenticación",
    "identities": "Identidades",
    "origin": "Origen",
    "virustotal": "VirusTotal",
    "urlscan": "URLscan",
    "whois": "WHOIS",
    "crt_sh": "Certificados CRT.SH",
    "screenshot": "Captura",
    "final_url": "URL final",
    "last_final_url": "Última URL final",
    "ip": "IP",
    "ip_addresses": "Direcciones IP",
    "country": "País",
    "redirected": "Redirigido",
    "redirects": "Redirecciones",
    "redirection_chain": "Cadena de redirecciones",
    "credentials": "Credenciales",
    "behavior_observed": "Comportamiento observado",
    "server": "Servidor",
    "registrar": "Registrador",
    "nameservers": "Servidores de nombres",
    "not_before": "Válido desde",
    "not_after": "Válido hasta",
    "entry_timestamp": "Marca de tiempo de entrada",
    "resource_type": "Tipo de recurso",
    "resources": "Recursos",
    "confirmed_phishing": "Phishing confirmado",
    "high_phishing_risk": "Alto riesgo de phishing",
    "mixed": "Evidencia mixta",
    "executable": "Ejecutable",
    "Authentication-Results": "Authentication-Results",
    "DKIM_cryptographic": "DKIM criptográfico",
    "SPF_independent": "SPF independiente",
    "DMARC_independent": "DMARC independiente",
    "SPF_alignment": "Alineación SPF",
    "DKIM_alignment": "Alineación DKIM",
}

_REPORT_TOKEN_LABELS = {
    "analysis": "análisis",
    "address": "dirección",
    "available": "disponible",
    "behavior": "comportamiento",
    "certificate": "certificado",
    "chain": "cadena",
    "cryptographic": "criptográfico",
    "date": "fecha",
    "description": "descripción",
    "domain": "dominio",
    "entry": "entrada",
    "file": "archivo",
    "final": "final",
    "first": "primer",
    "independent": "independiente",
    "ip": "IP",
    "last": "última",
    "macro": "macro",
    "name": "nombre",
    "observed": "observado",
    "redirect": "redirección",
    "registration": "registro",
    "relationship": "relación",
    "report": "informe",
    "result": "resultado",
    "script": "script",
    "service": "servicio",
    "serving": "servicio",
    "size": "tamaño",
    "source": "origen",
    "status": "estado",
    "submission": "envío",
    "timestamp": "marca de tiempo",
    "type": "tipo",
    "url": "URL",
}

_REPORT_UNAVAILABLE_STATES = {
    "unknown", "unavailable", "desconocido", "desconocida", "no disponible",
    "no disponibles", "not available", "not_available", "pending", "pendiente",
    "not_found", "sin informe", "no verificado", "no verificada", "error", "na", "n/a",
}

_REPORT_AVAILABLE_STATES = {
    "available", "disponible", "pass", "sin_detecciones", "sin detecciones",
    "clean", "malicious", "suspicious", "malicioso", "sospechoso", "fail",
    "consistent", "inconsistent",
}


def _report_field_key(key):
    return key.casefold() if isinstance(key, str) else str(key).casefold()


def _display_report_key(key, value=None):
    """Map report keys to stable Spanish labels without changing evidence data."""
    key_text = _compact_report_value(key, limit=120)
    normalized = _report_field_key(key_text)
    if normalized == "malicious":
        return "Indicador malicioso" if isinstance(value, bool) else "Detecciones maliciosas"
    if normalized == "suspicious":
        return "Indicador sospechoso" if isinstance(value, bool) else "Detecciones sospechosas"
    if normalized == "phishing" and isinstance(value, bool):
        return "Indicador de phishing"
    if key_text in _REPORT_FIELD_LABELS:
        return _REPORT_FIELD_LABELS[key_text]
    label = _REPORT_FIELD_LABELS.get(normalized)
    if label:
        return label
    if "_" not in key_text:
        return key_text
    parts = []
    for token in key_text.split("_"):
        parts.append(_REPORT_TOKEN_LABELS.get(token.casefold(), token))
    label = " ".join(parts).strip()
    return label[:1].upper() + label[1:] if label else key_text


def _report_availability_marker(value):
    if not isinstance(value, dict):
        return None
    report_available = value.get("report_available")
    available = report_available if isinstance(report_available, bool) else None
    for key in ("report", "status"):
        state = value.get(key)
        if not isinstance(state, str):
            continue
        normalized = re.sub(r"\s+", " ", state.strip().casefold())
        if normalized in _REPORT_UNAVAILABLE_STATES:
            return False
        if normalized in _REPORT_AVAILABLE_STATES and available is None:
            available = True
    if available is not None:
        return available
    if value.get("error"):
        return False
    stats = value.get("last_analysis_stats")
    results = value.get("last_analysis_results")
    if isinstance(stats, dict) and isinstance(results, dict) and results:
        return True
    return None


def _report_count_is_available(container, ancestors, context):
    candidates = [container]
    candidates.extend(ancestors)
    evidence = context.get("evidence") if isinstance(context, dict) else None
    if isinstance(evidence, dict):
        candidates.append(evidence)
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, dict) or id(candidate) in seen:
            continue
        seen.add(id(candidate))
        marker = _report_availability_marker(candidate)
        if marker is not None:
            return marker
    return None


def _display_report_scalar(key, value, container, ancestors, context):
    """Format one scalar while preserving canonical evidence statuses."""
    label = _display_report_key(key, value)
    normalized = _report_field_key(key)
    if normalized in ("malicious", "suspicious") and isinstance(value, int) and not isinstance(value, bool):
        if _report_count_is_available(container, ancestors, context) is False:
            return label, "no disponibles"
        if value == 0:
            return label, "ninguna"
        return label, _compact_report_value(value)
    if isinstance(value, bool):
        return label, "sí" if value else "no"
    return label, _compact_report_value(value)


def _print_report_value(value, indent=2, context=None, ancestors=()):
    """Print report values as bounded, deterministic, YAML-like evidence."""
    context = context if isinstance(context, dict) else {}
    prefix = " " * indent
    if isinstance(value, dict):
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            item = _meaningful_report_value(item)
            if item is None:
                continue
            if _report_value_is_container(item):
                key_text = _display_report_key(key, item)
                print(f"{prefix}{key_text}:")
                _print_report_value(item, indent + 2, context=context, ancestors=(value,) + tuple(ancestors))
            else:
                key_text, value_text = _display_report_scalar(key, item, value, ancestors, context)
                print(f"{prefix}{key_text}: {value_text}")
        return
    if isinstance(value, (list, tuple, set)):
        values = sorted(value, key=lambda item: _compact_report_value(item)) if isinstance(value, set) else value
        for item in values:
            item = _meaningful_report_value(item)
            if item is None:
                continue
            if _report_value_is_container(item):
                print(f"{prefix}-")
                _print_report_value(item, indent + 2, context=context, ancestors=ancestors)
            else:
                scalar = "sí" if item is True else "no" if item is False else _compact_report_value(item)
                print(f"{prefix}- {scalar}")
        return
    scalar = "sí" if value is True else "no" if value is False else _compact_report_value(value)
    print(f"{prefix}{scalar}")


def _print_report_section(label, value, evidence=None):
    value = _meaningful_report_value(value)
    if value is None:
        return
    print(f"{label}:")
    _print_report_value(value, context={"section": label, "evidence": evidence})


def _criteria_sort_key(item):
    preferred = ("authentication", "domain", "detections", "behavior")
    key = str(item[0])
    return (0, preferred.index(key)) if key in preferred else (1, key)


def _print_criteria_section(criteria):
    if not isinstance(criteria, dict):
        return
    entries = []
    for key, value in criteria.items():
        value = _meaningful_report_value(value)
        if value is not None:
            entries.append((key, value))
    if not entries:
        return

    print("CRITERIOS:")
    for key, value in sorted(entries, key=_criteria_sort_key):
        key_text = _compact_report_value(key, limit=120)
        if isinstance(value, dict):
            status = value.get("status", "unknown")
            details = dict(value)
            details.pop("status", None)
            if _report_value_is_container(status):
                print(f"  {key_text}:")
                _print_report_value(value, 4)
            else:
                print(f"  {key_text}: {_compact_report_value(status)}")
                details = _meaningful_report_value(details)
                if details is not None:
                    _print_report_value(details, 4)
        elif _report_value_is_container(value):
            print(f"  {key_text}:")
            _print_report_value(value, 4)
        else:
            print(f"  {key_text}: {_compact_report_value(value)}")


def imprimir_veredicto(evidencia):
    """Print only deterministic evidence fields and the established verdict."""
    verdict, reasons = evaluar_evidencia(evidencia)
    print(f"VEREDICTO: {verdict}")
    summary = reasons[0] if reasons else "evidencia insuficiente o no verificada"
    print(f"RESUMEN: {_compact_report_value(summary, limit=180)}")
    report = evidencia.get("report", {}) if isinstance(evidencia, dict) else {}
    sections = (
        ("AUTENTICACION", "authentication"),
        ("IDENTIDADES", "identities"),
        ("ORIGEN", "origin"),
        ("VIRUSTOTAL", "virustotal"),
        ("URLSCAN", "urlscan"),
        ("WHOIS", "whois"),
        ("CRT.SH", "crt_sh"),
        ("ARCHIVO", "file"),
    )
    resource_sections = {
        "eml": {"authentication", "identities", "origin", "virustotal", "urlscan", "whois", "crt_sh", "file"},
        "url": {"virustotal", "urlscan", "whois", "crt_sh"},
        "file": {"virustotal", "file"},
    }
    applicable = resource_sections.get(evidencia.get("resource_type"), set())
    for label, key in sections:
        if key in applicable:
            _print_report_section(label, report.get(key), evidence=evidencia)
    criteria = evidencia.get("criteria", {}) if isinstance(evidencia, dict) else {}
    _print_criteria_section(criteria)
    issues = []
    for item in evidencia.get("service_issues", []) if isinstance(evidencia, dict) else []:
        if isinstance(item, dict) and item.get("service") and item.get("reason"):
            issues.append((str(item["service"]), str(item["reason"])))
    if issues:
        _print_report_section("ESTADO", {service: reason for service, reason in sorted(set(issues))})
    alerts = [str(item) for item in evidencia.get("concrete_causes", []) if item]
    if alerts:
        _print_report_section("ALERTAS", list(dict.fromkeys(alerts))[:2])
    return verdict


def resumen_vt(attributes):
    if "error" in attributes:
        return {"report_available": False, "malicious": 0, "suspicious": 0}
    if not validar_informe_vt(attributes):
        return {"report_available": False, "malicious": 0, "suspicious": 0}
    stats = attributes["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    causes = [f"VirusTotal motor {engine}: {item.get('category')} ({str(item.get('result', 'sin detalle'))[:160]})"
              for engine, item in attributes['last_analysis_results'].items()
              if item.get('category') in ('malicious', 'suspicious')]
    return {"report_available": True, "malicious": malicious, "suspicious": suspicious,
            "concrete_causes": causes}


def _url_relationships(url):
    normalized_url = _normalizar_url_cache_key(url)
    identifier = base64.urlsafe_b64encode(normalized_url.encode()).decode().rstrip('=')
    result = {"relationships": {}, "service_issues": []}
    for relation in ("last_serving_ip_address",):
        related = _relacion_vt("urls", identifier, relation)
        result["relationships"][relation] = related.get("names", [])
        if related.get("error"):
            result["service_issues"].extend(_service_issues(related))
    return result


def _analizar_url_evidencia(url, domain_reports=None, domain_intelligence=None):
    if not validar_url(url):
        raise ValueError("Se requiere una URL HTTP(S) con dominio válido")
    if url_contiene_secretos(url):
        return {
            "resource_type": "url",
            "criteria": {"authentication": criterio("na", "URL"),
                         "domain": criterio("unknown", "URL omitida por privacidad"),
                         "detections": criterio("unknown", "URL omitida por privacidad"),
                         "behavior": criterio("unknown", "URL omitida por privacidad")},
            "optional_criteria": {}, "resources": [], "service_issues": [],
            "concrete_causes": [], "mixed": False,
            "report": {"virustotal": {"url": "omitida"}},
        }
    result = analizar_reputacion(url)
    attributes = result["_report"]
    if isinstance(domain_intelligence, dict):
        domain_result = _domain_intelligence_for_url(url, domain_intelligence)
    else:
        domain_result = analizar_inteligencia_dominio([url], domain_reports=domain_reports)
    domain_result = domain_result if isinstance(domain_result, dict) else {}
    result["service_issues"] = list(_service_issues(domain_result))
    relationships = _url_relationships(url)
    result["service_issues"].extend(relationships.get("service_issues", []))
    result.setdefault("concrete_causes", []).extend(domain_result.get("concrete_causes", []))
    result["mixed"] = domain_result.get("mixed", False)
    result["resources"] = domain_result.get("resources", [])
    if not result["report_available"]:
        result["service_issues"].extend(_service_issues(attributes))
    behavior = analizar_comportamiento_remoto_url(url, attributes)
    result["service_issues"].extend(_service_issues(behavior))
    result["resource_type"] = "url"
    result["confirmed_phishing"] = behavior["confirmed_phishing"]
    result["high_phishing_risk"] = behavior["high_phishing_risk"]
    result.setdefault("concrete_causes", []).extend(behavior["concrete_causes"])
    result["criteria"] = {"authentication": criterio("na", "URL, no correo"),
                           "domain": combinar_criterios(domain_result.get("criteria", []), empty="unknown"),
                           "detections": criterio_detecciones(attributes),
                           "behavior": criterio("na", "URL sin contenido local")}
    result["optional_criteria"] = {"remote_behavior": behavior["behavior_check"],
                                    "community_reputation": _community_reputation_check(attributes)}
    domain_entries = domain_result.get("domains", [])
    whois = [entry.get("whois", {}) for entry in domain_entries]
    crt = [entry.get("crt_sh", {}) for entry in domain_entries]
    domain_report = domain_entries[0].get("virustotal", {}) if domain_entries else {}
    result["report"] = {
        "virustotal": {
            "url": {"status": result.get("status", "desconocido"),
                    "malicious": result.get("malicious", 0),
                    "suspicious": result.get("suspicious", 0),
                    "reputation": attributes.get("reputation", "desconocida")},
            "domain": domain_report,
            "relationships": relationships.get("relationships", {}),
        },
        "urlscan": behavior.get("scan", {"status": "unknown"}),
        "whois": whois,
        "crt_sh": crt,
    }
    return result


@_analysis_entrypoint
def analizar_url(url, emitir=None, domain_reports=None, domain_intelligence=None):
    if emitir is None:
        emitir = _EML_DOMAIN_REPORTS is None
    if domain_reports is None and _EML_DOMAIN_REPORTS is not None:
        domain_reports = _EML_DOMAIN_REPORTS
    if domain_intelligence is None and _EML_DOMAIN_INTELLIGENCE is not None:
        domain_intelligence = _EML_DOMAIN_INTELLIGENCE
    evidence = _analizar_url_evidencia(
        url, domain_reports=domain_reports, domain_intelligence=domain_intelligence,
    )
    return imprimir_veredicto(evidence) if emitir else evidence


def analizar_comportamiento_remoto_url(url, report):
    """Share remote-only behavior reporting for standalone and extracted URLs."""
    scan = {}
    enabled = bool(_urlscan_key())
    if enabled:
        scan = consultar_urlscan_privado(url)
    behavior = evaluar_comportamiento_url(url, report, scan)
    behavior["service_issues"] = _service_issues(scan)
    behavior["scan"] = scan if scan else {"status": "unknown", "reason": "URLscan API key ausente"}
    if not enabled:
        behavior["behavior_check"]["evidence"] = "urlscan sin API key configurada; comportamiento remoto no verificado. " + behavior["behavior_check"]["evidence"]
    elif scan.get("reason"):
        behavior["behavior_check"]["evidence"] = scan["reason"] + ". " + behavior["behavior_check"]["evidence"]
    return behavior


def _urlscan_key():
    """Use the resolved configuration, including explicit empty overrides."""
    return _CONFIG.get("URLSCAN_API_KEY", "").strip()


def _urlscan_dom(scan_id):
    key = _urlscan_key()
    request = Request(f"https://urlscan.io/dom/{scan_id}/", headers={"API-Key": key, "accept": "text/html"})
    with urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
        raw = response.read(URLSCAN_MAX_RESPONSE_BYTES + 1)
    if len(raw) > URLSCAN_MAX_RESPONSE_BYTES:
        raise _LocalResponseLimit("DOM too large")
    return raw.decode("utf-8", errors="replace")


def _urlscan_request(url, data=None):
    key = _urlscan_key()
    request = Request(url, data=data, headers={"accept": "application/json", "API-Key": key, "Content-Type": "application/json"}, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
        raw = response.read(URLSCAN_MAX_RESPONSE_BYTES + 1)
    if len(raw) > URLSCAN_MAX_RESPONSE_BYTES:
        raise _LocalResponseLimit("response too large")
    return json.loads(raw)


def _urlscan_safe_target(url):
    """Screen syntax only; never resolve or connect to the investigated host locally."""
    if not validar_url(url) or url_contiene_secretos(url) or "#" in url:
        return False
    host = extraer_dominio(url)
    if not host or "." not in host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".example", ".invalid")):
        return False
    try:
        if ipaddress.ip_address(host).is_global:
            return True
        return False
    except ValueError:
        return bool(_safe_domain(host))


def consultar_urlscan_privado(url):
    key = _urlscan_key()
    if not key:
        return {"status": "unknown", "reason": "URLscan no evaluado: API key ausente"}
    if not _urlscan_safe_target(url):
        return {"status": "unknown", "reason": "URLscan omitido: URL no apta para envío privado"}
    issues = []
    try:
        _notificar_consulta("urlscan.io")
        submitted = _urlscan_request(f"{URLSCAN_BASE_URL}/scan", json.dumps({"url": url, "visibility": "private"}).encode())
        task = submitted.get("task", submitted)
        scan_id = task.get("uuid")
        if not isinstance(scan_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", scan_id) or task.get("visibility") != "private":
            return dict({"status": "unknown", "reason": "URLscan no evaluado: respuesta de envío no privada/válida"}, service_issues=[{"service": "urlscan.io", "reason": "URLscan no evaluado: respuesta de envío no privada/válida"}])
        result = None
        deadline = time.monotonic() + 60
        time.sleep(10)
        for attempt in range(26):
            if time.monotonic() >= deadline:
                break
            try:
                result = _urlscan_request(f"{URLSCAN_BASE_URL}/result/{scan_id}/")
                break
            except HTTPError as error:
                if error.code != 404:
                    raise
                if attempt < 25:
                    time.sleep(min(2, max(0, deadline - time.monotonic())))
        if result is None:
            return dict({"status": "unknown", "reason": "URLscan pendiente", "uuid": scan_id}, service_issues=[{"service": "urlscan.io", "reason": "URLscan pendiente"}])
        if not isinstance(result, dict) or result.get("task", {}).get("visibility") != "private":
            return dict({"status": "unknown", "reason": "URLscan no evaluado: visibilidad del resultado no confirmada", "uuid": scan_id}, service_issues=[{"service": "urlscan.io", "reason": "URLscan no evaluado: visibilidad del resultado no confirmada"}])
        page = result.get("page", {}) if isinstance(result.get("page"), dict) else {}
        verdicts = result.get("verdicts", {}) if isinstance(result.get("verdicts"), dict) else {}
        verdict = verdicts.get("urlscan", {}) if isinstance(verdicts.get("urlscan"), dict) else {}
        domains = result.get("lists", {}).get("domains", []) if isinstance(result.get("lists"), dict) else []
        clean_domains = sorted({re.sub(r"[^A-Za-z0-9.-]", "", item)[:253].lower() for item in domains[:20] if isinstance(item, str)}) if isinstance(domains, list) else []
        final_url = page.get("url")
        safe_final = _redact_display_url(final_url) if isinstance(final_url, str) else "desconocida"
        score = verdict.get("score")
        malicious = verdict.get("malicious") if isinstance(verdict.get("malicious"), bool) else None
        if isinstance(score, int) and not isinstance(score, bool) and score > 0:
            malicious = True  # Positive provider score remains a risk signal, never a clean default.
        cats = verdict.get("categories")
        phishing = any("phish" in item.lower() for item in cats) if isinstance(cats, list) and all(isinstance(item, str) for item in cats) else None
        redirects = []
        data = result.get("data", {})
        if isinstance(data, dict):
            for item in data.get("requests", [])[:200]:
                if isinstance(item, dict):
                    response = item.get("response", {})
                    response = response.get("response", {}) if isinstance(response, dict) else {}
                    if isinstance(response, dict) and response.get("status") in (301, 302, 303, 307, 308) and isinstance(response.get("url"), str):
                        redirects.append(_redact_display_url(response["url"]))
            for item in (data.get("redirects", []) if isinstance(data.get("redirects"), list) else [])[:20]:
                if isinstance(item, dict) and isinstance(item.get("url"), str):
                    redirects.append(_redact_display_url(item["url"]))
        credentials = "unknown"
        try:
            dom = _urlscan_dom(scan_id)
            parser = ExtractorCredenciales()
            parser.feed(dom)
            credentials = "password_input" if parser.password_input else "not_observed"
        except _LocalResponseLimit:
            pass  # Local bound; credentials remain unverified, not a provider outage.
        except (OSError, ValueError, TypeError):
            issues.append({"service": "urlscan.io", "reason": "DOM no disponible o no válido"})
        requests = data.get("requests", []) if isinstance(data, dict) else []
        behavior_observed = isinstance(requests, list) and bool(requests) and isinstance(page.get("url"), str) and bool(page.get("ip")) and bool(page.get("country")) and bool(clean_domains)
        if not behavior_observed:
            issues.append({"service": "urlscan.io", "reason": "respuesta de comportamiento incompleta (navegación, IP, país o dominios)"})
        return {"service_issues": issues, "status": "suspicious" if malicious or phishing else "unknown", "uuid": scan_id, "time": str(task.get("time", "desconocido"))[:40], "screenshot": f"https://urlscan.io/screenshots/{scan_id}.png", "final_url": safe_final, "ip": str(page.get("ip", "desconocida"))[:64], "country": str(page.get("country", "desconocido"))[:64], "domains": clean_domains, "malicious": malicious, "phishing": phishing, "redirected": bool(redirects), "redirects": redirects[:20], "credentials": credentials, "behavior_observed": behavior_observed}
    except _LocalResponseLimit:
        return {"status": "unknown", "reason": "URLscan no evaluado: límite local de respuesta"}
    except HTTPError as error:
        reason = {400: "solicitud rechazada", 401: "API key inválida", 403: "acceso privado denegado; se requiere acceso privado", 429: "límite de API alcanzado"}.get(error.code, f"HTTP {error.code}")
        return dict({"status": "unknown", "reason": f"URLscan no evaluado: {reason}"}, service_issues=[{"service": "urlscan.io", "reason": f"URLscan no evaluado: {reason}"}])
    except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError):
        return dict({"status": "unknown", "reason": "URLscan no evaluado: error de conexión/respuesta"}, service_issues=[{"service": "urlscan.io", "reason": "URLscan no evaluado: error de conexión/respuesta"}])



def _redact_display_url(value):
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "URL final omitida"
        return f"{parsed.scheme}://{parsed.hostname[:253]}{parsed.path[:256] or '/'}"
    except (ValueError, TypeError):
        return "URL final omitida"


class ExtractorCredenciales(HTMLParser):
    def __init__(self):
        super().__init__()
        self.password_input = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "input" and str(dict(attrs).get("type") or "").lower() == "password":
            self.password_input = True


def _analizar_archivo_bytes(data, name, vt_report=None, mime=None, macro_status=None,
                            sha256=None, size=None):
    """Build file evidence from bounded bytes; never writes or executes the payload."""
    if not isinstance(data, bytes):
        raise TypeError("el contenido debe ser bytes")
    size = len(data) if size is None else size
    bounded = data[:MAX_LOCAL_FILE_BYTES]
    detected, basis = detectar_tipo(bounded[:8192])
    script_status = analizar_scripts_embebidos(bounded, detected)
    macro_status = macro_status or analizar_macros_bytes(bounded, detected)
    sha256 = hashlib.sha256(data).hexdigest() if sha256 is None else sha256
    ext_type = tipo_por_extension(os.path.splitext(name)[1])
    vt_report = vt_report if isinstance(vt_report, dict) else consultar_virustotal_archivo(sha256)
    evidence = resumen_vt(vt_report)
    evidence.update({
        "resource_type": "file", "sha256": sha256, "name": os.path.basename(name)[:120],
        "size": size, "type": detected, "type_basis": basis,
        "extension_type": ext_type or "desconocido",
        "scripts": script_status, "macros": macro_status,
        "mime": mime or "desconocido", "executable": detected in ("PE", "ELF", "Mach-O", "script"),
        "service_issues": list(_service_issues(vt_report)),
    })
    evidence["criteria"] = {
        "authentication": criterio("na", "archivo"),
        "domain": criterio("na", "archivo"),
        "detections": criterio_detecciones(vt_report),
        "behavior": evaluar_comportamiento_archivo(detected, script_status, macro_status, size),
    }
    evidence["optional_criteria"] = {"community_reputation": _community_reputation_check(vt_report)}
    evidence["concrete_causes"] = list(evidence.get("concrete_causes", []))
    if evidence["criteria"]["behavior"]["status"] == "fail":
        evidence["concrete_causes"].append(f"{evidence['name']}: contenido activo; macros={macro_status}; scripts={script_status}")
    metadata = _metadatos_vt_archivo(vt_report) if evidence.get("report_available") else {}
    evidence["vt_metadata"] = metadata
    evidence["report"] = {
        "file": {"name": evidence["name"], "size": size, "type": detected,
                 "sha256": sha256, "scripts": script_status, "macros": macro_status,
                 "mime": mime or "desconocido", "extension_type": ext_type or "desconocido",
                 "vt_metadata": metadata},
        "virustotal": {"hash": sha256, "report": "available" if evidence.get("report_available") else "unknown",
                        "malicious": evidence.get("malicious", 0), "suspicious": evidence.get("suspicious", 0),
                        "first_seen": metadata.get("first_seen") if metadata.get("first_seen") != "desconocido" else metadata.get("first_submission_date", "desconocido"),
                        "names": metadata.get("names", [])},
    }
    return evidence


@_analysis_entrypoint
def analizar_archivo(ruta, emitir=True):
    digest = hashlib.sha256()
    chunks = []
    collected = 0
    with abrir_archivo_seguro(ruta) as stream:
        initial = os.fstat(stream.fileno())
        remaining = initial.st_size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("El archivo cambió durante la lectura (fin prematuro)")
            digest.update(chunk)
            if collected < MAX_LOCAL_FILE_BYTES:
                piece = chunk[:MAX_LOCAL_FILE_BYTES - collected]
                chunks.append(piece)
                collected += len(piece)
            remaining -= len(chunk)
        final = os.fstat(stream.fileno())
        if (final.st_size, final.st_mtime_ns, final.st_ctime_ns) != (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns):
            raise OSError("El archivo cambió durante la lectura")
    data = b"".join(chunks)
    if initial.st_size > MAX_LOCAL_FILE_BYTES:
        data = data[:MAX_LOCAL_FILE_BYTES]
    detected, _ = detectar_tipo(data[:8192])
    macro_status = analizar_macros_local(ruta, initial.st_size, detected)
    evidence = _analizar_archivo_bytes(
        data, os.fspath(ruta), macro_status=macro_status,
        sha256=digest.hexdigest(), size=initial.st_size,
    )
    return imprimir_veredicto(evidence) if emitir else evidence


def detectar_tipo(data):
    if data.startswith(b"MZ"): return "PE", "firma MZ (heurística; cabecera PE no validada)"
    if data.startswith(b"\x7fELF"): return "ELF", "firma ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"): return "Mach-O", "firma binaria"
    if data.startswith(b"%PDF-"): return "PDF", "firma PDF"
    if data.startswith(b"PK\x03\x04"): return "ZIP/OOXML", "firma ZIP; contenido OOXML no confirmado"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"): return "OLE", "firma OLE"
    if data.startswith(b"#!"): return "script", "shebang"
    try:
        text = data.decode("utf-8")
        if text and all(c.isprintable() or c in "\r\n\t" for c in text): return "texto/script", "heurística de texto"
    except UnicodeDecodeError:
        pass
    return "desconocido", "sin firma reconocida"


def tipo_por_extension(extension):
    ext = extension.lower()
    return {".exe":"PE", ".dll":"PE", ".pdf":"PDF", ".zip":"ZIP/OOXML", ".docx":"ZIP/OOXML", ".xlsx":"ZIP/OOXML", ".pptx":"ZIP/OOXML", ".doc":"OLE", ".xls":"OLE", ".ppt":"OLE", ".py":"script", ".js":"script", ".sh":"script", ".bat":"script", ".ps1":"script"}.get(ext)


def analizar_scripts_embebidos(data, detected):
    markers = (b"/JavaScript", b"/JS", b"<script", b"JavaScript", b"VBScript")
    observed = any(marker.lower() in data.lower() for marker in markers)
    if detected == "ZIP/OOXML":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_MACRO_ZIP_ENTRIES:
                    return "no evaluado (límite de miembros ZIP)"
                observed = observed or any(info.filename.lower().endswith((".js", ".vbs", ".ps1", ".wsf")) for info in entries)
                total = 0
                for info in entries:
                    total += info.file_size
                    if total > MAX_MACRO_ZIP_TOTAL_BYTES:
                        return "no evaluado (límite ZIP expandido)"
                    if info.filename.lower().endswith((".xml", ".html", ".rels")) and info.file_size <= MAX_OOXML_MEMBER_BYTES:
                        if info.flag_bits & 1 or info.file_size / max(1, info.compress_size) > MAX_MACRO_ZIP_RATIO:
                            continue
                        member = archive.read(info)
                        observed = observed or b"<script" in member.lower()
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, zlib.error):
            return "no evaluado (ZIP cifrado, corrupto o truncado)"
    return "scripts embebidos presentes" if observed else "scripts embebidos no observados"


def evaluar_comportamiento_archivo(detected, scripts, macros, size):
    if detected == "desconocido" or size > MAX_LOCAL_FILE_BYTES or scripts.startswith("no evaluado"):
        return criterio("unknown", f"tipo={detected}; {scripts}; lectura acotada")
    if "presentes" in scripts or "macros VBA detectadas" in macros:
        return criterio("fail", f"contenido activo observado; {scripts}; {macros}")
    if detected in ("OLE", "ZIP/OOXML") and macros.startswith("no evaluado"):
        return criterio("unknown", f"macros Office no evaluadas: {macros}")
    if detected in ("PE", "ELF", "Mach-O", "script"):
        return criterio("unknown", "contenido ejecutable identificado; comportamiento del proveedor no confirmado")
    return criterio("pass", f"inspección estática acotada: tipo={detected}; {scripts}; {macros}")


def analizar_macros_local(path, size, detected):
    if size > MAX_LOCAL_FILE_BYTES or detected not in ("OLE", "ZIP/OOXML"):
        return "no evaluado (tipo no compatible o archivo mayor a 25 MiB)"
    try:
        if detected == "ZIP/OOXML":
            _validar_metadatos_zip_macros(path)
        from oletools.olevba import VBA_Parser
        _notificar_consulta("oletools")
        parser = VBA_Parser(os.fspath(path))
        try:
            if not parser.detect_vba_macros():
                return "sin macros VBA detectadas por oletools"
            count = 0
            for _ in parser.analyze_macros():
                count += 1
                if count >= 1000: break
            return f"macros VBA detectadas; {count} indicadores estáticos"
        finally:
            parser.close()
    except ImportError:
        return "no evaluado (oletools no instalado)"
    except (zipfile.BadZipFile, OSError, ValueError, OverflowError):
        return "no evaluado (archivo ZIP cifrado, corrupto o fuera de límites)"
    except Exception:
        return "no evaluado (error, archivo cifrado o formato no compatible)"


def analizar_macros_bytes(data, detected):
    """Detect Office macro markers in attachment bytes without creating a file."""
    if detected not in ("OLE", "ZIP/OOXML"):
        return "no aplica (no Office)"
    if len(data) > MAX_LOCAL_FILE_BYTES:
        return "no evaluado (límite de lectura)"
    lowered = data.lower()
    if detected == "ZIP/OOXML":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()[:MAX_MACRO_ZIP_ENTRIES]
                if any("vbaproject.bin" in info.filename.lower() for info in entries):
                    return "macros VBA detectadas (vbaProject.bin)"
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, zlib.error):
            return "no evaluado (ZIP cifrado, corrupto o truncado)"
        return "sin macros VBA detectadas"
    if any(marker in lowered for marker in (b"vba", b"_vba_project", b"vba_project")):
        return "posibles macros VBA detectadas por marcadores OLE"
    return "sin macros VBA detectadas"


def _validar_metadatos_zip_macros(path):
    """Reject risky ZIP metadata before oletools; never extract or decompress members."""
    with zipfile.ZipFile(os.fspath(path)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_MACRO_ZIP_ENTRIES:
            raise ValueError("demasiadas entradas ZIP")
        total_size = 0
        for info in entries:
            filename = info.filename
            if (
                not isinstance(filename, str)
                or not filename
                or len(filename) > 1024
                or "\x00" in filename
                or any(ord(char) < 32 or ord(char) == 127 for char in filename)
                or "\\" in filename
                or filename.startswith("/")
                or re.match(r"^[A-Za-z]:", filename)
                or any(part in ("", ".", "..") for part in filename.rstrip("/").split("/"))
            ):
                raise ValueError("nombre de miembro ZIP no seguro")
            timestamp = info.date_time
            if (
                not isinstance(timestamp, tuple)
                or len(timestamp) != 6
                or any(isinstance(value, bool) or not isinstance(value, int) for value in timestamp)
                or not 1980 <= timestamp[0] <= 2107
            ):
                raise ValueError("fecha ZIP inválida")
            try:
                datetime(*timestamp)
            except (TypeError, ValueError, OverflowError):
                raise ValueError("fecha ZIP inválida") from None
            if info.flag_bits & 0x1:
                raise ValueError("miembro ZIP cifrado")
            if info.file_size < 0 or info.compress_size < 0 or info.file_size > MAX_MACRO_ZIP_MEMBER_BYTES:
                raise ValueError("tamaño de miembro ZIP fuera de límites")
            total_size += info.file_size
            if total_size > MAX_MACRO_ZIP_TOTAL_BYTES:
                raise ValueError("tamaño ZIP expandido total fuera de límites")
            if info.file_size and (not info.compress_size or info.file_size / info.compress_size > MAX_MACRO_ZIP_RATIO):
                raise ValueError("ratio de compresión ZIP sospechoso")


def indicadores_ooxml(data):
    """Inspect bounded OOXML ZIP metadata and small relevant members without extraction."""
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist()[:200]:
                if info.file_size > MAX_OOXML_MEMBER_BYTES:
                    continue
                if "vbaproject.bin" in info.filename.lower() or "vba" in info.filename.lower() and info.filename.lower().endswith(".rels"):
                    return True
    except (zipfile.BadZipFile, OSError, zlib.error):
        return False
    return False


def _metadatos_vt_archivo(attributes):
    metadata = {}
    if not validar_informe_vt(attributes):
        return metadata
    def clean_text(value, limit=160):
        if not isinstance(value, str):
            return "desconocido"
        value = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
        value = re.sub(r"https?://\S+", "[omitido]", value, flags=re.I)
        value = re.sub(r"\s+", " ", value).strip()
        return value[:limit] or "desconocido"
    def display(key):
        value = attributes.get(key)
        if key in ("first_submission_date", "first_seen", "last_analysis_date"):
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 253402300799:
                try:
                    value = datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                except (ValueError, OverflowError, OSError):
                    value = "desconocido"
            else:
                value = "desconocido"
        elif key == "names":
            if isinstance(value, list):
                value = ", ".join(clean_text(item, 120) for item in value[:5] if isinstance(item, str)) or "desconocido"
            else:
                value = "desconocido"
        elif key in ("type_description", "type_tag"):
            value = clean_text(value)
        elif key == "size" and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1):
            value = "desconocido"
        return value if value not in (None, '') else "desconocido"
    for key in ("type_description", "type_tag", "size", "names", "first_submission_date", "first_seen", "last_analysis_date"):
        metadata[key] = display(key)
    return metadata


def decodificar_candidatos(text):
    """Discover URLs through bounded Base64/URL decoding, entirely in-process."""
    from urllib.parse import unquote
    if not isinstance(text, str):
        return []
    initial = text[:MAX_DECODE_BYTES].encode("utf-8")[:MAX_DECODE_BYTES].decode("utf-8", errors="ignore").strip()
    pending, seen, found = [(initial, 0)], {initial}, []
    processed = 0
    while pending and processed < MAX_EML_DECODE_CANDIDATES:
        current, depth = pending.pop(0)
        processed += 1
        if depth:
            found.extend(re.findall(r'https?://[^\s<>"\']+', current, flags=re.I)[:MAX_EML_DECODE_CANDIDATES])
        if depth >= MAX_DECODE_DEPTH:
            continue
        decoded = []
        try:
            decoded.append(unquote(current, encoding="utf-8", errors="strict"))
        except UnicodeError:
            pass
        seeds = [current] + re.findall(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/_-])", current)[:MAX_EML_DECODE_CANDIDATES]
        for seed in seeds:
            try:
                compact = re.sub(r"\s+", "", seed)
                if len(compact) < 20 or len(compact) % 4 == 1 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
                    continue
                padded = compact + "=" * ((-len(compact)) % 4)
                decoded.append(base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8", errors="strict"))
            except (ValueError, UnicodeError):
                continue
        for value in decoded:
            if value in seen or len(value.encode("utf-8")) > MAX_DECODE_BYTES:
                continue
            if len(seen) >= MAX_EML_DECODE_CANDIDATES:
                break
            seen.add(value)
            pending.append((value, depth + 1))
    return list(dict.fromkeys(found))[:MAX_EML_DECODE_CANDIDATES]


def inventariar_adjuntos(correo):
    entries, total = [], 0
    for part in correo.walk():
        if part.is_multipart() or (part.get_content_disposition() != "attachment" and not part.get_filename()):
            continue
        if len(entries) >= MAX_EML_ATTACHMENTS:
            break
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            entries.append({"name": "adjunto-sin-nombre", "status": "no evaluado (contenido no decodificable)"}); continue
        name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(part.get_filename() or "adjunto-sin-nombre"))[:120]
        if total + len(payload) > MAX_EML_ATTACHMENT_BYTES:
            entries.append({"name": name, "status": "no evaluado (límite total de bytes)"}); break
        total += len(payload)
        evidence = _analizar_archivo_bytes(payload, name, mime=part.get_content_type())
        entries.append({"name": name, "sha256": evidence["sha256"], "status": "inventariado",
                        "script_status": evidence["scripts"], "macros": evidence["macros"],
                        "type": evidence["type"], "size": len(payload), "evidence": evidence})
    return entries


def analizar_reputacion(url):
    """Normalize one URL report; relationship queries are scheduled separately."""
    report = consultar_virustotal(url)
    result = resumen_vt(report)
    result["_report"] = report
    if not result["report_available"]:
        return dict(result, status="desconocido")
    behavior = evaluar_comportamiento_url(url, report, {})
    status = "malicioso" if result["malicious"] >= MALICIOUS_CONSENSUS_THRESHOLD or behavior["high_phishing_risk"] else "sospechoso" if result["malicious"] or result["suspicious"] else "sin_detecciones" if criterio_detecciones(report)["status"] == "pass" else "desconocido"
    return dict(result, status=status)


def extraer_dominio(url):
    """Return a normalized hostname only for absolute HTTP(S) URLs."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if parsed.scheme.lower() not in ("http", "https") or not hostname:
            return None
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if len(hostname) > 253 or not all(
            label and len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            return None
        return hostname
    except (UnicodeError, ValueError):
        return None


def _normalizar_url_cache_key(url):
    """Canonicalize only URL syntax used to identify one VT URL report."""
    if not isinstance(url, str):
        return str(url)
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        if scheme not in ("http", "https") or not hostname or parsed.username is not None or parsed.password is not None:
            return url
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = parsed.port
        if port is not None and port not in ((scheme == "http" and 80), (scheme == "https" and 443)):
            hostname = f"{hostname}:{port}"
        return urlunparse((scheme, hostname, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))
    except (UnicodeError, ValueError):
        return url


def _normalizar_sha256(value):
    return str(value).strip().lower()


def consultar_crtsh(dominio):
    """Query crt.sh for certificates covering the domain or its subdomains."""
    request = Request(f"{CRT_SH_URL}?q={quote('%.' + dominio)}&output=json", headers={"accept": "application/json"})
    try:
        _notificar_consulta("crt.sh")
        with urlopen(request, timeout=LOOKUP_TIMEOUT) as respuesta:
            raw = respuesta.read(MAX_INTEL_BYTES + 1)
        if len(raw) > MAX_INTEL_BYTES:
            return {"error": "Respuesta de crt.sh excede el límite local"}
        datos = json.loads(raw)
        if not isinstance(datos, list):
            return _service_error("crt.sh", "Respuesta de crt.sh no válida")
        nombres = sorted({
            nombre.strip().lower()
            for certificado in datos if isinstance(certificado, dict)
            for nombre in str(certificado.get("name_value", "")).splitlines()
            if nombre.strip() and (
                nombre.strip().lower().rstrip(".") == dominio
                or nombre.strip().lower().rstrip(".").endswith("." + dominio)
            )
        })
        certificates = []
        for item in datos[:200]:
            if not isinstance(item, dict):
                continue
            names = [n.strip().lower().rstrip(".") for n in str(item.get("name_value", "")).splitlines()]
            if not any(n == dominio or n.endswith("." + dominio) for n in names):
                continue
            certificates.append({key: str(item[key])[:80] for key in ("not_before", "not_after", "entry_timestamp") if isinstance(item.get(key), str)})
        return {"count": len(nombres), "names": nombres[:10], "certificates": certificates[:10]}
    except HTTPError as error:
        return _service_error("crt.sh", f"Error HTTP {error.code} en crt.sh")
    except (URLError, TimeoutError):
        return _service_error("crt.sh", "Error de conexión con crt.sh")
    except (ValueError, TypeError):
        return _service_error("crt.sh", "Respuesta de crt.sh no válida")



def _consulta_whois(servidor, consulta):
    """Send one bounded WHOIS TCP/43 request and return its text response."""
    chunks = []
    total = 0
    address = _public_resolved_ip(servidor)
    if not address:
        raise OSError("WHOIS host is not public")
    with socket.create_connection((address, WHOIS_PORT), timeout=LOOKUP_TIMEOUT) as conexion:
        conexion.settimeout(LOOKUP_TIMEOUT)
        conexion.sendall((consulta + "\r\n").encode("ascii"))
        while total < WHOIS_MAX_BYTES:
            bloque = conexion.recv(min(4096, WHOIS_MAX_BYTES - total))
            if not bloque:
                break
            chunks.append(bloque)
            total += len(bloque)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _public_resolved_ip(host):
    try:
        address = ipaddress.ip_address(host)
        return str(address) if address.is_global else None
    except ValueError:
        pass
    try:
        addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            return None
        return addresses[0]
    except (OSError, ValueError):
        return None


def consultar_whois(dominio):
    """Query IANA WHOIS, then the registry WHOIS server it refers to."""
    if not isinstance(dominio, str) or not all(
        label and len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in dominio.lower().rstrip(".").split(".")
    ):
        return {"error": "Dominio no válido para consulta WHOIS"}
    dominio = dominio.lower().rstrip(".")
    try:
        _notificar_consulta("WHOIS")
        iana = _consulta_whois(WHOIS_IANA_SERVER, dominio)
        referral = re.search(r"(?im)^refer:\s*(\S+)\s*$", iana)
        if not referral:
            return _service_error("WHOIS", "IANA WHOIS no devolvió servidor de referencia")
        servidor = referral.group(1).rstrip(".")
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", servidor):
            return _service_error("WHOIS", "Servidor de referencia WHOIS no válido")
        resultado = _consulta_whois(servidor, dominio)
        date_match = re.search(r"(?im)^(?:creation date|created|created on|registration date):\s*(.+)$", resultado)
        registered = _parse_registration_date(date_match.group(1).strip()) if date_match else None
        age_days = (datetime.now(timezone.utc) - registered).days if registered else None
        registrar = re.search(r"(?im)^(?:registrar|registrar name):\s*(.{1,160})$", resultado)
        nameservers = sorted(set(re.findall(r"(?im)^(?:name server|nserver):\s*([A-Za-z0-9.-]{1,253})", resultado)))[:10]
        return {"server": servidor, "registration_date": registered.isoformat() if registered else None,
                "registration_age_days": age_days, "registrar": registrar.group(1).strip()[:160] if registrar else None,
                "nameservers": nameservers}
    except (OSError, TimeoutError, UnicodeError):
        return _service_error("WHOIS", "Error de conexión con WHOIS")



def _safe_domain(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}", value.rstrip(".")):
        return None
    host = value.rstrip(".").lower()
    try:
        if ipaddress.ip_address(host):
            return None
    except ValueError:
        pass
    return host


def _provider_json(url, headers=None):
    request = Request(url, headers=headers or {"accept": "application/json"})
    _notificar_consulta("VirusTotal")
    with urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
        raw = response.read(MAX_INTEL_BYTES + 1)
    if len(raw) > MAX_INTEL_BYTES:
        raise _LocalResponseLimit("response too large")
    return json.loads(raw)


_vt_cache = {}
_EML_DOMAIN_REPORTS = None
_EML_DOMAIN_INTELLIGENCE = None


def _take_vt_budget():
    now = time.monotonic()
    with _vt_lock:
        while _vt_request_times and now - _vt_request_times[0] >= VT_WINDOW_SECONDS:
            _vt_request_times.pop(0)
        if len(_vt_request_times) >= MAX_VT_REQUESTS:
            return False
        _vt_request_times.append(now)
        return True


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urlopen(request, timeout=LOOKUP_TIMEOUT):
    """Allow only intelligence providers, never redirects to investigated sites."""
    parsed = urlparse(request.full_url)
    if (parsed.scheme != "https" or parsed.hostname not in {"www.virustotal.com", "crt.sh", "urlscan.io"}
            or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443)):
        raise ValueError("HTTP destination is not an allowed intelligence provider")
    return build_opener(_NoRedirect()).open(request, timeout=timeout)


def consultar_vt_objeto(collection, identifier):
    if collection not in ("domains", "urls"):
        return {"error": "VirusTotal no disponible (API key ausente o tipo no válido)"}
    if collection == "domains":
        identifier = _normalizar_dominio(identifier)
        if not _safe_domain(identifier):
            return {"error": "Dominio no válido para consulta VirusTotal"}
        key = ("domain", identifier)
    else:
        identifier = str(identifier)
        key = ("object", collection, identifier)
    if key in _vt_cache:
        return _vt_cache[key]
    if not VT_API_KEY:
        return {"error": "VirusTotal no disponible (API key ausente o tipo no válido)"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}
    try:
        data = _provider_json(f"{VT_BASE_URL}/{collection}/{quote(identifier, safe='')}", {"x-apikey": VT_API_KEY, "accept": "application/json"})
        attrs = data.get("data", {}).get("attributes", {})
        result = dict(attrs) if isinstance(attrs, dict) else {}
        if not validar_informe_vt(result):
            result.update(_service_error("VirusTotal", "Respuesta VirusTotal no válida/incompleta"))
    except _LocalResponseLimit:
        result = _service_error("VirusTotal", "Respuesta de VirusTotal excede el límite local")
    except HTTPError as error:
        result = {"error": f"VirusTotal HTTP {error.code}"} if error.code == 404 else _service_error("VirusTotal", f"VirusTotal HTTP {error.code}")
    except (URLError, TimeoutError, OSError, ValueError, TypeError, KeyError):
        result = _service_error("VirusTotal", "VirusTotal no disponible o respuesta no válida")
    _vt_cache[key] = result
    return result



def _relacion_vt(collection, identifier, relation):
    key = ("relationship", collection, str(identifier), relation)
    if key in _vt_cache:
        return _vt_cache[key]
    if not VT_API_KEY:
        return {"error": "VirusTotal no disponible"}
    if collection != "urls" or relation != "last_serving_ip_address":
        return {"error": "Relación no admitida"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}
    try:
        data = _provider_json(f"{VT_BASE_URL}/{collection}/{quote(identifier, safe='')}/relationships/{relation}", {"x-apikey": VT_API_KEY, "accept": "application/json"})
        entries = data.get("data", [])
        if isinstance(entries, dict):
            entries = [entries] if isinstance(entries.get("id"), str) else None
        if not isinstance(entries, list):
            result = _service_error("VirusTotal", f"Relación {relation}: respuesta no válida")
        else:
            result = {"names": [str(x.get("id", ""))[:253] for x in entries[:10] if isinstance(x, dict)]}
            if len(entries) > 10 or data.get("links", {}).get("next"):
                result["error"] = "relaciones parciales (paginación/límite local)"
    except _LocalResponseLimit:
        result = _service_error("VirusTotal", "Respuesta de VirusTotal excede el límite local")
    except HTTPError as error:
        result = _service_error("VirusTotal", f"Relación {relation} no disponible (HTTP {error.code})")
    except (URLError, TimeoutError, OSError, ValueError, TypeError):
        result = _service_error("VirusTotal", f"Relación {relation} no disponible")
    _vt_cache[key] = result
    return result



def analizar_inteligencia_dominio(urls, domain_reports=None, domain_targets=None, registry_domains=None):
    """Collect one shared domain pass for URL targets and explicit domain targets."""
    evidence = {"service_issues": [], "concrete_causes": [], "mixed": False,
                "criteria": [], "resources": [], "domains": [], "domain_reports": {},
                "by_domain": {}}
    domain_reports = domain_reports if isinstance(domain_reports, dict) else {}
    domains = set()
    explicit_domains = set()
    for url in urls or ():
        if not isinstance(url, str) or url_contiene_secretos(url):
            continue
        domain = _safe_domain(extraer_dominio(url))
        if domain:
            domains.add(domain)
    for target in domain_targets or ():
        domain = _safe_domain(_normalizar_dominio(target))
        if domain:
            domains.add(domain)
            explicit_domains.add(domain)
    registry_domains = None if registry_domains is None else {
        domain for domain in (_safe_domain(_normalizar_dominio(item)) for item in registry_domains) if domain
    }
    dominios = sorted(explicit_domains) + sorted(domains - explicit_domains)
    dominios = dominios[:MAX_DOMAIN_LOOKUPS]
    for dominio in dominios:
        vt = domain_reports.get(dominio)
        if not isinstance(vt, dict):
            vt = consultar_vt_objeto("domains", dominio)
        evidence["domain_reports"][dominio] = vt
        stats = vt.get("last_analysis_stats", {}) if validar_informe_vt(vt) else {}
        target_resources = []
        target_issues = list(_service_issues(vt)) if not stats else []
        target_causes = []
        if stats:
            resource = {"source": f"Dominio {dominio} (VirusTotal)",
                        "malicious": stats["malicious"], "suspicious": stats["suspicious"],
                        "report_available": True}
            target_resources.append(resource)
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            evidence["mixed"] = True
            target_causes.append(f"Dominio {dominio}: VirusTotal {stats['malicious']} maliciosos y {stats['suspicious']} sospechosos")
        use_registry = registry_domains is None or dominio in registry_domains
        certificados = {}
        whois = {}
        if use_registry:
            certificados = consultar_crtsh(dominio)
            if "error" in certificados:
                target_issues.extend(_service_issues(certificados))
            whois = consultar_whois(dominio)
            if "error" in whois:
                target_issues.extend(_service_issues(whois))
        criterion = evaluar_dominio(dominio, vt, whois)
        evidence["criteria"].append(criterion)
        evidence["service_issues"].extend(target_issues)
        evidence["concrete_causes"].extend(target_causes)
        status = criterio_detecciones(vt)["status"]
        virustotal = {
            "status": status,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": vt.get("reputation", "desconocida"),
            "requirements": "VT_clean; WHOIS_age>=180d; reputation>0",
        }
        entry = {"domain": dominio, **virustotal, "virustotal": virustotal}
        if use_registry:
            entry["whois"] = {key: whois.get(key) for key in ("registration_date", "registration_age_days", "registrar", "nameservers")}
            entry["crt_sh"] = certificados if isinstance(certificados, dict) else {}
        evidence["domains"].append(entry)
        evidence["resources"].extend(target_resources)
        evidence["by_domain"][dominio] = {
            "criterion": criterion, "resources": target_resources, "entry": entry,
            "service_issues": target_issues, "concrete_causes": target_causes,
            "mixed": bool(stats.get("malicious", 0) or stats.get("suspicious", 0)),
        }
    return evidence


def _domain_intelligence_for_url(url, shared):
    """Select one domain from a shared pass without re-querying providers."""
    domain = _safe_domain(extraer_dominio(url))
    selected = shared.get("by_domain", {}).get(domain) if domain else None
    if not isinstance(selected, dict):
        return {"service_issues": [], "concrete_causes": [], "mixed": False,
                "criteria": [], "resources": [], "domains": []}
    return {
        "service_issues": list(selected.get("service_issues", [])),
        "concrete_causes": list(selected.get("concrete_causes", [])),
        "mixed": bool(selected.get("mixed")),
        "criteria": [selected["criterion"]] if isinstance(selected.get("criterion"), dict) else [],
        "resources": list(selected.get("resources", [])),
        "domains": [selected["entry"]] if isinstance(selected.get("entry"), dict) else [],
    }


def _parse_registration_date(value):
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%d-%b-%Y"):
        try:
            result = datetime.strptime(value[:25], fmt)
            return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


# ==========================================
# ANÁLISIS EML
# ==========================================

def _normalizar_dominio(value):
    try:
        value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
        return value if value and len(value) <= 253 else ""
    except (UnicodeError, AttributeError):
        return ""


def _direcciones(header):
    return [address.strip().lower() for _, address in getaddresses([str(v) for v in header]) if address and "@" in address]


_AUTHENTICATION_RESULT_RE = re.compile(
    r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)(?=\s|;|$|\()",
    re.I,
)
_AUTHENTICATION_FAILURES = {"fail", "softfail", "permerror"}
_AUTHENTICATION_FALLBACKS = {"unknown", "unavailable", "temperror"}


def _authentication_results(correo):
    """Extract only bounded, recognized Authentication-Results result tokens."""
    records = []
    headers = correo.get_all("Authentication-Results", []) if correo is not None else []
    for index, value in enumerate(headers[:MAX_AUTHENTICATION_RESULTS_HEADERS], 1):
        bounded = str(value)[:MAX_AUTHENTICATION_RESULTS_BYTES]
        unfolded = re.sub(r"\r?\n[ \t]+", " ", bounded)
        source = f"Authentication-Results[{index}]"
        for match in _AUTHENTICATION_RESULT_RE.finditer(unfolded):
            records.append({"source": source, "check": match.group(1).upper(), "status": match.group(2).lower()})
    return records


def _authentication_header_status(records, check):
    statuses = [item["status"] for item in records if item.get("check") == check]
    if any(status in _AUTHENTICATION_FAILURES for status in statuses):
        return next(status for status in statuses if status in _AUTHENTICATION_FAILURES)
    if "pass" in statuses:
        return "pass"
    return statuses[0] if statuses else None


def _authentication_status_class(status):
    if status == "pass":
        return "pass"
    if status in _AUTHENTICATION_FAILURES:
        return "fail"
    return "unknown"


def _effective_authentication_status(independent, header):
    if independent in _AUTHENTICATION_FALLBACKS and header is not None:
        return header
    return independent


def _dkim_independent_status(results):
    statuses = [item.get("status") for item in results if isinstance(item, dict)]
    if "failed" in statuses:
        return "failed"
    if "verified" in statuses:
        return "verified"
    if statuses and all(status in ("unavailable", "unknown") for status in statuses):
        return "unavailable"
    return "unknown"


def _dkim_report_status(independent, header):
    effective = _effective_authentication_status(
        {"verified": "pass", "failed": "fail"}.get(independent, independent), header,
    )
    return effective


def _dns_txt(name, timeout=5):
    import dns.resolver
    answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    return [b"".join(record.strings) for record in answers]


def _dkim_dns_record(name, timeout=5):
    """Adapt the multi-record DNS API to dkimpy's one raw TXT-record contract."""
    _notificar_consulta("DNS (DKIM)")
    records = _dns_txt(name, timeout=timeout)
    candidates = []
    for record in records:
        if not isinstance(record, bytes):
            continue
        tags = dict(re.findall(rb"(?:^|;)\s*([A-Za-z]+)\s*=\s*([^;]*)", record))
        if b"p" in tags and tags.get(b"v", b"DKIM1").strip() == b"DKIM1":
            candidates.append(record)
    return candidates[0] if len(candidates) == 1 else None


def verificar_dkim(contenido_eml, dnsfunc=None):
    signatures = re.findall(rb"(?im)^DKIM-Signature\s*:\s*([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)", contenido_eml)
    results = []
    if not signatures:
        return [{"status": "unavailable", "reason": "sin firma DKIM"}]
    if len(signatures) > MAX_DKIM_SIGNATURES:
        signatures = signatures[:MAX_DKIM_SIGNATURES]
    try:
        import dkim
    except ImportError:
        return [{"status": "unavailable", "reason": "dkimpy no instalado"}]
    for index, raw in enumerate(signatures):
        tags = dict((key.lower(), value.strip()) for key, value in re.findall(r"(?:^|;)\s*([a-zA-Z]+)\s*=\s*([^;]+)", raw.decode("ascii", errors="ignore")))
        domain = _normalizar_dominio(tags.get("d", ""))
        selector = tags.get("s", "")[:128]
        if not domain or not selector or not re.fullmatch(r"[A-Za-z0-9._-]+", selector):
            results.append({"status": "unavailable", "domain": domain, "selector": selector, "reason": "firma malformada"})
            continue
        issues = []
        def resolver(name, timeout=5):
            try:
                return (dnsfunc or _dkim_dns_record)(name, timeout=timeout)
            except ImportError:
                raise
            except Exception as error:
                if _dns_transport_error(error):
                    issues.append({"service": "DNS", "reason": "consulta de clave DKIM sin respuesta utilizable"})
                raise
        try:
            verifier = dkim.DKIM(contenido_eml, timeout=5)
            verified = verifier.verify(idx=index, dnsfunc=dnsfunc or resolver)
            results.append({"status": "verified" if verified else "failed", "domain": domain, "selector": selector, "service_issues": issues})
        except Exception:
            results.append({"status": "unavailable", "domain": domain, "selector": selector, "reason": "error de verificación o DNS", "service_issues": issues})
    return results


def verificar_spf(smtp_ip=None, mail_from=None, helo=None):
    if not (smtp_ip and mail_from and helo):
        return "unknown", "falta contexto SMTP completo (EML o --smtp-ip, --mail-from, --helo)"
    try:
        ipaddress.ip_address(smtp_ip)
        if mail_from != " postmaster" and mail_from != "<>" and not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", mail_from):
            raise ValueError()
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", helo) or ".." in helo:
            raise ValueError()
    except ValueError:
        return "unknown", "contexto SMTP inválido"
    try:
        import spf
        _notificar_consulta("DNS (SPF)")
        status, _ = spf.check2(i=smtp_ip, s=mail_from, h=helo, querytime=5)
        reason = "evaluación pyspf de la tupla SMTP; confianza del origen evaluada por separado"
        if status.lower() == "temperror":
            return _AuthResult(status.lower(), reason, [{"service": "DNS", "reason": "SPF: error transitorio de consulta"}])
        return status.lower(), reason
    except ImportError:
        return "unknown", "pyspf no instalado"
    except Exception:
        return "unknown", "error de evaluación SPF"


def _alineado(domain, from_domain, strict):
    domain = _normalizar_dominio(domain)
    if not domain or not from_domain:
        return False
    if strict:
        return domain == from_domain
    if domain == from_domain:
        return True
    try:
        from publicsuffix2 import get_sld
        source, target = get_sld(domain, strict=True), get_sld(from_domain, strict=True)
        return source == target if source and target else None
    except ImportError:
        return None


def _dmarc_records(domain):
    try:
        _notificar_consulta("DNS (DMARC)")
        answers = _dns_txt(f"_dmarc.{domain}")
    except Exception as error:
        if type(error).__name__ in ("NXDOMAIN", "NoAnswer"):
            return []
        raise
    records = []
    for answer in answers:
        text = answer.decode("ascii", errors="strict") if isinstance(answer, bytes) else str(answer)
        if re.match(r"^v\s*=\s*DMARC1(?:\s*;|\s*$)", text.strip(), re.I):
            records.append(text.strip())
    return records


def _parse_dmarc_policy(record):
    tags = {}
    for field in record.split(";"):
        if not field.strip():
            continue
        if "=" not in field:
            raise ValueError("etiqueta DMARC malformada")
        key, value = (part.strip() for part in field.split("=", 1))
        if key in tags or not re.fullmatch(r"[a-z][a-z0-9]*", key):
            raise ValueError("etiqueta DMARC duplicada/inválida")
        tags[key] = value
    policies = ("none", "quarantine", "reject")
    if tags.get("v") != "DMARC1" or tags.get("p") not in policies:
        raise ValueError("versión/política p DMARC ausente o inválida")
    if "sp" in tags and tags["sp"] not in policies:
        raise ValueError("política sp DMARC inválida")
    if any(tags.get(key, "r") not in ("r", "s") for key in ("adkim", "aspf")):
        raise ValueError("modo de alineación DMARC inválido")
    if "pct" in tags and (not tags["pct"].isdigit() or not 0 <= int(tags["pct"]) <= 100):
        raise ValueError("porcentaje DMARC inválido")
    return tags


def verificar_dmarc(from_domain, dkim_results, spf_result):
    if not from_domain:
        return "unknown", "dominio From no disponible"
    policy_domain = from_domain
    try:
        records = _dmarc_records(from_domain)
        if not records:
            try:
                from publicsuffix2 import get_sld
                organization = get_sld(from_domain, strict=True)
            except ImportError:
                return "unknown", "descubrimiento de política organizacional requiere PSL no disponible"
            if not organization:
                return "unknown", "dominio organizacional no determinable mediante PSL"
            if organization != from_domain:
                policy_domain = organization
                records = _dmarc_records(organization)
    except ImportError:
        return "unknown", "biblioteca DNS no disponible"
    except Exception as error:
        issues = [{"service": "DNS", "reason": "consulta DMARC sin respuesta utilizable"}] if _dns_transport_error(error) else []
        return _AuthResult("unknown", "DNS DMARC no disponible", issues)
    if not records:
        return "unavailable", "registro DMARC ausente"
    if len(records) != 1:
        return "permerror", "múltiples registros DMARC; política no válida"
    try:
        tags = _parse_dmarc_policy(records[0])
    except ValueError as error:
        return "permerror", str(error)
    policy = tags.get("sp", tags["p"]) if policy_domain != from_domain else tags["p"]
    policy_evidence = f"política {policy_domain}; {'sp' if policy_domain != from_domain and 'sp' in tags else 'p'}={policy}"
    dkim_strict = tags.get("adkim", "r").lower() == "s"
    spf_strict = tags.get("aspf", "r").lower() == "s"
    dkim_alignment = [_alineado(item.get("domain"), from_domain, dkim_strict) for item in dkim_results if item.get("status") == "verified"]
    spf_alignment = _alineado(spf_result[2], from_domain, spf_strict) if spf_result[0] == "pass" else False
    if (None in dkim_alignment or spf_alignment is None) and not (True in dkim_alignment or spf_alignment is True):
        return "unknown", "alineación relajada requiere biblioteca PSL no disponible"
    aligned_dkim = True in dkim_alignment
    aligned_spf = spf_alignment is True
    if aligned_dkim or aligned_spf:
        return "pass", f"identidad SPF/DKIM verificada y alineada; {policy_evidence}"
    if spf_result[0] == "unknown" or any(item.get("status") == "unavailable" for item in dkim_results):
        return "unknown", "identidad SPF/DKIM no pudo evaluarse completamente"
    return "fail", f"no hay identidad SPF/DKIM verificada y alineada; {policy_evidence}"


def _smtp_value(key, value):
    """Validate header-derived SMTP candidates without DNS or executing content."""
    value = value.strip().strip('"')
    if key == "smtp_ip":
        try:
            return str(ipaddress.ip_address(re.sub(r"^IPv6:", "", value.strip("[]"), flags=re.I)))
        except ValueError:
            return None
    if key == "mail_from":
        if value == "<>":
            return value
        value = value.strip("<>")
        return value if re.fullmatch(r"[^\s<>@;,]+@[^\s<>@;,]+", value) else None
    return value.lower().rstrip(".") if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.?", value) and ".." not in value else None


def _received_spf_parts(header):
    """Split bounded RFC 7208 fields, excluding nested comments and quoted delimiters."""
    parts, field = [], []
    depth, quoted, escaped = 0, False, False
    for char in str(header)[:4096]:
        if escaped:
            if not depth:
                field.append(char)
            escaped = False
        elif char == "\\" and (depth or quoted):
            if quoted and not depth:
                field.append(char)
            escaped = True
        elif depth:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        elif char == '"':
            quoted = not quoted
            field.append(char)
        elif char == "(" and not quoted:
            depth = 1
            field.append(" ")
        elif char == ";" and not quoted:
            parts.append("".join(field))
            field = []
        else:
            field.append(char)
    if depth or quoted or escaped:
        return None
    parts.append("".join(field))
    result = re.match(r"\s*(?:none|neutral|pass|fail|softfail|temperror|permerror)\b", parts[0], re.I)
    if not result:
        return None
    parts[0] = parts[0][result.end():]
    return parts


def extraer_contexto_smtp(correo, trusted_receiver=None):
    """Extract one coherent candidate hop; header claims never establish trust."""
    keys = ("smtp_ip", "mail_from", "helo", "receiver")
    result = dict.fromkeys(keys)
    result.update(sources={}, warnings=[], trusted=False)
    warnings = result["warnings"]
    hops = []
    received = list(correo.get_all("Received", [])[:100])
    for index, header in reversed(list(enumerate(received, 1))):
        text = str(header)[:4096]
        match = re.search(r"\bfrom\s+(.*?)\s+by\s+([^\s;()]+)", text, re.I)
        if not match:
            warnings.append(f"Received[{index}]: formato no interpretable; contexto no determinado")
            continue
        sender, receiver = match.groups()
        # Only the FROM clause contains the SMTP peer, not the BY server's IP.
        sender_name = re.match(r"\s*([^\s()]+)", sender)
        ips = extraer_ip_received([sender])[0]["ips"] if sender_name else []
        helo = re.search(r"\b(?:helo|ehlo)\s*=\s*([^\s;)]+)", sender, re.I)
        helo_value = _smtp_value("helo", helo.group(1) if helo else sender_name.group(1)) if sender_name else None
        if not helo_value or len(ips) != 1:
            warnings.append(f"Received[{index}]: remitente SMTP ausente, incompleto o ambiguo; valores faltantes no determinados")
        hops.append({"smtp_ip": ips[0] if len(ips) == 1 else None,
                     "helo": helo_value,
                     "receiver": _smtp_value("receiver", receiver), "source": f"Received[{index}]"})
    selected = None
    if trusted_receiver is not None:
        matches = [hop for hop in hops if hop["receiver"] == _smtp_value("receiver", trusted_receiver)]
        if len(matches) == 1:
            selected = matches[0]
        elif hops:
            warnings.append("frontera indicada ausente o ambigua en Received; no se elige otro salto")
    elif hops:
        # Received headers are prepended; the first valid candidate from the bottom is earliest.
        selected = next((hop for hop in hops if hop.get("smtp_ip")), None)
    if selected:
        for key in ("smtp_ip", "helo", "receiver"):
            result[key] = selected[key]
            if selected[key] is not None:
                result["sources"][key] = selected["source"]

    records = []
    mapping = {"client-ip": "smtp_ip", "envelope-from": "mail_from", "helo": "helo", "receiver": "receiver"}
    for index, header in enumerate(correo.get_all("Received-SPF", [])[:100], 1):
        fields, invalid = {}, False
        parts = _received_spf_parts(header)
        if parts is None:
            warnings.append(f"Received-SPF[{index}]: sintaxis, comentarios o comillas no válidos; registro descartado")
            continue
        for field in parts:
            match = re.fullmatch(r'\s*(client-ip|envelope-from|helo|receiver)\s*=\s*(.*?)\s*', field, re.I)
            if not match:
                continue
            name, value = match.groups()
            key = mapping[name.lower()]
            if key in fields:
                invalid = True
            fields[key] = _smtp_value(key, value)
            invalid |= fields[key] is None
        if invalid:
            warnings.append(f"Received-SPF[{index}]: valores malformados o duplicados; registro descartado")
            continue
        if not fields:
            continue
        # Bind the SPF record to the selected receiving hop; never stitch hops together.
        receiver = selected["receiver"] if selected else _smtp_value("receiver", trusted_receiver) if trusted_receiver else None
        if (hops or trusted_receiver) and (not receiver or fields.get("receiver") != receiver):
            continue
        records.append((fields, f"Received-SPF[{index}]"))
    unique = {tuple(fields.get(key) for key in keys) for fields, _ in records}
    if len(unique) > 1:
        warnings.append("Received-SPF: registros candidatos contradictorios; contexto no combinado")
        # Preserve a self-contained Received candidate, but do not fill from conflicting SPF records.
    elif records:
        fields, source = records[0]
        conflicting = selected and any(result[key] and fields.get(key) and result[key] != fields[key]
                                       for key in ("smtp_ip", "helo"))
        if conflicting:
            warnings.append("Received y Received-SPF discrepan para el mismo receptor; contexto no determinado")
            for key in ("smtp_ip", "helo"):
                result[key] = None
                result["sources"].pop(key, None)
        else:
            for key, value in fields.items():
                result[key] = value
                result["sources"][key] = source

    paths = correo.get_all("Return-Path", [])
    if len(paths) > 1:
        result["mail_from"] = None
        result["sources"].pop("mail_from", None)
        warnings.append("Return-Path duplicado; MAIL FROM no determinado")
    elif paths:
        envelope = _smtp_value("mail_from", str(paths[0]))
        if not envelope or (result["mail_from"] and result["mail_from"] != envelope):
            result["mail_from"] = None
            result["sources"].pop("mail_from", None)
            warnings.append("Return-Path malformado o contradictorio con envelope-from; MAIL FROM no determinado")
        elif not result["mail_from"]:
            result["mail_from"] = envelope
            result["sources"]["mail_from"] = "Return-Path"
    return result


def extraer_ip_received(headers, trusted_receiver=None):
    hops = []
    bounded_headers = list(headers)[:100]
    for original_index, header in reversed(list(enumerate(bounded_headers, 1))):
        text = str(header)[:4096]
        candidates = []
        for token in re.findall(r"\[([^\]]+)\]|(?<![A-Za-z0-9:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,})", text):
            candidate = token[0] or token[1]
            if candidate.lower().startswith("ipv6:"):
                candidate = candidate[5:]
            try:
                ip = str(ipaddress.ip_address(candidate))
                if ip not in candidates:
                    candidates.append(ip)
            except ValueError:
                continue
        boundary_claimed = bool(trusted_receiver and re.search(r"\bby\s+" + re.escape(trusted_receiver) + r"(?=\s|;|$)", text, re.I))
        hops.append({"ips": candidates[:8], "trusted": False, "boundary_claimed": boundary_claimed,
                     "source": f"Received[{original_index}]"})
    return hops


def _email_identity_evidence(message):
    """Compare single, well-formed domains without filtering malformed identities away."""
    domains, causes, gaps = {}, [], []
    for name in ("From", "Reply-To", "Return-Path"):
        values = [value for field, value in message.raw_items() if field.lower() == name.lower()]
        if not values:
            if name == "From":
                gaps.append("From ausente; identidad no inspeccionable")
            continue
        if name == "Return-Path" and len(values) == 1 and str(values[0]).strip() == "<>":
            gaps.append("Return-Path nulo; dominio SMTP no comparable")
            continue
        try:
            # The email parser rejects a DNS root dot; canonicalize only that valid domain spelling.
            value = re.sub(r"\r?\n[ \t]+", " ", str(values[0]))
            value = re.sub(r"(@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)\.(?=[>\s,;]|$)", r"\1", value)
            header = policy.default.header_factory("From", value)
            addresses = header.addresses
            domain = _normalizar_dominio(addresses[0].domain) if len(addresses) == 1 else ""
            valid = (len(values) == 1 and len(addresses) == 1 and addresses[0].username
                     and not header.defects and domain and extraer_dominio("https://" + domain) == domain
                     and not any(group.display_name is not None for group in header.groups))
            if name == "Return-Path":
                valid = valid and re.fullmatch(r"<[^<>]+>", str(values[0]).strip())
        except (ValueError, IndexError):
            valid = False
        if not valid:
            causes.append(f"{name} presente pero malformado, múltiple o ambiguo (direcciones omitidas)")
        else:
            domains[name] = domain
    for name in ("Reply-To", "Return-Path"):
        if domains.get(name) and domains.get("From") and domains[name] != domains["From"]:
            causes.append(f"Dominio {name} distinto de From")
    return domains, causes, gaps


@_analysis_entrypoint
def analizar_eml(ruta, smtp_ip=None, mail_from=None, helo=None, trusted_receiver=None, emitir=True):
    """Analyze only requested EML evidence and delegate extracted resources."""
    global _EML_DOMAIN_REPORTS, _EML_DOMAIN_INTELLIGENCE
    with abrir_archivo_seguro(ruta) as archivo:
        contenido_eml = archivo.read(MAX_LOCAL_FILE_BYTES + 1)
    if len(contenido_eml) > MAX_LOCAL_FILE_BYTES:
        raise ValueError("El archivo supera el límite de 25 MiB durante la lectura")
    correo = BytesParser(policy=policy.default).parse(io.BytesIO(contenido_eml))

    context = extraer_contexto_smtp(correo, trusted_receiver)
    supplied = {"smtp_ip": smtp_ip, "mail_from": mail_from, "helo": helo}
    for key, value in supplied.items():
        if value is not None:
            context[key] = value
            context["sources"][key] = "argumento"
    smtp_ip, mail_from, helo = (context[key] for key in ("smtp_ip", "mail_from", "helo"))
    smtp_context_available = all(value is not None for value in (smtp_ip, mail_from, helo))

    identity_domains, mismatch_evidence, local_gaps = _email_identity_evidence(correo)
    from_domain = identity_domains.get("From", "")
    authentication_results = _authentication_results(correo)
    header_auth_statuses = {
        check: _authentication_header_status(authentication_results, check)
        for check in ("SPF", "DKIM", "DMARC")
    }
    dkim_results = verificar_dkim(contenido_eml)
    spf_result = verificar_spf(smtp_ip, mail_from, helo)
    spf_domain = _normalizar_dominio(mail_from.rsplit("@", 1)[1]) if mail_from and "@" in mail_from else ""
    spf_alignment = _alineado(spf_domain, from_domain, False)
    independent_spf = spf_result[0] if smtp_context_available else "unknown"
    dmarc_result = verificar_dmarc(
        from_domain, dkim_results,
        (independent_spf, spf_result[1], spf_domain),
    )
    service_issues = list(_service_issues(spf_result)) + list(_service_issues(dmarc_result))
    for signature in dkim_results:
        service_issues.extend(_service_issues(signature))

    hops = extraer_ip_received(correo.get_all("Received", []), trusted_receiver)
    if trusted_receiver:
        claimed = [hop for hop in hops if hop.get("boundary_claimed") and len(hop.get("ips", [])) == 1]
        origin_hop = claimed[0] if len(claimed) == 1 else next((hop for hop in hops if len(hop.get("ips", [])) == 1), None)
    else:
        origin_hop = next((hop for hop in hops if len(hop.get("ips", [])) == 1), None)
    origin = {
        "ip": origin_hop["ips"][0] if origin_hop else "desconocida",
        "header": origin_hop.get("source", "desconocida") if origin_hop else "desconocida",
        "receiver": context.get("receiver") or "desconocido",
        "status": "candidata-no-verificada" if origin_hop else "no-determinada",
    }

    attachments = inventariar_adjuntos(correo)
    urls = []
    inspected_body_parts = 0
    for parte in correo.walk():
        tipo = parte.get_content_type()
        for name in ("Content-Type", "Content-Disposition", "Content-Transfer-Encoding", "MIME-Version"):
            if len(parte.get_all(name, [])) > 1:
                local_gaps.append(f"cabecera MIME duplicada: {name}")
        if str(parte.get("MIME-Version", "1.0")).strip() != "1.0":
            local_gaps.append("versión MIME no cubierta")
        if parte.get_content_disposition() == "attachment" or parte.get_filename():
            local_gaps.append("adjunto con cobertura local parcial")
        if parte.is_multipart():
            if tipo not in ("multipart/mixed", "multipart/alternative", "multipart/related"):
                local_gaps.append(f"contenedor MIME no cubierto: {tipo}")
            continue
        if tipo not in ("text/plain", "text/html"):
            local_gaps.append(f"parte MIME no inspeccionada: {tipo}")
            continue
        encodings = parte.get_all("Content-Transfer-Encoding", [])
        encoding = str(encodings[0]).strip().lower() if encodings else "7bit"
        if len(encodings) > 1 or encoding not in ("7bit", "8bit", "binary", "base64", "quoted-printable"):
            local_gaps.append(f"codificación MIME ambigua: {encoding}")
        payload = parte.get_payload()
        if encoding == "quoted-printable" and isinstance(payload, str) and re.search(r"=(?![0-9a-fA-F]{2}|\r?\n)", payload):
            local_gaps.append("quoted-printable malformado")
        try:
            contenido = parte.get_content(errors="strict")
        except Exception as error:
            local_gaps.append(f"texto no decodificable: {type(error).__name__}")
            continue
        if not isinstance(contenido, str):
            local_gaps.append("parte de texto sin contenido")
            continue
        decoded_payload = parte.get_payload(decode=True)
        if encoding == "7bit" and isinstance(decoded_payload, bytes) and any(byte > 127 for byte in decoded_payload):
            local_gaps.append("bytes no ASCII declarados como 7bit")
        if contenido.strip():
            inspected_body_parts += 1
        if len(contenido.encode("utf-8")) > MAX_DECODE_BYTES:
            local_gaps.append("límite de decodificación alcanzado")
        urls.extend(re.findall(r'https?://[^\s<>"\']+', contenido, flags=re.IGNORECASE))
        decoded_urls = decodificar_candidatos(contenido)
        non_url_text = re.sub(r'https?://[^\s<>"\']+', "", contenido, flags=re.I)
        encoded = bool(decoded_urls) or bool(re.search(r"[A-Za-z0-9+/_-]{20,}={0,2}", non_url_text)) or bool(re.search(r"%[0-9a-fA-F]{2}", contenido))
        if encoded:
            local_gaps.append("contenido codificado: recuperación acotada")
        urls.extend(decoded_urls)
        if tipo == "text/html":
            extractor = ExtractorEnlaces()
            try:
                extractor.feed(contenido)
                extractor.close()
            except (ValueError, AssertionError):
                local_gaps.append("HTML no interpretable")
            urls.extend(extractor.urls)

    if not inspected_body_parts:
        local_gaps.append("sin cuerpo de texto inspeccionable")
    for part in correo.walk():
        defects = list(part.defects) + [defect for name, header in part.items()
                                        if name.lower() not in ("from", "reply-to", "return-path")
                                        for defect in getattr(header, "defects", ())]
        if defects:
            local_gaps.append("defectos MIME: " + ", ".join(sorted({type(defect).__name__ for defect in defects})))
    urls_limpias = []
    seen_url_keys = set()
    for url in urls:
        url = url.rstrip(".,;)")
        cache_key = _normalizar_url_cache_key(url)
        if cache_key not in seen_url_keys:
            seen_url_keys.add(cache_key)
            urls_limpias.append(url)

    analyzed_urls = urls_limpias[:MAX_URLS]
    url_domain_targets = {
        domain for domain in (_safe_domain(extraer_dominio(url)) for url in analyzed_urls) if domain
    }
    shared_domain_intelligence = analizar_inteligencia_dominio(
        analyzed_urls,
        domain_targets=[from_domain] if from_domain else (),
        registry_domains=url_domain_targets,
    )
    domain_reports = shared_domain_intelligence.get("domain_reports", {})
    from_intel = domain_reports.get(from_domain, {"error": "dominio From no disponible"}) if from_domain else {"error": "dominio From no disponible"}
    service_issues.extend(shared_domain_intelligence.get("service_issues", []))
    from_stats = from_intel.get("last_analysis_stats", {}) if validar_informe_vt(from_intel) else {}
    from_malicious = from_stats.get("malicious", 0) if isinstance(from_stats.get("malicious", 0), int) else 0
    from_suspicious = from_stats.get("suspicious", 0) if isinstance(from_stats.get("suspicious", 0), int) else 0

    url_evidences = []
    previous_domain_reports = _EML_DOMAIN_REPORTS
    previous_domain_intelligence = _EML_DOMAIN_INTELLIGENCE
    _EML_DOMAIN_REPORTS = domain_reports
    _EML_DOMAIN_INTELLIGENCE = shared_domain_intelligence
    try:
        for url in analyzed_urls:
            try:
                delegated = analizar_url(url)
            except (ValueError, TypeError, UnicodeError):
                local_gaps.append("URL extraída no válida para el flujo URL")
                delegated = {
                    "resource_type": "url", "criteria": {
                        "domain": criterio("unknown", "URL no válida"),
                        "detections": criterio("unknown", "URL no válida"),
                        "behavior": criterio("unknown", "URL no válida"),
                    }, "optional_criteria": {}, "resources": [], "service_issues": [],
                    "concrete_causes": [], "report": {"virustotal": {"url": "unknown"}},
                }
            if isinstance(delegated, dict):
                url_evidences.append((url, delegated))
                service_issues.extend(_service_issues(delegated))
    finally:
        _EML_DOMAIN_REPORTS = previous_domain_reports
        _EML_DOMAIN_INTELLIGENCE = previous_domain_intelligence
    if len(urls_limpias) > MAX_URLS:
        local_gaps.append("URLs omitidas por límite de análisis")

    url_resources, url_detection_checks, url_behavior_checks, url_reputation_checks = [], [], [], []
    url_causes = []
    for url, delegated in url_evidences:
        criteria = delegated.get("criteria", {})
        optional = delegated.get("optional_criteria", {})
        url_detection_checks.append(criteria.get("detections", criterio("unknown", "URL")))
        url_behavior_checks.append(optional.get("remote_behavior", criterio("unknown", "URLscan")))
        url_reputation_checks.append(optional.get("community_reputation", criterio("unknown", "VT")))
        service_issues.extend(delegated.get("service_issues", []))
        url_causes.extend(delegated.get("concrete_causes", []))
        url_resources.append({
            "source": url,
            "report_available": bool(delegated.get("report_available")),
            "malicious": delegated.get("malicious", 0),
            "suspicious": delegated.get("suspicious", 0),
            "confirmed_phishing": delegated.get("confirmed_phishing", False),
            "high_phishing_risk": delegated.get("high_phishing_risk", False),
        })

    attachment_resources, attachment_detection_checks, attachment_reputation_checks = [], [], []
    attachment_behavior_checks, attachment_causes = [], []
    for attachment in attachments:
        evidence = attachment.get("evidence")
        if not isinstance(evidence, dict):
            continue
        service_issues.extend(evidence.get("service_issues", []))
        attachment_detection_checks.append(evidence["criteria"]["detections"])
        attachment_reputation_checks.append(evidence["optional_criteria"]["community_reputation"])
        attachment_behavior_checks.append(evidence["criteria"]["behavior"])
        attachment_causes.extend(evidence.get("concrete_causes", []))
        attachment_resources.append({
            "source": f"archivo:{attachment['name']}",
            "report_available": bool(evidence.get("report_available")),
            "malicious": evidence.get("malicious", 0),
            "suspicious": evidence.get("suspicious", 0),
            "executable": evidence.get("executable", False),
        })

    verified_dkim_aligned = any(signature.get("status") == "verified" and _alineado(signature.get("domain"), from_domain, False) is True for signature in dkim_results)
    dkim_statuses = [signature.get("status") for signature in dkim_results]
    independent_dkim = _dkim_independent_status(dkim_results)
    independent_dmarc = dmarc_result[0]
    header_spf = header_auth_statuses["SPF"]
    header_dkim = header_auth_statuses["DKIM"]
    header_dmarc = header_auth_statuses["DMARC"]
    effective_spf = _effective_authentication_status(independent_spf, header_spf)
    effective_dkim = _dkim_report_status(independent_dkim, header_dkim)
    effective_dmarc = _effective_authentication_status(independent_dmarc, header_dmarc)

    independent_statuses = {
        "SPF": independent_spf,
        "DKIM": {"verified": "pass", "failed": "fail"}.get(independent_dkim, independent_dkim),
        "DMARC": independent_dmarc,
    }
    header_statuses = {"SPF": header_spf, "DKIM": header_dkim, "DMARC": header_dmarc}
    contradictions = []
    for check, independent_status in independent_statuses.items():
        header_status = header_statuses[check]
        if header_status is None:
            continue
        independent_class = _authentication_status_class(independent_status)
        header_class = _authentication_status_class(header_status)
        if independent_class in ("pass", "fail") and header_class in ("pass", "fail") and independent_class != header_class:
            contradictions.append({"check": check, "independent": independent_status, "header": header_status})

    spf_alignment_failure = bool(smtp_context_available and from_domain and spf_domain and spf_alignment is False)
    auth_failed_checks = []
    if (
        independent_spf in _AUTHENTICATION_FAILURES
        or header_spf in _AUTHENTICATION_FAILURES
        or spf_alignment_failure
    ):
        auth_failed_checks.append("SPF")
    if independent_dkim == "failed" or header_dkim in _AUTHENTICATION_FAILURES:
        auth_failed_checks.append("DKIM")
    if independent_dmarc in _AUTHENTICATION_FAILURES or header_dmarc in _AUTHENTICATION_FAILURES:
        auth_failed_checks.append("DMARC")
    auth_failed_checks = sorted(set(auth_failed_checks))

    spf_supported = (independent_spf == "pass" and spf_alignment is True) or (
        independent_spf in _AUTHENTICATION_FALLBACKS and header_spf == "pass"
    )
    dkim_supported = (independent_dkim == "verified" and verified_dkim_aligned) or (
        independent_dkim in _AUTHENTICATION_FALLBACKS and header_dkim == "pass"
    )
    dmarc_supported = independent_dmarc == "pass" or (
        independent_dmarc in _AUTHENTICATION_FALLBACKS and header_dmarc == "pass"
    )
    auth_bad = bool(auth_failed_checks or contradictions)
    auth_pass = bool(spf_supported and dkim_supported and dmarc_supported and not auth_bad)
    auth_alerts = list(auth_failed_checks)
    auth_header_summary = ",".join(
        f"{check}={header_statuses[check]}"
        for check in ("SPF", "DKIM", "DMARC")
        if header_statuses[check] is not None
    ) or "sin resultados reconocidos"
    auth_check = criterio(
        "pass" if auth_pass else "fail" if auth_bad else "unknown",
        f"SPF={effective_spf}; SPF_alineado={spf_alignment}; DKIM={effective_dkim}; "
        f"DKIM_cryptographic={','.join(dkim_statuses)}; DKIM_alineado={verified_dkim_aligned}; "
        f"DMARC={effective_dmarc}; Authentication-Results={auth_header_summary}",
    )

    from_domain_check = evaluar_dominio(from_domain, from_intel, {"registration_date": None})
    url_domain_checks = [item.get("criteria", {}).get("domain") for _, item in url_evidences]
    domain_check = combinar_criterios([from_domain_check] + [item for item in url_domain_checks if isinstance(item, dict)], empty="unknown")
    detection_check = combinar_criterios([criterio_detecciones(from_intel)] + url_detection_checks + attachment_detection_checks, empty="unknown")
    if len(attachments) > MAX_EML_ATTACHMENTS or any("evidence" not in item for item in attachments):
        local_gaps.append("adjuntos omitidos o no decodificables")
        detection_check = combinar_criterios([detection_check, criterio("unknown", "recursos omitidos")])
    local_inspection = criterio("unknown" if local_gaps else "pass", f"partes={inspected_body_parts}; gaps={'; '.join(dict.fromkeys(local_gaps)) if local_gaps else 'ninguno'}")
    behavior_check = combinar_criterios([local_inspection] + attachment_behavior_checks)

    concrete_causes = mismatch_evidence + url_causes + attachment_causes
    if from_malicious or from_suspicious:
        concrete_causes.append(f"Dominio From {from_domain}: VT maliciosos={from_malicious}; sospechosos={from_suspicious}")
    if auth_alerts:
        concrete_causes.append("fallos de autenticación: " + ", ".join(auth_alerts))
    if contradictions:
        concrete_causes.append("resultados de autenticación contradictorios: " + ", ".join(item["check"] for item in contradictions))
    url_reports = []
    urlscan_reports, delegated_whois, delegated_crt = [], [], []
    for url, delegated in url_evidences:
        delegated_report = delegated.get("report", {})
        url_reports.append({"url": _redact_display_url(url), "virustotal": delegated_report.get("virustotal", {})})
        if delegated_report.get("urlscan"):
            urlscan_reports.append({"url": _redact_display_url(url), **delegated_report["urlscan"]})
        delegated_whois.extend(delegated_report.get("whois", []))
        delegated_crt.extend(delegated_report.get("crt_sh", []))
    attachment_reports = [item["evidence"].get("report", {}).get("file", {}) for item in attachments if isinstance(item.get("evidence"), dict)]
    authentication_report = {
        "SPF": effective_spf,
        "SPF_independent": independent_spf,
        "DKIM": effective_dkim,
        "DKIM_cryptographic": ",".join(dkim_statuses) or "unavailable",
        "DMARC": effective_dmarc,
        "DMARC_independent": independent_dmarc,
        "SPF_alignment": spf_alignment,
        "DKIM_alignment": verified_dkim_aligned,
    }
    if authentication_results:
        authentication_report["Authentication-Results"] = authentication_results
    if contradictions:
        authentication_report["contradictions"] = contradictions
    report = {
        "authentication": authentication_report,
        "identities": {"From": identity_domains.get("From", "desconocido"),
                       "Reply-To": identity_domains.get("Reply-To", "desconocido"),
                       "Return-Path": identity_domains.get("Return-Path", "desconocido"),
                       "status": "inconsistent" if mismatch_evidence else "consistent" if identity_domains.get("From") else "incomplete"},
        "origin": origin,
        "virustotal": {"domains": shared_domain_intelligence.get("domains", []),
                        "urls": url_reports, "files": [{"name": item.get("name"), "sha256": item.get("sha256"),
                                                          "status": item.get("evidence", {}).get("report", {}).get("virustotal", {}).get("report", "unknown")}
                                                         for item in attachments]},
        "urlscan": urlscan_reports,
        "file": attachment_reports,
    }
    if delegated_whois:
        report["whois"] = delegated_whois
    if delegated_crt:
        report["crt_sh"] = delegated_crt
    verdict_evidence = {
        "resource_type": "eml",
        "resources": url_resources + attachment_resources + ([{"source": f"Dominio From {from_domain}", "malicious": from_malicious,
                                                               "suspicious": from_suspicious, "report_available": True}] if validar_informe_vt(from_intel) else []),
        "high_phishing_risk": any(item.get("high_phishing_risk") for item in url_resources),
        "auth_failure": bool(auth_alerts),
        "auth_failed_checks": auth_failed_checks,
        "mixed": bool(mismatch_evidence or from_malicious or from_suspicious),
        "report_available": bool(url_resources or attachment_resources) or validar_informe_vt(from_intel),
        "criteria": {"authentication": auth_check, "domain": domain_check, "detections": detection_check, "behavior": behavior_check},
        "local_inspection": local_inspection,
        "optional_criteria": {"remote_behavior": combinar_criterios(url_behavior_checks),
                              "community_reputation": combinar_criterios([_community_reputation_check(from_intel)] + url_reputation_checks + attachment_reputation_checks)},
        "concrete_causes": concrete_causes,
        "service_issues": [{"service": service, "reason": reason} for service, reason in
                           dict.fromkeys((issue["service"], issue["reason"]) for issue in service_issues if isinstance(issue, dict) and issue.get("service") and issue.get("reason"))],
        "report": report,
    }
    return imprimir_veredicto(verdict_evidence) if emitir else verdict_evidence


def analizar_recurso(recurso):
    """Route a URL or local resource without activating local content."""
    if recurso.lower().startswith(("http://", "https://")):
        return analizar_url(recurso)
    if recurso.lower().endswith(".eml"):
        return analizar_eml(recurso)
    return analizar_archivo(recurso)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analizador local de correos, URLs y archivos con VirusTotal"
    )

    parser.add_argument(
        "archivo",
        help="Ruta de un .eml, una URL HTTP(S) o un archivo local"
    )
    parser.add_argument("--smtp-ip", help="IP SMTP observada por una frontera confiable")
    parser.add_argument("--mail-from", help="MAIL FROM original registrado por una frontera confiable")
    parser.add_argument("--helo", help="HELO/EHLO original registrado por una frontera confiable")
    parser.add_argument("--trusted-receiver", help="Seleccionar receptor exacto en Received/Received-SPF; no autentica las cabeceras")

    args = parser.parse_args()
    _CONFIG = cargar_configuracion_env()
    VT_API_KEY = _CONFIG["VT_API_KEY"]
    if args.archivo.lower().endswith(".eml"):
        analizar_eml(args.archivo, args.smtp_ip, args.mail_from, args.helo, args.trusted_receiver)
    else:
        analizar_recurso(args.archivo)
