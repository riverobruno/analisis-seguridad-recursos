
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
import threading
import time
import textwrap
import tempfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
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
MAX_URLS = 5  # Limita las consultas a VirusTotal
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
MAX_EML_URL_EVIDENCE = 5
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
    if not VT_API_KEY:
        return {"error": "API key de VirusTotal no configurada"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    request = Request(
        endpoint,
        headers={
            "x-apikey": VT_API_KEY,
            "accept": "application/json"
        }
    )

    try:
        with urlopen(request, timeout=15) as respuesta:
            datos = json.load(respuesta)

        attributes = datos["data"]["attributes"]
        if not isinstance(attributes, dict) or not validar_informe_vt(attributes):
            return _service_error("VirusTotal", "Informe de VirusTotal incompleto o no válido")
        return attributes

    except HTTPError as error:
        if error.code == 404:
            return {"error": "URL sin informe disponible en VirusTotal"}
        if error.code == 401:
            return _service_error("VirusTotal", "API key inválida o no autorizada")
        if error.code == 403:
            return _service_error("VirusTotal", "Acceso denegado por VirusTotal")
        if error.code == 429:
            return _service_error("VirusTotal", "Límite de consultas de la API alcanzado")

        return _service_error("VirusTotal", f"Error HTTP {error.code}")

    except (URLError, TimeoutError):
        return _service_error("VirusTotal", "Error de conexión con VirusTotal")

    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return _service_error("VirusTotal", "Respuesta de VirusTotal no válida")



def consultar_virustotal_archivo(sha256):
    """Fetch an existing VirusTotal file report by SHA-256; never upload a file."""
    if not VT_API_KEY:
        return {"error": "API key de VirusTotal no configurada"}
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}
    return _consultar_virustotal_archivo_con_cuota(sha256)


def _consultar_virustotal_archivo_con_cuota(sha256):
    request = Request(
        f"{VT_BASE_URL}/files/{sha256}",
        headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=15) as response:
            data = json.load(response)
        attributes = data["data"]["attributes"]
        if not isinstance(attributes, dict) or not validar_informe_vt(attributes):
            return _service_error("VirusTotal", "Informe de VirusTotal incompleto o no válido")
        return attributes
    except HTTPError as error:
        messages = {404: "Archivo sin informe disponible en VirusTotal", 401: "API key inválida o no autorizada", 403: "Acceso denegado por VirusTotal", 429: "Límite de consultas de la API alcanzado"}
        return {"error": messages.get(error.code, f"Error HTTP {error.code}")} if error.code == 404 else _service_error("VirusTotal", messages.get(error.code, f"Error HTTP {error.code}"))
    except (URLError, TimeoutError, OSError):
        return _service_error("VirusTotal", "Error de conexión con VirusTotal")
    except (ValueError, KeyError, TypeError):
        return _service_error("VirusTotal", "Respuesta de VirusTotal no válida")



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
        return criterio("unknown", "VirusTotal: cero detecciones pero ningún motor completó un resultado harmless/undetected; timeout/failure/type-unsupported no prueba ausencia de amenazas")
    return criterio("fail" if count else "pass", f"VirusTotal: {stats['malicious']} maliciosos, {stats['suspicious']} sospechosos; {len(report['last_analysis_results'])} motores; cero detecciones no basta por sí solo")


def evaluar_dominio(domain, report, registry):
    detection = criterio_detecciones(report)
    reputation = report.get("reputation")
    healthy = isinstance(reputation, int) and not isinstance(reputation, bool) and reputation > 0
    negative = isinstance(reputation, int) and not isinstance(reputation, bool) and reputation < 0
    age = None
    try:
        created = datetime.fromisoformat(registry.get("registration_date", "").replace("Z", "+00:00"))
        created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
        age = (datetime.now(timezone.utc) - created).days
        if age < 0:
            age = None
    except (ValueError, TypeError, AttributeError):
        pass
    state = "fail" if detection["status"] == "fail" or negative or (age is not None and age < ESTABLISHED_DOMAIN_DAYS) else "pass" if detection["status"] == "pass" and healthy and age is not None else "unknown"
    return criterio(state, f"Dominio {domain}: creación WHOIS={registry.get('registration_date', 'desconocida')}; antigüedad={age if age is not None else 'desconocida'} días (establecido >= {ESTABLISHED_DOMAIN_DAYS}); reputación VT={reputation if reputation is not None else 'desconocida'}; {detection['evidence']}")


def evaluar_comportamiento_url(url, attributes, scan):
    source = extraer_dominio(url)
    targets = []
    chain = attributes.get("redirection_chain", [])
    if isinstance(chain, list):
        targets.extend(item.get("url") if isinstance(item, dict) else item for item in chain)
    if isinstance(attributes.get("last_final_url"), str):
        targets.append(attributes["last_final_url"])
    vt_external = any(isinstance(target, str) and extraer_dominio(target) not in (None, source) for target in targets)
    vt_phishing = validar_informe_vt(attributes) and any(item.get("category") == "malicious" and re.search("phish", str(item.get("result", "")), re.I) for item in attributes["last_analysis_results"].values())
    scan_targets = list(scan.get("redirects", []))
    scan_targets.append(scan.get("final_url"))
    external = any(isinstance(target, str) and extraer_dominio(target) not in (None, source) for target in scan_targets)
    credential = scan.get("credentials", "unknown")
    confirmed = bool(vt_phishing and vt_external) or bool(scan.get("malicious") is True and scan.get("phishing") is True and credential == "password_input" and external)
    risk = confirmed or scan.get("malicious") is True or scan.get("phishing") is True
    observed = bool(scan.get("behavior_observed") and scan.get("uuid") and not scan.get("reason"))
    normal = bool(observed and scan.get("malicious") is False and scan.get("phishing") is False and credential == "not_observed" and not external and extraer_dominio(scan.get("final_url", "")) == source)
    state = "fail" if risk or credential == "password_input" or external else "pass" if normal else "unknown"
    detail = f"urlscan: observado={observed}, malicioso={scan.get('malicious', 'desconocido')}, phishing={scan.get('phishing', 'desconocido')}, credenciales={credential}, redirección externa={external}; VT phishing malicioso+redirección externa={bool(vt_phishing and vt_external)}"
    return {"behavior_check": criterio(state, detail), "confirmed_phishing": confirmed,
            "high_phishing_risk": bool(risk), "concrete_causes": [detail] if risk else []}


def evaluar_evidencia(evidencia):
    """Return a conservative resource-aware triage verdict from normalized evidence."""
    reasons = []
    resources = [evidencia] + evidencia.get("resources", [])
    auth_failed_checks = sorted({str(check).upper() for check in evidencia.get("auth_failed_checks", [])
                                 if str(check).upper() in {"SPF", "DKIM", "DMARC"}})
    if evidencia.get("resource_type") == "eml" and len(auth_failed_checks) >= 2:
        return "Infectado", ["fallos verificados en métricas de autenticación: " + ", ".join(auth_failed_checks)]
    detections = False
    for resource in resources:
        malicious = int(resource.get("malicious", 0) or 0)
        suspicious = int(resource.get("suspicious", 0) or 0)
        detections = detections or bool(malicious or suspicious)
        if malicious or suspicious:
            reasons.append(f"{resource.get('source', 'un recurso')}: {malicious} motores maliciosos y {suspicious} sospechosos")
        bad_executable = resource.get("executable") is True and resource.get("report_available") is True and malicious > 0
        if malicious >= MALICIOUS_CONSENSUS_THRESHOLD:
            return "Infectado", reasons + [f"consenso de al menos {MALICIOUS_CONSENSUS_THRESHOLD} motores maliciosos sobre el mismo recurso"]
        if bad_executable:
            return "Infectado", reasons + ["hash SHA-256 de ejecutable reportado MALICIOSO por VirusTotal; no solo conocido"]
        if resource.get("confirmed_phishing"):
            return "Infectado", reasons + ["phishing corroborado por señal maliciosa y redirección/credenciales observadas"]
    high_phishing = any(resource.get("high_phishing_risk") for resource in resources)
    if detections or high_phishing or evidencia.get("auth_failure") or evidencia.get("mixed"):
        if evidencia.get("auth_failure"):
            reasons.append("fallo de autenticación/alineación")
        return "Sospechoso", reasons or ["señales mixtas"]
    checks = evidencia.get("criteria", {})
    required = ("authentication", "domain", "detections", "behavior")
    if all(key in checks and checks[key].get("status") in ("pass", "na") for key in required) and all(checks[key].get("status") == "pass" for key in ("detections", "behavior")):
        kind = evidencia.get("resource_type")
        if kind in ("eml", "url") and checks["domain"]["status"] != "pass":
            return "Sospechoso", ["dominio sin evidencia positiva suficiente"]
        if kind == "eml" and checks["authentication"]["status"] != "pass":
            return "Sospechoso", ["autenticación del EML no verificada y alineada"]
        return "Legítimo", ["todos los criterios obligatorios aplicables corroborados; no es garantía de seguridad"]
    return "Sospechoso", ["evidencia insuficiente para confirmar legitimidad"]


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


def imprimir_veredicto(evidencia):
    verdict, reasons = evaluar_evidencia(evidencia)
    def line(value, prefix="", continuation="  "):
        safe = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
        print(textwrap.fill(safe, width=88, initial_indent=prefix,
                            subsequent_indent=continuation))
    print("\n" + "=" * 72)
    print(f"VEREDICTO FINAL: {verdict}")
    print("=" * 72)
    print("Por qué:")
    for reason in dict.fromkeys(reasons + evidencia.get("concrete_causes", [])):
        line(reason, "  - ", "    ")
    print("\nCriterios del análisis:")
    labels = {"authentication": "Autenticación", "domain": "Dominio",
              "detections": "Detecciones", "behavior": "Comportamiento"}
    states = {"pass": "Favorable", "fail": "Alerta", "unknown": "No verificado", "na": "No aplica"}
    for name, label in labels.items():
        check = evidencia.get("criteria", {}).get(name, criterio("unknown", "evidencia insuficiente"))
        print(f"  {label}: {states.get(check['status'], 'No verificado')}")
        for detail in dict.fromkeys(str(check["evidence"]).split("; ")):
            line(detail, "    - ", "      ")
    issues = {(item["service"], item["reason"]) for item in evidencia.get("service_issues", [])}
    if issues:
        print("\nDatos externos no disponibles:")
        for service, reason in sorted(issues):
            line(f"{service}: {reason}", "  - ", "    ")
    print()
    line(f"Umbrales: {MALICIOUS_CONSENSUS_THRESHOLD} motores maliciosos coincidentes en un mismo recurso; dominio establecido desde {ESTABLISHED_DOMAIN_DAYS} días. Un formulario o un hash conocido no confirman infección.")
    return verdict


def resumen_vt(attributes):
    if "error" in attributes:
        print(f"VirusTotal: {attributes['error']} (análisis no disponible; no equivale a cero detecciones)")
        return {"report_available": False, "malicious": 0, "suspicious": 0}
    if not validar_informe_vt(attributes):
        print("VirusTotal: informe incompleto o no válido; detecciones no verificables")
        return {"report_available": False, "malicious": 0, "suspicious": 0}
    stats = attributes["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    print(f"VirusTotal: {malicious} maliciosos; {suspicious} sospechosos")
    causes = [f"VirusTotal motor {engine}: {item.get('category')} ({str(item.get('result', 'sin detalle'))[:160]})"
              for engine, item in attributes['last_analysis_results'].items()
              if item.get('category') in ('malicious', 'suspicious')]
    return {"report_available": True, "malicious": malicious, "suspicious": suspicious,
            "concrete_causes": causes}


def _print_urlscan(scan):
    print(f"URLscan privado: {scan.get('reason', scan.get('status', 'no evaluado'))}")
    if not scan.get("screenshot"):
        return
    print(f"URLscan UUID: {scan['uuid']}; captura para revisión MANUAL: {scan['screenshot']} (no inspeccionada automáticamente)")
    print(f"URL final: {scan.get('final_url', 'desconocida')}; IP: {scan.get('ip', 'desconocida')}; país: {scan.get('country', 'desconocido')}; dominios contactados: {', '.join(scan.get('domains', []))}")
    print(f"Redirecciones observadas: {', '.join(scan.get('redirects', [])) or 'sin datos observados'}")
    credential = scan.get("credentials", "unknown")
    if credential == "password_input":
        print("Solicitud de credenciales: campo password observado en DOM urlscan; no confirma phishing ni envío de datos")
    elif credential == "not_observed":
        print("Solicitud de credenciales: no se observaron campos password en DOM estático; no excluye formularios dinámicos")
    else:
        print("Solicitud de credenciales: no evaluada automáticamente (captura para revisión manual)")


def _url_relationships(url):
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    gaps = []
    for relation in ("last_serving_ip_address",):
        related = _relacion_vt("urls", identifier, relation)
        print(f"VirusTotal URL {relation}: {', '.join(related.get('names', [])) or related.get('error', 'sin relaciones observadas')}")
        if related.get("error"):
            gaps.extend(_service_issues(related))
    return gaps


def analizar_url(url):
    _vt_cache.clear()
    if not validar_url(url):
        raise ValueError("Se requiere una URL HTTP(S) con dominio válido")
    if url_contiene_secretos(url):
        print("Consulta remota omitida: URL con credenciales, fragmento o consulta.")
        return imprimir_veredicto({"report_available": False, "criteria": {"behavior": criterio("unknown", "análisis remoto omitido por privacidad")}})
    result = analizar_reputacion(url)
    attributes = result["_report"]
    domain_result = analizar_inteligencia_dominio([url])
    domain_result = domain_result if isinstance(domain_result, dict) else {}
    result["service_issues"] = list(_service_issues(domain_result))
    result["service_issues"].extend(_url_relationships(url))
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
                          "detections": criterio_detecciones(attributes), "behavior": behavior["behavior_check"]}
    return imprimir_veredicto(result)


def analizar_comportamiento_remoto_url(url, report):
    """Share remote-only behavior reporting for standalone and extracted URLs."""
    for field, label in (("redirection_chain", "redirecciones"), ("last_final_url", "URL final"), ("outgoing_links", "enlaces salientes")):
        value = report.get(field)
        values = value if isinstance(value, list) else [value]
        targets = [item.get("url") if isinstance(item, dict) else item for item in values[:20]]
        safe_targets = [_redact_display_url(item) for item in targets if isinstance(item, str) and validar_url(item)]
        if safe_targets:
            print(f"VirusTotal {label}: {', '.join(safe_targets)} (informe existente)")
    scan = {}
    enabled = bool(_urlscan_key())
    if enabled:
        print("ADVERTENCIA: urlscan.io recibe la URL para navegarla remotamente en un escaneo privado; no se visita ni resuelve el destino localmente. El filtro local es solo de mejor esfuerzo; urlscan gobierna la resolución y redirecciones remotas.")
        scan = consultar_urlscan_privado(url)
        _print_urlscan(scan)
    behavior = evaluar_comportamiento_url(url, report, scan)
    behavior["service_issues"] = _service_issues(scan)
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


def analizar_archivo(ruta):
    print("Análisis de archivos SOLO ESTÁTICO: lectura binaria, SHA-256 y reputación por hash; nunca se ejecuta el archivo.")
    digest = hashlib.sha256()
    prefix = bytearray()
    with abrir_archivo_seguro(ruta) as stream:
        initial = os.fstat(stream.fileno())
        remaining = initial.st_size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("El archivo cambió durante la lectura (fin prematuro)")
            digest.update(chunk)
            if len(prefix) < 8192:
                prefix.extend(chunk[:8192 - len(prefix)])
            remaining -= len(chunk)
        final = os.fstat(stream.fileno())
        if (final.st_size, final.st_mtime_ns, final.st_ctime_ns) != (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns):
            raise OSError("El archivo cambió durante la lectura")
    sha256 = digest.hexdigest()
    print(f"Tamaño real: {initial.st_size} bytes")
    print(f"Nombre local: {os.path.basename(os.fspath(ruta))}")
    print(f"SHA-256: {sha256}")
    detected, basis = detectar_tipo(bytes(prefix))
    print(f"Tipo detectado: {detected} ({basis})")
    ext_type = tipo_por_extension(os.path.splitext(os.fspath(ruta))[1])
    mismatch = bool(ext_type and detected != "desconocido" and ext_type != detected)
    if mismatch:
        print(f"ADVERTENCIA: extensión incompatible con el tipo detectado ({ext_type} vs {detected})")
    with abrir_archivo_seguro(ruta) as script_stream:
        script_bytes = script_stream.read(MAX_LOCAL_FILE_BYTES + 1)
    script_status = analizar_scripts_embebidos(script_bytes[:MAX_LOCAL_FILE_BYTES], detected)
    print(f"Análisis de scripts embebidos: {script_status}")
    if detected == "ZIP/OOXML" and initial.st_size <= MAX_LOCAL_FILE_BYTES:
        with abrir_archivo_seguro(ruta) as archive_stream:
            archive_bytes = archive_stream.read(MAX_LOCAL_FILE_BYTES + 1)
        if len(archive_bytes) <= MAX_LOCAL_FILE_BYTES:
            print(f"Marcadores OOXML VBA: {'presentes' if indicadores_ooxml(archive_bytes) else 'no observados en miembros acotados'} (no exhaustivo)")
        else:
            print("Marcadores OOXML VBA: no evaluado (límite de lectura)")
    macro_status = analizar_macros_local(ruta, initial.st_size, detected)
    print(f"Análisis estático de macros: {macro_status}")
    vt_report = consultar_virustotal_archivo(sha256)
    evidence = resumen_vt(vt_report)
    evidence["service_issues"] = _service_issues(vt_report)
    evidence.setdefault("concrete_causes", []).append(f"Archivo SHA-256 {sha256}; tipo {detected}; {script_status}; macros: {macro_status}")
    if evidence.get("report_available"):
        print_metadatos_vt_archivo(vt_report)
    evidence["resource_type"] = "file"
    evidence["executable"] = detected in ("PE", "ELF", "Mach-O", "script")
    evidence["criteria"] = {"authentication": criterio("na", "archivo, no correo"),
                            "domain": criterio("na", "archivo local, no dominio"),
                            "detections": criterio_detecciones(vt_report),
                            "behavior": evaluar_comportamiento_archivo(detected, script_status, macro_status, initial.st_size)}
    if mismatch:
        evidence["mixed"] = True
        evidence.setdefault("concrete_causes", []).append("extensión incompatible con firmas del contenido")
    return imprimir_veredicto(evidence)


def detectar_tipo(data):
    if data.startswith(b"MZ"): return "PE", "firma MZ (heurística; cabecera PE no validada)"
    if data.startswith(b"\x7fELF"): return "ELF", "firma ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"): return "Mach-O", "firma binaria"
    if data.startswith(b"%PDF-"): return "PDF", "firma PDF"
    if data.startswith(b"PK\x03\x04"): return "ZIP/OOXML", "firma ZIP; contenido OOXML no garantizado"
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
    return ("marcadores de scripts embebidos presentes" if observed else "scripts embebidos no observados") + " (inspección estática acotada, no exhaustiva; no ejecuta contenido)"


def evaluar_comportamiento_archivo(detected, scripts, macros, size):
    if detected == "desconocido" or size > MAX_LOCAL_FILE_BYTES or scripts.startswith("no evaluado"):
        return criterio("unknown", f"tipo={detected}; {scripts}; lectura de contenido acotada")
    if "presentes" in scripts or "macros VBA detectadas;" in macros:
        return criterio("fail", f"contenido activo observado; {scripts}; {macros}; no confirma ejecución ni payload")
    if detected in ("OLE", "ZIP/OOXML") and macros.startswith("no evaluado"):
        return criterio("unknown", f"macros Office no evaluadas: {macros}")
    if detected in ("PE", "ELF", "Mach-O", "script"):
        return criterio("unknown", "contenido ejecutable identificado; ausencia de marcadores textuales no prueba comportamiento normal; sin evidencia positiva de comportamiento del proveedor, no se ejecuta localmente")
    return criterio("pass", f"inspección estática de todo el archivo acotado: tipo={detected}; {scripts}; {macros}; no equivale a sandbox dinámico")


def analizar_macros_local(path, size, detected):
    if size > MAX_LOCAL_FILE_BYTES or detected not in ("OLE", "ZIP/OOXML"):
        return "no evaluado (tipo no compatible o archivo mayor a 25 MiB)"
    try:
        if detected == "ZIP/OOXML":
            _validar_metadatos_zip_macros(path)
        from oletools.olevba import VBA_Parser
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


def print_metadatos_vt_archivo(attributes):
    if not validar_informe_vt(attributes): return
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
        print(f"VirusTotal {key}: {value if value not in (None, '') else 'desconocido'} (fuente: VirusTotal)")
    for key in ("type_description", "type_tag", "size", "names", "first_submission_date", "first_seen", "last_analysis_date"):
        display(key)


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
    print("Adjuntos: análisis SOLO ESTÁTICO; se leen bytes y metadatos, nunca se ejecutan.")
    entries, total = [], 0
    for part in correo.walk():
        if part.is_multipart() or (part.get_content_disposition() != "attachment" and not part.get_filename()):
            continue
        if len(entries) >= MAX_EML_ATTACHMENTS:
            print("Adjuntos: inventario truncado por límite de cantidad."); break
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            entries.append({"name": "adjunto-sin-nombre", "status": "no evaluado (contenido no decodificable)"}); continue
        name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(part.get_filename() or "adjunto-sin-nombre"))[:120]
        if total + len(payload) > MAX_EML_ATTACHMENT_BYTES:
            entries.append({"name": name, "status": "no evaluado (límite total de bytes)"}); print("Adjuntos: inventario truncado por límite total de bytes."); break
        total += len(payload)
        detected, basis = detectar_tipo(payload[:8192])
        sha256 = hashlib.sha256(payload).hexdigest()
        script_status = analizar_scripts_embebidos(payload, detected)
        macros = "no aplica (no Office)"
        if detected in ("OLE", "ZIP/OOXML"):
            with tempfile.TemporaryDirectory(prefix="triage-static-") as directory:
                path = os.path.join(directory, "attachment.bin")
                with open(path, "wb") as stream:
                    stream.write(payload)
                macros = analizar_macros_local(path, len(payload), detected)
        print(f"Adjunto {name}: MIME={part.get_content_type()}, tamaño real={len(payload)} bytes, SHA-256={sha256}, tipo={detected} ({basis}); macros: {macros}; scripts embebidos: {script_status}")
        entries.append({"name": name, "sha256": sha256, "status": "inventariado", "script_status": script_status,
                        "macros": macros, "type": detected, "size": len(payload)})
    return entries


def analizar_reputacion(url):
    """Normalize one URL report; relationship queries are scheduled separately."""
    print(f"URL: {_redact_display_url(url)}")
    report = consultar_virustotal(url)
    result = resumen_vt(report)
    result["_report"] = report
    if not result["report_available"]:
        return dict(result, status="desconocido")
    print(f"VirusTotal URL: reputación={report.get('reputation', 'desconocida')}; estadísticas={report['last_analysis_stats']}")
    print(f"Último análisis (VirusTotal): {report.get('last_analysis_date', 'desconocido')}")
    for cause in result.get("concrete_causes", []):
        print(cause)
    behavior = evaluar_comportamiento_url(url, report, {})
    status = "malicioso" if result["malicious"] >= MALICIOUS_CONSENSUS_THRESHOLD or behavior["high_phishing_risk"] else "sospechoso" if result["malicious"] or result["suspicious"] else "sin_detecciones" if sum(report["last_analysis_stats"].values()) else "desconocido"
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


def consultar_crtsh(dominio):
    """Query crt.sh for certificates covering the domain or its subdomains."""
    request = Request(f"{CRT_SH_URL}?q={quote('%.' + dominio)}&output=json", headers={"accept": "application/json"})
    try:
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
    with urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
        raw = response.read(MAX_INTEL_BYTES + 1)
    if len(raw) > MAX_INTEL_BYTES:
        raise _LocalResponseLimit("response too large")
    return json.loads(raw)


_vt_cache = {}


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
    if collection not in ("domains", "ip_addresses", "urls") or not VT_API_KEY:
        return {"error": "VirusTotal no disponible (API key ausente o tipo no válido)"}
    key = (collection, identifier)
    if key in _vt_cache:
        return _vt_cache[key]
    if not _take_vt_budget():
        return {"error": "cuota local VirusTotal agotada; resultado desconocido"}
    try:
        data = _provider_json(f"{VT_BASE_URL}/{collection}/{quote(identifier, safe='')}", {"x-apikey": VT_API_KEY, "accept": "application/json"})
        attrs = data.get("data", {}).get("attributes", {})
        result = dict(attrs) if isinstance(attrs, dict) else {}
        if not validar_informe_vt(result):
            result.update(_service_error("VirusTotal", "Respuesta VirusTotal no válida/incompleta"))
    except _LocalResponseLimit:
        return {"error": "Respuesta de VirusTotal excede el límite local"}
    except HTTPError as error:
        result = {"error": f"VirusTotal HTTP {error.code}"} if error.code == 404 else _service_error("VirusTotal", f"VirusTotal HTTP {error.code}")
    except (URLError, TimeoutError, OSError, ValueError, TypeError, KeyError):
        result = _service_error("VirusTotal", "VirusTotal no disponible o respuesta no válida")
    _vt_cache[key] = result
    return result



def _relacion_vt(collection, identifier, relation):
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
            return _service_error("VirusTotal", f"Relación {relation}: respuesta no válida")
        result = {"names": [str(x.get("id", ""))[:253] for x in entries[:10] if isinstance(x, dict)]}
        if len(entries) > 10 or data.get("links", {}).get("next"):
            result["error"] = "relaciones parciales (paginación/límite local)"
        return result
    except _LocalResponseLimit:
        return {"error": "Respuesta de VirusTotal excede el límite local"}
    except HTTPError as error:
        return _service_error("VirusTotal", f"Relación {relation} no disponible (HTTP {error.code})")
    except (URLError, TimeoutError, OSError, ValueError, TypeError):
        return _service_error("VirusTotal", f"Relación {relation} no disponible")



def analizar_inteligencia_dominio(urls):
    evidence = {"service_issues": [], "concrete_causes": [], "mixed": False, "criteria": [], "resources": []}
    dominios = sorted({dominio for url in urls if not url_contiene_secretos(url) and (dominio := extraer_dominio(url)) and _safe_domain(dominio)})[:MAX_DOMAIN_LOOKUPS]
    print("\n========== INTELIGENCIA DE DOMINIOS (crt.sh + WHOIS) ==========")
    if not dominios:
        print("No hay dominios HTTP(S) válidos para consultar.")
        return evidence
    for dominio in dominios:
        print(f"\nDominio: {dominio}")
        vt = consultar_vt_objeto("domains", dominio)
        stats = vt.get("last_analysis_stats", {}) if validar_informe_vt(vt) else {}
        if stats:
            evidence["resources"].append({"source": f"Dominio {dominio} (VirusTotal)",
                                          "malicious": stats["malicious"], "suspicious": stats["suspicious"], "report_available": True})
        print(f"VirusTotal dominio: {stats.get('malicious', 'desconocido')} maliciosos; {stats.get('suspicious', 'desconocido')} sospechosos; reputación {vt.get('reputation', 'desconocida')} (fuente: VirusTotal)")
        if not stats:
            evidence["service_issues"].extend(_service_issues(vt))
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            evidence["mixed"] = True
            evidence["concrete_causes"].append(f"Dominio {dominio}: VirusTotal {stats['malicious']} maliciosos y {stats['suspicious']} sospechosos")
        certificados = consultar_crtsh(dominio)
        if "error" in certificados:
            print(f"crt.sh: {certificados['error']}")
            evidence["service_issues"].extend(_service_issues(certificados))
        else:
            print(f"crt.sh: {certificados['count']} nombres de certificados; nombres: {', '.join(certificados['names']) or 'ninguno'}")
            for cert in certificados.get("certificates", [])[:5]:
                print(f"crt.sh certificado (fechas reportadas): inicio={cert.get('not_before', 'desconocido')}; fin={cert.get('not_after', 'desconocido')}; entrada CT={cert.get('entry_timestamp', 'desconocida')}")
        whois = consultar_whois(dominio)
        structured = whois
        evidence["criteria"].append(evaluar_dominio(dominio, vt, structured))
        if "error" in whois:
            print(f"WHOIS: {whois['error']}")
            evidence["service_issues"].extend(_service_issues(whois))
        else:
            print(f"WHOIS: registro={structured.get('registration_date') or 'desconocido'}; registrador={structured.get('registrar') or 'desconocido'}; nameservers={', '.join(structured.get('nameservers', [])) or 'desconocidos'} (datos opcionales/redactados pueden no estar disponibles)")
    return evidence


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


def _dns_txt(name, timeout=5):
    import dns.resolver
    answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    return [b"".join(record.strings) for record in answers]


def _dkim_dns_record(name, timeout=5):
    """Adapt the multi-record DNS API to dkimpy's one raw TXT-record contract."""
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
    for index, header in enumerate(correo.get_all("Received", [])[:100], 1):
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
        # The most recent hop is just a candidate, not proof of the original sender.
        selected = hops[0]
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
    for header in reversed(headers):
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
        hops.append({"ips": candidates[:8], "trusted": False, "boundary_claimed": boundary_claimed})
    return hops


def analizar_eml(ruta, smtp_ip=None, mail_from=None, helo=None, trusted_receiver=None):
    _vt_cache.clear()
    with abrir_archivo_seguro(ruta) as archivo:
        contenido_eml = archivo.read(MAX_LOCAL_FILE_BYTES + 1)
    if len(contenido_eml) > MAX_LOCAL_FILE_BYTES:
        raise ValueError("El archivo supera el límite de 25 MiB durante la lectura")
    with io.BytesIO(contenido_eml) as archivo:
        correo = BytesParser(
            policy=policy.default
        ).parse(archivo)

    context = extraer_contexto_smtp(correo, trusted_receiver)
    supplied = {"smtp_ip": smtp_ip, "mail_from": mail_from, "helo": helo}
    print("\n========== CONTEXTO SMTP EXTRAÍDO ==========")
    for key, value in supplied.items():
        if value is not None:
            context[key] = value
            context["sources"][key] = "argumento manual (prioridad sobre EML)"
    for key in ("smtp_ip", "mail_from", "helo", "receiver"):
        print(f"{key}: {context[key] or 'no determinado'} — {context['sources'].get(key, 'sin fuente inequívoca')}")
    for warning in context["warnings"]:
        print(f"Contexto SMTP pendiente: {warning}")
    print("Los valores extraídos son candidatos no confiables; receiver no configura --trusted-receiver ni prueba la IP de origen real.")
    smtp_ip, mail_from, helo = (context[key] for key in ("smtp_ip", "mail_from", "helo"))
    smtp_context_available = all(value is not None for value in (smtp_ip, mail_from, helo))
    if smtp_context_available:
        source = "argumentos manuales" if all(value is not None for value in supplied.values()) else "valores extraídos del EML y/o argumentos manuales"
        print(f"SPF se calcula con la tupla SMTP completa ({source}); los Received del EML no prueban por sí solos el origen histórico.")
    else:
        print("SPF no evaluable: faltan valores SMTP en el EML. Los campos ausentes quedan desconocidos; no se infieren desde From.")

    print("\n========== INVENTARIO ESTÁTICO DE ADJUNTOS ==========")
    attachments = inventariar_adjuntos(correo)

    remitente = str(correo.get("From", "Desconocido"))
    destinatario = str(correo.get("To", "Desconocido"))
    asunto = str(correo.get("Subject", "Sin asunto"))

    print("\n========== INFORMACIÓN DEL CORREO ==========")
    print(f"Remitente: {remitente}")
    print(f"Destinatario: {destinatario}")
    print(f"Asunto: {asunto}")

    alertas_auth = []
    print("\n========== AUTENTICACIÓN (CABECERAS NO VERIFICADAS) ==========")
    for header in correo.get_all("Authentication-Results", []):
        claims = re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", str(header), re.I)
        for protocol, status in claims:
            print(f"Authentication-Results (afirmación NO verificada): {protocol.upper()}={status.upper()}")

    dkim_results = verificar_dkim(contenido_eml)
    from_addresses = _direcciones(correo.get_all("From", []))
    from_domain = _normalizar_dominio(from_addresses[0].rsplit("@", 1)[1]) if len(from_addresses) == 1 else ""
    for signature in dkim_results:
        alignment = _alineado(signature.get("domain"), from_domain, False)
        print(f"DKIM independiente: {signature['status'].upper()} d={signature.get('domain', 'no disponible')} s={signature.get('selector', 'no disponible')}; alineación From={'desconocida (PSL no disponible)' if alignment is None else 'sí' if alignment else 'no'}")
    spf_result = verificar_spf(smtp_ip, mail_from, helo)
    print(f"SPF independiente: {spf_result[0].upper()} — {spf_result[1]}; {'tupla SMTP completa' if smtp_context_available else 'tupla SMTP incompleta'}")
    spf_domain = _normalizar_dominio(mail_from.rsplit('@', 1)[1]) if mail_from and '@' in mail_from else ""
    spf_alignment = _alineado(spf_domain, from_domain, False)
    print(f"Alineación SPF/From: {'desconocida' if spf_alignment is None or not spf_domain else 'sí' if spf_alignment else 'no'} (comparación relajada; DNS actual no prueba estado histórico)")
    # DMARC uses independently calculated SPF/DKIM results, never Authentication-Results claims.
    effective_spf = spf_result[0] if smtp_context_available else "unknown"
    dmarc_result = verificar_dmarc(from_domain, dkim_results, (effective_spf, spf_result[1], _normalizar_dominio(mail_from.rsplit('@', 1)[1]) if mail_from and '@' in mail_from else ""))
    print(f"DMARC independiente: {dmarc_result[0].upper()} — {dmarc_result[1]}")
    if dmarc_result[0] == "fail":
        alertas_auth.append("DMARC independiente: fallo de alineación verificada")

    print("\n========== ORIGEN DE TRANSPORTE (CABECERAS NO CONFIABLES) ==========")
    print("Received se recorre de abajo hacia arriba; el primer candidato no prueba la IP de origen real. Se requieren registros SMTP confiables para confirmarla.")
    hops = extraer_ip_received(correo.get_all("Received", []), trusted_receiver)
    for hop in hops[:20]:
        label = "frontera receptora CLAIMED por coincidencia textual; IP candidata, no autenticada por el EML" if hop.get("boundary_claimed") else "candidato según cabecera no verificada"
        print(f"Received: {', '.join(hop['ips']) or 'sin IP reconocible'} — {label}")

    # Comparación de dominios
    print("\n========== ANÁLISIS DEL REMITENTE ==========")

    from_addr = parseaddr(remitente)[1]
    return_addresses = _direcciones(correo.get_all("Return-Path", []))
    return_addr = return_addresses[0] if len(return_addresses) == 1 else ""
    reply_addresses = _direcciones(correo.get_all("Reply-To", []))

    dominio_from = (
        from_addr.rsplit("@", 1)[1].lower()
        if "@" in from_addr else ""
    )
    dominio_return = (
        return_addr.rsplit("@", 1)[1].lower()
        if "@" in return_addr else ""
    )

    print(f"Dominio From: {dominio_from or 'No disponible'}")
    print(
        f"Dominio Return-Path: "
        f"{dominio_return or 'No disponible'}"
    )

    if dominio_from and dominio_return:
        if dominio_from != dominio_return:
            print(
                "Observación: Los dominios son diferentes. "
                "Esto no necesariamente indica phishing, "
                "pero requiere revisar su alineación DMARC."
            )
        else:
            print("Los dominios coinciden exactamente.")

    mismatch_evidence = []
    for label, addresses in (("Reply-To", reply_addresses), ("Return-Path", return_addresses)):
        if addresses and (len(addresses) != 1 or len(from_addresses) != 1 or addresses[0] != from_addresses[0]):
            mismatch_evidence.append(f"{label} no coincide con From")
            print(f"Evidencia sospechosa: {label} difiere de From (direcciones omitidas). No confirma malware.")

    # Extraer URLs
    print("\n========== EXTRACCIÓN DE ENLACES ==========")
    print("Decodificación estática Base64/URL con biblioteca estándar Python, sin procesos externos ni navegación; límites de bytes, candidatos y capas.")

    urls = []
    decode_gaps = []
    unresolved_encoded = False
    body_active = False
    body_credentials = False

    for parte in correo.walk():
        tipo = parte.get_content_type()

        if tipo not in ("text/plain", "text/html"):
            continue

        try:
            contenido = parte.get_content()
        except Exception:
            continue

        if not isinstance(contenido, str):
            continue

        urls.extend(
            re.findall(
                r'https?://[^\s<>"\']+',
                contenido,
                flags=re.IGNORECASE
            )
        )
        decoded_urls = decodificar_candidatos(contenido)
        encoded = bool(decoded_urls) or bool(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", contenido))
        body_active = body_active or bool(re.search(r"<script\b", contenido, re.I))
        if encoded:
            print("Decodificación Base64/URL local aplicada; el contenido recuperado no se ejecuta.")
            unresolved_encoded = unresolved_encoded or not decoded_urls
            if not decoded_urls:
                decode_gaps.append("contenido codificado sin URLs recuperables dentro de los límites; resultado estático no exhaustivo")
        urls.extend(decoded_urls)

        if tipo == "text/html":
            extractor = ExtractorEnlaces()
            extractor.feed(contenido)
            urls.extend(extractor.urls)
            credentials = ExtractorCredenciales()
            credentials.feed(contenido)
            body_credentials = body_credentials or credentials.password_input

    urls_limpias = []

    for url in urls:
        url = url.rstrip(".,;)")
        if url not in urls_limpias:
            urls_limpias.append(url)

    print(f"URLs encontradas: {len(urls_limpias)}")

    # VirusTotal
    print("\n========== VIRUSTOTAL ==========")

    resultados_vt = []
    service_issues = list(_service_issues(spf_result)) + list(_service_issues(dmarc_result))
    for signature in dkim_results:
        service_issues.extend(_service_issues(signature))
    if len(urls_limpias) > MAX_URLS:
        print(
            f"Se consultarán las primeras {MAX_URLS} URLs "
            "para limitar el consumo de la API."
        )

    # Round-robin primary URL/hash reports before any optional VT relationships.
    primary_urls = urls_limpias[:MAX_URLS]
    primary_attachments = [item for item in attachments[:MAX_URLS] if "sha256" in item]
    primary_url_reports, primary_hash_reports = {}, {}
    for index in range(max(len(primary_urls), len(primary_attachments))):
        if index < len(primary_urls):
            primary_url = primary_urls[index]
            if not url_contiene_secretos(primary_url):
                primary_url_reports[primary_url] = analizar_reputacion(primary_url)
        if index < len(primary_attachments):
            attachment = primary_attachments[index]
            sha256 = attachment["sha256"]
            if sha256 not in primary_hash_reports:
                primary_hash_reports[sha256] = consultar_virustotal_archivo(sha256)

    scan_causes = []
    url_resources, url_detection_checks, url_behavior_checks = [], [], []
    for url in primary_urls:
        if url_contiene_secretos(url):
            print("URL omitida: contiene credenciales, fragmento o consulta; consulta remota no realizada.")
            resultados_vt.append((url, "sospechoso", 0, 0))
            url_detection_checks.append(criterio("unknown", "URL omitida por privacidad"))
            url_behavior_checks.append(criterio("unknown", "URL sin análisis de comportamiento por privacidad"))
            continue
        estado = primary_url_reports[url]
        resultados_vt.append((url, estado["status"], estado["malicious"], estado["suspicious"]))
        if resultados_vt[-1][1] == "desconocido":
            service_issues.extend(_service_issues(estado.get("_report", {})))
        report = estado.get("_report", {})
        behavior = analizar_comportamiento_remoto_url(url, report)
        service_issues.extend(_service_issues(behavior))
        scan_causes.extend(behavior["concrete_causes"])
        url_detection_checks.append(criterio_detecciones(report))
        url_behavior_checks.append(behavior["behavior_check"])
        resource = dict(estado)
        resource.update(confirmed_phishing=behavior["confirmed_phishing"], high_phishing_risk=behavior["high_phishing_risk"])
        url_resources.append(resource)

    if not urls_limpias:
        print("No se encontraron URLs para consultar.")

    if from_domain and _safe_domain(from_domain):
        from_intel = consultar_vt_objeto("domains", from_domain)
    else:
        from_intel = {"error": "Dominio From no válido/no disponible"}
    from_stats = from_intel.get("last_analysis_stats", {}) if validar_informe_vt(from_intel) else {}
    from_malicious = from_stats.get("malicious", 0) if isinstance(from_stats.get("malicious", 0), int) else 0
    from_suspicious = from_stats.get("suspicious", 0) if isinstance(from_stats.get("suspicious", 0), int) else 0
    if "error" not in from_intel:
        print(f"VirusTotal dominio From {from_domain}: {from_malicious} maliciosos; {from_suspicious} sospechosos; reputación={from_intel.get('reputation', 'desconocida')} (fuente: VirusTotal)")
    else:
        print(f"VirusTotal dominio From: reputación no disponible ({from_intel['error']})")
    if not validar_informe_vt(from_intel):
        service_issues.extend(_service_issues(from_intel))

    for url in primary_urls:
        if not url_contiene_secretos(url):
            service_issues.extend(_url_relationships(url))

    for hop in hops[:20]:
        for candidate in hop["ips"]:
            try:
                address = ipaddress.ip_address(candidate)
                if address.is_global:
                    report = consultar_vt_objeto("ip_addresses", str(address))
                    service_issues.extend(_service_issues(report))
                    stats = report.get("last_analysis_stats", {})
                    state = "desconocido (cuota agotada)" if "error" in report and "cuota" in report["error"] else f"{stats.get('malicious', 'desconocido')} maliciosos; {stats.get('suspicious', 'desconocido')} sospechosos"
                    print(f"VirusTotal IP candidata {address}: {state} (fuente: VirusTotal; IP no verificada como origen)")
            except ValueError:
                continue

    domain_evidence = analizar_inteligencia_dominio(urls_limpias)
    domain_evidence = domain_evidence if isinstance(domain_evidence, dict) else {}
    service_issues.extend(_service_issues(domain_evidence))

    attachment_causes = []
    attachment_resources, attachment_detection_checks, attachment_behavior_checks = [], [], []
    for attachment in attachments[:MAX_URLS]:
        if "sha256" not in attachment:
            continue
        report = primary_hash_reports[attachment["sha256"]]
        service_issues.extend(_service_issues(report))
        attachment_detection_checks.append(criterio_detecciones(report))
        attachment_behavior_checks.append(evaluar_comportamiento_archivo(attachment["type"], attachment["script_status"], attachment["macros"], attachment["size"]))
        if validar_informe_vt(report):
            stats = report["last_analysis_stats"]
            malicious, suspicious = stats["malicious"], stats["suspicious"]
            attachment_resources.append({"resource_type": "file", "report_available": True,
                                         "malicious": malicious, "suspicious": suspicious,
                                         "executable": attachment["type"] in ("PE", "ELF", "Mach-O", "script")})
            print(f"VirusTotal adjunto {attachment['name']}: {malicious} maliciosos; {suspicious} sospechosos (fuente: VirusTotal)")
            print_metadatos_vt_archivo(report)
            if malicious or suspicious:
                attachment_causes.append(f"Adjunto {attachment['name']} SHA-256 {attachment['sha256']}: {malicious} motores maliciosos y {suspicious} sospechosos")
        else:
            print(f"VirusTotal adjunto {attachment['name']}: informe desconocido/no disponible")

    if alertas_auth:
        print("\nProblemas de autenticación reportados:")
        for alerta in alertas_auth:
            print(f" - {alerta}")

    available_reports = [estado for _, estado, _, _ in resultados_vt if estado != "desconocido"]
    url_causes = []
    for url, state, malicious, suspicious in resultados_vt:
        if state in ("malicioso", "sospechoso"):
            parsed_url = urlparse(url)
            safe_url = f"{parsed_url.scheme}://{parsed_url.hostname or 'dominio-no-disponible'}{parsed_url.path or '/'}"
            count_text = f"{malicious} motores maliciosos y {suspicious} sospechosos" if malicious or suspicious else f"URL clasificada como {state} por el proveedor; motores no verificables"
            url_causes.append(f"URL {safe_url}: {count_text}")
    from_causes = []
    if from_malicious or from_suspicious:
        from_causes.append(f"Dominio From {from_domain}: VirusTotal reportó {from_malicious} motores maliciosos y {from_suspicious} sospechosos; reputación={from_intel.get('reputation', 'desconocida')} (fuente: VirusTotal; no autentica por sí solo al remitente)")
    concrete_causes = url_causes + from_causes + mismatch_evidence + alertas_auth + attachment_causes + domain_evidence.get("concrete_causes", []) + scan_causes
    if concrete_causes:
        print("\nEvidencia concreta para el veredicto:")
        for cause in concrete_causes[:12]:
            print(f" - {cause[:300]}")
    verified_dkim_aligned = any(signature.get("status") == "verified" and _alineado(signature.get("domain"), from_domain, False) is True for signature in dkim_results)
    auth_pass = bool(smtp_context_available and spf_result[0] == "pass" and spf_alignment is True and verified_dkim_aligned and dmarc_result[0] == "pass")
    auth_bad = effective_spf in ("fail", "softfail", "permerror") or (smtp_context_available and spf_alignment is False) or dmarc_result[0] in ("fail", "permerror") or any(signature.get("status") == "failed" for signature in dkim_results)
    auth_failed_checks = []
    if smtp_context_available and effective_spf in ("fail", "softfail", "permerror"):
        auth_failed_checks.append("SPF")
    dkim_statuses = [signature.get("status") for signature in dkim_results]
    if "verified" not in dkim_statuses and "failed" in dkim_statuses:
        auth_failed_checks.append("DKIM")
    if dmarc_result[0] in ("fail", "permerror"):
        auth_failed_checks.append("DMARC")
    auth_check = criterio("pass" if auth_pass else "fail" if auth_bad else "unknown", f"SPF={spf_result[0]} (tupla SMTP completa={smtp_context_available}) alineado={spf_alignment}; DKIM verificado y alineado={verified_dkim_aligned}; DMARC={dmarc_result[0]}; valores SMTP extraídos/override del EML, no autenticación histórica del transporte; cabeceras Authentication-Results no usadas como prueba; SPF: {spf_result[1]}; DMARC: {dmarc_result[1]}; DKIM: {', '.join(signature.get('reason', signature['status']) for signature in dkim_results)}")
    registry = consultar_whois(from_domain) if from_domain else {"error": "From no disponible"}
    service_issues.extend(_service_issues(registry))
    domain_check = combinar_criterios([evaluar_dominio(from_domain, from_intel, registry)] + domain_evidence.get("criteria", []), empty="unknown")
    detection_check = combinar_criterios([criterio_detecciones(from_intel)] + url_detection_checks + attachment_detection_checks, empty="unknown")
    behavior_checks = url_behavior_checks + attachment_behavior_checks
    if body_active or unresolved_encoded or body_credentials:
        behavior_checks.append(criterio("fail" if body_active or body_credentials else "unknown", "scripts/campo de credenciales en cuerpo o contenido codificado no resuelto; formulario por sí solo no confirma phishing ni infección"))
    if len(urls_limpias) > MAX_URLS or len(attachments) > MAX_URLS or any("sha256" not in item for item in attachments):
        behavior_checks.append(criterio("unknown", "recursos omitidos/no decodificables por límites de análisis"))
    behavior_check = combinar_criterios(behavior_checks, empty="pass")
    if not behavior_checks:
        behavior_check = criterio("pass", "cuerpo inspeccionado sin enlaces, adjuntos, scripts ni contenido codificado no resuelto; análisis estático, no ejecución")
    verdict_evidence = {
        "resource_type": "eml",
        "resources": url_resources + attachment_resources + domain_evidence.get("resources", []) + ([{"source": f"Dominio From {from_domain} (VirusTotal)", "malicious": from_malicious, "suspicious": from_suspicious, "report_available": True}] if validar_informe_vt(from_intel) else []),
        "high_phishing_risk": bool(scan_causes),
        "auth_failure": bool(alertas_auth),
        "auth_failed_checks": auth_failed_checks,
        "mixed": bool(mismatch_evidence or from_malicious or from_suspicious),
        "report_available": bool(available_reports) or "error" not in from_intel,
        "criteria": {"authentication": auth_check, "domain": domain_check, "detections": detection_check, "behavior": behavior_check},
        "concrete_causes": concrete_causes,
        "service_issues": [{"service": service, "reason": reason} for service, reason in
                           dict.fromkeys((issue["service"], issue["reason"]) for issue in service_issues)],
    }
    return imprimir_veredicto(verdict_evidence)


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
