# Análisis de correos, URLs y archivos

Script de Python para analizar un correo `.eml`, una URL o un archivo local y generar un reporte con evidencias y veredicto: **Legítimo**, **Legítimo aparente — análisis estático** (solo EML), **No concluyente**, **Sospechoso** o **Infectado**.

> **Seguridad:** los archivos se analizan estáticamente; no se ejecutan ni se suben. Las URLs no se abren desde tu computadora. Si configurás `URLSCAN_API_KEY`, urlscan.io recibe la URL y la visita de forma remota.

## Instalación

Necesitás Python 3 y conexión a Internet para consultar servicios externos. Ejecutá los comandos desde la carpeta del proyecto.

**Windows (PowerShell):**
```powershell
py -3 -m venv .venv
& ./.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Claves de servicios (opcional)

No necesitás crear un archivo `.env` para ejecutar el script. Sin claves, las consultas a VirusTotal no estarán disponibles y no se iniciarán escaneos nuevos en urlscan; los análisis locales y los servicios que no requieren clave pueden continuar.


## Cómo ejecutar

El argumento obligatorio es un `.eml`, una URL HTTP(S) o la ruta de un archivo. El tipo de entrada determina el análisis.

```bash
python analisis_recursos.py --help
python analisis_recursos.py 'muestras/correo.eml'
python analisis_recursos.py 'https://example.org/'
python analisis_recursos.py 'muestras/archivo.pdf'
```

Estos comandos sirven en Windows, macOS y Linux si el entorno virtual está activado.

## ¿Qué análisis hace?

### Correos `.eml`
- Verifica SPF, DKIM, DMARC y sus alineaciones; compara `From`, `Reply-To` y `Return-Path` por dominio normalizado.
- Recorre `Received` desde la cabecera inferior hacia la superior y muestra una sola IP candidata con su cabecera de origen. La cabecera no convierte esa IP en una identidad verificada.
- Consulta en VirusTotal una vez el dominio `From`. No ejecuta WHOIS/crt.sh para el EML ni consulta VirusTotal para cada IP de `Received`.
- Extrae URLs y adjuntos. La decodificación Base64/URL es local, acotada y solo alimenta el análisis de URLs; no abre enlaces en la computadora. Cada URL se deriva al flujo de URLs y cada adjunto al flujo estático de archivos.
- En HTML solo extrae enlaces HTTP(S); no interpreta scripts, atributos inline ni esquemas `javascript:` como alertas del EML.
- `Authentication-Results` no sustituye las verificaciones reales. MIME ambiguo, contenido no decodificable, capas codificadas o límites alcanzados quedan como brechas de evidencia.

### URLs
- Consulta la reputación, detecciones y relaciones URL/dominio disponibles en VirusTotal.
- Con `URLSCAN_API_KEY`, solicita un escaneo privado y registra captura, redirecciones, IP, país, dominios contactados y solicitudes de credenciales.
- Consulta WHOIS para fecha de creación, registrador y servidores de nombres; consulta crt.sh con `%.dominio` para subdominios y fechas de emisión de certificados.
- Tu computadora no visita el sitio; urlscan sí lo visita desde sus sistemas. Enviá solo enlaces autorizados.

### Archivos locales y adjuntos
- Calcula SHA-256 y busca el hash en VirusTotal; no sube el archivo.
- Informa tamaño real, nombre, tipo detectado, nombres y fechas de primera detección disponibles.
- Busca estáticamente macros VBA y scripts embebidos cuando corresponde. Nunca ejecuta archivos, scripts ni macros.

### Salida
- La salida estándar contiene `VEREDICTO` y campos compactos de `AUTENTICACION`, `IDENTIDADES`, `ORIGEN`, `VIRUSTOTAL`, `URLSCAN`, `WHOIS`, `CRT.SH` y `ARCHIVO` cuando aplican.
- Los errores de proveedor se muestran como estados breves. No se imprimen tutoriales, justificaciones de política ni limitaciones repetidas.

## Flags

`--help` muestra la ayuda. Los siguientes flags son opcionales y aplican al análisis de correo:

| Flag | Uso |
|---|---|
| `--smtp-ip IP` | Reemplaza la IP SMTP candidata extraída del EML. |
| `--mail-from DIRECCIÓN` | Reemplaza el remitente SMTP (`MAIL FROM`). |
| `--helo HOST` | Reemplaza el nombre HELO/EHLO. |
| `--trusted-receiver HOST` | Selecciona una cabecera por el receptor exacto; no autentica la cabecera ni hace confiables sus datos. |

El EML es la fuente predeterminada; estos flags sirven para reemplazar candidatos. No existe un flag `--urlscan`: la clave activa el análisis automáticamente.

Ejemplo:
```bash
python analisis_recursos.py correo.eml --smtp-ip 192.0.2.10 --mail-from persona@example.org --helo mail.example.org
```

## Veredictos

- **Legítimo:** evidencia primaria aplicable corroborada: detecciones verificables sin alertas y, para EML/URLs, cada dominio relevante (From y enlaces) debe tener un informe VT válido sin detecciones, registro WHOIS válido con al menos 180 días y reputación comunitaria VT entera positiva. También exige autenticación correcta y alineada e inspección local completa para EML, o comprobaciones estáticas favorables para archivos.
- **Legítimo aparente — análisis estático:** solo EML con contenido local completamente inspeccionado dentro del alcance compatible y sin alertas observadas, pero con evidencia primaria de autenticación o detecciones/dominio aún no verificada. No confirma autenticidad ni ausencia de amenazas; una firma DKIM ausente no se convierte en autenticación favorable.
- **No concluyente:** evidencia primaria o inspección local insuficiente, sin una señal afirmativa de riesgo. Un resultado remoto desconocido no equivale a cero detecciones ni a un resultado limpio.
- **Sospechoso:** señales afirmativas aisladas o mixtas, como detecciones, reputación negativa, fallos de autenticación, cabeceras incoherentes, contenido activo observado en los flujos URL/archivo, solicitudes de credenciales o redirecciones externas. La falta de datos por sí sola no es una amenaza observada.
- **Infectado:** dos o más motores maliciosos coinciden sobre el mismo recurso; o fallan dos o más comprobaciones distintas de SPF/DKIM/DMARC; o VirusTotal reporta como malicioso el hash de un ejecutable; o hay evidencia corroborada de phishing según las reglas existentes de señal maliciosa y redirección/credenciales.

La precedencia es **Infectado → Sospechoso → evaluación de legitimidad/cobertura**. Una alerta observada prevalece incluso si falta otra evidencia. Para EML y URLs, la antigüedad WHOIS mínima de 180 días, la reputación comunitaria VT entera positiva y un informe VT válido sin detecciones son requisitos conjuntos de **Legítimo** para cada dominio From o de enlace. El flujo EML no realiza WHOIS/crt.sh; por eso la antigüedad del dominio From queda visible como evidencia faltante y no se convierte en una aprobación implícita. Un dato ausente, inválido o insuficiente deja el dominio no verificado y normalmente produce **No concluyente**; una reputación negativa sí es una alerta. Un dominio nuevo por sí solo no demuestra una amenaza. Un informe VT sin motores utilizables tampoco demuestra ausencia de detecciones.

Para archivos, autenticación y dominio no aplican. Un ejecutable o script sin detecciones queda **No concluyente** si su comportamiento no puede corroborarse y no hay otra alerta. Un archivo no ejecutable puede quedar **Legítimo** con detecciones verificables y comprobaciones estáticas favorables. Para URLs, la navegación remota no es un requisito universal de legitimidad; se muestran sus limitaciones y se conservan las alertas disponibles.

La cobertura local completa de un EML se limita a texto plano y extracción estática de enlaces HTTP(S) en HTML. Los adjuntos se incluyen en el inventario y se analizan, pero una brecha local impide un resultado favorable sin evidencia suficiente. La recuperación de enlaces Base64/URL tampoco prueba inspección completa de todas las capas del contenido. Estos casos reciben **No concluyente** si no hay alertas afirmativas.

## Conceptos útiles

- **SPF:** comprueba si la IP de envío está autorizada para el remitente.
- **DKIM:** verifica la firma criptográfica del correo.
- **DMARC:** aplica la política del dominio y comprueba alineación con `From`.
- **WHOIS / crt.sh:** aportan fecha de creación, datos registrales y datos públicos de certificados.
- **VirusTotal / urlscan.io:** aportan reputación y, en urlscan, navegación remota observada.

El veredicto resume la evidencia disponible y no constituye una garantía absoluta. **No verificado** no significa que la comprobación haya pasado.
