# Análisis de correos, URLs y archivos

Script de Python para analizar un correo `.eml`, una URL o un archivo local y generar un reporte con evidencias y veredicto: **Legítimo, Sospechoso o Infectado**.

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
- Extrae `From`, `Reply-To`, `Return-Path` y cabeceras `Received`; compara identidades y muestra IPs candidatas.
- Usa el propio EML como contexto. Calcula SPF si puede completar IP, `MAIL FROM` y HELO; verifica DKIM y DMARC y su alineación. No hacen falta flags SMTP si el mensaje ya contiene esos datos.
- `Authentication-Results` se muestra como declaración no verificada, no como prueba. Si falta contexto para SPF, queda no verificado.
- Extrae URLs y adjuntos. No abre URLs localmente; analiza las URLs por separado. Los adjuntos se analizan estáticamente y VirusTotal recibe solo su hash.

### URLs
- Consulta reputación/detecciones disponibles en VirusTotal.
- Con `URLSCAN_API_KEY`, solicita automáticamente un escaneo privado para observar redirecciones, IP, país, dominios contactados y señales de credenciales.
- Consulta WHOIS para antigüedad/datos del dominio y crt.sh para subdominios/certificados.
- Tu computadora no visita el sitio, pero urlscan sí lo visita desde sus sistemas. Enviá solo enlaces autorizados.

### Archivos locales y adjuntos
- Calcula SHA-256 y busca el hash en VirusTotal; no sube el archivo.
- Informa tamaño, nombre, tipo detectado y metadatos disponibles.
- Busca estáticamente macros VBA y scripts embebidos cuando corresponde. Nunca ejecuta archivos, scripts ni macros.

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

- **Legítimo:** evidencia favorable en todos los criterios aplicables: autenticación correcta y alineada para correos, dominio antiguo y con buena reputación cuando corresponde, sin detecciones y comportamiento normal observado.
- **Sospechoso:** señales aisladas, mixtas o insuficientes; por ejemplo, pocas detecciones, dominio nuevo, cabeceras incoherentes o comportamiento no verificado.
- **Infectado:** dos o más motores maliciosos coinciden sobre el mismo recurso; o fallan dos o más comprobaciones distintas de SPF/DKIM/DMARC; o VirusTotal reporta como malicioso el hash de un ejecutable; o hay evidencia corroborada de phishing con redirección y credenciales.

Para archivos, autenticación y dominio no aplican. Un ejecutable o script sin detecciones sigue como **Sospechoso** porque, al no ejecutarlo, el script no puede confirmar su comportamiento normal. Un archivo no ejecutable sí puede quedar **Legítimo** si sus comprobaciones estáticas y la reputación disponible son favorables.

## Conceptos útiles

- **SPF:** comprueba si la IP de envío está autorizada para el remitente.
- **DKIM:** verifica la firma criptográfica del correo.
- **DMARC:** aplica la política del dominio y comprueba alineación con `From`.
- **WHOIS / crt.sh:** aportan antigüedad del dominio y datos públicos de certificados.
- **VirusTotal / urlscan.io:** aportan reputación y, en urlscan, navegación remota observada.

El veredicto resume la evidencia disponible; no es una garantía absoluta. **No verificado** no significa que la comprobación haya pasado.
