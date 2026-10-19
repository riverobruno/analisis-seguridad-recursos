# Análisis de correos, URLs y archivos

El script analiza un correo `.eml`, una URL HTTP(S) o un archivo local y muestra evidencias junto con uno de tres veredictos. La legitimidad nunca puede garantizarse: el resultado solo resume la evidencia disponible y el alcance de las comprobaciones realizadas.

## Análisis por tipo de recurso

### Correo `.eml`

- Evalúa SPF, DKIM y DMARC, incluyendo los resultados `pass` de `Authentication-Results` como evidencia válida.
- Conserva la verificación criptográfica de DKIM como comprobación adicional y separada.
- Compara los dominios de `From`, `Reply-To` y `Return-Path`, y muestra la IP de origen candidata de `Received`.
- Analiza el dominio de `From` mediante VirusTotal; no consulta WHOIS ni crt.sh para ese dominio por sí solo.
- Extrae URLs y las analiza con el flujo URL. Inventaría adjuntos y los analiza como archivos, sin ejecutar ni subir contenido.

### URL

- Consulta reputación, detecciones y relaciones disponibles en VirusTotal.
- Puede consultar urlscan.io de forma privada si existe `URLSCAN_API_KEY`; el sitio se visita desde urlscan, no desde tu computadora.
- Consulta WHOIS y crt.sh para edad, registrador, servidores de nombres y certificados del dominio.

### Archivo local o adjunto

- Calcula el SHA-256 y consulta únicamente ese hash en VirusTotal; nunca sube el archivo.
- Informa tamaño, tipo detectado y metadatos disponibles.
- Inspecciona estáticamente macros y scripts embebidos cuando corresponde. Nunca ejecuta archivos, scripts ni macros.

## Ejecución

Necesitás Python 3 y las dependencias del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

En Windows PowerShell, activá el entorno con `./.venv/Scripts/Activate.ps1`.

El argumento indica el tipo de análisis:

```bash
python analisis_recursos.py correo.eml
python analisis_recursos.py 'https://example.org/'
python analisis_recursos.py archivo.pdf
```

Para un EML también podés reemplazar el contexto SMTP detectado:

```bash
python analisis_recursos.py correo.eml \
  --smtp-ip 192.0.2.10 \
  --mail-from persona@example.org \
  --helo mail.example.org
```

Las claves `VT_API_KEY` y `URLSCAN_API_KEY` son opcionales. Sin ellas, las comprobaciones que dependen de esos servicios quedan desconocidas. La salida muestra solo las secciones relevantes para el tipo de recurso y la evidencia disponible.

## Herramientas

| Herramienta | Función y flujo aplicable |
|---|---|
| `analisis_recursos.py` | Analizador local que orquesta los flujos de correo, URL y archivo, reúne la evidencia y calcula el veredicto. |
| VirusTotal | Consulta informes existentes para dominios, URLs y hashes de archivos; no sube archivos ni inicia análisis nuevos. |
| urlscan.io | Ejecuta, de forma privada y solo para URLs, la comprobación remota de navegación, redirecciones y formularios cuando hay clave configurada. |
| WHOIS | Consulta los dominios de URLs para aportar edad, registrador y servidores de nombres. |
| crt.sh | Consulta certificados de los dominios de URLs y sus subdominios. |
| `dnspython` | Resuelve registros DNS TXT usados por los flujos SPF, DKIM y DMARC de los correos. |
| `pyspf` | Evalúa SPF con el contexto SMTP disponible en el flujo de correo. |
| `dkimpy` | Verifica criptográficamente firmas DKIM en correos, como comprobación adicional. |
| `publicsuffix2` | Normaliza dominios registrables para comparar identidades y agrupar consultas de correo y URL. |
| `oletools` | Inspecciona estáticamente macros VBA en archivos OLE/OOXML o adjuntos, sin ejecutar su contenido. |

## Veredictos

- **LIMPIO / LEGÍTIMO:** la evidencia aplicable no presenta detecciones ni fallos relevantes y las comprobaciones necesarias están completas.
- **SOSPECHOSO:** falta evidencia, hay resultados desconocidos o contradictorios, o aparece algún indicador aislado de riesgo.
- **INFECTADO:** hay múltiples detecciones maliciosas coincidentes, múltiples fallos verificados de autenticación, phishing corroborado o un ejecutable cuyo hash resulta malicioso.

La precedencia es **INFECTADO → SOSPECHOSO → LIMPIO / LEGÍTIMO**. Un resultado **LIMPIO / LEGÍTIMO** no constituye una garantía absoluta de legitimidad; únicamente indica que no se encontraron problemas dentro de la evidencia y los límites del análisis.
