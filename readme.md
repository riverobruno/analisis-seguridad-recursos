# Análisis de correos, URLs y archivos

[`analisis_recursos.py`](analisis_recursos.py) realiza un análisis de triaje y genera un reporte en la terminal con un veredicto **Legítimo, Sospechoso o Infectado**, sus evidencias y los criterios aplicados. Acepta un correo `.eml`, una URL HTTP(S) o un archivo local por ejecución.

**Los archivos analizados nunca se ejecutan, emulan ni suben a las herramientas externas.** Su análisis es estático: lectura de bytes, SHA-256, metadatos e indicadores de contenido. Las URLs tampoco se abren localmente; **configurar `URLSCAN_API_KEY` activa automáticamente su visita remota privada**, también para URLs extraídas de correos.

## Inicio rápido

Ejecutar los comandos desde la carpeta del script. Se necesita Python 3 y `pip`; el código utiliza sintaxis disponible desde Python 3.8, pero eso no garantiza la compatibilidad de todas las versiones de las dependencias. La ayuda CLI se verificó con Python 3.14.5 en Windows; no se validó la instalación en macOS/Linux.

### 1. Crear un entorno e instalar las dependencias

Windows, PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe analisis_recursos.py --help
```

macOS/Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
.venv/bin/python analisis_recursos.py --help
```

La copia de `.env.example` es para la primera configuración: no sobrescribir un `.env` existente con claves propias. No hace falta activar el entorno si se usa directamente su intérprete, como en estos ejemplos.

[`requirements.txt`](requirements.txt) incluye `dkimpy`, `dnspython`, `publicsuffix2`, `pyspf` y `oletools`. Permiten verificar autenticación de correo y detectar macros Office. El script puede continuar sin estas bibliotecas, pero indica los análisis no disponibles; no los considera correctos por omisión. No necesita CyberChef, Node ni npm.

### 2. Configurar las API keys

Editar `.env`, **junto a `analisis_recursos.py`**:

```dotenv
VT_API_KEY=REEMPLAZAR_POR_CLAVE_PROPIA
URLSCAN_API_KEY=REEMPLAZAR_POR_CLAVE_PROPIA
```

| Clave | Uso |
|---|---|
| `VT_API_KEY` | Consultar informes existentes de URL, dominio, IP y hash en VirusTotal. |
| `URLSCAN_API_KEY` | Activa automáticamente análisis remoto de URLs mediante escaneos **privados**, sujeto a la cuota del servicio. |

Las variables del entorno tienen prioridad sobre `.env`, incluso si están vacías. El lector de `.env` solo reconoce estas dos claves, no ejecuta contenido ni expande variables. No publicar claves ni incluir `.env` en un repositorio.

WHOIS, crt.sh y las consultas DNS son públicos y no requieren otra API key. Se utilizan únicamente funciones disponibles con acceso gratuito; los datos pueden faltar o estar limitados por la cuota del servicio.

### Uso gratuito y cuotas

Condiciones verificadas el **17 de octubre de 2026**:


**Privacidad antes de configurar:** urlscan navega automáticamente los destinos enviados y puede activar seguimiento o enlaces de un solo uso. Utilizar únicamente URLs autorizadas; dejar `URLSCAN_API_KEY` vacía para deshabilitar este envío. La cuenta puede tener cuotas distintas; el programa no presupone capacidad por la cifra publicada.

### 3. Analizar un recurso

En los ejemplos siguientes, `python` representa el intérprete del entorno: `.\.venv\Scripts\python.exe` en Windows o `.venv/bin/python` en macOS/Linux.

```bash
python analisis_recursos.py "muestras/mensaje.eml"
python analisis_recursos.py "muestras/archivo.exe"
python analisis_recursos.py "https://example.test/ruta"
```

Los archivos son rutas ilustrativas: reemplazarlos por los propios. `example.test` es un dominio ficticio, no un caso para obtener resultados reales; urlscan lo rechaza. No abrir una muestra para ejecutar estos comandos: el único programa que se inicia es el analizador Python.

Con `URLSCAN_API_KEY` configurada, el mismo comando activa el escaneo remoto privado. Reemplazar la URL ficticia únicamente por un destino autorizado para enviar al servicio. Sin esa clave no se solicita un nuevo escaneo de comportamiento.

## Qué analiza

### Correos `.eml`

- Lee `From`, `Reply-To` y `Return-Path`, compara identidades y muestra inconsistencias.
- Distingue las afirmaciones de `Authentication-Results` de las comprobaciones independientes de SPF, DKIM y DMARC; calcula alineación con `From`.
- Extrae automáticamente candidatos para `smtp-ip`, `mail-from`, `helo` y receptor desde `Received-SPF`, `Received` y `Return-Path`, mostrando la procedencia de cada dato. No mezcla registros SPF de receptores distintos. Si hay datos malformados, duplicados o contradictorios, informa el problema y deja sin determinar los valores afectados.
- Recorre `Received` de abajo hacia arriba para mostrar IPs candidatas, pero **no elige automáticamente la IP inferior como origen real**. Para calcular SPF usa como candidato el salto superior interpretable, o el receptor indicado explícitamente, sin atribuirle confianza.
- Consulta reputación del dominio `From`, dominios enlazados y, cuando corresponde, IP de transporte en VirusTotal, dentro de la cuota disponible.
- Extrae URLs de texto/HTML y adjuntos; decodifica Base64 y URL encoding dentro del propio script, con límites de tamaño y profundidad. No evalúa ni ejecuta lo decodificado.
- Envía las URLs al flujo de análisis de enlaces, no al navegador local. Los adjuntos se registran y analizan estáticamente; VirusTotal recibe su hash, no su contenido. Para inspeccionar macros de adjuntos Office, escribe una copia temporal local que elimina al terminar ese paso.

El archivo `.eml` es la fuente predeterminada del contexto del correo: **no hace falta proporcionar por separado los datos SMTP que el mensaje contenga**. El comando básico extrae ese contexto sin argumentos adicionales:

```bash
python analisis_recursos.py "muestras/mensaje.eml"
```

Del EML se extraen `Received`/`Received-SPF` para obtener candidatos de IP, HELO y `MAIL FROM`, y `Return-Path` como alternativa para el remitente de sobre. Con una tupla completa, el script calcula SPF automáticamente usando DNS actual; verifica las firmas DKIM del mensaje y evalúa DMARC a partir del dominio `From`, los resultados SPF/DKIM y la política DNS. Estos resultados calculados pueden alimentar el veredicto sin flags SMTP ni una fuente externa de contexto. Las cabeceras de transporte son datos del archivo, no prueba independiente del origen histórico; el script las presenta como candidatas. Las afirmaciones `Authentication-Results` se muestran como no verificadas y no se usan como evidencia. Si faltan datos para la tupla, SPF queda **desconocido**; no se infieren desde el `From` visible.

Opcionalmente, se puede reemplazar cualquier candidato con datos manuales:

```bash
python analisis_recursos.py "muestras/mensaje.eml" --smtp-ip "192.0.2.10" --mail-from "sender@example.test" --helo "smtp.example.test" --trusted-receiver "mx.example.test"
```

La IP, los dominios y las direcciones anteriores son ficticios. Reemplazarlos por los valores observados en los registros del receptor confiable. `--mail-from` es la dirección SMTP original, sin los delimitadores `< >`.

Los argumentos `--smtp-ip`, `--mail-from` y `--helo` reemplazan individualmente los candidatos extraídos. SPF se calcula cuando la tupla resultante está completa, tanto si proviene del EML como si incluye argumentos manuales; si falta un valor, SPF queda desconocido.

`--trusted-receiver` permite seleccionar el salto por coincidencia exacta del receptor en `Received` o `Received-SPF`; si es ambiguo o falta, no selecciona otro salto como sustituto. **El nombre no autentica la cabecera** ni convierte automáticamente sus datos en confiables. El receptor extraído se muestra como candidato, sin configurar esta opción por sí mismo. DNS actual tampoco demuestra el estado de autenticación en la fecha histórica de recepción.

### URLs

- Consulta el informe existente de la URL y del dominio en VirusTotal: detecciones, motores, reputación, última IP de servicio y redirecciones/enlaces salientes disponibles en los atributos del informe. No solicita un nuevo análisis a VirusTotal.
- Con `URLSCAN_API_KEY` configurada, solicita automáticamente un escaneo privado y reporta URL final, redirecciones observadas, IP, país, dominios contactados, señales del proveedor y campos de contraseña observados en el DOM.
- Muestra el enlace a la captura de urlscan para **revisión visual manual**; no inspecciona la imagen automáticamente. La ausencia de un campo de contraseña en el DOM estático no excluye formularios dinámicos.
- Consulta WHOIS para fecha de creación, registrador y servidores de nombres. Usa IANA y el servidor de referencia por TCP 43; una red puede bloquear ese puerto o el registro omitir datos.
- Consulta crt.sh por `%.dominio` para nombres/subdominios y fechas reportadas de certificados, incluido inicio de validez y entrada en Certificate Transparency. Un certificado no prueba antigüedad de registro ni legitimidad.

**Sin acceso local al sitio:** el flujo de URLs no solicita páginas, no abre un navegador ni resuelve por DNS el hostname investigado desde el equipo. El filtro local es únicamente sintáctico: rechaza IPs privadas/reservadas y nombres locales o especiales reconocibles. urlscan realiza la resolución DNS y la navegación remotas; su política de seguridad gobierna los destinos y redirecciones reales.

El equipo sí contacta los proveedores: VirusTotal, urlscan.io, crt.sh y servidores WHOIS, y resuelve los nombres de esos proveedores. Las peticiones HTTP están limitadas a los proveedores permitidos y no siguen redirecciones HTTP, evitando que una respuesta del proveedor dirija al equipo hacia el sitio investigado. La autenticación de correos también puede consultar DNS para SPF/DKIM/DMARC, incluso si el dominio coincide con el de una URL; no es navegación web.

urlscan aporta comportamiento, pero no reemplaza toda la inteligencia: reputación/hash siguen en VirusTotal, antigüedad en WHOIS y certificados en crt.sh.

**Privacidad:** se omiten consultas remotas para URLs con usuario/contraseña, consulta (`?…`) o fragmento (`#…`).

urlscan recibe la URL y visita el sitio: puede activar seguimiento o enlaces de un solo uso. Solo se envía con visibilidad privada; se verifica esa visibilidad antes de usar el resultado. No hay consulta previa de cuota: el servicio acepta o rechaza el envío y se informa el HTTP 403/429 recibido, **sin recurrir a un escaneo público o no listado**.

### Archivos locales y adjuntos

- Calcula SHA-256 mediante `hashlib` sobre lectura binaria: no usa comandos específicos de Windows, macOS o Linux.
- Busca el hash en VirusTotal. Un hash desconocido queda sin informe: **no se sube el archivo**.
- Reporta tamaño, nombre local, tipo por firmas/heurísticas y discrepancias con la extensión. Si VirusTotal tiene datos, añade nombres conocidos y primera vez visto/primera presentación.
- Detecta firmas de PE, ELF, Mach-O, PDF, ZIP/OOXML y OLE, además de scripts/texto. Es identificación acotada, no un validador exhaustivo de formatos.
- Inspecciona estáticamente macros VBA Office mediante `oletools` y marcadores de scripts embebidos en contenido y miembros ZIP/OOXML, con límites contra archivos excesivos o comprimidos de forma abusiva.

No ejecuta ejecutables, scripts, macros, adjuntos ni payloads. Los marcadores estáticos pueden no detectar contenido comprimido u ofuscado; su ausencia no demuestra inocuidad.

## Cómo interpretar el reporte

El reporte destaca `VEREDICTO FINAL` y sus motivos concretos. Agrupa la evidencia en Autenticación, Dominio, Detecciones y Comportamiento; cada criterio indica Favorable, Alerta, No verificado o No aplica.

| Veredicto | Política implementada |
|---|---|
| **Legítimo** | Todos los criterios obligatorios aplicables corroborados, con detecciones y comportamiento en `PASS`. Para correos exige SPF calculado con una tupla SMTP completa, alineación correcta, DKIM verificado y alineado y DMARC correcto. Para correo/URL exige dominio con registro de al menos **180 días**, reputación VT **mayor que cero** y sin detecciones. |
| **Sospechoso** | Señales mixtas o insuficientes: pocas detecciones, autenticación fallida/desconocida, identidad incoherente, dominio nuevo o sin reputación positiva comprobada, comportamiento no verificado o recursos obligatorios sin evaluar. Requiere cautela o más análisis. |
| **Infectado** | Al menos **2 motores maliciosos coinciden en un mismo recurso**; o un EML tiene fallos independientes verificados en **2 o más** comprobaciones entre SPF, DKIM y DMARC; o VirusTotal clasifica como malicioso el hash SHA-256 de un ejecutable; o phishing altamente probable corroborado según las condiciones siguientes. |

Los fallos de SPF, DKIM y DMARC se cuentan solo cuando los calcula el análisis independiente del script; los textos `Authentication-Results` del EML son afirmaciones no confiables y nunca suman. SPF cuenta cuando puede calcularse desde una tupla SMTP completa extraída del EML o reemplazada manualmente; no hace falta contexto externo. Cada protocolo cuenta como máximo una vez. Un único fallo de autenticación queda como **Sospechoso**.

El phishing se considera corroborado cuando VT informa phishing malicioso junto con redirección externa observada, o urlscan informa malicioso **y** phishing, con campo de contraseña y redirección externa observados. Un formulario, una redirección o una métrica aislada no confirman infección.

No se suman detecciones de recursos diferentes. Un hash simplemente conocido en VirusTotal no equivale a malware: para archivos ejecutables se requiere que el informe clasifique positivamente ese hash como malicioso, aunque baste una detección. Cero detecciones sin resultados útiles de motores tampoco equivale a legitimidad.

Para archivos locales, autenticación y dominio no aplican. **Con el análisis estático actual, un ejecutable o script identificado como ejecutable (PE, ELF, Mach-O o script) no puede recibir el veredicto Legítimo**: si no hay evidencia suficiente para Infectado, queda Sospechoso, incluso cuando VirusTotal no informe detecciones. La razón es que el script no lo ejecuta y, por lo tanto, no puede confirmar que su comportamiento en ejecución sea normal. Un archivo no ejecutable sí puede quedar Legítimo si sus comprobaciones estáticas y la reputación disponible son favorables. “Infectado” clasifica el recurso analizado; no demuestra que el equipo donde se corrió el analizador esté infectado.

### Cómo leer los criterios

- **Autenticación:** SPF, DKIM, DMARC y alineación del correo. `pyspf` evalúa si la IP SMTP está autorizada para el remitente de sobre (`MAIL FROM`) o HELO; no analiza malware. DNS obtiene los registros SPF, claves públicas DKIM y políticas DMARC. Consultar DNS no equivale a abrir una URL ni descargar su contenido.
- **Comportamiento** (clave interna `behavior`): para URLs interpreta la navegación remota, redirecciones y señales de credenciales de urlscan, y evidencia de phishing de VT. Para archivos solo describe indicadores estáticos: no ejecuta ni emula. Por eso, un ejecutable sin señales de infección sigue como Sospechoso, no Legítimo. Para el cuerpo EML inspecciona contenido y recursos extraídos.
- **`URLSCAN_API_KEY`:** configurarla habilita el envío automático de URLs al navegador remoto privado. Dejarla vacía evita los nuevos escaneos; el comportamiento queda no verificado, no como supuesto fallo del servicio. La captura se enlaza para revisión visual; el script inspecciona el DOM devuelto, no interpreta la imagen.

Ejemplo de formato **sintético**, no resultado de un escaneo real (se omiten detalles para abreviar):

```text
========================================================================
VEREDICTO FINAL: Sospechoso
========================================================================
Por qué:
  - evidencia insuficiente para confirmar legitimidad

Criterios del análisis:
  Autenticación: No aplica
    - URL, no correo
  Dominio: Favorable
    - example.com: registro antiguo y reputación favorable (datos ficticios)
  Detecciones: Favorable
    - VirusTotal: 0 maliciosos, 0 sospechosos (datos ficticios)
  Comportamiento: No verificado
    - urlscan sin API key configurada; comportamiento remoto no verificado
```

El bloque final agrupa el veredicto, motivos y evidencia por criterio, sin códigos internos `PASS/FAIL/UNKNOWN`. Sus líneas se ajustan a 88 columnas, sin colores ANSI ni dependencias de presentación. El detalle técnico de las consultas se conserva antes del resumen.

### Guardar el reporte

No hay opciones `--output` ni `--json`. Se puede redirigir la salida de la terminal:

```bash
python analisis_recursos.py "muestras/mensaje.eml" > reporte.txt 2>&1
```

El reporte puede contener metadatos del correo, nombres y otros indicadores sensibles; protegerlo antes de compartirlo. No interpretar el código de salida del proceso como un veredicto: leer `VEREDICTO FINAL` y los criterios.

## Opciones y límites

La interfaz no es interactiva. `archivo` es obligatorio y su tipo determina el flujo: URL HTTP(S), extensión `.eml` o archivo local.

| Opción | Efecto |
|---|---|
| `-h`, `--help` | Muestra la ayuda y termina sin analizar recursos. |
| `--smtp-ip`, `--mail-from`, `--helo` | Reemplazan individualmente los candidatos SMTP extraídos del EML; SPF usa la tupla resultante si queda completa. |
| `--trusted-receiver` | Selecciona el salto por nombre exacto del receptor; no autentica las cabeceras ni otorga confianza a los valores extraídos. Solo `.eml`. |

No hay otras variables de configuración admitidas por `.env`. Los límites están definidos como constantes en el código, no como opciones CLI:


- Hasta **5 URLs** y reputación de los primeros **5 adjuntos** de un correo.
- EML de hasta **25 MiB**; inventario de hasta **20 adjuntos**, con **25 MiB acumulados** de contenido. El SHA-256 de un archivo local cubre el archivo completo; la inspección estática de contenido se limita a **25 MiB**.
- Decodificación de hasta **3 capas**, **20 candidatos** y **1 MiB** por contenido acotado; también hay límites de miembros/tamaños ZIP y firmas DKIM.

Cada criterio indica **Favorable, Alerta, No verificado o No aplica**, con su evidencia. Señales mixtas o información insuficiente mantienen el veredicto **Sospechoso**, según la política anterior.

**Datos externos no disponibles** aparece únicamente cuando una consulta realizada no obtiene una respuesta utilizable del proveedor (por ejemplo, timeout, HTTP 403/429 o respuesta inválida). Una clave ausente, una clave de urlscan vacía, un límite local o una dependencia faltante se explica en el análisis o criterio correspondiente; no se presenta como fallo del servicio. Un hash desconocido en VT es una respuesta válida, no una interrupción ni una detección maliciosa. Los campos opcionales ausentes de WHOIS/VT y un crt.sh sin resultados tampoco implican fallo del proveedor.


