-------
### QUE ES?
Un **HTTP Host Header Attack** es una vulnerabilidad que ocurre cuando una aplicación **confía en el valor de la cabecera `Host` enviado por el cliente** sin validarlo correctamente.
La cabecera `Host` indica al servidor **qué dominio está solicitando el navegador**, pero como es un valor controlado por el usuario, un atacante puede **modificarlo manualmente**.
Si la aplicación usa ese valor para generar **enlaces, redirecciones, emails de recuperación de contraseña o lógica interna**, el atacante puede manipular la aplicación para provocar comportamientos no deseados.
Permite cosas como **password reset poisoning, cache poisoning, bypass de controles de acceso o redirecciones maliciosas**.  
Se previene **validando el `Host` contra una lista de dominios permitidos y no usando directamente valores controlados por el cliente**.
#### PASOS:
- **INTERCEPTAR LA PETICIÓN:** usar **Burp Suite** y capturar una request normal del sitio.
- **MODIFICAR EL HOST:** cambiar la cabecera `Host` por un dominio controlado por el atacante: `Host: attacker.com
- **OBSERVAR EL COMPORTAMIENTO:** comprobar si la aplicación usa ese valor para enlaces, redirecciones...
- **PROBAR PASSWORD RESET POISONING:** probar a **robar el token de recuperación**.
- **PROBAR HEADERS RELACIONADOS:** `X-Forwarded-Host: attacker.com`,  `X-Host: attacker.co`,  `Forwarded: host=attacker.com`
- **CACHE POISONING:** enviar peticiones manipuladas para que el servidor o CDN **cachee contenido malicioso usando el Host modificado**.
- *DUPLICAR CABECERAS HOST:* duplicar la cabecera para engañar al servidor.
- *COMPROBAR CONEXION MEDIANTE COLLABORATOR:* comprobar si el servidor envia peticiones a nuestro collaborator (SSRF).
- *PROBAR PASARLE RUTAS ABSOLUTAS EN EL GET:* probar si al pasarle rutas absolutas las carga y nos deja modificar *Host:*.
- *PROBAR A ENVIAR LAS REQUEST EN GRUPOS*
### LAB1 BASIC PASSWORD RESET POISONING
En este laboratorio encontramos una funcionalidad de **reseteo de contraseña**. Si interceptamos la petición con _Burp Suite_, en la request que se envía cuando solicitamos el cambio de contraseña (la que indica que revisemos nuestro email), podemos modificar la cabecera `Host:` para comprobar si la aplicación la utiliza al generar el enlace que se envía por correo.
Al hacerlo, observamos que la aplicación **sí tiene en cuenta esta cabecera** al construir el link de recuperación. Por tanto, podemos sustituir el valor de `Host:` por el dominio de nuestro **exploit server**. De esta forma, cuando la víctima solicite el reseteo de contraseña y haga clic en el enlace recibido por email, la petición llegará a nuestro servidor y **el token de `forgot-password` aparecerá en los logs**.
Una vez obtenido ese token, solo tenemos que acceder al enlace legítimo de cambio de contraseña **sustituyendo el token por el de la víctima** y establecer una nueva contraseña para su cuenta.
### LAB2 HOST HEADER AUTHENTICATION BYPASS
En este laboratorio nos piden que nos convirtamos en admin. Podemos buscar el panel de forma manual o usar *Target* → *Site map* → *Engagement tools* → *Discover content*. Una vez encontrado nos dice que solo es accesible desde local. Podemos probar a modificar la etiqueta `Host:` para bypasearlo y acceder como admin.
### LAB3: WEB CACHE POISONING VIA AMBIGUOUS REQUESTS
En este laboratorio hay un usuario visitando el `/` de la pagina, si nos ponemos a investigar vemos que la request a `/` se almacena en cache y carga un recurso `/resources/js` cuyo dominio depende de la cabecera `Host:`. Podemos probar a modificar la cabecera y meter el dominio del *server exploit* pero está capado. Probamos a duplicar la cabecera `Host:` y de esta manera el dominio de nuestro *exploit server* se utiliza para cargar los recursos. Basta con crear en el *exploit server* un `/resources/js/tracking.js` con `alert(document.cookie);` importante modificar la cabecera `Content-type: text/javascript=utf8`.
### LAB4: ROUTING-BASED SSRF 
En este laboratorio si hacemos pruebas podemos comprobar que si metemos en la cabecera `Host:` nuestro dominio de collaborator y haciendo *Poll Now* la pagina envia peticiones a nuestro dominio. Basandonos en esto podemos enviar la request al intruder y modificar la cabecera `Host: 192.168.0.&0&` le metemos un payload de numeros del 0 al 255 y empezamos el ataque (deshabilitar *update Host header to mach target*). Si ordenamos los resultados del ataque podremos ver un *302* que nos redirige a `/admin`.
### LAB5: SSRF VIA FLAWED REQUEST PARSING
Este laboratorio es similar al anterior pero en este si tratamos de modificar la cabecera `Host:`nos bloquea. Podemos intentar modificar la request para pasarle direcctamente la dirección absoluta de esta manera `GET https:LAB-ID.web-security-academy.net/` al hacer esto no solo carga la pagina correctamente sino que ademas nos permite modificar la cabecera `Host:`sin bloquearnos. Basandonos en esto podemos enviar la request al intruder y modificar la cabecera `Host: 192.168.0.&0&` le metemos un payload de numeros del 0 al 255 y empezamos el ataque (deshabilitar *update Host header to mach target*). Si ordenamos los resultados del ataque podremos ver un *302* que nos redirige a `/admin`.
### LAB6: HOST VALIDATION BYPASS VIA CONNECTION STATE ATTACK
En este lab nos dan una ip `192.168.0.1` si probamos a hacer una petición a `/admin` modificando el `Host: 192.168.0.1` vemos que nos redirige automaticamente a la raíz. Podemos saltarnos esto si creamos un grupo formado por una primera request a la raíz y sin modificar el *Host* y la segunda que sería la request modificada. Si enviamos el grupo en modo *Send group in secuence (single connectio)* y con `connection: keep-alive` conseguiremos que nos cargue el `/admin`. De esta forma podremos eliminar usuarios.