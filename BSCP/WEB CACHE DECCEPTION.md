----
### QUE ES?
Un **Web Cache Deception** es una vulnerabilidad donde un atacante consigue que **contenido dinámico o privado sea almacenado en caché como si fuera contenido estático**.  
Ocurre cuando el servidor o el sistema de caché **interpreta incorrectamente una URL manipulada** y guarda la respuesta en caché aunque contenga información sensible de un usuario autenticado.  
Esto permite que otros usuarios accedan a **datos privados almacenados en la caché**, como perfiles, tokens o información personal.  
Se previene **configurando correctamente las reglas de caché, evitando cachear contenido autenticado y validando correctamente las rutas y extensiones de las URLs**.
#### PASOS:
- **IDENTIFICAR ENDPOINTS CON DATOS PRIVADOS:** por ejemplo `/my-account`, `/profile`, `/orders`.
- **MANIPULAR LA URL:** añadir rutas o extensiones que el sistema de caché interprete como estáticas, por ejemplo  `/my-account/abc.js` o `/my-account/abc.css`, ver si se cargan en caché.
- **RECUPERAR DESDE CACHE:** otro usuario o atacante accede a la misma URL manipulada y cachea el contenido, accede a la respuesta cacheada con los datos de la víctima.
- **PROBAR PATH DELIMITERS:** probar desde del *intruder* mas *path delimiters* como `;`.
- **PROBAR PATH TRAVERSAL:** probar a ver si se carga la *caché* mediante `/resources/..%2fmy-account
### LAB1: EXPLOITING PATH MAPPING FOR WEB CACHE DECEPTION
En este lab si nos logueamos y vemos el flujo de request a través del *Http History* podemos ver que la request a `/my-account`contiene nuestra *API KEY*. Podemos tratar de ver si se almacena en caché al meterle algo como `/my-account/abc.js`, vemos que se almacena por la cabecera en la respuesta *cache: hit*. De esta manera podemos crear un payload en el *exploit server* para que la víctima almacene en caché su *API KEY*:
`<script>document.location="https://LAB-ID.web-security-academy.net/my-account/abc.js"</script>
Solo tendremos que enviar una nueva petición a `/my-account/abc.js` y veremos la *API KEY* de la víctima.
### LAB2: EXPLOITING PATH DELIMITERS FOR WEB CACHE DECEPTION
En este lab pasa algo similar al anterior, si nos logueamos y vemos el flujo de request a través del *Http History* podemos ver que la request a `/my-account`contiene nuestra *API KEY*. Pero en este caso si probamos a intentar cachear `/my-account/abc.js` nos da un *404*. Podemos probar a fuzzear por los *path delimiters* a ver si nos permite usar alguno, mandamos la request al *intruder* y añadimos un payload simple con todos los delimitadores `/my-account&&abc.js` y esperamos hasta que haya alguno que no nos de un *404*. Una vez identificado creamos el payload en el *exploit server*:
`<script>document.location="https://LAB-ID.web-security-academy.net/my-account;abc.js"</script>
Solo tendremos que enviar una nueva petición a `/my-account;abc.js` y veremos la *API KEY* de la víctima.
### LAB3: EXPLOITING ORIGIN SERVER NORMALIZATION FOR WEB CACHE DECEPTION
En este lab nos podemos loguear y si miramos el *Http History* podemos ver que la request a `/my-account`contiene nuestra *API KEY*. Pero en este caso si probamos a intentar cachear `/my-account/abc.js` nos da un *404* y si intentamos encontrar *path delimiters* validos desde el *intruder* solo vemos `?` que no podemos usarlo. Podemos probar un *path traversal* enviando la petición a `/aaa/..%2fmy-acconunt`y vemos que nos resuelve pero no se almacena en caché. Si seguimos mirando request podemos ver que para cargar los recursos se usa `/resources` podemos tratar de probar si `/request/..%2f` se almacena en caché y vemos que si. Bastará con enviar la request a `/resources/..%2fmy-account`.
Creamos el payload en *exploit server*:
`<script>document.location="https://LAB-ID.web-security-academy.net/resources/..%2fmy-account?abc"</script>
Solo tendremos que enviar una nueva petición a `/resources/..%2fmy-account?abc` y veremos la *API KEY* de la víctima.
### LAB4: EXPLOITING CACHE SERVER NORMALIZATION FOR WEB CACHE DECEPTION
En este lab pasa algo similar al anterior, nos logueamos y si miramos el *Http History* podemos ver que la request a `/my-account`contiene nuestra *API KEY*. Pero en este caso si probamos a intentar cachear `/my-account/abc.js` nos da un *404* y si intentamos encontrar *path delimiters* validos desde el *intruder* solo vemos `?`, `#`, `%23` y `%3f` los probamos pero no obtenemos que se almacene en la caché. Podemos probar discrepancias en la normalización. Como vemos se usa `/resources` para cargar los recursos, entonces podemos probar `/my-account?%2f%2e%2e%2fresources`lo cual nos devuelve un *200 OK* pero no almacena en caché. Recordemos que tenemos mas delimitadores posibles, si probamos con `%23` es decir hacemos `/my-account?%23%2e%2e%2fresources` vemos *cache: hit*.Creamos el payload en *exploit server*:
`<script>document.location="https://LAB-ID.web-security-academy.net/my-account?%23%2e%2e%2fresources?abc"</script>
Solo tendremos que enviar una nueva petición a `/my-account?%23%2e%2e%2fresources?abc` y veremos la *API KEY* de la víctima.