-----
### QUE ES?
Un **Web Cache Poisoning** es una vulnerabilidad donde un atacante manipula el contenido almacenado en la **cache de un servidor o CDN** para que otros usuarios reciban una respuesta maliciosa.  
Ocurre cuando la cache almacena una respuesta generada a partir de una petición manipulada (headers, parámetros, etc.) sin validarla correctamente.  
Esto permite que el atacante envenene la cache y que otros usuarios reciban contenido alterado, pudiendo provocar **XSS, redirecciones maliciosas o robo de información**.  
Se previene validando correctamente los headers y parámetros que afectan a la respuesta y asegurando que la cache solo dependa de valores controlados.
#### PASOS:
- _IDENTIFICAR SI HAY CACHE EN LA RESPUESTA:_ Buscar headers como `X-Cache`, `Age`, `Cache-Control`, `Via` o `CF-Cache-Status`.
- _ENCONTRAR INPUTS QUE AFECTEN LA RESPUESTA:_ Probar headers como `X-Forwarded-Host`, `X-Host`, `Host`, `X-Forwarded-Proto`.
- *REVISAR SCRIPTS:* Probar a manipular mediante headers el contenido de los scripts.
- *REVISAR RECURSOS CARGADOS*
- _PROBAR CACHE KEYS:_ Enviar peticiones modificando headers o parámetros para ver si cambian la respuesta.
- _INYECTAR PAYLOAD:_ Introducir contenido malicioso en un header o parámetro que el servidor refleje.
- *USAR PARAM MINER*
- *PROBAR CONTENIDO EN EL BODY*
- *PROBAR A BUSCAR SITIOS QUE NO EXISTEN POR SI SE REFLEJAN EN ERROR*
#### CONCEPTOS:
**Unkeyed**: significa que un **parámetro o header de una petición no forma parte de la clave que usa la cache para almacenar la respuesta**, aunque sí puede influir en el contenido que genera el servidor. Esto es peligroso porque un atacante puede modificar ese valor para provocar que el servidor genere una respuesta manipulada y, como ese input no está incluido en la **cache key**, la cache almacenará esa respuesta como válida y se la servirá posteriormente a otros usuarios. Si llega otra petición con **la misma key**, la caché devuelve la respuesta ya almacenada.
- El atacante envía una petición manipulada (por ejemplo con un header raro).
- Ese valor **afecta a la respuesta que genera el servidor**.
- Pero ese valor **no forma parte de la cache key (es unkeyed)**.
- La caché guarda esa respuesta manipulada con una key “normal”.
- Cuando otros usuarios hacen una petición normal con la **misma key**, reciben la respuesta envenenada(la que contiene la cabecera o lo que sea unkeyed).

**X-Forwarded-Host**: indica cuál era el **host original que pidió el cliente**. Se usa cuando un proxy recibe la petición y la reenvía al backend, para que el servidor sepa el dominio real solicitado y pueda generar enlaces o redirecciones correctas.    
**X-Forwarded-Scheme**: indica **qué protocolo usó el cliente originalmente**, normalmente `http` o `https`. Esto es útil cuando el proxy termina el TLS (HTTPS) y luego comunica con el backend en HTTP, para que la aplicación sepa que el usuario realmente llegó por HTTPS.
Un **caché buster** es un parámetro o valor que se añade a una petición para **evitar que la caché devuelva una respuesta ya almacenada**, forzando al servidor a generar una nueva. Esto funciona porque muchas caches usan la **URL y sus parámetros para construir la cache key**, por lo que si añadimos un valor diferente (por ejemplo `?cb=12345`) la petición se considera distinta y no reutiliza la respuesta anterior.
El **Parameter Cloaking** es una técnica utilizada en ataques de **Web Cache Poisoning** donde un atacante oculta un parámetro malicioso dentro de otro parámetro que sí forma parte de la **cache key**, de forma que el sistema de caché lo interpreta como un valor normal pero el backend lo procesa como un parámetro separado. Esto ocurre porque el **cache y el servidor interpretan los parámetros de forma distinta**, permitiendo que el atacante inyecte valores que afectan a la respuesta del servidor sin modificar la cache key, lo que puede provocar que una respuesta manipulada quede almacenada en la caché y sea servida posteriormente a otros usuarios.
### LAB1: WEB CACHE POISONING WITH AN UNKEYED HEADER
En este laboratorio vemos una web aparentemente normal pero si vemos las respuestas a la *request* a la `/` vemos que devuelve la cabecera `X-Cache: hit` lo que nos indica que el contenido de la web se esta cargando en *caché*. Además si observamos vemos un *script* que parece cargar `/resources/js/tracking.js` probamos si mediante la cabecera `X-Forwarded-Host:` podemos cambiar la url del script. Como es vulnerable modificamos el exploit server para que su url sea `ID-EXPLOTI-SERVER/resources/js/tracking.js` y le metemos un **XSS** en el contenido algo como `alert(document.cookie);`
### LAB2: WEB CACHE POISONING WITH AN UNKEYED COOKIE
En este lab vemos una web que almacena el contenido en caché, observando un poco vemos que hay una cookie que no forma parte de la clave cache y que refleja su contenido en el codigo de la web `fehosts=` por lo que podemos tratar de realizar un XSS de esta forma:
`fehosts=abc"-alert(1)-"abc
### LAB3: WEB CACHE POISONING WITH MULTIPLE HEADERS
En este lab vemos una web que almacena el contenido en caché pero a primera vista no parece tener ni scripts raros, ni urls completas, ni cookies reflejadas unkeyed. Si vemos el Http History encontramos la carga de un recurso `resources/js/tracking.js` que al probar a meterle las cabeceras `X-Forwarded-Scheme: http` y `X-Forwarded-Hosts: EXPLOIT-SERVER`
carga en cache la url al exploit server, solo tenemos que meterle `File:/resources/js/tracking.js` y en el contenido `alert(document.cookie)`
### LAB4: TARGETED WEB CACHE POISONING USING AN UNKNOWN HEADER
En este lab vemos una web que almacena contenido en cache probamos a usar la extensión *Param Miner* →*Guess Headers* en la raíz `/` y vemos que nos reporta una cabecera `X-Hosts` esta hace que el hostname que le pasemos se vea reflejado al cargar los recursos `resources/js/tracking.js`, por lo que ponemos el hostname del server exploit y en este hacemos `File:/resources/js/tracking.js` y en el body `alert(document.cookie)`. Como no tenemos forma de enviárselo a la víctima directamente podemos irnos a los comentarios y tratar de meter en el body que permite *HTML*  `<img src="https://EXPLOIT-SERVER-ID.exploit-server.net/foo" />`. De esta forma podremos ver en los logs el *User Agent* de la víctima y al usarlo en nuestra request maliciosa, hará que aparezca la url de nuestro exploit server guardándola en caché.
### LAB5: WEB CACHE POISONING VIA AN UNKEYED QUERY STRING
En este lab vemos una web que almacena contenido en caché pero tras probar varias headers no conseguimos nada. Podemos probar un *caché buster* en la raíz `/?cb=ldasjflkas` que tras cargarse en caché vemos que se ve reflejado en un *link* de la web. Este también se puede encontrar mediante *Param Miner*. Metemos a través del caché buster el **XSS** `/?cb='/><script>alert(1)</script>`
### LAB6: WEB CACHE POISONING VIA AN UNKEYED QUERY PARAMETER
En este lab vemos una web que almacena contenido en *caché* pero tras probar varias headers no conseguimos nada. Probamos con *Param Miner* → *Guess query params* a ver si hay algún caché buster, encontramos `utm_content`. Podemos hacer `/?utm_content='/><script>alert(0)</script>`
### LAB7: PARAMETER CLOAKING
En este lab vemos una web que almacena contenido en *caché*, explorando vemos en el Http History una request `/js/geolocate.js` con un parámetro callback que parece que se usa para ejecutar la función que le pases al parámetro. Probamos a intentar hacer callback=alert(0) pero callback es parte de la clave cache por lo que no estaríamos envenenado la cache. Si probamos a usar *Param Miner* → *Guess query params* nos detecta `utm_content` el cual no pertenece a la clave cache. Podemos tratar de hacer parameter cloacking metiendo `/js/geolocate.js?callback=setCountryCookie&utm_content=foobar;callback=alert(1)` de esta forma estamos metiendo en cache los datos y como el backend si interpreta `;` entonces los considera como parámetros diferentes y ejecuta el ultimo callback `alert(1)`.
### LAB8: WEB CACHE POISONING VIA A FAT GET REQUEST
En este lab vemos una web que almacena contenido en *caché*, explorando vemos en el Http History una request `/js/geolocate.js` con un parámetro callback que parece que se usa para ejecutar la función que le pases al parámetro. Probamos diferentes cosas y vemos que `callback`es parte de la *caché key* por lo que no podemos modificarla a nuestro gusto. Podemos probar a introducir valores en el cuerpo de la request *GET*, como nos deja vamos a probar a meter un `callback=lksqdfo` y vemos que de esta manera podemos controlar el nombre de la función que se llama haciendo que se almacene en caché ya que la *caché key* es la misma. `callback=alert(0)` para llevar a cabo el **XSS**.
### LAB9: URL NORMALIZATION
En este lab podemos realizar una request a algo que no existe y esto se ve reflejado en el código de la página. Si metemos `GET %2f<script>alert(1)</script> HTTP/2` y lo cargamos en caché, si buscamos la url debería de producirse el **XSS**. Solo tendríamos que enviárselo a la víctima


