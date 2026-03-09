-----
### QUE ES?
Una **JWT Vulnerability** es una vulnerabilidad que ocurre cuando una aplicación **maneja incorrectamente los JSON Web Tokens (JWT)** usados para autenticación.  
Sucede cuando el servidor **no valida correctamente la firma, el algoritmo o los campos del token**, permitiendo que un atacante **modifique el contenido del JWT**.  
Esto puede permitir **escalar privilegios, hacerse pasar por otro usuario o acceder a recursos restringidos**.  
Se previene validando siempre la **firma del token, restringiendo los algoritmos permitidos y nunca confiando en los datos del payload sin verificar**.
#### PASOS:
- _IDENTIFICAR JWT:_ buscar tokens con formato `header.payload.signature` en cookies o headers.
- _DECODIFICAR TOKEN:_ base64 decode para ver el contenido del `header` y `payload`.
-  _MODIFICAR PAYLOAD:_ cambiar campos como:  `"user":"administrator"` o `"role":"admin"`
- _PROBAR `alg:none` ATTACK:_ cambiar `"alg":"HS256"` por `"alg":"none"` y eliminar la firma.
- *PROBAR A FIRMAR EL TOKEN CON NUESTRA PROPIA CLAVE PRIVADA:* si acepta *jwk* en la cabecera crear clave privada y publica, firmarlo y pasarle la clave publica en *jwk*.
- _ALGORITHM CONFUSION:_ cambiar `RS256` → `HS256` y firmar el token usando la **public key como secret**.
- _ENVIAR TOKEN MODIFICADO:_ reemplazar el JWT en la cookie o header y comprobar si se obtienen **privilegios elevados o acceso no autorizado**.
### LAB1: JWT AUTHENTICATON BYPASS VIA UNVERIFIED SIGNATURE
En este lab nos piden que nos convirtamos en *administador* para ello iniciamos sesión con nuestra cuenta. Vemos que nuestro token de sesion es un *JWT* formado por `header.payload.signature` si inspeccionamos el payload vemos que contempla nuestro usuario, bastará con cambiarlo a *administrator* y acceder a `/admin`.
### LAB2: JWT AUTHENTICATION BYPASS VIA FLAWLED SIGNATURE VERIFICATION
En este lab nos piden que nos convirtamos en *administador* para ello iniciamos sesión con nuestra cuenta. Vemos que nuestro token de sesion es un *JWT* formado por `header.payload.signature` si inspeccionamos el payload vemos que contempla nuestro usuario, pero al cambiarlo a *administrador* sigue sin funcionar. Podemos probar a modificar el algoritmo de firma a *none* y eliminar la parte de la firma del *JWT* (recordar dejar el *.*)
### LAB3: JWT AUTHENTICATION BYPASS VIA WEAK SIGNING KEY
En este laboratorio tenemos que elevar nuestros privilegios. Para ello si iniciamos sesion veremos nuestro *JWT*, a veces el secreto que usan para firmarlo es debil y se puede crackear con `hashcat -a 0 -m 16500 <JWT> /path/secrets.txt`. Una vez roto vemos que el secreto es `secret1`. Haciendo uso de la extensión *JWT Editor* podemos crear una nueva clave simetrica dandole a generar y poniendo en *k:* el valor en base64 del secreto. De esta forma realizamos una peticion a `/admin` y desde la extension modificamos el valor de *sub:* a administrator y lo firmamos en *sign* con la clave simetrica que hemos creado.
### LAB4: JWT AUTHENTICATION BYPASS VIA JWK HEADER INJECTION
En este laboratorio tenemos que elevar nuestros privilegios. Para ello si iniciamos sesion veremos nuestro *JWT*. Si intentamos acceder  `/admin` nos dirá que solo tienen acceso los administradores. En este caso el servidor permite meter en el header el parámetro *jwk* que se usa para meter directamente en el token la clave correcta de verificación, el problema es que no verifica la procedencia de esa clave. Por lo tanto podemos usar la extension *JWT Editor* para crear una nueva *clave RSA*, pinchamos y le damos a *generate*. Una vez generada solo tenemos que realizar una request a `/admin'`, en el apartado de la extensión modificar *sub:* administrator y darle a *attack* → *Embedded JWK* con la clave que hemos creado antes. De esta forma firmamos el *JWK* con nuestra *clave privada* y incrustamos la *clave publica* en el propip *JWT*.
### LAB5: JWT AUTHENTICATION BYPASS VIA JKU HEADER INJECTION
En este laboratorio tenemos que elevar nuestros privilegios. Para ello si iniciamos sesion veremos nuestro *JWT*. En este caso el *JWT* permite el uso del parametro *jku* que indica **dónde debe ir el servidor a buscar las claves públicas** para verificar la firma del token. El problema es que no valida si la url que contiene *jku* es legitima. Aprovechando esto podemos crear nuestras propias claves en *JWT Editor* con *new RSA key*. Pinchamos y le damos a generate, tras esto con click derecho copiamos la clave publica como *JWK*. Vamos a usar nuestro exploit server como endpoint, donde se almacenará nuestra clave. Para ello en el body debemos añadir esta estructura con el *kid* y *n* de nuestra clave:
`{
`        "keys": [
`            {
`                "kty": "RSA",
`                "e": "AQAB",
`                "kid": "NUESTRO-KID",
`                "n": "NUESTRO-N"
`            }
`        ]
`    }
Una vez tengamos esto solo tenemos que enviar la request a `/admin` modificando *sub* a administrator, modificando el parámetro *kid* de la cabecera por el nuestro y añadiendo el parametro *jku* con la url completa a el exploit server. Lo firmamos con nuestra clave creada al principio y enviamos la petición.
### LAB6: JWT AUTHENTICATION BYPASS VIA KID HEADER PATH TRAVERSAL
En este laboratorio tenemos que elevar nuestros privilegios. Para ello si iniciamos sesión veremos nuestro *JWT*. En este caso el *JWT* al validar la clave con el parámetro *kid* nosotros podemos controlar este valor. Podemos crear una clave simétrica con *New Symmetric Key* y meter como valor de *k* un valor nulo `AA==`. De esta manera nos vamos a la request a `/admin`y cambiamos *sub:* a administrator. Para que funcione debemos hacer un *path traversal* a la ruta `/dev/null` en el parametro *kid*, de esta manera al validar la clave será *null* y podremos bypasearlo