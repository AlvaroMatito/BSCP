-----
### QUE ES?
Una **vulnerabilidad de Access Control** ocurre cuando una aplicación no restringe correctamente lo que un usuario puede hacer o ver.  
Sucede cuando el servidor no valida adecuadamente los permisos y confía en información manipulable (como parámetros, roles en el cliente o IDs en la URL).  
Permite a un atacante acceder a recursos, funciones o datos que no debería, como paneles de administración o información de otros usuarios.  
Se previene aplicando controles de autorización en el servidor y validando siempre los permisos antes de procesar cada solicitud.
### TIPOS COMUNES:
- **Horizontal** → Acceder a recursos de otro usuario con el mismo nivel (ej: cambiar el `user_id=123` por `124`).
- **Vertical** → Acceder a funciones de mayor privilegio (ej: entrar en `/admin` siendo usuario normal).
- **Context-dependent** → Saltarse restricciones en flujos específicos (ej: realizar acciones fuera del orden permitido).
#### PASOS: 
- *BUSCAR EL ROBOTS.TXT*
- *BUSCAR COOKIES ADMIN*
- *BUSCAR CHIVATOS EN LAS URL*
- *PROBAR CABECERAS*
### LAB1: UNPROTECTED ADMIN FUNCIONALITY
En este laboratorio observamos que si buscamos el *robots.txt*, este contiene una ruta oculta `/administrator-panel` la cual no tiene protección y nos permite realizar acciones de administrador.
### LAB2: UNPROTECTED ADMIN FUNCTIONALITY WITH UNPREDICTABLE URL
En este laboratorio observamos que si inspeccionamos el código fuente de la pagina o lo interceptamos con *Burp* vemos un script que nos chiva un directorio de administrador:
`<script>
`var isAdmin = false;
`if (isAdmin) {
`   var topLinksTag = document.getElementsByClassName("top-links")[0];
`   var adminPanelTag = document.createElement('a');
`   adminPanelTag.setAttribute('href', '/admin-ecdgt4');
`   adminPanelTag.innerText = 'Admin panel';
`   topLinksTag.append(adminPanelTag);
`   var pTag = document.createElement('p');
`   pTag.innerText = '|';
`   topLinksTag.appendChild(pTag);
`}
`</script>
### LAB3: USER ROLE CONTROLLED BY REQUEST PARAMETER
En este laboratorio observamos que hay un directorio de administrador `/admin` pero que solo puedes acceder si eres el usuario *administrador*, si miramos las cookies vemos que hay una cookie modificable  `admin` la cual podemos establecer a true y entrar.
### LAB4: USER ROLE CAN BE MODIFIED IN USER PROFILE
En este lab tras iniciar sesión como `wiener:peter` vemos un apartado de cambio de correo, al interceptar esta petición nos encontramos que tenemos *roleid=1* para ponernos como administrador debemos enviar la solicitud de cambio de correo y modificar ese *roleid*.
`{
`	"email":"test@tets.com",
`	"roleid": 2
`}
### LAB5: USER ID CONTROLLED BY REQUEST PARAMETER, WITH UNPREDICTABLE USER IDS
En este laboratorio observamos que los usuarios usan una cadena de números y letras en el parámetro *id* para identificarlos pero también vemos que en los post, las urls de estos post contienen el identificador del usuario que ha subido el post. Podemos cambiar el identificador por el de otro usuario y tendriamos acceso como este.
### LAB6: USER ID CONTROLLED BY REQUEST PARAMETER WITH DATA LEAKAGE IN REDIRECT
En este laboratorio vemos que cada usuario tiene un identificador en la *url* con su nombre, si interceptamos la request de `my-account` con *burp* y modificamos el *i*d por el de otro usuario vemos que se produce un *redirect* que muestra el contenido de la pagina del usuario del id para posteriormente redirigirte de nuevo a tu usuario con el que estas logueado. 
### LAB7: USER ID CONTROLLED BY REQUEST PARAMETER WITH PASSWORD DISCLOSURE
En este laboratorio podemos llegar a ver la contraseña del *administrador* simplemente cambiando desde *burp* el *id* asociado a la cuenta de wiener por administrator, ya que la password esta en un input puesta como hidden.
### LAB8: INSECURE DIRECT OBJECT REFERENCES
En este lab podemos ver que hay un *chat en directo* y que nos permite descargarnos la conversación, al darle nos damos cuenta que la descarga comienza en el intento numero 2, cambiamos al numero 1 y al visualizarlo encontramos una contraseña en la conversación.
### LAB9: URL-BASED ACCESS CONTROL CAN BE CIRCUMVENTED
En este laboratorio nos encontramos un `/admin` al que no tenemos acceso pero podemos bypasear esto ya que el servidor confía en la cabecera `X-Original-Url`.
La cabecera **`X-Original-URL`** se usa en algunos entornos con proxies o balanceadores para indicar al backend cuál era la ruta original solicitada antes de una reescritura interna.
`GET /?username=carlos HTTP/2
`Host: LAB-ID.web-security-academy.net
`Cookie: session=lBcHnkZvlaVf2XTiov4GCHZCbe2ihoT8
`X-Original-Url: /admin/delete
### LAB10: METHOD-BASED ACCESS CONTROL CAN BE CIRCUMVENTED
En este lab nos permiten acceder como administrador para familiarizarnos con la parte de *administrador*, vemos que podemos aumentar o disminuir privilegios a un usuario.
Si interceptamos la request para aumentar privilegios y después la intentamos hacer con un usuario que no sea admin, nos dará un error, pero si le cambiamos el metodo a GET funcionará
### LAB11: MULTI-STEP PROCESS WITH NO ACCESS CONTROL ON ONE STEP
En este lab ocurre algo similar al anterior pero en este tenemos dos pasos para subir los privilegios, por eso debemos añadir `&confirmed=true` de esta forma y con la session del administrador podemos elevar privilegios.
### LAB12: REFERER-BASED ACCESS CONTROL
En este laboratorio iniciamos sesión con el usuario administrador y, desde el panel de administración, promocionamos al usuario _carlos_, interceptando la petición con Burp Repeater para analizarla.
Después, accedemos con un usuario sin privilegios e intentamos llamar directamente a `/admin-roles?username=carlos&action=upgrade`, observando que el servidor la rechaza al no incluir la cabecera **Referer**, lo que indica que se está utilizando como mecanismo de control de acceso.
Finalmente, copiamos la cookie de sesión del usuario no administrador en la petición previamente capturada en Repeater, modificamos el parámetro `username` por el nuestro y reenviamos la solicitud, logrando así la elevación de privilegios al reutilizar una petición válida que el servidor no valida correctamente a nivel de autorización.
