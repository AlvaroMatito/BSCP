-----
### QUE ES?
Una **Race Condition** es una vulnerabilidad que ocurre cuando una aplicación **no gestiona correctamente operaciones concurrentes**.  
Sucede cuando **dos o más peticiones se ejecutan casi al mismo tiempo y el sistema no controla el orden correcto de ejecución**.
Esto puede permitir que un atacante **ejecute múltiples acciones antes de que el sistema actualice su estado**, provocando comportamientos inesperados como usar el mismo cupón varias veces, transferir dinero duplicado o saltarse controles de seguridad.
El problema aparece cuando la aplicación **verifica una condición y después realiza una acción**, pero **otra petición puede modificar el estado entre esos dos pasos**.
Se previene usando **bloqueos (locking), operaciones atómicas, transacciones y validaciones en el backend**.
#### PASOS:
- **IDENTIFICAR OPERACIONES CRÍTICAS**  buscar acciones donde el estado cambia *uso de cupones*, *compras*, *cambio de contraseña*.
- **ENVIAR MUCHAS PETICIONES A LA VEZ O EN PARALELO:** usar burpsuite para manipular el envio o la velocidad de envio de las request.
### LAB1: LIMIT OVERRUN RACE CONDITIONS
En este laboratorio vemos que hay un cupón de descuento, si seguimos el flujo normal de compra aplicando el descuento vemos las request de ver el carrito y de añadir el cupón. Si las enviamos al *repeater* y probamos a canjear varias veces el cupón nos dice que ya esta aplicado. Podemos probar a copiar esta reques muchas veces y meterlas todas en el mismo grupo, enviándolas en paralelo, consiguiendo apliar el cupón varias veces.
### LAB2: BYPASSING RATE LIMITS VIA RACE CONDITIONS
En este laboratorio nos piden que usemos fuerza bruta para entrar como carlos para ello podemos seguir el flujo de login con nuestro usuario y contraseña. Comprobamos que si enviamos varias peticiones de login erróneas nos bloquean. Podemos tratar enviar varias a la vez en un grupo de forma paralela y como vemos se envían mas de tres request antes de bloquearnos. Esto puede ser debido a que el contador de intentos se haga en el lado del servidor, entonces si conseguimos meter mas peticiones antes de que el contador nos bloquee en el servidor lo bypaseamos. Para el ataque final tenemos que enviar la request al *Turbo intruder* marcando el campo de password y con el usuario carlos. Podemos seleccionar la plantilla `examples/race-single-packet-attack.py` y adaptarla de esta manera:
`def queueRequests(target, wordlists):
`    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
`    engine = RequestEngine(endpoint=target.endpoint,
`                           concurrentConnections=1,
`                           engine=Engine.BURP2
`                           )
`    
`    # assign the list of candidate passwords from your clipboard
`    passwords = wordlists.clipboard
`    
`    # queue a login request using each password from the wordlist
`    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
`    for password in passwords:
`        engine.queue(target.req, password, gate='1')
`    
`    # once every request has been queued
`    # invoke engine.openGate() to send all requests in the given gate simultaneously
`    engine.openGate('1')
`
`
`def handleResponse(req, interesting):
`    table.add(req)
Importante tener en la clipboard el diccionario de contraseñas.
### LAB3: MULTI-ENDPOINT RACE CONDITIONS
Para resolver el lab se explota una **race condition entre `POST /cart` y `POST /cart/checkout`**. Primero se estudia el flujo comprando una gift card y observando en **Burp Suite** que `POST /cart` añade productos al carrito y `POST /cart/checkout` finaliza la compra. Se envían ambas peticiones a Repeater y se agrupan. Luego se modifica la request `POST /cart` para que el `productId` sea **1 (la chaqueta)**(importante tener una giftcard añadida para que se piense que la chaqueta vale 10$). Si se envían en secuencia el servidor devuelve _insufficient funds_. El ataque consiste en **enviar ambas requests en paralelo** (añadir producto y checkout al mismo tiempo). Debido a la carrera, el servidor **valida el saldo antes de que el producto caro se procese completamente**, por lo que la compra se confirma aunque no haya crédito suficiente. Puede requerir varios intentos hasta que la colisión ocurre y la chaqueta se compra correctamente.
### LAB4: SINGLE-ENDOPOINT RACE CONDITIONS
En este laboratorio vemos al iniciar sesión un apartado de cambio de correo y un servidor de emails. Nos dicen que se ha creado una cuenta de administrador para el correo `carlos@ginandjuice.shop`pero que aun no se le ha asignado a ninguna cuenta. Podemos probar si hay alguna *race condition* a la hora de cambiar el correo, para ello creamos un grupo de unas 20 request a `/my-account/change-email`cada una con un usuario diferente algo como `test1@exploitserver.net`vemos que si las enviamos de forma *secuencial* se asigna a cada correo un link para confirmar. El problema viene al enviarlas en *paralelo* que vemos que los links que se crean de confirmación no se asignan correctamente. Podemos repertir esto pero con solo dos request de manera que una sea al correo `test1@exploitserver.net` y otra a `carlos@ginandjuice.shop` y enviarlas en *paralelo* consiguiendo asignar a nuestra cuenta el correo de `carlos@ginandjuice.shop`.
### LAB5: EXPLOITING TIME-SENSITIVE VULNERABILITIES
Este laboratorio explota un **password reset mal diseñado** donde el **token de reseteo se genera usando un timestamp**. El token cambia en cada solicitud, pero si **dos peticiones se procesan exactamente al mismo tiempo**, el timestamp usado en el hash es el mismo y **ambos usuarios reciben el mismo token**. El servidor además **procesa solo una request por sesión (locking de PHP)**, por lo que primero hay que enviar las peticiones desde **dos sesiones diferentes**. Para obtener la `phpsessionid` y el `csrftoken` debemos enviar una request sin parametros a `/forgot-password` por *GET*. Luego se mandan **dos `POST /forgot-password` en paralelo**, uno para tu usuario y otro para **carlos**. Si ambas requests se ejecutan en el mismo instante, el sistema genera **el mismo reset token para ambos usuarios**. Tú recibes el email con el token de tu cuenta, pero **ese mismo token también es válido para carlos**, lo que permite **resetear su contraseña, iniciar sesión como carlos, acceder al panel admin y eliminar su usuario** usando **Burp Suite**.