-----
### QUE ES?
Una **Information Disclosure** es una vulnerabilidad donde una aplicación expone **información sensible que no debería ser accesible para el usuario**.  
Ocurre cuando el sistema revela datos internos como **rutas del servidor, versiones de software, mensajes de error, credenciales, archivos de configuración o datos de otros usuarios**.  
Esta información puede ser usada por un atacante para **entender mejor la infraestructura y preparar ataques más avanzados**.  
Se previene **limitando la información que devuelve la aplicación, deshabilitando errores detallados en producción y protegiendo archivos sensibles**.
#### PASOS:
- _BUSCAR ERRORES DETALLADOS:_ provocar errores en parámetros (`' " < >`) para ver **versiones, stack traces o rutas del servidor**.
- *REVISAR TARGET SITE MAP:* puede haber request con información sensible.
- _ENUMERAR ARCHIVOS SENSIBLES:_ probar rutas comunes como `/robots.txt`, `/backup`, `/.git`, `/config`, `/admin`, `/debug`.
- _REVISAR RESPUESTAS HTTP:_ analizar **cabeceras (`Server`, `X-Powered-By`)** usar metodos alternativos como **TRACE**.
- _INSPECCIONAR COMENTARIOS Y JS:_ revisar **código fuente y archivos JavaScript** por claves API, endpoints ocultos o comentarios de desarrolladores.
- _REVISAR RESPUESTAS DE LA API:_ algunas APIs devuelven **más información de la necesaria (IDs, emails, tokens, etc.)**.
- _BUSCAR METADATOS:_ archivos subidos (PDF, imágenes, docs) pueden contener **metadata con usuarios, rutas o software utilizado**.
### LAB1: INFORMATION DISCLOSURE IN ERROR MESSAGE
En este primer laboratorio si miramos el contenido del *Http History* de *Burp* y nos vamos a las request de los productos vemos que usan un parámetro *productId* el cual si modificamos con un caracteer extraño o alguna palabra dará un error (`productId=test`). La vulnerabilidad reside en que en este error podemos ver la version de *Apache Struts* la cual ademas es vulnerable.
### LAB2: INFORMATION DISCLOSURE ON DEBUG PAGE
En este laboratorio si nos vamos al apartado de *Target* en el *Site map* podemos ver todas las request del laboratorio. Si analizamos todas vemos una a `/cgi-bin/phpinfo.php` la cual nos revela *información sensible* como la `SECRET_KEY`.
### LAB3: SOURCE CODE DISCLOUSURE VIA BACKUP FILES
En este lab no vemos nada raro siguiendo el *Site map* de *Burp*, pero si buscamos el archivo `robots.txt` nos chiva que hay un *backup* y ademas tenemos capacidad de *directory listing*. 
En este archivo encontramos la *contraseña* de la base de dato hardcodeada.
### LAB4: AUTENTICATION BYPASS VIA INFORMATION DISCLOSURE
En este laboratorio no vemos nada raro en el *Site map*, tampoco encontramos un `robots.txt`, pero podemos probar a enumerar `/admin`. Veremos que nos dice que solo aceptan solicitudes desde local. Si utilizamos el método `TRACE` en vez de `GET` este nos revela una cabecera `X-Custom-Ip-Authorization` en la que confían. Podemos enviar esta cabecera con el valor `127.0.0.1` y ganar acceso al panel de administrador.

El método **HTTP `TRACE`** se usa para **diagnóstico y depuración**, ya que hace que el servidor **devuelva exactamente la misma petición que recibió**.
Sirve para comprobar **cómo la solicitud pasa por proxies, firewalls o servidores intermedios**, mostrando cabeceras y modificaciones que hayan ocurrido en el camino.
### LAB5: INFORMATION DISCLOSURE IN VERSION CONTROL HISTORY
En este laboratorio no vemos nada raro al principio pero si buscamos `/.git` encontramos toda la información de *git*, *commits*, *logs*, etc. Podemos descargarla en nuestro equipo mediante `wget -r https://ID-LAB.web-security-academy.net/.git`, meternos en la carpeta `.git`, mirar los *logs* con `git log` y inspeccionar el log del cambio de *contraseña a admin* con `git show HASH-COMMIT`.
