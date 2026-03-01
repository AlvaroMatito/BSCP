-----
### QUE ES?
Un **Path Traversal**  es una vulnerabilidad donde un atacante manipula rutas de archivos para acceder a ficheros fuera del directorio permitido.  
Ocurre cuando la aplicación usa directamente el input del usuario para construir una ruta en el sistema sin validarla correctamente.  
Permite leer archivos sensibles del sistema como configuraciones, credenciales o incluso código fuente.  
Se previene validando rutas, usando listas blancas de archivos permitidos y evitando concatenar directamente el input en rutas del sistema.
#### PASOS:
- _IDENTIFICAR EL PARÁMETRO VULNERABLE:_  tipo `file=`, `page=`, `path=`, `download=`.
- _PROBAR RETROCESOS DE DIRECTORIO:_  `../../../../etc/passwd`
- _PROBAR BYPASSES COMUNES:_
    - Codificación URL: `%2e%2e%2f`
    - Doble codificación: `%252e%252e%252f`
    - Uso de `....//`
    - Null byte: `%00`
- _OBJETIVO TÍPICO EN LINUX:_  
    `/etc/passwd`  
    `/etc/shadow` (si hay permisos)
- _OBJETIVO TÍPICO EN WINDOWS:_  
    `C:\Windows\win.ini`  
    `C:\Windows\System32\drivers\etc\hosts`

### LAB1: FILE PATH TRAVERSAL SIMPLE CASE
En este primer laboratorio vemos en el *http history* que al cargar las fotos usa el parámetro `filename=`, podemos probar si es vulnerable a **Path Traversal**.
`https://LAB-ID.web-security-academy.net/image?filename=../../../../../../etc/passwd`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*
### LAB2: FILE PATH TRAVERSAL, TRAVERSAL SEQUENCES BLOCKED WITH ABSOLUTE PATH BYPASS
En este laboratorio nos volvemos a encontrar que para cargar imágenes usa el parámetro `filename=`, pero al probar `../../` no funciona,
esto puede ser por que este configurado para apuntar solo a archivos por la ruta absoluta.
`https://LAB-ID.web-security-academy.net/image?filename=/etc/passwd`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*
### LAB3: FILE PATH TRAVERSAL, TRAVERSAL SEQUENCES STRIPPED NON-RECURSIVELY
En este laboratorio vemos que las imágenes se cargan mediante el parámetro `filename=`. Probamos rutas absolutas y secuencias `../`, pero no funcionan porque la aplicación elimina esas cadenas.
El filtro borra `../`, pero no lo hace de forma recursiva. Esto permite un bypass usando `....//`, ya que al eliminar parte de la cadena se reconstruye el retroceso de directorio.
`https://LAB-ID.web-security-academy.net/image?filename=....//....//....//etc/passwd`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*
### LAB4: FILE PATH TRAVERSAL, TRAVERSAL SEQUENCES STRIPPED WITH SUPERFLUOS URL-DECODE
En este laboratorio vemos que las imágenes se cargan mediante el parámetro `filename=`. Probamos rutas absolutas, secuencias `../` y `....//`pero no funcionan.
Otra cosa que podemos probar es a URL encodear o doble URL encodear las `/`.
`https://LAB-ID.web-security-academy.net/image?filename=..%252f..%252f..%252fetc/passwd`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*
### LAB5: FILE PATH TRAVERSAL, VALIDATION OF START OF PATH
En este laboratorio vemos que las imágenes se cargan mediante el parámetro `filename=` y que va seguido de una ruta ya establecida `/var/www/images`, lo mas probable es que se valide que al apuntar a un recurso a través de la url este esa ruta por lo tanto podemos probar:
`https://LAB-ID.web-security-academy.net/image?filename=/var/www/images/../../../../../etc/passwd`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*
### LAB6: FILE PATH TRAVERSAL, VALIDATION OF FILE EXTENSION WITH NULL BYTE BYPASS
En este laboratorio vemos que las imágenes se cargan mediante el parámetro `filename=`. Probamos rutas absolutas, secuencias `../` y `....//`pero no funcionan.
También observamos una extensión`.jpg` podemos probar a meter un *null byte* delante de la extensión para bypasearlo.
`https://LAB-ID.web-security-academy.net/image?filename=../../../../../etc/passwd%00.jpg`
Esto nos permite ver el `/etc/passwd`a través de *Burpsuite*