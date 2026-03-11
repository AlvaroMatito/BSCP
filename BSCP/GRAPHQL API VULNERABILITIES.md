----
### QUE ES?

Las **GraphQL API vulnerabilities** son vulnerabilidades que afectan a aplicaciones que usan **GraphQL** para exponer su API.  
GraphQL permite que el cliente solicite exactamente los datos que quiere mediante consultas estructuradas, pero si la API no implementa controles adecuados puede permitir que un atacante acceda a datos sensibles, abuse de la lógica del backend o provoque ataques de denegación de servicio.
Estas vulnerabilidades suelen aparecer cuando el servidor **no restringe correctamente qué consultas se pueden hacer**, permite introspección sin control o no limita la profundidad o complejidad de las queries.
Un atacante puede aprovechar esto para **enumerar el esquema completo de la API, acceder a datos no autorizados o realizar consultas extremadamente pesadas**.
Se previene **deshabilitando introspection en producción, implementando control de acceso por campo, limitando la profundidad de las queries y aplicando rate limiting**.
#### PASOS:
- **DESCUBRIR LA API  GRAPHQL:**  buscar endpoints por *POST* como: `/api`, `/graphql/v1`, `/api/graphql`, `/graphql/graphql` o peticiones con *JSON*.
- **ENUMERAR EL ESQUEMA (INTROSPECTION):**  si está habilitado permite ver toda la estructura de la *API*.
- **EXTRAER DATOS:**  una vez descubierto el esquema se pueden hacer queries directas añadiendo parámetros ocultos.
- **QUERIES:** una vez vista toda la estructura de la *API* podemos enviar todas las queries posibles a *target* con *GraphQL* *Save GraphQL queries to site map*.
- **BYPASS BLOQUEO INSTROSPECTION:** podemos tratar de meter un `%0a`tras `__schema`.
### LAB1: ACCESSING PRIVATE GRAPHQL POSTS
En este primer laboratorio si miramos el *Http History* podemos ver una request por *POST* a lo que parece la *API* de *graphql*. Podemos probar a desde *burpsuite* → click derecho → *GraphQl* → *set instrospecction query*, esto nos permitira listar toda la estructura de la api. Si probamos a filtrar por password veremos un campo *postPassword* y ademas si nos fijamos no se lista el post con *id: 3*. Debemos abrir un post y mandar al *repeater* la request de `/graphql/v1` es esta podmos añadir el parametro *postPassword* y modificar el *id* a 3 para ver la contraseña oculta.
### LAB2: ACCIDENTAL EXPOSURE OF PRIVATE GRAPHQL FIELDS
En este lab nos encontramos una request por *POST* `/graphql/v1` podemos ver la estructura de la *API* con click derecho → *GraphQl* → *set instrospecction query*. Si observamos bien vemos que hay un tipo de request *getUser* que devuelve *usuario* y *contraseña*. Podemos listar todos los tipos de queries con click derecho → *GraphQl* → *GraphQL* *Save GraphQL queries to site map*. Enviamos la request de *getUser* pero le modificamos el *id* a 1 y nos devuelve el usuario y contraseña de *administrator*.
### LAB3: FINDING A HIDDEN GRAPHQL ENDPOINT
En este laboratorio el endpoint está oculto, no podemos encontrarlo simplemente mirando el *Http History*. Podemos ir probando rutas, vemos que cuando probamos a `/api` el mensaje de error cambia a *query not present*.  Enviamos esta request al *repeater* y tratamos de ver toda la estructura con *set instrospecction query* pero no nos lo permite, cabe destacar también que tenemos que hacerlo mediante *GET* ya que *POST* nos bloquea. Para bypasear y poder listar toda la estructura podemos añadir un `%0a` después de `__schema` ya que el servidor bloquea a través de esa palabra. Una vez bypaseado *GraphQL* *Save GraphQL queries to site map* y usamos la query *getUser* para pillar el usuario y contraseña de *administrator*.
### LAB4: BYPASSING GRAPHQL BRUTE FORCE PROTECTIONS
En este lab nos piden que nos conectemos como Carlos. Podemos tratar de hacerlo por fuerza bruta porque no conocemos su contraseña, para ello vamos al *Http History* y en la request `/graphql/v1` → *set instrospecction query* → *GraphQL* *Save GraphQL queries to site map*. En la request de login podemos probar varias contraseñas y vemos que nos bloquea por intentos. Esto se puede bypasear si enviamos todas las contraseñas a la vez. Para ello nos dan un codigo que nos permite crear la request:
`copy(``123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow``.split(',').map((element,index)=>`
`bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
`       token
`        success
`    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));console.log("The query has been copied to your clipboard.");
De esta forma la request debe quedarnos algo asi:
`mutation login{
`
`bruteforce0:login(input:{password: "123456", username: "carlos"}) {
`        token
`        success
`    }
`
`     ...
`
`bruteforce99:login(input:{password: "password", username: "carlos"}) {
`        token
`        success
`    }
### LAB5: PERFORMING CSRF EXPLOITS OVER GRAPHQL
En este laboratorio iniciamos sesión como wiener y vemos un apartado de cambio de correos, si interceptamos la request vemos que usa *graphql* para ello. Podemos probar si es susceptible a un CSRF para cambiar la contraseña de otro usuario. Para ello debemos incluir en el *Content-Type* `x-www-form-urlencoded`para hacerlo mas rapido podemos darle dos veces a *change request method*. El problema es que nos borra el body, añadirlo manualmente:
`query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D`
Una vez añadido click derecho → *Generate CSRF PoC* → *exploit server* → *delivery to victim*.